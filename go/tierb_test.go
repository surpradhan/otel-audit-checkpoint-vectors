package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// linkChain fills in each checkpoint's prev_hash from its predecessor's
// canonical bytes, so a hand-built test chain satisfies B2 and can exercise the
// other rules. Tests that mean to break the linkage set prev_hash themselves.
func linkChain(t *testing.T, cps ...Checkpoint) []Checkpoint {
	t.Helper()
	out := make([]Checkpoint, 0, len(cps))
	prev := sha256Empty
	for _, cp := range cps {
		cp.PrevHash = prev
		out = append(out, cp)
		cb, err := canonical(cp)
		if err != nil {
			t.Fatalf("linkChain: %v", err)
		}
		sum := sha256.Sum256(cb)
		prev = hex.EncodeToString(sum[:])
	}
	return out
}

func mkTip(stream string, epoch, seq, count int, tip string) Tip {
	return Tip{EntryCount: count, Epoch: ptr(epoch), SequenceNumber: seq, StreamID: stream, TipHash: tip}
}

// B3: the same (stream_id, epoch) committed twice in one chain is a hard
// reject, whether or not the tips differ. Within one generation the producer's
// dedup map is intact, so no second commit of any kind is legitimate.
func TestB3RejectsSameStreamSameEpoch(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 3, 3, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 0, 2, 2, "bb")}})
	if _, err := checkTierB(chain); err == nil {
		t.Fatal("checkTierB accepted a same-epoch re-commit; want a rejection")
	}
}

// B4: the same stream under a NEW epoch is the declared at-least-once path.
// It must be accepted even when entry_count goes backwards, because an honest
// timeout-split produces exactly that shape -- and it must warn.
func TestB4AcceptsSameStreamNewEpochWithWarning(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 7, 7, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 1, 5, 5, "bb")}})
	warns, err := checkTierB(chain)
	if err != nil {
		t.Fatalf("checkTierB rejected a legitimate cross-epoch re-commit: %v", err)
	}
	if len(warns) != 1 || warns[0] != "B4:s1" {
		t.Fatalf("warnings = %v, want exactly [B4:s1]", warns)
	}
}

// B5: a timestamp regression warns and does not reject.
func TestB5WarnsOnTimestampRegression(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 1, 1, "bb")}})
	warns, err := checkTierB(chain)
	if err != nil {
		t.Fatalf("timestamp regression must warn, not reject: %v", err)
	}
	if len(warns) != 1 || warns[0] != "B5:2" {
		t.Fatalf("warnings = %v, want exactly [B5:2]", warns)
	}
}

// B1: seq must increment by exactly 1.
func TestB1RejectsSeqSkip(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 3, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 1, 1, "bb")}})
	if _, err := checkTierB(chain); err == nil {
		t.Fatal("checkTierB accepted a seq gap; want a rejection")
	}
}

// R4: two tips for one stream at different epochs are legal in ONE checkpoint,
// so the sort key must be composite or the canonical bytes depend on input order.
func TestR4CompositeSortKey(t *testing.T) {
	x := mkTip("s1", 0, 1, 1, "aa")
	y := mkTip("s1", 1, 2, 2, "bb")
	c1, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{x, y}})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{y, x}})
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) != string(c2) {
		t.Errorf("input order changed canonical bytes:\n %s\n %s", c1, c2)
	}
}

// A version-1 tip carries no epoch key, and re-marshalling must not add one.
// This is what keeps the seven frozen vectors byte-identical.
func TestVersion1TipOmitsEpoch(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	cb, err := canonical(cp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cb, []byte("epoch")) {
		t.Errorf("version-1 canonical bytes must not contain an epoch key: %s", cb)
	}
}

// freezeKey is the byte string v1FreezeKeys' hashes are taken over: an
// explicit, hand-ordered concatenation of a checkpoint's own scalar fields
// plus its signature and (for a negative that carries one) prev_sha256,
// NUL-separated. It does not call canonical(): that function deliberately
// errors on duplicate_tip_identity, one of the seven vectors this pins, and
// even where it succeeds, using it here would conflate two different failure
// classes -- "the frozen input changed" and "the shared canonicalization
// logic changed" -- that this repo's other tests already cover separately.
// Every field is read directly off the struct (Seq/Timestamp/PrevHash are
// plain, non-pointer values, never absent), so there is no absent-vs-zero
// ambiguity to resolve, unlike the epoch reads elsewhere in this file. Tips
// are walked in the order they appear in Input, not sorted, since the point
// is to detect ANY change to what genFrozenV1 produced, including one that
// changed only their order. Mirrors Python's freeze_key byte for byte.
//
// The \x00 join has no length-prefixing or escaping, so two different field
// sequences could in principle concatenate to the same bytes if any field
// ever contained an embedded NUL -- the exact assumption tipKey's own doc
// comment in main.go describes replacing, for the same reason. Safe here
// only because every field is either a short hex/UUID/timestamp literal
// genFrozenV1 hardcodes, or base64/hex derived deterministically from one
// (signature, prevSHA256) -- never third-party or attacker-derived input;
// this function must not be reused anywhere that assumption doesn't hold.
func freezeKey(cp Checkpoint, signature, prevSHA256 string) []byte {
	parts := []string{cp.PrevHash, strconv.Itoa(cp.Seq), cp.Timestamp}
	for _, tip := range cp.Tips {
		epoch := ""
		if tip.Epoch != nil {
			epoch = strconv.Itoa(*tip.Epoch)
		}
		parts = append(parts, tip.StreamID, epoch,
			strconv.Itoa(tip.SequenceNumber), strconv.Itoa(tip.EntryCount), tip.TipHash)
	}
	parts = append(parts, signature, prevSHA256)
	return []byte(strings.Join(parts, "\x00"))
}

// v1FreezeKeys pins the seven format_version-1 entries genFrozenV1 produces
// (main.go), keyed by name, against sha256(freezeKey(...)) computed once from
// the committed vectors.json when this test was added. CI's existing no-drift
// check only ever compares `gen`'s output against ITSELF, so it cannot catch
// a genFrozenV1 edit that changes what these entries contain: a normal regen
// after such an edit is internally self-consistent and passes every other
// gate (no-drift, both validators, both test suites) unchanged. This is the
// independent baseline that catches it. A failure here means STOP, not
// regenerate -- per CONTRIBUTING's vector-stability discipline, a change to a
// published vector's canonical bytes, hash or signature is breaking and
// requires superseding under a version marker, never a silent update to this
// map. Mirrors Python's _V1_FREEZE.
var v1FreezeKeys = map[string]string{
	"genesis_empty_tips":                "0bb3f2c250debdb9c56cf60f5202cae3f5914fec129f916eabaf25ed447d59f5",
	"single_tip":                        "0ad96391b112a968c47a8a300e6e152e2af9ba280faedf50bd5b732472f92784",
	"multi_tip_unsorted_input":          "37119009365ff5b0286ee2db5d6ae51d4fd7d774176236446c7ed7e74ee304b8",
	"tampered_signature":                "f4e76bc9b72c8acc951522dfdf9bfeac9c8e0204b71dc8fe7a36e59878db8b14",
	"truncation_rewrites_committed_tip": "c56203cab8d5054e74cf8ba24105cd5b3b887163d10bdcc57510f549a0e47396",
	"broken_chain":                      "33c0d43f179bd1462cb46a5f15462dd713071c0b9912508b9d88a53383445e04",
	"duplicate_tip_identity":            "d3cdff059ba1e3a124daaad05de680b3e239c7f3bef416b270b0012fafa7b937",
}

// TestV1VectorsMatchFrozenSnapshot is the machine-checked gate named in issue
// #31 / PR #4's own backlog: a deliberate or accidental edit to genFrozenV1
// must fail SOMETHING, even though it fails neither the no-drift check nor
// either validator. Reads the actually-committed vectors.json (not
// genFrozenV1's live output) so it also catches a hand-edit that happens to
// leave the file self-consistent enough to pass everything else.
func TestV1VectorsMatchFrozenSnapshot(t *testing.T) {
	data, err := os.ReadFile("../vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite Suite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	check := func(name string, cp Checkpoint, signature, prevSHA256 string) {
		found[name] = true
		want, ok := v1FreezeKeys[name]
		if !ok {
			t.Errorf("%s: not one of the pinned v1 vectors; if this is a genuinely new "+
				"format_version-1 entry, add it to v1FreezeKeys (and Python's _V1_FREEZE) "+
				"rather than leaving it unpinned", name)
			return
		}
		sum := sha256.Sum256(freezeKey(cp, signature, prevSHA256))
		got := hex.EncodeToString(sum[:])
		if got != want {
			t.Errorf("%s: frozen v1 vector's checkpoint/signature/prev_sha256 no longer "+
				"matches the pinned snapshot (got %s, want %s) -- this is exactly the "+
				"CONTRIBUTING vector-stability violation this test exists to catch; do not "+
				"update v1FreezeKeys to make this pass unless the change is a deliberately "+
				"documented breaking change under a new version marker",
				name, got, want)
		}
	}
	for _, v := range suite.Vectors {
		if v.MinFormatVersion <= 1 {
			check(v.Name, v.Input, v.Signature, "")
		}
	}
	for _, nv := range suite.Negatives {
		if nv.MinFormatVersion <= 1 {
			check(nv.Name, nv.Input, nv.Signature, nv.PrevSHA256)
		}
	}
	for name := range v1FreezeKeys {
		if !found[name] {
			t.Errorf("%s: pinned in v1FreezeKeys but no longer present in vectors.json "+
				"at format_version 1 -- a frozen vector must not be silently removed", name)
		}
	}
}

// Spec 5a: epoch is required at format_version 2 and above, and must be absent
// in version-1 vectors. A version-2 tip missing epoch must be rejected, not
// defaulted to 0 -- otherwise the absent-vs-zero distinction is unenforced
// spec text. Mirrors py/test_validate.py's test_epoch_presence_boundary.
func TestEpochPresenceBoundary(t *testing.T) {
	v2Missing := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	if err := checkEpochPresence(v2Missing, 2); err == nil {
		t.Error("a version-2 tip with no epoch must be rejected")
	}
	if err := checkEpochPresence(v2Missing, 0); err != nil {
		t.Errorf("a version-1 tip with no epoch is well-formed, got: %v", err)
	}

	v1WithEpoch := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		mkTip("s1", 0, 1, 1, "aa"),
	}}
	if err := checkEpochPresence(v1WithEpoch, 0); err == nil {
		t.Error("epoch is not permitted in a version-1 vector")
	}
	if err := checkEpochPresence(v1WithEpoch, 2); err != nil {
		t.Errorf("a version-2 tip with an explicit epoch is well-formed, got: %v", err)
	}
}

// --- Round-1 review fixes -------------------------------------------------

func testPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(testSeed()).Public().(ed25519.PublicKey)
}

func signed(t *testing.T, cp Checkpoint) SignedCheckpoint {
	t.Helper()
	return signCP(ed25519.NewKeyFromSeed(testSeed()), cp)
}

// The MUST on SignedCheckpoint: a prefix's signature is verified, not merely
// hashed for linkage. A verifier that skipped this would accept a forged
// history, so deleting the check must be visible from outside.
func TestPrefixSignatureIsVerified(t *testing.T) {
	pub := testPub(t)
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}}
	good := signed(t, cp)
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{good}, 2); reason != "" {
		t.Fatalf("a correctly signed prefix was rejected (%s)", reason)
	}
	raw, err := base64.StdEncoding.DecodeString(good.Signature)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0x01
	bad := SignedCheckpoint{Input: cp, Signature: base64.StdEncoding.EncodeToString(raw)}
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{bad}, 2); reason != "signature" {
		t.Fatalf("tampered prefix signature: reason = %q, want \"signature\"", reason)
	}
}

// The format_version boundary applies to chain prefixes too. Unchecked,
// tipEpoch reads a missing epoch as 0 and it silently feeds B3 identity and B4
// comparisons -- the Step 7 failure, one level down.
func TestPrefixEpochPresenceIsChecked(t *testing.T) {
	pub := testPub(t)
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{signed(t, cp)}, 2); reason != "schema" {
		t.Fatalf("version-2 prefix with no epoch: reason = %q, want \"schema\"", reason)
	}
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{signed(t, cp)}, 0); reason != "" {
		t.Fatalf("version-1 prefix with no epoch was rejected (%s)", reason)
	}
	// ...and at index >= 1: a chain[0]-only epoch check misses this.
	ok := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s0", 0, 1, 1, "00")}}
	twoPrefix := []SignedCheckpoint{signed(t, ok), signed(t, cp)}
	if _, reason := verifyPrefixes(pub, twoPrefix, 2); reason != "schema" {
		t.Fatalf("SECOND version-2 prefix with no epoch: reason = %q, want \"schema\"", reason)
	}
}

// checkEpochPresence must scan every tip, not just the first.
func TestEpochPresenceScansAllTips(t *testing.T) {
	missingOnSecond := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
		{EntryCount: 2, Epoch: nil, SequenceNumber: 2, StreamID: "s2", TipHash: "bb"},
	}}
	if err := checkEpochPresence(missingOnSecond, 2); err == nil {
		t.Error("epoch missing on the SECOND tip must be rejected; a Tips[0]-only check would miss it")
	}
	negativeOnSecond := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
		{EntryCount: 2, Epoch: ptr(-1), SequenceNumber: 2, StreamID: "s2", TipHash: "bb"},
	}}
	if err := checkEpochPresence(negativeOnSecond, 2); err == nil {
		t.Error("a negative epoch on the SECOND tip must be rejected")
	}
}

// A negative epoch is rejected rather than ordered. The two references AGREE on
// how to order one -- both compare the identity as a pair -- so the rule is
// about the third party: epoch is a producer generation counter, and an
// implementation that builds a TEXT sort key puts a leading "-" above the
// digits and orders -10 above -1. Rejecting keeps that ambiguity off the wire.
func TestNegativeEpochRejected(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(-1), SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	if err := checkEpochPresence(cp, 2); err == nil {
		t.Error("a negative epoch must be rejected")
	}
}

// The sort key must order epochs NUMERICALLY. A key that compares the epoch as
// text puts "10" before "2" and silently disagrees with Python's tuple compare
// on published bytes. TestR4CompositeSortKey cannot catch this: it uses
// single-digit epochs, where text and numeric order coincide.
func TestCompositeSortKeyIsNumericForMultiDigitEpochs(t *testing.T) {
	lo := mkTip("s1", 2, 3, 3, "aa")
	hi := mkTip("s1", 10, 11, 11, "bb")
	if !lessTip(lo, hi) {
		t.Fatalf("epoch 2 must sort below epoch 10, got %v >= %v", tipIdentity(lo), tipIdentity(hi))
	}
	cb, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{hi, lo}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cb, []byte(`"epoch":2`)) || !bytes.Contains(cb, []byte(`"epoch":10`)) {
		t.Fatalf("both epochs must appear: %s", cb)
	}
	if bytes.Index(cb, []byte(`"epoch":2`)) > bytes.Index(cb, []byte(`"epoch":10`)) {
		t.Errorf("epoch 10 was sorted before epoch 2 -- the sort key is not numeric:\n %s", cb)
	}
}

// B4 and B5 raised by the same checkpoint, in a pinned order. Without a case
// where both fire, their interleaving is mirrored between the two languages
// but verified by nothing.
func TestB4AndB5BothRaisedInOrder(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 1, 2, 2, "bb")}})
	warns, err := checkTierB(chain)
	if err != nil {
		t.Fatalf("both advisory rules must warn, not reject: %v", err)
	}
	want := []string{"B4:s1", "B5:2"}
	if !slices.Equal(warns, want) {
		t.Fatalf("warnings = %v, want %v", warns, want)
	}
}

// gen() is self-consistent by construction, so a change to canonicalization or
// the sort key regenerates cleanly and every gen()-based test still passes.
// Only the COMMITTED bytes catch that. This is what fails if the tip sort stops
// ordering epochs numerically.
func TestCommittedVectorsStillValidate(t *testing.T) {
	var err error
	out := captureStdout(t, func() { err = validate("../vectors.json") })
	if err != nil {
		t.Fatalf("the committed vectors.json no longer validates: %v\noutput:\n%s", err, out)
	}
}

// --- Round-2 review fixes -------------------------------------------------

// The identity-order tip walk. Two DIFFERENT streams each changing epoch in one
// checkpoint must emit their B4 tokens in a fixed order regardless of how the
// tips were supplied -- warnings are compared as ordered lists, and a
// checkpoint's tips are explicitly allowed to arrive unsorted.
func TestB4TokenOrderIsIndependentOfTipInputOrder(t *testing.T) {
	prefix := Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		mkTip("s1", 0, 1, 1, "aa"), mkTip("s2", 0, 2, 2, "bb"),
	}}
	lo, hi := mkTip("s1", 1, 3, 3, "cc"), mkTip("s2", 1, 4, 4, "dd")

	// Same signed bytes either way: canonical() sorts the tips, so both
	// checkpoints hash identically and both chains satisfy B2.
	sorted := linkChain(t, prefix, Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{lo, hi}})
	reversed := linkChain(t, prefix, Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{hi, lo}})

	warnsA, errA := checkTierB(sorted)
	warnsB, errB := checkTierB(reversed)
	if errA != nil || errB != nil {
		t.Fatalf("neither ordering may reject: %v / %v", errA, errB)
	}
	want := []string{"B4:s1", "B4:s2"}
	if !slices.Equal(warnsA, want) {
		t.Errorf("identity-order input: warnings = %v, want %v", warnsA, want)
	}
	if !slices.Equal(warnsB, want) {
		t.Errorf("reversed input: warnings = %v, want %v -- tip input order leaked into the warning sequence", warnsB, want)
	}
}

// B4 is emitted once per epoch TRANSITION, not once per checkpoint: one stream
// at three epochs in a single checkpoint yields two identical tokens.
func TestB4EmittedOncePerTransition(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 2, 3, 3, "bb"), mkTip("s1", 1, 2, 2, "cc")}})
	warns, err := checkTierB(chain)
	if err != nil {
		t.Fatalf("three epochs for one stream is legal (R4), got: %v", err)
	}
	want := []string{"B4:s1", "B4:s1"}
	if !slices.Equal(warns, want) {
		t.Fatalf("warnings = %v, want %v (0->1 and 1->2 are two transitions)", warns, want)
	}
}

// verifyPrefixes must check EVERY prefix, not just chain[0].
func TestVerifyPrefixesChecksEveryPrefix(t *testing.T) {
	pub := testPub(t)
	first := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}}
	second := Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 2, 2, "bb")}}
	secondSigned := signed(t, second)
	raw, err := base64.StdEncoding.DecodeString(secondSigned.Signature)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0x01
	chain := []SignedCheckpoint{
		signed(t, first),
		{Input: second, Signature: base64.StdEncoding.EncodeToString(raw)},
	}
	if _, reason := verifyPrefixes(pub, chain, 2); reason != "signature" {
		t.Fatalf("tampered SECOND prefix: reason = %q, want \"signature\" -- a chain[0]-only check misses it", reason)
	}
}

// The positive-path Tier B guard fires on ExpectWarnings alone, not only when a
// chain is present. Without that arm a chainless vector's advisory assertion is
// never evaluated and a validator that ignores B4 still passes the suite.
func TestChainlessExpectWarningsAreStillChecked(t *testing.T) {
	full := gen()
	var v Vector
	for _, cand := range full.Vectors {
		if cand.Name == "multi_epoch_same_stream" {
			v = cand
		}
	}
	if v.Name == "" {
		t.Fatal("multi_epoch_same_stream not found in gen() output")
	}
	// Drop the chain (the signature covers only the input, so it still
	// verifies) and state warnings that cannot be right.
	v.Chain = nil
	v.ExpectWarnings = []string{"B4:this-stream-does-not-exist"}

	suite := Suite{
		FormatVersion: full.FormatVersion, Description: full.Description,
		Algorithm: full.Algorithm, SeedHex: full.SeedHex, PublicKeyHex: full.PublicKeyHex,
		Vectors: []Vector{v},
	}
	out, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chainless_warnings.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	var verr error
	captured := captureStdout(t, func() { verr = validate(path) })
	if verr == nil {
		t.Fatalf("a chainless vector with wrong expect_warnings was accepted; the Tier B guard must fire on ExpectWarnings alone\noutput:\n%s", captured)
	}
	if !strings.Contains(verr.Error(), "warnings") {
		t.Fatalf("rejected, but not for the warning mismatch: %v", verr)
	}
}

// --- Round-3 review fixes -------------------------------------------------

// B4 fires when a stream's epoch DIFFERS from its previous committed epoch, in
// either direction. A stream re-committed under an OLDER generation is the most
// rollback-shaped case B4 exists to surface, and B3 does not cover it: (s,5) and
// (s,3) are distinct identities. Every other transition in the suite increases,
// so a validator warning only on an increase would otherwise pass everything.
func TestB4FiresOnEpochRegression(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 5, 9, 9, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 3, 4, 4, "bb")}})
	warns, err := checkTierB(chain)
	if err != nil {
		t.Fatalf("an epoch regression is advisory, not a rejection: %v", err)
	}
	if !slices.Equal(warns, []string{"B4:s1"}) {
		t.Fatalf("warnings = %v, want [B4:s1] -- B4 must fire on epoch DIFFERENCE, not increase", warns)
	}
}

// B2 must hold across the whole assembled chain, not only at the vector's own
// link: a chain whose prefixes do not hash-link is a forged history.
func TestChainPrevHashLinkageIsChecked(t *testing.T) {
	good := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 2, 2, "bb")}},
		Checkpoint{Seq: 3, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s3", 0, 3, 3, "cc")}})
	if _, err := checkTierB(good); err != nil {
		t.Fatalf("a correctly linked chain was rejected: %v", err)
	}
	// Break the link between the two PREFIXES, leaving the last link intact --
	// exactly what a vector-level prev_sha256 field cannot see.
	broken := append([]Checkpoint(nil), good...)
	broken[1].PrevHash = "22" + strings.Repeat("22", 31)
	if _, err := checkTierB(broken); err == nil {
		t.Fatal("checkTierB accepted a chain whose second checkpoint does not link to the first")
	}
}

// B1 must hold at every transition, not only between chain[0] and chain[1].
func TestB1CheckedOnEveryTransition(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 2, 2, "bb")}},
		Checkpoint{Seq: 4, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s3", 0, 3, 3, "cc")}})
	if _, err := checkTierB(chain); err == nil {
		t.Fatal("checkTierB accepted a seq gap at the SECOND transition; B1 must hold at every transition")
	}
}

// B1 checks seq's RELATIVE delta between adjacent checkpoints, never its
// absolute value against the checkpoint's position in the chain array. A real
// verifier holding a mid-chain window, with no genesis in view, must accept a
// correctly incrementing chain that does not start at seq 1.
func TestB1AcceptsChainNotStartingAtSeqOne(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 400, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 401, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 2, 2, "bb")}})
	if _, err := checkTierB(chain); err != nil {
		t.Fatalf("checkTierB rejected a correctly incrementing chain that does not start at seq 1: %v", err)
	}
}

// A mid-chain checkpoint with zero tips is legitimate under the delta model:
// an idle interval commits nothing new, but still advances seq and prev_hash.
// It must not disrupt B1/B2 on either side of it, and the tip walk (B3/B4)
// must run zero iterations for it rather than mishandling the empty slice.
func TestZeroTipCheckpointAcceptedMidChain(t *testing.T) {
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{}},
		Checkpoint{Seq: 3, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s2", 0, 2, 2, "bb")}})
	warns, err := checkTierB(chain)
	if err != nil {
		t.Fatalf("checkTierB rejected a chain with a mid-chain zero-tip checkpoint: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings = %v, want none", warns)
	}
}

// expect_warnings is an ORDERED contract. No published vector can catch a
// comparison weakened to a multiset, because every vector's expectation is
// correct and a looser comparison never fails on correct data -- only feeding a
// PERMUTED expectation can distinguish the two.
func TestWarningOrderIsPartOfTheContract(t *testing.T) {
	full := gen()
	var v Vector
	for _, cand := range full.Vectors {
		if cand.Name == "advisory_chain_b5_then_b4" {
			v = cand
		}
	}
	if v.Name == "" {
		t.Fatal("advisory_chain_b5_then_b4 not found in gen() output")
	}
	if len(v.ExpectWarnings) != 2 {
		t.Fatalf("this test needs a two-warning vector, got %v", v.ExpectWarnings)
	}
	v.ExpectWarnings = []string{v.ExpectWarnings[1], v.ExpectWarnings[0]} // same multiset, wrong order

	suite := Suite{
		FormatVersion: full.FormatVersion, Algorithm: full.Algorithm,
		SeedHex: full.SeedHex, PublicKeyHex: full.PublicKeyHex,
		Vectors: []Vector{v},
	}
	out, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "permuted_warnings.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	var verr error
	captured := captureStdout(t, func() { verr = validate(path) })
	if verr == nil {
		t.Fatalf("permuted expect_warnings was accepted; the comparison must be ordered, not a multiset\noutput:\n%s", captured)
	}
	if !strings.Contains(verr.Error(), "warnings") {
		t.Fatalf("rejected, but not for the warning mismatch: %v", verr)
	}
}
