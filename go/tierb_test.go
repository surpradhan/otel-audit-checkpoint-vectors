package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"testing"
)

func mkTip(stream string, epoch, seq, count int, tip string) Tip {
	return Tip{EntryCount: count, Epoch: ptr(epoch), SequenceNumber: seq, StreamID: stream, TipHash: tip}
}

// B3: the same (stream_id, epoch) committed twice in one chain is a hard
// reject, whether or not the tips differ. Within one generation the producer's
// dedup map is intact, so no second commit of any kind is legitimate.
func TestB3RejectsSameStreamSameEpoch(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 3, 3, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 0, 2, 2, "bb")}},
	}
	if err, _ := checkTierB(chain); err == nil {
		t.Fatal("checkTierB accepted a same-epoch re-commit; want a rejection")
	}
}

// B4: the same stream under a NEW epoch is the declared at-least-once path.
// It must be accepted even when entry_count goes backwards, because an honest
// timeout-split produces exactly that shape -- and it must warn.
func TestB4AcceptsSameStreamNewEpochWithWarning(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 7, 7, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 1, 5, 5, "bb")}},
	}
	err, warns := checkTierB(chain)
	if err != nil {
		t.Fatalf("checkTierB rejected a legitimate cross-epoch re-commit: %v", err)
	}
	if len(warns) != 1 || warns[0] != "B4:s1" {
		t.Fatalf("warnings = %v, want exactly [B4:s1]", warns)
	}
}

// B5: a timestamp regression warns and does not reject.
func TestB5WarnsOnTimestampRegression(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 1, 1, "bb")}},
	}
	err, warns := checkTierB(chain)
	if err != nil {
		t.Fatalf("timestamp regression must warn, not reject: %v", err)
	}
	if len(warns) != 1 || warns[0] != "B5:2" {
		t.Fatalf("warnings = %v, want exactly [B5:2]", warns)
	}
}

// B1: seq must increment by exactly 1.
func TestB1RejectsSeqSkip(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		{Seq: 3, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 1, 1, "bb")}},
	}
	if err, _ := checkTierB(chain); err == nil {
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
// This is what keeps the six frozen vectors byte-identical.
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

// A negative epoch orders differently in the two implementations (Go pads it
// into a string key where "-" sorts above the digits; Python compares it as an
// integer tuple element), so it is rejected rather than ordered arbitrarily.
func TestNegativeEpochRejected(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: ptr(-1), SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	if err := checkEpochPresence(cp, 2); err == nil {
		t.Error("a negative epoch must be rejected")
	}
}

// The sort key must order epochs NUMERICALLY. Without the zero-padding, "10"
// sorts before "2" as a string and Go silently disagrees with Python's tuple
// compare on published bytes. TestR4CompositeSortKey cannot catch this: it
// uses single-digit epochs, where padding is irrelevant.
func TestCompositeSortKeyIsNumericForMultiDigitEpochs(t *testing.T) {
	lo := mkTip("s1", 2, 3, 3, "aa")
	hi := mkTip("s1", 10, 11, 11, "bb")
	if tipIdentity(lo) >= tipIdentity(hi) {
		t.Fatalf("epoch 2 must sort below epoch 10, got %q >= %q", tipIdentity(lo), tipIdentity(hi))
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
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 1, 2, 2, "bb")}},
	}
	err, warns := checkTierB(chain)
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
// Only the COMMITTED bytes catch that. This is what fails if the zero-padding
// is dropped.
func TestCommittedVectorsStillValidate(t *testing.T) {
	var err error
	out := captureStdout(t, func() { err = validate("../vectors.json") })
	if err != nil {
		t.Fatalf("the committed vectors.json no longer validates: %v\noutput:\n%s", err, out)
	}
}
