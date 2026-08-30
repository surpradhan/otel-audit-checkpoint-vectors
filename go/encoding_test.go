package main

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// spliceStray puts a character outside the base64 alphabet into the middle of
// an otherwise valid encoding. A decoder that skips unknown characters -- the
// default in Python's base64.b64decode -- recovers the original signature from
// the result, so this is a mutation that a lenient validator silently repairs
// rather than one it merely fails to notice.
func spliceStray(sig string) string { return sig[:10] + "!" + sig[10:] }

// A signature string that is not valid base64 must be rejected, not repaired.
// The published signature_with_stray_character vector pins this end to end;
// this test pins the same rule at the function the vector reaches, and its
// mirror is py/test_validate.py's test_stray_character_signature_is_not_repaired.
func TestStrayCharacterSignatureIsNotRepaired(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed())
	pub := priv.Public().(ed25519.PublicKey)
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z",
		Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}}
	good := signCP(priv, cp).Signature

	// The premise: the underlying signature is genuinely valid, so the only
	// thing wrong with the mutated string is its ENCODING. Without this the
	// test below could pass against a validator that rejects everything.
	if got := rejectReason(pub, NegativeVector{Input: cp, Signature: good, MinFormatVersion: 2}); got != "" {
		t.Fatalf("the unmutated signature must verify; rejectReason = %q", got)
	}
	if got := rejectReason(pub, NegativeVector{Input: cp, Signature: spliceStray(good), MinFormatVersion: 2}); got != "signature" {
		t.Fatalf("a stray character in the signature: rejectReason = %q, want \"signature\"", got)
	}
}

// The same rule on a chain prefix's signature. verifyPrefixes decodes
// separately from rejectReason, so a strict decode in one and a lenient one in
// the other would leave a forged history acceptable at the prefix level only.
func TestStrayCharacterPrefixSignatureIsNotRepaired(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed())
	pub := priv.Public().(ed25519.PublicKey)
	chain := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		Checkpoint{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 2, 2, "bb")}})
	prefix := signCP(priv, chain[0])
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{prefix}, 2); reason != "" {
		t.Fatalf("the unmutated prefix must verify; reason = %q", reason)
	}
	prefix.Signature = spliceStray(prefix.Signature)
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{prefix}, 2); reason != "signature" {
		t.Fatalf("a stray character in a prefix signature: reason = %q, want \"signature\"", reason)
	}
}

// A present-but-null epoch is neither an epoch nor an absent one. A *int alone
// cannot tell the two apart, so it read as "no epoch": rejected at version 2
// for the right reason by accident, and silently ACCEPTED at version 1, where
// the same bytes would then feed epoch 0 into every identity comparison.
// Mirrors py/test_validate.py's test_null_epoch_rejected_at_every_version.
func TestNullEpochRejectedAtEveryVersion(t *testing.T) {
	for _, minVer := range []int{1, 2} {
		cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
			{EntryCount: 1, Epoch: nil, EpochNull: true, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
		}}
		if err := checkSchema(cp, minVer); err == nil {
			t.Fatalf("minVer=%d: an explicit null epoch was accepted; want a schema rejection", minVer)
		}
		// The contrast that makes the case: a genuinely ABSENT epoch is legal
		// at version 1, so the rejection above is about null specifically and
		// not about the version boundary doing the work.
		cp.Tips[0].EpochNull = false
		if err := checkSchema(cp, 1); err != nil {
			t.Fatalf("an absent epoch must stay legal at version 1: %v", err)
		}
	}
}

// The flag is only useful if decoding sets it: gen() builds structs directly,
// but a third party hands the validator JSON. Without this, the rule above
// holds for values no external input can produce.
func TestNullEpochSurvivesJSONRoundTrip(t *testing.T) {
	var tip Tip
	if err := json.Unmarshal([]byte(`{"entry_count":1,"epoch":null,"sequence_number":1,"stream_id":"s1","tip_hash":"aa"}`), &tip); err != nil {
		t.Fatalf("decoding a tip with a null epoch: %v", err)
	}
	if !tip.EpochNull {
		t.Fatal("a decoded null epoch was not recorded as null; it is indistinguishable from an absent one")
	}
	if tip.Epoch != nil {
		t.Fatal("a null epoch must leave Epoch nil")
	}
	var absent Tip
	if err := json.Unmarshal([]byte(`{"entry_count":1,"sequence_number":1,"stream_id":"s1","tip_hash":"aa"}`), &absent); err != nil {
		t.Fatalf("decoding a tip with no epoch: %v", err)
	}
	if absent.EpochNull {
		t.Fatal("an ABSENT epoch was recorded as null; the two must stay distinguishable in both directions")
	}
	// Re-emitting must reproduce the member it came from, or the published
	// null_epoch vector cannot exist.
	out, err := json.Marshal(tip)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"epoch":null`) {
		t.Fatalf("re-marshalled tip = %s, want an explicit \"epoch\":null", out)
	}
	out, err = json.Marshal(absent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"epoch"`) {
		t.Fatalf("re-marshalled tip = %s, want no epoch member at all", out)
	}
}

// A present-but-null tips member is not an empty array. Canonicalization
// normalizes it to [], so accepting it would let one signature cover two
// distinct documents -- and in the Python reference, iterating it is a crash
// rather than a verdict. Mirrors test_null_tips_rejected.
func TestNullTipsRejected(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: nil}
	if err := checkSchema(cp, 2); err == nil {
		t.Fatal("a null tips member was accepted; want a schema rejection")
	}
	// The collision the rule forecloses: null and [] canonicalize identically,
	// so the rejection above is the only thing separating the two documents.
	empty := cp
	empty.Tips = []Tip{}
	if err := checkSchema(empty, 2); err != nil {
		t.Fatalf("an empty tips array must stay legal: %v", err)
	}
	nullCanon, err := canonical(cp)
	if err != nil {
		t.Fatal(err)
	}
	emptyCanon, err := canonical(empty)
	if err != nil {
		t.Fatal(err)
	}
	if string(nullCanon) != string(emptyCanon) {
		t.Fatalf("this test assumes the collision it guards against:\n null:  %s\n empty: %s", nullCanon, emptyCanon)
	}
}

// A chain prefix carrying either null member must produce a reason, not feed a
// zero value into the Tier B rules. verifyPrefixes is the path a forged history
// arrives on, so it gets the check too, not just the vector's own input.
func TestNullMembersRejectedOnChainPrefixes(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed())
	pub := priv.Public().(ed25519.PublicKey)
	for name, cp := range map[string]Checkpoint{
		"null_epoch": {PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
			{EntryCount: 1, EpochNull: true, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"}}},
		"null_tips": {PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: nil},
	} {
		if _, reason := verifyPrefixes(pub, []SignedCheckpoint{signCP(priv, cp)}, 2); reason != "schema" {
			t.Fatalf("%s prefix: reason = %q, want \"schema\"", name, reason)
		}
	}
}
