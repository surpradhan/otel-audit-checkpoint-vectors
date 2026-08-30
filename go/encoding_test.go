package main

import (
	"crypto/ed25519"
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
