package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spliceStray splices `stray` into the middle of an otherwise valid encoding.
// Every value below is one a decoder somewhere silently REPAIRS -- it recovers
// the original signature from the result -- rather than one it merely fails to
// notice, and the two references were lenient about different ones:
//
//	"!"   Python's base64.b64decode discards it by default; Go rejects it.
//	"\n"  Go's base64.StdEncoding.DecodeString ignores it by documented
//	      behaviour, and .Strict() does not change that; Python rejects it.
//	"\r"  the same, in Go.
//
// Round 1 tested only "!" -- the direction Python had just been fixed in --
// which is exactly why the newline direction survived it. Both are checked in
// both languages now.
var strayChars = []string{"!", "\n", "\r"}

func spliceStray(sig, stray string) string { return sig[:10] + stray + sig[10:] }

// b64Alphabet indexes a base64 value to its character, for mutatePadBits.
const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// mutatePadBits returns a DIFFERENT signature string that decodes to the same
// 64 bytes, by flipping the padding bits of the last data character of an
// 88-character Ed25519 signature. A 64-byte value leaves one byte in the final
// group, so that character carries four bits no byte depends on; both
// languages' decoders ignore them, and both therefore verified two distinct
// strings for one signature. Only the round-trip comparison rejects it, which
// is why the same round trip had to go into both references and not just Go.
func mutatePadBits(t *testing.T, sig string) string {
	t.Helper()
	if len(sig) != 88 || !strings.HasSuffix(sig, "==") {
		t.Fatalf("expected an 88-character Ed25519 signature ending in \"==\", got %q", sig)
	}
	i := len(sig) - 3
	v := strings.IndexByte(b64Alphabet, sig[i])
	if v < 0 {
		t.Fatalf("signature character %q is not in the base64 alphabet", sig[i])
	}
	return sig[:i] + string(b64Alphabet[v^0x0f]) + sig[i+1:]
}

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
	for _, stray := range strayChars {
		mutated := spliceStray(good, stray)
		if got := rejectReason(pub, NegativeVector{Input: cp, Signature: mutated, MinFormatVersion: 2}); got != "signature" {
			t.Errorf("stray %q in the signature: rejectReason = %q, want \"signature\"", stray, got)
		}
	}
	// Same bytes, different string: the padding bits of the last data
	// character. Nothing about the ALPHABET is wrong here, so a decoder that
	// only checks the alphabet accepts it -- which both references did.
	if got := rejectReason(pub, NegativeVector{Input: cp, Signature: mutatePadBits(t, good), MinFormatVersion: 2}); got != "signature" {
		t.Errorf("non-canonical padding bits: rejectReason = %q, want \"signature\"", got)
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
	good := prefix.Signature
	for _, stray := range strayChars {
		prefix.Signature = spliceStray(good, stray)
		if _, reason := verifyPrefixes(pub, []SignedCheckpoint{prefix}, 2); reason != "signature" {
			t.Errorf("stray %q in a prefix signature: reason = %q, want \"signature\"", stray, reason)
		}
	}
	prefix.Signature = mutatePadBits(t, good)
	if _, reason := verifyPrefixes(pub, []SignedCheckpoint{prefix}, 2); reason != "signature" {
		t.Errorf("non-canonical padding bits in a prefix signature: reason = %q, want \"signature\"", reason)
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

// An unknown member is bytes the signature does not cover. Struct decoding
// drops it, so the checkpoint was re-canonicalized WITHOUT it and the
// signature verified over bytes that are not the ones on the wire -- on a
// chain prefix, that is a forged history the linkage cannot see.
//
// The injection is done on the generated suite's JSON rather than through the
// structs, because the structs are exactly what cannot express it. Mirrored by
// py/test_validate.py's test_unknown_member_is_rejected, which pins the same
// four positions in the other reference -- there against a suite re-signed
// after the injection, because that reference had no member-set rule at all
// and was only ever rejecting the broken signature.
func TestUnknownMemberIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   func(suite map[string]any)
	}{
		{"on a checkpoint", func(s map[string]any) {
			v := s["vectors"].([]any)[0].(map[string]any)
			v["input"].(map[string]any)["injected"] = "not covered by the signature"
		}},
		{"on a tip", func(s map[string]any) {
			for _, raw := range s["vectors"].([]any) {
				v := raw.(map[string]any)
				tips := v["input"].(map[string]any)["tips"].([]any)
				if len(tips) > 0 {
					tips[0].(map[string]any)["injected"] = "not covered by the signature"
					return
				}
			}
			t.Fatal("no vector with a tip to inject into")
		}},
		{"on a signed chain prefix", func(s map[string]any) {
			for _, raw := range s["vectors"].([]any) {
				v := raw.(map[string]any)
				chain, ok := v["chain"].([]any)
				if !ok || len(chain) == 0 {
					continue
				}
				cp := chain[0].(map[string]any)["input"].(map[string]any)
				cp["injected"] = "forged history"
				return
			}
			t.Fatal("no vector with a chain prefix to inject into")
		}},
		// The wrapper, not the checkpoint inside it. Nothing canonicalizes the
		// wrapper, so a member injected here changes no signed bytes at all --
		// the one position where "the signature breaks anyway" was never even
		// accidentally true in either reference.
		{"on a chain prefix wrapper", func(s map[string]any) {
			for _, raw := range s["vectors"].([]any) {
				v := raw.(map[string]any)
				chain, ok := v["chain"].([]any)
				if !ok || len(chain) == 0 {
					continue
				}
				chain[0].(map[string]any)["injected"] = "forged history"
				return
			}
			t.Fatal("no vector with a chain prefix to inject into")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(gen())
			if err != nil {
				t.Fatal(err)
			}
			var suite map[string]any
			if err := json.Unmarshal(raw, &suite); err != nil {
				t.Fatal(err)
			}
			tc.at(suite)
			out, err := json.Marshal(suite)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "injected.json")
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := validate(path); err == nil {
				t.Fatal("a suite carrying an unknown member was accepted; the signature does not cover it")
			}
		})
	}
}

// The premise of the test above: without the injection the same round trip
// through a generic map still validates, so the rejections there are about the
// injected member and not about the round trip mangling something.
func TestRoundTrippedSuiteStillValidates(t *testing.T) {
	raw, err := json.Marshal(gen())
	if err != nil {
		t.Fatal(err)
	}
	var suite map[string]any
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(suite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "roundtrip.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validate(path); err != nil {
		t.Fatalf("the unmodified suite must survive a round trip through a generic map: %v", err)
	}
}

// The generator asserts every negative's expect field before writing the file,
// so a vector whose expect is wrong can never be published. Spec 5.6 claimed
// this assertion existed; it did not. Feeding it a deliberately wrong
// expectation is what shows the loop is connected to anything.
func TestGenAssertsEveryNegativeExpectation(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed())
	pub := priv.Public().(ed25519.PublicKey)
	negs := gen().Negatives
	if err := checkNegativeExpectations(pub, negs); err != nil {
		t.Fatalf("the generated suite must satisfy its own assertion: %v", err)
	}
	if len(negs) == 0 {
		t.Fatal("no negatives to check")
	}
	for i := range negs {
		mutated := append([]NegativeVector(nil), negs...)
		// "no_such_reason" is not a reason rejectReason can ever return, so
		// this is a wrong expectation at every index in turn.
		mutated[i].Expect = "no_such_reason"
		if err := checkNegativeExpectations(pub, mutated); err == nil {
			t.Fatalf("negative %d (%s) with a wrong expect field was accepted", i, negs[i].Name)
		}
	}
}

// wantNULCanonical is the canonical form of a checkpoint whose two tips are
// "a" and "a\x00" at the same epoch, supplied in the wrong order. The same
// literal appears in py/test_validate.py as WANT_NUL_CANONICAL: the two
// references must agree on these exact bytes, not merely each be internally
// consistent.
const wantNULCanonical = `{"prev_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":[{"entry_count":1,"epoch":0,"sequence_number":1,"stream_id":"a","tip_hash":"aa"},{"entry_count":2,"epoch":0,"sequence_number":2,"stream_id":"a\u0000","tip_hash":"bb"}]}`

// The published sort rule is "stream_id ascending by Unicode code point, then
// epoch ascending numerically". The old key flattened that into
// stream_id + "\x00" + zero-padded epoch, which reproduces the rule only while
// no stream_id contains a NUL: with tips "a" and "a\x00" at the same epoch the
// flattened key compares 0x00 against the '0' of the padding and orders them
// the OTHER WAY ROUND from the rule -- and from Python's tuple compare, which
// is exactly the disagreement on signed bytes this repo exists to rule out.
func TestNULInStreamIDSortsByThePublishedRule(t *testing.T) {
	lo := Tip{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "a", TipHash: "aa"}
	hi := Tip{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "a\x00", TipHash: "bb"}
	if !lessTip(lo, hi) {
		t.Fatalf("%q must sort below %q by Unicode code point", lo.StreamID, hi.StreamID)
	}
	// Supplied in the wrong order, so the sort has to fix it.
	cb, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z",
		Tips: []Tip{hi, lo}})
	if err != nil {
		t.Fatal(err)
	}
	if string(cb) != wantNULCanonical {
		t.Fatalf("canonical bytes:\n got:  %s\n want: %s", cb, wantNULCanonical)
	}
}

// A conformance suite is ONE JSON document. A json.Decoder reads one value and
// stops, so DisallowUnknownFields said nothing about what follows: appending a
// second object -- or arbitrary text -- to the published file left it PASSING
// here while Python's json.load rejected it. Mirrors
// py/test_validate.py's test_trailing_data_after_the_suite_is_rejected.
func TestTrailingDataAfterSuiteIsRejected(t *testing.T) {
	raw, err := json.Marshal(gen())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// The premise: the same bytes with nothing appended validate, so the
	// rejections below are about the trailing data and nothing else.
	clean := filepath.Join(dir, "clean.json")
	if err := os.WriteFile(clean, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validate(clean); err != nil {
		t.Fatalf("the unmodified suite must validate: %v", err)
	}
	for _, tail := range []string{
		`{"format_version":9}`,          // a second, well-formed JSON document
		"this is not JSON at all",       // arbitrary text
		"\n\n[1,2,3]",                   // a document of another type, after blank lines
		`{"vectors":[],"negatives":[]}`, // a suite-shaped second document
	} {
		t.Run(tail, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trailing.json")
			if err := os.WriteFile(path, append(append([]byte(nil), raw...), tail...), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := validate(path); err == nil {
				t.Fatalf("a file with %q appended after the suite was accepted; it is not a single JSON document", tail)
			}
		})
	}
}

// The third decode site: the positive path in validate(). rejectReason and
// verifyPrefixes are covered above, but a must-accept vector's own signature
// is decoded separately, and a strict decode in two places out of three leaves
// exactly one lenient. End to end on the generated suite, which is the shape a
// third party actually hands the validator. Mirrors
// py/test_validate.py's test_non_canonical_signature_encoding_is_rejected.
func TestNonCanonicalSignatureEncodingIsRejectedEndToEnd(t *testing.T) {
	mutations := map[string]func(string) string{}
	for _, stray := range strayChars {
		mutations["stray "+stray] = func(sig string) string { return spliceStray(sig, stray) }
	}
	mutations["padding bits"] = func(sig string) string { return mutatePadBits(t, sig) }

	for name, mutate := range mutations {
		for _, where := range []string{"a positive vector's own signature", "a chain prefix's signature"} {
			t.Run(name+" in "+where, func(t *testing.T) {
				suite := gen()
				switch where {
				case "a positive vector's own signature":
					suite.Vectors[0].Signature = mutate(suite.Vectors[0].Signature)
				default:
					done := false
					for i := range suite.Vectors {
						if len(suite.Vectors[i].Chain) > 0 {
							suite.Vectors[i].Chain[0].Signature = mutate(suite.Vectors[i].Chain[0].Signature)
							done = true
							break
						}
					}
					if !done {
						t.Fatal("no vector with a chain prefix to mutate")
					}
				}
				raw, err := json.Marshal(suite)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "mutated.json")
				if err := os.WriteFile(path, raw, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := validate(path); err == nil {
					t.Fatal("a non-canonically encoded signature was accepted; the decoder repaired it")
				}
			})
		}
	}
}
