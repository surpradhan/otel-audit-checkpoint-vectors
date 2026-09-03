package main

import (
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
//
// "a" and "a\x00" stand in a proper prefix relationship (differing stream_id
// LENGTHS, one a prefix of the other), which is what makes this pair the
// discriminator: a NUL is the lowest possible byte, so it sorts at or below
// ANY separator byte a flattened key might choose -- not only \x00 -- so this
// one pair catches the whole mutation class in one shot, including the
// specific \x00 -> ~ swap that took five review rounds on Task 3 to surface
// (docs/superpowers/specs/2026-08-26-checkpoint-detection-semantics-design.md).
// tipKey has no separator to collide with, so this is a regression guard
// against reintroducing the flattened encoding, not a live ambiguity today.
//
// Mirrors py/test_validate.py's
// test_nul_in_stream_id_sorts_by_the_published_rule.
func TestNULInStreamIDSortsByThePublishedRule(t *testing.T) {
	lo := Tip{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "a", TipHash: "aa"}
	hi := Tip{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "a\x00", TipHash: "bb"}
	// Two DIFFERENT stream_ids standing in a prefix relationship must still be
	// two DISTINCT tip identities -- the concern a flattened separator-based
	// key put at risk, since a poorly chosen separator can make two distinct
	// stream_ids collide once epoch is folded in.
	if tipIdentity(lo) == tipIdentity(hi) {
		t.Fatalf("%q and %q must be distinct tip identities: they are different stream_ids", lo.StreamID, hi.StreamID)
	}
	if !lessTip(lo, hi) {
		t.Errorf("%q must sort below %q by Unicode code point", lo.StreamID, hi.StreamID)
	}
	if lessTip(hi, lo) {
		t.Errorf("%q must NOT sort below %q", hi.StreamID, lo.StreamID)
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

// public_key_hex missing, null, wrong-typed, or the wrong length must not
// crash validate(): decoding leaves the Go string field at its zero value for
// a missing or null member, and hex.DecodeString happily returns a short (or
// empty) byte slice for "abcd" or "" -- ed25519.Verify then panics on
// anything but exactly 32 bytes, rather than erroring, the moment a signature
// actually needs checking. Checked unconditionally right after the decode, so
// a bad key fails the whole suite even with nothing in it that would have
// needed the key at all. Mirrors py/test_validate.py's
// test_malformed_public_key_hex_rejects_cleanly, which pins the same property
// against Python's own (already-eager) public_key_hex handling.
//
// non_string is included for the same reason Python includes it -- it names
// the same JSON shape -- but it does NOT exercise the new check: a bare
// number for a string-typed field fails strict decoding of the envelope
// itself (dec.Decode(&suite), above) before public_key_hex is ever looked at.
// Its wantErr pins that distinct, pre-existing failure specifically, so this
// subtest cannot pass by way of the wrong check firing.
func TestMalformedPublicKeyHexRejectsCleanly(t *testing.T) {
	mutations := []struct {
		name    string
		mutate  func(map[string]json.RawMessage)
		wantErr string
	}{
		{"missing", func(m map[string]json.RawMessage) { delete(m, "public_key_hex") }, "public_key_hex is invalid"},
		{"null", func(m map[string]json.RawMessage) { m["public_key_hex"] = json.RawMessage("null") }, "public_key_hex is invalid"},
		{"wrong_length", func(m map[string]json.RawMessage) { m["public_key_hex"] = json.RawMessage(`"abcd"`) }, "public_key_hex is invalid"},
		{"non_string", func(m map[string]json.RawMessage) { m["public_key_hex"] = json.RawMessage("12345") }, "cannot unmarshal"},
	}

	suiteAsMap := func(t *testing.T, vectors []Vector, negatives []NegativeVector) map[string]json.RawMessage {
		t.Helper()
		s := gen()
		s.Vectors = vectors
		s.Negatives = negatives
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	writeAndValidate := func(t *testing.T, m map[string]json.RawMessage) error {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "suite.json")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return validate(path)
	}

	check := func(t *testing.T, m map[string]json.RawMessage, name, wantErr string) {
		t.Helper()
		err := writeAndValidate(t, m)
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("public_key_hex %s: want an error containing %q, got %v", name, wantErr, err)
		}
	}

	// An otherwise-empty suite: the bad key alone must still fail it cleanly,
	// with nothing that would ever have reached ed25519.Verify.
	for _, tc := range mutations {
		t.Run("empty suite/"+tc.name, func(t *testing.T) {
			m := suiteAsMap(t, nil, nil)
			tc.mutate(m)
			check(t, m, tc.name, tc.wantErr)
		})
	}

	// A real vector present changes nothing about how the key itself fails --
	// this is the shape that used to panic in the positive-vector loop's own
	// direct ed25519.Verify call, and the exact shape issue #12 reported.
	firstVector := gen().Vectors[:1]
	for _, tc := range mutations {
		t.Run("with a real vector/"+tc.name, func(t *testing.T) {
			m := suiteAsMap(t, firstVector, nil)
			tc.mutate(m)
			check(t, m, tc.name, tc.wantErr)
		})
	}

	// A real NEGATIVE present exercises the other reachable ed25519.Verify
	// call site, rejectReason -- which panicked at a DIFFERENT line than the
	// one in issue #12's own trace on pre-fix code. Picked by Expect ==
	// "signature" specifically: a schema-rejected negative never reaches
	// Verify regardless of the key, so it would not have caught this bug.
	var sigRejectedNegative NegativeVector
	for _, nv := range gen().Negatives {
		if nv.Expect == "signature" {
			sigRejectedNegative = nv
			break
		}
	}
	if sigRejectedNegative.Name == "" {
		t.Fatal(`no generated negative vector has Expect == "signature"; needed one that reaches ed25519.Verify`)
	}
	for _, tc := range mutations {
		t.Run("with a real negative/"+tc.name, func(t *testing.T) {
			m := suiteAsMap(t, nil, []NegativeVector{sigRejectedNegative})
			tc.mutate(m)
			check(t, m, tc.name, tc.wantErr)
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

// A JSON null tip element is not a zero tip. Go's UnmarshalJSON convention
// leaves the zero value for null, which made `"tips": [null]` decode into a
// full tip of zero values and validate at version 1 -- while the Python
// reference, which type-checks the element, rejected it at every version. The
// two agreed at version 2 only by accident: the zero tip has no epoch, so the
// epoch-required rule caught it there. Mirrors
// py/test_validate.py's test_null_tip_element_rejected_at_every_version.
func TestNullTipElementRejected(t *testing.T) {
	var tip Tip
	if err := json.Unmarshal([]byte(`null`), &tip); err == nil {
		t.Fatal("a null tip element was accepted; a null is not a tip")
	}
	// It is the ELEMENT that must be rejected, so the enclosing checkpoint
	// fails too -- decoding a tip in isolation is not where a suite arrives.
	for _, minVer := range []int{1, 2} {
		var cp Checkpoint
		body := `{"prev_hash":"` + sha256Empty + `","seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":[null]}`
		if err := json.Unmarshal([]byte(body), &cp); err == nil {
			t.Fatalf("minVer=%d: a checkpoint with a null tip element decoded cleanly into %+v", minVer, cp.Tips)
		}
	}
	// The contrast: a real tip object still decodes, so the rejection above is
	// about null specifically and not about the method refusing everything.
	var ok Tip
	if err := json.Unmarshal([]byte(`{"entry_count":1,"epoch":0,"sequence_number":1,"stream_id":"s1","tip_hash":"aa"}`), &ok); err != nil {
		t.Fatalf("an ordinary tip must still decode: %v", err)
	}
}

// A wrong-typed epoch must produce a clean rejection in both references, not a
// decode panic in one and a traceback in the other. Go's *int rejects every
// value below while decoding; the Python mirror
// (test_wrong_typed_epoch_returns_a_reason) type-gates before comparing,
// because `ep < 0` against a str raised TypeError and `epoch: true` /
// `epoch: 1.0` passed there while failing here.
func TestWrongTypedEpochIsRejectedWhileDecoding(t *testing.T) {
	for _, raw := range []string{`"1"`, `[1]`, `true`, `1.0`, `{"a":1}`} {
		var tip Tip
		body := `{"entry_count":1,"epoch":` + raw + `,"sequence_number":1,"stream_id":"s1","tip_hash":"aa"}`
		if err := json.Unmarshal([]byte(body), &tip); err == nil {
			t.Errorf("epoch %s was accepted; epoch must be an integer", raw)
		}
	}
	var tip Tip
	if err := json.Unmarshal([]byte(`{"entry_count":1,"epoch":3,"sequence_number":1,"stream_id":"s1","tip_hash":"aa"}`), &tip); err != nil {
		t.Fatalf("an integer epoch must still decode: %v", err)
	}
}

// The two marshal paths must agree on EVERY member except `epoch`. The null
// path used to re-declare all five fields in a parallel anonymous struct, so a
// sixth field added to Tip would appear in the signed bytes of an ordinary tip
// and vanish from those of a null-epoch one -- silently, and only for the tips
// whose shape is already the subtle one. This test is derived from the struct
// rather than from a second hand-written list, so it cannot drift the same way
// the code it guards did.
func TestNullEpochMarshalPathDropsNoField(t *testing.T) {
	tip := Tip{EntryCount: 7, Epoch: nil, SequenceNumber: 9, StreamID: "s1", TipHash: "aa"}
	normal := tip
	normal.Epoch = ptr(4)

	decode := func(v Tip) map[string]json.RawMessage {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	nullTip := tip
	nullTip.EpochNull = true
	got, want := decode(nullTip), decode(normal)
	if string(got["epoch"]) != "null" {
		t.Fatalf("the null path must emit an explicit null epoch, got %s", got["epoch"])
	}
	// Every field the ordinary path emits, the null path must emit too, with
	// the same bytes -- epoch excepted, which is the whole point of the path.
	delete(got, "epoch")
	delete(want, "epoch")
	if len(got) != len(want) {
		t.Fatalf("the two marshal paths emit different member sets:\n null:   %v\n normal: %v",
			slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want)))
	}
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("the null-epoch path dropped %q; it is in the ordinary path's output but not in the signed bytes here", k)
			continue
		}
		if string(gv) != string(wv) {
			t.Errorf("member %q: null path %s, ordinary path %s", k, gv, wv)
		}
	}
	// The premise: the ordinary path really does carry every field of the
	// struct, so "agrees with the ordinary path" is a meaningful bar.
	if n := reflect.TypeOf(Tip{}).NumField(); len(want)+1 != n-1 {
		t.Fatalf("Tip has %d fields (one of them the unserialized EpochNull) but the ordinary path emits %d members plus epoch; the counts must match or this test is checking a stale field set",
			n, len(want))
	}
}

// wantShorterLaterCanonical is the canonical form of a checkpoint whose two
// tips are "aa" and "b". The same literal appears in py/test_validate.py as
// WANT_SHORTER_LATER_CANONICAL: the two references must agree on these exact
// bytes, not merely each be internally consistent.
const wantShorterLaterCanonical = `{"prev_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":[{"entry_count":1,"epoch":0,"sequence_number":1,"stream_id":"aa","tip_hash":"aa"},{"entry_count":2,"epoch":0,"sequence_number":2,"stream_id":"b","tip_hash":"bb"}]}`

// The published rule is "stream_id ascending by Unicode code point": "aa"
// sorts BELOW "b" because the first code point decides, however much longer
// "aa" is. An implementation that orders by length first and only then
// lexicographically -- a natural shape if the key is built from a
// length-prefixed or fixed-width encoding -- puts "b" first and produces
// different signed bytes.
//
// Nothing in the published suite could tell the two apart. Every stream_id in
// it is a 36-character UUID, so length never breaks a tie;
// TestNULInStreamIDSortsByThePublishedRule does not discriminate either,
// because "a" and "a\x00" stand in a prefix relationship and prefix pairs
// order the same way under both rules -- as do all the other pairs the suite's
// "not pinned" notes call out. This case needs a shorter, lexicographically
// LATER id against a longer, lexicographically EARLIER one, which is the one
// shape that separates them.
//
// Mirrors py/test_validate.py's
// test_stream_id_sorts_by_code_point_not_length.
func TestStreamIDSortsByCodePointNotLength(t *testing.T) {
	lo := Tip{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "aa", TipHash: "aa"}
	hi := Tip{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: "b", TipHash: "bb"}
	if !lessTip(lo, hi) {
		t.Errorf("%q must sort below %q: the first code point decides, not the length",
			lo.StreamID, hi.StreamID)
	}
	if lessTip(hi, lo) {
		t.Errorf("%q must NOT sort below %q; the comparator is ordering by length",
			hi.StreamID, lo.StreamID)
	}
	// Supplied in the wrong order, so the sort has to fix it -- and so the
	// rule is pinned where it actually bites, in the signed bytes.
	cb, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z",
		Tips: []Tip{hi, lo}})
	if err != nil {
		t.Fatal(err)
	}
	if string(cb) != wantShorterLaterCanonical {
		t.Fatalf("canonical bytes:\n got:  %s\n want: %s", cb, wantShorterLaterCanonical)
	}
}

// An unknown member must be reported wherever it sits, including on a negative
// vector that was ALREADY going to be rejected for the reason its `expect`
// names. This reference fails the whole file while decoding, so it never had
// the problem; the Python reference compared only the reason TOKEN, so an
// unknown member injected into a negative whose `expect` is already "schema"
// still returned "schema", matched, and PASSED. The two must agree, so both
// hold the case.
//
// Mirrors py/test_validate.py's
// test_unknown_member_is_not_masked_by_the_expected_reason.
func TestUnknownMemberOnANegativeIsNotMaskedByItsExpectedReason(t *testing.T) {
	raw, err := json.Marshal(gen())
	if err != nil {
		t.Fatal(err)
	}
	var suite map[string]any
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	injected := ""
	for _, e := range suite["negatives"].([]any) {
		nv := e.(map[string]any)
		if nv["expect"] != "schema" {
			continue
		}
		nv["input"].(map[string]any)["injected"] = "not covered by the signature"
		injected = nv["name"].(string)
		break
	}
	if injected == "" {
		t.Fatal("no negative with expect \"schema\" to inject into")
	}
	out, err := json.Marshal(suite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "masked.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	err = validate(path)
	if err == nil {
		t.Fatalf("an unknown member on negative %q was accepted because it was already expected to fail for \"schema\"", injected)
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("negative %q was rejected, but not as an unknown member: %v", injected, err)
	}
}
