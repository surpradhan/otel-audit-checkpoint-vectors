package main

// Cross-product position tests.
//
// go/positional_test.go closes ONE factor of "position": the index of a
// checkpoint within a chain. Position is a product of at least four:
//
//	(chain index) x (tip index within a checkpoint)
//	              x (prefix vs the vector's own checkpoint)
//	              x (vector-list index in the suite file)
//
// plus two the rules do not own at all: the order of the warning list a
// verifier reports, and the order of the chain array it was handed. A mutation
// of the form "apply this check only at position X" escapes on any factor left
// unswept, so each rule below is asserted across every factor that applies to
// it. Mirrored in py/test_validate.py.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// xpTips builds k tips for checkpoint i, all at epoch 0 with distinct streams,
// supplied in REVERSE identity order so sorting is actually exercised.
func xpTips(i, k int) []Tip {
	tips := make([]Tip, 0, k)
	for j := k; j >= 1; j-- {
		tips = append(tips, mkTip(posStream(100*i+j), 0, j, j, fmt.Sprintf("%02x", j)))
	}
	return tips
}

// runValidateOnSuite writes a suite to a temp file and validates it, returning
// the error and whatever was printed.
func runValidateOnSuite(t *testing.T, suite Suite, name string) (error, string) {
	t.Helper()
	out, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name+".json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	var verr error
	captured := captureStdout(t, func() { verr = validate(path) })
	return verr, captured
}

// ---- factor: tip index within a checkpoint ------------------------------

// The epoch boundary and the non-negativity guard must fire at EVERY tip
// index, and at every magnitude. Both epoch negatives in the suite put their
// defect on the last tip of two, so a check reading only the last tip -- or
// only the first -- passes the whole published suite.
func TestEpochPresenceFiresAtEveryTipIndex(t *testing.T) {
	const k = 4
	clean := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: xpTips(1, k)}
	if err := checkEpochPresence(clean, 2); err != nil {
		t.Fatalf("a clean version-2 checkpoint was rejected: %v", err)
	}
	for d := 0; d < k; d++ {
		t.Run(fmt.Sprintf("missing_tip_%d", d), func(t *testing.T) {
			cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: xpTips(1, k)}
			cp.Tips[d].Epoch = nil
			if err := checkEpochPresence(cp, 2); err == nil {
				t.Fatalf("tip %d of %d missing epoch was accepted at version 2", d, k)
			}
		})
		for _, mag := range []int{-1, -3, -1000} {
			t.Run(fmt.Sprintf("negative_tip_%d_epoch_%d", d, mag), func(t *testing.T) {
				cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: xpTips(1, k)}
				cp.Tips[d].Epoch = ptr(mag)
				if err := checkEpochPresence(cp, 2); err == nil {
					t.Fatalf("tip %d of %d with epoch %d was accepted", d, k, mag)
				}
			})
		}
	}
}

// xpInterleaved returns a two-checkpoint chain whose tips interleave: cp0
// carries the odd-numbered streams and cp1 the even ones, so replacing cp1's
// tip at index d with cp0's stream 2d+1 keeps it at identity position d.
func xpInterleaved(t *testing.T, k int) []Checkpoint {
	t.Helper()
	a := make([]Tip, 0, k)
	b := make([]Tip, 0, k)
	for j := 0; j < k; j++ {
		a = append(a, mkTip(posStream(2*j+1), 0, j+1, j+1, fmt.Sprintf("a%d", j)))
		b = append(b, mkTip(posStream(2*j+2), 0, j+1, j+1, fmt.Sprintf("b%d", j)))
	}
	return []Checkpoint{
		{Seq: 1, Timestamp: posTS(100), Tips: a},
		{Seq: 2, Timestamp: posTS(110), Tips: b},
	}
}

// B3 must fire for a duplicate involving ANY tip index in either checkpoint.
// Every B3 vector before this round duplicated a checkpoint's only tip.
func TestB3FiresForEveryTipIndexPair(t *testing.T) {
	const k = 4
	for a := 0; a < k; a++ {
		for b := 0; b < k; b++ {
			t.Run(fmt.Sprintf("cp0_tip_%d_cp1_tip_%d", a, b), func(t *testing.T) {
				cps := xpInterleaved(t, k)
				cps[1].Tips[b].StreamID = cps[0].Tips[a].StreamID
				err, _ := checkTierB(linkChain(t, cps...))
				if err == nil {
					t.Fatalf("identity of cp0 tip %d repeated at cp1 tip %d was accepted", a, b)
				}
				if !strings.HasPrefix(err.Error(), "B3:") {
					t.Fatalf("cp0 tip %d / cp1 tip %d rejected by %v; want a B3 rejection", a, b, err)
				}
			})
		}
	}
}

// B4 must fire for an epoch change on ANY tip index, interior ones included.
func TestB4FiresAtEveryTipIndex(t *testing.T) {
	const k = 4
	for d := 0; d < k; d++ {
		t.Run(fmt.Sprintf("tip_%d", d), func(t *testing.T) {
			cps := xpInterleaved(t, k)
			cps[1].Tips[d].StreamID = posStream(2*d + 1) // re-commit cp0's stream
			cps[1].Tips[d].Epoch = ptr(1)
			err, warns := checkTierB(linkChain(t, cps...))
			if err != nil {
				t.Fatalf("cross-epoch re-commit on tip %d is advisory, not a rejection: %v", d, err)
			}
			want := []string{"B4:" + posStream(2*d+1)}
			if !slices.Equal(warns, want) {
				t.Fatalf("epoch change on tip %d: warnings %v, want %v", d, warns, want)
			}
		})
	}
}

// canonical() must reject a duplicate identity at ANY pair of tip indices,
// including one involving tips[0].
func TestDuplicateTipIdentityAtEveryTipIndexPair(t *testing.T) {
	const k = 4
	for a := 0; a < k; a++ {
		for b := a + 1; b < k; b++ {
			t.Run(fmt.Sprintf("%d_and_%d", a, b), func(t *testing.T) {
				cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: xpTips(1, k)}
				cp.Tips[b].StreamID = cp.Tips[a].StreamID
				cp.Tips[b].Epoch = ptr(tipEpoch(cp.Tips[a]))
				if _, err := canonical(cp); err == nil {
					t.Fatalf("tips %d and %d share an identity but canonical() accepted the checkpoint", a, b)
				}
			})
		}
	}
}

// The tip sort must be a FULL sort, not a single adjacent-swap pass. No
// published positive needed more than one swap before this round, so a
// one-pass bubble would have reproduced every canonical field in the suite.
func TestCanonicalFullySortsTips(t *testing.T) {
	const k = 5
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: xpTips(1, k)}
	cb, err := canonical(cp)
	if err != nil {
		t.Fatal(err)
	}
	var got Checkpoint
	if err := json.Unmarshal(cb, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tips) != k {
		t.Fatalf("canonical dropped tips: got %d, want %d", len(got.Tips), k)
	}
	for i := 1; i < len(got.Tips); i++ {
		if !lessTip(got.Tips[i-1], got.Tips[i]) {
			t.Fatalf("canonical tips are not fully sorted at index %d: %s then %s\n%s",
				i, got.Tips[i-1].StreamID, got.Tips[i].StreamID, cb)
		}
	}
}

// ---- factor: chain index, for the canonical-vs-as-received rule ---------

// B2 hashes canonical bytes at EVERY chain index, chain[0] included.
// advisory_middle_chain_unsorted_prefix_tips puts its unsorted prefix at index
// 1, so a validator special-casing chain[0] passes it.
func TestB2HashesCanonicalBytesAtEveryChainIndex(t *testing.T) {
	const n = 4
	for d := 0; d < n-1; d++ {
		t.Run(fmt.Sprintf("unsorted_at_%d", d), func(t *testing.T) {
			cps := make([]Checkpoint, n)
			for i := range cps {
				k := 1
				if i == d {
					k = 3 // three tips, supplied in reverse identity order
				}
				cps[i] = Checkpoint{Seq: i + 1, Timestamp: posTS(100 + 10*i), Tips: xpTips(i+1, k)}
			}
			chain := linkChain(t, cps...)

			// The case only discriminates if the two byte strings differ.
			canonBytes, err := canonical(chain[d])
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(chain[d])
			if err != nil {
				t.Fatal(err)
			}
			if string(canonBytes) == string(raw) {
				t.Fatalf("checkpoint %d is not discriminating: its tips are already in identity order", d)
			}
			if err, _ := checkTierB(chain); err != nil {
				t.Fatalf("chain whose checkpoint %d supplies tips out of identity order was rejected: %v", d, err)
			}
		})
	}
}

// ---- factor: prefix vs the vector's own checkpoint ----------------------

// The epoch boundary applies to a vector's OWN input whether or not it carries
// chain context. Every epoch-boundary negative before this round was chainless,
// so skipping the own-input check for chain carriers passed the whole suite.
func TestOwnInputEpochCheckedWithAndWithoutChain(t *testing.T) {
	pub := testPub(t)
	bad := Checkpoint{PrevHash: sha256Empty, Seq: 2, Timestamp: posTS(110), Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: posStream(1), TipHash: "aa"},
		{EntryCount: 2, Epoch: ptr(0), SequenceNumber: 2, StreamID: posStream(2), TipHash: "bb"},
	}}
	prefix := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: []Tip{
		mkTip(posStream(9), 0, 9, 9, "99"),
	}}
	for _, tc := range []struct {
		name  string
		chain []SignedCheckpoint
	}{
		{"chainless", nil},
		{"with_chain", []SignedCheckpoint{signed(t, prefix)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nv := NegativeVector{
				Name: "x", Expect: "schema", Input: bad,
				Signature: signed(t, bad).Signature, Chain: tc.chain, MinFormatVersion: 2,
			}
			if got := rejectReason(pub, nv); got != "schema" {
				t.Fatalf("own input missing epoch (%s): reason = %q, want \"schema\"", tc.name, got)
			}
		})
	}
}

// A chain entry with no signature (or no input at all) must produce a reason,
// never a crash. Go decodes the absent keys into zero values; Python read
// sc["signature"] directly and raised KeyError, so the two references
// disagreed on third-party input.
//
// An entry with no "input" at all decodes to a zero Checkpoint, whose tips are
// nil rather than empty -- checkSchema names that "schema", ahead of the
// signature check. Mirrored by py/test_validate.py's
// test_malformed_chain_entry_rejects_cleanly, which reads a missing "input"
// the same way.
func TestMalformedChainEntryRejectsCleanly(t *testing.T) {
	pub := testPub(t)
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: []Tip{
		mkTip(posStream(1), 0, 1, 1, "aa"),
	}}
	for _, tc := range []struct {
		name string
		sc   SignedCheckpoint
		want string
	}{
		{"no_signature", SignedCheckpoint{Input: cp}, "signature"},
		{"empty_entry", SignedCheckpoint{}, "schema"},
		{"not_base64", SignedCheckpoint{Input: cp, Signature: "!!!not base64!!!"}, "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, reason := verifyPrefixes(pub, []SignedCheckpoint{tc.sc}, 2); reason != tc.want {
				t.Fatalf("%s: reason = %q, want %q", tc.name, reason, tc.want)
			}
		})
	}
}

// ---- factor: the order of the chain array itself -----------------------

// The chain array's order is the producer's claim about history, so it is
// verified as given. A validator that sorted the prefixes by seq would silently
// repair a reordered chain, and every other chain in the suite arrives ordered.
func TestChainPrefixOrderIsPreserved(t *testing.T) {
	pub := testPub(t)
	cps := linkChain(t,
		Checkpoint{Seq: 1, Timestamp: posTS(100), Tips: []Tip{mkTip(posStream(1), 0, 1, 1, "11")}},
		Checkpoint{Seq: 2, Timestamp: posTS(110), Tips: []Tip{mkTip(posStream(2), 0, 2, 2, "22")}},
		Checkpoint{Seq: 3, Timestamp: posTS(120), Tips: []Tip{mkTip(posStream(3), 0, 3, 3, "33")}})
	reversed := []SignedCheckpoint{signed(t, cps[1]), signed(t, cps[0])}
	full, reason := verifyPrefixes(pub, reversed, 2)
	if reason != "" {
		t.Fatalf("both prefixes are correctly signed, but verifyPrefixes returned %q", reason)
	}
	if len(full) != 2 || full[0].Seq != 2 || full[1].Seq != 1 {
		t.Fatalf("verifyPrefixes reordered the chain: seqs %v, want [2 1]", []int{full[0].Seq, full[1].Seq})
	}
	if err, _ := checkTierB(append(full, cps[2])); err == nil {
		t.Fatal("a chain supplied newest-first was accepted; the array order is the claim being verified")
	}
}

// ---- factor: the warning list's own index ------------------------------

// expect_warnings is compared element-wise over the WHOLE list. Every published
// expectation is correct, so no vector can catch a comparison weakened to "the
// first element" or "the shorter prefix" -- only feeding a wrong expectation at
// each index in turn can.
func TestWarningComparisonIsPositionGeneric(t *testing.T) {
	full := gen()
	var v Vector
	for _, cand := range full.Vectors {
		if cand.Name == "advisory_middle_chain_unsorted_prefix_tips" {
			v = cand
		}
	}
	if v.Name == "" {
		t.Fatal("advisory_middle_chain_unsorted_prefix_tips not found in gen() output")
	}
	if len(v.ExpectWarnings) < 4 {
		t.Fatalf("this test needs a vector with at least four warnings, got %v", v.ExpectWarnings)
	}

	mutations := map[string][]string{}
	for i := range v.ExpectWarnings {
		bad := slices.Clone(v.ExpectWarnings)
		bad[i] = "B9:wrong-at-index-" + fmt.Sprint(i)
		mutations[fmt.Sprintf("corrupt_index_%d", i)] = bad
	}
	mutations["truncated"] = slices.Clone(v.ExpectWarnings[:len(v.ExpectWarnings)-1])
	mutations["extra_appended"] = append(slices.Clone(v.ExpectWarnings), "B9:extra")
	mutations["permuted_tail"] = append(slices.Clone(v.ExpectWarnings[:len(v.ExpectWarnings)-2]),
		v.ExpectWarnings[len(v.ExpectWarnings)-1], v.ExpectWarnings[len(v.ExpectWarnings)-2])

	for name, bad := range mutations {
		t.Run(name, func(t *testing.T) {
			mv := v
			mv.ExpectWarnings = bad
			suite := Suite{
				FormatVersion: full.FormatVersion, Algorithm: full.Algorithm,
				SeedHex: full.SeedHex, PublicKeyHex: full.PublicKeyHex,
				Vectors: []Vector{mv},
			}
			verr, out := runValidateOnSuite(t, suite, "warnings_"+name)
			if verr == nil {
				t.Fatalf("expect_warnings %v (%s) was accepted; actual is %v\noutput:\n%s",
					bad, name, v.ExpectWarnings, out)
			}
			if !strings.Contains(verr.Error(), "warnings") {
				t.Fatalf("%s rejected, but not for the warning mismatch: %v", name, verr)
			}
		})
	}
}

// ---- factor: vector-list index in the suite file -----------------------

var checkedLine = regexp.MustCompile(
	`checked: (\d+) positive \((\d+) through Tier B\) \+ (\d+) negative`)

// The rules cannot fix a harness that skips entries: a loop truncated to its
// first element, or a Tier B block that runs only for the first chain-carrying
// vector, leaves every rule intact and every gate green. validate() counts what
// it actually reached; this test recounts the committed file independently and
// requires the two to agree.
func TestValidateChecksEveryVectorAndNegative(t *testing.T) {
	data, err := os.ReadFile("../vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite Suite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	wantPos, wantTierB, wantNeg := 0, 0, 0
	for _, v := range suite.Vectors {
		if v.MinFormatVersion > supportedFormatVersion {
			continue
		}
		wantPos++
		if len(v.Chain) > 0 || len(v.ExpectWarnings) > 0 {
			wantTierB++
		}
	}
	for _, nv := range suite.Negatives {
		if nv.MinFormatVersion <= supportedFormatVersion {
			wantNeg++
		}
	}
	if wantTierB < 2 || wantNeg < 2 || wantPos < 2 {
		t.Fatalf("the committed suite is too small for this test to mean anything: %d/%d/%d",
			wantPos, wantTierB, wantNeg)
	}

	var verr error
	out := captureStdout(t, func() { verr = validate("../vectors.json") })
	if verr != nil {
		t.Fatalf("the committed vectors.json no longer validates: %v\n%s", verr, out)
	}
	m := checkedLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("validate() printed no \"checked:\" line; the harness cannot show what it reached\n%s", out)
	}
	var gotPos, gotTierB, gotNeg int
	fmt.Sscanf(m[1], "%d", &gotPos)
	fmt.Sscanf(m[2], "%d", &gotTierB)
	fmt.Sscanf(m[3], "%d", &gotNeg)
	if gotPos != wantPos || gotTierB != wantTierB || gotNeg != wantNeg {
		t.Fatalf("validate reached %d positive / %d Tier B / %d negative, want %d / %d / %d",
			gotPos, gotTierB, gotNeg, wantPos, wantTierB, wantNeg)
	}
}
