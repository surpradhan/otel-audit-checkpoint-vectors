package main

// Position-generic Tier B tests.
//
// Every VECTOR in this suite pins its rule at exactly one chain position, so
// any mutation of the form "apply this check only at position X" escapes the
// vectors unless some vector happens to sit at X. Adding more hand-placed
// vectors only moves the hole; it never closes it.
//
// The tests here are generic over position instead: for a rule and a chain of
// length N they inject the defect at EVERY index in turn and require the rule
// to fire each time. A validator that applies the rule at only one position
// fails N-2 of the sub-tests, whichever position it picked. Mirrored in
// py/test_validate.py.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
)

// posChainLen is 5, giving four transitions (1..4): a first, two middles and a
// last. Four is the smallest count at which "only the first", "only the last"
// and "only some fixed middle" are all distinguishable from "every".
const posChainLen = 5

func posTS(sec int) string {
	return fmt.Sprintf("2026-01-01T00:%02d:%02dZ", sec/60, sec%60)
}

func posStream(n int) string {
	return fmt.Sprintf("%08d-0000-4000-8000-%012d", n, n)
}

// posClean builds a Tier-B-clean chain of n checkpoints: seq 1..n, strictly
// increasing timestamps, one distinct stream each at epoch 0. Callers inject a
// single defect at a chosen index, then link.
func posClean(n int) []Checkpoint {
	cps := make([]Checkpoint, n)
	for i := range cps {
		cps[i] = Checkpoint{Seq: i + 1, Timestamp: posTS(100 + 10*i), Tips: []Tip{
			mkTip(posStream(i+1), 0, i+1, i+1, fmt.Sprintf("%02x", i+1)),
		}}
	}
	return cps
}

// posRelink recomputes prev_hash from index `from` onwards, so a chain carries
// exactly the one defect the caller injected.
func posRelink(t *testing.T, cps []Checkpoint, from int) {
	t.Helper()
	for i := from; i < len(cps); i++ {
		cb, err := canonical(cps[i-1])
		if err != nil {
			t.Fatalf("posRelink: %v", err)
		}
		sum := sha256.Sum256(cb)
		cps[i].PrevHash = hex.EncodeToString(sum[:])
	}
}

// B1 must hold at EVERY transition, not at the first (which seq_skip pins) nor
// at the last (which seq_skip_after_first_transition pins).
func TestB1FiresAtEveryTransition(t *testing.T) {
	for d := 1; d < posChainLen; d++ {
		t.Run(fmt.Sprintf("transition_%d", d), func(t *testing.T) {
			cps := posClean(posChainLen)
			// One gap, at transition d; every later transition stays contiguous.
			for i := d; i < posChainLen; i++ {
				cps[i].Seq++
			}
			_, err := checkTierB(linkChain(t, cps...))
			if err == nil {
				t.Fatalf("seq gap at transition %d accepted; B1 must hold at every transition", d)
			}
			if !strings.HasPrefix(err.Error(), "B1:") {
				t.Fatalf("seq gap at transition %d rejected by %v; want a B1 rejection", d, err)
			}
		})
	}
}

// B2 must hold at EVERY transition, including the LAST -- a vector's own link
// to its final prefix. prev_sha256 pins only that last link and only for
// chainless vectors, so nothing else reaches it through checkTierB.
func TestB2FiresAtEveryTransition(t *testing.T) {
	for d := 1; d < posChainLen; d++ {
		t.Run(fmt.Sprintf("transition_%d", d), func(t *testing.T) {
			chain := linkChain(t, posClean(posChainLen)...)
			chain[d].PrevHash = "22" + strings.Repeat("22", 31)
			posRelink(t, chain, d+1)
			_, err := checkTierB(chain)
			if err == nil {
				t.Fatalf("broken link at transition %d accepted; B2 must hold at every transition", d)
			}
			if !strings.HasPrefix(err.Error(), "B2:") {
				t.Fatalf("broken link at transition %d rejected by %v; want a B2 rejection", d, err)
			}
		})
	}
}

// B3 spans the WHOLE chain: a repeat of a (stream_id, epoch) is a rejection
// wherever the two commits sit, including between two prefixes with the
// vector's own input clean.
func TestB3FiresForEveryPositionPair(t *testing.T) {
	for a := 0; a < posChainLen; a++ {
		for b := a + 1; b < posChainLen; b++ {
			t.Run(fmt.Sprintf("%d_and_%d", a, b), func(t *testing.T) {
				cps := posClean(posChainLen)
				cps[b].Tips[0].StreamID = cps[a].Tips[0].StreamID
				cps[b].Tips[0].TipHash = "ff"
				_, err := checkTierB(linkChain(t, cps...))
				if err == nil {
					t.Fatalf("identity repeated at %d and %d accepted; B3 spans the whole chain", a, b)
				}
				if !strings.HasPrefix(err.Error(), "B3:") {
					t.Fatalf("identity repeated at %d and %d rejected by %v; want a B3 rejection", a, b, err)
				}
			})
		}
	}
}

// B4 fires at EVERY transition. It is asserted as an exact ordered list, so a
// check pinned to one index shows up as a missing token here and a spurious
// one elsewhere.
func TestB4FiresAtEveryTransition(t *testing.T) {
	for d := 1; d < posChainLen; d++ {
		t.Run(fmt.Sprintf("transition_%d", d), func(t *testing.T) {
			cps := posClean(posChainLen)
			cps[d].Tips[0].StreamID = posStream(1) // re-commit checkpoint 1's stream
			cps[d].Tips[0].Epoch = ptr(1)
			warns, err := checkTierB(linkChain(t, cps...))
			if err != nil {
				t.Fatalf("cross-epoch re-commit at index %d is advisory, not a rejection: %v", d, err)
			}
			want := []string{"B4:" + posStream(1)}
			if !slices.Equal(warns, want) {
				t.Fatalf("epoch change at index %d: warnings %v, want %v", d, warns, want)
			}
		})
		// The same transition, but the stream's PREVIOUS commit sits at index
		// d-1 rather than at chain[0]. A validator that records epochs only
		// from chain[0] passes the case above and fails this one.
		t.Run(fmt.Sprintf("consecutive_%d", d), func(t *testing.T) {
			cps := posClean(posChainLen)
			cps[d].Tips[0].StreamID = posStream(d) // the stream committed at index d-1
			cps[d].Tips[0].Epoch = ptr(1)
			warns, err := checkTierB(linkChain(t, cps...))
			if err != nil {
				t.Fatalf("cross-epoch re-commit at index %d is advisory, not a rejection: %v", d, err)
			}
			want := []string{"B4:" + posStream(d)}
			if !slices.Equal(warns, want) {
				t.Fatalf("epoch change at index %d (previous commit at %d): warnings %v, want %v",
					d, d-1, warns, want)
			}
		})
	}
}

// B5 compares against the IMMEDIATE predecessor at every transition. Each
// regressed timestamp below is still above chain[0]'s, so a validator
// comparing against chain[0] misses the real regression and invents others.
func TestB5FiresAtEveryTransition(t *testing.T) {
	for d := 1; d < posChainLen; d++ {
		t.Run(fmt.Sprintf("transition_%d", d), func(t *testing.T) {
			cps := posClean(posChainLen)
			cps[d].Timestamp = posTS(100 + 10*(d-1) - 1) // one second before its predecessor
			warns, err := checkTierB(linkChain(t, cps...))
			if err != nil {
				t.Fatalf("timestamp regression at index %d is advisory, not a rejection: %v", d, err)
			}
			want := []string{fmt.Sprintf("B5:%d", cps[d].Seq)}
			if !slices.Equal(warns, want) {
				t.Fatalf("regression at index %d: warnings %v, want %v", d, warns, want)
			}
		})
	}
}

// B2 hashes the previous checkpoint's CANONICAL bytes, not the bytes as
// received. A checkpoint's tips are explicitly allowed to arrive unsorted, so
// a validator that JCS-transformed the checkpoint without first imposing the
// tip order would compute a different digest and reject a legitimate chain.
func TestB2HashesCanonicalBytesNotAsReceived(t *testing.T) {
	unsorted := Checkpoint{Seq: 2, Timestamp: posTS(110), Tips: []Tip{
		mkTip(posStream(9), 0, 9, 9, "99"), // posStream(9) sorts AFTER posStream(3)
		mkTip(posStream(3), 0, 3, 3, "33"),
	}}
	cps := []Checkpoint{
		{Seq: 1, Timestamp: posTS(100), Tips: []Tip{mkTip(posStream(1), 0, 1, 1, "11")}},
		unsorted,
		{Seq: 3, Timestamp: posTS(120), Tips: []Tip{mkTip(posStream(2), 0, 2, 2, "22")}},
	}
	chain := linkChain(t, cps...)

	// The test only discriminates if the two byte strings actually differ.
	canonBytes, err := canonical(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	asReceived, err := jcs.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonBytes) == string(asReceived) {
		t.Fatal("fixture is not discriminating: the prefix's tips are already in identity order")
	}

	if _, err := checkTierB(chain); err != nil {
		t.Fatalf("a chain whose prefix supplies tips out of identity order was rejected: %v", err)
	}
}

// verifyPrefixes applies BOTH of its rules at every prefix index. Tampering
// index 0 and index len-1 are the two positions the suite's vectors happen to
// occupy; a middle index is the one neither reaches.
func TestPrefixRulesFireAtEveryPrefixIndex(t *testing.T) {
	const n = 4
	pub := testPub(t)
	for d := 0; d < n; d++ {
		t.Run(fmt.Sprintf("signature_prefix_%d", d), func(t *testing.T) {
			cps := linkChain(t, posClean(n)...)
			prefixes := make([]SignedCheckpoint, 0, n)
			for _, cp := range cps {
				prefixes = append(prefixes, signed(t, cp))
			}
			raw, err := base64.StdEncoding.DecodeString(prefixes[d].Signature)
			if err != nil {
				t.Fatal(err)
			}
			raw[0] ^= 0x01
			prefixes[d].Signature = base64.StdEncoding.EncodeToString(raw)
			if _, reason := verifyPrefixes(pub, prefixes, 2); reason != "signature" {
				t.Fatalf("tampered prefix %d: reason = %q, want \"signature\"", d, reason)
			}
		})
		t.Run(fmt.Sprintf("epoch_prefix_%d", d), func(t *testing.T) {
			cps := posClean(n)
			cps[d].Tips[0].Epoch = nil
			cps = linkChain(t, cps...)
			prefixes := make([]SignedCheckpoint, 0, n)
			for _, cp := range cps {
				prefixes = append(prefixes, signed(t, cp))
			}
			if _, reason := verifyPrefixes(pub, prefixes, 2); reason != "schema" {
				t.Fatalf("prefix %d missing epoch: reason = %q, want \"schema\"", d, reason)
			}
		})
	}
}

// A checkpoint with keys missing must produce a clean B-rule rejection, not a
// crash. Go decodes the absent keys into zero values and rejects at B2; Python
// read cp["prev_hash"] directly and raised KeyError, so the two reference
// implementations disagreed on third-party input -- exactly the defect class
// this suite publishes vectors against. Mirrored in py/test_validate.py.
func TestMalformedCheckpointRejectsCleanly(t *testing.T) {
	head := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: posTS(100), Tips: []Tip{
		mkTip(posStream(1), 0, 1, 1, "11"),
	}}
	// Seq, Timestamp and PrevHash all left at their zero values.
	bare := Checkpoint{Seq: 2, Tips: []Tip{mkTip(posStream(2), 0, 2, 2, "22")}}
	_, err := checkTierB([]Checkpoint{head, bare})
	if err == nil {
		t.Fatal("a checkpoint with no prev_hash was accepted; want a B2 rejection")
	}
	if !strings.HasPrefix(err.Error(), "B2:") {
		t.Fatalf("checkpoint with no prev_hash rejected by %v; want a B2 rejection", err)
	}
}
