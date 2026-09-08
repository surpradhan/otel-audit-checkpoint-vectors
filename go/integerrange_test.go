package main

import (
	"strings"
	"testing"
)

// checkIntegerRange is A5 (spec §4): every integer field on a checkpoint
// must fall within I-JSON's safe range, [-(2^53-1), 2^53-1]. These tests
// exercise it directly, across all four fields it covers and the
// min_format_version gate the published vectors alone don't fully exercise
// (only entry_count, only at v3, is pinned by a vector).

func boundaryTip() Tip {
	return Tip{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "x", TipHash: "aa"}
}

// checkpointWithField returns a checkpoint that is otherwise entirely
// ordinary, with exactly one of the four A5-covered fields set to n --
// isolating which field a failure belongs to the same way
// TestWrongTypedTipScalarsAreRejectedWhileDecoding's body() helper does for
// decoding, and for the identical reason: a table that reused one shared
// checkpoint and mutated it in place risked one iteration's field leaking
// into the next.
func checkpointWithField(field string, n int) Checkpoint {
	tip := boundaryTip()
	switch field {
	case "seq":
		return Checkpoint{Seq: n, Tips: []Tip{tip}}
	case "entry_count":
		tip.EntryCount = n
	case "sequence_number":
		tip.SequenceNumber = n
	case "epoch":
		tip.Epoch = &n
	default:
		panic("checkpointWithField: unknown field " + field)
	}
	return Checkpoint{Seq: 1, Tips: []Tip{tip}}
}

// TestCheckIntegerRangeBoundaries is table-driven over all four A5-covered
// fields and both sides of the range, 16 cases in total (4 fields x
// {accept-min, accept-max, reject-below-min, reject-above-max}). Every
// individual reject test before this one tested exactly one field on
// exactly one side -- entry_count only above max, sequence_number only
// below min, and so on -- so a bug that flipped a `<`/`<=` on a field's
// UNTESTED side, or compared the wrong field against the wrong constant,
// could have shipped undetected. This table closes that gap: every field is
// checked against both minSafeInt and maxSafeInt, not just whichever side a
// prior test happened to pick.
func TestCheckIntegerRangeBoundaries(t *testing.T) {
	for _, field := range []string{"seq", "entry_count", "sequence_number", "epoch"} {
		t.Run(field, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				n       int
				wantErr bool
			}{
				{"accept-min", minSafeInt, false},
				{"accept-max", maxSafeInt, false},
				{"reject-below-min", minSafeInt - 1, true},
				{"reject-above-max", maxSafeInt + 1, true},
			} {
				cp := checkpointWithField(field, tc.n)
				err := checkIntegerRange(cp, 3)
				if tc.wantErr && err == nil {
					t.Errorf("%s: %s (%d) was accepted", tc.name, field, tc.n)
				}
				if !tc.wantErr && err != nil {
					t.Errorf("%s: %s (%d) was rejected: %v", tc.name, field, tc.n, err)
				}
			}
		})
	}
}

// TestCheckIntegerRangeIsGatedByMinVer pins that the same out-of-range value
// is accepted below format_version 3 and rejected at or above it -- the
// published integer_out_of_range vector only exercises the v3 side; nothing
// published pins that an older-labeled vector is left alone.
func TestCheckIntegerRangeIsGatedByMinVer(t *testing.T) {
	cp := checkpointWithField("entry_count", maxSafeInt+1)
	if err := checkIntegerRange(cp, 2); err != nil {
		t.Errorf("an out-of-range entry_count was rejected below format_version 3: %v", err)
	}
	if err := checkIntegerRange(cp, 3); err == nil {
		t.Error("an out-of-range entry_count was accepted at format_version 3")
	}
}

// TestCheckIntegerRangeEpochLowerBoundIsUnreachableThroughCheckSchema pins a
// property of the full pipeline, not of checkIntegerRange in isolation:
// checkEpochPresence already rejects any negative epoch unconditionally, at
// every format version, and runs before checkIntegerRange inside
// checkSchema -- so epoch's own lower-bound branch in checkIntegerRange
// (epoch < minSafeInt) can never fire through checkSchema; 0 is always a
// tighter floor than minSafeInt. checkIntegerRange still checks it, for a
// caller that reaches it directly (as every test above does) rather than
// through checkSchema, and because minSafeInt is what RFC 7493 actually
// specifies -- but nothing published, and no other test in this file,
// exercises checkSchema's real call order for this specific interaction, so
// this pins it explicitly rather than leaving it to be discovered.
func TestCheckIntegerRangeEpochLowerBoundIsUnreachableThroughCheckSchema(t *testing.T) {
	e := minSafeInt - 1
	tip := boundaryTip()
	tip.Epoch = &e
	cp := Checkpoint{Seq: 1, Tips: []Tip{tip}}
	err := checkSchema(cp, 3)
	if err == nil {
		t.Fatal("a negative epoch was accepted by checkSchema")
	}
	if got := err.Error(); !strings.Contains(got, "non-negative") {
		t.Errorf("checkSchema rejected it, but not via checkEpochPresence's non-negativity rule as expected: %v", err)
	}
}
