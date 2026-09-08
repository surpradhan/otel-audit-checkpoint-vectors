package main

import "testing"

// checkIntegerRange is A5 (spec §4): every integer field on a checkpoint
// must fall within I-JSON's safe range, [-(2^53-1), 2^53-1]. These tests
// exercise it directly, across all four fields it covers and the
// min_format_version gate the published vectors alone don't fully exercise
// (only entry_count, only at v3, is pinned by a vector).

func boundaryTip() Tip {
	return Tip{EntryCount: 1, Epoch: ptr(0), SequenceNumber: 1, StreamID: "x", TipHash: "aa"}
}

func TestCheckIntegerRangeAcceptsTheBoundaryValues(t *testing.T) {
	tip := boundaryTip()
	tip.EntryCount = maxSafeInt
	tip.SequenceNumber = minSafeInt
	e := minSafeInt
	tip.Epoch = &e
	cp := Checkpoint{Seq: maxSafeInt, Tips: []Tip{tip}}
	if err := checkIntegerRange(cp, 3); err != nil {
		t.Errorf("boundary values (min and max) were rejected: %v", err)
	}
}

func TestCheckIntegerRangeRejectsEntryCountOneOverMax(t *testing.T) {
	tip := boundaryTip()
	tip.EntryCount = maxSafeInt + 1
	cp := Checkpoint{Seq: 1, Tips: []Tip{tip}}
	if err := checkIntegerRange(cp, 3); err == nil {
		t.Error("entry_count one past maxSafeInt was accepted")
	}
}

func TestCheckIntegerRangeRejectsSequenceNumberOneUnderMin(t *testing.T) {
	tip := boundaryTip()
	tip.SequenceNumber = minSafeInt - 1
	cp := Checkpoint{Seq: 1, Tips: []Tip{tip}}
	if err := checkIntegerRange(cp, 3); err == nil {
		t.Error("sequence_number one past minSafeInt was accepted")
	}
}

func TestCheckIntegerRangeRejectsEpochOverMax(t *testing.T) {
	tip := boundaryTip()
	e := maxSafeInt + 1
	tip.Epoch = &e
	cp := Checkpoint{Seq: 1, Tips: []Tip{tip}}
	if err := checkIntegerRange(cp, 3); err == nil {
		t.Error("epoch one past maxSafeInt was accepted")
	}
}

func TestCheckIntegerRangeRejectsSeqOverMax(t *testing.T) {
	cp := Checkpoint{Seq: maxSafeInt + 1, Tips: []Tip{boundaryTip()}}
	if err := checkIntegerRange(cp, 3); err == nil {
		t.Error("seq one past maxSafeInt was accepted")
	}
}

// TestCheckIntegerRangeIsGatedByMinVer pins that the same out-of-range value
// is accepted below format_version 3 and rejected at or above it -- the
// published integer_out_of_range vector only exercises the v3 side; nothing
// published pins that an older-labeled vector is left alone.
func TestCheckIntegerRangeIsGatedByMinVer(t *testing.T) {
	tip := boundaryTip()
	tip.EntryCount = maxSafeInt + 1
	cp := Checkpoint{Seq: 1, Tips: []Tip{tip}}
	if err := checkIntegerRange(cp, 2); err != nil {
		t.Errorf("an out-of-range entry_count was rejected below format_version 3: %v", err)
	}
	if err := checkIntegerRange(cp, 3); err == nil {
		t.Error("an out-of-range entry_count was accepted at format_version 3")
	}
}
