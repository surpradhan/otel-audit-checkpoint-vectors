package main

import "testing"

// Two tips sharing an identity make the checkpoint's canonical bytes depend on
// input order. It must be rejected, not silently sorted.
func TestDuplicateTipIdentityRejected(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, SequenceNumber: 1, StreamID: "dup", TipHash: "aa"},
		{EntryCount: 2, SequenceNumber: 2, StreamID: "dup", TipHash: "bb"},
	}}
	if _, err := canonical(cp); err == nil {
		t.Fatal("canonical accepted a duplicate tip identity; want an error")
	}
}

// A naive adjacent-scan duplicate check (comparing c.Tips[i] to c.Tips[i-1] in
// original, unsorted order) would miss this: the duplicate pair is separated
// by a non-duplicate tip, so it is never adjacent in input order. Only a
// set-based check over all tips catches it.
func TestDuplicateTipIdentityRejectedNonAdjacent(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, SequenceNumber: 1, StreamID: "dup", TipHash: "aa"},
		{EntryCount: 3, SequenceNumber: 3, StreamID: "other", TipHash: "cc"},
		{EntryCount: 2, SequenceNumber: 2, StreamID: "dup", TipHash: "bb"},
	}}
	if _, err := canonical(cp); err == nil {
		t.Fatal("canonical accepted a non-adjacent duplicate tip identity; want an error")
	}
}

// The regression that motivated the rule: the same logical set in two input
// orders must never produce two different canonical byte strings.
func TestCanonicalIsInputOrderIndependent(t *testing.T) {
	a := Tip{EntryCount: 1, SequenceNumber: 1, StreamID: "aaa", TipHash: "aa"}
	b := Tip{EntryCount: 2, SequenceNumber: 2, StreamID: "bbb", TipHash: "bb"}
	c1, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{b, a}})
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) != string(c2) {
		t.Errorf("input order changed canonical bytes:\n %s\n %s", c1, c2)
	}
}
