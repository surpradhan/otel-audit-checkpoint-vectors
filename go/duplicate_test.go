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
