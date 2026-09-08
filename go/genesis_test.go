package main

import "testing"

// checkGenesis is A6 (spec §4): seq == 1 iff prev_hash is the genesis
// constant. These tests exercise it directly, including the two ACCEPT
// cases the published vectors don't demonstrate on their own -- every
// negative vector pins one violating direction, but neither pins that the
// two ordinary, non-violating shapes are still accepted.

func TestCheckGenesisAcceptsTheGenesisCheckpoint(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2027-01-01T00:00:00Z", Tips: []Tip{}}
	if err := checkGenesis(cp); err != nil {
		t.Errorf("seq 1 with the genesis prev_hash was rejected: %v", err)
	}
}

func TestCheckGenesisAcceptsAnOrdinaryNonGenesisCheckpoint(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty[:63] + "1", Seq: 400, Timestamp: "2027-01-01T00:00:00Z", Tips: []Tip{}}
	if err := checkGenesis(cp); err != nil {
		t.Errorf("seq 400 with a non-genesis prev_hash was rejected: %v", err)
	}
}

func TestCheckGenesisRejectsGenesisHashWithWrongSeq(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 2, Timestamp: "2027-01-01T00:00:00Z", Tips: []Tip{}}
	if err := checkGenesis(cp); err == nil {
		t.Error("the genesis prev_hash with seq 2 was accepted")
	}
}

func TestCheckGenesisRejectsSeqOneWithWrongHash(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty[:63] + "1", Seq: 1, Timestamp: "2027-01-01T00:00:00Z", Tips: []Tip{}}
	if err := checkGenesis(cp); err == nil {
		t.Error("seq 1 with a non-genesis prev_hash was accepted")
	}
}

// TestCheckGenesisDoesNotFireOnZeroValue pins that a Checkpoint whose Seq was
// never set (Go's int zero value, 0) is not treated as satisfying "seq == 1"
// -- 0 and 1 must stay distinct, or a decode failure that leaves Seq at its
// zero value could accidentally read as a valid genesis claim.
func TestCheckGenesisDoesNotFireOnZeroValue(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty[:63] + "1", Seq: 0, Timestamp: "2027-01-01T00:00:00Z", Tips: []Tip{}}
	if err := checkGenesis(cp); err != nil {
		t.Errorf("seq 0 (not a genesis claim) with a non-genesis prev_hash was rejected: %v", err)
	}
	cp.PrevHash = sha256Empty
	if err := checkGenesis(cp); err == nil {
		t.Error("seq 0 with the genesis prev_hash was accepted -- 0 must not be treated as seq 1")
	}
}
