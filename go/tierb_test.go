package main

import (
	"bytes"
	"testing"
)

func mkTip(stream string, epoch, seq, count int, tip string) Tip {
	return Tip{EntryCount: count, Epoch: ptr(epoch), SequenceNumber: seq, StreamID: stream, TipHash: tip}
}

// B3: the same (stream_id, epoch) committed twice in one chain is a hard
// reject, whether or not the tips differ. Within one generation the producer's
// dedup map is intact, so no second commit of any kind is legitimate.
func TestB3RejectsSameStreamSameEpoch(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 3, 3, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 0, 2, 2, "bb")}},
	}
	if err, _ := checkTierB(chain); err == nil {
		t.Fatal("checkTierB accepted a same-epoch re-commit; want a rejection")
	}
}

// B4: the same stream under a NEW epoch is the declared at-least-once path.
// It must be accepted even when entry_count goes backwards, because an honest
// timeout-split produces exactly that shape -- and it must warn.
func TestB4AcceptsSameStreamNewEpochWithWarning(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 7, 7, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s1", 1, 5, 5, "bb")}},
	}
	err, warns := checkTierB(chain)
	if err != nil {
		t.Fatalf("checkTierB rejected a legitimate cross-epoch re-commit: %v", err)
	}
	if len(warns) != 1 || warns[0] != "B4:s1" {
		t.Fatalf("warnings = %v, want exactly [B4:s1]", warns)
	}
}

// B5: a timestamp regression warns and does not reject.
func TestB5WarnsOnTimestampRegression(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:10Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		{Seq: 2, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 1, 1, "bb")}},
	}
	err, warns := checkTierB(chain)
	if err != nil {
		t.Fatalf("timestamp regression must warn, not reject: %v", err)
	}
	if len(warns) != 1 || warns[0] != "B5:2" {
		t.Fatalf("warnings = %v, want exactly [B5:2]", warns)
	}
}

// B1: seq must increment by exactly 1.
func TestB1RejectsSeqSkip(t *testing.T) {
	chain := []Checkpoint{
		{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{mkTip("s1", 0, 1, 1, "aa")}},
		{Seq: 3, Timestamp: "2026-01-01T00:00:05Z", Tips: []Tip{mkTip("s2", 0, 1, 1, "bb")}},
	}
	if err, _ := checkTierB(chain); err == nil {
		t.Fatal("checkTierB accepted a seq gap; want a rejection")
	}
}

// R4: two tips for one stream at different epochs are legal in ONE checkpoint,
// so the sort key must be composite or the canonical bytes depend on input order.
func TestR4CompositeSortKey(t *testing.T) {
	x := mkTip("s1", 0, 1, 1, "aa")
	y := mkTip("s1", 1, 2, 2, "bb")
	c1, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{x, y}})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := canonical(Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{y, x}})
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) != string(c2) {
		t.Errorf("input order changed canonical bytes:\n %s\n %s", c1, c2)
	}
}

// A version-1 tip carries no epoch key, and re-marshalling must not add one.
// This is what keeps the six frozen vectors byte-identical.
func TestVersion1TipOmitsEpoch(t *testing.T) {
	cp := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	cb, err := canonical(cp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cb, []byte("epoch")) {
		t.Errorf("version-1 canonical bytes must not contain an epoch key: %s", cb)
	}
}

// Spec 5a: epoch is required at format_version 2 and above, and must be absent
// in version-1 vectors. A version-2 tip missing epoch must be rejected, not
// defaulted to 0 -- otherwise the absent-vs-zero distinction is unenforced
// spec text. Mirrors py/test_validate.py's test_epoch_presence_boundary.
func TestEpochPresenceBoundary(t *testing.T) {
	v2Missing := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		{EntryCount: 1, Epoch: nil, SequenceNumber: 1, StreamID: "s1", TipHash: "aa"},
	}}
	if err := checkEpochPresence(v2Missing, 2); err == nil {
		t.Error("a version-2 tip with no epoch must be rejected")
	}
	if err := checkEpochPresence(v2Missing, 0); err != nil {
		t.Errorf("a version-1 tip with no epoch is well-formed, got: %v", err)
	}

	v1WithEpoch := Checkpoint{PrevHash: sha256Empty, Seq: 1, Timestamp: "2026-01-01T00:00:00Z", Tips: []Tip{
		mkTip("s1", 0, 1, 1, "aa"),
	}}
	if err := checkEpochPresence(v1WithEpoch, 0); err == nil {
		t.Error("epoch is not permitted in a version-1 vector")
	}
	if err := checkEpochPresence(v1WithEpoch, 2); err != nil {
		t.Errorf("a version-2 tip with an explicit epoch is well-formed, got: %v", err)
	}
}
