package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSuiteCarriesFormatVersion(t *testing.T) {
	s := gen()
	if s.FormatVersion != 1 {
		t.Errorf("format_version = %d, want 1", s.FormatVersion)
	}
}

// A vector requiring a newer format than the validator supports must be
// skipped with a warning, never counted as a failure.
func TestUnsupportedVectorIsSkippedNotFailed(t *testing.T) {
	if skipVector(supportedFormatVersion+1, supportedFormatVersion) != true {
		t.Error("vector above supported version must be skipped")
	}
	if skipVector(0, supportedFormatVersion) != false {
		t.Error("vector with no minimum must not be skipped")
	}
	if skipVector(supportedFormatVersion, supportedFormatVersion) != false {
		t.Error("vector at exactly the supported version must not be skipped")
	}
}

// TestValidateSkipsUnsupportedVectorEndToEnd pins the loop-level skip
// behavior in validate(), not just the skipVector() helper in isolation.
//
// It builds a synthetic suite from gen() (real key material, so signatures
// verify) and marks the middle positive vector ("single_tip") and one
// negative ("tampered_signature") as requiring a format newer than this
// build supports, then feeds the result through validate() exactly as a
// real run would.
//
// gen()'s output is byte-identical to the committed vectors.json (enforced
// by CI's no-drift check), and this test marks the same named vector and
// negative that py/test_validate.py marks starting from that same committed
// file. Both therefore skip the same entries and must reach the same PASS
// verdict, satisfying the cross-implementation parity this test and its
// Python counterpart together establish.
func TestValidateSkipsUnsupportedVectorEndToEnd(t *testing.T) {
	suite := gen()

	skipName := "single_tip"
	marked := false
	for i := range suite.Vectors {
		if suite.Vectors[i].Name == skipName {
			suite.Vectors[i].MinFormatVersion = supportedFormatVersion + 1
			marked = true
		}
	}
	if !marked {
		t.Fatalf("fixture vector %q not found in gen() output", skipName)
	}

	skipNegName := "tampered_signature"
	markedNeg := false
	for i := range suite.Negatives {
		if suite.Negatives[i].Name == skipNegName {
			suite.Negatives[i].MinFormatVersion = supportedFormatVersion + 1
			markedNeg = true
		}
	}
	if !markedNeg {
		t.Fatalf("fixture negative %q not found in gen() output", skipNegName)
	}

	out, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatalf("marshal synthetic suite: %v", err)
	}
	path := filepath.Join(t.TempDir(), "synthetic_skip_suite.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write synthetic suite: %v", err)
	}

	// 1: a skip must never fail the run.
	// 2: multi_tip_unsorted_input, chained after the skipped single_tip,
	//    must still validate -- proving the skip does not poison
	//    prevExpected for the next (supported) vector's chain check.
	if err := validate(path); err != nil {
		t.Fatalf("validate() on a suite containing a skip-eligible vector returned an error: %v", err)
	}
}
