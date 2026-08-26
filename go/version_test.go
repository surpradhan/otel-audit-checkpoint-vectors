package main

import "testing"

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
