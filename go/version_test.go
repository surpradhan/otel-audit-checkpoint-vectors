package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// skipRuleFixture is shared with py/test_validate.py via
// testdata/skip_rule_fixture.json: both tests read the same file to decide
// which real vectors.json entries to mark as requiring a newer format, so a
// pass in both languages demonstrates the two implementations agree on the
// same synthetic input -- not just that each is internally self-consistent.
type skipRuleFixture struct {
	SkipVectors   []string `json:"skip_vectors"`
	SkipNegatives []string `json:"skip_negatives"`
}

func loadSkipRuleFixture(t *testing.T) skipRuleFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/skip_rule_fixture.json")
	if err != nil {
		t.Fatalf("read skip_rule_fixture.json: %v", err)
	}
	var f skipRuleFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal skip_rule_fixture.json: %v", err)
	}
	return f
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. validate() reports skip/ok/fail decisions only
// via fmt.Printf, so this is the only way to observe which vectors were
// actually skipped versus actually validated.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return buf.String()
}

var skipLineRE = regexp.MustCompile(`(?m)^  skip (\S+)\s+requires format_version \d+$`)

// skippedNames extracts the vector/negative names validate() actually
// printed a "skip" line for, from its captured stdout.
func skippedNames(output string) []string {
	var names []string
	for _, m := range skipLineRE.FindAllStringSubmatch(output, -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	return names
}

func assertStringSetsEqual(t *testing.T, got, want []string, context string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if len(g) != len(w) {
		t.Fatalf("%s: got %v, want %v", context, g, w)
	}
	for i := range g {
		if g[i] != w[i] {
			t.Fatalf("%s: got %v, want %v", context, g, w)
		}
	}
}

// TestValidateSkipsUnsupportedVectorEndToEnd pins the loop-level skip
// behavior in validate(), not just the skipVector() helper in isolation.
//
// It builds a synthetic suite from gen() (real key material, so signatures
// verify), marks the entries named in testdata/skip_rule_fixture.json as
// requiring a format newer than this build supports, and feeds the result
// through validate() exactly as a real run would -- capturing stdout so the
// test can tell "skipped" apart from "validated normally", which asserting
// only on the returned error cannot do: the marked vectors are valid data
// that would pass ordinary validation just as happily as a skip.
//
// This is deliberately sensitive to skipVector() being disabled (every
// vector validated normally, no skip lines at all) and to it being forced
// on (every vector skipped, no ok lines at all, including for vectors that
// were never marked).
func TestValidateSkipsUnsupportedVectorEndToEnd(t *testing.T) {
	fixture := loadSkipRuleFixture(t)
	suite := gen()

	markedVectors := map[string]bool{}
	for _, name := range fixture.SkipVectors {
		found := false
		for i := range suite.Vectors {
			if suite.Vectors[i].Name == name {
				suite.Vectors[i].MinFormatVersion = supportedFormatVersion + 1
				found = true
			}
		}
		if !found {
			t.Fatalf("fixture vector %q not found in gen() output", name)
		}
		markedVectors[name] = true
	}

	markedNegatives := map[string]bool{}
	for _, name := range fixture.SkipNegatives {
		found := false
		for i := range suite.Negatives {
			if suite.Negatives[i].Name == name {
				suite.Negatives[i].MinFormatVersion = supportedFormatVersion + 1
				found = true
			}
		}
		if !found {
			t.Fatalf("fixture negative %q not found in gen() output", name)
		}
		markedNegatives[name] = true
	}

	out, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatalf("marshal synthetic suite: %v", err)
	}
	path := filepath.Join(t.TempDir(), "synthetic_skip_suite.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write synthetic suite: %v", err)
	}

	var validateErr error
	output := captureStdout(t, func() {
		validateErr = validate(path)
	})

	// Requirement 1: a skip must never fail the run.
	if validateErr != nil {
		t.Fatalf("validate() on a suite containing a skip-eligible vector returned an error: %v\noutput:\n%s", validateErr, output)
	}

	// Requirement 1 (the part the returned error can't show): the marked
	// vector/negative must actually be REPORTED as skipped -- not silently
	// validated normally, which would also return a nil error since these
	// are otherwise-valid entries.
	wantSkipped := append(append([]string(nil), fixture.SkipVectors...), fixture.SkipNegatives...)
	assertStringSetsEqual(t, skippedNames(output), wantSkipped, "skipped vector/negative names")

	for name := range markedVectors {
		if bytes.Contains([]byte(output), []byte(fmt.Sprintf("ok  %s", name))) {
			t.Errorf("marked vector %q was validated normally (an \"ok\" line appeared); it must be skipped instead\noutput:\n%s", name, output)
		}
	}
	for name := range markedNegatives {
		if bytes.Contains([]byte(output), []byte(fmt.Sprintf("ok  %s", name))) {
			t.Errorf("marked negative %q was validated normally (an \"ok\" line appeared); it must be skipped instead\noutput:\n%s", name, output)
		}
	}

	// Requirement 2: vectors/negatives NOT marked must still be validated --
	// this is what catches a "skip everything" mutation, and specifically
	// covers multi_tip_unsorted_input, chained after the skipped
	// single_tip, proving the skip does not poison prevExpected for the
	// next (supported) vector's chain check.
	for _, v := range suite.Vectors {
		if markedVectors[v.Name] {
			continue
		}
		if !bytes.Contains([]byte(output), []byte(fmt.Sprintf("ok  %s", v.Name))) {
			t.Errorf("unmarked vector %q was not validated (no \"ok\" line found); it must not be skipped\noutput:\n%s", v.Name, output)
		}
	}
	for _, nv := range suite.Negatives {
		if markedNegatives[nv.Name] {
			continue
		}
		if !bytes.Contains([]byte(output), []byte(fmt.Sprintf("ok  %s", nv.Name))) {
			t.Errorf("unmarked negative %q was not validated (no \"ok\" line found); it must not be skipped\noutput:\n%s", nv.Name, output)
		}
	}
}
