package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestSuiteCarriesFormatVersion(t *testing.T) {
	s := gen()
	if s.FormatVersion != 2 {
		t.Errorf("format_version = %d, want 2", s.FormatVersion)
	}
	// The published suite must never claim a format this build cannot check.
	if s.FormatVersion != supportedFormatVersion {
		t.Errorf("format_version = %d, but supportedFormatVersion = %d", s.FormatVersion, supportedFormatVersion)
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

// futureFormatFixture is testdata/future_format_fixture.json: two entries of a
// format NEWER than this build, each carrying members it has no field for.
// Shared with py/test_validate.py's mirror so both references are handed the
// same bytes.
//
// The entries are held as generic maps because that is exactly what the
// structs cannot express -- a Vector has no field for a v3 member, which is
// the whole premise.
type futureFormatFixture struct {
	FormatVersion int            `json:"format_version"`
	Vector        map[string]any `json:"vector"`
	Negative      map[string]any `json:"negative"`
}

func loadFutureFormatFixture(t *testing.T) futureFormatFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/future_format_fixture.json")
	if err != nil {
		t.Fatalf("read future_format_fixture.json: %v", err)
	}
	var f futureFormatFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal future_format_fixture.json: %v", err)
	}
	if f.FormatVersion <= supportedFormatVersion {
		t.Fatalf("fixture format_version %d does not exceed supportedFormatVersion %d",
			f.FormatVersion, supportedFormatVersion)
	}
	return f
}

// futureFormatSuite is the committed suite with the fixture's two entries
// appended and format_version raised, marshalled through a generic map so the
// v3 members survive.
func futureFormatSuite(t *testing.T, f futureFormatFixture, minVer int) string {
	t.Helper()
	raw, err := json.Marshal(gen())
	if err != nil {
		t.Fatal(err)
	}
	var suite map[string]any
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	suite["format_version"] = f.FormatVersion
	v, nv := maps.Clone(f.Vector), maps.Clone(f.Negative)
	v["min_format_version"] = minVer
	nv["min_format_version"] = minVer
	suite["vectors"] = append(suite["vectors"].([]any), v)
	suite["negatives"] = append(suite["negatives"].([]any), nv)
	out, err := json.Marshal(suite)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "future_format.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A vector of a format this build does not support must be SKIPPED even when
// it carries members this build has no field for -- which is the only
// interesting case, since a future format that added nothing would need no
// version bump. "Validators MUST skip ... and MUST NOT treat a skip as a
// failure" is what allows new vector shapes to be added without breaking
// existing validators, and strict-decoding the whole file before consulting
// the skip rule broke exactly that: the file failed to load with
// `json: unknown field "provenance"` and every vector in it, old and new
// alike, went unchecked.
//
// Mirrors py/test_validate.py's
// test_future_format_entry_is_skipped_not_strict_decoded, over the same
// fixture bytes.
func TestFutureFormatEntryIsSkippedNotStrictDecoded(t *testing.T) {
	f := loadFutureFormatFixture(t)
	suite := gen()

	path := futureFormatSuite(t, f, f.FormatVersion)
	var validateErr error
	output := captureStdout(t, func() { validateErr = validate(path) })
	if validateErr != nil {
		t.Fatalf("a future-format entry must be skipped, not fail the file: %v\noutput:\n%s", validateErr, output)
	}
	assertStringSetsEqual(t, skippedNames(output),
		[]string{f.Vector["name"].(string), f.Negative["name"].(string)},
		"skipped vector/negative names")
	// The skip must not cost the rest of the file: every committed entry is
	// still checked. This is what catches "skip everything on a version
	// mismatch" as much as it catches the load failure.
	for _, v := range suite.Vectors {
		if !bytes.Contains([]byte(output), []byte(fmt.Sprintf("ok  %s", v.Name))) {
			t.Errorf("vector %q was not validated alongside the skipped future entry\noutput:\n%s", v.Name, output)
		}
	}
	for _, nv := range suite.Negatives {
		if !bytes.Contains([]byte(output), []byte(fmt.Sprintf("ok  %s", nv.Name))) {
			t.Errorf("negative %q was not validated alongside the skipped future entry\noutput:\n%s", nv.Name, output)
		}
	}

	// The control, and the reason the assertions above are not vacuous: the
	// SAME entries at a version this build does support must be rejected, as
	// unknown members. Without this the test would pass just as happily if
	// those members were ones the structs already knew.
	t.Run("not skipped, therefore rejected", func(t *testing.T) {
		path := futureFormatSuite(t, f, supportedFormatVersion)
		err := validate(path)
		if err == nil {
			t.Fatal("the fixture entries carry no member this build is unaware of; the skip assertion above proves nothing")
		}
		if !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("rejected, but not as an unknown member: %v", err)
		}
	})
}

// The validator's view of the file must not drift from the generator's. They
// are two structs over one document -- suiteFile holds the entry arrays raw so
// the skip rule can run before strict decoding -- and a member added to one
// and not the other would be silently dropped on the way in or out.
func TestSuiteFileMirrorsSuiteMembers(t *testing.T) {
	jsonNames := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			tag, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
			out = append(out, tag)
		}
		sort.Strings(out)
		return out
	}
	assertStringSetsEqual(t, jsonNames(suiteFile{}), jsonNames(Suite{}),
		"suiteFile vs Suite JSON member names")
}
