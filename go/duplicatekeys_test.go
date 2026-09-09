package main

import (
	"strings"
	"testing"
)

// checkDuplicateKeys is the raw-structure pre-parse step #47 requires. These
// tests pin the property directly: a repeated member name anywhere in the
// document is rejected, at every nesting level, while the same name
// appearing once in two DIFFERENT objects is not a repeat at all. Mirrors
// py/test_validate.py's test_check_duplicate_keys_* functions.

func TestCheckDuplicateKeysAcceptsAnOrdinaryDocument(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`{"a":1,"b":2}`)); reason != "" {
		t.Errorf("an ordinary, duplicate-free object was rejected: %q", reason)
	}
}

func TestCheckDuplicateKeysRejectsAFlatDuplicate(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`{"a":1,"a":2}`)); reason == "" {
		t.Error("a top-level duplicate key was accepted")
	}
}

func TestCheckDuplicateKeysRejectsADuplicateEvenWithAnIdenticalValue(t *testing.T) {
	// The class the whole-file tests below actually exercise: a duplicate
	// that changes nothing decode could observe is still an ambiguous
	// document -- two distinct byte sequences a validator might be handed,
	// not one.
	if reason := checkDuplicateKeys([]byte(`{"a":1,"a":1}`)); reason == "" {
		t.Error("a duplicate key with an identical value was accepted")
	}
}

func TestCheckDuplicateKeysRejectsANullDuplicate(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`{"a":1,"a":null}`)); reason == "" {
		t.Error("a duplicate key with one null occurrence was accepted")
	}
}

func TestCheckDuplicateKeysRejectsADuplicateInsideANestedObject(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`{"tips":[{"a":1,"a":2}]}`)); reason == "" {
		t.Error("a duplicate key inside a nested object was accepted")
	}
}

func TestCheckDuplicateKeysRejectsADuplicateInTheSecondArrayElement(t *testing.T) {
	// Not just the first element: the walk must actually visit every
	// element of an array, not stop after the first.
	if reason := checkDuplicateKeys([]byte(`{"tips":[{"a":1},{"a":1,"b":2,"b":3}]}`)); reason == "" {
		t.Error("a duplicate key in the second array element was accepted")
	}
}

func TestCheckDuplicateKeysAcceptsTheSameKeyNameInDifferentObjects(t *testing.T) {
	// The defect class is a repeat WITHIN one object, not a name recurring
	// across the document -- every checkpoint has its own "seq", and this
	// suite's own envelope/vector/checkpoint schema all share member names
	// like "name". Duplicate-key tracking is scoped per object (a fresh
	// `seen` set at each '{'), and this is the test that would catch a
	// regression to a single, document-wide set instead.
	if reason := checkDuplicateKeys([]byte(`{"a":1,"tips":[{"a":1}]}`)); reason != "" {
		t.Errorf("the same key name in two different objects was rejected: %q", reason)
	}
}

func TestCheckDuplicateKeysAcceptsAnEmptyObject(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`{}`)); reason != "" {
		t.Errorf("an empty object was rejected: %q", reason)
	}
}

func TestCheckDuplicateKeysAcceptsAnArrayOfScalars(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`[1,2,3]`)); reason != "" {
		t.Errorf("a top-level array of scalars was rejected: %q", reason)
	}
}

func TestCheckDuplicateKeysRejectsADeeplyNestedDuplicate(t *testing.T) {
	if reason := checkDuplicateKeys([]byte(`{"x":{"y":{"z":1,"z":2}}}`)); reason == "" {
		t.Error("a duplicate three levels deep was accepted")
	}
}

// TestCheckDuplicateKeysDoesNotReportAPlainSyntaxErrorAsADuplicate pins the
// review-found distinction checkDuplicateKeys/duplicateKeyError exist for: a
// document that's malformed for some OTHER reason -- not a repeated key --
// must return "" here, not "duplicate_key". Without this, a merely
// syntactically broken (but duplicate-free) file was misreported, and the
// misreport propagated all the way to resolveInput's own "reason" token for
// a malformed, non-duplicate input_raw_hex payload -- confirmed directly:
// {"seq":1,} (a trailing comma) used to change resolveInput's reason from
// "schema" to "encoding", a live reason-token divergence from Python, whose
// object_pairs_hook already discriminated this correctly via a dedicated
// exception type. Found in round 1 review.
func TestCheckDuplicateKeysDoesNotReportAPlainSyntaxErrorAsADuplicate(t *testing.T) {
	for _, raw := range []string{
		`{"a":1,}`,           // trailing comma
		``,                   // empty
		`{"a":"unterminated`, // unterminated string
	} {
		if reason := checkDuplicateKeys([]byte(raw)); reason != "" {
			t.Errorf("%q: reason = %q, want \"\" -- this is a syntax error, not a duplicate key", raw, reason)
		}
	}
}

// nestedObjectJSON returns depth levels of `{"a":...}` nesting around a
// scalar, e.g. nestedObjectJSON(2) == `{"a":{"a":0}}` -- a lone `{}` is
// nesting level 1, matching maxJSONDepth's own counting convention and
// check_max_depth's identical one on the Python side (#51).
func nestedObjectJSON(depth int) string {
	return strings.Repeat(`{"a":`, depth) + "0" + strings.Repeat("}", depth)
}

// nestedArrayJSON is nestedObjectJSON's array-nesting counterpart --
// maxJSONDepth applies to `[` exactly as it does to `{`.
func nestedArrayJSON(depth int) string {
	return strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
}

// TestCheckMaxDepthAcceptsExactlyMaxDepth and
// TestCheckMaxDepthRejectsOneOverMaxDepth pin the exact boundary #51
// requires: maxJSONDepth must match encoding/json's own real, internal
// limit precisely, confirmed directly against json.Unmarshal itself (depth
// 10000 decodes fine, depth 10001 fails with "invalid character '{'
// exceeded max depth") before this constant was chosen.

func TestCheckMaxDepthAcceptsExactlyMaxDepth(t *testing.T) {
	if reason := checkMaxDepth([]byte(nestedObjectJSON(maxJSONDepth))); reason != "" {
		t.Errorf("nesting exactly maxJSONDepth (%d) levels deep was rejected: %q", maxJSONDepth, reason)
	}
}

func TestCheckMaxDepthRejectsOneOverMaxDepth(t *testing.T) {
	if reason := checkMaxDepth([]byte(nestedObjectJSON(maxJSONDepth + 1))); reason != "max_depth" {
		t.Errorf("nesting maxJSONDepth+1 (%d) levels deep: reason = %q, want \"max_depth\"", maxJSONDepth+1, reason)
	}
}

func TestCheckMaxDepthAppliesToArraysToo(t *testing.T) {
	if reason := checkMaxDepth([]byte(nestedArrayJSON(maxJSONDepth + 1))); reason != "max_depth" {
		t.Errorf("an array nested maxJSONDepth+1 levels deep: reason = %q, want \"max_depth\"", reason)
	}
}

func TestCheckMaxDepthAppliesToMixedObjectArrayNesting(t *testing.T) {
	// The depth counter must thread through BOTH recursive branches
	// (object-member-value and array-element), not just one -- alternating
	// {/[ is the case that would catch a regression to incrementing depth
	// in only one of the two switch cases.
	half := maxJSONDepth/2 + 1
	nested := strings.Repeat(`{"a":[`, half) + "0" + strings.Repeat("]}", half)
	if reason := checkMaxDepth([]byte(nested)); reason != "max_depth" {
		t.Errorf("alternating object/array nesting past maxJSONDepth: reason = %q, want \"max_depth\"", reason)
	}
}

func TestCheckMaxDepthDoesNotFireOnAnOrdinaryDuplicateKeyDocument(t *testing.T) {
	// checkMaxDepth and checkDuplicateKeys are deliberately two independent
	// passes (#51 round 1: see checkMaxDepth's own doc comment for why they
	// were split apart from an earlier, combined design) -- checkMaxDepth
	// itself must have no opinion about a duplicate key, however shallow.
	if reason := checkMaxDepth([]byte(`{"a":1,"a":2}`)); reason != "" {
		t.Errorf("an ordinary shallow duplicate-key document was rejected by checkMaxDepth: %q", reason)
	}
}

func TestCheckDuplicateKeysDoesNotFireOnAnExcessivelyDeepDuplicateFreeDocument(t *testing.T) {
	// The mirror image: checkDuplicateKeys itself must have no opinion
	// about depth, however deep -- it no longer tracks depth at all since
	// #51 round 1 split checkMaxDepth out as its own pass. This document is
	// deep enough that, before that split, checkDuplicateKeys's own
	// (removed) depth counter would have rejected it as "max_depth"; now it
	// walks all the way through and correctly finds nothing.
	if reason := checkDuplicateKeys([]byte(nestedObjectJSON(maxJSONDepth + 1))); reason != "" {
		t.Errorf("an excessively deep, duplicate-free document was rejected by checkDuplicateKeys: %q", reason)
	}
}
