package main

import "testing"

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
