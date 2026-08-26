#!/usr/bin/env python3
"""End-to-end test for the min_format_version skip rule in validate.py.

Not a pytest suite -- py/requirements.txt pins only `cryptography`, and this
repo does not want a test-framework dependency for one behavior. Plain script
with asserts; exits non-zero on failure.

Pins the loop-level skip behavior in main(), not just skip_vector() in
isolation: it loads the real, committed vectors.json, marks the middle
positive vector ("single_tip") and one negative ("tampered_signature") as
requiring a format newer than SUPPORTED_FORMAT_VERSION, writes the result to
a temp file, and runs main() against it exactly as a real invocation would.

vectors.json is never mutated on disk -- only an in-memory copy is written to
a temp path. The go/version_test.go end-to-end test marks the same two named
entries, starting from gen()'s output, which CI's no-drift check guarantees
is byte-identical to this file. So both implementations skip the same
vectors and must reach the same PASS verdict on equivalent input -- that
parity is what this test and its Go counterpart together establish.

    python3 py/test_validate.py
"""
import copy
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate  # noqa: E402

VECTORS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "vectors.json"
)


def _load_real_suite():
    with open(VECTORS_PATH) as f:
        return json.load(f)


def _marked(entries, name, min_ver):
    """Return a deep copy of entries with entry `name`'s min_format_version
    set to min_ver. Does not touch canonical/sha256/signature/input -- only
    the sibling field the skip rule reads."""
    out = copy.deepcopy(entries)
    found = False
    for e in out:
        if e["name"] == name:
            e["min_format_version"] = min_ver
            found = True
    assert found, f"fixture entry {name!r} not found in vectors.json"
    return out


def _run_main(suite):
    """Write `suite` to a temp file and run validate.main() against it
    exactly as `python3 validate.py <path>` would, returning its exit code."""
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(suite, f)
        old_argv = sys.argv
        sys.argv = ["validate.py", path]
        try:
            return validate.main()
        finally:
            sys.argv = old_argv
    finally:
        os.unlink(path)


def test_baseline_suite_still_passes():
    """Sanity check: the unmodified real suite passes end to end, so the
    skip test below is compared against a known-good baseline."""
    rc = _run_main(_load_real_suite())
    assert rc == 0, f"main() returned {rc} on the unmodified real suite, want 0"


def test_skip_is_not_a_failure_and_does_not_poison_the_chain():
    """1. A vector above SUPPORTED_FORMAT_VERSION is skipped and main()
       still returns 0 -- a skip is never a failure.
    2. multi_tip_unsorted_input, chained after the skipped single_tip, still
       validates -- proving the skip does not poison prev_expected for the
       next vector's chain check. (Without the `prev_expected = None` reset
       and the `prev_expected is not None` guard, this would instead fail
       with a spurious chain break, because multi_tip_unsorted_input's real
       prev_hash chains to single_tip's real hash, not to genesis's.)
    """
    suite = _load_real_suite()
    suite["vectors"] = _marked(
        suite["vectors"], "single_tip", validate.SUPPORTED_FORMAT_VERSION + 1
    )
    suite["negatives"] = _marked(
        suite["negatives"], "tampered_signature", validate.SUPPORTED_FORMAT_VERSION + 1
    )

    rc = _run_main(suite)
    assert rc == 0, f"main() returned {rc}, want 0 (a skip must never fail the run)"


def main():
    tests = [
        test_baseline_suite_still_passes,
        test_skip_is_not_a_failure_and_does_not_poison_the_chain,
    ]
    failed = []
    for t in tests:
        print(f"--- {t.__name__}")
        try:
            t()
        except AssertionError as e:
            print(f"FAIL: {t.__name__}: {e}")
            failed.append(t.__name__)
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        return 1
    print("PASS: all end-to-end skip-rule tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
