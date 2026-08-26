#!/usr/bin/env python3
"""End-to-end test for the min_format_version skip rule in validate.py.

Not a pytest suite -- py/requirements.txt pins only `cryptography`, and this
repo does not want a test-framework dependency for one behavior. Plain script
with asserts; exits non-zero on failure.

Pins the loop-level skip behavior in main(), not just skip_vector() in
isolation. Asserting only main()'s return code is not enough: the marked
vectors are otherwise-valid data that would pass ordinary validation just as
happily as a skip, so a disabled skip rule would still return 0. This test
captures stdout instead and checks which vectors were actually reported
skipped versus actually validated.

testdata/skip_rule_fixture.json (repo root) names the entries to mark and is
shared with go/version_test.go's equivalent test: both read the same file and
mark the same names on equivalent input (this file loads the real, committed
vectors.json; the Go test loads gen()'s output, which CI's no-drift check
guarantees is byte-identical to it), so a pass in both languages shows the
two implementations agree, not just that each is internally self-consistent.

vectors.json is never mutated on disk -- only an in-memory copy is written to
a temp path.

    python3 py/test_validate.py
"""
import copy
import io
import json
import os
import re
import sys
import tempfile
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(HERE, "..", "vectors.json")
FIXTURE_PATH = os.path.join(HERE, "..", "testdata", "skip_rule_fixture.json")

SKIP_LINE_RE = re.compile(r"^  skip (\S+)\s+requires format_version \d+$", re.MULTILINE)


def _load_real_suite():
    with open(VECTORS_PATH) as f:
        return json.load(f)


def _load_fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def _marked(entries, names, min_ver):
    """Return a deep copy of entries with each of `names`'s
    min_format_version set to min_ver. Does not touch
    canonical/sha256/signature/input -- only the sibling field the skip rule
    reads."""
    out = copy.deepcopy(entries)
    remaining = set(names)
    for e in out:
        if e["name"] in remaining:
            e["min_format_version"] = min_ver
            remaining.discard(e["name"])
    assert not remaining, f"fixture entries {sorted(remaining)!r} not found"
    return out


def _run_main_capturing_stdout(suite):
    """Write `suite` to a temp file and run validate.main() against it
    exactly as `python3 validate.py <path>` would, returning
    (exit_code, captured_stdout)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(suite, f)
        old_argv = sys.argv
        sys.argv = ["validate.py", path]
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                rc = validate.main()
        finally:
            sys.argv = old_argv
        return rc, buf.getvalue()
    finally:
        os.unlink(path)


def _skipped_names(output):
    return sorted(m.group(1) for m in SKIP_LINE_RE.finditer(output))


def test_baseline_suite_still_passes():
    """Sanity check: the unmodified real suite passes end to end, so the
    skip test below is compared against a known-good baseline."""
    rc, output = _run_main_capturing_stdout(_load_real_suite())
    print(output, end="")
    assert rc == 0, f"main() returned {rc} on the unmodified real suite, want 0\n{output}"
    assert _skipped_names(output) == [], (
        f"unmodified real suite reported skips: {_skipped_names(output)}\n{output}"
    )


def test_skip_is_not_a_failure_and_does_not_poison_the_chain():
    """1. A vector above SUPPORTED_FORMAT_VERSION is actually reported
       skipped (not silently validated normally -- disabling the skip rule
       entirely would still return 0 here, since these are otherwise-valid
       vectors) and main() still returns 0: a skip is never a failure.
    2. Every vector/negative NOT marked in the fixture is still validated
       (an "ok" line is present for each) -- this is what catches a
       "skip everything" mutation, and specifically covers
       multi_tip_unsorted_input, chained after the skipped single_tip,
       proving the skip does not poison prev_expected for the next vector's
       chain check. (Without the `prev_expected = None` reset and the
       `prev_expected is not None` guard, this would instead fail with a
       spurious chain break, because multi_tip_unsorted_input's real
       prev_hash chains to single_tip's real hash, not to genesis's.)
    """
    fixture = _load_fixture()
    skip_vectors = fixture["skip_vectors"]
    skip_negatives = fixture["skip_negatives"]

    suite = _load_real_suite()
    suite["vectors"] = _marked(
        suite["vectors"], skip_vectors, validate.SUPPORTED_FORMAT_VERSION + 1
    )
    suite["negatives"] = _marked(
        suite["negatives"], skip_negatives, validate.SUPPORTED_FORMAT_VERSION + 1
    )

    rc, output = _run_main_capturing_stdout(suite)
    print(output, end="")
    assert rc == 0, f"main() returned {rc}, want 0 (a skip must never fail the run)\n{output}"

    want_skipped = sorted(skip_vectors + skip_negatives)
    got_skipped = _skipped_names(output)
    assert got_skipped == want_skipped, (
        f"skipped names = {got_skipped}, want {want_skipped}\n{output}"
    )

    marked = set(skip_vectors) | set(skip_negatives)
    for v in suite["vectors"]:
        if v["name"] in marked:
            assert f"ok  {v['name']}" not in output, (
                f"marked vector {v['name']!r} was validated normally "
                f"(an \"ok\" line appeared); it must be skipped instead\n{output}"
            )
        else:
            assert f"ok  {v['name']}" in output, (
                f"unmarked vector {v['name']!r} was not validated "
                f"(no \"ok\" line found); it must not be skipped\n{output}"
            )
    for nv in suite["negatives"]:
        if nv["name"] in marked:
            assert f"ok  {nv['name']}" not in output, (
                f"marked negative {nv['name']!r} was validated normally "
                f"(an \"ok\" line appeared); it must be skipped instead\n{output}"
            )
        else:
            assert f"ok  {nv['name']}" in output, (
                f"unmarked negative {nv['name']!r} was not validated "
                f"(no \"ok\" line found); it must not be skipped\n{output}"
            )


def test_duplicate_tip_identity_rejected_adjacent():
    """Two tips sharing an identity, adjacent in input order, must make
    canonical() raise -- the checkpoint's canonical bytes would otherwise
    depend on input order."""
    cp = {
        "prev_hash": "e" * 64,
        "seq": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "tips": [
            {"entry_count": 1, "sequence_number": 1, "stream_id": "dup", "tip_hash": "aa"},
            {"entry_count": 2, "sequence_number": 2, "stream_id": "dup", "tip_hash": "bb"},
        ],
    }
    try:
        validate.canonical(cp)
        raise AssertionError("canonical() accepted an adjacent duplicate tip identity; want ValueError")
    except ValueError:
        pass


def test_duplicate_tip_identity_rejected_non_adjacent():
    """A naive adjacent-scan duplicate check (comparing tip i to tip i-1 in
    original, unsorted order) would miss a duplicate pair separated by a
    non-duplicate tip. Only a check over the full set of identities catches
    this -- this is the case the Task 2 review flagged as uncovered."""
    cp = {
        "prev_hash": "e" * 64,
        "seq": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "tips": [
            {"entry_count": 1, "sequence_number": 1, "stream_id": "dup", "tip_hash": "aa"},
            {"entry_count": 3, "sequence_number": 3, "stream_id": "other", "tip_hash": "cc"},
            {"entry_count": 2, "sequence_number": 2, "stream_id": "dup", "tip_hash": "bb"},
        ],
    }
    try:
        validate.canonical(cp)
        raise AssertionError("canonical() accepted a non-adjacent duplicate tip identity; want ValueError")
    except ValueError:
        pass


def main():
    tests = [
        test_baseline_suite_still_passes,
        test_skip_is_not_a_failure_and_does_not_poison_the_chain,
        test_duplicate_tip_identity_rejected_adjacent,
        test_duplicate_tip_identity_rejected_non_adjacent,
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
