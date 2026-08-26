#!/usr/bin/env python3
"""Tests for validate.py: the min_format_version skip rule (end to end) and
the Tier B cross-checkpoint rules (unit, mirroring go/tierb_test.go).

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


def _tip(stream, epoch, seq, count, tip):
    return {"entry_count": count, "epoch": epoch, "sequence_number": seq,
            "stream_id": stream, "tip_hash": tip}


def _cp(seq, ts, tips, prev="e" * 64):
    return {"prev_hash": prev, "seq": seq, "timestamp": ts, "tips": tips}


# The Tier B tests below mirror go/tierb_test.go one-for-one. Both languages
# assert the same rejections and the same exact warning tokens, so a pass in
# both shows the two implementations agree on Tier B -- not merely that each is
# internally self-consistent.

def test_b3_rejects_same_stream_same_epoch():
    """B3: the same (stream_id, epoch) committed twice in one chain is a hard
    reject, whether or not the tips differ. Within one producer generation the
    dedup map is intact, so no second commit of any kind is legitimate."""
    chain = [
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 3, 3, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 0, 2, 2, "bb")]),
    ]
    err, _ = validate.check_tier_b(chain)
    assert err is not None, "check_tier_b accepted a same-epoch re-commit; want a rejection"


def test_b4_accepts_same_stream_new_epoch_with_warning():
    """B4: the same stream under a NEW epoch is the declared at-least-once
    path. It must be accepted even when entry_count goes backwards, because an
    honest timeout-split produces exactly that shape -- and it must warn."""
    chain = [
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 7, 7, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 1, 5, 5, "bb")]),
    ]
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"check_tier_b rejected a legitimate cross-epoch re-commit: {err}"
    assert warns == ["B4:s1"], f"warnings = {warns}, want exactly ['B4:s1']"


def test_b5_warns_on_timestamp_regression():
    """B5: a timestamp regression warns and does not reject."""
    chain = [
        _cp(1, "2026-01-01T00:00:10Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s2", 0, 1, 1, "bb")]),
    ]
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"timestamp regression must warn, not reject: {err}"
    assert warns == ["B5:2"], f"warnings = {warns}, want exactly ['B5:2']"


def test_b1_rejects_seq_skip():
    """B1: seq must increment by exactly 1 -- not merely increase."""
    chain = [
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(3, "2026-01-01T00:00:05Z", [_tip("s2", 0, 1, 1, "bb")]),
    ]
    err, _ = validate.check_tier_b(chain)
    assert err is not None, "check_tier_b accepted a seq gap; want a rejection"


def test_r4_composite_sort_key():
    """R4: two tips for one stream at different epochs are legal in ONE
    checkpoint, so the sort key must be composite or the canonical bytes
    depend on input order."""
    x = _tip("s1", 0, 1, 1, "aa")
    y = _tip("s1", 1, 2, 2, "bb")
    c1 = validate.canonical(_cp(1, "2026-01-01T00:00:00Z", [x, y]))
    c2 = validate.canonical(_cp(1, "2026-01-01T00:00:00Z", [y, x]))
    assert c1 == c2, f"input order changed canonical bytes:\n {c1}\n {c2}"


def test_epoch_presence_boundary():
    """Spec 5a: epoch is required at format_version 2 and above, and must be
    absent in version-1 vectors. A v2 tip missing epoch must be rejected, not
    defaulted to 0."""
    v2_missing = _cp(1, "2026-01-01T00:00:00Z", [
        {"entry_count": 1, "sequence_number": 1, "stream_id": "s1", "tip_hash": "aa"}])
    assert validate.check_epoch_presence(v2_missing, 2) is not None, (
        "a version-2 tip with no epoch must be rejected")
    assert validate.check_epoch_presence(v2_missing, 0) is None, (
        "a version-1 tip with no epoch is well-formed")
    v1_with = _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa")])
    assert validate.check_epoch_presence(v1_with, 0) is not None, (
        "epoch is not permitted in a version-1 vector")
    assert validate.check_epoch_presence(v1_with, 2) is None, (
        "a version-2 tip with an explicit epoch is well-formed")


def test_version1_tip_omits_epoch():
    """A version-1 tip carries no epoch key, and canonicalizing must not add
    one. This is what keeps the six frozen vectors byte-identical."""
    cp = _cp(1, "2026-01-01T00:00:00Z", [
        {"entry_count": 1, "sequence_number": 1, "stream_id": "s1", "tip_hash": "aa"}])
    cb = validate.canonical(cp)
    assert b"epoch" not in cb, f"version-1 canonical bytes must not contain an epoch key: {cb!r}"


def main():
    tests = [
        test_baseline_suite_still_passes,
        test_skip_is_not_a_failure_and_does_not_poison_the_chain,
        test_duplicate_tip_identity_rejected_adjacent,
        test_duplicate_tip_identity_rejected_non_adjacent,
        test_b3_rejects_same_stream_same_epoch,
        test_b4_accepts_same_stream_new_epoch_with_warning,
        test_b5_warns_on_timestamp_regression,
        test_b1_rejects_seq_skip,
        test_r4_composite_sort_key,
        test_epoch_presence_boundary,
        test_version1_tip_omits_epoch,
    ]
    failed = []
    for t in tests:
        print(f"--- {t.__name__}")
        try:
            t()
        except Exception as e:
            # Catch Exception, not just AssertionError: a broken implementation
            # can raise (e.g. canonical() rejecting a legal input) rather than
            # fail an assert, and that must be reported as a named test
            # failure, not crash the runner with no attribution.
            print(f"FAIL: {t.__name__}: {type(e).__name__}: {e}")
            failed.append(t.__name__)
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        return 1
    print("PASS: all skip-rule and Tier B tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
