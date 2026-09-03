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


def _run_main_on_raw(text):
    """As above, but writes `text` verbatim. json.dump can only produce a
    single well-formed document, so a file with trailing data after the suite
    object -- the thing being tested -- cannot be built through it."""
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
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


def _link(*cps):
    """Fill in each checkpoint's prev_hash from its predecessor's canonical
    bytes, so a hand-built test chain satisfies B2 and can exercise the other
    rules. Tests that mean to break the linkage set prev_hash themselves."""
    import hashlib as _h
    out = []
    prev = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    for cp in cps:
        cp = dict(cp)
        cp["prev_hash"] = prev
        out.append(cp)
        prev = _h.sha256(validate.canonical(cp)).hexdigest()
    return out


# The Tier B tests below mirror go/tierb_test.go one-for-one. Both languages
# assert the same rejections and the same exact warning tokens, so a pass in
# both shows the two implementations agree on Tier B -- not merely that each is
# internally self-consistent.

def test_b3_rejects_same_stream_same_epoch():
    """B3: the same (stream_id, epoch) committed twice in one chain is a hard
    reject, whether or not the tips differ. Within one producer generation the
    dedup map is intact, so no second commit of any kind is legitimate."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 3, 3, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 0, 2, 2, "bb")]))
    err, _ = validate.check_tier_b(chain)
    assert err is not None, "check_tier_b accepted a same-epoch re-commit; want a rejection"


def test_b4_accepts_same_stream_new_epoch_with_warning():
    """B4: the same stream under a NEW epoch is the declared at-least-once
    path. It must be accepted even when entry_count goes backwards, because an
    honest timeout-split produces exactly that shape -- and it must warn."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 7, 7, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 1, 5, 5, "bb")]))
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"check_tier_b rejected a legitimate cross-epoch re-commit: {err}"
    assert warns == ["B4:s1"], f"warnings = {warns}, want exactly ['B4:s1']"


def test_b5_warns_on_timestamp_regression():
    """B5: a timestamp regression warns and does not reject."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:10Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s2", 0, 1, 1, "bb")]))
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"timestamp regression must warn, not reject: {err}"
    assert warns == ["B5:2"], f"warnings = {warns}, want exactly ['B5:2']"


def test_b1_rejects_seq_skip():
    """B1: seq must increment by exactly 1 -- not merely increase."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(3, "2026-01-01T00:00:05Z", [_tip("s2", 0, 1, 1, "bb")]))
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


# --- Round-1 review fixes -------------------------------------------------

def _pub():
    import json as _json
    with open(VECTORS_PATH) as f:
        suite = _json.load(f)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(suite["public_key_hex"]))


def _signed_from_vectors(name):
    """Pull a real signed chain prefix out of the committed suite, so these
    tests use genuine key material rather than re-deriving signatures."""
    with open(VECTORS_PATH) as f:
        suite = json.load(f)
    for e in suite["vectors"] + suite["negatives"]:
        if e["name"] == name:
            return e["chain"][0]
    raise AssertionError(f"{name!r} not found in vectors.json")


def test_prefix_signature_is_verified():
    """The MUST on chain prefixes: the signature is verified, not merely hashed
    for linkage. A verifier that skipped this would accept a forged history."""
    import base64 as _b64
    pub = _pub()
    good = _signed_from_vectors("advisory_stream_recommitted_new_epoch")
    prefixes, reason = validate.verify_prefixes(pub, [good], 2)
    assert reason == "", f"a correctly signed prefix was rejected ({reason})"
    assert len(prefixes) == 1

    raw = bytearray(_b64.b64decode(good["signature"]))
    raw[0] ^= 0x01
    bad = {"input": good["input"], "signature": _b64.b64encode(bytes(raw)).decode()}
    _, reason = validate.verify_prefixes(pub, [bad], 2)
    assert reason == "signature", f"tampered prefix signature: reason={reason!r}, want 'signature'"


def test_prefix_epoch_presence_is_checked():
    """The format_version boundary applies to chain prefixes too. Unchecked,
    tip_epoch reads a missing epoch as 0 and it silently feeds B3 identity and
    B4 comparisons."""
    pub = _pub()
    good = _signed_from_vectors("advisory_stream_recommitted_new_epoch")
    stripped = copy.deepcopy(good)
    for t in stripped["input"]["tips"]:
        t.pop("epoch", None)
    _, reason = validate.verify_prefixes(pub, [stripped], 2)
    assert reason == "schema", f"v2 prefix with no epoch: reason={reason!r}, want 'schema'"
    # ...and at index >= 1: a chain[0]-only epoch check misses this.
    _, reason = validate.verify_prefixes(pub, [good, stripped], 2)
    assert reason == "schema", (
        f"SECOND v2 prefix with no epoch: reason={reason!r}, want 'schema'")


def test_epoch_presence_scans_all_tips():
    """check_epoch_presence must scan every tip, not just the first."""
    missing_on_second = _cp(1, "2026-01-01T00:00:00Z", [
        _tip("s1", 0, 1, 1, "aa"),
        {"entry_count": 2, "sequence_number": 2, "stream_id": "s2", "tip_hash": "bb"},
    ])
    assert validate.check_epoch_presence(missing_on_second, 2) is not None, (
        "epoch missing on the SECOND tip must be rejected; a tips[0]-only check would miss it")
    negative_on_second = _cp(1, "2026-01-01T00:00:00Z", [
        _tip("s1", 0, 1, 1, "aa"), _tip("s2", -1, 2, 2, "bb")])
    assert validate.check_epoch_presence(negative_on_second, 2) is not None, (
        "a negative epoch on the SECOND tip must be rejected")


def test_negative_epoch_rejected():
    """A negative epoch is rejected rather than ordered. The two references
    agree on how to order one -- both compare the identity as a pair -- so the
    rule is about the third party: an implementation that builds a TEXT sort
    key puts a leading "-" above the digits and orders -10 above -1. Mirrors
    TestNegativeEpochRejected."""
    cp = _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", -1, 1, 1, "aa")])
    assert validate.check_epoch_presence(cp, 2) is not None, "a negative epoch must be rejected"


def test_composite_sort_key_is_numeric_for_multi_digit_epochs():
    """The sort key must order epochs NUMERICALLY. An implementation that
    compares the epoch as TEXT puts 10 before 2 and disagrees with this one on
    published bytes. test_r4_composite_sort_key cannot catch that: it uses
    single-digit epochs, where text and numeric order coincide."""
    lo = _tip("s1", 2, 3, 3, "aa")
    hi = _tip("s1", 10, 11, 11, "bb")
    assert validate.tip_identity(lo) < validate.tip_identity(hi), (
        f"epoch 2 must sort below epoch 10, got {validate.tip_identity(lo)} "
        f">= {validate.tip_identity(hi)}")
    cb = validate.canonical(_cp(1, "2026-01-01T00:00:00Z", [hi, lo])).decode()
    assert cb.index('"epoch":2') < cb.index('"epoch":10'), (
        f"epoch 10 was sorted before epoch 2 -- the sort key is not numeric:\n {cb}")


def test_b4_and_b5_both_raised_in_order():
    """B4 and B5 raised by the same checkpoint, in a pinned order. Without a
    case where both fire, their interleaving is verified by nothing."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:10Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 1, 2, 2, "bb")]))
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"both advisory rules must warn, not reject: {err}"
    assert warns == ["B4:s1", "B5:2"], f"warnings = {warns}, want ['B4:s1', 'B5:2']"


# --- Round-2 review fixes -------------------------------------------------

def test_b4_token_order_is_independent_of_tip_input_order():
    """The identity-order tip walk. Two DIFFERENT streams each changing epoch
    in one checkpoint must emit their B4 tokens in a fixed order regardless of
    how the tips were supplied -- warnings are compared as ordered lists, and a
    checkpoint's tips are explicitly allowed to arrive unsorted."""
    prefix = _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa"), _tip("s2", 0, 2, 2, "bb")])
    lo, hi = _tip("s1", 1, 3, 3, "cc"), _tip("s2", 1, 4, 4, "dd")

    # Same signed bytes either way: canonical() sorts the tips, so both
    # checkpoints hash identically and both chains satisfy B2.
    err_a, warns_a = validate.check_tier_b(
        _link(prefix, _cp(2, "2026-01-01T00:00:05Z", [lo, hi])))
    err_b, warns_b = validate.check_tier_b(
        _link(prefix, _cp(2, "2026-01-01T00:00:05Z", [hi, lo])))
    assert err_a is None and err_b is None, f"neither ordering may reject: {err_a} / {err_b}"
    want = ["B4:s1", "B4:s2"]
    assert warns_a == want, f"identity-order input: warnings = {warns_a}, want {want}"
    assert warns_b == want, (
        f"reversed input: warnings = {warns_b}, want {want} -- "
        "tip input order leaked into the warning sequence")


def test_b4_emitted_once_per_transition():
    """B4 is emitted once per epoch TRANSITION, not once per checkpoint: one
    stream at three epochs in a single checkpoint yields two identical tokens."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 2, 3, 3, "bb"), _tip("s1", 1, 2, 2, "cc")]))
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"three epochs for one stream is legal (R4), got: {err}"
    assert warns == ["B4:s1", "B4:s1"], (
        f"warnings = {warns}, want ['B4:s1', 'B4:s1'] (0->1 and 1->2 are two transitions)")


def test_verify_prefixes_checks_every_prefix():
    """verify_prefixes must check EVERY prefix, not just chain[0]."""
    import base64 as _b64
    pub = _pub()
    good = _signed_from_vectors("advisory_stream_recommitted_new_epoch")
    raw = bytearray(_b64.b64decode(good["signature"]))
    raw[0] ^= 0x01
    bad = {"input": good["input"], "signature": _b64.b64encode(bytes(raw)).decode()}
    _, reason = validate.verify_prefixes(pub, [good, bad], 2)
    assert reason == "signature", (
        f"tampered SECOND prefix: reason={reason!r}, want 'signature' -- "
        "a chain[0]-only check misses it")


def test_chainless_expect_warnings_are_still_checked():
    """The positive-path Tier B guard fires on expect_warnings alone, not only
    when a chain is present. Without that arm a chainless vector's advisory
    assertion is never evaluated and a validator that ignores B4 still passes
    the whole suite."""
    suite = _load_real_suite()
    v = None
    for cand in suite["vectors"]:
        if cand["name"] == "multi_epoch_same_stream":
            v = copy.deepcopy(cand)
    assert v is not None, "multi_epoch_same_stream not found in vectors.json"
    # Drop the chain (the signature covers only the input, so it still
    # verifies) and state warnings that cannot be right.
    v.pop("chain", None)
    v["expect_warnings"] = ["B4:this-stream-does-not-exist"]
    suite["vectors"] = [v]
    suite["negatives"] = []

    rc, output = _run_main_capturing_stdout(suite)
    assert rc != 0, (
        "a chainless vector with wrong expect_warnings was accepted; the Tier B "
        f"guard must fire on expect_warnings alone\n{output}")
    assert "warnings" in output, f"rejected, but not for the warning mismatch:\n{output}"


# --- Round-3 review fixes -------------------------------------------------

def test_b4_fires_on_epoch_regression():
    """B4 fires when a stream's epoch DIFFERS from its previous committed
    epoch, in either direction. A stream re-committed under an OLDER generation
    is the most rollback-shaped case B4 exists to surface, and B3 does not cover
    it: (s,5) and (s,3) are distinct identities."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 5, 9, 9, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s1", 3, 4, 4, "bb")]))
    err, warns = validate.check_tier_b(chain)
    assert err is None, f"an epoch regression is advisory, not a rejection: {err}"
    assert warns == ["B4:s1"], (
        f"warnings = {warns}, want ['B4:s1'] -- B4 must fire on epoch DIFFERENCE, not increase")


def test_chain_prev_hash_linkage_is_checked():
    """B2 must hold across the whole assembled chain, not only at the vector's
    own link: a chain whose prefixes do not hash-link is a forged history."""
    good = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s2", 0, 2, 2, "bb")]),
        _cp(3, "2026-01-01T00:00:10Z", [_tip("s3", 0, 3, 3, "cc")]))
    err, _ = validate.check_tier_b(good)
    assert err is None, f"a correctly linked chain was rejected: {err}"
    # Break the link between the two PREFIXES, leaving the last link intact --
    # exactly what a vector-level prev_sha256 field cannot see.
    broken = copy.deepcopy(good)
    broken[1]["prev_hash"] = "22" * 32
    err, _ = validate.check_tier_b(broken)
    assert err is not None, (
        "check_tier_b accepted a chain whose second checkpoint does not link to the first")


def test_b1_checked_on_every_transition():
    """B1 must hold at every transition, not only between chain[0] and chain[1]."""
    chain = _link(
        _cp(1, "2026-01-01T00:00:00Z", [_tip("s1", 0, 1, 1, "aa")]),
        _cp(2, "2026-01-01T00:00:05Z", [_tip("s2", 0, 2, 2, "bb")]),
        _cp(4, "2026-01-01T00:00:10Z", [_tip("s3", 0, 3, 3, "cc")]))
    err, _ = validate.check_tier_b(chain)
    assert err is not None, (
        "check_tier_b accepted a seq gap at the SECOND transition; "
        "B1 must hold at every transition")


def test_warning_order_is_part_of_the_contract():
    """expect_warnings is an ORDERED contract. No published vector can catch a
    comparison weakened to a multiset, because every vector's expectation is
    correct and a looser comparison never fails on correct data -- only feeding
    a PERMUTED expectation can distinguish the two."""
    suite = _load_real_suite()
    v = None
    for cand in suite["vectors"]:
        if cand["name"] == "advisory_chain_b5_then_b4":
            v = copy.deepcopy(cand)
    assert v is not None, "advisory_chain_b5_then_b4 not found in vectors.json"
    assert len(v["expect_warnings"]) == 2, (
        f"this test needs a two-warning vector, got {v['expect_warnings']}")
    v["expect_warnings"] = [v["expect_warnings"][1], v["expect_warnings"][0]]
    suite["vectors"] = [v]
    suite["negatives"] = []

    rc, output = _run_main_capturing_stdout(suite)
    assert rc != 0, (
        "permuted expect_warnings was accepted; the comparison must be ordered, "
        f"not a multiset\n{output}")
    assert "warnings" in output, f"rejected, but not for the warning mismatch:\n{output}"



# --- Position-generic tests (round 4) -------------------------------------
#
# Every VECTOR in this suite pins its rule at exactly one chain position, so
# any mutation of the form "apply this check only at position X" escapes the
# vectors unless some vector happens to sit at X. Adding more hand-placed
# vectors only moves the hole; it never closes it.
#
# The tests below are generic over position instead: for a rule and a chain of
# length N they inject the defect at EVERY index in turn and require the rule
# to fire each time. A validator that applies the rule at only one position
# fails N-2 of the cases, whichever position it picked. Mirrors
# go/positional_test.go one-for-one, so a pass in both shows the two
# implementations agree rather than each being internally self-consistent.

# Five checkpoints give four transitions: a first, two middles and a last.
POS_CHAIN_LEN = 5


def _pos_ts(sec):
    return f"2026-01-01T00:{sec // 60:02d}:{sec % 60:02d}Z"


def _pos_stream(n):
    return f"{n:08d}-0000-4000-8000-{n:012d}"


def _pos_clean(n):
    """A Tier-B-clean chain of n checkpoints: seq 1..n, strictly increasing
    timestamps, one distinct stream each at epoch 0. Callers inject a single
    defect at a chosen index, then link."""
    return [_cp(i + 1, _pos_ts(100 + 10 * i),
                [_tip(_pos_stream(i + 1), 0, i + 1, i + 1, f"{i + 1:02x}")])
            for i in range(n)]


def _pos_relink(cps, start):
    """Recompute prev_hash from index `start` onwards, so a chain carries
    exactly the one defect the caller injected."""
    import hashlib as _h
    for i in range(start, len(cps)):
        cps[i]["prev_hash"] = _h.sha256(validate.canonical(cps[i - 1])).hexdigest()


def _priv():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    # The TEST-ONLY signing seed is published in the suite header, so these
    # tests use genuine key material without a second copy of it.
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(_load_real_suite()["signing_seed_hex"]))


def _sign(priv, cp):
    import base64 as _b64
    return {"input": cp,
            "signature": _b64.b64encode(priv.sign(validate.canonical(cp))).decode()}


def test_b1_fires_at_every_transition():
    """B1 must hold at EVERY transition, not at the first (which seq_skip pins)
    nor at the last (which seq_skip_after_first_transition pins)."""
    for d in range(1, POS_CHAIN_LEN):
        cps = _pos_clean(POS_CHAIN_LEN)
        # One gap, at transition d; every later transition stays contiguous.
        for i in range(d, POS_CHAIN_LEN):
            cps[i]["seq"] += 1
        err, _ = validate.check_tier_b(_link(*cps))
        assert err is not None, (
            f"seq gap at transition {d} accepted; B1 must hold at every transition")
        assert err.startswith("B1:"), (
            f"seq gap at transition {d} rejected by {err!r}; want a B1 rejection")


def test_b2_fires_at_every_transition():
    """B2 must hold at EVERY transition, including the LAST -- a vector's own
    link to its final prefix. prev_sha256 pins only that last link and only for
    chainless vectors, so nothing else reaches it through check_tier_b."""
    for d in range(1, POS_CHAIN_LEN):
        chain = _link(*_pos_clean(POS_CHAIN_LEN))
        chain[d]["prev_hash"] = "22" * 32
        _pos_relink(chain, d + 1)
        err, _ = validate.check_tier_b(chain)
        assert err is not None, (
            f"broken link at transition {d} accepted; B2 must hold at every transition")
        assert err.startswith("B2:"), (
            f"broken link at transition {d} rejected by {err!r}; want a B2 rejection")


def test_b3_fires_for_every_position_pair():
    """B3 spans the WHOLE chain: a repeat of a (stream_id, epoch) is a
    rejection wherever the two commits sit, including between two prefixes
    with the vector's own input clean."""
    for a in range(POS_CHAIN_LEN):
        for b in range(a + 1, POS_CHAIN_LEN):
            cps = _pos_clean(POS_CHAIN_LEN)
            cps[b]["tips"][0]["stream_id"] = cps[a]["tips"][0]["stream_id"]
            cps[b]["tips"][0]["tip_hash"] = "ff"
            err, _ = validate.check_tier_b(_link(*cps))
            assert err is not None, (
                f"identity repeated at {a} and {b} accepted; B3 spans the whole chain")
            assert err.startswith("B3:"), (
                f"identity repeated at {a} and {b} rejected by {err!r}; want a B3 rejection")


def test_b4_fires_at_every_transition():
    """B4 fires at EVERY transition. Asserted as an exact ordered list, so a
    check pinned to one index shows up as a missing token here and a spurious
    one elsewhere."""
    for d in range(1, POS_CHAIN_LEN):
        cps = _pos_clean(POS_CHAIN_LEN)
        cps[d]["tips"][0]["stream_id"] = _pos_stream(1)  # re-commit checkpoint 1's stream
        cps[d]["tips"][0]["epoch"] = 1
        err, warns = validate.check_tier_b(_link(*cps))
        assert err is None, (
            f"cross-epoch re-commit at index {d} is advisory, not a rejection: {err}")
        assert warns == ["B4:" + _pos_stream(1)], (
            f"epoch change at index {d}: warnings {warns}, want ['B4:{_pos_stream(1)}']")

        # The same transition, but the stream's PREVIOUS commit sits at index
        # d-1 rather than at chain[0]. A validator that records epochs only
        # from chain[0] passes the case above and fails this one.
        cps = _pos_clean(POS_CHAIN_LEN)
        cps[d]["tips"][0]["stream_id"] = _pos_stream(d)  # committed at index d-1
        cps[d]["tips"][0]["epoch"] = 1
        err, warns = validate.check_tier_b(_link(*cps))
        assert err is None, (
            f"cross-epoch re-commit at index {d} is advisory, not a rejection: {err}")
        assert warns == ["B4:" + _pos_stream(d)], (
            f"epoch change at index {d} (previous commit at {d - 1}): "
            f"warnings {warns}, want ['B4:{_pos_stream(d)}']")


def test_b5_fires_at_every_transition():
    """B5 compares against the IMMEDIATE predecessor at every transition. Each
    regressed timestamp below is still above chain[0]'s, so a validator
    comparing against chain[0] misses the real regression and invents others."""
    for d in range(1, POS_CHAIN_LEN):
        cps = _pos_clean(POS_CHAIN_LEN)
        cps[d]["timestamp"] = _pos_ts(100 + 10 * (d - 1) - 1)  # one second before its predecessor
        err, warns = validate.check_tier_b(_link(*cps))
        assert err is None, (
            f"timestamp regression at index {d} is advisory, not a rejection: {err}")
        assert warns == [f"B5:{cps[d]['seq']}"], (
            f"regression at index {d}: warnings {warns}, want ['B5:{cps[d]['seq']}']")


def test_b2_hashes_canonical_bytes_not_as_received():
    """B2 hashes the previous checkpoint's CANONICAL bytes, not the bytes as
    received. A checkpoint's tips are explicitly allowed to arrive unsorted, so
    a validator that serialized the checkpoint without first imposing the tip
    order would compute a different digest and reject a legitimate chain."""
    unsorted_cp = _cp(2, _pos_ts(110), [
        _tip(_pos_stream(9), 0, 9, 9, "99"),  # sorts AFTER _pos_stream(3)
        _tip(_pos_stream(3), 0, 3, 3, "33"),
    ])
    chain = _link(
        _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "11")]),
        unsorted_cp,
        _cp(3, _pos_ts(120), [_tip(_pos_stream(2), 0, 2, 2, "22")]))

    # The test only discriminates if the two byte strings actually differ.
    as_received = json.dumps(chain[1], sort_keys=True, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
    assert validate.canonical(chain[1]) != as_received, (
        "fixture is not discriminating: the prefix's tips are already in identity order")

    err, _ = validate.check_tier_b(chain)
    assert err is None, (
        f"a chain whose prefix supplies tips out of identity order was rejected: {err}")


def test_prefix_rules_fire_at_every_prefix_index():
    """verify_prefixes applies BOTH of its rules at every prefix index.
    Tampering index 0 and index len-1 are the two positions the suite's vectors
    happen to occupy; a middle index is the one neither reaches."""
    import base64 as _b64
    n = 4
    pub, priv = _pub(), _priv()
    for d in range(n):
        cps = _link(*_pos_clean(n))
        prefixes = [_sign(priv, cp) for cp in cps]
        raw = bytearray(_b64.b64decode(prefixes[d]["signature"]))
        raw[0] ^= 0x01
        prefixes[d] = {"input": prefixes[d]["input"],
                       "signature": _b64.b64encode(bytes(raw)).decode()}
        _, reason = validate.verify_prefixes(pub, prefixes, 2)
        assert reason == "signature", (
            f"tampered prefix {d}: reason={reason!r}, want 'signature'")

        cps = _pos_clean(n)
        del cps[d]["tips"][0]["epoch"]
        cps = _link(*cps)
        prefixes = [_sign(priv, cp) for cp in cps]
        _, reason = validate.verify_prefixes(pub, prefixes, 2)
        assert reason == "schema", (
            f"prefix {d} missing epoch: reason={reason!r}, want 'schema'")


def test_malformed_checkpoint_rejects_cleanly():
    """A checkpoint with keys missing must produce a clean B-rule rejection,
    not a crash. Go decodes the absent keys into zero values and rejects at B2;
    this implementation read cp["prev_hash"] directly and raised KeyError, so
    the two references disagreed on third-party input -- exactly the defect
    class this suite publishes vectors against. Mirrors
    TestMalformedCheckpointRejectsCleanly."""
    head = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "11")],
               prev="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    # No prev_hash and no timestamp key at all.
    bare = {"seq": 2, "tips": [_tip(_pos_stream(2), 0, 2, 2, "22")]}
    err, _ = validate.check_tier_b([head, bare])
    assert err is not None, "a checkpoint with no prev_hash was accepted; want a B2 rejection"
    assert err.startswith("B2:"), (
        f"checkpoint with no prev_hash rejected by {err!r}; want a B2 rejection")



# --- Cross-product position tests (round 5) -------------------------------
#
# The positional tests above close ONE factor of "position": the index of a
# checkpoint within a chain. Position is a product of at least four:
#
#     (chain index) x (tip index within a checkpoint)
#                   x (prefix vs the vector's own checkpoint)
#                   x (vector-list index in the suite file)
#
# plus two the rules do not own at all: the order of the warning list a
# verifier reports, and the order of the chain array it was handed. A mutation
# of the form "apply this check only at position X" escapes on any factor left
# unswept. Mirrors go/crossproduct_test.go one-for-one.

CHECKED_RE = re.compile(
    r"checked: (\d+) positive \((\d+) through Tier B\) \+ (\d+) negative")


def _xp_tips(i, k):
    """k tips for checkpoint i, all epoch 0 with distinct streams, supplied in
    REVERSE identity order so sorting is actually exercised."""
    return [_tip(_pos_stream(100 * i + j), 0, j, j, f"{j:02x}") for j in range(k, 0, -1)]


def _xp_interleaved(k):
    """Two checkpoints whose tips interleave: cp0 carries the odd-numbered
    streams and cp1 the even ones, so replacing cp1's tip at index d with cp0's
    stream 2d+1 keeps it at identity position d."""
    a = [_tip(_pos_stream(2 * j + 1), 0, j + 1, j + 1, f"a{j}") for j in range(k)]
    b = [_tip(_pos_stream(2 * j + 2), 0, j + 1, j + 1, f"b{j}") for j in range(k)]
    return [_cp(1, _pos_ts(100), a), _cp(2, _pos_ts(110), b)]


def _synthetic_suite(vectors=(), negatives=()):
    """A suite carrying the real header (so the published public key verifies)
    and only the entries given."""
    real = _load_real_suite()
    return {"format_version": real["format_version"], "description": real["description"],
            "algorithm": real["algorithm"], "signing_seed_hex": real["signing_seed_hex"],
            "public_key_hex": real["public_key_hex"],
            "vectors": list(vectors), "negatives": list(negatives)}


def test_epoch_presence_fires_at_every_tip_index():
    """The epoch boundary and the non-negativity guard must fire at EVERY tip
    index and at every magnitude. Both epoch negatives put their defect on the
    last tip of two, so a check reading only the last tip -- or only the first --
    passes the whole published suite."""
    k = 4
    clean = _cp(1, _pos_ts(100), _xp_tips(1, k))
    assert validate.check_epoch_presence(clean, 2) is None, \
        "a clean version-2 checkpoint was rejected"
    for d in range(k):
        cp = _cp(1, _pos_ts(100), _xp_tips(1, k))
        del cp["tips"][d]["epoch"]
        assert validate.check_epoch_presence(cp, 2) is not None, \
            f"tip {d} of {k} missing epoch was accepted at version 2"
        for mag in (-1, -3, -1000):
            cp = _cp(1, _pos_ts(100), _xp_tips(1, k))
            cp["tips"][d]["epoch"] = mag
            assert validate.check_epoch_presence(cp, 2) is not None, \
                f"tip {d} of {k} with epoch {mag} was accepted"


def test_b3_fires_for_every_tip_index_pair():
    """B3 must fire for a duplicate involving ANY tip index in either
    checkpoint. Every B3 vector before this round duplicated a checkpoint's
    only tip."""
    k = 4
    for a in range(k):
        for b in range(k):
            cps = _xp_interleaved(k)
            cps[1]["tips"][b]["stream_id"] = cps[0]["tips"][a]["stream_id"]
            err, _ = validate.check_tier_b(_link(*cps))
            assert err is not None, \
                f"identity of cp0 tip {a} repeated at cp1 tip {b} was accepted"
            assert err.startswith("B3:"), \
                f"cp0 tip {a} / cp1 tip {b} rejected by {err!r}; want a B3 rejection"


def test_b4_fires_at_every_tip_index():
    """B4 must fire for an epoch change on ANY tip index, interior included."""
    k = 4
    for d in range(k):
        cps = _xp_interleaved(k)
        cps[1]["tips"][d]["stream_id"] = _pos_stream(2 * d + 1)  # re-commit cp0's stream
        cps[1]["tips"][d]["epoch"] = 1
        err, warns = validate.check_tier_b(_link(*cps))
        assert err is None, f"cross-epoch re-commit on tip {d} is advisory, not a rejection: {err}"
        assert warns == ["B4:" + _pos_stream(2 * d + 1)], \
            f"epoch change on tip {d}: warnings {warns}, want ['B4:{_pos_stream(2 * d + 1)}']"


def test_duplicate_tip_identity_at_every_tip_index_pair():
    """canonical() must reject a duplicate identity at ANY pair of tip indices,
    including one involving tips[0]."""
    k = 4
    for a in range(k):
        for b in range(a + 1, k):
            cp = _cp(1, _pos_ts(100), _xp_tips(1, k))
            cp["tips"][b]["stream_id"] = cp["tips"][a]["stream_id"]
            cp["tips"][b]["epoch"] = cp["tips"][a]["epoch"]
            try:
                validate.canonical(cp)
                raise AssertionError(
                    f"tips {a} and {b} share an identity but canonical() accepted the checkpoint")
            except ValueError:
                pass


def test_canonical_fully_sorts_tips():
    """The tip sort must be a FULL sort, not a single adjacent-swap pass. No
    published positive needed more than one swap before this round, so a
    one-pass bubble would have reproduced every canonical field in the suite."""
    k = 5
    cp = _cp(1, _pos_ts(100), _xp_tips(1, k))
    got = json.loads(validate.canonical(cp).decode("utf-8"))
    assert len(got["tips"]) == k, f"canonical dropped tips: {len(got['tips'])}, want {k}"
    keys = [validate.tip_identity(t) for t in got["tips"]]
    assert keys == sorted(keys), f"canonical tips are not fully sorted: {keys}"


def test_b2_hashes_canonical_bytes_at_every_chain_index():
    """B2 hashes canonical bytes at EVERY chain index, chain[0] included.
    advisory_middle_chain_unsorted_prefix_tips puts its unsorted prefix at index
    1, so a validator special-casing chain[0] passes it."""
    n = 4
    for d in range(n - 1):
        cps = [_cp(i + 1, _pos_ts(100 + 10 * i), _xp_tips(i + 1, 3 if i == d else 1))
               for i in range(n)]
        chain = _link(*cps)
        as_received = json.dumps(chain[d], sort_keys=True, ensure_ascii=False,
                                 separators=(",", ":")).encode("utf-8")
        assert validate.canonical(chain[d]) != as_received, \
            f"checkpoint {d} is not discriminating: its tips are already in identity order"
        err, _ = validate.check_tier_b(chain)
        assert err is None, \
            f"chain whose checkpoint {d} supplies tips out of identity order was rejected: {err}"


def test_own_input_epoch_checked_with_and_without_chain():
    """The epoch boundary applies to a vector's OWN input whether or not it
    carries chain context. Every epoch-boundary negative before this round was
    chainless, so skipping the own-input check for chain carriers passed the
    whole suite. reject_reason is nested inside main(), so this runs end to
    end."""
    import base64 as _b64
    priv = _priv()
    genesis = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    bad = _cp(2, _pos_ts(110), [
        _tip(_pos_stream(1), 0, 1, 1, "aa"),
        _tip(_pos_stream(2), 0, 2, 2, "bb"),
    ], prev=genesis)
    del bad["tips"][0]["epoch"]
    prefix = _cp(1, _pos_ts(100), [_tip(_pos_stream(9), 0, 9, 9, "99")], prev=genesis)
    sig = _b64.b64encode(priv.sign(validate.canonical(bad))).decode()
    for name, chain in (("chainless", None), ("with_chain", [_sign(priv, prefix)])):
        nv = {"name": "own_input_missing_epoch", "expect": "schema",
              "reason": "own input missing epoch", "input": bad, "signature": sig,
              "min_format_version": 2}
        if chain:
            nv["chain"] = chain
        rc, output = _run_main_capturing_stdout(_synthetic_suite(negatives=[nv]))
        assert rc == 0, f"own input missing epoch ({name}) was not rejected as schema\n{output}"
        assert "rejected (schema)" in output, \
            f"own input missing epoch ({name}) rejected for the wrong reason\n{output}"


def test_malformed_chain_entry_rejects_cleanly():
    """A chain entry with a key missing, present-but-null, or not an object at
    all must produce a reason, never a crash. This implementation read
    sc["signature"] directly and raised KeyError; .get(k, default) then still
    returned None for a present-but-null member, which is a TypeError one line
    later. Go decodes each of these into zero values and returns a verdict, so
    every case here must too. Mirrors TestMalformedChainEntryRejectsCleanly."""
    pub = _pub()
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    cases = {
        # No "input" at all, and an explicitly null one, both read as a zero
        # checkpoint, whose absent tips are a schema failure ahead of the
        # signature check.
        "empty_entry": ({}, "schema"),
        "null_input": ({"input": None, "signature": ""}, "schema"),
        "null_tips": ({"input": dict(cp, tips=None), "signature": ""}, "schema"),
        "scalar_entry": (42, "schema"),
        "no_signature": ({"input": cp}, "signature"),
        "null_signature": ({"input": cp, "signature": None}, "signature"),
        "not_base64": ({"input": cp, "signature": "!!!not base64!!!"}, "signature"),
    }
    for name, (sc, want) in cases.items():
        _, reason = validate.verify_prefixes(pub, [sc], 2)
        assert reason == want, f"{name}: reason={reason!r}, want {want!r}"


def test_chain_prefix_order_is_preserved():
    """The chain array's order is the producer's claim about history, so it is
    verified as given. A validator that sorted the prefixes by seq would
    silently repair a reordered chain, and every other chain in the suite
    arrives ordered."""
    pub, priv = _pub(), _priv()
    cps = _link(
        _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "11")]),
        _cp(2, _pos_ts(110), [_tip(_pos_stream(2), 0, 2, 2, "22")]),
        _cp(3, _pos_ts(120), [_tip(_pos_stream(3), 0, 3, 3, "33")]))
    reversed_chain = [_sign(priv, cps[1]), _sign(priv, cps[0])]
    full, reason = validate.verify_prefixes(pub, reversed_chain, 2)
    assert reason == "", f"both prefixes are correctly signed, but verify_prefixes returned {reason!r}"
    assert [c["seq"] for c in full] == [2, 1], \
        f"verify_prefixes reordered the chain: seqs {[c['seq'] for c in full]}, want [2, 1]"
    err, _ = validate.check_tier_b(full + [cps[2]])
    assert err is not None, \
        "a chain supplied newest-first was accepted; the array order is the claim being verified"


def test_warning_comparison_is_position_generic():
    """expect_warnings is compared element-wise over the WHOLE list. Every
    published expectation is correct, so no vector can catch a comparison
    weakened to the first element or to the shorter prefix -- only feeding a
    wrong expectation at each index in turn can."""
    real = _load_real_suite()
    v = None
    for cand in real["vectors"]:
        if cand["name"] == "advisory_middle_chain_unsorted_prefix_tips":
            v = cand
    assert v is not None, "advisory_middle_chain_unsorted_prefix_tips not found in vectors.json"
    ew = v["expect_warnings"]
    assert len(ew) >= 4, f"this test needs a vector with at least four warnings, got {ew}"

    mutations = {}
    for i in range(len(ew)):
        bad = list(ew)
        bad[i] = f"B9:wrong-at-index-{i}"
        mutations[f"corrupt_index_{i}"] = bad
    mutations["truncated"] = list(ew[:-1])
    mutations["extra_appended"] = list(ew) + ["B9:extra"]
    mutations["permuted_tail"] = list(ew[:-2]) + [ew[-1], ew[-2]]

    for name, bad in mutations.items():
        mv = copy.deepcopy(v)
        mv["expect_warnings"] = bad
        rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[mv]))
        assert rc != 0, f"expect_warnings {bad} ({name}) was accepted; actual is {ew}\n{output}"
        assert "warnings" in output, f"{name} rejected, but not for the warning mismatch:\n{output}"


def test_validate_checks_every_vector_and_negative():
    """The rules cannot fix a harness that skips entries: a loop truncated to
    its first element, or a Tier B block that runs only for the first
    chain-carrying vector, leaves every rule intact and every gate green.
    main() counts what it actually reached; this recounts the committed file
    independently and requires the two to agree."""
    suite = _load_real_suite()
    want_pos = want_tier_b = want_neg = 0
    for v in suite["vectors"]:
        if v.get("min_format_version", 0) > validate.SUPPORTED_FORMAT_VERSION:
            continue
        want_pos += 1
        if v.get("chain") or v.get("expect_warnings"):
            want_tier_b += 1
    for nv in suite.get("negatives", []):
        if nv.get("min_format_version", 0) <= validate.SUPPORTED_FORMAT_VERSION:
            want_neg += 1
    assert want_pos >= 2 and want_tier_b >= 2 and want_neg >= 2, \
        f"the committed suite is too small for this test to mean anything: {want_pos}/{want_tier_b}/{want_neg}"

    rc, output = _run_main_capturing_stdout(suite)
    assert rc == 0, f"the committed vectors.json no longer validates\n{output}"
    m = CHECKED_RE.search(output)
    assert m, f"main() printed no 'checked:' line; the harness cannot show what it reached\n{output}"
    got = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    assert got == (want_pos, want_tier_b, want_neg), \
        f"main reached {got}, want {(want_pos, want_tier_b, want_neg)}"


# --- Encoding of the signature string (round 6) ----------------------------


# Every character here is one a decoder somewhere silently REPAIRS -- it
# recovers the original signature from the result -- rather than one it merely
# fails to notice, and the two references were lenient about different ones:
#
#   "!"   base64.b64decode discards it by default; Go rejects it.
#   "\n"  Go's base64.StdEncoding.DecodeString ignores it by documented
#         behaviour, and .Strict() does not change that; this one rejects it.
#   "\r"  the same, in Go.
#
# Round 1 tested only "!" -- the direction this reference had just been fixed
# in -- which is exactly why the newline direction survived it. Mirrors go's
# strayChars.
STRAY_CHARS = ("!", "\n", "\r")

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _splice_stray(sig, stray):
    """Splice `stray` into the middle of an otherwise valid encoding. Mirrors
    go's spliceStray."""
    return sig[:10] + stray + sig[10:]


def _mutate_pad_bits(sig):
    """A DIFFERENT signature string that decodes to the same 64 bytes, by
    flipping the padding bits of the last data character of an 88-character
    Ed25519 signature. A 64-byte value leaves one byte in the final group, so
    that character carries four bits no byte depends on; both languages'
    decoders ignore them, and both therefore verified two distinct strings for
    one signature. Only a round-trip comparison rejects it, which is why the
    same round trip had to go into both references. Mirrors go's
    mutatePadBits."""
    assert len(sig) == 88 and sig.endswith("=="), \
        f"expected an 88-character Ed25519 signature ending in '==', got {sig!r}"
    i = len(sig) - 3
    return sig[:i] + B64_ALPHABET[B64_ALPHABET.index(sig[i]) ^ 0x0F] + sig[i + 1:]


def test_stray_character_signature_is_not_repaired():
    """A signature string that is not valid base64 must be rejected, not
    repaired. With validate=False this implementation decoded the spliced
    string back to the untampered 64 bytes and ACCEPTED a vector Go rejects
    with "illegal base64 data" -- the two references disagreeing on
    third-party input. Mirrors TestStrayCharacterSignatureIsNotRepaired."""
    import base64 as _b64
    pub, priv = _pub(), _priv()
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    good = _b64.b64encode(priv.sign(validate.canonical(cp))).decode()

    # The premise: the underlying signature is genuinely valid, so the only
    # thing wrong with the mutated string is its encoding.
    nv = {"input": cp, "signature": good, "min_format_version": 2}
    assert validate.reject_reason(pub, nv) == "", \
        "the unmutated signature must verify, or the assertion below proves nothing"
    for stray in STRAY_CHARS:
        nv = {"input": cp, "signature": _splice_stray(good, stray),
              "min_format_version": 2}
        got = validate.reject_reason(pub, nv)
        assert got == "signature", \
            f"stray {stray!r} in the signature: reject_reason={got!r}, want 'signature'"
    # Same bytes, different string: the padding bits of the last data
    # character. Nothing about the ALPHABET is wrong here, so a decoder that
    # only checks the alphabet accepts it -- which both references did.
    nv = {"input": cp, "signature": _mutate_pad_bits(good), "min_format_version": 2}
    got = validate.reject_reason(pub, nv)
    assert got == "signature", \
        f"non-canonical padding bits: reject_reason={got!r}, want 'signature'"


def test_stray_character_prefix_signature_is_not_repaired():
    """The same rule on a chain prefix. verify_prefixes decodes separately from
    reject_reason, so a strict decode in one and a lenient one in the other
    would leave a forged history acceptable at the prefix level only. Mirrors
    TestStrayCharacterPrefixSignatureIsNotRepaired."""
    pub, priv = _pub(), _priv()
    cps = _link(_cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")]),
                _cp(2, _pos_ts(110), [_tip(_pos_stream(2), 0, 2, 2, "bb")]))
    prefix = _sign(priv, cps[0])
    _, reason = validate.verify_prefixes(pub, [prefix], 2)
    assert reason == "", f"the unmutated prefix must verify; reason={reason!r}"
    good = prefix["signature"]
    for stray in STRAY_CHARS:
        mutated = dict(prefix, signature=_splice_stray(good, stray))
        _, reason = validate.verify_prefixes(pub, [mutated], 2)
        assert reason == "signature", \
            f"stray {stray!r} in a prefix signature: reason={reason!r}, want 'signature'"
    mutated = dict(prefix, signature=_mutate_pad_bits(good))
    _, reason = validate.verify_prefixes(pub, [mutated], 2)
    assert reason == "signature", \
        f"non-canonical padding bits in a prefix signature: reason={reason!r}, want 'signature'"


def test_non_canonical_signature_encoding_is_rejected():
    """The third decode site: the positive path in main(). reject_reason and
    verify_prefixes are covered above, but a must-accept vector's own signature
    is decoded separately, and a strict decode in two places out of three
    leaves exactly one lenient. End to end on the committed suite, which is the
    shape a third party actually hands the validator. Mirrors
    TestNonCanonicalSignatureEncodingIsRejectedEndToEnd."""
    mutations = {f"stray {stray!r}": (lambda sig, c=stray: _splice_stray(sig, c))
                 for stray in STRAY_CHARS}
    mutations["padding bits"] = _mutate_pad_bits

    def on_own_signature(suite, mutate):
        suite["vectors"][0]["signature"] = mutate(suite["vectors"][0]["signature"])

    def on_prefix_signature(suite, mutate):
        for v in suite["vectors"]:
            if v.get("chain"):
                v["chain"][0]["signature"] = mutate(v["chain"][0]["signature"])
                return
        raise AssertionError("no vector with a chain prefix to mutate")

    for name, mutate in mutations.items():
        for where, inject in (("a positive vector's own signature", on_own_signature),
                              ("a chain prefix's signature", on_prefix_signature)):
            suite = _load_real_suite()
            inject(suite, mutate)
            rc, output = _run_main_capturing_stdout(suite)
            assert rc != 0, \
                f"{name} in {where} was accepted; the decoder repaired it\n{output}"


# --- Present-but-null members (round 6) ------------------------------------


def test_null_epoch_rejected_at_every_version():
    """A present-but-null epoch is neither an epoch nor an absent one.
    .get("epoch", 0) returns None for it, and None is not orderable against an
    int -- a TypeError where Go returned a verdict. Reading it as ABSENT
    instead is no better: the same bytes would then be a legal version-1 tip
    and a silent epoch 0 at version 2. Both references reject it outright.
    Mirrors TestNullEpochRejectedAtEveryVersion."""
    for min_ver in (1, 2):
        cp = _cp(1, _pos_ts(100), [dict(_tip(_pos_stream(1), 0, 1, 1, "aa"), epoch=None)])
        assert validate.check_schema(cp, min_ver) is not None, \
            f"min_ver={min_ver}: an explicit null epoch was accepted; want a schema rejection"
        # The contrast that makes the case: a genuinely ABSENT epoch is legal
        # at version 1, so the rejection above is about null specifically.
        del cp["tips"][0]["epoch"]
        assert validate.check_schema(cp, 1) is None, \
            "an absent epoch must stay legal at version 1"


def test_null_tip_element_rejected_at_every_version():
    """A JSON null tip ELEMENT is not a zero tip. This reference type-checks
    the element and rejected it at every version; Go's UnmarshalJSON convention
    left the zero value for null, so `"tips": [null]` decoded into a full tip
    of zero values and VALIDATED at version 1. The two agreed at version 2 only
    by accident -- the zero tip has no epoch, so the epoch-required rule caught
    it there. Mirrors TestNullTipElementRejected."""
    for min_ver in (1, 2):
        cp = _cp(1, _pos_ts(100), [None])
        assert validate.check_schema(cp, min_ver) is not None, \
            f"min_ver={min_ver}: a null tip element was accepted; null is not a tip"
    # The contrast: a real tip object is still legal, so the rejection above is
    # about null specifically.
    assert validate.check_schema(_cp(1, _pos_ts(100),
                                     [_tip(_pos_stream(1), 0, 1, 1, "aa")]), 2) is None, \
        "an ordinary tip must stay legal"


def test_wrong_typed_epoch_returns_a_reason():
    """check_epoch_presence must return a reason, never raise -- Go returns a
    clean decode error for every value below. `ep < 0` against a str, a list or
    a dict raised TypeError here, and `epoch: true` / `epoch: 1.0` PASSED (bool
    is an int subclass, and a float compares fine against 0) while Go rejected
    both. Mirrors TestWrongTypedEpochIsRejectedWhileDecoding."""
    for ep in ("1", [1], True, False, 1.0, {"a": 1}):
        for min_ver in (1, 2):
            cp = _cp(1, _pos_ts(100),
                     [dict(_tip(_pos_stream(1), 0, 1, 1, "aa"), epoch=ep)])
            try:
                err = validate.check_schema(cp, min_ver)
            except Exception as e:  # noqa: BLE001 -- a raise IS the failure here
                raise AssertionError(
                    f"min_ver={min_ver}, epoch={ep!r}: raised {type(e).__name__}; "
                    "this path must return a reason, never raise") from e
            assert err is not None, \
                f"min_ver={min_ver}: epoch={ep!r} was accepted; epoch must be an integer"
    # The contrast: an ordinary integer epoch is still legal at v2.
    assert validate.check_schema(
        _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 3, 1, 1, "aa")]), 2) is None, \
        "an integer epoch must stay legal"


def test_null_tips_rejected():
    """A present-but-null tips member is not an empty array: canonicalization
    normalizes it to [], so one signature would cover two distinct documents,
    and iterating it raises. Mirrors TestNullTipsRejected."""
    cp = _cp(1, _pos_ts(100), None)
    assert validate.check_schema(cp, 2) is not None, \
        "a null tips member was accepted; want a schema rejection"
    empty = _cp(1, _pos_ts(100), [])
    assert validate.check_schema(empty, 2) is None, "an empty tips array must stay legal"
    # The collision the rule forecloses.
    assert validate.canonical(cp) == validate.canonical(empty), \
        "this test assumes the collision it guards against"


def test_null_members_reject_cleanly_on_every_path():
    """Every reason-returning path must survive a null member: the vector's own
    input, a chain prefix, and the Tier B walk. Each of these raised
    TypeError/AttributeError before, which is a traceback in this reference and
    a clean verdict in the other. Mirrors TestNullMembersRejectedOnChainPrefixes."""
    pub, priv = _pub(), _priv()
    cases = {
        "null_epoch": _cp(1, _pos_ts(100),
                          [dict(_tip(_pos_stream(1), 0, 1, 1, "aa"), epoch=None)]),
        "null_tips": _cp(1, _pos_ts(100), None),
    }
    for name, cp in cases.items():
        nv = {"input": cp, "signature": "", "min_format_version": 2}
        assert validate.reject_reason(pub, nv) == "schema", \
            f"{name} as a vector's own input: want 'schema'"
        _, reason = validate.verify_prefixes(pub, [_sign(priv, cp)], 2)
        assert reason == "schema", f"{name} as a chain prefix: reason={reason!r}, want 'schema'"
    # check_tier_b runs after check_schema on every path, but it is reached
    # with third-party data and must not raise on its own.
    err, _ = validate.check_tier_b([cases["null_tips"]])
    assert err is None or isinstance(err, str), "check_tier_b raised on a null tips member"


def _positive(cp, chain=None):
    """A must-accept vector built from `cp`: canonical bytes, hash and
    signature all derived from the checkpoint as given. Everything is computed
    AFTER the caller has injected whatever it means to inject, so the vector is
    self-consistent and only a schema rule can reject it."""
    import base64 as _b64
    import hashlib as _h
    cb = validate.canonical(cp)
    v = {"name": "probe", "input": cp, "canonical": cb.decode(),
         "sha256": _h.sha256(cb).hexdigest(),
         "signature": _b64.b64encode(_priv().sign(cb)).decode(),
         "min_format_version": 2}
    if chain is not None:
        v["chain"] = chain
    return v


def _unknown_member_cases():
    """A self-consistently signed suite carrying one unknown member, at each of
    the four positions the schema has: a checkpoint, a tip, the checkpoint
    inside a signed chain prefix, and the prefix WRAPPER itself."""
    import hashlib as _h
    genesis = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def tail_after(pre):
        """A clean second checkpoint linked to `pre` AS GIVEN. The prefix is
        built first and the link computed from its canonical bytes afterwards,
        so an injected member leaves B2 satisfied and the prefix signature
        valid: nothing but the schema rule can then reject the vector. Linking
        to the uninjected prefix instead would let a B2 break do the work and
        the test would pass with no unknown-member rule at all."""
        return dict(_cp(2, _pos_ts(110), [_tip(_pos_stream(2), 0, 2, 2, "bb")]),
                    prev_hash=_h.sha256(validate.canonical(pre)).hexdigest())

    clean_cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")], prev=genesis)
    pre = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")], prev=genesis)
    injected_pre = dict(pre, injected="forged history")

    # Each case is (vector, fragment the FAIL line must contain). The fragment
    # is what separates "rejected by the schema rule" from "rejected because
    # the signature broke" -- and these signatures are all valid, so only the
    # schema rule can be doing the work.
    #
    # All four fragments are the same now. They were not: the two prefix cases
    # used to be reported through reject_reason's shared vocabulary
    # ("chain context was rejected (schema)"), because the member check reached
    # them only once validation was already under way. It now runs over every
    # non-skipped entry BEFORE any of them is validated -- the position Go's
    # strict decode occupies -- so all four positions report the member
    # directly, and a defect that would also have failed for another reason can
    # no longer hide behind that reason's token.
    return {
        "clean": (_positive(clean_cp), None),
        "on a checkpoint": (
            _positive(dict(clean_cp, injected="not covered by the signature")),
            "unknown member"),
        "on a tip": (
            _positive(_cp(1, _pos_ts(100),
                          [dict(_tip(_pos_stream(1), 0, 1, 1, "aa"),
                                injected="not covered by the signature")],
                          prev=genesis)),
            "unknown member"),
        "on a chain prefix's checkpoint": (
            _positive(tail_after(injected_pre), chain=[_sign(_priv(), injected_pre)]),
            "unknown member"),
        "on a chain prefix wrapper": (
            _positive(tail_after(pre),
                      chain=[dict(_sign(_priv(), pre), injected="forged history")]),
            "unknown member"),
    }


def test_unknown_member_is_rejected():
    """An unknown member is bytes the signature does not cover, and it is
    rejected on a checkpoint, on a tip, on a signed chain prefix and on the
    prefix wrapper alike -- the rule the README states as normative.

    This reference did NOT have that rule; it only had a side effect of one.
    Canonicalizing the object as it arrives means an injected member changes
    the bytes, so injecting into the ALREADY-SIGNED committed suite always
    failed the signature check -- which is what the previous version of this
    test did, and so it could never have failed however absent the schema rule
    was. Every suite below is re-signed AFTER the injection, exactly as a
    forger would produce it: against the pre-fix code all four returned rc=0,
    PASS while Go rejected all four. Mirrors TestUnknownMemberIsRejected."""
    cases = _unknown_member_cases()
    # The premise: the same construction with nothing injected passes, so the
    # rejections below are about the injected member and not about the shape of
    # these synthetic vectors.
    clean, _ = cases.pop("clean")
    rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[clean]))
    assert rc == 0, f"the uninjected probe suite must validate\n{output}"
    for name, (v, want) in cases.items():
        rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[v]))
        assert rc != 0, f"a re-signed suite with an unknown member {name} was accepted\n{output}"
        assert want in output, \
            f"an unknown member {name} was rejected, but not by the schema rule ({want!r}):\n{output}"


def test_unknown_member_on_the_envelope_is_rejected():
    """The unknown-member rule covers the DOCUMENT, not only the objects a
    signature happens to reach. An unknown member beside "name" on a vector or
    a negative, or beside "vectors" at the top level, is not covered by any
    signature at all -- so nothing but an explicit member set can notice it.
    Go's DisallowUnknownFields refused the file at all three; this reference
    accepted all three. No Go mirror is needed: its decoder gets these for
    free, and TestUnknownMemberIsRejected already shows the decoder refusing a
    file."""
    for name, inject in (
            ("on a vector", lambda s: s["vectors"][0].update(bogus="x")),
            ("on a negative", lambda s: s["negatives"][0].update(bogus="x")),
            ("on the suite object", lambda s: s.update(bogus="x"))):
        suite = _load_real_suite()
        inject(suite)
        rc, output = _run_main_capturing_stdout(suite)
        assert rc != 0, f"an unknown member {name} was accepted\n{output}"
        assert "unknown member" in output, \
            f"an unknown member {name} was rejected, but not as an unknown member:\n{output}"
    # The premise: the untouched suite still passes.
    rc, output = _run_main_capturing_stdout(_load_real_suite())
    assert rc == 0, f"the committed suite no longer validates\n{output}"


def test_trailing_data_after_the_suite_is_rejected():
    """A conformance suite is ONE JSON document. json.load already refuses a
    file with data appended after the suite object, but it did so by raising
    JSONDecodeError out of main() -- a traceback, not a verdict -- while Go's
    json.Decoder read one value, stopped, and PASSED the same file. Both
    references must now print a FAIL line and return non-zero. Mirrors
    TestTrailingDataAfterSuiteIsRejected."""
    body = json.dumps(_load_real_suite())
    # The premise: the same bytes with nothing appended pass, so the rejections
    # below are about the trailing data and nothing else.
    rc, output = _run_main_on_raw(body)
    assert rc == 0, f"the unmodified suite must validate\n{output}"
    for tail in ('{"format_version":9}',
                 "this is not JSON at all",
                 "\n\n[1,2,3]",
                 '{"vectors":[],"negatives":[]}'):
        rc, output = _run_main_on_raw(body + tail)
        assert rc != 0, f"a file with {tail!r} appended was accepted\n{output}"
        assert "FAIL" in output, \
            f"{tail!r} was rejected without a FAIL line; a traceback is not a verdict\n{output}"


# The same literal appears in go/encoding_test.go as wantNULCanonical: the two
# references must agree on these exact bytes, not merely each be internally
# consistent.
WANT_NUL_CANONICAL = (
    '{"prev_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
    '"seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":['
    '{"entry_count":1,"epoch":0,"sequence_number":1,"stream_id":"a","tip_hash":"aa"},'
    '{"entry_count":2,"epoch":0,"sequence_number":2,"stream_id":"a\\u0000","tip_hash":"bb"}]}'
)


def test_nul_in_stream_id_sorts_by_the_published_rule():
    """The published rule is "stream_id ascending by Unicode code point, then
    epoch ascending numerically" -- what this implementation's tuple key does
    literally. Go flattened it into stream_id + a NUL separator + a zero-padded
    epoch, which reproduces the rule only while no stream_id contains a NUL:
    with tips "a" and "a<NUL>" at the same epoch the flattened key ordered them
    the other way round, so the two references disagreed on signed bytes.

    "a" and "a<NUL>" stand in a proper prefix relationship (differing
    stream_id lengths, one a prefix of the other): a NUL is the lowest
    possible byte, so it sorts at or below ANY separator a flattened key might
    pick, not only \\x00 -- this one pair catches the whole mutation class,
    including the \\x00 -> ~ swap that took five review rounds on Task 3 to
    surface. The tuple key has no separator to collide with, so this is a
    regression guard, not a live ambiguity today.

    Mirrors TestNULInStreamIDSortsByThePublishedRule."""
    lo = {"entry_count": 1, "epoch": 0, "sequence_number": 1,
          "stream_id": "a", "tip_hash": "aa"}
    hi = {"entry_count": 2, "epoch": 0, "sequence_number": 2,
          "stream_id": "a" + chr(0), "tip_hash": "bb"}
    # Two DIFFERENT stream_ids standing in a prefix relationship must still be
    # two DISTINCT tip identities -- the concern a flattened separator-based
    # key put at risk, since a poorly chosen separator can make two distinct
    # stream_ids collide once epoch is folded in.
    assert validate.tip_identity(lo) != validate.tip_identity(hi), \
        "'a' and 'a<NUL>' must be distinct tip identities: they are different stream_ids"
    assert validate.tip_identity(lo) < validate.tip_identity(hi), \
        "'a' must sort below 'a<NUL>' by Unicode code point"
    assert not validate.tip_identity(hi) < validate.tip_identity(lo), \
        "'a<NUL>' must NOT sort below 'a'"
    # Supplied in the wrong order, so the sort has to fix it.
    cp = _cp(1, "2026-01-01T00:00:00Z", [hi, lo],
             prev="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    got = validate.canonical(cp).decode()
    assert got == WANT_NUL_CANONICAL, \
        f"canonical bytes:\n got:  {got}\n want: {WANT_NUL_CANONICAL}"


# The same literal appears in go/encoding_test.go as
# wantShorterLaterCanonical: the two references must agree on these exact
# bytes, not merely each be internally consistent.
WANT_SHORTER_LATER_CANONICAL = (
    '{"prev_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
    '"seq":1,"timestamp":"2026-01-01T00:00:00Z","tips":['
    '{"entry_count":1,"epoch":0,"sequence_number":1,"stream_id":"aa","tip_hash":"aa"},'
    '{"entry_count":2,"epoch":0,"sequence_number":2,"stream_id":"b","tip_hash":"bb"}]}'
)


def test_stream_id_sorts_by_code_point_not_length():
    """The published rule is "stream_id ascending by Unicode code point": "aa"
    sorts BELOW "b" because the first code point decides, however much longer
    "aa" is. An implementation that orders by length first and only then
    lexicographically -- a natural shape if the key is built from a
    length-prefixed or fixed-width encoding -- puts "b" first and signs
    different bytes.

    Nothing in the published suite could tell the two apart. Every stream_id in
    it is a 36-character UUID, so length never breaks a tie;
    test_nul_in_stream_id_sorts_by_the_published_rule does not discriminate
    either, because "a" and "a<NUL>" stand in a prefix relationship and prefix
    pairs order the same way under both rules. This case needs a shorter,
    lexicographically LATER id against a longer, lexicographically EARLIER one,
    which is the one shape that separates them. Mirrors
    TestStreamIDSortsByCodePointNotLength."""
    lo = {"entry_count": 1, "epoch": 0, "sequence_number": 1,
          "stream_id": "aa", "tip_hash": "aa"}
    hi = {"entry_count": 2, "epoch": 0, "sequence_number": 2,
          "stream_id": "b", "tip_hash": "bb"}
    assert validate.tip_identity(lo) < validate.tip_identity(hi), \
        "'aa' must sort below 'b': the first code point decides, not the length"
    assert not validate.tip_identity(hi) < validate.tip_identity(lo), \
        "'b' must not sort below 'aa'; the key is ordering by length"
    # Supplied in the wrong order, so the sort has to fix it -- and so the rule
    # is pinned where it actually bites, in the signed bytes.
    cp = _cp(1, "2026-01-01T00:00:00Z", [hi, lo],
             prev="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    got = validate.canonical(cp).decode()
    assert got == WANT_SHORTER_LATER_CANONICAL, \
        f"canonical bytes:\n got:  {got}\n want: {WANT_SHORTER_LATER_CANONICAL}"


def _load_future_format_fixture():
    """testdata/future_format_fixture.json: two entries of a format NEWER than
    this build, each carrying members it has no member set for. Shared with
    go/version_test.go's mirror, so both references are handed the same
    bytes."""
    with open(os.path.join(HERE, "..", "testdata", "future_format_fixture.json")) as f:
        fx = json.load(f)
    assert fx["format_version"] > validate.SUPPORTED_FORMAT_VERSION, \
        "fixture format_version must exceed SUPPORTED_FORMAT_VERSION"
    return fx


def _future_format_suite(fx, min_ver):
    """The committed suite with the fixture's two entries appended at
    `min_ver` and format_version raised."""
    suite = _load_real_suite()
    suite["format_version"] = fx["format_version"]
    suite["vectors"].append(dict(fx["vector"], min_format_version=min_ver))
    suite["negatives"].append(dict(fx["negative"], min_format_version=min_ver))
    return suite


def test_future_format_entry_is_skipped_not_strict_decoded():
    """A vector of a format this build does not support must be SKIPPED even
    when it carries members this build does not recognize -- which is the only
    interesting case, since a future format that added nothing would need no
    version bump. "Validators MUST skip ... and MUST NOT treat a skip as a
    failure" is what lets new vector shapes be added without breaking existing
    validators, and applying the member-set rule to the whole file before
    consulting the skip rule broke exactly that. Mirrors
    TestFutureFormatEntryIsSkippedNotStrictDecoded, over the same fixture
    bytes."""
    fx = _load_future_format_fixture()
    real = _load_real_suite()
    rc, output = _run_main_capturing_stdout(_future_format_suite(fx, fx["format_version"]))
    assert rc == 0, f"a future-format entry must be skipped, not fail the file\n{output}"
    assert _skipped_names(output) == sorted([fx["vector"]["name"], fx["negative"]["name"]]), \
        f"skipped names: {_skipped_names(output)}\n{output}"
    # The skip must not cost the rest of the file: every committed entry is
    # still checked. This catches "skip everything on a version mismatch" as
    # much as it catches the load failure.
    for e in real["vectors"] + real["negatives"]:
        assert f"ok  {e['name']}" in output, \
            f"{e['name']!r} was not validated alongside the skipped future entry\n{output}"

    # The control, and the reason the assertions above are not vacuous: the
    # SAME entries at a version this build does support must be rejected, as
    # unknown members. Without this the test would pass just as happily if
    # those members were ones the schema already defined.
    rc, output = _run_main_capturing_stdout(
        _future_format_suite(fx, validate.SUPPORTED_FORMAT_VERSION))
    assert rc != 0, \
        f"the fixture entries carry no member this build is unaware of; the skip assertion proves nothing\n{output}"
    assert "unknown member" in output, \
        f"rejected, but not as an unknown member:\n{output}"


def test_unknown_member_is_not_masked_by_the_expected_reason():
    """An unknown member must be reported wherever it sits, including on a
    negative that was ALREADY going to be rejected for the reason its `expect`
    names.

    reject_reason compares only the reason TOKEN, so an unknown member injected
    into a negative whose `expect` is already "schema" still returned "schema",
    matched, and the suite PASSED -- while Go refused to load the same file.
    The member-set check now runs over every non-skipped entry before the
    reason dispatch, which is the position that makes the two agree. Mirrors
    TestUnknownMemberOnANegativeIsNotMaskedByItsExpectedReason."""
    suite = _load_real_suite()
    injected = None
    for nv in suite["negatives"]:
        if nv["expect"] == "schema":
            nv["input"]["injected"] = "not covered by the signature"
            injected = nv["name"]
            break
    assert injected, "no negative with expect 'schema' to inject into"
    rc, output = _run_main_capturing_stdout(suite)
    assert rc != 0, \
        f"an unknown member on negative {injected!r} was accepted because it was already expected to fail for 'schema'\n{output}"
    assert "unknown member" in output, \
        f"negative {injected!r} was rejected, but not as an unknown member:\n{output}"


def test_member_sets_match_the_committed_suite():
    """The six member frozensets in validate.py are a hand-written parallel to
    the Go structs' JSON tags, and nothing in either language makes the two
    agree. This closes the loop the only way one reference can: vectors.json is
    generated FROM the Go structs, so the members it actually carries are the
    Go tags, and each frozenset must equal the union observed across the
    committed file.

    Partial by construction, and deliberately so: a Go field that is `omitempty`
    and never set emits nothing, so it appears in no suite and this cannot see
    it. It catches the drift that matters in practice -- a field renamed,
    removed, or added and used -- and it needs no cross-language plumbing to do
    it."""
    suite = _load_real_suite()
    observed = {"suite": set(suite), "vector": set(), "negative": set(),
                "checkpoint": set(), "tip": set(), "prefix": set()}

    def scan_checkpoint(cp):
        observed["checkpoint"] |= set(cp)
        for t in cp.get("tips") or []:
            observed["tip"] |= set(t)

    for key, kind in (("vectors", "vector"), ("negatives", "negative")):
        for e in suite[key]:
            observed[kind] |= set(e)
            scan_checkpoint(e["input"])
            for sc in e.get("chain", []):
                observed["prefix"] |= set(sc)
                scan_checkpoint(sc["input"])

    for kind, declared in (("suite", validate._SUITE_MEMBERS),
                           ("vector", validate._VECTOR_MEMBERS),
                           ("negative", validate._NEGATIVE_MEMBERS),
                           ("checkpoint", validate._CP_MEMBERS),
                           ("tip", validate._TIP_MEMBERS),
                           ("prefix", validate._SIGNED_CP_MEMBERS)):
        seen = observed[kind]
        assert seen, f"no {kind} object found in the committed suite; this test is vacuous"
        assert seen == set(declared), (
            f"the {kind} member set has drifted from the committed suite: "
            f"in the suite but not declared {sorted(seen - set(declared))}, "
            f"declared but never emitted {sorted(set(declared) - seen)}")


# --- Uncaught-exception hardening (issue: malformed/null input must reject
# --- cleanly, never crash) -------------------------------------------------
#
# Every case below reproduces a traceback this reference used to raise on
# third-party input that Go already handles without one. None of them needs a
# Go mirror test: in each case Go's struct decoding already zero-values the
# missing/null member and either proceeds (a bare string field) or reports a
# normal verdict (a nil slice ranges as empty) -- there is no Go behavior to
# pin, only a Python reporting/construction path that skipped a `.get()` Go's
# decode gets for free.


def test_malformed_public_key_hex_rejects_cleanly():
    """public_key_hex missing, null, wrong-typed, or the wrong length must not
    crash main(): a missing key used to raise KeyError, a non-string one
    TypeError out of bytes.fromhex, and a bad-length or non-hex one ValueError
    out of the key constructor -- all before a single vector was considered.

    This reference validates the key unconditionally, up front, so a bad key
    fails the whole suite even with nothing in it that would have needed the
    key at all. That is a deliberate divergence from Go, not an oversight: Go
    stores the key as a plain byte slice and only discovers a bad length if a
    signature actually gets verified against it -- and then panics rather
    than erroring (a Go-side gap, tracked separately and out of scope for this
    Python-only issue) -- so Go's laziness here is not a property worth
    reproducing. Silently accepting an unusable signing key merely because no
    vector happened to need it yet is a footgun, not a feature."""
    mutations = (
        ("missing", lambda s: s.pop("public_key_hex", None)),
        ("null", lambda s: s.__setitem__("public_key_hex", None)),
        ("wrong_length", lambda s: s.__setitem__("public_key_hex", "abcd")),
        ("non_string", lambda s: s.__setitem__("public_key_hex", 12345)),
    )
    # An otherwise-empty suite: the bad key alone must still fail it cleanly.
    for name, mutate in mutations:
        suite = _synthetic_suite()
        mutate(suite)
        rc, output = _run_main_capturing_stdout(suite)
        assert rc != 0, f"public_key_hex {name} must be rejected even with nothing to verify\n{output}"
        assert "FAIL: public_key_hex" in output, \
            f"public_key_hex {name} rejected, but not by name:\n{output}"

    # A real vector present changes nothing about how the key itself fails.
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    v = _positive(cp)
    for name, mutate in mutations:
        suite = _synthetic_suite(vectors=[v])
        mutate(suite)
        rc, output = _run_main_capturing_stdout(suite)
        assert rc != 0, f"public_key_hex {name} must not verify a real vector\n{output}"
        assert "FAIL: public_key_hex" in output, \
            f"public_key_hex {name} rejected, but not by name:\n{output}"


def test_null_or_missing_vectors_and_negatives_pass_cleanly():
    """"vectors"/"negatives" absent or explicitly null must read as zero
    entries of that kind, exactly like Go's nil-slice decode of a missing or
    null JSON array. check_envelope already folds null to [] before its
    array-type check, so an untouched suite passes there either way -- but
    main()'s own loops read `suite["vectors"]` and `suite.get("negatives",
    [])` directly, neither of which applies that same fallback, so a null
    value raised TypeError ranging over it and a missing "vectors" key raised
    KeyError outright."""
    real = _load_real_suite()
    mutations = (
        ("vectors missing", lambda s: s.pop("vectors", None)),
        ("vectors null", lambda s: s.__setitem__("vectors", None)),
        ("negatives missing", lambda s: s.pop("negatives", None)),
        ("negatives null", lambda s: s.__setitem__("negatives", None)),
        ("both missing", lambda s: (s.pop("vectors", None), s.pop("negatives", None))),
        ("both null", lambda s: (s.__setitem__("vectors", None),
                                 s.__setitem__("negatives", None))),
    )
    for name, mutate in mutations:
        suite = copy.deepcopy(real)
        mutate(suite)
        rc, output = _run_main_capturing_stdout(suite)
        assert rc == 0, f"a suite with {name} must still pass, as zero entries of that kind\n{output}"


def test_skipped_vector_with_missing_or_null_name_reports_cleanly():
    """A skipped vector's report line pads the name to a column with
    f"{name:<34}". object.__format__ rejects any non-empty format spec for
    anything but a str or number, so a present-but-null name raised TypeError
    there, one line after an absent name raised KeyError at the `v['name']`
    subscript itself."""
    base = {"input": {}, "min_format_version": 99}
    for label, entry in (("missing", dict(base)), ("null", dict(base, name=None))):
        rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[entry]))
        assert rc == 0, f"a skipped vector with a {label} name must not fail the suite\n{output}"
        assert "skip" in output, f"a skipped vector with a {label} name produced no skip line\n{output}"


def test_skipped_negative_with_missing_or_null_name_reports_cleanly():
    """As above, for a skipped negative's report line."""
    base = {"input": {}, "expect": "schema", "min_format_version": 99}
    for label, entry in (("missing", dict(base)), ("null", dict(base, name=None))):
        rc, output = _run_main_capturing_stdout(_synthetic_suite(negatives=[entry]))
        assert rc == 0, f"a skipped negative with a {label} name must not fail the suite\n{output}"
        assert "skip" in output, f"a skipped negative with a {label} name produced no skip line\n{output}"


def test_accepted_vector_with_missing_or_null_name_reports_cleanly():
    """An accepted (must-pass) vector's "ok" line pads the name the same way
    the skip line does, and is reached only after every real check on the
    vector's data already passed -- so a missing/null name here is purely a
    reporting-path defect, not a validation one."""
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    v = _positive(cp)
    for label, mutate in (("missing", lambda e: e.pop("name", None)),
                          ("null", lambda e: e.__setitem__("name", None))):
        entry = dict(v)
        mutate(entry)
        rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[entry]))
        assert rc == 0, f"an otherwise-valid vector with a {label} name must still be accepted\n{output}"
        assert "  ok " in output, f"an accepted vector with a {label} name produced no ok line\n{output}"


def test_accepted_negative_with_missing_or_null_name_reports_cleanly():
    """As above, for a correctly-rejected negative's "ok" line."""
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    base = {"input": dict(cp, tips=None), "expect": "schema", "min_format_version": 2}
    for label, mutate in (("missing", lambda e: e.pop("name", None)),
                          ("null", lambda e: e.__setitem__("name", None))):
        entry = dict(base)
        mutate(entry)
        rc, output = _run_main_capturing_stdout(_synthetic_suite(negatives=[entry]))
        assert rc == 0, f"a correctly-rejected negative with a {label} name must still pass\n{output}"
        assert "  ok " in output, f"a rejected negative with a {label} name produced no ok line\n{output}"


def test_accepted_vector_survives_missing_canonical_sha256_or_signature():
    """A vector missing "canonical", "sha256", or "signature" outright raised
    KeyError before, on the very subscript the corresponding check needs.
    Each is now read with a default equal to Go's zero value for that field
    (an empty string), so the vector fails its ordinary mismatch check with a
    clean FAIL line -- never a crash -- exactly as if the field had been
    present but wrong."""
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    v = _positive(cp)
    for field in ("canonical", "sha256", "signature"):
        entry = dict(v)
        del entry[field]
        rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[entry]))
        assert rc != 0, f"a vector missing {field!r} was accepted\n{output}"
        assert "FAIL [probe]" in output, \
            f"a vector missing {field!r} was rejected, but not with a clean FAIL line\n{output}"


def test_accepted_vector_survives_missing_input():
    """A vector missing "input" entirely reads as Go's zero Checkpoint, whose
    absent tips check_schema already rejects as "schema" -- not a KeyError on
    the bare `v["input"]` subscript this used to be, reached from four
    separate call sites in the positive-vector loop."""
    v = {"name": "no_input", "min_format_version": 2}
    rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[v]))
    assert rc != 0, f"a vector with no input at all was accepted\n{output}"
    assert "FAIL [no_input]" in output, f"rejected, but not cleanly\n{output}"


def test_rejected_negative_survives_missing_expect():
    """A negative missing "expect" reads as Go's zero string "", so it can
    only match a rejection reason of "" -- which reject_reason never returns
    for genuinely malformed input -- and reports a clean mismatch rather than
    raising on the bare `nv["expect"]` subscript this used to be."""
    cp = _cp(1, _pos_ts(100), None)
    nv = {"name": "no_expect", "input": cp, "signature": "", "min_format_version": 2}
    rc, output = _run_main_capturing_stdout(_synthetic_suite(negatives=[nv]))
    assert rc != 0, f"a negative missing 'expect' was accepted\n{output}"
    assert "FAIL [no_expect]" in output, f"rejected, but not cleanly\n{output}"


def test_suite_format_version_wrong_type_rejects_cleanly():
    """A non-integer top-level format_version (a string, or explicitly null)
    raised TypeError comparing it against SUPPORTED_FORMAT_VERSION with `>`,
    uncaught. min_format_version already gets this type-gate in check_entries;
    format_version needs the identical one at its own point of use."""
    for label, bad in (("string", "not-a-number"), ("null", None), ("bool", True)):
        suite = _synthetic_suite()
        suite["format_version"] = bad
        rc, output = _run_main_capturing_stdout(suite)
        assert rc != 0, f"format_version {label} ({bad!r}) was accepted\n{output}"
        assert "format_version" in output, \
            f"format_version {label} rejected, but not by name:\n{output}"
    # The premise: an ordinary integer format_version still passes.
    suite = _synthetic_suite()
    rc, output = _run_main_capturing_stdout(suite)
    assert rc == 0, f"an untouched empty suite must still pass\n{output}"


def test_chain_or_expect_warnings_wrong_type_rejects_cleanly():
    """"chain" or "expect_warnings" present as a non-list, non-null value (a
    number, a string) raised TypeError out of len() or a `for` loop
    downstream in main() -- check_entries let a wrong-typed value through
    with a comment claiming the verdict belonged to a check that, in fact,
    never runs it. Explicitly null must still pass through untouched (Go's
    nil slice, legal), so this also checks the negative: null is not rejected
    here, only a present non-list value is."""
    cp = _cp(1, _pos_ts(100), [_tip(_pos_stream(1), 0, 1, 1, "aa")])
    v = _positive(cp)
    for field in ("chain", "expect_warnings"):
        for bad in (5, "not-a-list", {"a": 1}):
            entry = dict(v)
            entry[field] = bad
            rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[entry]))
            assert rc != 0, f"{field}={bad!r} was accepted\n{output}"
            assert field in output, f"{field}={bad!r} rejected, but not by name:\n{output}"
        # The negative: explicitly null must NOT be rejected by the type gate
        # -- it is legal and must reach ordinary (chainless) validation.
        entry = dict(v)
        entry[field] = None
        rc, output = _run_main_capturing_stdout(_synthetic_suite(vectors=[entry]))
        assert rc == 0, f"{field}=None must be accepted like an absent {field}\n{output}"


def main():
    # Derived from the module, not hand-maintained. A list written out by hand
    # silently stops running any test nobody remembers to add to it -- a test
    # that never runs is indistinguishable from one that passes, which is the
    # same failure class this file's reached-count tests exist to catch.
    # Definition order is preserved (globals() is insertion-ordered), so the
    # run order still reads top to bottom.
    tests = [fn for name, fn in globals().items()
             if name.startswith("test_") and callable(fn)]
    assert tests, "no test functions found; the discovery above is broken"
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
