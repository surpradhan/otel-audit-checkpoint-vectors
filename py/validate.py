#!/usr/bin/env python3
"""Independent validator for the audit-checkpoint conformance vectors.

Re-derives the canonical form, SHA-256 chain hash, and Ed25519 signature from
each vector's `input` alone and checks them against the published values. This
implementation shares no code with the Go generator: it uses Python's stdlib
json as a restricted-profile JCS canonicalizer (valid because the checkpoint
schema is strings and integers only), plus hashlib and `cryptography`.

    python3 validate.py <vectors.json>
"""
import base64
import json
import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def tip_epoch(t: dict) -> int:
    """Epoch, treating absence as 0. Absence is legal only in v1 vectors.

    Read once with .get(), never with `"epoch" in t`: a present-but-null member
    must read as the same thing a pointer-typed decoder reads it as, and the
    two differ only where check_schema has already rejected the checkpoint."""
    ep = t.get("epoch")
    return 0 if ep is None else ep


def tip_identity(t: dict) -> tuple:
    """Uniqueness and sort key (spec R4). Epoch is part of the identity: two
    tips for one stream at different epochs are legal in a single checkpoint,
    so sorting on stream_id alone would let input order leak into signed
    bytes.

    Missing keys read as Go's zero value rather than raising. A third party
    feeding either reference implementation a checkpoint with a key missing
    must get the same verdict from both: Go's struct decoding yields "" and
    rejects cleanly, so a KeyError here would be the two references
    disagreeing on third-party input -- the exact defect class this suite
    publishes vectors against."""
    return (t.get("stream_id", ""), tip_epoch(t))


def canonical(cp: dict) -> bytes:
    # Producer rule: tips are ordered by identity before canonicalization
    # (JCS fixes object-key order but preserves array order). Two tips
    # sharing an identity would make that order -- and thus the canonical
    # bytes -- depend on input order, so duplicates are rejected outright.
    # `or []` rather than a default: a present-but-null tips member is not an
    # absent one, and .get("tips", []) hands None straight to the loop below.
    # check_schema rejects null tips outright, so a caller can only reach this
    # line with a checkpoint that already has an array -- this is the belt to
    # that braces, and it matches Go, whose canonical() copies a nil slice into
    # an empty one.
    tips = cp.get("tips") or []
    seen = set()
    for t in tips:
        ident = tip_identity(t)
        if ident in seen:
            raise ValueError(f"duplicate tip identity {ident}: "
                             "canonical bytes would depend on input order")
        seen.add(ident)
    cp = dict(cp)
    cp["tips"] = sorted(tips, key=tip_identity)
    # For a strings-and-integers schema, RFC 8785 JCS reduces to sorted keys,
    # compact separators, UTF-8, and standard JSON string escaping.
    return json.dumps(cp, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


SUPPORTED_FORMAT_VERSION = 2


def skip_vector(min_ver: int, supported_ver: int) -> bool:
    """A vector needing a newer format is skipped with a warning, never failed."""
    return min_ver > supported_ver


def check_epoch_presence(cp: dict, min_ver: int):
    """Spec 5a boundary: epoch required at v2+, absent at v1. Without this the
    absent-vs-zero distinction is unenforced spec text, and a v2 tip missing
    epoch would silently validate as 0."""
    for t in (cp.get("tips") or []):
        sid = t.get("stream_id", "")
        # Present-but-null is neither an epoch nor an absent epoch. Rejecting
        # it explicitly is what keeps `"epoch": null` from meaning "epoch 0" at
        # version 2 and "legal, no epoch" at version 1 -- and it is the reading
        # Go's decoder records too, so both references say "schema" here.
        if "epoch" in t and t["epoch"] is None:
            return (f"stream {sid!r}: epoch is present but null; null is not an "
                    "epoch and is not the same as an absent epoch")
        # Read once. Branching on `"epoch" in t` and then subscripting reads the
        # member twice under two different rules; `ep is None` is exactly what
        # Go's *int reports once null is out of the way.
        ep = t.get("epoch")
        if min_ver >= 2 and ep is None:
            return f"stream {sid!r}: epoch required at format_version >= 2"
        if min_ver < 2 and ep is not None:
            return f"stream {sid!r}: epoch not permitted in a v1 vector"
        # Epoch must be non-negative: it is a producer generation counter, so
        # no conformant producer emits one, and an implementation that builds a
        # TEXT sort key -- the shape the spec already warns against -- puts a
        # leading "-" above the digits and orders -10 above -1. Rejecting the
        # value keeps that ambiguity off the wire rather than relying on every
        # implementation to compare it the same way.
        if ep is not None and ep < 0:
            return f"stream {sid!r}: epoch must be non-negative, got {ep}"
    return None


def check_schema(cp, min_ver: int):
    """Structural rules a checkpoint must satisfy before any byte-level check:
    it is an object, `tips` is present as an array of objects, and every tip
    satisfies the epoch rules for the vector's format_version. Mirrors Go's
    checkSchema; both report a failure as "schema".

    The tips rule is not pedantry. Canonicalization normalizes a missing or
    null tips member to `[]`, so `"tips": null` and `"tips": []` would
    otherwise canonicalize to the same bytes and one signature would cover both
    documents. Rejecting null here makes that collision unreachable rather than
    merely unexercised.

    Like every reason-returning function on third-party input, it must return a
    reason, never raise: `.get(k, default)` returns None for a present-but-null
    member, and a None fed to the loops below is a TypeError, which is a
    traceback in this reference and a clean verdict in the other."""
    if not isinstance(cp, dict):
        return "a checkpoint must be a JSON object"
    tips = cp.get("tips")
    if not isinstance(tips, list) or not all(isinstance(t, dict) for t in tips):
        return ("tips is required and must be an array of objects; null and "
                "absent are not an empty array")
    return check_epoch_presence(cp, min_ver)


def verify_prefixes(pub, chain: list, min_ver: int) -> tuple:
    """Check a vector's preceding chain context, returning (prefixes, reason);
    reason is "" on success.

    Each prefix is held to the same bar as the vector's own input: the
    format_version epoch boundary AND a real signature verification. The
    signature check is the MUST documented in the README -- a verifier that
    merely hashed prefixes for linkage would accept a forged history. Shared by
    the positive and negative paths so the rule cannot drift between them."""
    full = []
    for sc in chain:
        # Read with defaults equal to Go's zero values, for the same reason as
        # check_tier_b: Go decodes a chain entry with no "input" or "signature"
        # key into a zero Checkpoint and an empty signature and returns
        # reason="signature", while a direct subscript here raises KeyError.
        # This is a reason-returning function on third-party input; it must
        # return a reason, never raise.
        # A chain entry that is not an object at all (a bare scalar) is
        # third-party input like any other: Go fails to decode it and reports
        # that, so this must report rather than raise AttributeError.
        if not isinstance(sc, dict):
            return ([], "schema")
        # `or {}`, not .get("input", {}): a present-but-null input is not an
        # absent one. Go decodes either into a zero Checkpoint, whose nil tips
        # checkSchema rejects as "schema".
        cp = sc.get("input") or {}
        err = check_schema(cp, min_ver)
        if err:
            return ([], "schema")
        try:
            scb = canonical(cp)
        except ValueError:
            return ([], "canonical")
        try:
            # binascii.Error (a ValueError) for non-base64 input, TypeError for
            # a non-string: Go folds a base64 decode failure into "signature"
            # via `err != nil || !Verify`, so this must too.
            # validate=True is load-bearing, not decoration. The default
            # (validate=False) DISCARDS characters outside the base64 alphabet,
            # so a signature with a stray character spliced into it decodes
            # back to the untampered bytes and verifies here, while Go's
            # base64.StdEncoding.DecodeString returns "illegal base64 data" and
            # rejects. A tampered signature accepted here and rejected there is
            # the two references disagreeing on third-party input.
            pub.verify(base64.b64decode(sc.get("signature", ""), validate=True), scb)
        except (InvalidSignature, ValueError, TypeError):
            return ([], "signature")
        full.append(cp)
    return (full, "")


def check_tier_b(chain: list) -> tuple:
    """Cross-checkpoint rules. Returns (error_or_None, warnings). B4 and B5 are
    advisory: reported as stable tokens, never rejected. The tokens are
    machine-comparable so the Go and Python validators can be checked for
    agreement rather than eyeballed."""
    warns = []
    seen_identity = {}
    last_epoch = {}
    # Every key below is read with a default equal to Go's zero value for the
    # corresponding struct field (prev_hash "", seq 0, timestamp "",
    # stream_id ""). Go decodes a checkpoint with a key missing into that zero
    # value and returns a clean B-rule rejection; reading the key directly here
    # would raise KeyError instead, so the two reference implementations would
    # disagree on third-party input. Whether a malformed checkpoint is rejected
    # must not depend on which reference you ran.
    for i, cp in enumerate(chain):
        seq = cp.get("seq", 0)
        if i > 0:
            prev_seq = chain[i - 1].get("seq", 0)
            if seq != prev_seq + 1:
                return (f"B1: checkpoint seq {seq} follows {prev_seq}", warns)
            # B2 across the assembled chain. The vector-level prev_sha256 field
            # only pins the LAST link, so without this a chain whose prefixes do
            # not hash-link is accepted -- the linkage rule would be enforced
            # exactly where it does not matter.
            try:
                prev_canon = canonical(chain[i - 1])
            except ValueError as e:
                return (f"B2: checkpoint {seq}: previous checkpoint is malformed: {e}", warns)
            want = hashlib.sha256(prev_canon).hexdigest()
            if cp.get("prev_hash", "") != want:
                return (f"B2: checkpoint {seq} prev_hash={cp.get('prev_hash', '')} does not "
                        f"link to checkpoint {prev_seq} ({want})", warns)
        # Iterate tips in identity order, not input order. Warnings are
        # compared as ORDERED lists and a checkpoint's tips are explicitly
        # allowed to arrive unsorted, so when two streams each change epoch in
        # one checkpoint an input-order walk emits their B4 tokens in whatever
        # order the tips happened to be supplied -- two conformant validators
        # handed the same signed bytes could report different sequences.
        # (It does NOT change whether a later checkpoint warns: B3 rejects any
        # repeat of a (stream_id, epoch), so the next epoch differs from every
        # value last_epoch could hold and B4 fires either way.)
        # advisory_two_streams_new_epoch is the vector that pins this.
        for t in sorted(cp.get("tips") or [], key=tip_identity):
            ident = tip_identity(t)
            sid = t.get("stream_id", "")
            if ident in seen_identity:
                return (f"B3: stream {sid!r} epoch {tip_epoch(t)} "
                        f"committed in checkpoint {seen_identity[ident]} and again in {seq}", warns)
            seen_identity[ident] = seq
            prev = last_epoch.get(sid)
            if prev is not None and tip_epoch(t) != prev:
                warns.append("B4:" + sid)
            last_epoch[sid] = tip_epoch(t)
        # B5 is a plain string comparison: the pinned YYYY-MM-DDTHH:MM:SSZ
        # profile sorts chronologically, so no date parsing is needed.
        if i > 0 and cp.get("timestamp", "") < chain[i - 1].get("timestamp", ""):
            warns.append(f"B5:{seq}")
    return (None, warns)


def reject_reason(pub, nv):
    """Return the check that rejects a negative vector, or "" if it is
    (wrongly) accepted. At module scope, mirroring Go's top-level
    rejectReason, so both references can be exercised the same way."""
    cp = nv.get("input") or {}
    err = check_schema(cp, nv.get("min_format_version", 0))
    if err:
        return "schema"
    try:
        cb = canonical(cp)
    except ValueError:
        return "canonical"
    try:
        # validate=True: see verify_prefixes. A lenient decode silently
        # repairs a mutated signature string.
        pub.verify(base64.b64decode(nv.get("signature", ""), validate=True), cb)
    except (InvalidSignature, ValueError, TypeError):
        return "signature"
    if nv.get("chain"):
        prefixes, reason = verify_prefixes(
            pub, nv["chain"], nv.get("min_format_version", 0))
        if reason:
            return reason
        tb_err, _ = check_tier_b(prefixes + [cp])
        if tb_err:
            return "tier_b"
    if nv.get("prev_sha256") and cp.get("prev_hash", "") != nv["prev_sha256"]:
        return "chain"
    return ""


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 validate.py <vectors.json>")
        return 2
    # json.load already rejects a file carrying trailing data after the suite
    # object ("Extra data") -- but as an uncaught traceback, which is not a
    # verdict. Go now prints "FAIL: ..." and exits 1 for the same file, and a
    # third party must not have to read a stack trace in one reference and a
    # diagnosis in the other. Catching it here is the whole difference.
    try:
        with open(sys.argv[1], "rb") as f:
            suite = json.load(f)
    except json.JSONDecodeError as e:
        print(f"FAIL: {sys.argv[1]} is not a single JSON document: {e}")
        return 1
    if suite.get("format_version", 1) > SUPPORTED_FORMAT_VERSION:
        print(f"  note: suite format_version={suite['format_version']} exceeds "
              f"supported={SUPPORTED_FORMAT_VERSION}; unsupported vectors will be skipped")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(suite["public_key_hex"]))

    # How many entries MUST be checked, computed in a pre-pass that is
    # textually separate from the loops that do the checking. The rules cannot
    # fix a harness that silently skips vectors: a loop truncated to its first
    # entry, or a Tier B block that runs only for the first chain-carrying
    # vector, leaves every rule intact and every gate green. Counting what was
    # actually reached and comparing it here is the instrument closest to that
    # class; test_validate_checks_every_vector_and_negative and its Go mirror
    # recount the committed file independently and catch it too.
    want_positives = want_tier_b = want_negatives = 0
    for v in suite["vectors"]:
        if skip_vector(v.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            continue
        want_positives += 1
        if len(v.get("chain", [])) != 0 or len(v.get("expect_warnings", [])) != 0:
            want_tier_b += 1
    for nv in suite.get("negatives", []):
        if not skip_vector(nv.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            want_negatives += 1
    got_positives = got_tier_b = got_negatives = 0

    prev_expected = None
    for i, v in enumerate(suite["vectors"]):
        if skip_vector(v.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            print(f"  skip {v['name']:<34} requires format_version {v['min_format_version']}")
            prev_expected = None
            continue
        # Same check order as Go's positive path -- schema boundary first,
        # then canonical bytes, hash, signature. Both negative paths already
        # agree on that order; this one lagged, and a check order a third party
        # can observe is part of what the two references must share.
        err = check_schema(v["input"], v.get("min_format_version", 0))
        if err:
            print(f"FAIL [{v['name']}] {err}")
            return 1
        # A must-accept vector is third-party data like any other: Go prints a
        # clean "FAIL:" line for a malformed one, so raising here would make
        # the same input a traceback in one reference and a diagnosis in the
        # other.
        try:
            cb = canonical(v["input"])
        except ValueError as e:
            print(f"FAIL [{v['name']}] canonical: {e}")
            return 1
        if cb.decode("utf-8") != v["canonical"]:
            print(f"FAIL [{v['name']}] canonical mismatch")
            print(f"  got:  {cb.decode('utf-8')}")
            print(f"  want: {v['canonical']}")
            return 1
        if hashlib.sha256(cb).hexdigest() != v["sha256"]:
            print(f"FAIL [{v['name']}] sha256 mismatch")
            return 1
        try:
            pub.verify(base64.b64decode(v["signature"], validate=True), cb)
        except (InvalidSignature, ValueError, TypeError):
            print(f"FAIL [{v['name']}] signature does not verify")
            return 1
        if v.get("chain") or v.get("expect_warnings"):
            # A must-accept vector's prefixes are verified exactly as a
            # negative's are: same helper, same MUST.
            prefixes, reason = verify_prefixes(
                pub, v.get("chain", []), v.get("min_format_version", 0))
            if reason:
                print(f"FAIL [{v['name']}] must be accepted, but its chain "
                      f"context was rejected ({reason})")
                return 1
            full = prefixes + [v["input"]]
            tb_err, warns = check_tier_b(full)
            if tb_err:
                print(f"FAIL [{v['name']}] must be accepted, but Tier B rejected it: {tb_err}")
                return 1
            if warns != v.get("expect_warnings", []):
                print(f"FAIL [{v['name']}] warnings {warns}, want {v.get('expect_warnings', [])}")
                return 1
            got_tier_b += 1
        # A vector carrying its own chain context is not part of the positives'
        # own hash chain, so prev_expected does not apply to it.
        if (i > 0 and prev_expected is not None and not v.get("chain")
                and v["input"].get("prev_hash", "") != prev_expected):
            print(f"FAIL [{v['name']}] chain break")
            return 1
        if not v.get("chain"):
            # Only vectors in the positives' own hash chain advance it; a
            # chain-carrying vector must not become the next one's expected
            # predecessor.
            prev_expected = v["sha256"]
        got_positives += 1
        print(f"  ok  {v['name']:<34} sha256={v['sha256'][:16]}…")

    for nv in suite.get("negatives", []):
        if skip_vector(nv.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            print(f"  skip {nv['name']:<34} requires format_version {nv['min_format_version']}")
            continue
        got = reject_reason(pub, nv)
        if got == "":
            print(f"FAIL [{nv['name']}] accepted, but must be rejected")
            return 1
        if got != nv["expect"]:
            print(f"FAIL [{nv['name']}] rejected for {got!r}, expected {nv['expect']!r}")
            return 1
        got_negatives += 1
        print(f"  ok  {nv['name']:<34} rejected ({got})")

    if got_positives != want_positives:
        print(f"FAIL harness: validated {got_positives} of {want_positives} positive vectors")
        return 1
    if got_tier_b != want_tier_b:
        print(f"FAIL harness: ran the cross-checkpoint block for {got_tier_b} of "
              f"{want_tier_b} chain-carrying positive vectors")
        return 1
    if got_negatives != want_negatives:
        print(f"FAIL harness: checked {got_negatives} of {want_negatives} negative vectors")
        return 1
    print(f"  checked: {got_positives} positive ({got_tier_b} through Tier B) + "
          f"{got_negatives} negative")
    print(f"PASS: {got_positives} positive + {got_negatives} negative "
          f"vectors, all as expected (independent Python impl)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
