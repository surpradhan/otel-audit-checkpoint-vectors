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
    """Epoch, treating absence as 0. Absence is legal only in v1 vectors."""
    return t.get("epoch", 0)


def tip_identity(t: dict) -> tuple:
    """Uniqueness and sort key (spec R4). Epoch is part of the identity: two
    tips for one stream at different epochs are legal in a single checkpoint,
    so sorting on stream_id alone would let input order leak into signed
    bytes."""
    return (t["stream_id"], tip_epoch(t))


def canonical(cp: dict) -> bytes:
    # Producer rule: tips are ordered by identity before canonicalization
    # (JCS fixes object-key order but preserves array order). Two tips
    # sharing an identity would make that order -- and thus the canonical
    # bytes -- depend on input order, so duplicates are rejected outright.
    tips = cp.get("tips", [])
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
    for t in cp.get("tips", []):
        if min_ver >= 2 and "epoch" not in t:
            return f"stream {t['stream_id']!r}: epoch required at format_version >= 2"
        if min_ver < 2 and "epoch" in t:
            return f"stream {t['stream_id']!r}: epoch not permitted in a v1 vector"
        # Epoch must be non-negative. Go zero-pads it into a string sort key
        # where a leading "-" sorts above the digits, while this tuple compare
        # puts -10 below -1: the two implementations would order the same tips
        # differently, which is precisely what this repo exists to rule out.
        if t.get("epoch", 0) < 0:
            return f"stream {t['stream_id']!r}: epoch must be non-negative, got {t['epoch']}"
    return None


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
        err = check_epoch_presence(sc["input"], min_ver)
        if err:
            return ([], "schema")
        try:
            scb = canonical(sc["input"])
        except ValueError:
            return ([], "canonical")
        try:
            pub.verify(base64.b64decode(sc["signature"]), scb)
        except InvalidSignature:
            return ([], "signature")
        full.append(sc["input"])
    return (full, "")


def check_tier_b(chain: list) -> tuple:
    """Cross-checkpoint rules. Returns (error_or_None, warnings). B4 and B5 are
    advisory: reported as stable tokens, never rejected. The tokens are
    machine-comparable so the Go and Python validators can be checked for
    agreement rather than eyeballed."""
    warns = []
    seen_identity = {}
    last_epoch = {}
    for i, cp in enumerate(chain):
        if i > 0 and cp["seq"] != chain[i - 1]["seq"] + 1:
            return (f"B1: checkpoint seq {cp['seq']} follows {chain[i-1]['seq']}", warns)
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
        for t in sorted(cp.get("tips", []), key=tip_identity):
            ident = tip_identity(t)
            if ident in seen_identity:
                return (f"B3: stream {t['stream_id']!r} epoch {tip_epoch(t)} "
                        f"committed in checkpoint {seen_identity[ident]} and again in {cp['seq']}", warns)
            seen_identity[ident] = cp["seq"]
            prev = last_epoch.get(t["stream_id"])
            if prev is not None and tip_epoch(t) != prev:
                warns.append("B4:" + t["stream_id"])
            last_epoch[t["stream_id"]] = tip_epoch(t)
        # B5 is a plain string comparison: the pinned YYYY-MM-DDTHH:MM:SSZ
        # profile sorts chronologically, so no date parsing is needed.
        if i > 0 and cp["timestamp"] < chain[i - 1]["timestamp"]:
            warns.append(f"B5:{cp['seq']}")
    return (None, warns)


def main() -> int:
    with open(sys.argv[1], "rb") as f:
        suite = json.load(f)
    if suite.get("format_version", 1) > SUPPORTED_FORMAT_VERSION:
        print(f"  note: suite format_version={suite['format_version']} exceeds "
              f"supported={SUPPORTED_FORMAT_VERSION}; unsupported vectors will be skipped")
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(suite["public_key_hex"]))

    prev_expected = None
    for i, v in enumerate(suite["vectors"]):
        if skip_vector(v.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            print(f"  skip {v['name']:<34} requires format_version {v['min_format_version']}")
            prev_expected = None
            continue
        cb = canonical(v["input"])
        if cb.decode("utf-8") != v["canonical"]:
            print(f"FAIL [{v['name']}] canonical mismatch")
            print(f"  got:  {cb.decode('utf-8')}")
            print(f"  want: {v['canonical']}")
            return 1
        if hashlib.sha256(cb).hexdigest() != v["sha256"]:
            print(f"FAIL [{v['name']}] sha256 mismatch")
            return 1
        try:
            pub.verify(base64.b64decode(v["signature"]), cb)
        except InvalidSignature:
            print(f"FAIL [{v['name']}] signature does not verify")
            return 1
        err = check_epoch_presence(v["input"], v.get("min_format_version", 0))
        if err:
            print(f"FAIL [{v['name']}] {err}")
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
        # A vector carrying its own chain context is not part of the positives'
        # own hash chain, so prev_expected does not apply to it.
        if (i > 0 and prev_expected is not None and not v.get("chain")
                and v["input"]["prev_hash"] != prev_expected):
            print(f"FAIL [{v['name']}] chain break")
            return 1
        if not v.get("chain"):
            # Only vectors in the positives' own hash chain advance it; a
            # chain-carrying vector must not become the next one's expected
            # predecessor.
            prev_expected = v["sha256"]
        print(f"  ok  {v['name']:<34} sha256={v['sha256'][:16]}…")

    def reject_reason(nv):
        err = check_epoch_presence(nv["input"], nv.get("min_format_version", 0))
        if err:
            return "schema"
        try:
            cb = canonical(nv["input"])
        except ValueError:
            return "canonical"
        try:
            pub.verify(base64.b64decode(nv["signature"]), cb)
        except InvalidSignature:
            return "signature"
        if nv.get("chain"):
            prefixes, reason = verify_prefixes(
                pub, nv["chain"], nv.get("min_format_version", 0))
            if reason:
                return reason
            tb_err, _ = check_tier_b(prefixes + [nv["input"]])
            if tb_err:
                return "tier_b"
        if nv.get("prev_sha256") and nv["input"]["prev_hash"] != nv["prev_sha256"]:
            return "chain"
        return ""

    for nv in suite.get("negatives", []):
        if skip_vector(nv.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            print(f"  skip {nv['name']:<34} requires format_version {nv['min_format_version']}")
            continue
        got = reject_reason(nv)
        if got == "":
            print(f"FAIL [{nv['name']}] accepted, but must be rejected")
            return 1
        if got != nv["expect"]:
            print(f"FAIL [{nv['name']}] rejected for {got!r}, expected {nv['expect']!r}")
            return 1
        print(f"  ok  {nv['name']:<34} rejected ({got})")

    print(f"PASS: {len(suite['vectors'])} positive + {len(suite.get('negatives', []))} negative "
          f"vectors, all as expected (independent Python impl)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
