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


def canonical(cp: dict) -> bytes:
    # Producer rule: tips are ordered by stream_id before canonicalization
    # (JCS fixes object-key order but preserves array order).
    cp = dict(cp)
    cp["tips"] = sorted(cp.get("tips", []), key=lambda t: t["stream_id"])
    # For a strings-and-integers schema, RFC 8785 JCS reduces to sorted keys,
    # compact separators, UTF-8, and standard JSON string escaping.
    return json.dumps(cp, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def main() -> int:
    with open(sys.argv[1], "rb") as f:
        suite = json.load(f)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(suite["public_key_hex"]))

    prev_expected = None
    for i, v in enumerate(suite["vectors"]):
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
        if i > 0 and v["input"]["prev_hash"] != prev_expected:
            print(f"FAIL [{v['name']}] chain break")
            return 1
        prev_expected = v["sha256"]
        print(f"  ok  {v['name']:<34} sha256={v['sha256'][:16]}…")

    def reject_reason(nv):
        cb = canonical(nv["input"])
        try:
            pub.verify(base64.b64decode(nv["signature"]), cb)
        except InvalidSignature:
            return "signature"
        if nv.get("prev_sha256") and nv["input"]["prev_hash"] != nv["prev_sha256"]:
            return "chain"
        return ""

    for nv in suite.get("negatives", []):
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
