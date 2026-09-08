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


def cp_seq(cp: dict) -> int:
    """A checkpoint's seq, treating a present null the same as absent: 0.

    `.get("seq", 0)` at a use site only supplies 0 when the key is ABSENT; a
    PRESENT null still reads back as None and would reach B1's `prev_seq + 1`
    unguarded. Go's non-pointer `Seq int` field decodes JSON null as a
    documented no-op, leaving the zero value (verified directly: decoding
    `{"seq":null,...}` yields `Seq == 0`). Mirrors tip_epoch's fold, for the
    same reason and the same shape of bug."""
    seq = cp.get("seq")
    return 0 if seq is None else seq


def cp_timestamp(cp: dict) -> str:
    """A checkpoint's timestamp, treating a present null the same as absent:
    "". Same reasoning as cp_seq, guarding B5's `<` against Go's non-pointer
    `Timestamp string` field, which decodes JSON null the same documented-no-op
    way."""
    ts = cp.get("timestamp")
    return "" if ts is None else ts


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


# format_version 3 added input_raw_hex (spec §5.5) and the A4 encoding check
# (spec §7/§8 step 4): a checkpoint may now arrive as raw bytes to
# canonicalize instead of a typed input object, specifically so a vector can
# carry invalid UTF-8 -- inexpressible on the typed path at all, since
# json.loads would already have to succeed to populate one -- or a lone
# surrogate escape, which the typed path CAN carry, just inconsistently: this
# module's own json.loads keeps the literal surrogate in the resulting str
# (Go's encoding/json instead silently substitutes U+FFFD), so the two
# references disagree on such a checkpoint today unless it arrives as
# input_raw_hex and goes through check_encoding below. See
# https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/36.
# Unknown-member rejection makes this non-additive for a v2 validator
# (spec §5 point 2), hence the bump rather than a same-version add.
SUPPORTED_FORMAT_VERSION = 3


def skip_vector(min_ver: int, supported_ver: int) -> bool:
    """A vector needing a newer format is skipped with a warning, never failed."""
    return min_ver > supported_ver


def check_epoch_presence(cp: dict, min_ver: int):
    """Spec 5a boundary: epoch required at v2+, absent at v1. Without this the
    absent-vs-zero distinction is unenforced spec text, and a v2 tip missing
    epoch would silently validate as 0.

    Like every reason-returning function here it must return a reason, never
    raise: Go's decoder gives a clean error for a wrong-typed epoch, and a
    traceback in one reference where the other prints a diagnosis is the two
    disagreeing on third-party input."""
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
        # Type-gate before comparing. `ep < 0` against a str, list or dict
        # raises TypeError, which the contract above forbids; and bool is an
        # int subclass while a float compares fine against 0, so `epoch: true`
        # and `epoch: 1.0` passed here while Go's *int rejected both with
        # "cannot unmarshal". One gate, in one place, rather than a defence at
        # every comparison below.
        if ep is not None and (isinstance(ep, bool) or not isinstance(ep, int)):
            return (f"stream {sid!r}: epoch must be an integer, got "
                    f"{type(ep).__name__}")
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


# RFC 7493 (I-JSON) §2.2's stated integer range: the largest magnitude an
# IEEE 754 double represents exactly, 2^53-1. This repo's own canonical form
# is RFC 8785 JCS, which defers entirely to whatever range a schema declares
# -- the restriction enforced below is I-JSON's, not JCS's, and exists to
# protect a THIRD implementation that parses JSON numbers as float64
# (JavaScript's Number, for one), not because Go or Python have any trouble
# with a larger value themselves: both round-trip far past this boundary
# exactly (Go's int64, Python's arbitrary-precision int), confirmed directly
# before this comment was written, not assumed. _MIN_SAFE_INT is its
# negative mirror; RFC 7493 states the range symmetrically.
_MAX_SAFE_INT = 2**53 - 1
_MIN_SAFE_INT = -(2**53 - 1)


def check_integer_range(cp: dict, min_ver: int):
    """A5 (spec §4, §7): every integer field on a checkpoint -- seq, and each
    tip's entry_count, epoch and sequence_number -- must fall within
    _MIN_SAFE_INT/_MAX_SAFE_INT. Applied uniformly across all four fields
    rather than only entry_count (the one field the spec names for the
    published vector), because the interoperability risk this rule exists to
    close applies equally to any of them. Mirrors Go's checkIntegerRange;
    both report a failure as "schema". Gated on min_ver the same way
    check_epoch_presence gates its own rules: a format_version 1 or 2 vector
    is never rejected by this rule.

    entry_count and sequence_number reach this function completely
    untyped by anything upstream -- check_schema type-gates seq, and
    check_epoch_presence type-gates epoch, but neither of those two fields
    had ever been read at all before this function existed: `_TIP_MEMBERS`
    only declares the member NAME as allowed, and canonical() serializes
    whatever value is present without inspecting it. A wrong-typed
    entry_count (a string, say) reached the comparison below and raised
    TypeError, uncaught, where Go's `EntryCount int` struct field already
    refuses the whole file at decode -- the exact defect class already fixed
    for every OTHER scalar in this schema, just not these two until now.
    Type-gated here, in the same position and the same way as every sibling
    gate in this file, and -- unlike the range check itself -- NOT
    min_ver-gated: Go's struct decode enforces the type unconditionally, at
    every format version, so this reference must too or a v1/v2 vector with
    a wrong-typed entry_count would newly diverge in the other direction.
    None (absent, or explicit null) stays legal, matching seq's own gate
    just above and Go's non-pointer int fields: a JSON null decoded into
    either is a documented no-op, leaving the zero value, not an error."""
    seq = cp.get("seq") or 0
    if min_ver >= 3 and not (_MIN_SAFE_INT <= seq <= _MAX_SAFE_INT):
        return f"seq {seq} is outside the I-JSON-safe integer range [{_MIN_SAFE_INT}, {_MAX_SAFE_INT}]"
    for t in (cp.get("tips") or []):
        sid = t.get("stream_id", "")
        for field in ("entry_count", "sequence_number"):
            val = t.get(field)
            if val is not None and (isinstance(val, bool) or not isinstance(val, int)):
                return f"stream {sid!r}: {field} must be an integer, got {type(val).__name__}"
            if min_ver >= 3 and val is not None and not (_MIN_SAFE_INT <= val <= _MAX_SAFE_INT):
                return (f"stream {sid!r}: {field} {val} is outside the "
                        f"I-JSON-safe integer range [{_MIN_SAFE_INT}, {_MAX_SAFE_INT}]")
        ep = t.get("epoch")
        if min_ver >= 3 and ep is not None and not (_MIN_SAFE_INT <= ep <= _MAX_SAFE_INT):
            return f"stream {sid!r}: epoch {ep} is outside the I-JSON-safe integer range [{_MIN_SAFE_INT}, {_MAX_SAFE_INT}]"
    return None


# The complete member set of each object in the schema. Anything else is bytes
# the signature does not cover, and both references reject it -- Go through its
# decoder's DisallowUnknownFields, this one through the checks below.
#
# Declaring the sets explicitly is the only way this reference can hold that
# rule. It canonicalizes the object AS IT ARRIVES, so an injected member does
# change the bytes and break the published signature -- but that only rejects a
# suite whose signatures were computed BEFORE the injection. A third party who
# re-signs after injecting, which is what a forger does, produced a
# self-consistent suite this reference ACCEPTED and Go rejected: on a
# checkpoint, on a tip, and on a signed chain prefix alike. "The signature no
# longer matches" was never the unknown-member rule; it was a side effect that
# happened to fire on the one case a test injected.
_CP_MEMBERS = frozenset({"prev_hash", "seq", "timestamp", "tips"})
_TIP_MEMBERS = frozenset({"entry_count", "epoch", "sequence_number",
                          "stream_id", "tip_hash"})
_SIGNED_CP_MEMBERS = frozenset({"input", "signature"})
# The envelope around the checkpoints. Go's DisallowUnknownFields covers these
# structs as a matter of course, so an unknown member beside "name" -- or
# beside "vectors" at the top level -- failed the whole file there while this
# reference ignored it. The rule the README states is about the document, not
# only about the objects a signature happens to cover.
_SUITE_MEMBERS = frozenset({"format_version", "description", "algorithm",
                            "signing_seed_hex", "public_key_hex", "vectors",
                            "negatives"})
_VECTOR_MEMBERS = frozenset({"name", "input", "input_raw_hex", "canonical", "sha256",
                             "signature", "chain", "expect_warnings", "min_format_version"})
_NEGATIVE_MEMBERS = frozenset({"name", "expect", "reason", "input", "input_raw_hex",
                               "signature", "prev_sha256", "chain", "min_format_version"})


def check_envelope(suite):
    """Reason the suite ENVELOPE is malformed, or None: the suite object may
    carry only the members the schema defines, and `vectors`/`negatives` must
    be arrays of objects.

    Envelope only. The per-ENTRY member sets live in check_entries, which runs
    after the skip decision, because a vector of a newer format is skipped and
    a skipped entry's members must not be examined at all -- "MUST NOT treat a
    skip as a failure". Go draws the line in the same place: its envelope
    decode is strict and eager (there is no per-file version a validator may
    ignore), its entry decodes strict and only for the entries it will check.

    "Is it an object" stays here rather than moving with them, because Go
    cannot skip past that either: it has to read min_format_version off every
    entry to make the skip decision at all, and a non-object entry defeats
    that in both references."""
    if not isinstance(suite, dict):
        return "the suite must be a JSON object"
    err = unknown_members(suite, _SUITE_MEMBERS, "the suite")
    if err:
        return err
    # description/algorithm/signing_seed_hex are never read for any check --
    # unknown_members above only gates member NAMES, never types -- so a
    # wrong-typed value here reached no comparison and the suite validated
    # normally.
    for field in ("description", "algorithm", "signing_seed_hex"):
        val = suite.get(field)
        if val is not None and not isinstance(val, str):
            return f"{field} on the suite must be a string, got {type(val).__name__}"
    for key, what in (("vectors", "a vector"), ("negatives", "a negative")):
        entries = suite.get(key) or []
        if not isinstance(entries, list):
            return f"{key} must be an array"
        for e in entries:
            if not isinstance(e, dict):
                return f"{what} must be a JSON object"
    return None


def check_checkpoint_members(cp, what: str):
    """Reason for an unknown member on a checkpoint or on one of its tips, or
    None. Shape problems below that -- a null `input`, a non-object, a
    wrong-typed or null `tips` -- are check_schema's verdict, not this one, and
    are passed over here so the two references keep reporting them the same
    way."""
    if not isinstance(cp, dict):
        return None
    err = unknown_members(cp, _CP_MEMBERS, what)
    if err:
        return err
    tips = cp.get("tips")
    if not isinstance(tips, list):
        return None
    for t in tips:
        if not isinstance(t, dict):
            continue
        err = unknown_members(t, _TIP_MEMBERS, f"a tip on {what}")
        if err:
            return err
    return None


def check_entries(suite):
    """Reason an entry this build will actually CHECK carries a member the
    schema does not define, or None.

    Two things about WHERE this runs, and both are the point of it.

    After the skip decision: Go strict-decodes only the non-skipped entries and
    never looks inside a skipped one, so this must not either. A future-format
    vector carrying a member neither build knows is skipped by both -- which is
    the whole promise of min_format_version, that new vector shapes can be
    added without breaking existing validators.

    Before the per-entry validation, unconditionally: reject_reason compares
    only the reason TOKEN, so an unknown member injected into a negative whose
    `expect` is already "schema" still returned "schema", matched, and the
    suite PASSED -- while Go refused to load the same file. A pre-existing
    defect must not mask an injected one. An unknown member is bytes the
    signature does not cover; it is reported wherever it sits.

    The positions covered are exactly the ones Go's strict decode reaches: the
    entry itself, its checkpoint and that checkpoint's tips, each signed chain
    prefix wrapper, and each prefix's checkpoint and tips."""
    for key, allowed, what in (("vectors", _VECTOR_MEMBERS, "a vector"),
                               ("negatives", _NEGATIVE_MEMBERS, "a negative")):
        entries = suite.get(key) or []
        if not isinstance(entries, list):
            continue  # check_envelope's verdict, already returned above
        for e in entries:
            if not isinstance(e, dict):
                continue  # likewise
            named = f"{what} ({e.get('name', '?')!r})"
            min_ver = e.get("min_format_version", 0)
            # Type-gate before comparing: `>` against a str raises TypeError,
            # which is a traceback here and a clean decode error in Go. It runs
            # before the skip decision because the skip decision is what reads
            # the member -- Go reads it off every entry too, skipped or not.
            if isinstance(min_ver, bool) or not isinstance(min_ver, int):
                return (f"min_format_version on {named} must be an integer, got "
                        f"{type(min_ver).__name__}")
            # Same reasoning, for "name": Go's entryHeader{Name string} is
            # unmarshaled for every entry before the skip decision too (it is
            # the struct the skip decision itself is read off), so a
            # non-string name fails the whole file at load regardless of
            # skip status -- not just for entries this build goes on to
            # check. `is not None`, not `"name" in e`: a present-but-null
            # name unmarshals into Go's zero string "" without error (JSON
            # null into a non-pointer field is a no-op), so null must stay
            # legal here the same way a missing name already is.
            # Checked after min_format_version, so an entry with BOTH fields
            # wrong-typed is diagnosed by min_format_version here. Go's
            # entryHeader unmarshal instead reports whichever field the JSON
            # text happens to list first, since a decoder is a stream over
            # the document as written -- an order this reference cannot
            # reproduce without parsing raw key order, and the two would
            # still only ever agree by coincidence of input order. Neither
            # verdict is what disagrees, only which reason is printed for an
            # entry malformed in two ways at once, so this is left as a fixed
            # pick rather than chased.
            name = e.get("name")
            if name is not None and not isinstance(name, str):
                return (f"name on {named} must be a string, got "
                        f"{type(name).__name__}")
            if skip_vector(min_ver, SUPPORTED_FORMAT_VERSION):
                continue
            err = unknown_members(e, allowed, named)
            if err:
                return err
            # reason and prev_sha256 are members of the full NegativeVector,
            # not of the header the skip decision above already read -- Go
            # only strict-decodes a NegativeVector for an entry it did NOT
            # skip, so these must be gated here rather than alongside
            # min_format_version/name. reason is pure documentation, read
            # nowhere; prev_sha256 used to be read only inside
            # reject_reason's `if nv.get("prev_sha256") and ...`, whose `!=`
            # never raises across Python types -- a truthy wrong type (e.g.
            # a list) coincidentally reproduced the "chain" token a real
            # linkage defect returns, and a falsy one ([], 0, {}) no-opped
            # past the truthy check same as an absent field. Gating the type
            # here, unconditionally, fails the whole file for every wrong
            # type alike, matching Go's plain `string` field instead of a
            # per-entry verdict that depended on the value's truthiness.
            if key == "negatives":
                reason = e.get("reason")
                if reason is not None and not isinstance(reason, str):
                    return (f"reason on {named} must be a string, got "
                            f"{type(reason).__name__}")
                prev_sha256 = e.get("prev_sha256")
                if prev_sha256 is not None and not isinstance(prev_sha256, str):
                    return (f"prev_sha256 on {named} must be a string, got "
                            f"{type(prev_sha256).__name__}")
            err = check_checkpoint_members(e.get("input"),
                                           f"the checkpoint of {named}")
            if err:
                return err
            # input_raw_hex is a member of the full Vector/NegativeVector,
            # not of the header the skip decision above already read, so it
            # is gated here rather than alongside min_format_version/name --
            # same reasoning as reason/prev_sha256 above, just for a field
            # both vectors and negatives can carry. Go's struct field is
            # plain `string`, so a wrong-typed value there fails the whole
            # file at strict decode; resolve_input's own `len(s) % 2 == 0`
            # read of it crashed uncaught on anything without a length (an
            # int, a bool, a float) rather than returning a reason, same
            # shape of bug as the pre-#7/#20 fields once did.
            input_raw_hex = e.get("input_raw_hex")
            if input_raw_hex is not None and not isinstance(input_raw_hex, str):
                return (f"input_raw_hex on {named} must be a string, got "
                        f"{type(input_raw_hex).__name__}")
            # Type-gate "chain" and "expect_warnings" before either is read
            # as a list downstream: absent OR explicitly null is Go's nil
            # slice -- legal, zero entries -- but a PRESENT non-list value
            # (a number, a string, an object) is a defect Go's strict decode
            # would fail the whole file on, and main()'s `len()`/iteration
            # over it raised TypeError uncaught rather than reporting it.
            for field in ("chain", "expect_warnings"):
                val = e.get(field)
                if val is not None and not isinstance(val, list):
                    return (f"{field} on {named} must be an array, got "
                            f"{type(val).__name__}")
            chain = e.get("chain")
            if not isinstance(chain, list):
                continue
            for sc in chain:
                if not isinstance(sc, dict):
                    continue  # verify_prefixes' verdict, not this one
                err = unknown_members(sc, _SIGNED_CP_MEMBERS,
                                      f"a signed chain prefix of {named}")
                if err:
                    return err
                err = check_checkpoint_members(
                    sc.get("input"),
                    f"the checkpoint of a signed chain prefix of {named}")
                if err:
                    return err
    return None


def unknown_members(obj, allowed, what: str):
    """Reason naming the members of `obj` outside `allowed`, or None. Sorted,
    so the message does not depend on dict iteration order."""
    extra = sorted(set(obj) - allowed)
    if extra:
        return f"unknown member(s) {extra} on {what}; the signature does not cover them"
    return None


def _hex4_value(b: bytes) -> int:
    """Parses exactly 4 strict hex digits (0-9, A-F, a-f only) into an int,
    or raises ValueError -- for check_encoding's \\uXXXX window. Not
    int(bytes_or_str, 16): that stdlib constructor is a permissive
    superset of what Go's strconv.ParseUint(s, 16, 32) accepts for the
    equivalent window -- it additionally allows a leading `+`/`-` sign,
    `_` digit-group separators, a `0x`/`0X` prefix, and surrounding
    whitespace, every one of which consumes at least one of the 4
    available bytes here and so caps what int() can extract from a
    malformed window at 0xFFF, always below the surrogate range -- but
    still a real reason-token divergence (Go says "encoding", Python's
    lenient parse either succeeds wrongly or falls through to a
    downstream "schema" once json.loads' own strict grammar catches it),
    proven directly against checkEncoding, not merely reasoned about.
    Mirrors Go's strconv.ParseUint call sites exactly."""
    if len(b) != 4:
        raise ValueError(f"not 4 bytes: {b!r}")
    value = 0
    for c in b:
        if 0x30 <= c <= 0x39:
            value = value * 16 + (c - 0x30)
        elif 0x41 <= c <= 0x46:
            value = value * 16 + (c - 0x41 + 10)
        elif 0x61 <= c <= 0x66:
            value = value * 16 + (c - 0x61 + 10)
        else:
            raise ValueError(f"not a hex digit: {bytes([c])!r}")
    return value


def check_encoding(raw: bytes) -> str:
    """A4's explicit validation step on raw bytes, run before any JSON
    parsing -- never as an emergent property of the JSON stack, which is
    exactly where the two references disagree (spec §1 defect 2): given
    `"\\ud800\\ud800"`, Go's encoding/json silently yields two U+FFFD with no
    error, while Python's own json.loads preserves the lone surrogates and a
    later .encode("utf-8") raises. Neither is a clean rejection, and they
    disagree with each other -- before gowebpki/jcs (or this reference's own
    canonicalization) is even reached.

    Two things are checked, both about UTF-8 specifically: the raw bytes
    must be valid UTF-8 outright, and no \\uXXXX escape inside a string
    literal may encode a surrogate (U+D800-U+DFFF) that is not the
    correctly-ordered half of an adjacent pair. A decoded, correctly-paired
    surrogate pair (like 😀 for U+1F600) is NOT rejected -- see
    valid_surrogate_pair, without which an implementation could pass this
    suite by rejecting every \\ud escape, which is the over-rejection §6
    already argues against for the suite as a whole.

    Byte-oriented, not rune-oriented: after the upfront UTF-8-validity
    check, `"`, `\\`, `u` and hex digits are all single-byte ASCII (<0x80),
    and every UTF-8 continuation byte is >=0x80, so a multi-byte character
    can never be misread as one of these structural markers. Mirrors Go's
    checkEncoding byte for byte."""
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return "encoding"
    in_string = False
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if not in_string:
            if c == 0x22:  # '"'
                in_string = True
            i += 1
            continue
        if c == 0x22:  # '"'
            in_string = False
            i += 1
        elif c == 0x5C:  # '\\'
            if i + 1 >= n:
                return "encoding"  # truncated escape
            if raw[i + 1] != 0x75:  # 'u'
                i += 2  # \\, \", \/, \b, \f, \n, \r, \t
                continue
            if i + 6 > n:
                return "encoding"  # truncated \uXXXX
            try:
                code = _hex4_value(raw[i + 2:i + 6])
            except ValueError:
                return "encoding"  # \u not followed by 4 hex digits
            if 0xD800 <= code <= 0xDBFF:
                # High surrogate: legal only immediately followed by a low
                # surrogate escape, forming one pair. Anything else -- EOF,
                # a different escape, a non-surrogate \uXXXX, ordinary text
                # -- is a lone high surrogate.
                if i + 12 <= n and raw[i + 6] == 0x5C and raw[i + 7] == 0x75:
                    try:
                        low = _hex4_value(raw[i + 8:i + 12])
                    except ValueError:
                        low = -1
                    if 0xDC00 <= low <= 0xDFFF:
                        i += 12
                        continue
                return "encoding"
            elif 0xDC00 <= code <= 0xDFFF:
                # A low surrogate reached on its own: the branch above only
                # advances past one as part of consuming a pair together, so
                # reaching one here means nothing claimed it as a pair.
                return "encoding"
            else:
                i += 6  # an ordinary \uXXXX escape, not a surrogate
        else:
            i += 1
    return ""


_HEX_ALPHABET = "0123456789abcdefABCDEF"


def _is_strict_hex(s: str) -> bool:
    """True iff `s` is exactly what Go's encoding/hex.DecodeString accepts:
    an even-length string of hex digits only. Not a check bytes.fromhex()
    already makes redundant -- it doesn't. bytes.fromhex() silently ignores
    embedded ASCII whitespace (that's documented CPython behavior, not a
    bug in it), which Go's decoder rejects outright. Proven to matter, not
    just theoretical: the committed valid_surrogate_pair vector's own
    input_raw_hex, with one space spliced in, is REJECTED by Go's
    resolveInput ("schema") and was ACCEPTED by this function before this
    check existed, decoding to byte-identical content -- a genuine
    accept/reject divergence between the two references on realistic input,
    not a contrived one. Gating on this exact alphabet, before
    bytes.fromhex ever runs, closes it."""
    return len(s) % 2 == 0 and all(c in _HEX_ALPHABET for c in s)


def resolve_input(input_obj, input_raw_hex: str):
    """The checkpoint an entry actually means: `input_obj` as given, or --
    when `input_raw_hex` is non-empty -- the checkpoint that raw byte string
    decodes to, after check_encoding has passed it. Returns (checkpoint,
    reason); reason is "" on success and "encoding" or "schema" on failure,
    matching the same tokens check_schema and the rest of this file already
    use. Never raises on malformed third-party input -- like every other
    check in this file, it returns a reason.

    Callers that already have input_raw_hex == "" (every vector before
    format 3) pay nothing beyond the one truthiness check: input_obj passes
    through completely unchanged, None/non-dict included -- check_schema's
    own `isinstance(cp, dict)` gate is what turns that into a clean "schema"
    reason, exactly as it already did before this function existed. Mirrors
    Go's resolveInput."""
    if not input_raw_hex:
        return input_obj, ""
    if not _is_strict_hex(input_raw_hex):
        return {}, "schema"
    try:
        raw = bytes.fromhex(input_raw_hex)
    except (ValueError, TypeError):
        return {}, "schema"
    reason = check_encoding(raw)
    if reason:
        return {}, reason
    try:
        cp = json.loads(raw)
    except json.JSONDecodeError:
        return {}, "schema"
    if not isinstance(cp, dict):
        return {}, "schema"
    return cp, ""


def check_schema(cp, min_ver: int):
    """Structural rules a checkpoint must satisfy before any byte-level check:
    it is an object, it carries no member the schema does not define, its
    scalar members (seq, timestamp, prev_hash) are correctly typed, `tips` is
    present as an array of objects, and every tip satisfies the epoch rules for
    the vector's format_version. Mirrors Go's checkSchema; both report a failure
    as "schema".

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
    err = unknown_members(cp, _CP_MEMBERS, "a checkpoint")
    if err:
        return err
    # Type-gate before Tier B ever touches these: B1's prev_seq + 1 raises
    # TypeError for a wrong-typed seq, and B5's `<` raises for a
    # non-comparable timestamp -- a traceback here where Go's strict
    # `Seq int` / `Timestamp string` decode gives a clean rejection.
    # prev_hash never reaches an unsafe operation (B2 compares it with `!=`,
    # which never raises across Python types) but is gated the same way for
    # the same reason description/algorithm/reason/prev_sha256 already are:
    # Go's `PrevHash string` rejects a wrong type at decode regardless of
    # whether anything reads it unsafely. One gate, in one place, rather than
    # a defence at every comparison below -- the same shape as the epoch gate
    # just below. None/absent stay legal: a non-pointer Go field decodes JSON
    # null into its zero value as a documented no-op, matching seq's existing
    # `.get("seq", 0)` and timestamp/prev_hash's `.get(field, "")` defaults
    # elsewhere in this file.
    seq = cp.get("seq")
    if seq is not None and (isinstance(seq, bool) or not isinstance(seq, int)):
        return f"seq on a checkpoint must be an integer, got {type(seq).__name__}"
    for field in ("timestamp", "prev_hash"):
        val = cp.get(field)
        if val is not None and not isinstance(val, str):
            return f"{field} on a checkpoint must be a string, got {type(val).__name__}"
    tips = cp.get("tips")
    if not isinstance(tips, list) or not all(isinstance(t, dict) for t in tips):
        return ("tips is required and must be an array of objects; null and "
                "absent are not an empty array")
    for t in tips:
        err = unknown_members(t, _TIP_MEMBERS, "a tip")
        if err:
            return err
    err = check_epoch_presence(cp, min_ver)
    if err:
        return err
    return check_integer_range(cp, min_ver)


# The genesis constant: SHA-256 of the empty string. Derived rather than
# copied from Go's hardcoded sha256Empty literal, so this reference's
# agreement with it is evidence, not an assumption baked into a shared
# constant.
_GENESIS_HASH = hashlib.sha256(b"").hexdigest()


def check_genesis(cp) -> str:
    """Tier A rule A6 (spec §4): a checkpoint claims to be the genesis of the
    chain -- seq 1 -- if and only if its prev_hash is the genesis constant.
    seq is a single counter for the whole audit trail (B1: it increments by
    exactly 1 at every transition of the assembled chain), so seq 1 can only
    ever be a claim to BE the genesis checkpoint -- never a claim about
    position within whatever chain window a validator happens to have been
    handed. mid_chain_window_no_genesis (seq 400, a non-genesis prev_hash) is
    the vector that already pins the rule is evaluated against the absolute
    value, not a checkpoint's index in the chain array; this rule is what
    makes that distinction load-bearing rather than incidental.

    Deliberately NOT part of check_schema: broken_chain (a published, frozen
    negative) has seq 1 and a non-genesis prev_hash, rejected today purely by
    the prev_sha256 linkage check -- the last step of reject_reason. Folding
    this rule into check_schema, which runs first, would flip broken_chain's
    reject reason from "chain" to "genesis" and require superseding a frozen
    vector. Called after that linkage check instead, so broken_chain never
    reaches it. Mirrors Go's checkGenesis; both report a failure as
    "genesis"."""
    is_genesis_seq = cp.get("seq") == 1
    is_genesis_hash = cp.get("prev_hash") == _GENESIS_HASH
    if is_genesis_seq != is_genesis_hash:
        return (f"seq and prev_hash disagree about genesis: seq={cp.get('seq')!r}, "
                f"prev_hash is the genesis constant={is_genesis_hash}")
    return ""


def decode_signature(s) -> bytes:
    """Decode a base64 signature, requiring the encoding to be the CANONICAL
    one. Raises ValueError (or TypeError for a non-string) otherwise; every
    caller already folds both into reason "signature", as Go does.

    The round trip is the check, not the decode, and it mirrors Go's decodeSig
    byte for byte. Go's base64.StdEncoding.DecodeString ignores embedded
    newlines and carriage returns by documented behaviour, so a signature with
    a "\n" spliced into it verified there and was rejected here -- and .Strict()
    does not fix it, since it enforces the padding BITS, not the alphabet.
    Making Go strict by round trip without doing the same here would only move
    the divergence: both decoders ignore non-zero padding bits, so two
    different signature STRINGS decode to the same 64 bytes and both verify.
    Re-encoding and comparing closes both classes, in both references.

    validate=True stays: it is what rejects the stray "!" of the published
    signature_with_stray_character vector as a decode failure rather than
    silently discarding it, and it is a narrower, clearer error than the round
    trip alone would give.
    """
    raw = base64.b64decode(s, validate=True)
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError("signature is not canonically base64-encoded")
    return raw


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
        # The wrapper gets the unknown-member rule too, not only the checkpoint
        # inside it. Nothing here canonicalizes the wrapper, so an injected
        # member on it changes no signed bytes at all -- it is the one position
        # where the "it breaks the signature anyway" reasoning was never even
        # accidentally true. Go's DisallowUnknownFields covers the wrapper as a
        # matter of course; this reference has to say so.
        err = unknown_members(sc, _SIGNED_CP_MEMBERS, "a signed chain prefix")
        if err:
            return ([], "schema")
        # `or {}`, not .get("input", {}): a present-but-null input is not an
        # absent one. Go decodes either into a zero Checkpoint, whose nil tips
        # checkSchema rejects as "schema".
        cp = sc.get("input") or {}
        err = check_schema(cp, min_ver)
        if err:
            return ([], "schema")
        err = check_genesis(cp)
        if err:
            return ([], "genesis")
        try:
            scb = canonical(cp)
        except ValueError:
            return ([], "canonical")
        try:
            # binascii.Error (a ValueError) for non-base64 input, TypeError for
            # a non-string: Go folds a base64 decode failure into "signature"
            # via `err != nil || !Verify`, so this must too.
            # decode_signature, not a bare b64decode: a lenient or merely
            # alphabet-checking decode silently repairs a mutated signature
            # string, and the two references must repair exactly the same set
            # of them -- which is none. See its docstring.
            pub.verify(decode_signature(sc.get("signature", "")), scb)
        except (InvalidSignature, ValueError, TypeError):
            return ([], "signature")
        full.append(cp)
    return (full, "")


def check_tier_b(chain: list) -> tuple:
    """Cross-checkpoint rules. Returns (error_or_None, warnings). B4 and B5 are
    advisory: reported as stable tokens, never rejected. The tokens are
    machine-comparable so the Go and Python validators can be checked for
    agreement rather than eyeballed.

    A null seq/timestamp is folded to its zero value by cp_seq/cp_timestamp
    below, so this function never raises on one by itself. A wrong-TYPED one
    (a string, a list, ...) is a different matter: every caller of this
    function (main(), reject_reason()) runs check_schema directly on its own
    input, and indirectly via verify_prefixes on each chain prefix, before a
    checkpoint ever reaches here -- that is the only thing rejecting a wrong
    type -- this function does not re-check it. Go has no
    equivalent of calling this function directly with a wrong-typed seq at
    all: its Checkpoint struct cannot hold one, by construction, because
    decode-time strict typing already ran. A caller that skips check_schema
    and invokes this function directly on unchecked third-party data forfeits
    that protection, the same as it would by skipping check_schema before
    reading epoch."""
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
    #
    # seq and timestamp specifically go through cp_seq/cp_timestamp, not a
    # bare `.get(field, default)`: that default only covers an ABSENT key, and
    # a PRESENT null -- legal, since Go's non-pointer Seq/Timestamp fields
    # decode null as the same zero value -- would otherwise reach this
    # function's own arithmetic (B1's `prev_seq + 1`) or comparison (B5's `<`)
    # as None and raise. check_schema only gates wrong TYPES; folding null to
    # the zero value is this function's own job, same as tip_epoch's fold for
    # epoch. prev_hash keeps the bare `.get`: B2 compares it with `!=`, which
    # never raises for None or for any wrong type either.
    for i, cp in enumerate(chain):
        seq = cp_seq(cp)
        if i > 0:
            prev_seq = cp_seq(chain[i - 1])
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
        if i > 0 and cp_timestamp(cp) < cp_timestamp(chain[i - 1]):
            warns.append(f"B5:{seq}")
    return (None, warns)


def entry_name(e: dict) -> str:
    """A safe display name for a vector/negative entry in a report line.

    `name` is not a required member (Go's Name field zero-values to "" when
    it is absent or null, and never errors), but a bare `e['name']` raises
    KeyError on absence, and even `e.get('name')` fed to an aligned format
    spec like `f"{n:<34}"` raises TypeError for None or for any non-str,
    non-number value -- object.__format__ only accepts an empty spec. Both
    are third-party input like any other, so this reference must return a
    string, never raise."""
    name = e.get("name", "")
    return name if isinstance(name, str) else str(name)


def reject_reason(pub, nv):
    """Return the check that rejects a negative vector, or "" if it is
    (wrongly) accepted. At module scope, mirroring Go's top-level
    rejectReason, so both references can be exercised the same way."""
    cp, reason = resolve_input(nv.get("input") or {}, nv.get("input_raw_hex", ""))
    if reason:
        return reason
    err = check_schema(cp, nv.get("min_format_version", 0))
    if err:
        return "schema"
    try:
        cb = canonical(cp)
    except ValueError:
        return "canonical"
    try:
        # decode_signature: see verify_prefixes. A lenient decode silently
        # repairs a mutated signature string.
        pub.verify(decode_signature(nv.get("signature", "")), cb)
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
    if check_genesis(cp):
        return "genesis"
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
    err = check_envelope(suite)
    if err:
        print(f"FAIL: {err}")
        return 1
    # Structural member check over the entries this build will check, in the
    # position Go's strict entry decode occupies: after the envelope, after the
    # skip decision, before anything is validated or reported. Both references
    # therefore refuse the same file, before printing a single "ok" line.
    err = check_entries(suite)
    if err:
        print(f"FAIL: {err}")
        return 1
    # Type-gate before comparing, for the same reason check_entries gates
    # min_format_version: `>` against a str or None raises TypeError, which is
    # a traceback here and a clean decode error in Go.
    fv = suite.get("format_version", 1)
    if isinstance(fv, bool) or not isinstance(fv, int):
        print(f"FAIL: format_version must be an integer, got {type(fv).__name__}")
        return 1
    if fv > SUPPORTED_FORMAT_VERSION:
        print(f"  note: suite format_version={fv} exceeds "
              f"supported={SUPPORTED_FORMAT_VERSION}; unsupported vectors will be skipped")
    # A missing public_key_hex reads as "" here, matching Go's zero-valued
    # string field -- but Python's key constructor, unlike a raw Go byte
    # slice, validates length eagerly and raises on anything but exactly 32
    # bytes. Third-party data of the wrong type or length must produce a
    # clean top-level FAIL, not a traceback, so the construction is guarded
    # the same way the envelope and JSON-decode failures above it are.
    try:
        pub = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(suite.get("public_key_hex", "")))
    except (TypeError, ValueError) as e:
        print(f"FAIL: public_key_hex is invalid: {e}")
        return 1

    # How many entries MUST be checked, computed in a pre-pass that is
    # textually separate from the loops that do the checking. The rules cannot
    # fix a harness that silently skips vectors: a loop truncated to its first
    # entry, or a Tier B block that runs only for the first chain-carrying
    # vector, leaves every rule intact and every gate green. Counting what was
    # actually reached and comparing it here is the instrument closest to that
    # class; test_validate_checks_every_vector_and_negative and its Go mirror
    # recount the committed file independently and catch it too.
    want_positives = want_tier_b = want_negatives = 0
    # `or []`, not suite["vectors"]/suite.get(key, []): a missing OR explicitly
    # null "vectors"/"negatives" both read as Go's nil slice -- zero entries,
    # not an error -- and check_envelope has already rejected any non-null
    # value that is not an array of objects, so by this point either form is
    # safe to iterate.
    for v in suite.get("vectors") or []:
        if skip_vector(v.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            continue
        want_positives += 1
        # `or []`: check_entries allows "chain"/"expect_warnings" to be
        # explicitly null (Go's nil slice), so `.get(key, [])`'s default does
        # not apply and `len(None)` would raise here without this.
        if len(v.get("chain") or []) != 0 or len(v.get("expect_warnings") or []) != 0:
            want_tier_b += 1
    for nv in suite.get("negatives") or []:
        if not skip_vector(nv.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            want_negatives += 1
    got_positives = got_tier_b = got_negatives = 0

    prev_expected = None
    for i, v in enumerate(suite.get("vectors") or []):
        if skip_vector(v.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            print(f"  skip {entry_name(v):<34} requires format_version {v['min_format_version']}")
            prev_expected = None
            continue
        # `or {}`: a present-but-null "input" is not an absent one, and both
        # decode to Go's zero Checkpoint, whose nil tips check_schema rejects
        # as "schema" rather than raising on the None fed to it here.
        cp_input, reason = resolve_input(v.get("input") or {}, v.get("input_raw_hex", ""))
        if reason:
            print(f"FAIL [{entry_name(v)}] must be accepted, but input_raw_hex was rejected ({reason})")
            return 1
        # Same check order as Go's positive path -- schema boundary first,
        # then canonical bytes, hash, signature. Both negative paths already
        # agree on that order; this one lagged, and a check order a third party
        # can observe is part of what the two references must share.
        err = check_schema(cp_input, v.get("min_format_version", 0))
        if err:
            print(f"FAIL [{entry_name(v)}] {err}")
            return 1
        err = check_genesis(cp_input)
        if err:
            print(f"FAIL [{entry_name(v)}] {err}")
            return 1
        # A must-accept vector is third-party data like any other: Go prints a
        # clean "FAIL:" line for a malformed one, so raising here would make
        # the same input a traceback in one reference and a diagnosis in the
        # other.
        try:
            cb = canonical(cp_input)
        except ValueError as e:
            print(f"FAIL [{entry_name(v)}] canonical: {e}")
            return 1
        if cb.decode("utf-8") != v.get("canonical", ""):
            print(f"FAIL [{entry_name(v)}] canonical mismatch")
            print(f"  got:  {cb.decode('utf-8')}")
            print(f"  want: {v.get('canonical', '')}")
            return 1
        if hashlib.sha256(cb).hexdigest() != v.get("sha256", ""):
            print(f"FAIL [{entry_name(v)}] sha256 mismatch")
            return 1
        try:
            pub.verify(decode_signature(v.get("signature", "")), cb)
        except (InvalidSignature, ValueError, TypeError):
            print(f"FAIL [{entry_name(v)}] signature does not verify")
            return 1
        if v.get("chain") or v.get("expect_warnings"):
            # A must-accept vector's prefixes are verified exactly as a
            # negative's are: same helper, same MUST. `or []`: an explicitly
            # null chain is legal (see check_entries) but not iterable.
            prefixes, reason = verify_prefixes(
                pub, v.get("chain") or [], v.get("min_format_version", 0))
            if reason:
                print(f"FAIL [{entry_name(v)}] must be accepted, but its chain "
                      f"context was rejected ({reason})")
                return 1
            full = prefixes + [cp_input]
            tb_err, warns = check_tier_b(full)
            if tb_err:
                print(f"FAIL [{entry_name(v)}] must be accepted, but Tier B rejected it: {tb_err}")
                return 1
            # `or []`: an explicitly null expect_warnings means "none
            # expected", the same as an absent one -- not a mismatch against
            # whatever warns computed to, and not a `len(None)` crash above.
            if warns != (v.get("expect_warnings") or []):
                print(f"FAIL [{entry_name(v)}] warnings {warns}, want {v.get('expect_warnings') or []}")
                return 1
            got_tier_b += 1
        # A vector carrying its own chain context is not part of the positives'
        # own hash chain, so prev_expected does not apply to it.
        if (i > 0 and prev_expected is not None and not v.get("chain")
                and cp_input.get("prev_hash", "") != prev_expected):
            print(f"FAIL [{entry_name(v)}] chain break")
            return 1
        if not v.get("chain"):
            # Only vectors in the positives' own hash chain advance it; a
            # chain-carrying vector must not become the next one's expected
            # predecessor.
            prev_expected = v.get("sha256", "")
        got_positives += 1
        print(f"  ok  {entry_name(v):<34} sha256={v.get('sha256', '')[:16]}…")

    for nv in suite.get("negatives") or []:
        if skip_vector(nv.get("min_format_version", 0), SUPPORTED_FORMAT_VERSION):
            print(f"  skip {entry_name(nv):<34} requires format_version {nv['min_format_version']}")
            continue
        got = reject_reason(pub, nv)
        if got == "":
            print(f"FAIL [{entry_name(nv)}] accepted, but must be rejected")
            return 1
        if got != nv.get("expect", ""):
            print(f"FAIL [{entry_name(nv)}] rejected for {got!r}, expected {nv.get('expect', '')!r}")
            return 1
        got_negatives += 1
        print(f"  ok  {entry_name(nv):<34} rejected ({got})")

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
