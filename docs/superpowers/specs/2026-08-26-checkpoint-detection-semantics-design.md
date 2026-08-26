# Design: checkpoint detection semantics

> **Status:** Approved, revised after independent review · **Date:** 2026-08-26
> **Author:** Surabhi Pradhan

## 1. Problem

This repo publishes conformance vectors for a signed audit checkpoint. Its stated
purpose is to argue, to the OpenTelemetry Audit Logging SIG, that a checkpoint
construct is worth adding to a spec that today has only per-record chaining
(`audit.sequence.prev_hash`, `.number`, `.stream_id`).

It does not currently make that argument. Three defects, all verified:

1. **There is no cross-checkpoint detection logic.** Both validators check
   canonical bytes, SHA-256, signature and `prev_hash`. Neither compares tips
   across checkpoints. The negative vector `truncation_rewrites_committed_tip`
   is therefore mechanically a second signature-mismatch case with a narrative
   attached: it exercises Ed25519, not truncation detection.
2. **The two "independent implementations" diverge on ill-formed Unicode.**
   Given `"\ud800\ud800"`, Go's `encoding/json` silently yields
   `ef bf bd ef bf bd` (two U+FFFD) with no error; Python's `json.loads`
   preserves the lone surrogates and `.encode("utf-8")` then raises
   `UnicodeEncodeError`. Neither rejects cleanly and they disagree — before
   `gowebpki/jcs` is reached. The repo also pins `gowebpki/jcs v1.0.1`, the
   version shown in `open-telemetry/opentelemetry-collector-contrib#50079` to
   canonicalize distinguishable inputs to identical bytes.
3. **Duplicate `stream_id` leaks input order into signed bytes.** `sort.Slice`
   imposes no total order on equal keys, so the same logical tip set in two
   input orders produces two different canonical byte strings, two hashes and
   two signatures — in a repo whose entire claim is determinism.

A fourth, documentation-level defect: the README describes checkpoints as
committing "the tips of every active stream", which is a **snapshot** model. The
reference implementation is a **delta** model — `chain.Accumulator.Build` resets
the pending set. The README's "disappearance becomes detectable" overstates what
a delta model provides.

## 2. Goals and non-goals

**Goal.** Make the repo demonstrate the detection semantics that justify a
checkpoint construct, at a rigor level that survives the differential scrutiny
applied to JCS libraries in #50079.

**Non-goals.** Competing on JCS string-level conformance (ceded to
`astrogilda/aee-conformance`, which this repo cites and links); a third
implementation; fuzzing, property-based testing, differential JCS harnesses.

## 3. The delta model and the at-least-once problem

Each checkpoint commits the tips of streams **sealed since the previous
checkpoint**. A checkpoint is a delta; the chain is the accumulation.

An earlier draft of this design claimed the consequence was "a `stream_id` is
committed at most once across the chain," and built the whole of Tier B on it.
**That claim is false against the reference implementation.** `otel-agent-audit`
clears its `sealedTraces` dedup map after every successful WAL compaction, so a
re-delivered root span for an already-sealed `trace_id` is sealed again as a
second independent chain. `docs/threat-model.md` §5 documents this as an
"accepted at-least-once delivery trade-off", and the errors table states that
`duplicate_trace_segment` is "not evidence of tampering". A crash between
checkpoint persistence and `wal.MarkSealed`, and a timeout-split trace whose
late spans arrive after the dedup window, produce the same duplication — and the
timeout case yields a *lower* `entry_count` on re-commit, which is exactly the
shape of a rollback attack.

A hard "at most once" rule would therefore reject honest behaviour.

### Resolution: an explicit epoch on each tip

Each tip carries an `epoch`. The pair `(stream_id, epoch)` — not `stream_id`
alone — is the identity that must be unique across the chain.

`epoch` is **a producer generation counter, not a per-stream commit count.**
This distinction is load-bearing: after compaction the producer has forgotten it
ever saw the stream, so it cannot count that stream's prior commits. It always
knows its own generation. The generation is incremented whenever the dedup
window resets — on WAL compaction and on process start — and applies to every
tip committed while it is current.

That converts an undeclared artifact into a declared one:

- Same `(stream_id, epoch)`, different `tip_hash` → **hard reject.** Nothing
  legitimate produces this: within one generation the producer's dedup map is
  intact, so a second commit of the same stream cannot occur.
- Same `stream_id`, different `epoch` → **accepted, surfaced as advisory.** This
  is the declared at-least-once path. A verifier reports it, and the operator
  reconciles or ignores it, exactly as `duplicate_trace_segment` is handled today.

**Dependency:** this requires a change in `otel-agent-audit` —
`chain.Accumulator` gains a generation field, bumped by the compaction and start
paths. That is a chain-format change there and carries that project's
`schema_version` bump, fixture and doc requirements. This spec covers the vector
format only; the production change is tracked separately.

## 4. Taxonomy

### Tier A — per-checkpoint, stateless

| # | Property | Status |
|---|---|---|
| A1 | Canonical bytes reproduce | have (3 positives) |
| A2 | Signature verifies | have (`tampered_signature`) |
| A3 | No duplicate `(stream_id, epoch)` within a checkpoint | **add** |
| A4 | Ill-formed Unicode rejected, as an explicit pre-parse step on raw bytes | **add** |
| A5 | Integers within I-JSON range: `2^53−1` accepted, `2^53` rejected | **add** |

A5 is RFC 7493 §2.2's stated range, not an IEEE representability limit —
`2^53` is exactly representable; `2^53+1` is the first that is not. Cite I-JSON,
not JCS, if challenged.

### Tier B — cross-checkpoint, single chain, single verifier

| # | Rule | Detects | Strength |
|---|---|---|---|
| B1 | `seq` increments by exactly 1 | dropped or replayed checkpoint | hard |
| B2 | `prev_hash` equals SHA-256 of the previous checkpoint's canonical bytes | reordering, forking | hard (have) |
| B3 | `(stream_id, epoch)` appears at most once in the chain | re-commit within a generation, rollback | hard |
| B4 | Same `stream_id` under a different `epoch` | at-least-once re-delivery | **advisory** |
| B5 | `timestamp` non-decreasing across the chain | clock regression | **advisory** — the operator controls the clock |

B1 is largely subsumed by B2 on a contiguous chain: a dropped or duplicated
checkpoint breaks `prev_hash` either way. It is retained for precise diagnostics
and for verifying a suffix of a chain, not because it catches anything B2 misses.

**B1 and B2 detect a discontinuity; they cannot attribute cause.** Honest data
loss produces the same signal as deletion — see the known write-ordering defect
in the reference implementation, where an IO failure advances the accumulator and
strands tips. A verifier reports a broken chain; it does not report tampering.

### Tier C — beyond one verifier with one chain

Prose only, in `docs/limits.md`, linked to `otel-agent-audit/docs/threat-model.md` §2:

- **Split-view / equivocation.** Undetectable by a single verifier holding one
  chain; *provable* across two views, since two checkpoints with the same `seq`
  under one key and different hashes form a self-contained equivocation proof —
  the object CT uses for inconsistent STHs. This is the argument for the
  checkpoint being the right unit for a witness to gossip.
- **Full rewrite by the key holder**, served consistently. Needs external anchoring.
- **Staleness** — serving a valid old prefix. Currently undetectable; a maximum
  checkpoint interval plus a timestamp check would convert it into a detectable
  violation, as TUF does with expiry. Surface to the SIG as a design decision.
- **Never-committed streams.** Checkpoints attest what *was* committed, never
  that everything which occurred was committed. `threat-model.md` §7 already
  states the verifier cannot detect a trace that was never written.

## 5. Format changes and the consumer contract

1. **`format_version`** on `Suite`: an integer, starting at 1, incremented when
   a vector shape is added that an older validator cannot parse. Added now;
   adding it later is itself breaking.
2. **Per-vector feature gating.** `format_version` alone is insufficient: every
   Tier B negative carries a `chain` array, and an existing validator that
   ignores unknown fields would find such a vector signature-valid and
   chain-valid, report "accepted, but must be rejected", and hard-fail on a
   suite update — precisely the silent invalidation CONTRIBUTING forbids. Each
   vector therefore carries `min_format_version`. **Validators MUST skip, with a
   warning, any vector whose `min_format_version` exceeds their supported
   version, and MUST NOT treat a skip as a failure.** This rule ships in
   `format_version: 1`, before any vector needs it.
3. **Chain context for Tier B.** An optional ordered `chain` array of preceding
   checkpoints. **A validator MUST verify the signature of every checkpoint in
   the prefix, not merely hash it for linkage** — otherwise a suite could pass
   against a prefix of forged checkpoints. Stated explicitly because either
   answer is defensible and silence guarantees divergence.
4. **`input_raw_hex`.** `input` is a typed object round-tripped through each
   language's JSON parser, so encoding-level malformations are inexpressible.
   When `input_raw_hex` is present it is the exact bytes to canonicalize, and
   `input` is absent.
5. **`expect` becomes advisory for third parties.** `rejectReason` checks
   signature before chain, so a validator checking in another order reports a
   different reason on a vector failing both. Internally the suite guarantees
   each negative fails exactly one check, and **the generator asserts this at
   `gen` time** so the invariant cannot rot as vectors accumulate.
6. **Surface to the SIG, not fixed here:** the signed object carries no version
   field *inside the signed bytes*. Production gets this right —
   `schema_version` is inside `checkpointForSigning`. `format_version` versions
   the file, not the object, so a future canonical-form change is
   indistinguishable inside a signature.

## 6. Why there is no `limits` vector category

The conclusion stands; an earlier draft's argument for it did not, and is
withdrawn. That draft claimed a vector whose expected outcome is "accepted"
cannot fail. **That is wrong** — accept-vectors catch *over-rejection*, and the
positive vectors establish acceptance only for the shapes they contain. With B4
and B5 advisory, there is real implementation variance, which is exactly the
condition that justifies Wycheproof's third `acceptable` tier.

The correct narrow claim: undetectability of key-holder rewrite and single-view
equivocation is quantified over all possible verifier algorithms, and no fixture
tests that. Prose is the right home for *that* class. CT keeps split-view in RFC
6962 security considerations; TUF converts freeze into a detectable violation via
expiry and leaves the rest to prose; in-toto, SLSA and C2PA do the same.

Consequently: no `limits` category, **and** one **must-accept** vector per
advisory rule — `advisory_stream_recommitted_new_epoch` (B4) and
`advisory_timestamp_regression` (B5) — each asserting the verifier accepts and
warns rather than rejects. The equivocation proof is deferred until the OTEP has
a witness section.

## 7. Testing

Both validators implement Tiers A and B and must agree, including on which rules
are advisory and what a warning looks like.

**New negatives:** `duplicate_stream_epoch_in_checkpoint` (A3),
`ill_formed_utf8_bytes` (A4, raw invalid UTF-8), `lone_surrogate_escape` (A4,
well-formed bytes containing `\ud800`), `integer_out_of_range` (A5, `entry_count`
of `2^53`), `seq_skip` (B1), `stream_recommitted_same_epoch` (B3),
`tip_rollback_same_epoch` (B3), `genesis_wrong_seq` and `genesis_wrong_prev_hash`.

A4 needs **two** vectors because the failure modes differ: invalid UTF-8 bytes
must be caught by an explicit `utf8.Valid` check on the raw input, while a lone
surrogate *escape* is well-formed UTF-8 that both parsers accept and mangle
differently — and after parsing, Go cannot distinguish a decoded lone surrogate
from a literal U+FFFD. **A4 is therefore specified as an explicit validation step
on raw bytes before parsing, never as an emergent property of the JSON stack.**
That assumption's absence is exactly defect 2.

**New positives:** a non-BMP `stream_id` adjacent to a U+E000–U+FFFF one (the tip
sort is code-point ascending, while JCS sorts *object keys* by UTF-16 code unit;
surrogates sort below U+E000 in UTF-16 and above it by code point, so an
implementer reusing their JCS comparator for tips gets a different order), one at
`2^53−1`, and the two must-accept advisory vectors from §6.

**Timestamp profile:** exactly `YYYY-MM-DDTHH:MM:SSZ` — uppercase `T` and `Z`, no
fractional seconds, no numeric offset, no leap seconds. This matches production's
`ts.UTC().Format(time.RFC3339)` byte for byte. It is a **producer** rule:
verifiers treat the timestamp as an opaque signed string and do not enforce the
profile, so there is no negative vector for it. The hole it closes is two
producers rendering the same instant differently.

**Surface to the SIG:** OTel's native timestamp is `uint64` nanoseconds, and
current unix nanoseconds (~1.7×10^18) exceed I-JSON's `2^53−1`. Nanoseconds as a
JSON integer are therefore incompatible with JCS. This constrains the audit
record format regardless of checkpoints, and nobody in #2409 has raised it.

`py/requirements.txt` pins `cryptography`.

## 8. Sequencing

1. `format_version` + `min_format_version` skip rule, pinned `cryptography`,
   pinned timestamp profile
2. A3 + `duplicate_stream_epoch_in_checkpoint`. `gen` rejects duplicate
   `(stream_id, epoch)` **before signing**, so malformed input fails loudly
   rather than silently producing order-dependent bytes; `sort.SliceStable` is
   used so the ordering is defined even if A3 is ever bypassed.
3. Tier B in both validators, with the epoch resolution from §3, plus the B1/B3
   negatives and the B4/B5 must-accept vectors
4. `input_raw_hex` + both A4 vectors, README paragraph citing #50079
5. Remaining boundary positives and genesis negatives
6. `docs/limits.md`; README corrected from snapshot to delta

The epoch resolution in §3 is settled **in this document** before step 3 is
implemented, because CONTRIBUTING freezes published vectors and a Tier B vector
shipped under the wrong identity rule would have to be superseded rather than
corrected.

**Gate for linking this repo from `open-telemetry/community#2409`:** steps 1–3
merged to `main` **and** both validators green on the new suite in CI. Until
then the repo would not survive the scrutiny it is modelled on. Twelve days of
thread silence is normal SIG cadence and is not a reason to post early; if
presence is needed sooner, a concept-only comment on delta-checkpoint semantics
without the link is the compromise. Posting upstream is the human's action.
