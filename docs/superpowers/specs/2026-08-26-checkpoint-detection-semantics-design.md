# Design: checkpoint detection semantics

> **Status:** Approved · **Date:** 2026-08-26 · **Author:** Surabhi Pradhan

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
reference implementation in `otel-agent-audit` is a **delta** model —
`chain.Accumulator.Build` resets the pending set after each checkpoint. The
README's claim that "disappearance becomes detectable" overstates what a delta
model provides.

## 2. Goals and non-goals

**Goal.** Make the repo demonstrate the detection semantics that justify a
checkpoint construct, at a rigor level that survives the differential scrutiny
applied to JCS libraries in #50079.

**Non-goals.**

- Competing on JCS string-level conformance. That ground is covered by
  `astrogilda/aee-conformance`; this repo will cite and link it.
- A third implementation. Two independent validators carry the argument.
- Fuzzing, property-based testing, differential JCS harnesses. Not worth the
  maintenance cost for a solo maintainer.
- Vectors for attacks the mechanism cannot detect. See §6.

## 3. The delta model, stated explicitly

Each checkpoint commits the tips of streams **sealed since the previous
checkpoint**, not all active streams. A checkpoint is a delta; the checkpoint
chain is the accumulation.

The load-bearing consequence: **a `stream_id` is committed at most once across
the whole chain.** ("Exactly once" is the producer's invariant; a verifier
holding a possibly-partial chain can only check "at most once", so that is the
rule stated in B3.) A stream is sealed once, committed once, and never
re-committed. That single invariant makes re-commit, rollback and replay
detectable from the checkpoint chain alone, with no access to stream records.

## 4. Taxonomy

### Tier A — per-checkpoint, stateless

| # | Property | Status |
|---|---|---|
| A1 | Canonical bytes reproduce | have (3 positives) |
| A2 | Signature verifies | have (`tampered_signature`) |
| A3 | No duplicate `stream_id` within a checkpoint | **add** |
| A4 | Ill-formed Unicode rejected | **add** |
| A5 | Integers within I-JSON range: `2^53−1` accepted, `2^53` rejected | **add** |

### Tier B — cross-checkpoint, single chain, single verifier

This tier is the checkpoint's reason to exist and is currently empty but for B2.

| # | Rule | Detects |
|---|---|---|
| B1 | `seq` increments by exactly 1 | dropped or replayed checkpoint |
| B2 | `prev_hash` equals SHA-256 of the previous checkpoint's canonical bytes | reordering, forking (have) |
| B3 | A `stream_id` appears in at most one checkpoint in the chain | re-commit, rollback, replay |
| B4 | `timestamp` non-decreasing across the chain | clock regression (advisory only — the operator controls the clock) |

### Tier C — beyond one verifier with one chain

Prose only, in `docs/limits.md`, linked to `otel-agent-audit/docs/threat-model.md` §2:

- **Split-view / equivocation.** Undetectable by a single verifier holding one
  chain. It is, however, *provable* across two views: two checkpoints with the
  same `seq` under the same key and different hashes form a self-contained
  equivocation proof, the same object CT uses for inconsistent STHs. This is the
  argument for the checkpoint being the right unit for a witness to gossip.
- **Full rewrite by the key holder**, served consistently to everyone.
  Undetectable without external anchoring.
- **Staleness** — serving a valid old prefix. Currently undetectable; a maximum
  checkpoint interval plus a timestamp check would convert it into a detectable
  violation, as TUF does with expiry. Surface this to the SIG as a design
  decision rather than a fixed limit.
- **Never-committed streams.** Checkpoints attest what *was* committed. They do
  not prove that everything which occurred was committed. No log-side mechanism
  can. This is the correction to the README's "disappearance" claim.

## 5. Format changes

1. **`format_version`** on `Suite`, added now. Adding it later is itself a
   breaking change and third parties may already consume the file.
2. **Chain context for negatives.** Tier B cases require more than one
   checkpoint, so a negative vector gains an optional ordered `chain` array of
   preceding checkpoints. `prev_sha256` is retained for the existing
   `broken_chain` case.
3. **Raw input representation.** `input` is a typed object round-tripped through
   each language's JSON parser, so encoding-level malformations are
   inexpressible. Add optional `input_raw_hex`; when present it is the exact
   bytes to canonicalize, and the vector asserts rejection.
4. **`expect` becomes advisory.** `rejectReason` checks signature before chain,
   so a validator checking in a different order reports a different reason on a
   vector failing both. Today each negative fails exactly one check, so this
   works by accident. Document that as a suite invariant and treat a
   reason mismatch as a warning, not a failure.

## 6. Why there is no `limits` vector category

A vector whose expected outcome is "a conformant verifier accepts this" cannot
fail: acceptance of a valid chain is already established by the positive
vectors, so no implementation could fail such a vector without also failing
those. Undetectability is a claim quantified over all possible verifier
algorithms; no fixture tests it. Certificate Transparency, TUF, in-toto, SLSA
and C2PA all keep this class of statement in security-considerations prose.
Wycheproof's third `acceptable` tier works only because implementations
genuinely vary there, which is not the case here.

Limits go in `docs/limits.md`. The one machine-checkable artifact in this area
is the equivocation proof, and it is deferred until the OTEP has a witness
section — before that it is speculative.

## 7. Testing

Both validators implement Tiers A and B and must agree. New negatives:
`duplicate_stream_id`, `ill_formed_utf8` (via `input_raw_hex`), `seq_skip`,
`stream_recommitted` (B3), `tip_rollback` (B3 with a lower `entry_count`), and
`integer_out_of_range` (A5, an `entry_count` of 2^53).
New positives: non-BMP `stream_id` adjacent to a U+E000–U+FFFF one (the tip sort
is code-point ascending, while JCS sorts *object keys* by UTF-16 code unit — an
implementer reusing their JCS comparator for tips gets a different order), and
one at 2^53−1.

`timestamp` is pinned to `YYYY-MM-DDTHH:MM:SSZ` — no fractional seconds, no
numeric offsets — so that a re-serializing implementation cannot alter signed
bytes. `py/requirements.txt` pins `cryptography`.

## 8. Sequencing

1. `format_version`, pinned `cryptography`, pinned timestamp profile
2. A3 + deterministic sort + `duplicate_stream_id`. A3 rejects duplicates, so
   ties cannot reach the sort in a valid checkpoint; the generator still uses
   `sort.SliceStable` so that malformed input fails loudly at A3 rather than
   silently producing order-dependent bytes.
3. Tier B in both validators + `seq_skip`, `stream_recommitted`, `tip_rollback`
4. `input_raw_hex` + `ill_formed_utf8`, README paragraph citing #50079
5. Boundary positives
6. `docs/limits.md`, README corrected from snapshot to delta

Steps 1–3 are the substance. Do not link this repo from
`open-telemetry/community#2409` until at least step 3 has landed: until then the
repo would not survive the scrutiny it is modelled on.
