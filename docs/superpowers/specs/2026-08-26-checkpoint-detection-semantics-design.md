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
knows its own generation.

Four rules make the scheme sound. All four are necessary; omitting any one
reintroduces the false-positive class this resolution exists to remove.

**R1 — Stamped at `AddTip`, never at `Build`.** The epoch current when a tip is
added is the epoch recorded on that tip. Build-time stamping is unsound:
compaction runs after every seal while the default checkpoint interval is 100
seals, so one pending set spans roughly 100 generations. A stream sealed in
generation *g* and re-delivered in *g+2* can have both tips pending in the same
`Build`; stamping at Build gives them the same epoch, a different `tip_hash`, and
a false hard reject. Stamping at `AddTip` gives them distinct epochs and the
correct advisory outcome.

**R2 — Bump before clear.** The generation increment and the dedup-map reset must
be atomic with respect to sealing, and if they cannot be, the bump must happen
first. A seal landing between a clear and a later bump sees a cleared map with
the old generation, which is precisely a same-epoch duplicate.

**R3 — Generation recovery on restart: `max(epoch) in the last valid checkpoint,
plus one`.** An in-memory counter reset to zero on start would let a stream
committed at epoch 5 in a previous run collide with a fresh epoch 5 — the
original defect reborn. Recovery from the log is sufficient and needs no new
persistence: epochs are monotonic at `AddTip` time and every tip in checkpoint
*N+1* was added after `Build(N)`, so the chain-wide maximum always lies in the
last checkpoint. The existing `readLastCheckpoint` path already recovers `seq`
and `prev_hash` and can carry this.
**Epochs need not be contiguous.** `readLastCheckpoint` skips corrupt lines, so a
torn final line recovers an older checkpoint and a lower maximum; any recovery
ambiguity must be resolved by over-bumping. A gap in epoch values is harmless; a
reuse is not.

**R4 — The sort key is `(stream_id, epoch)`, not `stream_id`.** Two tips for the
same stream with different epochs in one checkpoint are legal under this design
and occur in the `advisory_stream_recommitted_new_epoch` vector. Sorting on
`stream_id` alone lets equal keys reach the sort, and a stable sort then makes
the canonical bytes depend on input order — defect 3 of §1, reintroduced.

Given R1–R4:

- Same `(stream_id, epoch)` → **hard reject**, whether or not the tips differ.
  Within one generation the dedup map is intact, so no second commit of any kind
  can occur legitimately; a byte-identical replay lands in a new generation.
- Same `stream_id`, different `epoch` → **accepted, surfaced as advisory.** The
  declared at-least-once path, handled as `duplicate_trace_segment` is today.

**Dependency and sequencing.** R1–R3 require a change in `otel-agent-audit`:
`chain.Accumulator` gains a generation field, bumped by the compaction and start
paths, recovered per R3. That is a chain-format change there and carries that
project's `schema_version` bump, fixture and doc requirements. **This repo does
not wait for it.** This repo is the proposal artifact; the dependency is on the
design being settled here, which this document does, not on production landing
first.

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
| B1 | `seq` increments by exactly 1, at **every** transition of the assembled chain | dropped or replayed checkpoint | hard |
| B2 | `prev_hash` equals SHA-256 of the previous checkpoint's canonical bytes, at **every** transition of the assembled chain including between prefixes | reordering, forking | hard |
| B3 | `(stream_id, epoch)` appears at most once in the chain | re-commit within a generation; **same-epoch** rollback | hard |
| B4 | A stream's `epoch` differs from its previous committed `epoch` (same checkpoint or an earlier one), in **either direction** | at-least-once re-delivery; **cross-epoch** rollback | **advisory** |
| B5 | `timestamp` non-decreasing against the **immediate predecessor**, at every transition | clock regression | **advisory** — the operator controls the clock |

B4 fires on an epoch **difference**, not an increase: a stream re-committed
under an older generation is the most rollback-shaped case B4 exists to surface,
and B3 does not cover it, since `(s, 5)` and `(s, 3)` are distinct identities.

B4 is defined **per transition**, not per checkpoint pair. Two commits of one
stream at different epochs raise it whether they land in the same checkpoint or
in two, because the operational fact reported — the producer's generation
changed between those commits — is identical either way; scoping it to chains
would make the warning depend on the producer's batching, which is exactly the
input-shape dependence this design removes. It is emitted once per transition,
so a stream committed at three epochs in one checkpoint yields two identical
`B4:<stream_id>` tokens.

Because warnings are compared as ordered lists, tips are walked in
`(stream_id, epoch)` order rather than input order: a checkpoint's tips may
arrive unsorted, and an input-order walk would let that order decide the
sequence of `B4` tokens when two different streams each change epoch.

That ordered comparison is a stated requirement of a conformant validator, not
one the published vectors mechanically enforce. For every `expect_warnings`
vector in the suite, the warnings a correct validator emits are already in the
expected order — that is what makes the vector correct — so a validator that
compares warnings as an unordered multiset also passes the entire suite. No
vector can force the ordered comparison; it has to be stated as a requirement,
same as here.

A cross-epoch re-commit carrying a lower `entry_count` is advisory, not a hard
reject. That is not a detection regression: forging a cross-epoch checkpoint
requires the signing key, which is Tier C territory, and an honest timeout-split
produces exactly that shape.

**Every B rule holds at every chain index and every tip index, and that is a
separate claim from the rules themselves — but it is narrower than "every
position."** Pinned: the chain index (every transition of a multi-checkpoint
chain, and all ordered index pairs for the identity-uniqueness rule, B3) and
the tip index (interior tips, not only first or last). A validator that applies
a rule at exactly one position computes correct bytes and rejects everything a
one- or two-prefix chain, or a one- or two-tip checkpoint, can express; collapse
either axis and it passes. The suite therefore carries four-checkpoint vectors
whose single defect sits in the **middle**, one whose defect is on the
**final** link of a chain that reaches Tier B (a vector's `prev_sha256` field
pins only that last link, and only for chainless vectors), three-tip
checkpoints whose defect sits on the **interior** tip, an epoch defect on a
chain carrier's **own** input, and prefixes supplied **out of order**.
Alongside them, both test suites are table-driven over position: for each rule
the defect is injected at every chain index, every tip index, every tip-index
pair and every warning-list index in turn. Because rules cannot fix a harness
that skips entries, both validators additionally count what they actually
reached and fail if it disagrees with an independent pre-pass over the suite.

Not pinned, and worth stating rather than leaving implicit: every chain in the
suite starts at `seq: 1`, so a validator that compares `seq` against its
position in the `chain` array rather than its absolute value is
indistinguishable from a correct one on every vector here; no zero-tip
checkpoint appears as a `chain` prefix (`genesis_empty_tips` supplies one only
as a vector's own input); every `stream_id` in the suite is a 36-character
UUID, so no vector compares two of different lengths and a validator that sorts
by length before code point is indistinguishable from a correct one here; and
an unknown member on a checkpoint, a tip, a
chain prefix or a prefix wrapper is rejected by both references — each by an
explicit member-set rule, Go's decoder and Python's declared sets — but the two
report it differently, so no vector can express it; the same is true of a
wrong-typed scalar (`"epoch": "1"`, `true`, `1.0`) and of a null `tips`
element, which both references reject and neither can publish. These are gaps in what the suite currently constrains,
not defects in the rules.

The tip-identity key is compared as a pair — a comparable struct in Go, a tuple
in Python — rather than flattened into a single string, so the published sort
rule holds for any `stream_id` rather than only for ones that avoid the
separator byte a flattened encoding would need. Unit tests in both references
hold the two orderings no published vector separates: `a` against `a<NUL>`,
which a NUL-separated flattened key gets backwards, and `aa` against `b`, which
a length-before-code-point comparator gets backwards.

The two orderings belonging to the verifier's contract rather than to any
single rule — the order of the warning list it reports and the order of the
`chain` array it was handed — are checked the same way by this repo's own
position-generic tests. The warning-order case has a narrower guarantee at the
level of the published vectors themselves: see the paragraph above on
`expect_warnings`, and the README's "Warning ordering is a stated requirement,
not a vector-enforced one" section.

B2 hashes the previous checkpoint's **canonical** bytes, not the bytes as
received. A checkpoint's tips are explicitly allowed to arrive unsorted, so a
validator that canonicalized without first imposing the tip order would compute
a different digest and reject a legitimate chain; the suite carries a chain
prefix supplying its tips out of identity order to pin this.

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
   Note what this does *not* do: it cannot protect a harness written against
   today's published file, which ignores the unknown field and still crashes on
   a missing `input` or hard-fails a `chain` negative. Nothing in-file can. The
   actual sufficiency argument is sequencing — the skip rule lands in step 1 and
   the §8 linking gate means the repo gains visibility only after steps 1–3, so
   the population of pre-rule consumers is effectively zero.
3. **Chain context for Tier B**, on negatives **and positives** (the advisory
   must-accept vectors need it too). An optional ordered `chain` array of
   preceding checkpoints. **A validator MUST verify the signature of every
   checkpoint in the prefix, not merely hash it for linkage.** The reason is
   deployed-verifier parity, not fixture trust — the prefix here is trusted test
   data, but the vector should exercise the behaviour wanted in a production
   verifier. Stated explicitly because either answer is defensible and silence
   guarantees divergence.
4. **`expect_warnings`** on positives, naming the advisory conditions a verifier
   is expected to surface. Without it a must-accept vector tests nothing beyond a
   plain positive, because a validator that silently accepts passes. A
   warning-taxonomy mismatch warns rather than fails, on the same reasoning as
   `expect` below.
5. **`input_raw_hex`.** `input` is a typed object round-tripped through each
   language's JSON parser, so encoding-level malformations are inexpressible.
   When `input_raw_hex` is present it is the exact bytes to canonicalize, and
   `input` is absent.
6. **`expect` becomes advisory for third parties.** `rejectReason` fixes an
   order — schema, canonical, signature, Tier B, chain — that a conformant
   validator need not share, so a validator checking in another order can
   report a different reason on a vector that fails more than one check. Not
   every negative fails exactly one: `duplicate_tip_identity` ships with an
   empty signature and fails both the canonical and the signature check,
   reporting `canonical` only because that check runs first. What the generator
   asserts at `gen` time, in `checkNegativeExpectations`, is the invariant that
   can be mechanically held: **every negative is rejected for exactly the
   reason its `expect` field names, under this reference's check order**, so a
   vector whose `expect` is wrong can never be published.
7. **Surface to the SIG, not fixed here:** the signed object carries no version
   field *inside the signed bytes*. Production gets this right —
   `schema_version` is inside `checkpointForSigning`. `format_version` versions
   the file, not the object, so a future canonical-form change is
   indistinguishable inside a signature.

### 5a. `epoch` is a breaking change *in this repo*, and its own rules apply

§3 tracks the production repo's `schema_version` obligation. This repo has one
too, and the earlier draft ignored it. Adding `epoch` changes the tip field set,
which CONTRIBUTING defines as a breaking vector change.

The divergence this would otherwise cause is concrete: a typed Go validator
unmarshals `input` into a struct with no `Epoch` field, silently drops it, and
fails on canonical mismatch, while a dict-based Python validator carries the
field through and passes. The two implementations disagree on the new vectors
for any consumer that has not implemented the skip rule.

Therefore:

- The six existing vectors are **retained unchanged** under `format_version: 1`.
- The first epoch-bearing vector bumps the file to **`format_version: 2`** and
  carries `min_format_version: 2`. This bump is co-located with that vector, in
  step 3 — not with step 1.
- **An absent `epoch` is valid only in `format_version: 1` vectors.** In version
  2 and above it is required on every tip.
- A README note records what changed and why, per CONTRIBUTING.

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

**New negatives:** `duplicate_tip_identity` (A3),
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

**A4 needs a positive too.** A raw-text scan for lone surrogate escapes must
still accept a *valid* surrogate pair, and must handle `\\u` and case variants.
Without `valid_surrogate_pair` — a raw-hex **positive** containing
`\ud83d\ude00` — an implementation passes the suite by rejecting every `\ud`
escape, which is over-rejection: the exact class §6 now says the suite guards
against.

**New positives:** `valid_surrogate_pair` (above), a non-BMP `stream_id` adjacent to a U+E000–U+FFFF one (the tip
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
A second argument for the profile, beyond determinism: profile strings sort
chronologically, so B5 reduces to a lexicographic string comparison and the
advisory check needs no timestamp parsing at all.

**Surface to the SIG:** OTel's native timestamp is `uint64` nanoseconds, and
current unix nanoseconds (~1.7×10^18) exceed I-JSON's `2^53−1`. Nanoseconds as a
JSON integer are therefore incompatible with JCS. This constrains the audit
record format regardless of checkpoints, and nobody in #2409 has raised it.

`py/requirements.txt` pins `cryptography`.

## 8. Sequencing

1. `format_version` + `min_format_version` skip rule, pinned `cryptography`,
   pinned timestamp profile
2. A3 + `duplicate_tip_identity`. `gen` rejects a duplicate
   `(stream_id, epoch)` **before signing**, so malformed input fails loudly
   rather than silently producing order-dependent bytes. Note that A3 forbids
   duplicate *pairs*, not duplicate `stream_id`s — repeated stream ids are legal
   across epochs — so ties genuinely can reach the sort and the R4 composite sort
   key, not a stable sort, is what makes the ordering total.
3. Tier B in both validators, with R1–R4 from §3, plus the B1/B3 negatives and
   the B4/B5 must-accept vectors. **This step bumps the file to
   `format_version: 2`** per §5a; the six existing vectors stay at version 1.
4. `input_raw_hex` + both A4 vectors, README paragraph citing #50079
5. Remaining boundary positives and genesis negatives
6. `docs/limits.md`; README corrected from snapshot to delta

R1–R4 are settled **in this document** before step 3 is implemented, because
CONTRIBUTING freezes published vectors and a Tier B vector shipped under the
wrong identity rule would have to be superseded rather than corrected. R3 in
particular: an epoch scheme shipped without the generation-recovery rule
contains the same false-positive class the epoch was introduced to remove.

**Gate for linking this repo from `open-telemetry/community#2409`:** steps 1–3
merged to `main` **and** both validators green on the new suite in CI. Until
then the repo would not survive the scrutiny it is modelled on. Twelve days of
thread silence is normal SIG cadence and is not a reason to post early; if
presence is needed sooner, a concept-only comment on delta-checkpoint semantics
without the link is the compromise. Posting upstream is the human's action.
