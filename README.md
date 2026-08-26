# audit-checkpoint conformance vectors

Reproducible test vectors for the canonical form of a signed **audit checkpoint**
(the cross-stream completeness structure sketched for the OpenTelemetry Audit
Logging effort). Two independent implementations agree byte-for-byte on the
canonical bytes, the SHA-256 chain hash, and the Ed25519 signatures.

## Why a checkpoint

Per-record chaining (`prev_hash` plus a monotonic sequence number) makes a single
stream tamper-evident: you cannot edit or reorder a record inside it without
breaking the chain. What it cannot do is attest to an **absence**. Nothing inside
a stream can tell you that the stream was truncated at the tail, or that a whole
stream stopped arriving and was never seen at all.

A checkpoint is a small signed object that periodically commits the tips of every
active stream, chained to the previous checkpoint. Truncation and disappearance
become detectable, because a tip a checkpoint has committed cannot be edited
without re-signing it.

Field names below are **placeholders** aligned to the sketch; they map to
whatever the OTEP settles on. The point of this repo is to show the shape is
concrete, deterministic, and independently verifiable, not to fix a vocabulary.

## Suite format

`vectors.json` carries a `format_version` (integer, currently **2**). Individual
vectors may carry `min_format_version`.

**Validators MUST skip, with a warning, any vector whose `min_format_version`
exceeds the version they support, and MUST NOT treat a skip as a failure.**
This is what allows new vector shapes to be added without breaking existing
validators.

**Version 2 changed no previously published bytes.** Every version-1 vector's
`input`, `canonical`, `sha256` and `signature` is byte-identical to what was on
`main` before the bump; the only change to an existing line is the suite-level
`format_version` itself. `epoch` is omitted (not emitted as `0`) when absent, so
re-canonicalizing a version-1 checkpoint reproduces its original bytes exactly.

Version 2 adds `epoch` (see below) and the cross-checkpoint rules. Two further
optional fields appear on vectors that exercise them:

- `chain` — the preceding, already-signed checkpoints this vector's
  cross-checkpoint rules are evaluated against. A validator MUST verify each
  prefix signature and each prefix's `epoch` boundary, not merely hash the
  prefix for linkage — a verifier that skipped this would accept a forged
  history. The `tampered_prefix_signature` and `chain_prefix_missing_epoch`
  negatives exist so that skipping it is detectable from outside.
- `expect_warnings` — on a **positive** vector, the advisory conditions a
  verifier must surface while still accepting the checkpoint. Warning tokens
  are stable, machine-comparable strings (`B4:<stream_id>`, `B5:<seq>`) so the
  two implementations can be checked for agreement rather than eyeballed.
  Without this an advisory rule is untestable: a validator that silently
  accepts would pass a must-accept vector without ever running the rule.

## Canonical form

A checkpoint is a JSON object:

| Field | Type | Notes |
|-------|------|-------|
| `prev_hash` | string | Hex SHA-256 of the previous checkpoint's canonical bytes. The first checkpoint uses the SHA-256 of the empty string (`e3b0c442…b855`). |
| `seq` | integer | Monotonic checkpoint sequence, starting at 1. |
| `timestamp` | string | Exactly `YYYY-MM-DDTHH:MM:SSZ`: uppercase `T` and `Z`, no fractional seconds, no numeric offset, no leap seconds. This is a producer rule; verifiers treat it as an opaque signed string. Profile strings sort chronologically, so an ordering check needs no date parsing. |
| `tips` | array | One entry per stream committed by this checkpoint. |

Each `tips` entry:

| Field | Type | Notes |
|-------|------|-------|
| `stream_id` | string | The stream (per-trace chain, in `otel-agent-audit`). |
| `epoch` | integer | Producer *generation* counter, not a per-stream commit count. Incremented whenever the producer's dedup window resets. `(stream_id, epoch)` is the tip's unique identity. **Non-negative.** Required at `format_version` 2 and above; absent in version-1 vectors. |
| `sequence_number` | integer | The stream's highest committed sequence number. |
| `tip_hash` | string | Hex hash of the stream's tip (the `IntegrityHash` of its highest record). |
| `entry_count` | integer | Number of records in the stream so far (truncation shows up here too). |

### Why epoch exists

Under at-least-once delivery a stream can legitimately be committed twice — a
re-delivered record after the producer's dedup window has reset. Without a way
to tell that apart from a replay, a rule rejecting repeated stream ids would
flag honest behaviour. The epoch makes the difference explicit: the same
`(stream_id, epoch)` twice is a hard reject, while the same stream under a new
epoch is the declared at-least-once path, accepted with a `B4` warning.

The epoch is a producer generation counter rather than a per-stream count
because after a dedup reset the producer has forgotten the stream and cannot
count its prior commits — it always knows its own generation. See spec §3
R1–R4 for the rules a conformant producer must follow, including the
generation-recovery rule that keeps epochs from being reused after a restart.

Version-1 vectors predate the field and carry no `epoch` key; they are retained
byte-identical. A tip missing `epoch` in a version-2 vector is rejected, not
defaulted — see the `missing_epoch_in_v2` vector.

**Rules an implementation must follow to reproduce the bytes:**

1. **Tip order.** `tips` MUST be sorted before canonicalization by the composite
   key `(stream_id, epoch)` — `stream_id` ascending by Unicode code point, then
   `epoch` ascending numerically. JCS fixes object-key order but preserves array
   order, so the producer imposes the tip order. The key is composite because
   two tips for one stream at different epochs are legal in a single checkpoint;
   sorting on `stream_id` alone would let input order leak into the signed bytes.
   Two tips sharing a `(stream_id, epoch)` identity are rejected outright rather
   than sorted arbitrarily.

   `epoch` sorts **numerically**, not as text: epoch 2 precedes epoch 10. An
   implementation that compares the epoch as a string puts 10 before 2 and
   silently disagrees with a conformant one on the signed bytes. The
   `multi_epoch_same_stream` vector publishes exactly that pair, in an input
   order the sort has to fix, so the disagreement cannot go unnoticed.

   A negative `epoch` is **rejected**, not ordered: signed-integer sort keys
   differ between implementations at the sign boundary, and no conformant
   producer emits one. See the `negative_epoch` vector.
2. **Canonicalization.** RFC 8785 (JCS) over the checkpoint object. The schema is
   strings and integers only (no floats), so JCS reduces to sorted keys, compact
   separators, UTF-8, and standard JSON string escaping. Integrity/signature
   fields are NOT part of the canonical object.
3. **Chain hash.** SHA-256 over the canonical bytes, hex-encoded. The next
   checkpoint's `prev_hash` MUST equal it.
4. **Signature.** Ed25519 over the canonical bytes. Ed25519 is deterministic, so
   a correct implementation reproduces the exact signature bytes in the vectors.

## Negative vectors (a conformant validator MUST reject these)

Positive vectors prove an implementation computes the same bytes. Negative
vectors prove it actually enforces the rules. Each is rejected for the reason in
its `expect` field:

- `tampered_signature` — one byte of a valid signature is flipped. Rejected: signature.
- `truncation_rewrites_committed_tip` — a stream is truncated (`entry_count` 7 to 5)
  and the checkpoint tip is rewritten to match, but the original signature is kept.
  The signature no longer covers the mutated tip. Rejected: signature. This is the
  checkpoint's defence against a silently truncated stream: a committed tip cannot
  be edited without re-signing, and the signing key is not the operator's to use
  freely on honest infrastructure.
- `broken_chain` — a valid, correctly signed checkpoint whose `prev_hash` does not
  equal the previous checkpoint's hash. Rejected: chain.
- `duplicate_tip_identity` — two tips share a `(stream_id, epoch)` identity, so the
  canonical bytes would depend on input order. Rejected: canonical, before any
  signature check.
- `stream_recommitted_same_epoch` — a stream committed twice under the same epoch.
  Within one producer generation the dedup map is intact, so no second commit of
  any kind is legitimate. Rejected: tier_b (B3).
- `tip_rollback_same_epoch` — the committed tip regresses (`entry_count` 7 to 5)
  under the same epoch: a rollback inside one generation. Rejected: tier_b (B3).
- `seq_skip` — checkpoint `seq` jumps from 1 to 3. Rejected: tier_b (B1).
- `missing_epoch_in_v2` — a version-2 tip with no `epoch` key. Rejected: schema,
  not silently defaulted to epoch 0. The offending tip is deliberately not the
  first, so a check that inspects only the first tip fails this vector.
- `tampered_prefix_signature` — one byte of a **chain prefix's** signature is
  flipped. The vector's own input is valid and passes every cross-checkpoint
  rule, so the only thing that rejects it is actually verifying the prefix
  signature. Rejected: signature.
- `chain_prefix_missing_epoch` — the *second* prefix of a two-prefix chain omits
  `epoch` at version 2. Left unchecked it would be read as epoch 0 and feed the
  B3 identity and B4 comparisons; putting the defect at index 1 also catches a
  validator that epoch-checks only `chain[0]`. Rejected: schema.
- `tampered_second_prefix_signature` — a **two-prefix** chain whose *second*
  prefix has a flipped signature byte. Every other chain in the suite has one
  prefix, so this is what catches a validator that verifies only `chain[0]`.
  Rejected: signature.
- `chain_prefix_broken_link` — a two-prefix chain whose *second prefix* does not
  hash-link to the first. Every checkpoint is correctly signed and the vector's
  own `prev_hash` is right, so only a B2 check across the assembled chain
  rejects it. Rejected: tier_b.
- `seq_skip_after_first_transition` — `seq` jumps from 2 to 4 at the chain's
  *second* transition, catching a validator that checks B1 only between
  `chain[0]` and `chain[1]`. Rejected: tier_b.
- `negative_epoch` — a tip with `epoch: -1` (again not the first tip).
  Rejected: schema.

The six below all carry a **four-checkpoint** chain (three prefixes), so that
*first*, *middle* and *last* are three distinct positions — see
[Rules hold at every position](#rules-hold-at-every-position).

- `tampered_middle_prefix_signature` — the *middle* prefix of a three-prefix
  chain has a flipped signature byte. `tampered_prefix_signature` puts the
  defect on a chain's only prefix and `tampered_second_prefix_signature` on its
  last, so a validator that verifies only the last prefix passes both and fails
  this. Rejected: signature.
- `middle_chain_prefix_missing_epoch` — the *middle* prefix omits `epoch` at
  version 2, with the first and last prefixes clean. Rejected: schema.
- `middle_chain_link_broken` — B2 broken at the *middle* transition, with the
  first and last links both correct. Rejected: tier_b.
- `final_chain_link_broken` — the vector's own `prev_hash` does not equal its
  last prefix's hash, with all three prefixes linking correctly. `broken_chain`
  reaches a bad final link through the separate `prev_sha256` field and carries
  no `chain`, so this is the only vector that pins B2 at the last transition of
  a chain that actually reaches the cross-checkpoint rules. Rejected: tier_b.
- `seq_skip_at_middle_transition` — `seq` runs 1, 2, 4, 5: the gap is at the
  *middle* transition and the first and last transitions are both contiguous.
  Rejected: tier_b (B1).
- `stream_recommitted_between_prefixes` — the same `(stream_id, epoch)` is
  committed by the second and third *prefixes*, with the vector's own input
  clean. A validator that only compares its input against `chain[0]` accepts
  this. Rejected: tier_b (B3).

## Cross-checkpoint rules

Everything above judges one checkpoint (against its signature, or its immediate
`prev_hash`). These rules judge a checkpoint **against the chain that precedes
it**, and are what make a rollback detectable at all. Vectors exercising them
carry a `chain` field.

| Rule | Condition | Outcome |
|------|-----------|---------|
| B1 | `seq` must increment by exactly 1 | reject (`tier_b`) |
| B2 | `prev_hash` must equal the previous checkpoint's hash | reject (`tier_b`) |
| B3 | the same `(stream_id, epoch)` must not be committed twice | reject (`tier_b`) |
| B4 | a stream's `epoch` differs from its previous committed `epoch`, **in either direction** | accept, warn `B4:<stream_id>` |
| B5 | `timestamp` regresses against the previous checkpoint | accept, warn `B5:<seq>` |

B1 and B2 are checked at **every** transition of the assembled chain, not just
the last one. B2 in particular is easy to under-apply: a vector's `prev_sha256`
field pins only the vector's own link, so a chain whose *prefixes* do not
hash-link would otherwise be accepted — a forged history behind a correct final
link. See `chain_prefix_broken_link` and `seq_skip_after_first_transition`.

B4 fires on an epoch **difference**, not an increase. A stream re-committed
under an *older* generation is the most rollback-shaped case B4 exists to
surface, and B3 does not cover it: `(s, 5)` and `(s, 3)` are distinct identities
and pass. See `advisory_epoch_regression`.

B4 is defined **per transition**, not per checkpoint pair: it fires whenever a
stream's `epoch` differs from its previous committed `epoch`, whether that
previous commit is in the same checkpoint or an earlier one. The operational
fact it reports — this stream's producer generation changed between two commits,
so an `entry_count` regression is an at-least-once artefact rather than a
rollback — is identical either way, and scoping it to chains would make an
operator's warning depend on how the producer batched its commits.

It follows that B4 is emitted **once per transition**. One stream committed at
three epochs in a single checkpoint makes two transitions and yields two
identical `B4:<stream_id>` tokens — see `multi_epoch_same_stream`.

B4 and B5 are advisory on purpose. B4 is the declared at-least-once path: an
honest timeout-split produces exactly that shape, including an `entry_count`
that goes backwards, so rejecting it would flag correct producers. B5 is a clock
observation, and clocks move; the checkpoint `seq` (B1), not the timestamp, is
the ordering authority. Both are asserted by must-accept vectors carrying
`expect_warnings`, so a validator that silently swallows them fails the suite.

B5 is a plain string comparison — the pinned `YYYY-MM-DDTHH:MM:SSZ` profile
sorts chronologically, so no date parsing is needed.

Warnings are compared **element-wise and in order**, so when one checkpoint
raises both, the interleaving is part of the contract: B4 (raised per tip, in
tip-identity order) precedes B5 (raised once per checkpoint). The
`advisory_new_epoch_and_timestamp_regression` vector pins that pair.

Tips are examined in `(stream_id, epoch)` order rather than input order. This
matters because a checkpoint's `input.tips` are explicitly allowed to be
unsorted: when two different streams each change epoch in one checkpoint, an
input-order walk emits their `B4` tokens in whatever order the tips happened to
be supplied, so two conformant validators handed identical signed bytes could
report different warning sequences. The `advisory_two_streams_new_epoch` vector
supplies exactly that pair in non-identity order and pins the result.

### Rules hold at every position

Every rule above holds at **every** position of the assembled chain. That is a
separate claim from the rules themselves, and it needs its own coverage: a
validator that applies a rule at exactly one chain position — only the first
transition, only the last prefix — still computes correct bytes and still
rejects everything a short chain can express. With one or two prefixes,
"first", "middle" and "last" collapse into each other, so such a validator
passes.

Two things pin it:

- **Four-checkpoint vectors with the defect in the middle.** Listed above; a
  middle defect is missed by "only the first" and "only the last" alike.
  `advisory_middle_chain_unsorted_prefix_tips` is the must-accept counterpart:
  its `timestamp` regresses at the second *and* the final transition but not
  the first, and both regressed values are still above `chain[0]`'s, so a
  validator comparing against `chain[0]` rather than the immediate predecessor
  reports a warning sequence that does not match. Its `B4` tokens likewise fall
  at the middle and last transitions and not the first. Its second prefix also
  supplies its tips **out of identity order**: B2 hashes the previous
  checkpoint's *canonical* bytes, so the link still holds, and a validator that
  hashed the checkpoint as received would reject a legitimate chain.
- **Position-generic tests.** `go/positional_test.go` and the matching section
  of `py/test_validate.py` are table-driven over position: for each rule they
  inject the defect at every index of a five-checkpoint chain in turn and
  require the rule to fire each time. A vector can only pin the positions
  someone thought to write down; these fail for any position a validator omits.

Rules R1–R3 of the spec constrain the *producer* (how epochs are allocated and
recovered) rather than the verifier, and are documented rather than implemented
here; R4, the composite sort key, is enforced above.

## Test key (TEST ONLY — never use for anything real)

- Ed25519 seed: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- Public key: printed in `vectors.json` as `public_key_hex`.

## Reproduce

```bash
# Go: regenerate and self-check (full RFC 8785 via gowebpki/jcs)
cd go && go run . gen ../vectors.json && go run . validate ../vectors.json

# Python: independent re-derivation, shares no code with the Go side
python3 py/validate.py vectors.json
```

Both accept the positive vectors on identical canonical bytes, hashes, and
signatures, and reject every negative vector for the expected reason.

CI (`.github/workflows/ci.yml`) runs both validators on every push, plus a
no-drift check that `vectors.json` is exactly what the generator produces.

## Relationship to a running implementation

This is the mechanism `otel-agent-audit` runs in production, restated in the
Audit Logging vocabulary: signed checkpoints over sealed per-trace chain tips,
chained via `prev_checkpoint_hash`, committing `{trace_id, tip_hash, entry_count}`
in batches. The vectors here use JCS (the spec's canonicalization) rather than
that project's internal canonical form, so they drop straight into the OTEP.

## License

Apache-2.0.
