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

A checkpoint is a small signed object, chained to the previous checkpoint, that
periodically commits the tips of the streams sealed since then — a delta, not
a snapshot of every currently active stream. Truncation of an already-committed
tip becomes detectable, because it cannot be edited without re-signing the
checkpoint. A stream that stops arriving before any checkpoint ever commits it
stays undetectable: the same absence gap described above, which a checkpoint
closes only for streams it has actually attested to.

Field names below are **placeholders** aligned to the sketch; they map to
whatever the OTEP settles on. The point of this repo is to show the shape is
concrete, deterministic, and independently verifiable, not to fix a vocabulary.

## Suite format

`vectors.json` carries a `format_version` (integer, currently **3**). Individual
vectors may carry `min_format_version`.

**Validators MUST skip, with a warning, any vector whose `min_format_version`
exceeds the version they support, and MUST NOT treat a skip as a failure.**
This is what allows new vector shapes to be added without breaking existing
validators.

**The skip decision comes first — before any structural check, including the
unknown-member rule below.** A vector of a newer format is precisely one that
may carry members the reading validator has no schema for, so a validator that
rejects unknown members *before* deciding whether to skip fails the whole file
on the first future vector it meets and checks nothing in it, old vectors
included. Both references therefore read only `name` and `min_format_version`
off an entry to make the decision, and apply the member rules afterwards, to
the entries they will actually check. `testdata/future_format_fixture.json`
pins this in both languages: a version-3 vector and negative carrying
unrecognized members on the entry, the checkpoint, a tip and a chain-prefix
wrapper, alongside untouched version-1 and version-2 entries, which must be
skipped while everything else still validates.

`min_format_version` does double duty: besides gating whether a validator
skips the vector, it is also that vector's own self-declared schema version,
and it is what a validator checks the `epoch` field's presence against (see
"Why epoch exists" below). A vector that needs `epoch` but omits
`min_format_version` is read as version 1, where `epoch` is not permitted —
so a third party authoring a new vector must set `min_format_version`
explicitly, or get the confusing "epoch is not permitted in a format_version 1
vector" rather than the schema error they meant to trigger.

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

**Version 3 changed no previously published bytes** either, the same way
version 2 didn't: every earlier vector's fields are untouched, and the only
change to an existing line is `format_version` itself.

Version 3 adds one further optional field:

- `input_raw_hex` — when present, the exact hex-encoded bytes to validate and
  canonicalize, in place of `input`. A typed `input` object is round-tripped
  through each language's own JSON parser before a validator ever sees it, so
  it cannot express invalid UTF-8 at all — a parse would already have to
  succeed to populate a typed field, and invalid UTF-8 can't produce a string
  either language's JSON parser will accept. `input_raw_hex` exists so a
  vector pinning that specific malformation class can be published at all.

  **Encoding check (A4) runs over the whole file, once, before any JSON
  parsing — not only over `input_raw_hex` payloads.** A validator MUST run
  this check on the raw file bytes before attempting to parse them at all,
  in the same position both references do: the very first check, ahead of
  even the envelope/suite-level decode. The raw bytes must be
  valid UTF-8 outright, and no `\uXXXX` escape inside a string literal may
  encode a surrogate (U+D800–U+DFFF) that is not the correctly-ordered half of
  an adjacent pair — checked on the entire suite file's bytes, before either
  language's own JSON stack has even started running, not only within an
  `input_raw_hex` value. Before this whole-file check existed, an unpaired
  surrogate escape reaching a *typed* `input` field was handled
  inconsistently — Go's `encoding/json` silently substitutes U+FFFD and keeps
  parsing, while Python's `json.loads` keeps the literal (unencodable)
  surrogate, so the two references disagreed on such a checkpoint, through no
  check the spec actually named ([#36](https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/36),
  now closed by this check). Go cannot detect this class of malformation
  *after* its own decode at all: the substitution is irreversible, so the
  check has to run on raw bytes, before parsing, for every string in the
  file, not only inside `input_raw_hex`. No vector can pin this the same way
  `ill_formed_utf8_bytes`
  and `lone_surrogate_escape` (below) pin the `input_raw_hex` path specifically
  — a malformed escape anywhere in the file fails the whole file to load, the
  same way an unknown member does, so mirrored unit tests hold the property
  instead (see "Not pinned" below). `valid_surrogate_pair` is the must-accept
  positive without which an implementation could pass this suite by rejecting
  every `\ud` escape wholesale, which is over-rejection, not conformance — see
  "Positive vectors" below. `ill_formed_utf8_bytes` and `lone_surrogate_escape`
  are the `input_raw_hex`-specific negatives, `expect: encoding`.

  **This is not a hypothetical failure mode for the canonicalizer this repo
  itself depends on.**
  [astrogilda's differential corpus](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/50079#issuecomment-5374471203)
  (86 vectors, run against `gowebpki/jcs` at the pinned commit `1a4242a` —
  exactly v1.0.1, the version pinned here) reports that `gowebpki/jcs` accepts
  `"\ud800\ud800"`, a high surrogate followed by another high surrogate and
  not a valid pair, and silently substitutes U+FFFD rather than erroring — so
  that malformed input canonicalizes identically to any ordinary, legitimate
  string that happens to contain a real U+FFFD, and one signature covers both.
  Confirmed directly against the pinned version, not merely cited, and
  extended one step further: `"\udfff\udfff"` (a *low* surrogate repeated, an
  equally invalid, differently malformed pair) canonicalizes to the identical
  bytes too, showing this isn't specific to one bad escape value. A validator
  that trusted the library alone for encoding validity would accept a
  malformed record in place of a legitimate one, or either malformed record
  in place of the other; this is precisely the case A4's explicit, pre-parse
  byte-level check exists to close, ahead of any JCS or JSON-stack
  involvement. The corpus and the reference verifier astrogilda
  maintains for RFC 8785/7493 conformance more broadly are at
  [astrogilda/aee-conformance](https://github.com/astrogilda/aee-conformance).

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

**A member that is present and `null` is not an absent member.** `"epoch":
null` is rejected at every `format_version`, and so is `"tips": null` and a
null `tips` *element*. None is a hypothetical: a pointer- or Optional-typed
decoder reads a null epoch as "no epoch", which is legal at version 1 and a
silent epoch `0` in every identity and ordering comparison at version 2;
canonicalization normalizes a null `tips` to `[]`, so accepting it would let
one signature cover two distinct documents; and a null tips *element* decodes
into a tip of zero values under Go's usual `UnmarshalJSON(null)` convention.
The `null_epoch` and `null_tips` negatives pin the parts a vector can express
— see each vector's entry below for exactly which reading it discriminates —
and unit tests in both references hold the rest.

**An unknown member is rejected** anywhere in the document the validator
reads: on a checkpoint, on a tip, on a signed `chain` prefix, on the prefix
wrapper, on a vector or negative entry, and on the suite object itself. It is
bytes the signature does not cover: a struct-decoding validator that drops the
member re-canonicalizes the checkpoint *without* it and verifies a signature
over bytes that are not the ones on the wire — on a prefix, that is a forged
history the `prev_hash` linkage cannot see. Both references hold it as an
explicit rule: Go through its decoder's `DisallowUnknownFields`, Python through
a declared member set for each object in the schema. Neither leans on "the
signature breaks anyway" — that only rejects a member injected into an
*already-signed* document, and a forger re-signs.

Two boundaries on it, and both references draw them in the same place. The
rule covers the suite envelope and every **non-skipped** entry, not a skipped
one — see the skip rule above. And it is applied to a whole entry **before**
that entry is validated, not as one verdict among the others: a negative
vector's `reason` token is what its `expect` is compared against, so an
unknown member injected into a negative that was already going to be rejected
for the reason it names would otherwise be masked by that reason and the suite
would pass.
No published vector can express this — see [Not pinned](#rules-hold-at-every-position--what-that-does-and-does-not-cover).

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

   Both references compare the key **as a pair** — Go a comparable struct,
   Python a tuple — rather than flattening it into one string. A flattened
   encoding reproduces this rule only under an assumption about what a
   `stream_id` may contain; comparing the pair reproduces it unconditionally.

   A negative `epoch` is **rejected**, not ordered. No conformant producer
   emits one — `epoch` is a generation counter — and an implementation that
   builds a *text* sort key (the shape this rule already warns against) orders
   negative values inconsistently, so rejecting the value outright keeps the
   ambiguity off the wire entirely. See the `negative_epoch` vector.
2. **Canonicalization.** RFC 8785 (JCS) over the checkpoint object. The schema is
   strings and integers only (no floats), so JCS reduces to sorted keys, compact
   separators, UTF-8, and standard JSON string escaping. Integrity/signature
   fields are NOT part of the canonical object.
3. **Chain hash.** SHA-256 over the canonical bytes, hex-encoded. The next
   checkpoint's `prev_hash` MUST equal it.
4. **Signature.** Ed25519 over the canonical bytes. Ed25519 is deterministic, so
   a correct implementation reproduces the exact signature bytes in the vectors.

## Positive vectors (a conformant validator MUST accept these)

The 18 positive vectors, one line each:

- `genesis_empty_tips` — the first checkpoint of the positives' own hash
  chain, with an empty `tips` array.
- `single_tip` — the second checkpoint of that chain, one committed stream.
- `multi_tip_unsorted_input` — the third checkpoint, two tips supplied out of
  `stream_id` order, exercising the sort rule.
- `multi_epoch_same_stream` — one stream committed at three epochs across a
  chain: two (2, then 10) in the vector's own checkpoint, with a third (0)
  in its chain prefix; two B4 transitions — one cross-checkpoint (0→2) and
  one intra-checkpoint (2→10) — so the identical token is emitted twice.
  See "Why epoch exists" above.
- `stream_id_prefix_pair` — two tips, `"abc"` and `"abc-1"`, whose stream_ids
  stand in a proper prefix relationship, supplied out of sort order; proves
  the tip-identity comparator is prefix-free (see "Rules hold at every
  position" below).
- `non_bmp_and_pua_stream_id_order` — two tips, stream_ids U+E000 and U+10000
  (the first non-BMP code point), supplied in UTF-16-code-unit order rather
  than the published one. Code point order ranks U+E000 first; a comparator
  that instead reused UTF-16 code-unit order — the mistake this vector exists
  to catch, realistic for a port to a UTF-16-native language — would rank the
  non-BMP tip first instead, since its high surrogate is numerically below
  U+E000. Go's `strings.Compare` and Python's `str` comparison already agree
  with the code-point rule natively; this vector pins it against a wrong port
  rather than fixing anything here.
- `advisory_stream_recommitted_new_epoch` — the declared at-least-once path:
  a stream re-committed under a new epoch, accepted with one `B4` warning.
- `advisory_timestamp_regression` — a timestamp regression against the
  previous checkpoint, accepted with one `B5` warning.
- `advisory_new_epoch_and_timestamp_regression` — B4 and B5 raised by the
  *same* checkpoint; pins their relative order for a validator that compares
  warnings in order (see Warning ordering below).
- `advisory_two_streams_new_epoch` — two different streams each change epoch
  in one checkpoint, with tips supplied out of identity order; pins the B4
  token order for a validator that compares warnings in order.
- `advisory_chain_b5_then_b4` — a three-checkpoint chain raising B5 then B4,
  whose expected warning list is deliberately not in sorted order.
- `advisory_epoch_regression` — a stream re-committed under an *older* epoch,
  the rollback-shaped case B4 exists to catch and B3 does not.
- `mid_chain_window_no_genesis` — a chain prefix that opens at `seq: 400`
  instead of 1, with an arbitrary `prev_hash` standing in for a checkpoint the
  verifier never saw; proves B1 checks `seq`'s relative delta, not its
  position in the `chain` array (see "Rules hold at every position" below).
- `mid_chain_zero_tip_checkpoint` — a three-checkpoint chain whose *middle*
  checkpoint has an empty `tips` array; proves a zero-tip checkpoint is
  accepted, and that B1/B2 hold on both transitions around it, when it is a
  `chain` prefix rather than a vector's own input (see "Rules hold at every
  position" below).
- `advisory_middle_chain_unsorted_prefix_tips` — must-accept over a
  three-prefix chain, with the *middle* prefix's tips supplied out of
  identity order and warnings landing at middle/final/interior positions.
- `advisory_first_prefix_unsorted_tips` — the counterpart to the above, with
  unsorted tips (three, in reverse order) at `chain[0]` instead of the
  middle, and the changed epoch on the identity-interior tip.
- `valid_surrogate_pair` — carries `input_raw_hex` instead of `input`: a
  correctly-ordered high/low surrogate escape pair (`😀`, U+1F600)
  in a tip's `stream_id`. The positive control for A4 (see below) — without
  it an implementation could pass this suite by rejecting every `\ud`
  escape wholesale, which is over-rejection, not conformance. The only
  vector that exercises `input_raw_hex`'s accept path at all.
- `max_safe_integer_entry_count` — a tip's `entry_count` is `2^53 − 1`, the
  I-JSON boundary itself, one below `integer_out_of_range`'s value. The
  positive control for A5: it establishes that ordinary, unmodified integer
  decoding doesn't over-reject a large-but-in-range value, which is why it
  stays at `min_format_version: 2` rather than 3 — accepting it depends on
  nothing the new check added.

## Negative vectors (a conformant validator MUST reject these)

Positive vectors prove an implementation computes the same bytes. Negative
vectors prove it actually enforces the rules. Each must be **rejected**; the
reason in its `expect` field is **advisory for third parties**.

`expect` records the reason *this repo's* reference validators give, under
their check order — encoding (only for a vector carrying `input_raw_hex`,
before it is even parsed into a checkpoint), schema, canonical, signature,
Tier B, chain, genesis — and the
generator asserts that at `gen` time, so a vector whose `expect` is wrong
cannot be published. A conformant validator need not share that order, and a
vector that fails more than one check may be named differently by one that
does not: `duplicate_tip_identity` ships with an empty signature and fails both
the canonical and the signature check, reporting `canonical` only because that
check runs first. **What conformance requires is the rejection, not the
label.**

- `tampered_signature` — one byte of a valid signature is flipped. Rejected: signature.
- `truncation_rewrites_committed_tip` — a stream is truncated (`entry_count` 7 to 5)
  and the checkpoint tip is rewritten to match, but the original signature is kept.
  The signature no longer covers the mutated tip. Rejected: signature. This is the
  checkpoint's defence against a silently truncated stream: a committed tip cannot
  be edited without re-signing, and the signing key is not the operator's to use
  freely on honest infrastructure.
- `broken_chain` — a valid, correctly signed checkpoint whose `prev_hash` does not
  equal the previous checkpoint's hash. Rejected: chain. Same `seq: 1`,
  non-genesis-`prev_hash` shape as `genesis_wrong_prev_hash` below, but reaches
  a different check: this vector sets `prev_sha256` to the genesis hash, so it
  is caught by the mismatch against that specific expected value before A6
  (below) ever runs.
- `genesis_wrong_seq` — `prev_hash` is the genesis constant, `sha256("")`,
  claiming to be the first checkpoint of the chain, but `seq` is 2, not 1.
  Rejected: genesis. The direction of the rule no other vector covers: every
  genesis-hash-carrying checkpoint elsewhere in the suite already has `seq: 1`.
- `genesis_wrong_prev_hash` — `seq` is 1, claiming to be the first checkpoint
  of the chain, but `prev_hash` is not the genesis constant. Rejected: genesis.
  Carries no `prev_sha256`, unlike `broken_chain` above — the only thing that
  can catch it is the intrinsic rule itself, checked with no chain context.
- `chain_prefix_wrong_genesis` — the same malformation as `genesis_wrong_seq`,
  but on a `chain` *prefix* rather than the vector's own input; the input
  above it is ordinary and correctly linked. Rejected: genesis. Pins that the
  rule is checked on every prefix a validator examines, not only the final
  checkpoint — the same position-generic standard `chain_prefix_missing_epoch`
  holds the epoch-presence rule to.
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
[Rules hold at every position](#rules-hold-at-every-position--what-that-does-and-does-not-cover) below.

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
- `stream_recommitted_at_chain_distance_3` — the same `(stream_id, epoch)` is
  committed by `chain[0]` and by the vector's own input, **three checkpoints
  apart**, with two clean checkpoints between them. Every other B3 negative
  places its duplicate at adjacent chain indices, so a validator comparing each
  checkpoint's identities only against its immediate predecessor — rather than
  against every identity committed so far — passed the whole published suite.
  Rejected: tier_b (B3).
- `stream_recommitted_between_prefixes` — the same `(stream_id, epoch)` is
  committed by the second and third *prefixes*, with the vector's own input
  clean. A validator that only compares its input against `chain[0]` accepts
  this. Rejected: tier_b (B3).

The five below move the defect off the chain-index axis entirely — onto a tip
index, onto the vector's own checkpoint, or onto the order of the `chain` array.
Several carry **three tips supplied in reverse identity order**, so that an
*interior* tip exists at all.

- `missing_epoch_interior_tip` — the middle tip of three omits `epoch` at
  version 2. `missing_epoch_in_v2` puts its defect on the last tip of two, so a
  check reading only the last tip passes it and fails here. Rejected: schema.
- `negative_epoch_interior_tip` — the middle tip of three carries `epoch: -3`.
  Same tip index, and a magnitude other than `-1`, so a guard weakened to
  `< -1` is caught too. Rejected: schema.
- `interior_tip_recommitted_same_epoch` — the identity-*interior* tip of a
  three-tip checkpoint re-commits an identity already committed by the interior
  tip of a three-tip prefix. Every other B3 vector duplicates a checkpoint's
  only tip. Rejected: tier_b (B3).
- `chain_carrier_missing_epoch` — the vector's **own** first tip omits `epoch`
  while the vector carries a `chain`. Every other epoch-boundary negative is
  chainless, so a validator that checks its own input only when there is no
  chain passes all of them. Rejected: schema.
- `prefixes_out_of_order` — the two chain prefixes are supplied newest-first.
  The `chain` array's order is the producer's claim about history, so it is
  checked as given; a validator that sorted the prefixes by `seq` would
  silently repair a reordered chain. Rejected: tier_b (B1).

The last group leaves the position axis behind and pins what a validator reads
*before* any rule applies: the **shape of the members** that arrive, and the
**encoding** of the signature string.

- `null_epoch` — the second tip of two carries `epoch: null`. `null` is neither
  an epoch nor an absent epoch, and a dynamically typed validator that reaches
  for a default gets `None`, which is not orderable against an integer.
  Rejected: schema.

  What this vector discriminates, precisely: the **null-read-as-zero**
  direction. A validator that reads `null` as the integer `0` accepts a
  checkpoint it must reject, and only this vector catches that. It does *not*
  discriminate the **null-read-as-absent** direction — the vector declares
  `min_format_version: 2`, so a validator conflating null with absent still
  rejects it, under the ordinary "epoch is required at version 2" rule.
  Reading `null` as absent is wrong at version 1, where the same bytes would
  be a legal tip; no vector can pin that (a version-1 vector must not carry an
  `epoch` member at all — see [Not
  pinned](#rules-hold-at-every-position--what-that-does-and-does-not-cover)),
  so `TestNullEpochRejectedAtEveryVersion` and
  `test_null_epoch_rejected_at_every_version` hold it in both references
  instead.
- `null_tips` — the `tips` member is present and `null`. It is not an empty
  array: canonicalization would normalize it to `[]` and let one signature
  cover two distinct documents. The signature published with this vector is
  valid over exactly those bytes, so nothing but the schema check rejects it.
  Rejected: schema.
- `integer_out_of_range` — a tip's `entry_count` is `2^53`, one past the
  largest integer RFC 7493 (I-JSON) §2.2 allows without precision loss on an
  IEEE 754 double. This repo's own canonical form (RFC 8785 JCS) places no
  limit on integer magnitude at all — the restriction is I-JSON's, protecting
  a third implementation that parses JSON numbers as `float64` (JavaScript's
  `Number`, for one), not either reference here: both round-trip far past
  this boundary exactly. Rejected: schema.
- `signature_with_stray_character` — the signature is not valid base64: a stray
  `!` is spliced into the middle of an otherwise valid 88-character encoding.
  Every other signature negative carries well-formed base64 whose *bytes* are
  wrong, so nothing pinned the encoding. A decoder that skips characters
  outside the base64 alphabet — the default in Python's `base64.b64decode` —
  reassembles the original signature from this string and *accepts* a tampered
  vector, so a lenient validator does not merely miss the mutation, it repairs
  it. Rejected: signature.

**The signature must carry the canonical base64 encoding of its bytes**, not
merely *an* encoding that decodes to them. Both references decode and then
re-encode, comparing the result against the string on the wire. Two mutation
classes need it, and each was silently repaired by exactly one of the two
before: Go's `base64.StdEncoding.DecodeString` ignores embedded newlines and
carriage returns by documented behaviour (and `.Strict()` does not change that
— it enforces the padding *bits*, not the alphabet), while Python's
`b64decode(validate=True)` rejects them; and *both* ignored non-canonical
padding bits, so two different signature strings decoded to the same 64 bytes
and both verified. The round trip is what makes one signature have exactly one
spelling. `go/encoding_test.go` and `py/test_validate.py` splice `!`, `\n` and
`\r` and flip the padding bits, at all three decode sites in each reference.

- `ill_formed_utf8_bytes` — carries `input_raw_hex` instead of `input`: the
  raw bytes contain `0xFF`, never valid in any position of a UTF-8 sequence.
  A typed `input` object cannot express this at all — a JSON parse would
  already have to succeed to populate one. Caught by an explicit byte-level
  UTF-8 validity check before any parsing is attempted. Rejected: encoding.
- `lone_surrogate_escape` — carries `input_raw_hex`: a tip's `stream_id`
  literally contains the six-character escape `\ud800`, a high surrogate
  with no low surrogate immediately after it — syntactically valid UTF-8
  and valid JSON, but not a correctly-paired escape, so it does not
  correspond to any single Unicode scalar value. Go's `encoding/json`
  silently decodes this to U+FFFD; Python's `json.loads` decodes it to a
  real (if unencodable) lone surrogate — both accept it, and disagree on
  what they accepted. Caught by a raw-text surrogate scan before either
  parser ever runs. Rejected: encoding.

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
three epochs across a chain — two (2, then 10) in its own checkpoint, a third
(0) in the chain prefix — makes two transitions, one cross-checkpoint (0→2)
and one intra-checkpoint (2→10), and yields two identical `B4:<stream_id>`
tokens — see `multi_epoch_same_stream`.

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
`advisory_new_epoch_and_timestamp_regression` vector pins that pair for a
validator that compares warnings in order; see Warning ordering below.

Tips are examined in `(stream_id, epoch)` order rather than input order. This
matters because a checkpoint's `input.tips` are explicitly allowed to be
unsorted: when two different streams each change epoch in one checkpoint, an
input-order walk emits their `B4` tokens in whatever order the tips happened to
be supplied, so two conformant validators handed identical signed bytes could
report different warning sequences. The `advisory_two_streams_new_epoch` vector
supplies exactly that pair in non-identity order and pins the result for a
validator that compares warnings in order; see Warning ordering below.

### Warning ordering is a stated requirement, not a vector-enforced one

`expect_warnings` is an **ordered** list, and a conformant validator compares
it to what it produces element-wise, in order — not as a set.

The order is not cosmetic: warnings are emitted by walking tips in identity
order and appending the timestamp warning after the tip loop, so a validator
whose warning order varies with the order `tips` happened to be supplied has a
non-deterministic tip walk. The ordering check above is a diagnostic for
exactly that defect, not an arbitrary convention.

**No vector in this suite can force that comparison to be ordered rather than
unordered.** For every published `expect_warnings` vector, the warnings a
*correct* validator emits are already in the expected order — that is what
makes the vector correct in the first place — so a validator that compares
warnings as an unordered multiset also passes the entire published suite. The
ordered comparison is a stated requirement of a conformant validator; it is
not something the fixture data mechanically enforces.

### Rules hold at every position — what that does and does not cover

**Pinned.** Every rule above is asserted at every **chain index** — every
transition of a multi-checkpoint chain, not only the first or the last, and,
for the identity-uniqueness rule, across all ordered index pairs rather than
adjacent ones only (`stream_recommitted_at_chain_distance_3` carries that one
into the published vectors, at distance 3; the full sweep of pairs is the test
suite's) — and at every **tip index**: rules are asserted against
interior tips, not only the first or last tip of a checkpoint.

That is a separate claim from the rules themselves, and it needs its own
coverage. A validator that applies a rule at exactly one position — only the
first transition, only the last tip — still computes correct bytes and still
rejects everything a short chain or a two-tip checkpoint can express. Collapse
either axis and such a validator passes. Two further orderings are checked the
same way by this repo's own test suite, and belong to the *verifier's*
contract rather than to any single rule: the order of the warning list it
reports, and the order of the `chain` array it was handed. (The warning-order
case has a narrower guarantee at the level of the published vectors themselves
— see [Warning ordering](#warning-ordering-is-a-stated-requirement-not-a-vector-enforced-one)
above.)

The tip-identity comparator's *prefix-freeness* is pinned the same way, at
both levels. `stream_id_prefix_pair` is a real, additive vector proving that
two DIFFERENT stream_ids standing in a prefix relationship (`"abc"` and
`"abc-1"`, differing lengths, one a strict prefix of the other) produce
distinct tip identities and sort correctly — something an implementation that
flattens the composite key into one string (`stream_id + separator +
zero-padded epoch`) gets wrong the moment its chosen separator can be
confused with a byte the stream_id itself might contain, which is exactly the
`\x00` → `~` swap that took five review rounds on Task 3 to surface.
`TestNULInStreamIDSortsByThePublishedRule` (`go/encoding_test.go`) and
`test_nul_in_stream_id_sorts_by_the_published_rule` (`py/test_validate.py`)
assert the same property against this repo's own two reference
implementations with the most adversarial such pair available — the
`a`/`a<NUL>` pair mentioned in the "not pinned" note just below, which does
*not* help there but is exactly the right tool here: a NUL is the lowest
possible byte, so it defeats every separator choice at once rather than one
at a time, and would also catch a flattened key colliding outright for some
other pair in the same defect class. `tipKey` (`go/main.go`) has no separator
to collide with — a comparable struct, not a flattened string — so none of
this can fail today; the vector and the two tests are conformance proof and
regression guards respectively, not evidence of a live gap.

Two more gaps from that list are pinned the same way now, with real vectors
rather than an argument for why one is not needed. Every OTHER chain in the
suite starts at `seq: 1`, so nothing before `mid_chain_window_no_genesis`
could separate a validator that checks B1's actual rule (`seq[i+1] ==
seq[i]+1`) from one that checks `seq[i]` against its own position in the
`chain` array — the two agree whenever the window happens to start at 1. The
vector's chain prefix opens at `seq: 400` with an arbitrary `prev_hash`
standing in for a checkpoint the verifier never saw — deliberately not
`sha256Empty`, so nothing about the fixture claims to be genesis — and it
must still be accepted: exactly the mid-chain window a real verifier holds
once it stops keeping every checkpoint back to genesis.
`mid_chain_zero_tip_checkpoint` closes the other: `genesis_empty_tips`
exercises an empty `tips` array, but only as a vector's own checkpoint, never
as a `chain` *prefix*, so the cross-checkpoint tip walk had never run zero
iterations for a checkpoint it did not stop at. The delta model makes this a
real case, not a boundary curiosity: a checkpoint commits only the streams
sealed since the one before it, so an idle interval with nothing newly sealed
still advances `seq` and `prev_hash` with an empty `tips`. The vector's
*middle* checkpoint does exactly that, so B1/B2 must hold on both the
transition into it and the transition out of it, with nothing for B3/B4 to
walk on the checkpoint itself.

**Not pinned**, stated plainly rather than left to be discovered:

- **`stream_id` ordering by code point vs. by length.** No published vector
  distinguishes the two: `stream_id_prefix_pair`'s differing-length pair
  (`"abc"`/`"abc-1"`) does not separate them, because one is a prefix of the
  other and prefix pairs order the same way under both schemes — the shorter
  string sorts first either way. A validator that sorts by length first and
  only then lexicographically reproduces every vector here exactly, and
  disagrees on the signed bytes the moment a real deployment uses ids of mixed
  length that are *not* in a prefix relationship — `"aa"` precedes `"b"` under
  the published rule and follows it under that one. The `a`/`a<NUL>` case does
  not separate them either, for the identical reason: those two also stand in
  a prefix relationship.
  `TestStreamIDSortsByCodePointNotLength` (`go/encoding_test.go`) and
  `test_stream_id_sorts_by_code_point_not_length` (`py/test_validate.py`)
  assert the discriminating pair in both references instead, over the same
  expected canonical bytes.
- **Unknown members, at the level of the published vectors.** Both references
  reject a member the schema does not define (above) and both refuse the whole
  file rather than reporting a per-vector verdict, so a suite file containing
  one cannot be loaded at all and the case is unpublishable as a vector. (They
  still word it differently — Go names the field its decoder tripped on,
  Python the member set it violated.) `go/encoding_test.go` and
  `py/test_validate.py` inject a member on
  a checkpoint, a tip, a chain prefix and a prefix wrapper in turn — each into
  a suite that is **re-signed afterwards**, so the signature is valid and only
  the schema rule can reject it — and require both references to reject, which
  is the strongest instrument available for it. The envelope positions (a
  vector, a negative, the suite object) are covered the same way; no signature
  reaches them at all, so only an explicit member set can.

- **A lone surrogate escape or invalid UTF-8 byte outside `input_raw_hex`.**
  A4's whole-file check (above) rejects one anywhere in the file, but like
  unknown members, that means no vector can carry one without failing every
  other vector's verdict alongside it — the whole file refuses to load, not
  one entry. Two pairs of tests cover this, one per class of position: for an
  envelope field never subject to any other check, `go/encoding_test.go`'s
  `TestWholeFileEncodingIsCheckedBeforeParsing` and `py/test_validate.py`'s
  `test_whole_file_encoding_is_checked_before_parsing` splice a lone `\ud800`
  into `description`; for a checkpoint payload field,
  `TestWholeFileEncodingCatchesTheCheckpointPayloadCase` and
  `test_whole_file_encoding_catches_the_checkpoint_payload_case` splice the
  same escape into `stream_id` in a properly re-signed fixture (a naive
  splice into an already-signed one is rejected by the pre-existing
  canonical/signature check regardless of whether this one exists, proving
  nothing about this check specifically). All four require both references
  to reject cleanly — not silently normalize it away (Go) or crash the
  reporting layer while printing a verdict about it (Python,
  [#36](https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/36)).

- **Wrong-typed scalars, at the level of the published vectors.** `"epoch":
  "1"`, `"epoch": true`, `"epoch": 1.0` and a null `tips` *element* are
  rejected by both references, but — like unknown members — by different
  mechanisms: Go's decoder refuses the whole file, while Python returns a
  per-tip schema reason. So no vector can carry one. `go/encoding_test.go` and
  `py/test_validate.py` assert both directions instead. (Getting this wrong is
  not hypothetical: `true` and `1.0` were *accepted* by the Python reference
  until this was written down, because `bool` is an `int` subclass and a float
  compares fine against `0`.)

- **Wrong-typed scalars, at the level of a vector/negative's own header.**
  `"name": [1, 2]` (or any non-string, non-null value) is rejected by both
  references, and — unlike the per-tip case above — by the *same shape* of
  mechanism on both sides: Go's `entryHeader{Name string}` is unmarshaled for
  every entry, skipped or not, to make the skip decision itself, so a
  non-string name refuses the whole file at load; Python's `check_entries`
  gates it in the identical position, before the skip decision, for the
  identical reason. So no vector or negative can carry one.
  `TestWrongTypedNameIsRejectedWhileDecoding` (`go/encoding_test.go`) and
  `test_wrong_typed_name_rejects_the_whole_file` /
  `test_wrong_typed_name_rejects_even_on_an_entry_that_would_be_skipped`
  (`py/test_validate.py`) assert both directions instead. (Not hypothetical
  here either: a non-string name validated normally in the Python reference —
  printed in an "ok" line via its `repr()` — until this was written down.)

- **Wrong-typed scalars, at the level of the suite envelope.** `description`,
  `algorithm` and `signing_seed_hex` are the suite's own scalar members —
  `unknown_members` only gates which member *names* the envelope may carry,
  never their types, and none of the three is read for any comparison, so a
  wrong-typed value there reached nothing that could catch it. Rejected by
  both references, by the same shape of mechanism as the header case above:
  Go's `suiteFile` strict-decodes the envelope eagerly for every suite, so a
  wrong type there refuses the whole file at load; Python's `check_envelope`
  now gates the same three fields before anything else is read. So no suite
  can carry a wrong-typed envelope member.
  `TestWrongTypedEnvelopeStringsAreRejectedWhileDecoding`
  (`go/encoding_test.go`) and
  `test_wrong_typed_envelope_strings_reject_the_whole_file`
  (`py/test_validate.py`) assert both directions instead.

- **Wrong-typed scalars, on a negative's own body.** `reason` and
  `prev_sha256` are members of the full `NegativeVector`, not of the header
  the skip decision itself reads, so — unlike `name` above — Go only
  strict-decodes them for a negative that will actually be checked; a wrong
  type on a would-be-skipped entry is never reached and must stay legal.
  `reason` is pure documentation, read nowhere; `prev_sha256` previously
  reached a `!=` comparison in `reject_reason` that never raises across
  Python types, so a *falsy* wrong type (`[]`, `{}`, `0`) no-opped past the
  check the same as an absent field, while a *truthy* one (`[1, 2]`)
  coincidentally reproduced the `"chain"` token a real linkage defect
  returns — accepting a file Go refuses to load either way. Gated in
  `check_entries` now, in the same position as the unknown-member check and
  for the same reason: failing the whole file there matches Go's verdict for
  every wrong type, not only the truthy ones a per-entry comparison happened
  to catch. `TestWrongTypedNegativeBodyFieldsAreRejectedWhileDecoding`
  (`go/encoding_test.go`),
  `test_wrong_typed_negative_body_fields_reject_the_whole_file` and
  `test_wrong_typed_negative_body_fields_ignored_when_the_entry_is_skipped`
  (`py/test_validate.py`) assert all of this instead.

- **Wrong-typed scalars, on a checkpoint's own body.** `seq`, `timestamp` and
  `prev_hash` are `Checkpoint`'s members besides `tips`. A wrong-typed `seq`
  or `timestamp` used to reach unguarded Tier B arithmetic/comparison in the
  Python reference — B1's `prev_seq + 1` and B5's `<` — and crash with an
  uncaught `TypeError` instead of a clean rejection; `prev_hash` never reached
  an unsafe operation (B2 compares it with `!=`, which never raises across
  Python types) but is gated the same way for the same reason the fields
  above are. Rejected by both references, by the same shape of mechanism as
  the header/envelope/negative-body cases above: Go's `Checkpoint` strict-
  decodes all three eagerly, so a wrong type refuses the whole file at load;
  Python's `check_schema` now gates the same three fields before `tips` is
  even examined. A *null* value for any of the three stays legal in both —
  none of `Checkpoint`'s fields are pointers, so JSON null is a documented
  no-op leaving the zero value — but null still needed its own fix in the
  Python reference: `check_tier_b`'s own reads used to default only for an
  *absent* key (`.get("seq", 0)`), so a *present* null reached B1/B5 as `None`
  and crashed exactly like a wrong type. `cp_seq`/`cp_timestamp` fold a
  present null to the zero value the same way `tip_epoch` already does for
  epoch. `TestWrongTypedCheckpointBodyScalarsAreRejectedWhileDecoding`
  (`go/encoding_test.go`),
  `test_wrong_typed_checkpoint_body_scalars_returns_a_reason`,
  `test_null_checkpoint_body_scalars_fold_to_zero_value_in_tier_b` and
  `test_wrong_typed_checkpoint_body_scalars_reject_cleanly_through_the_validator`
  (`py/test_validate.py`) assert all of this instead.

  That fold closed the CRASH, but not the whole gap: `canonical()` itself
  never called `cp_seq`/`cp_timestamp` — it serialized `cp`'s raw scalars
  untouched, so a checkpoint published with `seq` absent and mutated to
  carry `"seq": null` instead kept validating in Go (same canonical bytes,
  same signature) but failed here (different bytes, signature no longer
  verifies). This was found only while grounding the tip-level version of
  the same question below — and NOT actually fixed at the time, despite
  that issue's own text incorrectly assuming it already was.
  `canonical()` now builds a folded copy of `cp`'s scalars
  (`cp_seq`/`cp_timestamp`/the new `cp_prev_hash`) before serializing,
  mirroring the tip-level fold below exactly.
  `TestCheckpointScalarsCollapseNullAndAbsentIdentically`
  (`go/encoding_test.go`) and
  `test_checkpoint_scalars_fold_to_identical_canonical_bytes_null_vs_absent`/
  `test_a_signature_over_absent_checkpoint_scalars_still_verifies_when_mutated_to_explicit_null`
  (`py/test_validate.py`) assert this
  ([#44](https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/44)).

- **A null tip scalar (`entry_count`, `sequence_number`, `stream_id`,
  `tip_hash`) canonicalizing differently from an absent one.** None of
  `Tip`'s four plain scalar fields are pointers either, so Go's decode
  collapses a present null and an absent key to the identical zero value —
  but this was never actually fixed for `canonical()`, only assumed to
  already be, by analogy with the checkpoint-level bullet above (an
  assumption later found to be wrong: `cp_seq`/`cp_timestamp` were
  `check_tier_b`-only helpers, never wired into `canonical()` — the
  checkpoint-level version of *this exact* gap, tracked separately as
  [#44](https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/44),
  is now fixed too, above).
  Before this fix, `canonical()` serialized each tip's raw dict untouched, so
  a checkpoint published with `entry_count` absent and mutated to carry
  `"entry_count": null` instead kept validating in Go (same canonical bytes,
  same signature) but failed here (different bytes, signature no longer
  verifies) — a real accept/reject divergence, not a formatting nicety.
  Worse for `stream_id` specifically: a checkpoint with one tip missing
  `stream_id` and another carrying an explicit null compared a `str` against
  a `None` inside `canonical()`'s own tip sort and crashed with an uncaught
  `TypeError`, not a clean rejection. `tip_entry_count`/`tip_sequence_number`/
  `tip_stream_id`/`tip_tip_hash` fold a present null the same way
  `cp_seq`/`cp_timestamp`/`tip_epoch` already do, and `canonical()` now
  builds each tip from the folded values rather than the raw dict. `epoch`
  is deliberately excluded from this fold: Go tracks its null-vs-absent
  distinction explicitly (`Tip.EpochNull`) and canonicalizes the two
  differently *on purpose* (absence is legal only pre-v2; an explicit null
  is a distinct, format-version-gated shape), so folding it here would be
  the opposite of correct.
  `TestTipScalarsCollapseNullAndAbsentIdentically`/
  `TestEpochNullVsAbsentStillDivergesOnTheGoSide` (`go/encoding_test.go`)
  and
  `test_tip_scalars_fold_to_identical_canonical_bytes_null_vs_absent`/
  `test_a_signature_over_absent_tip_scalars_still_verifies_when_mutated_to_explicit_null`/
  `test_epoch_null_vs_absent_still_diverges_in_canonical_bytes`/
  `test_mixed_null_and_string_stream_id_tips_canonicalize_without_crashing`
  (`py/test_validate.py`) assert all of this
  ([#40](https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/40)).
  A `stream_id`/`tip_hash` carrying the WRONG TYPE entirely (not null, an
  int or other non-string) is a related but distinct gap — neither field has
  a type-gate at all, unlike `entry_count`/`sequence_number` — tracked
  separately as
  [#45](https://github.com/surpradhan/otel-audit-checkpoint-vectors/issues/45).

- **The version-1-carrying-`epoch` direction.** A version-2 tip missing
  `epoch` is published as a vector (`missing_epoch_in_v2`); the mirror-image
  case — a version-1 vector that *carries* an `epoch` — is not, and cannot be.
  Any vector declaring `min_format_version` below 2 while carrying an `epoch`
  member would be mangled by a genuine version-1 consumer, which is the one
  reader the boundary exists to protect. `TestEpochPresenceBoundary`
  (`go/tierb_test.go`) and `test_epoch_presence_boundary`
  (`py/test_validate.py`) assert that direction as a unit test in both
  references instead.

This is an honest account of what the position-axis vectors currently
constrain, not a claim that every conceivable position is covered.

Two things pin the part that *is* covered:

- **Vectors whose defect sits where the collapse would hide it.** Listed above:
  four-checkpoint chains with the defect in the middle, three-tip checkpoints
  with the defect on the interior tip, an epoch defect on a chain carrier's own
  input, and prefixes supplied out of order. `advisory_middle_chain_unsorted_prefix_tips`
  and `advisory_first_prefix_unsorted_tips` are the must-accept counterparts:
  between them a prefix at index 1 and a prefix at index 0 each supply their
  tips **out of identity order**, so B2 must hash *canonical* bytes at every
  chain index; the second supplies three tips in reverse order, which needs a
  full sort rather than one adjacent swap; their `B4` and `B5` tokens fall at
  middle, final and interior-tip positions rather than at first ones; and every
  regressed timestamp stays above `chain[0]`'s, so comparing against `chain[0]`
  instead of the immediate predecessor no longer matches.
- **Position-generic tests.** `go/positional_test.go`, `go/crossproduct_test.go`
  and the matching sections of `py/test_validate.py` are table-driven over
  position: for each rule they inject the defect at every chain index, every tip
  index, every tip-index *pair*, and every index of the warning list in turn,
  and require the rule to fire each time. A vector can only pin the positions
  someone thought to write down; these fail for any position a validator omits.

A count of what the harness actually reached backstops both: rules cannot fix
a harness that skips entries, so a loop truncated to its first element would
otherwise leave every rule intact and every gate green. Both validators print
a line like

```
checked: 18 positive (14 through Tier B) + 35 negative
```

and fail if those counts do not match an independent pre-pass over the suite.
The tests recount the committed file a third time and compare.

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

**Scope of what "full RFC 8785" above actually means here.** Every published
canonical *key name* is ASCII, drawn from a 40-character alphabet, so the
suite's key ordering is exercised only over ASCII keys — where UTF-16
code-unit order, code-point order and byte order all coincide. It exercises
none of JCS's string-escaping rules, and nothing here distinguishes the
UTF-16 code-unit key ordering RFC 8785 §3.2.3
requires from a plain code-point sort. That distinction is exactly where
Python's `sort_keys=True` stops being general JCS.

`valid_surrogate_pair` and `non_bmp_and_pua_stream_id_order` are exceptions
at the *value* level: their stream_ids (😀 U+1F600; and U+E000 and U+10000,
the first non-BMP code point, respectively) are published as literal UTF-8
rather than `\u` escapes, because JCS only requires escaping a small fixed
set of characters (control characters, `"`, `\`) and none of these are among
them. That is real coverage of JCS's string-escaping rule, at these specific
code points — not general JCS string-escaping conformance, and not a second
exception to the key-ordering scope above, since a tip's `stream_id` is an
array-element *value*, sorted by this repo's own R4 rule, not a JSON object
key subject to RFC 8785 §3.2.3 at all.

The suite therefore exercises JCS's compact separators throughout. The two
implementations are also not symmetric in kind: Go canonicalizes through
`gowebpki/jcs`, a general-purpose RFC 8785 implementation, while Python's
`json.dumps(sort_keys=True, ensure_ascii=False, separators=(",", ":"))` is
valid JCS only for this restricted, ASCII-keys/integers-only profile — it is
not a general RFC 8785 implementation.

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
