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

## Canonical form

A checkpoint is a JSON object:

| Field | Type | Notes |
|-------|------|-------|
| `prev_hash` | string | Hex SHA-256 of the previous checkpoint's canonical bytes. The first checkpoint uses the SHA-256 of the empty string (`e3b0c442…b855`). |
| `seq` | integer | Monotonic checkpoint sequence, starting at 1. |
| `timestamp` | string | RFC 3339 UTC. |
| `tips` | array | One entry per stream committed by this checkpoint. |

Each `tips` entry:

| Field | Type | Notes |
|-------|------|-------|
| `stream_id` | string | The stream (per-trace chain, in `otel-agent-audit`). |
| `sequence_number` | integer | The stream's highest committed sequence number. |
| `tip_hash` | string | Hex hash of the stream's tip (the `IntegrityHash` of its highest record). |
| `entry_count` | integer | Number of records in the stream so far (truncation shows up here too). |

**Rules an implementation must follow to reproduce the bytes:**

1. **Tip order.** `tips` MUST be sorted by `stream_id` ascending (Unicode code
   point) before canonicalization. JCS fixes object-key order but preserves
   array order, so the producer imposes the tip order.
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
