# Limits

What this repo's Tier A and Tier B vectors do **not**, and cannot, prove.

Tiers A and B (see the design spec's [Taxonomy](superpowers/specs/2026-08-26-checkpoint-detection-semantics-design.md#4-taxonomy))
cover what one verifier can conclude from one chain: canonical bytes reproduce,
a signature verifies, and the chain is internally consistent. The four limits
below are different in kind, not degree — each is undetectable *by construction*
for a single verifier holding a single chain, quantified over every possible
verifier algorithm, not just the two shipped here. No fixture can test a claim
of that shape; Certificate Transparency, TUF, in-toto, SLSA and C2PA all draw
the same line for their own equivalent limits, in prose rather than a fixture
suite. So this document, not a vector category, is where these live.

## Split-view / equivocation

A single verifier holding one chain cannot detect an operator serving
**different, individually-valid histories to different verifiers** — each
recipient sees a chain whose signatures verify and whose links hold; nothing
in either history is internally wrong.

It *is* provable across two views: two checkpoints carrying the same `seq`
under one signing key, with different hashes, are a self-contained
equivocation proof — the same object Certificate Transparency uses for
inconsistent Signed Tree Heads. That is the argument for the checkpoint being
the right unit for a witness to gossip: comparing checkpoints across
independent observers, not extending this suite, is how equivocation actually
gets caught.

See [`otel-agent-audit`'s threat model, §2 "Malicious-operator limit"](https://github.com/surpradhan/otel-agent-audit/blob/main/docs/threat-model.md#2-malicious-operator-limit),
which names this the same way and states the defense: external witnesses
comparing checkpoint hashes out-of-band, not a v1 feature of either repo.

## Full rewrite by the key holder

An operator who holds the signing key can rewrite the entire log and re-sign
every checkpoint from genesis. Every canonical-bytes check, every signature
check and every chain-linkage check in this suite passes on the rewritten
history — a self-consistent forgery is, from inside one chain, indistinguishable
from the truth. Detecting this needs an anchor outside the key holder's
control: the same external-witness upgrade path as split-view, above.

Also covered by [threat model §2](https://github.com/surpradhan/otel-agent-audit/blob/main/docs/threat-model.md#2-malicious-operator-limit).

## Staleness

A verifier that only checks internal consistency cannot distinguish a
checkpoint chain that has genuinely stopped advancing from one whose operator
is deliberately serving a valid **old** prefix, withholding what came after
it — both look like a chain that ends where it ends.

Unlike the two limits above, this one has a credible fix that stays inside
what a single verifier can check: a maximum checkpoint interval, plus a
timestamp comparison against wall-clock time, converts silent staleness into
a detectable violation — the same shape as TUF's role-metadata expiry. This
repo does not adopt that fix; it is a policy decision (what interval, and what
clock-skew tolerance) for the Audit Logging SIG to make, not one this suite
should presume on the SIG's behalf.

## Never-committed streams

A checkpoint attests to what **was** committed by the time it was sealed —
never that everything which actually occurred was committed. A trace that
never reached the log at all leaves no record to be missing; there is no
absence to detect, only silence indistinguishable from "nothing happened."

[`otel-agent-audit`'s threat model, §7 "What the verifier can and cannot conclude"](https://github.com/surpradhan/otel-agent-audit/blob/main/docs/threat-model.md#7-what-the-verifier-can-and-cannot-conclude)
already states this directly: a trace that was never written is absent, not
corrupted, and the verifier cannot tell the two apart.
