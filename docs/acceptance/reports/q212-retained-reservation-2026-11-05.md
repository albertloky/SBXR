# Build 212 retained reservation — 2026-11-05

The Owner approved preserving failed v3.1.138/212 as signed-unqualified through
SBXR's existing fixed reservation mechanism. The exact draft, files, signature
and failed outcome remain unchanged. No live attempt or remote release mutation
is part of this change.

## Exact authority and fresh evidence

[Run 41958829811](https://github.com/albertloky/SBXR/actions/runs/41958829811)
signed source `13431bc29500bf20dc108dc325590403d0ca056c`, draft 434759360.
The manifest SHA-256 is
`30bbbeb56f16bb16ebc6be0cb2dbfa305cc16e403d0c3a609dc0918ac2591b74`;
release-index SHA-256 is
`f006de0f4719bc8a6fe21af86a11fd837cc20cf7e73911e13b905e0cdd187a98`.
The compiled reservation independently pins all four asset identities and bytes.

After approval, GET-only inspection at 09:18:54 UTC matched the original draft
metadata/body and all four downloaded asset sizes and SHA-256 hashes, with both
release and burn refs absent. Retained attestation verification at 09:22:15 UTC
passed for the exact repository, candidate workflow, main ref, source digest and
hosted-runner requirement. Downloaded assets were not executed. These reads are
not atomic; supported future operations must recheck the live bindings.

The [failed live report](q212-details-timeout-2026-11-05.md) remains authoritative
for its dated observations: install/setup passed, initial details timed out,
later journeys were not reached, and scoped host/client cleanup was verified.
The cleanup-unqualified job intentionally stopped for a disposition decision;
reservation adoption does not change its failed result or rerun it. Historical
cleanup does not establish current host readiness.

## Bounded change

The tenth fixed record adds only this identity. The Go validator and shell
collector require exactly ten matching reservations. Current candidate fixtures
advance to v3.1.139/213 and continue checking strict sequence progression and
independent tag/sequence/release-ID collision refusals. All previous nine source
record blocks and historical initial qualification fixtures are unchanged.

No product Rust behavior, deadline, schema, credential, security setting, workflow
permission or approval gate changed. No draft, asset, tag, signature or release
metadata was mutated. This neither promotes the failed build nor dispatches its
replacement. The existing GET-only observation helper suffices; no inventory
workflow permission change or dispatch is needed.

## Validation

The new exact-record and next-sequence regressions failed against the old nine-
record policy, then passed after the change. The focused reservation suite passed
in 42.953 seconds, including the real shell/jq/Python/Go collector adapter,
tenth-record mutation/ref-unavailability/ref-presence refusal, historical replay
and fresh qualification/publication decision fixtures. Those fixtures do not
perform remote publication. Formatting, shell syntax and diff checks passed.

The complete release-tool package passed in 456.812 seconds; repository-root
integration tests passed in 96.220 seconds, followed by `go vet ./...`. All used
Go 1.26.6 with offline module resolution and separate short workspace temporary
roots; those temporary roots were removed empty. The fresh full observation
replay at 09:24:39 UTC accepted all ten exact reservation records and twenty
explicitly absent refs across the current release inventory. Independent review
found no blocking regression; documentation links and whitespace checks passed.
Product Rust source was unchanged, so its already valid local results were reused.
Exact final-source GitHub CI is a separate post-push check, not implied by these
local results; its outcome is retained with the commit under the run directory.
Private evidence: `.scratch/acceptance/q212res/`; earlier proposal/inventory files
remain under `.scratch/acceptance/q213-proposal-20261105/`.

## Remaining prerequisites

Final-source CI and fresh global release/reservation/ref admission are required
before selecting the next candidate. v3.1.139/213 remains prospective, not allocated.
One concrete live approval must bind the final source, host/profile, actual host/
client readiness, temporary trust/routing/firewall and disposable-secret effects,
attended cutoffs and scoped cleanup. The 90-second details criterion, outside
traffic and Karing evidence remain unverified by this change. Stable publication
needs separate approval after complete exact-candidate qualification and cleanup.
