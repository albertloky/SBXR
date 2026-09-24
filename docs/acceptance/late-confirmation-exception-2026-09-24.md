# Approved late-confirmation exception — 2026-09-24

**Owner approved archival validation and end-to-end integration for one fresh
target, v3.1.81 / sequence 159. No publication or new live run is authorized by
this exception.**

Albert approved the proposed narrow exception for human-confirmation timing.
It concerns the retained observations for `v3.1.80`, sequence `158`, source
`1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52`,
[candidate run 35965345632](https://github.com/albertloky/SBXR/actions/runs/35965345632),
attempt 2. The signed manifest SHA-256 is
`1d664476d96ee0cea97eef1ce91445e159d56c234f6772939e15014b792f1046`.

## Evidence and decision

The first four journeys were accepted. Server-side restart, removal and
preservation checks passed. Final removal of the disposable Karing entry,
clearing the copied URL/clipboard, and preservation of the original connection,
Rules mode and settings were subsequently confirmed by the Owner without errors
reported in those steps. The confirmation was recorded at
`2026-09-24T09:26:44.001843+00:00`, after the final journey's
`2026-09-24T08:12:20Z` deadline. The time the Owner actually performed cleanup
is not established; do not describe this as independently observed on-time cleanup.

Retain that evidence and its actual timestamps. Do not require a repeat merely
because the human confirmation arrived late. Review explicitly which observations
can apply to one new release identity. Do not claim that an old candidate's live
observations were performed on a different build.

The original workflow failure and `release-burned/v3.1.80` remain unchanged.
This approval does not revive that identity, fabricate an all-observed timed
record, waive failing automated checks, authorize repeated certificate requests,
or approve stable publication. Any resulting release must disclose the exception
and reused evidence rather than claim a fresh five-journey live pass.

## Implementation boundary

The ordinary [MVP procedure](mvp-live-acceptance.md) still has no retroactive
timed-pass path. [ADR-0017](../adr/0017-one-release-owner-exception.md)
is restricted to v3.1.0/83 and is not reusable. The current gate requires a
successful candidate workflow and a valid exact-identity Acceptance Record.

[ADR-0024](../adr/0024-r24-late-confirmation-supplement.md) defines the implemented
`mvp-late-confirmation-supplement` stage. It checks the exact archived document
bytes and returns `accepted-supplement`, never a live pass or publication action.
It refuses changed, missing or additional evidence and runtime target/approval
overrides. The raw supplement still cannot satisfy the ordinary live-result gate.

Release integration designates v3.1.81 / sequence 159 only. A target-bound Git
applicability review is included in the signed manifest and independently
reproduced by the workflow. Normal native automated checks, artifact identity,
attestations, history/baseline checks, secret containment and separate publication
approval remain required. Reused package/host/client declarations must match the
archived signed attempt; they are not fresh live observations. Public release
readers and finalization preserve the exception label. See ADR-0024 for the source
comparison boundary. This document is not an Acceptance Record or publication
permission.

Implementation checks include actual CLI decision-chain execution through stable
finalization (fixture only), real temporary Git comparison, HTTP public-reader
checks, and refusals for changed evidence/environment/identity, missing approval,
failed native candidate, burn records and fabricated fresh live results. Local
validation output lives in [i24](../../.scratch/acceptance/i24/). Remote candidate
results must be assessed separately; local tests do not establish a live pass.

Local evidence: [approval and CI audit](../../.scratch/acceptance/ci-review-20260924/),
[original run](../../.scratch/acceptance/r24/), and
[late Owner confirmation](../../.scratch/acceptance/r24/owner-late-cleanup-confirmation.json).
