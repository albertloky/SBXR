---
status: accepted
---

# Publish qualified files and preserve publication retries

The Owner requested on 2026-10-15 that passing all required tests should lead to
a stable release, and approved this simplification at 13:27 UTC. A publication
job failure must not consume an otherwise qualified candidate. This refines the
separate publication approval and failure/burn rules in ADR-0016, ADR-0028 and
ADR-0030. Historical signed records and their actual outcomes remain intact.

## Qualification is the publication authority

Stable publication requires the successful signed qualification for the exact
candidate: required native checks, all live journeys in its declared scope,
actual complete removal and host/client/secret cleanup, unchanged asset names,
sizes and digests, and authenticated manifest, workflow and release proofs.
Passing these checks permits stable publication without another human
`stable-publication` environment approval. The workflow automatically binds its
publication decision chain to the verified preflight facts and decision. It
performs no new `acceptance-vps` host probe merely to publish already tested files.
Successful completion of the official `Construct qualified drafts` workflow on
`main` in this repository automatically starts the stable workflow through
`workflow_run` for the current clean-install-only scope. Historical scopes retain
explicit dispatch. Failed or foreign-repository runs cannot start publication.
Manual dispatch remains available for a retry of the same qualification run or
explicit abandonment.

Each publication attempt rechecks the original qualification, current release
state, release history and exact downloaded bytes. Changed candidate source or
assets need qualification for the changed files. Authentication or integrity
failure never grants publication, and missing evidence is not success.

ADR-0030's exact main-divergence review remains: review the committed diff and
ordered commits, bind the candidate SHA, current main SHA and divergence digest,
and assess missing security fixes and continued evidence applicability. Missing
or stale review pauses publication; a candidate missing security fixes needs a
replacement candidate and its qualification. The automatic decision binding
replaces the protected-environment approval ceremony, including after review.
Fresh main observations still bound the race immediately before publication.

## Publication failures preserve qualification

A failed publication job retains its actual failure and available diagnostic
evidence for a retry of the same successful qualification run. It does not
automatically burn, withdraw or mark the candidate failed. An uncertain request
outcome requires observing the release before another mutation: a completed
publication may need verification rather than another publication request.
Explicit abandonment retains the authenticated failure finalizer and burn path.
Failed or incomplete required tests and cleanup cannot use this retry rule.
Their existing qualification failure handling remains; this change concerns
publication after successful qualification.

Retain fixed diagnostic codes and bounded secret-safe statuses, counts, input
sizes and digests. Diagnostic collection or upload failure cannot change the
qualification result. Keep the original failure record even when a later retry
succeeds; a reconstructed request cannot establish a lost historical error.

## Recover an already finalized prepublication failure

The narrow recovery route accepts a clean-install-only candidate whose original
successful qualification and complete cleanup can be replayed, but whose old
publication workflow subsequently created an authenticated
`prepublication-failure` burn and immutable failed prerelease. It requires the
same signed manifest, candidate run, Release Identity, sequence, release ID,
tag, source commit and exact four asset bytes. The original failed release body
and burn must agree with that identity. Other burns, changed bytes, failed tests,
incomplete cleanup or contradictory evidence still refuse.

Recover by running the current stable-publication workflow against that original
successful qualification run. The workflow authenticates the original burn and
replays the acceptance chain, then promotes the same immutable prerelease through
release metadata only and verifies public stable/Latest acceptance. It preserves
the original burn tag and signed qualification record. Before editing metadata,
the workflow archives the validated recovery facts. Existing signed qualification
and burn evidence authenticate the recovery; no new signing permission is needed. The release notes replace the
failed status with the original qualified Acceptance Record and an audit footer
containing the complete original failed record in base64 and its SHA-256 digest.
This updates public Acceptance Record metadata transparently while retaining the
failure history; it neither replaces assets nor rewrites a tag, signed manifest
or sequence. No new candidate reservation or live tests are needed when the
original proof remains complete and applicable.

This route can recover v3.1.95/173, source
`f99e0b7367db9af20a6b74043e97a6a5bdee4360`, from successful qualification
[38718454118](https://github.com/albertloky/SBXR/actions/runs/38718454118), subject to
those fresh verification checks. Failed publishing run
[38728113572](https://github.com/albertloky/SBXR/actions/runs/38728113572) remains a
failure. Its exact cause is unproved because the original preflight input,
decision bytes and specific error were not retained; it must not be described as
a proved policy rejection. Recovery does not make that failed run pass.
Publishing it from a newer policy/tooling commit still requires the exact
main-divergence review above; a policy-only diff is not an automatic review result.

This decision grants no new live-run or host/security-mutation scope. The approved
local implementation is reviewed before any commit, push or remote release
mutation; this ADR does not record such an operation or a stable publication.
