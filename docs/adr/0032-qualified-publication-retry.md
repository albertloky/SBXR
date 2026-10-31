---
status: accepted
---

# Publish qualified files and preserve publication retries

The Owner requested on 2026-10-15 that passing all required tests should lead to
a stable release, and approved this simplification at 13:27 UTC. A publication
job failure must not consume an otherwise qualified candidate. This refines the
separate publication approval and failure/burn rules in ADR-0016, ADR-0028 and
ADR-0030. Historical signed records and their actual outcomes remain intact.

## Qualification and explicit publication approval

Stable publication requires the successful signed qualification for the exact
candidate: required native checks, all live journeys in its declared scope,
actual complete removal and host/client/secret cleanup, unchanged asset names,
sizes and digests, and authenticated manifest, workflow and release proofs.
The Owner's current no-publication-before-approval direction, reflected in this
2026-10-23 local refinement, supersedes the automatic `workflow_run` trigger
previously specified here. Passing qualification makes the candidate eligible;
publication still requires the Owner's explicit approval and then manual
`stable.yml` dispatch on `main`, naming the successful `qualification_run_id`.
Qualification completion alone never starts publication. The workflow retains
its authenticated successful-run binding and automatically binds its publication
decision chain to the verified preflight facts and decision. It performs no new
`acceptance-vps` host probe merely to publish already tested files and adds no
separate `stable-publication` environment ceremony. Manual dispatch also permits
a retry of the same qualification run or explicit abandonment within approved scope.

Each publication attempt rechecks the original qualification, current release
state, release history and exact downloaded bytes. Changed candidate source or
assets need qualification for the changed files. Authentication or integrity
failure never grants publication, and missing evidence is not success.

ADR-0030's exact main-divergence review remains: review the committed diff and
ordered commits, bind the candidate SHA, current main SHA and divergence digest,
and assess missing security fixes and continued evidence applicability. Missing
or stale review pauses publication; a candidate missing security fixes needs a
replacement candidate and its qualification. The automatic decision binding
retains the exact evidence chain after manual dispatch, including after review;
it does not replace the Owner's publication approval.
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

## Candidate failures require an action-time decision

The Owner approved this workflow safety change on 2026-10-29. Candidate failures
now retain bounded, screened evidence and validated failure proposals, then stop
with a failed result. Neither partial draft construction nor later unsigned or
signed qualification failure automatically deletes drafts/tags, signs or pushes
burn records, or publishes failed prereleases. This supersedes automatic candidate
failure finalization; historical burns and the explicit stable abandonment path
retain their meaning. Required host/client/secret cleanup is unchanged.

A proposal is not authorization. Before any later failure action, obtain a separate
explicit Owner decision for the exact run, commit, tag, sequence, release ID,
asset identity and proposed effects, then freshly recheck the authenticated state.
Changed or uncertain state stops the action. This change introduces no automatic
resume or approval switch and does not make a failed qualification publishable.
Candidate creation refuses unresolved drafts rather than deleting them or reusing
their pending sequence. The exact reservation below is the sole reviewed exception.

## Preserve one unknown-signing draft and reserve its identity

On 2026-10-29 the Owner approved a fresh-start policy that preserves the old draft
and evidence, reserves its version/sequence, and prevents accidental promotion.
`candidate_reservations.go` pins draft `v3.1.129`, sequence 203, release 426359967,
source `3656473eb694f18018c1ebbd95829dfe96ed8e3c`, run 40644460970, the release-index
digest, and all four asset IDs, sizes and digests. Signing remains **unknown**.
This source-controlled reservation is not a burn, attestation, unsigned proof,
cleanup decision or acceptance evidence. No remote resource is changed to adopt it.

The current workflow accepts that retained draft only while every pinned field
agrees and both its release-tag and burn-tag refs remain explicitly absent.
Missing, changed, duplicated or unavailable observations refuse. Other pending
drafts still refuse, except the exact current workflow candidate tags during later
checks; that allowance cannot exempt the reserved identity. The existing common
release concurrency group remains serialized. The already write-authorized draft
job checks observations immediately before each draft-creation request. Signing stays read-only and
compares that successful current-run record with the compiled policy and preflight
facts before host readiness or signing. Stable preflight and the final publication
boundary recheck live metadata using their existing permissions; the final main
check remains after the reservation check. No token permissions are expanded.

New preflight facts bind the exact reservation into the existing decision and
signed qualification chain. Sequence allocation counts it independently of public
release history and burns. Tags and sequences at the reservation remain unavailable;
all subsequent candidates require the exact record, even if public history advances.
Pre-reservation historical facts retain their original interpretation. The old
release ID cannot be reused by a new draft verification chain. Current qualification
and publication replay refuse the reserved candidate, rather than rewriting its
historical records or claiming it was never signed.

A fresh candidate must still use the next sequence above all observed releases,
burns and reservations and complete its own unchanged qualification requirements.
With a highest public/burn sequence of 202, the next candidate uses 204, not 203.
This is a narrowly reviewed one-draft mechanism, not a general ignore-list.
Changing its policy or disposing of the draft requires another explicit decision.

These protections cover the supported workflows and validators. They cannot make
GitHub metadata reads and later operations atomic, or prevent a privileged operator
from manually changing releases or replacing trusted workflow code. Such observed
changes stop the supported path. No repository security setting, signing authority,
installed admission rule or historical signature is changed. This decision grants
no live qualification, signing, deletion or publication permission.


## Preserve the signed, unqualified second draft

On 2026-10-29 the Owner separately approved extending the reservation to exactly
two drafts. This supersedes the one-draft limit above, not its validation,
non-promotion, failure-decision or qualification safeguards. The original
v3.1.129/203 record and its unknown signing state remain unchanged.

The second record pins v3.1.130/204, release 427453228, source
`8ef6898573d8e7886d11c65b693f79d7c502787f`, run 40811037642, index digest
`96d95146293481005b8977aac80c35e088a681d6c135cf2c00e7ee103b92e47c`, and all four
asset IDs, sizes and digests. Its state is `signed-unqualified`: the authenticated
manifest digest is
`0fe088fd0cd19a7bd27e0dc62ab7c510736ba7991cc827d45a85d140749334bf`.
The run was cancelled without successful live qualification. Retaining that
signed identity neither makes it unsigned nor creates a burn or qualification.
Its historical signed bytes and the original one-reservation chain remain intact;
they cannot authorize promotion through the current policy.

Every new candidate must bind both exact records. Read-only checks require both
unchanged drafts and explicit absence of each release-tag and burn-tag ref.
Missing, unavailable, duplicated or changed observations refuse; neither retained
tag may use the current-candidate allowance. Both tags, sequences and release IDs
are unavailable for reuse or promotion. With public/burn history through 202 and
reservations 203 and 204, the next candidate is sequence 205, prospectively
v3.1.131, subject to fresh history and collision checks. It must complete its own
full qualification. The exception remains exactly these two identities, not an
open-ended ignore-list. Further additions require a separate Owner decision.

No existing draft, asset, tag, signature, stable release, repository permission or
host setting is changed by this policy. It grants no signing, live test, cleanup,
burn or publication authority.

## Read-only inventory of the retained q205 draft

On 2026-10-31 the Owner approved changing only `cleanup-unqualified` repository
contents permission from read to write so its token can inspect private draft
metadata, then separately approved a fixed `inventory_only` dispatch mode in
that job. This token has real write capability; the mode itself performs only
GETs and local evidence collection. All other jobs and ordinary failure steps
are explicitly excluded, including candidate construction, signing, publication,
deletion and VPS work. It accepts no alternate release target, credentials or
additional permissions. A mismatch or access failure stops without retry.

The pinned q205 metadata and four downloaded asset hashes are observations for a
separately approved reservation decision, not qualification or publication proof.
Neither this mode nor its retained artifact changes any draft, asset or tag.
