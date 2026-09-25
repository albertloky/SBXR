---
status: accepted
---

# Ordinary recurring live acceptance and an exact packaged upgrade route

On 2026-09-25 the Owner requested repeatable ordinary live acceptance and a
proven upgrade path, selected **v3.1.81 to the next release only** for the first
route, and approved retaining the five ordinary MVP journeys plus three live
packaged-source checks: normal update, precommit recovery, and postcommit recovery.

## Scope

`mvp-recurring-live-v1` uses the existing `recurring-subscription-upgrade`
support declaration and `sbxr-subscription-update-v1` contract. Each attempt
declares exactly one source: the freshly verified then-current Qualified Stable
Release, including exact repository, tag, commit, index digest, assets and
sequence. The initial approved source is v3.1.81/159. Supporting an older source
or multiple sources is not part of this decision. Later ordinary attempts must
qualify their own then-current source; no earlier upgrade result carries forward.

The order is the source's `precommit`, `upgrade`, and `postcommit` checks,
followed by `mvp-install`, `mvp-subscription`, `mvp-credentials`, `mvp-renewal`,
and `mvp-removal`. Precommit rollback leaves the source available for the normal
update. Before postcommit, and again before the clean-install journeys, use
reviewed Complete removal and supported fresh installation/setup as necessary.
These preparations are not themselves upgrades; no downgrade, protected-state
edit, copied authority, helper updater, or intermediate release is permitted.

The three source checks require the unchanged packaged source's own public
Update/Recover routes, actual observed interruption boundaries, exact prior
restoration before commitment, and candidate-only forward runtime completion
after commitment. Preserve creating provenance, ownership, both credentials,
Subscription Link and proxy runtime; prove outside HTTPS and proxy traffic.
Only Subscription Serving may restart for update completion. An unobserved or
missed boundary fails; a successful normal update cannot stand in for recovery.

This explicitly replaces the retired full recurring live matrix for this new
policy, not for historical records. It adds no other forced product fault,
contention, drift, outage, snap refresh, natural timer, due-renewal or client
auto-refresh journey. Applicable ordinary regressions remain required. There is
no blanket claim that the excluded historical matrix passed automatically.

## Existing safety and timing contracts remain

Keep the signed attempt, exact candidate, source support binding, native checks,
artifact/attestation verification, real disposable Ubuntu 24.04 amd64 host,
outside runner, trusted TLS, and real Karing with its selected connection
preserved. Keep 30-minute scenarios, two hours for `mvp-subscription`, five-minute
validation/submission, strict decoding, secret-safe evidence, and failure/burn
handling. The existing overall transport/job limits also remain; individual
limits are ceilings, not a promise they can all be consumed in one session.

No exception reuse, backdated confirmation, retrospective successful record, or
publication authorization is added. The v3.1.81 exception remains historical.
Machine/host and human cleanup observations must all arrive during their real
journey. The optional observation recorder timestamps explicit check-by-check
operator statements; it cannot observe the product or infer a pass.

## Compatibility with the unchanged source

v3.1.81's public reader reserves `Evidence policy`, `Live acceptance coverage`,
`Karing connectivity evidence`, and `Scenario: mvp-*` for clean-install repair.
Do not publish a new recurring record in that incompatible representation or
pretend it used the full historical matrix.

The new record explicitly uses `Recurring evidence policy`, `Recurring live
acceptance coverage`, `Recurring Karing evidence`, five `Journey: mvp-*`
references, and the existing three exact `Scenario: source-<tag>-*` references.
The same signed attempt and structured record retain the new policy and all
eight scenarios. The old reader validates its existing recurring envelope and
source references; new readers additionally require the exact new disclosures
and five journey references. Stable publication still reproduces the complete
record from validated evidence. Reader compatibility is not packaged upgrade
proof, and does not relax the source's runtime admission rules.

See the [ordinary recurring procedure](../acceptance/ordinary-recurring-live.md).
Implementation/tests do not establish current host readiness, a live pass, or
permission to consume a CA budget. The interruption mechanism must be rehearsed
against the actual execution boundary before a new release attempt, not tried
for the first time in a candidate run.
