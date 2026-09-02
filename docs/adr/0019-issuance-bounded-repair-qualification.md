---
status: accepted
---

# Bound repair qualification to the production issuance budget

On 2026-09-02 Albert approved retaining production HTTPS and the complete exact
Karing journey while moving repeated destructive cases that exceed the
certificate limit to automated-only evidence. This supersedes ADR-0018's full
live-matrix requirement only for `subscription-clean-install-repair`. It changes
evidence coverage, not production behavior, certificate trust, or stable-publication
authority. Other scopes and historical signed attempts keep their contracts.

Require the signed attempt to name `repair-issuance-bounded-v1` and the exact
ordered automated-only list below. Keep its remaining ordered scenarios mandatory
live checks. Native amd64 and arm64 full automated/race suites remain mandatory;
an automated-only case is never a live pass or Not applicable. The Acceptance
Record must publish the policy, exact automated-only list, and that distinction.
Missing, changed, duplicate, or extra cases refuse. The old Owner waiver remains
unavailable. Exact baseline, bytes, signatures, source exclusions, clocks, failure
burns, and secret-containment rules remain unchanged.

Automated-only scenarios, in original matrix order:

```text
enable-precommit enable-postcommit enable-schema2-absent
repair-precommit repair-postcommit activation-precommit activation-postcommit invalid-replacement
recorder-start recorder-outcome recorder-stale recorder-retention recorder-death recorder-reboot
remove-enable-precommit remove-enable-postcommit remove-link-precommit remove-link-postcommit
remove-repair-precommit remove-repair-postcommit remove-activation-precommit remove-activation-postcommit
remove-identity-precommit remove-identity-postcommit
remove-death remove-reboot remove-shared-route remove-finalization remove-exact-restoration
```

These repeated enablement, certificate replacement, failed-recorder recovery, and
complete-removal cycles require fresh issuance or recovery that can consume the
same production allowance. Keep the no-certificate proxy baseline, both link
boundaries, the supported interrupted managed attempt and reviewed production
repair, recorder live/lock checks, supported snap refresh, unsupported-route
accounting, Client Identity/session/startup/fallback checks, lifecycle menu,
active-writer/removal refusal checks, live secret containment, and final Karing.

Plan three production issuances: initial enablement, the mandatory managed-renewal
repair, and enablement after the absent-subscription identity scenario. Preserve
the last healthy installation through final Karing and its Complete removal.
This is a request budget, not proof of available CA capacity or a successful test.
No retry after an unexpected failure may borrow earlier passes. Do not probe the
CA by issuing extra certificates, change identifiers/accounts to avoid limits,
use staging trust, restore deleted lineage state, or extend the six-hour transport.
Natural timer firing and naturally due renewal remain excluded and Not observed.
