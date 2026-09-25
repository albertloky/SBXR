# Recurring candidate delivery implementation plan

Owner authorization: fix all blockers to remaining live acceptance without asking
for each follow-on fix. Exclude natural multi-day Certbot renewal. Do not publish
a stable release, bypass signatures, change old release bytes, fabricate evidence,
or modify protected product authority.

## Design and execution

- [x] Extend the existing gateway's version-3 admission from only
  `v3-subscription-clean` to also `v3-recurring`; retain
  `validStableFailureManifest` and exact asset validation. In
  `cmd/sbxr-release/gateway_test.go`, exercise both scopes using bound indexes and
  reject mismatched scope/source declarations. First run the new recurring case
  red, then change the admission guard in `gateway.go` and rerun green.
- [x] Extend the existing GitHub Adapter's signed-attempt admission in
  `internal/softwarelifecycle/adapter/github/github.go`. Match the manifest state
  to support scope, compare candidate index exactly, convert qualification-wire
  source identities explicitly, require nonempty bounded unique recurring sources,
  and match each declared source to the verified package's source list. Preserve
  first-clean and historical refusal behavior. Exercise the real CheckLatest
  path in `github_test.go`, including changed or missing source identities.
- [x] Verify the unchanged public source's admission behavior separately. No new
  candidate can repair code already frozen in a source package. Record that limit
  honestly instead of weakening evidence or inventing a bridge.
- [x] Run focused tests with `GOTOOLCHAIN=go1.26.6`, independent spec/security
  review, full tests, affected race tests, vet, builds, and diff checks. Update the
  packaged-live delivery documentation, commit only scoped files, and integrate
  through a checked fast-forward only if the complete route is usable.
- [ ] Prepare the exact signed candidate through the existing workflow only when
  its fixed source/scenario prerequisites are achievable. Drive supported packaged
  operations and retain real evidence. At an unexpected failure stop that attempt,
  perform safe cleanup, fix the cause, and use a new identity; never borrow passes.

Self-review: reuse the existing delivery and qualification authority; no new
product entry point or new evidence waiver. Source compatibility is a separate
hard prerequisite, not inferred from successful candidate installation.

Outcome: source fixes and verification completed. Both reviews found no
actionable issues. Preserve and push the fix branch without merging to main.
The last task is blocked by the unchanged published source's incompatible
candidate admission; no qualified attempt can complete under the present rules.
Details: `docs/acceptance/recurring-delivery-fix-2026-09-02.md`.
