# Sticky mutation lock parent fix

Approved scope: fix subscription lock admission and rerun available acceptance,
excluding the natural multi-day Certbot test. Do not publish a stable release or
change the shared `/run/lock` permissions.

## Design

For the exact `/run/lock/sbxr.lock` path, allow a real, expected-owner `/run/lock`
directory with the sticky bit set. Keep strict ancestor checks, and continue to
reject writable non-sticky parents. Other paths retain the existing parent policy.
Reuse the existing read-only lock authority acquisition, including ownership,
0600 mode, regular-file, one-link, no-follow, and mutual-exclusion checks.
Independent review identified a FIFO denial-of-service at the newly admitted
shared parent. Add nonblocking open to existing-lock acquisition so the existing
type check can refuse a FIFO without waiting for a writer; regression uses a
bounded child process.

## Execution

1. Add a real-filesystem regression in `internal/proxyinstallation/adapter/host/subscription_test.go`.
   Run `GOTOOLCHAIN=go1.26.6 go test ./internal/proxyinstallation/adapter/host -run TestSubscriptionReviewLock -count=1`; confirm the sticky-parent case fails.
2. Change only the parent admission in `AcquireSubscriptionReviewLock` in
   `internal/proxyinstallation/adapter/host/subscription.go`. Add negative safety
   cases, then rerun the focused tests.
3. Review the diff independently. Run host and lifecycle tests, broad tests,
   race checks, vet, and a Linux build. Run the focused test binary on the
   disposable Ubuntu VPS to check Linux semantics; this is not packaged acceptance.
4. Record results and commit only intended files. Live product acceptance needs
   an authorized, correctly identified candidate through the release workflow;
   never substitute new bytes for public `v3.1.0` or edit protected records.

Self-review: the exception is confined to the shared lock's exact path; no global
parent-policy change, dependencies, alternate runtime, or directory mutation.

Outcome: implementation, red/green regressions, independent review, full normal
suite, affected-package race suites, vet, dependency verification, both Linux
architecture builds, and root/Linux focused checks passed. VPS test fixtures were
removed with shared directory permissions unchanged. Packaged live acceptance is
blocked by the existing transport refusing recurring subscription candidates;
extending that route remains outside this approved lock fix. Evidence is in
`docs/acceptance/v3.1.0-live-acceptance-2026-09-02.md`.
