# Disclosure fixtures

`client-standard.json` and `client-vless-vmess.json` are exact client JSON bytes
emitted by the current Go sing-box adapter using the existing synthetic server
fixtures and public IPv4 `8.8.8.8`. Regenerate from repository root with
`GOTOOLCHAIN=go1.26.6 GOPROXY=off go run tests/testdata/disclosure/generate.go`.
No credential generation, remote request, or host configuration effect occurs.

The Rust tests exercise the injected public Session/Host seam with retained RAII
locks, shared observations, exact record CAS and partial output. Protected reads
are injected metadata proofs, not native filesystem qualification. A native host
must establish those proofs from bounded no-follow descriptors and protected
parents. No serving health observation is substituted for token/state agreement.

Behavior references: Go `TestOwnerCanReviewDeclineAndDiscloseOneRunningClientConfiguration`,
`TestSubscriptionProblemPreservesConfirmedClientConfigurationFallback` (the confirmed fallback
cases in `serving_test.go`), `TestSubscriptionLinkRedisclosureRequiresExactProtectedCredential`,
`TestFailedRevocationKeepsOldLinkWorkingAndSecurityProblemVisible`, and terminal
disclosure/output tests. Compromise marking uses the existing Rust authority
transition, with explicit confirmation; Go has no separate compromise menu action.

These are local synthetic regression fixtures, not deployment or live evidence.

## Owner composition

The module is exported normally and the integration tests use that public
export. The protected Host and shared Owner/output routing are now implemented, with
additional real-filesystem/output tests in `src/proxyinstallation/subscription_tests.rs`.
This worker's pure tests do not themselves establish native deployment proof.

`Session<H: Host>` owns the injected host and Review generation:

- `status()` returns secret-free availability/compromise flags, reading no client
  configuration or subscription credential.
- `review(Action)` returns an opaque single-use `Prepared`. `Action::plan()`
  supplies the exact client warnings or compromise-marking explanation.
- `execute(prepared, Confirmation, Option<&mut dyn Write>)` confirms and freshly
  revalidates under the retained guard. Client output is framed and flushed;
  output failure is `Error::Output`, never successful display. Compromise marking
  uses the existing `OwnershipRecord::mark_subscription_compromised` transition
  and one exact durable CAS. `Error::Publication` preserves uncertain outcome.
- `view_details()` returns an optional redacted `SubscriptionLink` after exact
  canonical token/digest/serving-state agreement. `write_link` warns, writes and
  flushes it. It permits the authoritative source during pending link work, never
  reads a candidate, and never completes a change. Current HTTP and retained
  historical HTTPS keep their schemes.
- Every review/status/details call expires earlier prepared authority. The
  composed Owner must call `expire()` for its other Review actions too.
  `host_mut()` also expires authority before another flow uses that host;
  `into_host()` recovers the host. `cancellation()` returns the shared stop handle.

A concrete host implements `acquire`, `verify_guard`, `snapshot`, `inspect`,
`read(Material)`, and `publish`. Read operations need protected, bounded no-follow
reads and independent installed-release/ownership/runtime proofs, represented by
`Inspection`, `RunningFacts`, and `FileProof`. Configuration reads require exact
root:sing-box `0640` using the independently resolved and reviewed sing-box GID;
subscription token/state reads require root:root `0600`. Publication needs expected-current
CAS and file/directory durability, with uncertain failures reported rather than
retried. This slice supplies no native host adapter. Tests model these effects;
their metadata observations are not native OS proofs.

Go has no separately named compromise-marking menu action. The new confirmed
operation exposes the existing Rust authority transition; it neither stops
serving nor replaces a credential. Failed replacement cleanup keeps compromise
visible, while only completed link rotation clears it.

The Host's default namespace owner remains UID/GID 0. Explicit filesystem
fixtures override the independently pinned namespace owner to match their real
OS owner; native construction still requires root:root. Configuration GID stays
independently resolved rather than copied from the file. This permits actual
protected-file tests on macOS without creating a privileged user or changing
real host security settings.
