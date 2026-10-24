# Offline parity reference

Reference: Go commit `abbe4d7dbe9ca7de93afa6475975fc4cb35ef74a`.
No Go subprocess, network, live host, credentials or deployment is needed.

- `result-codes.tsv` freezes the six implemented setup outcome strings from
  `internal/proxyinstallation/proxyinstallation.go` (`ResultCode` constants).
  Tests obtain those outcomes by executing the public Rust API, rather than
  merely testing the enum-to-string mapping.
- `wizard-cases.tsv` records Standard-only inputs after selecting Start setup:
  name, escaped stdin, outcome key, Review count, Choose connection count.
  `\n` and `\r` denote LF and CR. A missing trailing newline is intentional.
  Menu numbers are discovered from the explicit library simulator, so Go/Rust menu ordering
  is not asserted to be identical.
- Wizard behavior comes from `internal/proxyinstallation/adapter/terminal/setup.go`
  (`runSetup`, `readSetupInput`) and `setup_test.go` (defaults, Help, Back,
  cancellation, missing input). Go's unsupported-Cloudflare fixture is the
  reference for the currently Standard-only Rust increment.
- Stale authority comes from `TestExecuteRefusesUntrustedPreparedAuthority` in
  `internal/proxyinstallation/proxyinstallation_test.go`, especially
  **stale after a later review**. A later Status, details or setup Review must
  invalidate earlier authority even if host facts and phase are unchanged.
- Recovery direction comes from `reviewOwned`, `Execute`, `setup`, and
  `finishCleanup` in `internal/proxyinstallation/proxyinstallation.go`:
  before Activation committed, Finish cleanup; after commitment, Finish setup.

The tests compare only implemented behavior and retain honest simulator labels.
They do not claim parity for real Ubuntu inspection, durable crash recovery,
Subscription Serving, credentials, removal, Software Lifecycle, outside-client
traffic, Karing, packaging, signing, publication or live qualification. The
in-memory effects counter proves only simulator non-mutation. Durable state is
owned by the core implementation worker and requires separate boundary tests.

The public executable now uses native admission and refuses an unsupported or
unqualified environment before opening the menu; it never selects simulation
automatically. Wizard assertions remain unchanged in the explicit library
terminal. `tests/menu.rs` separately exercises the real executable's closed native
entry and private/public argument refusals. These are not deployment passes.
