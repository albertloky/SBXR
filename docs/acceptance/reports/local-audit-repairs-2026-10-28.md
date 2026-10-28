# Combined local audit repairs — 2026-10-28

Scope: reviewed working-tree repairs against `e7b774a02c601a8623c72e73afacc500232a7de1` on `main`. This is an implementation and local regression report, not stable readiness or live qualification. Final independent Go review closure and permission to commit/push were supplied by the coordinating thread after removal of the rejected experimental account mount-count guard. No other guard was relaxed during integration.

## Coverage ledger

| Area | Defect and repair | Evidence and limits |
|---|---|---|
| Rust Client Identity | Native root incorrectly selected the injected proxy runtime. Startup verification and both cutover directions now share native/injected constructor selection. | Constructor selection/refusal tests; injected-root refusal remains. Actual admitted native identity effects require Linux qualification. |
| Rust HTTP merged-/usr | Exact Ubuntu `lib -> usr/lib` layout was refused. Recognize only the protected relative alias, scan canonical vendor units, and recheck identities. | Real temporary-root merged/unmerged enablement; foreign/absolute/parent/dangling/linked/writable aliases; vendor units, drop-ins and enablement conflicts; stale prepared action refusal. Ordinary NOFOLLOW traversal remains. |
| Rust presentation | Native removal described itself as unavailable/injected; VMess typed check diagnostics were lost at the terminal boundary. | Native/injected wording and outcome tests; setup/check/finish output tests; cancellation does not replay diagnostics; secret-shaped fixture values stay absent. No change to qualification authority. |
| Go interrupted publication | Exact staged configuration and two-link token/state/unit publication could prevent cleanup; unvalidated same-inode aliases could be removed. | Configuration staging, candidate publication phases, repeated cleanup, post-link sync interruption and unsafe link/content/mode regressions. Ordinary reads still reject hardlinks. |
| Go command drainage | Inherited output descriptors could keep command return blocked after direct-child exit or cancellation. | Real local subprocess tests cover success/failure/deadline and preserve normal exit codes; incomplete drainage is unobserved. This bounds drainage, not descendant lifetime or output memory. |
| Installer/gateway/test safety | Downloads lacked total/connect deadlines; partially constructed gateway assets leaked descriptors; non-root fixture could execute a real installer entry; wrong Go toolchain silently skipped. | Both bootstrap templates use 10s connect/120s total; inert curl classification fixtures, partial-construction descriptor tests, injected non-root fixture, explicit toolchain failure. |
| Workflow/tooling | Unverifiable signing could be treated as unsigned; failure evidence was not retained; SSH lacked whole-call bounds; optimized Python bypassed fixture assertions; source snapshot ignored modes. | Positive unsigned proof, signed/unknown/rerun cases; screened bounded evidence with malformed types/partial files/link/secret refusals; transport adapter timeout/interruption tests; early optimized-fixture refusal; exact source-mode tests. No workflow dispatch or SSH operation performed. |
| Five documentation files | Stale simulator-only/closed-native/candidate-unavailable/fixture-missing/output-mode statements. | Corrected README, Rust handoff, acquisition fixture README, packaging README and Linux handoff; implementation versus live qualification remains explicit. |

## Aggregate validation

Rust fmt, all-target clippy with warnings denied, debug build, all 649 product tests (including five doctests), 12 packaging tests and five packaging Python tests passed. All ten Go packages passed across `go test -json ./...` (nine packages) and the complete host-package rerun (one package); `go vet ./...` and `git diff --check` passed. The release package completed in 435.321 seconds. No implementation changes were required during integration. Logs are local-only in [i13](../../../.scratch/acceptance/i13/). Existing Rust 1.90.0 and Go 1.26.6 are used with locked/offline Cargo and Go module downloads disabled. Temporary fixtures use the dedicated workspace-local `t/` directory with umask 022. No tool installation, live host, SSH, signing, credential or host permission changes were requested or performed by this integration run.

Two local environment failures were retained, not hidden: the first Go invocation stopped before tests because `GOSUMDB=off` conflicts with automatic toolchain selection; direct invocation of the existing Go 1.26.6 binary with `GOTOOLCHAIN=local` resolved it without downloads. The first executing aggregate failed only runtime-start tests because its 114-byte Unix-socket path exceeded the macOS limit. The complete host package passed with `/tmp/sbxr-i13` temporarily pointing to the same workspace-owned fixture directory. Both empty temporary directories and that symlink were removed. Unchanged successful packages were not rerun. No local race check was added; the existing native Verify workflow includes race and module verification.

The integration reviewed the exact diff and affected terminal/runtime, publication, collector fixture-copy and workflow callers. No additional implementation edits were needed. The final Go reviewer reported no actionable findings in the assigned patch. `host_test.go` is identical to the base; the experimental mount-count guard is absent. Existing stash and ignored evidence are preserved.

## Unresolved issues and coverage gaps

- The earlier executor receipt/denial outcome remains unknown. Local test success supplies no missing executor receipt.
- Native blocked-output cancellation remains unresolved.
- The original cross-mount account ownership gap remains unresolved; removing the rejected mount-count experiment does not resolve it.
- Go descendant quiescence remains unresolved despite bounded output drainage; a returned command result does not prove that inherited-descriptor descendants stopped.
- Actual exact-candidate live qualification, native admitted identity/removal execution, systemd/proc/cgroup effects, crash durability and optional two-node client acceptance were not run here.
- Installer deadline tests use an inert curl substitute, not a genuinely stalled TLS peer. SSH timeout tests mock process ownership/termination; real SSH fixtures were not run on this host. Optimized-fixture admission tests execute the extracted function with inert dependencies rather than running destructive scripts.
- Merged-/usr tests cover injected filesystem layouts, not privileged foreign-UID/GID changes or every concurrent alias replacement schedule. Native identity tests prove constructor selection/refusal, not a complete admitted native cutover.
- Presentation tests use explicit fixture hosts; they do not prove native terminal backpressure cancellation. Evidence screening covers known secret patterns, not arbitrary secret recognition.
- Native Linux-only and disposable-systemd/SSH fixtures must not be inferred from macOS aggregate success. The Go run skipped the explicit disposable Linux observer/startup-cleanup and root-Linux SSH fixtures, pinned-sing-box traffic test, two historical record-compatibility tests, and four foreign-owner subcases requiring privilege. Rust target-specific Linux execution is not covered merely because the macOS-selected tests report zero ignored cases.

## Exact intended change inventory

Paths below are the reviewed repair set, followed by this report and its index. No ignored evidence or stash is included.

- `.github/scripts/bounded-ssh.py`
- `.github/scripts/candidate-evidence.py`
- `.github/scripts/test_mvp_protected_menu.py`
- `.github/scripts/test_mvp_startup_cleanup.py`
- `.github/scripts/test_release_safety.py`
- `.github/scripts/test_ssh_boundary.py`
- `.github/scripts/test_ssh_boundary_account.py`
- `.github/scripts/v3-recurring-evidence.sh`
- `.github/workflows/candidate.yml`
- `README.md`
- `cmd/sbxr-release/bootstrap.go`
- `cmd/sbxr-release/gateway.go`
- `cmd/sbxr-release/gateway_test.go`
- `cmd/sbxr-release/installer_test.go`
- `cmd/sbxr-release/main_test.go`
- `docs/rust-rewrite.md`
- `internal/proxyinstallation/adapter/host/command_boundary_test.go`
- `internal/proxyinstallation/adapter/host/host.go`
- `internal/proxyinstallation/adapter/host/mutation.go`
- `internal/proxyinstallation/adapter/host/recovery_publication_test.go`
- `internal/proxyinstallation/adapter/host/subscription.go`
- `release_safety_test.go`
- `release_workflow_test.go`
- `src/host/identity.rs`
- `src/host/subscription/material.rs`
- `src/proxyinstallation/merged_usr_tests.rs`
- `src/proxyinstallation/removal.rs`
- `src/proxyinstallation/subscription_tests.rs`
- `src/proxyinstallation/tunnel.rs`
- `src/release_acquisition/testdata/README.md`
- `src/terminal.rs`
- `tests/removal.rs`
- `tests/tunnel_setup.rs`
- `tooling/rust-package/README.md`
- `tooling/rust-package/linux-validation.md`
- `tooling/rust-package/source_snapshot.py`
- `tooling/rust-package/templates/install.sh.tmpl`
- `tooling/rust-package/tests/test_release_tools.py`
- `docs/acceptance/reports/local-audit-repairs-2026-10-28.md`
- `docs/acceptance/reports/README.md`
