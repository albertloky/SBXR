# Code map

Use this map to locate the implementation and tests for a change. The domain
vocabulary lives in [CONTEXT.md](../../CONTEXT.md); architectural decisions live
in [docs/adr](../adr). The [documentation index](../README.md) separates current
MVP guidance from historical material. Module READMEs explain the contracts
behind these paths.

## Product execution

`cmd/sbxr` selects the platform entry point and private runtime roles. Normal
zero-argument execution reaches the numbered menu in the Proxy Installation
terminal adapter. That menu calls `Review`/`Execute` for proxy actions and
Software Lifecycle for `Check`/`Update`/`Recover`.

| Task | Start here | Follow into / focused tests |
|---|---|---|
| Executable startup and role dispatch | [cmd/sbxr/run.go](../../cmd/sbxr/run.go), [main_linux.go](../../cmd/sbxr/main_linux.go) | [run_test.go](../../cmd/sbxr/run_test.go); `go test ./cmd/sbxr` |
| Menu selection, confirmation, and result rendering | [terminal/run.go](../../internal/proxyinstallation/adapter/terminal/run.go), [lifecycle.go](../../internal/proxyinstallation/adapter/terminal/lifecycle.go) | Adjacent `run_test.go`; `go test ./internal/proxyinstallation/adapter/terminal` |
| Proxy actions and setup/removal orchestration | [proxyinstallation.go](../../internal/proxyinstallation/proxyinstallation.go) | [Proxy Installation map](../../internal/proxyinstallation/README.md); `go test ./internal/proxyinstallation` |
| Ownership Record decoding, compatibility, or resource admission | [ownership.go](../../internal/proxyinstallation/ownership.go) | `proxyinstallation_test.go`, `software_update_test.go`, and adjacent feature tests |
| Proxy status details | [details.go](../../internal/proxyinstallation/details.go) | Module tests plus terminal rendering tests |
| Reviewed certificate replacement and fault repair | [repair.go](../../internal/proxyinstallation/repair.go), [host renewal](../../internal/proxyinstallation/adapter/host/renewal.go) | `repair_test.go`, `renewal_process_test.go`; [replacement procedure](../acceptance/mvp-live-acceptance.md#certificate-replacement-procedure) |
| Certificate snapshot publication, mismatch recovery, and ordinary-start coordination | [activation.go](../../internal/proxyinstallation/activation.go), [certificate_state.go](../../internal/proxyinstallation/adapter/host/certificate_state.go), [runtime_start.go](../../internal/proxyinstallation/adapter/host/runtime_start.go) | Adjacent certificate-state/runtime tests; [isolated Linux checks and recovery plan](../acceptance/reports/certificate-start-coordination-repair-2026-09-19.md) |
| One-time v3.1.75 snapshot maintenance handoff | [standalone helper](../../.github/scripts/sbxr-snapshot-recovery/main.go), [executable driver](../../.github/scripts/sbxr-snapshot-recovery/rehearse.py), [protected log-parent wrapper](../../.github/scripts/sbxr-snapshot-recovery/with-protected-log-parent.sh), [command supervisor](../../.github/scripts/sbxr-snapshot-recovery/protected_command_supervisor.py), [snapshot_recovery.go](../../internal/proxyinstallation/snapshot_recovery.go) | Tagged Linux executable rehearsal in `snapshot_recovery_linux_test.go`; adjacent [wrapper VM qualification](../../.github/scripts/sbxr-snapshot-recovery/with-protected-log-parent-test.sh) and [runbook comparison regression](../../.github/scripts/sbxr-snapshot-recovery/test_runbook.py); [exact VPS runbook](../acceptance/v3.1.75-snapshot-recovery-runbook.md) |
| Volatile whole-host lock creation after reboot | [lock_provision.go](../../internal/proxyinstallation/lock_provision.go), [host lock provisioning](../../internal/proxyinstallation/adapter/host/lock_provision.go), [mutation lock primitive](../../internal/softwarelifecycle/mutation_lock.go) | Adjacent `lock_provision_test.go` and `mutation_lock_test.go`, plus private-role dispatch in `cmd/sbxr/run_test.go`; `go test ./internal/proxyinstallation/... ./internal/softwarelifecycle ./cmd/sbxr` |
| Ubuntu filesystem, packages, systemd, locks, or processes | [host/host.go](../../internal/proxyinstallation/adapter/host/host.go), [mutation.go](../../internal/proxyinstallation/adapter/host/mutation.go) | Named host feature files and adjacent tests; `go test ./internal/proxyinstallation/adapter/host` |
| sing-box configuration and client encoding | [singbox.go](../../internal/proxyinstallation/adapter/singbox/singbox.go) | Adjacent `singbox_test.go` |
| HTTPS subscription artifact and serving runtime | [subscriptionserving/README.md](../../internal/proxyinstallation/subscriptionserving/README.md) | `serving.go` and adjacent tests; module authority remains in Proxy Installation |
| Installed state, update ordering, transactions, and recovery | [Software Lifecycle README](../../internal/softwarelifecycle/README.md) | `status_local.go`, `latest.go`, `review.go`, `update_transaction.go`, `update_runtime.go`; `go test ./internal/softwarelifecycle/...` |
| GitHub release discovery, attestations, and supported sources | [github.go](../../internal/softwarelifecycle/adapter/github/github.go), [release_support.go](../../internal/softwarelifecycle/adapter/github/release_support.go) | Adjacent adapter tests; external dependencies stay in this adapter |

`*_linux.go`, `*_darwin.go`, and `*_other.go` select platform behavior. Tests
beside the implementation exercise those distinctions; a macOS skip is not
Linux validation. `testdata/` directories contain test inputs, not live evidence.

## Release tooling and qualification harness

These are separate from installed product behavior. For a missing menu action,
first inspect product review/legal-action logic; for lost menu output or a
deadline failure, inspect the driver and operator wrapper.

| Task | Implementation | Checks / procedure |
|---|---|---|
| Packaging, index, bootstrap installer, or tool dispatch | [cmd/sbxr-release/main.go](../../cmd/sbxr-release/main.go), [bootstrap.go](../../cmd/sbxr-release/bootstrap.go) | Adjacent `main_test.go` / `installer_test.go`; `go test ./cmd/sbxr-release` |
| Qualification decisions and accepted wire formats | [Release stage map](../../cmd/sbxr-release/README.md), [qualification.go](../../cmd/sbxr-release/qualification.go), [scope](../../cmd/sbxr-release/qualification_scope.go), [recurring](../../cmd/sbxr-release/qualification_recurring.go), [MVP](../../cmd/sbxr-release/qualification_mvp.go) | Corresponding `qualification*_test.go`; [MVP acceptance](../acceptance/mvp-live-acceptance.md) describes `mvp-live-v1`, while historical scopes retain their interpretation |
| Candidate delivery transport | [gateway.go](../../cmd/sbxr-release/gateway.go), [v3-qualification-transport.sh](../../.github/scripts/v3-qualification-transport.sh) | `gateway_test.go`, `release_transport_test.go` |
| Authenticated release asset downloads | [download-release-asset.py](../../.github/scripts/download-release-asset.py), [recheck-qualified-release.sh](../../.github/scripts/recheck-qualified-release.sh) | `test_download_release_asset.py`, `release_asset_download_test.go`; requires `gh`, `python3`, `jq`, and `sha256sum` |
| Native CI / pinned actions | [.github/workflows](../../.github/workflows), [script map](../../.github/scripts/README.md) | `release_workflow_test.go` |
| Candidate preflight, build, draft, signing, or handoff | [Release stage map](../../cmd/sbxr-release/README.md), [.github/workflows](../../.github/workflows) | `release_candidate_workflow_test.go`, `release_candidate_handoff_test.go`, `release_declaration_dispatch_test.go` |
| Stable publication, failure, or burn record | [publication](../../cmd/sbxr-release/qualification_publication.go), [failure](../../cmd/sbxr-release/qualification_failure.go) | `release_stable_workflow_test.go` |
| Collector request or result submission | [v3-recurring-evidence.sh](../../.github/scripts/v3-recurring-evidence.sh) | `release_collector_test.go` |
| Real SSH fixture readiness, account isolation, or transport boundaries | [test_ssh_boundary.py](../../.github/scripts/test_ssh_boundary.py) | Adjacent `test_ssh_boundary_account.py` locks the caller account and proves success/failure preservation; root `v3_ssh_boundary_test.go` runs both on root Linux |
| Packaged menu results, protected-footprint inventory, interruptions, cleanup, or downloads | [v3-packaged-live.sh](../../.github/scripts/v3-packaged-live.sh), [v3-menu-session.py](../../.github/scripts/v3-menu-session.py) | `release_packaged_driver_test.go`, including exact absence and broken-link checks |
| Current MVP observation assembly and submission | [v3-mvp-evidence.py](../../.github/scripts/v3-mvp-evidence.py), [v3-recurring-evidence.sh](../../.github/scripts/v3-recurring-evidence.sh) | [MVP evidence handoff](../acceptance/mvp-live-acceptance.md#evidence-handoff), `test_mvp_evidence.py`, and `v3_mvp_evidence_test.go` |
| Ordinary recurring upgrade scope and incremental observations | [qualification_mvp.go](../../cmd/sbxr-release/qualification_mvp.go), [mvp-observe.py](../../.github/scripts/mvp-observe.py) | `qualification_mvp_recurring_test.go`, `qualification_mvp_assembly_test.go`, `recurring_mvp_test.go`, `test_mvp_observe.py`; [current recurring procedure](../acceptance/ordinary-recurring-live.md) |
| Controlled update checkpoints and creation-mask compatibility | [mvp-update-interrupt.py](../../.github/scripts/mvp-update-interrupt.py), [mvp-protected-menu.sh](../../.github/scripts/mvp-protected-menu.sh), [update_transaction.go](../../internal/softwarelifecycle/update_transaction.go) | `update_umask_test.go`, `test_mvp_update_interrupt.py`, `test_mvp_released_umask.py`, `v3_update_interrupt_test.go`; [repair report](../acceptance/reports/ordinary-recurring-umask-repair-2026-09-25.md) |
| Read-only MVP package/window observations | [mvp-inspect-window.py](../../.github/scripts/mvp-inspect-window.py), [documented SSH caller](../acceptance/mvp-protected-log-parent-2026-09-19.md#read-only-state-checks-corrected-september-22) | Adjacent `test_mvp_inspect_window.py`, opt-in `test_mvp_inspect_window_linux.py` and root `v3_mvp_window_test.go`; real pinned DEB/dpkg/SSH in a marked disposable amd64 VM |
| Temporary MVP log-parent prerequisite | [mvp-protected-menu.sh](../../.github/scripts/mvp-protected-menu.sh), [operator plan](../acceptance/mvp-protected-log-parent-2026-09-19.md) | Adjacent `test_mvp_protected_menu.py` and [isolated systemd/TLS test](../../internal/proxyinstallation/protected_log_parent_linux_test.go); uses the reviewed wrapper and [startup cancellation regression](../../.github/scripts/test_mvp_startup_cleanup.py) |
| Retired V4 producer source | [V4 tree at commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator) | Historical readers/validators remain in `cmd/sbxr-release`; do not restore or run the producer for MVP work |
| Current ordinary live procedure | [Recurring acceptance](../acceptance/ordinary-recurring-live.md), [ADR-0025](../adr/0025-ordinary-recurring-live-acceptance.md) | Five normal MVP journeys plus the exact source's update, rollback and forward recovery; the old clean-install policy retains its meaning |
| Find a historical V4 scenario or its controls | [Retired Operator README](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/README.md) | [V4 scenario procedures](../acceptance/historical/v4-operator-procedures.md) |
| Historical V4 evidence timing or assembly | [Retired assembly source](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/assemble-evidence.py), [retired timing source](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/evidence-timing.py) | [Assembly guide](../acceptance/historical/evidence-assembly.md) |

The retired operator producer grouped numbered entry scripts with
`identity-*`, `link-*`, `managed-*`/`recorder-*`, and `test_*`/`rehearse-*`.
Use the cited commit when interpreting a historical record. It is not part of
the current MVP path.

## Choosing validation

Use the Go toolchain declared in [go.mod](../../go.mod). From the repository root,
choose a short local run name (replace `r1` as needed):

```sh
(
  set -eu
  umask 022
  run="$PWD/.scratch/acceptance/r1"
  mkdir -p "$run"
  export TMPDIR="$run/t"
  mkdir "$TMPDIR" # Refuse to reuse an existing temporary directory.
  trap 'rmdir "$TMPDIR" || exit 1' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  GOTOOLCHAIN=go1.26.6 go test ./...
  GOTOOLCHAIN=go1.26.6 go vet ./...
)
```

The subshell keeps these settings local and removes its newly created temporary
directory after the tools clean their fixtures. If a failure or interruption
leaves files behind, cleanup fails rather than deleting them; inspect and clean
only that run's disposable fixtures. Retain logs and useful evidence outside `t/`.

Host-adapter fixtures expect newly created files to have the current user's group.
Use a workspace-local directory owned by that user and group, not macOS
`/private/tmp`, which can give fixtures the `wheel` group.

On macOS, runtime-start tests also create Unix sockets under `TMPDIR`. Long
absolute paths can exceed the operating system's socket-path limit and fail
with `bind: invalid argument`. Keep the run name short, as in the recipe above.

The tables identify narrower package tests during development. Root Go tests
cover architecture, dependencies, script integration, and workflow contracts;
they are intentionally rooted here because they read repository-relative files.

For current MVP qualification changes, start with the focused Go/Python tests
and [MVP procedure](../acceptance/mvp-live-acceptance.md). Do not run the retired
V4 rehearsal or `check-readiness.py` for an MVP candidate. To interpret a
historical V4 record, use the cited retired source; do not restore the producer.
Local fixtures and tests do not establish live qualification or Karing acceptance.

## Documentation and historical material

- [docs README](../README.md): documentation entry point and current/historical routing.
- [README.md](../../README.md): product overview and navigation.
- [CONTEXT.md](../../CONTEXT.md): the single domain glossary.
- [ADR-0025](../adr/0025-ordinary-recurring-live-acceptance.md) and [ordinary recurring acceptance](../acceptance/ordinary-recurring-live.md): five ordinary journeys plus exact-source update and both recovery directions. [ADR-0023](../adr/0023-mvp-live-acceptance.md) retains the five-journey clean-install policy.
- [acceptance README](../acceptance/README.md): current procedure and historical acceptance routing.
- [research README](../research/README.md): investigation notes and their authority limits.
- [ADR index](../adr/README.md): decisions grouped by applicable scope and era.
- [Acceptance reports](../acceptance/reports/README.md): dated results, separate
  from current procedures. A report describes its named run, not current host state.
- [Historical acceptance](../acceptance/historical/README.md): retired procedures.
- [Installer-Updater release procedure](../acceptance/historical/installer-updater-release.md): historical Installer-Updater
  release-pair procedure, not the current MVP procedure.
- [Historical plans](../history/README.md): retained design and implementation plans.

Local scratch and research files may contain unfinished user work. Inspect their
Git status before reorganizing them; use tracked source and current procedures
to determine implemented behavior.

Follow [the test-file and artifact locations guide](files-and-artifacts.md).
Tests live beside their code, run artifacts under `.scratch/acceptance/`, and
readable reports under `docs/acceptance/reports/`. `.scratch/` is excluded from Git and
normal source searches.
