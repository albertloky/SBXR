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
| Packaged menu results, interruptions, cleanup, or downloads | [v3-packaged-live.sh](../../.github/scripts/v3-packaged-live.sh), [v3-menu-session.py](../../.github/scripts/v3-menu-session.py) | `release_packaged_driver_test.go` |
| Current MVP observation assembly and submission | [v3-mvp-evidence.py](../../.github/scripts/v3-mvp-evidence.py), [v3-recurring-evidence.sh](../../.github/scripts/v3-recurring-evidence.sh) | [MVP evidence handoff](../acceptance/mvp-live-acceptance.md#evidence-handoff), `test_mvp_evidence.py`, and `v3_mvp_evidence_test.go` |
| Retired V4 producer source | [V4 tree at commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator) | Historical readers/validators remain in `cmd/sbxr-release`; do not restore or run the producer for MVP work |
| Current MVP live procedure | [MVP acceptance](../acceptance/mvp-live-acceptance.md), [ADR-0023](../adr/0023-mvp-live-acceptance.md) | Five normal journeys: install, subscription, credentials, renewal, and removal |
| Find a historical V4 scenario or its controls | [Retired Operator README](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/README.md) | [V4 scenario procedures](../acceptance/v4-operator-procedures.md) |
| Historical V4 evidence timing or assembly | [Retired assembly source](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/assemble-evidence.py), [retired timing source](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/evidence-timing.py) | [Assembly guide](../acceptance/evidence-assembly.md) |

The retired operator producer grouped numbered entry scripts with
`identity-*`, `link-*`, `managed-*`/`recorder-*`, and `test_*`/`rehearse-*`.
Use the cited commit when interpreting a historical record. It is not part of
the current MVP path.

## Choosing validation

Use the Go toolchain declared in [go.mod](../../go.mod). From the repository root:

```sh
umask 022
GOTOOLCHAIN=go1.26.6 go test ./...
GOTOOLCHAIN=go1.26.6 go vet ./...
```

Host-adapter fixtures expect newly created files to have the current user's
group. On macOS, `/private/tmp` can instead give them the `wheel` group. If that
causes ownership assertions to fail, set `TMPDIR` to a temporary directory owned
by the current user and group before running the tests.

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
- [ADR-0023](../adr/0023-mvp-live-acceptance.md) and [MVP live acceptance](../acceptance/mvp-live-acceptance.md): the current five-journey clean-install scope.
- [acceptance README](../acceptance/README.md): current procedure and historical acceptance routing.
- [research README](../research/README.md): investigation notes and their authority limits.
- [docs/adr](../adr): decisions, including scope-specific historical contracts.
- [docs/acceptance](../acceptance): current procedures alongside historical
  procedures and dated reports. A report describes its named run, not current
  host state.
- [acceptance/RELEASE.md](../../acceptance/RELEASE.md): historical Installer-Updater
  release-pair procedure, not the current MVP procedure.
- `docs/superpowers/`: historical design and implementation plans.

Local scratch and research files may contain unfinished user work. Inspect their
Git status before reorganizing them; use tracked source and current procedures
to determine implemented behavior.

Follow [the test-file and artifact locations in AGENTS.md](../../AGENTS.md#test-files-and-local-artifacts).
Tests live beside their code, run artifacts under `.scratch/acceptance/`, and
readable reports under `docs/acceptance/`. `.scratch/` is excluded from Git and
normal source searches.
