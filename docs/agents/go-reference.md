# Retained Go product reference

Use this map when comparing historical Go product behavior or following an import
from the active [Go release evaluator](../../cmd/sbxr-release/README.md).
For a new Rust candidate, start with the [Rust product map](rust-product.md).
The package maps below retain the Go executable’s own behavior and tests.

`cmd/sbxr` selects the platform entry point and private runtime roles. Normal
zero-argument execution reaches the numbered menu in the Proxy Installation
terminal adapter. That menu calls `Review`/`Execute` for proxy actions and
Software Lifecycle for `Check`/`Recover`. Update is absent from the menu; the
compatibility Interface refuses new Update while historical transaction recovery
remains.

| Task | Start here | Follow into / focused tests |
|---|---|---|
| Executable startup and role dispatch | [cmd/sbxr/run.go](../../cmd/sbxr/run.go), [main_linux.go](../../cmd/sbxr/main_linux.go) | [run_test.go](../../cmd/sbxr/run_test.go); `go test ./cmd/sbxr` |
| Menu selection, confirmation, and result rendering | [terminal/run.go](../../internal/proxyinstallation/adapter/terminal/run.go), [lifecycle.go](../../internal/proxyinstallation/adapter/terminal/lifecycle.go) | Adjacent `run_test.go`; `go test ./internal/proxyinstallation/adapter/terminal` |
| Proxy actions and setup/removal orchestration | [proxyinstallation.go](../../internal/proxyinstallation/proxyinstallation.go) | [Proxy Installation map](../../internal/proxyinstallation/README.md); `go test ./internal/proxyinstallation` |
| Ownership Record decoding, compatibility, or resource admission | [ownership.go](../../internal/proxyinstallation/ownership.go) | `proxyinstallation_test.go`, `software_update_test.go`, and adjacent feature tests |
| Proxy status details | [details.go](../../internal/proxyinstallation/details.go) | Module tests plus terminal rendering tests |
| Reviewed certificate replacement and fault repair | [repair.go](../../internal/proxyinstallation/repair.go), [host renewal](../../internal/proxyinstallation/adapter/host/renewal.go) | `repair_test.go`, `renewal_process_test.go`; [replacement procedure](https://github.com/albertloky/SBXR/blob/c298af182cdd159a6258c0d17fb37b9b663cf4ee/docs/acceptance/mvp-live-acceptance.md#certificate-replacement-procedure) |
| Certificate snapshot publication, mismatch recovery, and ordinary-start coordination | [activation.go](../../internal/proxyinstallation/activation.go), [certificate_state.go](../../internal/proxyinstallation/adapter/host/certificate_state.go), [runtime_start.go](../../internal/proxyinstallation/adapter/host/runtime_start.go) | Adjacent certificate-state/runtime tests; [isolated Linux checks and recovery plan](../acceptance/reports/certificate-start-coordination-repair-2026-09-19.md) |
| Volatile whole-host lock creation after reboot | [lock_provision.go](../../internal/proxyinstallation/lock_provision.go), [host lock provisioning](../../internal/proxyinstallation/adapter/host/lock_provision.go), [mutation lock primitive](../../internal/softwarelifecycle/mutation_lock.go) | Adjacent `lock_provision_test.go` and `mutation_lock_test.go`, plus private-role dispatch in `cmd/sbxr/run_test.go`; `go test ./internal/proxyinstallation/... ./internal/softwarelifecycle ./cmd/sbxr` |
| Ubuntu filesystem, packages, systemd, locks, or processes | [host/host.go](../../internal/proxyinstallation/adapter/host/host.go), [mutation.go](../../internal/proxyinstallation/adapter/host/mutation.go) | Named host feature files and adjacent tests; `go test ./internal/proxyinstallation/adapter/host` |
| Subscription firewall command and enablement-link ownership | [subscription_firewall.go](../../internal/proxyinstallation/adapter/host/subscription_firewall.go), [subscription_http.go](../../internal/proxyinstallation/adapter/host/subscription_http.go) | `subscription_firewall_test.go`; `go test ./internal/proxyinstallation/adapter/host` |
| sing-box configuration and client encoding | [singbox.go](../../internal/proxyinstallation/adapter/singbox/singbox.go) | Adjacent `singbox_test.go` |
| Optional VMess WebSocket, dedicated tunnel connector and public connection check | [VMess encoding](../../internal/proxyinstallation/adapter/singbox/vmess.go), [tunnel journey](../../internal/proxyinstallation/tunnel.go), [host connector](../../internal/proxyinstallation/adapter/host/tunnel.go), [traffic probe](../../internal/proxyinstallation/adapter/host/vmess_probe.go), [terminal](../../internal/proxyinstallation/adapter/terminal/run.go) | Adjacent `vmess_test.go`, `tunnel_test.go` and `vmess_probe_test.go`; opt-in `TestDedicatedTunnelUnderIsolatedSystemd`; [setup guide](../setup-vmess-tunnel.md) |
| HTTP subscription serving and legacy HTTPS runtime | [subscriptionserving/README.md](../../internal/proxyinstallation/subscriptionserving/README.md) | `serving.go` and adjacent tests; module authority remains in Proxy Installation |
| Installed state, update ordering, transactions, and recovery | [Software Lifecycle README](../../internal/softwarelifecycle/README.md) | `status_local.go`, `latest.go`, `review.go`, `update_transaction.go`, `update_runtime.go`; `go test ./internal/softwarelifecycle/...` |
| GitHub release discovery, attestations, and supported sources | [github.go](../../internal/softwarelifecycle/adapter/github/github.go), [release_support.go](../../internal/softwarelifecycle/adapter/github/release_support.go) | Adjacent adapter tests; external dependencies stay in this adapter |

`*_linux.go`, `*_darwin.go`, and `*_other.go` select platform behavior. Tests
beside the implementation exercise those distinctions; a macOS skip is not
Linux validation. `testdata/` directories contain test inputs, not live evidence.
