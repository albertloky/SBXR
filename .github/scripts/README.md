# Release and qualification scripts

This directory contains the current release-support tooling. The current live
producer is the `mvp-live-v1` collector described in
[MVP live acceptance](../../docs/acceptance/mvp-live-acceptance.md); it records
explicit human observations and does not run the historical V4 protocol.

| Area | Entry points |
|---|---|
| Candidate declaration and dispatch | `v3-candidate-dispatch.sh` |
| MVP observation assembly and submission | `v3-mvp-evidence.py`, `v3-recurring-evidence.sh` |
| Packaged public-menu helpers | `v3-packaged-live.sh`, `v3-menu-session.py` |
| Temporary MVP log-parent window | [launcher](mvp-protected-menu.sh), [driver integration test](test_mvp_protected_menu.py), [operator plan](../../docs/acceptance/mvp-protected-log-parent-2026-09-19.md) |
| Candidate transport | `v3-qualification-transport.sh` |
| Release history and publication support | `release-history.sh`, `prepare-burn-tag.sh`, `recheck-qualified-release.sh`, `qualification-gateway-readiness.sh` |
| Authenticated release asset reads | `download-release-asset.py` |
| One-time v3.1.75 maintenance (outside release dispatch) | [helper](sbxr-snapshot-recovery/main.go), [executable driver](sbxr-snapshot-recovery/rehearse.py), [protected log-parent wrapper](sbxr-snapshot-recovery/with-protected-log-parent.sh), [command supervisor](sbxr-snapshot-recovery/protected_command_supervisor.py), [wrapper VM qualification](sbxr-snapshot-recovery/with-protected-log-parent-test.sh), [runbook comparison regression](sbxr-snapshot-recovery/test_runbook.py), and [runbook](../../docs/acceptance/v3.1.75-snapshot-recovery-runbook.md) |

`v3-packaged-live.sh` inventories the complete protected candidate footprint and
proves its absence after public cleanup, including the owned mutation-lock boot
unit, its staged publication path, and its enablement symlink. Absence checks
treat broken symlinks as present. Keep that inventory aligned with
`internal/proxyinstallation` whenever an owned host resource is added or moved;
`release_packaged_driver_test.go` owns the script-level regression checks.

The log-parent wrapper qualification is destructive and runs only as root on a
prepared disposable Ubuntu/systemd VM. With the wrapper, supervisor, and test
script staged in `/root/recovery/log-parent-qualification`, invoke it exactly as
`bash /root/recovery/log-parent-qualification/with-protected-log-parent-test.sh`.

`test_mvp_protected_menu.py` separately tests the real menu driver through the
temporary launcher and unchanged wrapper. It also requires a marked disposable
root Linux VM and refuses existing product/staging/Certbot-log fixture paths.
Use the operator plan for its scope and the adjacent Go Linux test for real
systemd/TLS behavior. Neither test contacts a public CA or qualifies a release.

`python3 .github/scripts/sbxr-snapshot-recovery/test_runbook.py` executes the
runbook's actual listener-comparison program against preservation and refusal
fixtures. Set `TMPDIR` to an absolute temporary directory under the current
local acceptance run; each test removes its fixture directory on success or failure.

The asset reader uses `gh api` and makes at most one fresh GET after a TCP read
reset, the failure observed in the unsigned `v3.1.73` draft download. It discards
the incomplete body, obtains a new redirect from the API, and exposes a completed
file atomically. Other errors and a second reset fail. Callers retain their
existing identity, size, and SHA-256 verification; release mutations are not
retried. Error logs retain the read failure and discarded byte count with URLs
redacted. `python3 .github/scripts/test_download_release_asset.py -v` exercises
the real `gh` client against a local server, including resets and HTTP refusals;
the root `release_asset_download_test.go` includes it in ordinary Go checks.

Focused helper tests live beside the scripts they exercise, including
`test_mvp_evidence.py` and `test_ssh_boundary.py`. The former
outside-probe mode is retired. Repository-root Go tests are split by concern:
`release_workflow_test.go` covers native CI; `release_candidate_workflow_test.go`
covers candidate preparation; `release_stable_workflow_test.go` covers
publication/failure; and `release_collector_test.go`,
`release_packaged_driver_test.go`, and `release_transport_test.go` cover their
matching script boundaries. The former V4 operator producer is retired; retrieve
it only to interpret historical records at
[commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator).
