# Release and qualification scripts

This directory contains the current release-support tooling. The current live
producer supports `mvp-live-v1` and `mvp-recurring-live-v1`, described in
[ordinary recurring acceptance](../../docs/acceptance/ordinary-recurring-live.md)
and [MVP live acceptance](../../docs/acceptance/mvp-live-acceptance.md); it records
explicit human observations and does not run the historical V4 protocol.

| Area | Entry points |
|---|---|
| Candidate declaration and dispatch | `v3-candidate-dispatch.sh` |
| One-target r24 evidence applicability | `late-confirmation-review.py`, `test_late_confirmation_review.py`; [ADR-0024](../../docs/adr/0024-r24-late-confirmation-supplement.md) |
| MVP observation assembly and submission | `v3-mvp-evidence.py`, `v3-recurring-evidence.sh` |
| Incremental explicit operator observations | `mvp-observe.py`, `test_mvp_observe.py`; no product driving or automatic pass |
| Packaged public-menu helpers | `v3-packaged-live.sh`, `v3-menu-session.py` |
| Ordinary source update interruption | `mvp-update-interrupt.py`, `test_mvp_update_interrupt.py`; [controlled interruption](../../docs/acceptance/ordinary-recurring-live.md#controlled-update-interruption) |
| Temporary MVP log-parent window | [launcher](mvp-protected-menu.sh), [driver integration test](test_mvp_protected_menu.py), [startup cancellation regression](test_mvp_startup_cleanup.py), [operator plan](../../docs/acceptance/mvp-protected-log-parent-2026-09-19.md); use the driver's `--protected-wrapper` opt-in |
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

For the current MVP's installed-candidate check, use the
[documented SSH handoff](../../docs/acceptance/mvp-live-acceptance.md#checking-the-installed-candidate-over-ssh).
It streams this module and calls only `exact_candidate`; the current transport
does not stage `/run/sbxr-qualification/v3-packaged-live.sh`. The existing four-file
temporary-menu staging is unchanged. `release_candidate_handoff_test.go` covers
fresh-shell and streamed-source identity checks; `test_ssh_boundary.py` executes
the documented command over real SSH with the old helper path absent, and proves
refusal stops continuation without changing the synthetic installation.
The fixture supplies a read-only, synthetic password-disabled root shadow
record inside its private mount namespace, so key-only SSH does not inherit a
cloud image's locked-root/PAM policy. It never unlocks the host account.
`test_ssh_boundary_account.py` runs the same 25 real-SSH cases beneath a
deliberately locked caller account and exercises post-readiness failure cleanup;
both paths preserve the caller and host shadow records. The root Go integration
test includes both scripts. These Linux/root namespace tests are local regression
checks, not live acceptance.

The log-parent wrapper qualification is destructive and runs only as root on a
prepared disposable Ubuntu/systemd VM. With the wrapper, supervisor, and test
script staged in `/root/recovery/log-parent-qualification`, invoke it exactly as
`bash /root/recovery/log-parent-qualification/with-protected-log-parent-test.sh`.

`test_mvp_protected_menu.py` separately tests the real menu driver through the
temporary launcher and reviewed wrapper. It also requires a marked disposable
root Linux VM and refuses existing product/staging/Certbot-log fixture paths.
Use the operator plan for its scope and the adjacent Go Linux test for real
systemd/TLS behavior. Neither test contacts a public CA or qualifies a release.

The repaired launcher sets `umask 022` only in the child that execs the unchanged
product; the pinned wrapper and supervisor retain private `077` state files.
`test_mvp_released_umask.py` exercises a diagnostic test binary built from the
frozen v3.1.81 source through that actual launcher. Copy
`testdata/released-umask-main_test.go` into its disposable
`internal/softwarelifecycle` package to select the four existing source tests;
stage the unchanged `subscription-absent-schema2.json` fixture at its repository
path. This is source-level Update/Recover evidence, not original packaged-binary
execution. The test requires the marked disposable VM and restores its paths.

`mvp-update-interrupt.py` reuses the real menu session, with an argv form only
for the fixed wrapper/tracer process chain. The ordinary executable-string
callers retain their behavior. It stops the real source at a successful durable
checkpoint syscall and leaves public recovery and outside checks to the operator.
Its separately staged controller imports the existing protected menu driver
without writing bytecode into the four-file directory. Use the
[current operator procedure](../../docs/acceptance/ordinary-recurring-live.md#controlled-update-interruption).
`test_mvp_update_interrupt.py FIXTURE` requires the marked root VM; build its
synthetic native Go fixture from `testdata/update-interrupt-fixture`. It tests
18 success/refusal/cancellation cases with real Linux tracing and cleanup,
not a packaged upgrade or CA operation. `v3_update_interrupt_test.go` provides
portable syntax checks and an opt-in `SBXR_UPDATE_CONTROL_VM=1` root VM wrapper.
The extended amd64 rehearsal currently fails early-deadline wrapper cleanup;
this controller is **not cleared for live dispatch**. Preserve that failure and
follow the [repair report](../../docs/acceptance/reports/ordinary-recurring-umask-repair-2026-09-25.md)
before another run. Do not treat the ARM64 fixture pass as resolving it.
The new recorder handoff adds four actual streamed-SSH cases to the earlier 21.

The read-only `mvp-inspect-window.py` replaces run-local package/window probes.
Use its [documented SSH call and receipt inputs](../../docs/acceptance/mvp-protected-log-parent-2026-09-19.md#read-only-state-checks-corrected-september-22).
It queries the installed held package independently of the deliberately removed
DEB and compares the Ownership Record string, not the declaration object.
Snap images may have snapd cache hard links; root ownership, regular-file type,
non-writable group/other permissions, no xattrs, and exact receipts are still
required. Other protected files keep the one-link rule.
`test_mvp_inspect_window.py` covers portable contracts and, when run as root on
Linux, real snap/cache hard links and metadata/content refusals;
`test_mvp_inspect_window_linux.py VERIFIED_DEB` exercises the exact documented
call through loopback SSH, real dpkg install/hold/purge of the pinned official
amd64 package, the existing driver/launcher/wrapper, timer/lock refusals and
fixture cleanup. It refuses anything other than an explicitly marked disposable
root amd64 Linux VM with absent fixture resources. SBXR records/menu and snap
CLI/images are synthetic, with real snap/cache hard links; no CA or product
acceptance is claimed. Keep egress
restricted. The opt-in root Go wrapper uses `SBXR_MVP_OBSERVER_DEB`.

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
