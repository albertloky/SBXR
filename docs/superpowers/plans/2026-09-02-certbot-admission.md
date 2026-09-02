# Certbot Admission Diagnosis Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the code task and its reviews. Host work stays with the primary agent. Albert approved the host-permission correction and code/test fixes; no release publication is authorized by this plan.

**Goal:** Preserve strict Certbot file/lock safety, report the actual refusal affecting both actions, and correct the approved host prerequisite.

**Architecture:** Keep Proxy Installation Review/Execute and its private Host Adapter. Carry bounded, secret-safe Certbot inspection diagnostics through existing preflight facts. Reuse them for Enable subscription and Rotate Client Identity; do not force either action into the legal menu. Leave shared-path validation, POSIX lock checks, and inode checks strict.

**Tech Stack:** Go 1.26.6, existing Go tests, SSH, Ubuntu systemd/rsyslog.

## Task 1: Host prerequisite and bounded verification

- [x] Recheck no queued/running acceptance and exact `/var/log` ownership/mode.
- [x] Verify baseline logging with a unique non-secret `logger` marker in both the journal and `/var/log/syslog`.
- [x] Change only `/var/log` from `0775` to `0755`, retaining UID/GID; preserve ACLs and all children. Roll back only this permission change if immediate logging verification fails.
- [x] Verify rsyslog remains active and a new marker reaches journal and syslog. Check service configuration and logrotate in non-mutating validation mode. Do not claim an actual future rotation was tested.
- [x] If safe, use unchanged v3.1.0 through its real install/setup/menu paths to check which actions the corrected host admits. Do not bypass another refusal or claim new code is installed. Clean up through Complete removal.

## Task 2: Actual refusal diagnostics and regressions

Modify `internal/proxyinstallation/adapter/host/subscription.go` and, only as needed for bounded parent diagnostics, `mutation.go`; update `internal/proxyinstallation/subscription.go` and `proxyinstallation.go`. Tests belong beside those files and at the existing terminal seam if menu rendering changes.

- [x] Add failing Host tests using real temporary directories with `/var/log` mode `0775` and root-owned-equivalent `/var/log/letsencrypt` mode `0700`. Require a diagnostic naming `/var/log` and `0775`, rejection without mutation, and cleared diagnosis after `0755`. Preserve active POSIX lock, symlink, hard-link, unsafe mode, and unknown inspection refusals.
- [x] Add failing Review tests for both affected actions: neither may be legal under failed renewal admission, both need truthful diagnostics, and neither may advise waiting when the refusal is filesystem safety. Busy work still receives bounded retry guidance. Reuse acceptedHost and existing startup/identity fixtures.
- [x] Run red checks: `GOTOOLCHAIN=go1.26.6 go test ./internal/proxyinstallation/adapter/host ./internal/proxyinstallation -run 'Certbot|Admission|SubscriptionReview' -count=1`. Confirm failure is the missing diagnosis, not test setup.
- [x] Implement the minimum bounded diagnostic data and propagate it through the existing checks. Do not add a permission exception, alternate Certbot path, public command, dependency, or automatic chmod.
- [x] Run the focused checks green, then full non-race and race checks, `go vet ./...`, and `git diff --check`. Run packages sequentially with `-p 1`; retry the release-builder package with a `30m` cumulative runner limit after its default `10m` timeout. Preserve all individual safety-test and production deadlines. Exact commands and results are in the acceptance report.

## Task 3: Review and evidence

- [x] Spec review against this approved scope, then independent code-quality review; resolve findings before completion.
- [x] Record actual host results and remaining live/release limits in the acceptance report. Preserve its original failed run as history.
- [x] Leave the completed change on `codex/certbot-admission-diagnostics`; do not publish a release, change the old Acceptance Record, or claim live Karing acceptance.
