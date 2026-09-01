# #357: Subscription qualification preflight

Observed on 2026-09-01 UTC from checkout `26488284602825c7ffbb409d5bb4f6b3d4176786`.

**Disposition: blocked before candidate construction and the signed acceptance boundary. Keep [#357](https://github.com/albertloky/SBXR/issues/357) open.** This is a read-only preflight report, not an Acceptance Record or a failed signed attempt. No candidate identity was selected or burned, no qualification scenario was started, and no VPS mutation or release publication was performed.

## Authority and immediate blocker

Both native prerequisites, #355 and #356, are CLOSED; #357 reports zero open blockers. The first subscription release uses the explicit clean-install scope in [#342's approved decision](https://github.com/albertloky/SBXR/issues/342#issuecomment-5494248873), [ADR-0016](../adr/0016-v3-proxy-product-and-modules.md#approved-scope-change-first-subscription-release-uses-clean-installation), and the [qualification procedure](v3-packaged-live.md).

The available SSH target `RackNerd` has an active existing proxy installation. Read-only SSH inspection found:

| Fact | Observation |
|---|---|
| Operating system | Ubuntu 24.04, `x86_64` |
| Executable | `/usr/local/bin/sbxr` present; SHA-256 matches its Installed Record |
| Installed authority | `/var/lib/sbxr` and `/var/lib/sbxr/installed.json` present |
| Proxy footprint | `/etc/sing-box` present; `sing-box` active |
| Qualification footprint | `/run/sbxr-qualification` absent |
| Interruption tool | `/usr/bin/strace` present |
| GitHub activity | No queued or in-progress runs at the preflight observation |

This host fails the candidate workflow's required absence checks. The GitHub environment's secret host value was not available for comparison; this report does not assert that `RackNerd` is the configured `acceptance-vps` target. An active service is not proof of outside traffic or complete installation health.

The approved scope decision explicitly does not authorize removal of a live installation. Before using `RackNerd`, obtain explicit Owner authorization for its supported reviewed Complete removal and its use as a disposable Acceptance VPS, including the required interruptions and reboot scenarios. Removal entails downtime, loss of the old proxy credentials, and new client setup. Prove `Not installed` through the old release's supported removal/finishing route before any clean installation; do not delete protected authority, install over it, or describe this transition as an upgrade. A separately approved clean disposable VPS is also possible.

Recheck host identity, installation state, GitHub activity, package activity, and workflow environment binding immediately before any authorized mutation. This snapshot does not authorize later work against changed state.

## Verified current stable baseline

The current checkout's production `verify-public-latest` command returned `accepted`. Its Release Identity matches the fields read from `RackNerd`'s Installed Record:

| Field | Value |
|---|---|
| Repository | `albertloky/SBXR` |
| Tag | `v3.0.21` |
| Commit | `989094b9766f02bf17510a71753c6a5c736bf120` |
| Release index SHA-256 | `90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331` |
| Release Sequence | `82` |
| Installed Record schema / architecture | `1` / `amd64` |

This confirms the observed stable baseline, not first-subscription eligibility. Complete release-history verification, exact candidate assets, empty incoming-source binding, package/runner facts, and publication-time revalidation remain required in the signed attempt. Incoming source upgrades and two-release recovery must be recorded as Not applicable for the first clean-install scope, never Passed.

## Karing package preflight

The official [Karing Latest release](https://github.com/KaringX/karing/releases/tag/v1.2.23.2606) was non-draft and non-prerelease:

| Field | Value |
|---|---|
| Release | `v1.2.23.2606` |
| Asset | `karing_1.2.23.2606_macos_universal.dmg` |
| Size | `102859263` bytes |
| Official asset SHA-256 | `6f421213b6208e3abc1eda6fdd8ddc2014239c7f4241387749ae3a3729c658ea` |
| Local Mac | macOS `26.6.2`, build `25G83`, `arm64` |
| Installed app metadata | `/Applications/Karing.app`, `com.nebula.karing`, version `1.2.23`, build `2606` |

Matching app metadata does not establish exact downloaded package or installed-byte identity. No Karing profile, settings, connection, import, or refresh was changed or tested. Exact-package verification and the final uninterrupted Karing journey remain missing. Retain `static-official-evidence-passed-live-karing-pending`; do not claim client compatibility from this preflight.

## Automated evidence and remaining work

[Verify run 33516112169](https://github.com/albertloky/SBXR/actions/runs/33516112169) passed on the exact inspected checkout for native Ubuntu 24.04 `amd64` and `arm64`. Both jobs passed focused/full tests, race checks, vet, four-asset package construction/verification, packaged root/menu checks, and package-surface secret scans. These are automated verification packages, not a signed subscription candidate or live acceptance evidence.

Local checks used `GOTOOLCHAIN=go1.26.6`: focused qualification scope/recurring tests, `go vet ./...`, and `go mod verify` passed. Repository-wide test results are recorded with the delivery comment after completion.

No full runner/VPS/Mac/terminal capture-coverage or exact-secret absence claim is made. The observations above exclude credentials, complete Subscription Links, configuration, private keys, raw addresses, and raw process output. All applicable packaged scenario families, actual Certbot/snap package facts, outside-network observations, serving-sandbox credential denial, comprehensive secret containment, and final Karing/removal evidence remain required. Natural timer firing and naturally due renewal are Not observed; unsupported new/renamed renewal-route accounting retains its stated limit.

After host authorization and readiness, construct one exact candidate through the existing workflow, obtain the signed handoff, and drive the complete applicable matrix with its original scenario clocks. Only a successful complete attempt can produce the required Acceptance Record and justify closing #357. Stable publication remains separately gated.
