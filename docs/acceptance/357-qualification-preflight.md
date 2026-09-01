# #357: Subscription qualification preflight

## Owner-directed ticket closure, 2026-09-01 UTC

Albert rejected multi-day scope and explicitly directed: “multi-day scope is not included in live qualificationa t first, so do other test and commit and push and close the ticket.” Close #357 after the remaining automated verification and delivery. This supersedes this report's earlier instructions to keep the ticket open; it does not turn unobserved scenarios into passes or create a successful Acceptance Record.

ADR-0016 already excludes waiting multiple days for natural renewal. Natural timer firing and naturally due renewal remain **Not observed**. The separately identified repeated-issuance budget below explains why the complete signed matrix was not attempted; it does not add a multi-day requirement to this ticket. No multi-day implementation or automation is authorized or included.

The existing signed collector requires the ordered complete scenario list and a cumulative validated prefix. It has no partial-success route. No new signed attempt was started for a knowingly incomplete matrix. Signed packaged VPS scenarios, outside-network subscription/rotation proof, complete secret-capture coverage, and the final Karing journey remain missing. Retain `static-official-evidence-passed-live-karing-pending`. Ticket closure is an Owner-directed work disposition, not Release Qualification success; the existing stable-publication gate remains unchanged.

Final verification on checkout `0ef6a0d6733ad80c9bbe2fb7851e11fca46fe938` (only this report changed afterward):

- `GOTOOLCHAIN=go1.26.6 go test ./... -count=1`: passed all ten packages.
- `GOTOOLCHAIN=go1.26.6 go test -race ./... -count=1`: passed all ten packages.
- `GOTOOLCHAIN=go1.26.6 go vet ./...` and `GOTOOLCHAIN=go1.26.6 go mod verify`: passed.
- Ruby YAML parsing of all three workflows and `bash -n` on all 30 embedded run blocks: passed. `git diff --check`: passed.
- [Verify run 33528137052](https://github.com/albertloky/SBXR/actions/runs/33528137052): passed native Ubuntu `amd64` and `arm64` jobs, including four-asset construction/verification, packaged production menu checks, race checks, and package-surface secret-marker scans.
- The workflow's prohibited-marker pattern found no match in the two new local test logs or this report. This bounded scan does not prove absence on uncollected runner/VPS/Mac surfaces.
- Final Standards and Spec reviews of the closure disposition: zero actionable findings on each axis.

No production code, acceptance validator, or release policy changed in this closure commit. The earlier observations and exact candidate/package identities remain historical evidence under their original limits.

## Historical disposition after earlier Owner approvals

Albert approved using `RackNerd` as the disposable Acceptance VPS, including reviewed Complete removal, downtime, new credentials/client setup, and the required interruption/reboot scenarios. That authorization remains valid; do not ask for the same host authorization again.

The installed `v3.0.21` executable performed its supported reviewed Complete removal on 2026-09-01, from `15:02:15.654937 UTC` to `15:02:29.241710 UTC`. Its zero-argument menu received the exact `REMOVE SBXR` confirmation and returned exit `0`, `SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED`, and `SBXR is not installed.` Fresh inspection proved absence of the executable, `/var/lib/sbxr`, finalization authority, proxy configuration/state, SagerNet APT source/key, and installed sing-box package. The original SSH session survived; a new SSH connection succeeded; the SSH service remained active and the observed routing table was unchanged. This was preparatory removal, not a signed candidate scenario or upgrade.

Albert subsequently approved extending the existing signed qualification channel for version 3, including isolated transport and safe reboot/removal restoration. That authorization also remains valid. The implementation below resolves the identified draft-access code gap. Candidate `v3.1.0`, sequence `83`, was constructed from `6dcbaf694d7418cf432dafa0bf804d76c81e96ac`, but signing was stopped for the confirmed issuer-budget conflict below. No signed attempt or candidate burn occurred. #357 remains OPEN until the complete exact packaged and Karing attempt passes.

### Current blocker: production issuance budget

The [official Let's Encrypt limits](https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers), updated 2026-08-05, allow five new certificates for one exact identifier set in seven days, replenishing one slot about every 34 hours. That limit has no override. ARI renewal orders can be exempt, but ordinary repeated orders remain limited.

Inspection of the exact official Certbot `5.6.0` revision `5603` package found that `certbot/_internal/client.py` calls `new_order(csr_pem, profile=profile)`, and its bundled `acme/client.py` constructs `NewOrder` with identifiers/profile only. It sends no ARI replacement identifier. The exact downloaded `5.7.0` revision `5781` ACME client has the same order construction. This is package-source evidence, not an observed CA rejection; no production certificate request was made.

The current matrix requires at least six separate fresh enabled installations for `remove-link-precommit`, `remove-link-postcommit`, `remove-repair-precommit`, `remove-repair-postcommit`, `remove-activation-precommit`, and `remove-activation-postcommit`, each ending `Not installed`. `removeOwnedLineage` removes the owned renewal configuration, live links, archive, and keys; `InspectSubscriptionAbsence` rejects any such surviving footprint. The next clean enablement uses the same VPS IPv4 and production issuer. These six cases alone exceed the initial issuer allowance; other issuance/repair and final Karing scenarios add work. Keeping old protected lineage material or using a replacement endpoint would violate the current acceptance scope.

This cannot fit the current single hosted job or its six-hour transport window. Waiting inside a scenario also cannot satisfy its 30-minute inclusive limit. Do not sign a candidate on the assumption that short-lived certificates or a new ACME account bypass this restriction.

[Candidate run 33526922837](https://github.com/albertloky/SBXR/actions/runs/33526922837) passed preflight, both native architecture builds, and draft construction. The unsigned candidate's Release Index SHA-256 was `a46d9251f53c7bfbe8eef0f3678fad4406c3c750099a0d3c62961dfb8788c32b`. Signing was rejected before attestation to select the existing unsigned-cleanup path. `cleanup-unqualified` completed successfully; subsequent API checks returned HTTP 404 for release ID `380631801`, tag `v3.1.0`, and its burned-identity tag. No candidate was burned and no successful Acceptance Record exists. [Verify run 33526501870](https://github.com/albertloky/SBXR/actions/runs/33526501870) also passed both native architecture jobs on the same commit.

The next execution plan must reconcile this issuer budget with the complete required matrix before signing another candidate. No acceptance-policy change is recorded here.

### Confirmed transport gap

At `8af07d56ef606acb5d98928f8bb929af74b235ec`:

- The workflow requires `sbxr-qualification-manifest-v3`, but [`newQualificationGateway`](../../cmd/sbxr-release/gateway.go) rejects every schema other than `sbxr-qualification-manifest-v1`.
- The version-3 branches in [candidate.yml](../../.github/workflows/candidate.yml) exit before TLS/gateway preparation and invoke only the evidence collector. The collector supplies no packaged draft-download route.
- The unchanged [installer](../../cmd/sbxr-release/bootstrap.go) downloads its pinned index/archive through `https://github.com/albertloky/SBXR/releases/download/<tag>/<asset>`. Authenticated workflow asset downloads do not install those bytes through the Owner's installer. No successful version-3 draft installation is established.
- If the existing gateway is extended to supply lifecycle discovery, the production GitHub Adapter's [`qualificationLatest`](../../internal/softwarelifecycle/adapter/github/github.go) also currently requires a version-1, two-release manifest. Changing the gateway alone cannot establish that route.
- The historical gateway binds `127.0.0.1:8443`; reusing that setup unchanged would occupy the subscription port. This is a static conflict, not an observed live subscription failure.

A local comparison exercised the compiled repository `sbxr-release gateway` command with one synthetic four-asset set, a local test TLS certificate, and two manifests differing only in `schema`. Version 1 served the bound installer over local HTTPS; version 3 exited with `sbxr qualification gateway refused`. The probe was not a signed attempt, did not install anything, and does not count as packaged acceptance. Existing `TestQualificationGateway*` checks passed; they cover the historical version-1 route.

The approved extension now carries the unchanged version-3 manifest and exact asset binding through the existing gateway and production GitHub Adapter for `first-subscription-clean-install`. The adapter retains signature/workflow/approval checks and binds the downloaded index and empty incoming-source scope to the signed attempt. Public stable discovery still requires a completed Acceptance Record; other version-3 scopes are refused by this transport.

The workflow verifies attestation before root-only transport setup. `sbxr-qualification-v3.service` binds `127.0.0.1:9443`; only the qualification-owned `127.0.0.2:443` redirect reaches it. Product ports remain available. The service restores its temporary CA/route after reboot and retains the original six-hour deadline. Cleanup removes its matching service/CA/rule and exact hosts line, restores the original hosts bytes when otherwise unchanged, preserves unrelated concurrent hosts edits, and removes staged keys. Routing inspection errors fail closed. Workflow staging has run-bound ownership and cleanup retries; an unreachable host leaves cleanup explicitly unproved with the supported transport cleanup command. Product authority is never deleted by this transport. Scenario requests now persist in `/root/sbxr-qualification-evidence` across reboot without resetting their start times.

An unsigned transport-only smoke check ran on the approved disposable VPS on 2026-09-01. Initial startup exposed a hosts file without a final newline; the helper was corrected and a regression check added. The probe then served bound synthetic assets over HTTPS, survived an actual VPS reboot with the same asset and original deadline, and completed cleanup. SHA-256 verified exact `/etc/hosts` restoration; the temporary listener, redirect, CA, unit, handoff, and key were absent. `/usr/local/bin/sbxr` and `/var/lib/sbxr` remained absent. These observations prove only transport behavior; they are not signed candidate or product acceptance and do not burn a candidate.

Focused checks cover signed clean-install discovery, scope/approval/index refusal, unchanged signed bytes in HTTP metadata, gateway asset delivery, firewall inspection failure, refusal of a pre-existing unit, trust-store refresh after prior CA-source removal, and hosts restoration with and without concurrent edits. Standards and Spec reviews reported zero remaining actionable findings after fixes. The full local Go suite, `go vet ./...`, and `go mod verify` passed with `GOTOOLCHAIN=go1.26.6`; workflow YAML and all embedded shell blocks parsed. The complete packaged installer/lifecycle and live matrix still need the exact signed candidate.

### Additional readiness evidence

- The existing paginated release-history collector completed and returned 77 published releases, maximum Release Sequence `82`, with no subscription-support declaration in their indices. Public Latest verification accepted the baseline recorded below. The authoritative first-release eligibility check must still run in candidate preflight and again at publication.
- The downloaded official Karing DMG matched SHA-256 `6f421213b6208e3abc1eda6fdd8ddc2014239c7f4241387749ae3a3729c658ea`. All 2987 regular-file/symlink entries in `/Applications/Karing.app` matched the application in that read-only DMG. This proves that comparison, not live Karing acceptance.
- Official Snap Store metadata and `snap info certbot` agreed on amd64 stable/beta Certbot `5.7.0`, revision `5781`; edge was `5.8.0.dev0`, revision `5891`. An official historical download of revision `5778` contained `5.7.0.dev0`. The development versions do not meet the current production/evidence parser contract. Further official Store revision metadata identified Certbot `5.6.0`, revision `5603`. `snap download certbot --revision=5603` retrieved its official package/assertion; squashfs metadata confirmed `amd64`, `classic`, and `core24`. The package size is `77099008` bytes and SHA-256 is `815dfc1c1d45a965db71b5ff7e81ce15061d2977a65a56fc4d6d19518ccd95e0`. This supplies a supported planned predecessor to `5.7.0`; the actual `5.6.0` installation was subsequently proved, while signed refresh/qualification remains unproved. Certbot `5.6.0` was subsequently installed through its official assertion, pulling official `core24` revision `1643` and snapd `2.76.2` revision `27710`. Certbot/snapd/core24 general refreshes were temporarily held during preparation and explicitly released after stopping the unsigned run. The packages remain installed; reobserve their exact identities before another attempt. No SBXR installation or ACME issuance followed.
- [Verify run 33522702455](https://github.com/albertloky/SBXR/actions/runs/33522702455) completed successfully on exact checkout `8af07d56ef606acb5d98928f8bb929af74b235ec` for native Ubuntu `amd64` and `arm64`. Earlier local full-suite, vet, and dependency results remain recorded in [the first delivery comment](https://github.com/albertloky/SBXR/issues/357#issuecomment-5495906170).

At that observation the host had no SBXR proxy service. Stable publication remains separately gated. All signed packaged scenarios, exact outside-network observations, full secret-capture coverage, and the final Karing journey remain missing. These observations do not support a successful Acceptance Record; the later Owner-directed ticket closure is recorded above.

## Historical pre-approval snapshot

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
