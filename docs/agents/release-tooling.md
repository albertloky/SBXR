# Release and qualification tooling

| Stage | Implementation | Evidence or decision |
|---|---|---|
| Build and verify | [verify.yml](../../.github/workflows/verify.yml) and the [Rust packaging crate](../../tooling/rust-package/README.md) | Native amd64/arm64 archives, four-asset assembly and offline package checks. Repeated assembly uses the same two archives. |
| Construct the candidate | [candidate.yml](../../.github/workflows/candidate.yml), [Go release stages](../../cmd/sbxr-release/README.md) and [reservation policy](../../cmd/sbxr-release/candidate_reservations.go) | Declaration, candidate assets, identity and signed manifest. A signed draft still requires successful qualification. |
| Observe the five journeys | [HTTP procedure](../acceptance/http-subscription-live.md), [packaged driver](../../.github/scripts/v3-packaged-live.sh), [collector](../../.github/scripts/v3-recurring-evidence.sh) and [Go evaluator](../../cmd/sbxr-release/qualification_mvp.go) | The driver operates the product. The recorder and evaluator consume the observations. On failure, product removal can still require candidate authentication before terminal submission. |
| Interpret a diagnostic | [Disclosure-only guide](../acceptance/disclosure-diagnostic.md), [one-node Karing test](../acceptance/karing-one-node-diagnostic.md) | A bounded diagnostic records its own result. An ordinary Acceptance Record requires the declared product journeys and cleanup. |
| Publish or retry | [stable.yml](../../.github/workflows/stable.yml), [publication decision](../../cmd/sbxr-release/qualification_publication.go) and [ADR-0032](../adr/0032-qualified-publication-retry.md) | Explicit Owner approval, successful qualification run, exact bytes and main-divergence review when applicable. The candidate revision supplies the fixed checklist for replay. |

For an installer mismatch, identify which revision supplied the template. Candidate
assembly uses the package tool’s embedded inputs. Stable preflight and the public
package check replay the signed release commit’s template and tunnel unit from
local Git objects. The [package tests](../../tooling/rust-package/tests/package.rs)
exercise differing revisions and both architectures. The [workflow test](../../release_stable_workflow_test.go)
checks which commit each caller passes.

For a user-visible product failure, follow the [Rust journey](rust-product.md) as well as the driver that reported it.

## Candidate deployment reviews

After Albert approves the exact review at action time, submit it through GitHub's
[normal pending-deployment review API](https://docs.github.com/en/rest/actions/workflow-runs#review-pending-deployments-for-a-workflow-run)
using the existing authenticated reviewer when GitHub confirms eligibility. This
is the default review path. Keep the existing credentials, permissions and
environment protections.

1. Read the exact repository, run ID and attempt, source commit, candidate
   identity, named job ID and current status. In candidate runs, `sign` and
   `acceptance-vps` are two separate reviews even though both use the
   `acceptance-vps` environment label. Bind the approval to the specific waiting
   job and its effects. For live acceptance, verify the signed deadlines and
   that the full approved work and restoration still fit.
2. Read the run's [pending deployments](https://docs.github.com/en/rest/actions/workflow-runs#get-pending-deployments-for-a-workflow-run)
   with the same authenticated reviewer. Require `current_user_can_approve: true`
   for the exact environment ID and a single unambiguous matching pending job.
   The review request identifies an environment by ID. Refresh the run's jobs
   and pending deployments immediately before submitting. A changed or ambiguous
   state stops the review. Chat approval and GitHub eligibility are both required.
   Ask Albert to use the exact GitHub job
   link when the existing reviewer path is unavailable or GitHub requires a
   human review. An unclear, unapproved or expired action stops here.
3. Read the review history and exact job state after submission. If the response
   is uncertain, reconcile both observations before any new submission. An
   unresolved outcome stops the review. Keep the second gate closed until
   separately authorized. The normal review does not grant broader
   live effects, security changes, admin bypass or release publication.

For [build 206](https://github.com/albertloky/SBXR/actions/runs/41165244627) on
October 31, 2026, Albert approved the review in chat and the operator checked
the existing account's reviewer eligibility via pending deployments. GitHub
accepted the review. GitHub's review history records two approvals by that
account in the shared environment. The [`sign` job](https://github.com/albertloky/SBXR/actions/runs/41165244627/job/124440936729)
succeeded and the separate [`acceptance-vps` job](https://github.com/albertloky/SBXR/actions/runs/41165244627/job/124444088917)
later failed. This precedent records the supported review path. Each future
review still needs its own authorization and eligibility check.

## Implementation and focused checks

These are separate from installed product behavior. For a missing menu action,
first inspect product review/legal-action logic; for lost menu output or a
deadline failure, inspect the driver and operator wrapper. Native fixed timing
scopes live in `src/host/timing.rs`; the details driver relays their closed schema
without raw stderr. See the script map for clock and scope-exit semantics.

| Task | Implementation | Checks / procedure |
|---|---|---|
| Retained Go packaging, bootstrap generation, and tool dispatch | [cmd/sbxr-release/main.go](../../cmd/sbxr-release/main.go), [bootstrap.go](../../cmd/sbxr-release/bootstrap.go) | Adjacent `main_test.go` / `installer_test.go`; `go test ./cmd/sbxr-release` |
| Qualification decisions and accepted wire formats | [Release stage map](../../cmd/sbxr-release/README.md), [qualification.go](../../cmd/sbxr-release/qualification.go), [scope](../../cmd/sbxr-release/qualification_scope.go), [recurring](../../cmd/sbxr-release/qualification_recurring.go), [MVP](../../cmd/sbxr-release/qualification_mvp.go) | Corresponding `qualification*_test.go`; [HTTP acceptance](../acceptance/http-subscription-live.md) describes the current five journeys; historical scopes retain their interpretation |
| Candidate delivery transport | [gateway.go](../../cmd/sbxr-release/gateway.go), [v3-qualification-transport.sh](../../.github/scripts/v3-qualification-transport.sh) | `gateway_test.go`, `release_transport_test.go` |
| Authenticated release asset downloads | [download-release-asset.py](../../.github/scripts/download-release-asset.py), [recheck-qualified-release.sh](../../.github/scripts/recheck-qualified-release.sh) | `test_download_release_asset.py`, `release_asset_download_test.go`; requires `gh`, `python3`, `jq`, and `sha256sum` |
| Native CI / pinned actions | [.github/workflows](../../.github/workflows), [script map](../../.github/scripts/README.md) | `release_workflow_test.go` |
| Candidate preflight, build, draft, signing, or handoff | [Release stage map](../../cmd/sbxr-release/README.md), [.github/workflows](../../.github/workflows) | `release_candidate_workflow_test.go`, `release_candidate_handoff_test.go`, `release_declaration_dispatch_test.go` |
| Stable publication, retry, failure, or burn record | [publication](../../cmd/sbxr-release/qualification_publication.go), [recovery](../../cmd/sbxr-release/qualification_publication_recovery.go), [failure](../../cmd/sbxr-release/qualification_failure.go) | `release_stable_workflow_test.go`, `release_publication_recovery_test.go`, adjacent publication retry/recovery tests; [ADR-0032](../adr/0032-qualified-publication-retry.md) |
| Collector request or result submission | [v3-recurring-evidence.sh](../../.github/scripts/v3-recurring-evidence.sh) | `release_collector_test.go` |
| Real SSH fixture readiness, account isolation, or transport boundaries | [test_ssh_boundary.py](../../.github/scripts/test_ssh_boundary.py) | Adjacent `test_ssh_boundary_account.py` locks the caller account and proves success/failure preservation; root `v3_ssh_boundary_test.go` runs both on root Linux |
| Packaged menu results, protected-footprint inventory, or cleanup | [v3-packaged-live.sh](../../.github/scripts/v3-packaged-live.sh), [v3-menu-session.py](../../.github/scripts/v3-menu-session.py) | `release_packaged_driver_test.go`, including exact absence and broken-link checks |
| Current MVP observation assembly and submission | [v3-mvp-evidence.py](../../.github/scripts/v3-mvp-evidence.py), [v3-recurring-evidence.sh](../../.github/scripts/v3-recurring-evidence.sh) | [HTTP evidence handoff](../acceptance/http-subscription-live.md#recording-the-five-journeys), `test_mvp_evidence.py`, and `v3_mvp_evidence_test.go` |
| Retained recurring upgrade scope and incremental observations | [qualification_mvp.go](../../cmd/sbxr-release/qualification_mvp.go), [mvp-observe.py](../../.github/scripts/mvp-observe.py) | `qualification_mvp_recurring_test.go`, `qualification_mvp_assembly_test.go`, `recurring_mvp_test.go`, `test_mvp_observe.py`; [retained recurring procedure](https://github.com/albertloky/SBXR/blob/c298af182cdd159a6258c0d17fb37b9b663cf4ee/docs/acceptance/ordinary-recurring-live.md) |
| Read-only MVP package/window observations | [mvp-inspect-window.py](../../.github/scripts/mvp-inspect-window.py), [documented SSH caller](../acceptance/mvp-protected-log-parent-2026-09-19.md#read-only-state-checks-corrected-september-22) | Adjacent `test_mvp_inspect_window.py`, opt-in `test_mvp_inspect_window_linux.py` and root `v3_mvp_window_test.go`; real pinned DEB/dpkg/SSH fixtures in a marked disposable amd64 VM |
| Temporary MVP log-parent prerequisite | [mvp-protected-menu.sh](../../.github/scripts/mvp-protected-menu.sh), [operator plan](../acceptance/mvp-protected-log-parent-2026-09-19.md) | Adjacent `test_mvp_protected_menu.py` and [isolated systemd/TLS test](../../internal/proxyinstallation/protected_log_parent_linux_test.go); uses the reviewed wrapper and [startup cancellation regression](../../.github/scripts/test_mvp_startup_cleanup.py) |
| Current ordinary live procedure | [HTTP acceptance](../acceptance/http-subscription-live.md), [ADR-0028](../adr/0028-clean-install-only.md) | Five HTTP journeys, explicit empty incoming sources |
