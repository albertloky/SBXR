# Implementation Plan: Existing SBXR project review

**Branch**: `main` | **Date**: 2026-11-05 | **Spec**: [spec.md](spec.md)

## Summary

Audit the eight existing capability areas against their current contracts. Repair
confirmed stale readiness documentation and remove redundant action aggregation
from output-only details, if regression evidence establishes preserved behavior.
Do not broaden scope or claim live timing success from local evidence.

## Technical Context

**Language/Version**: Rust 1.90.0 edition 2024; retained Go release tooling and Python driver.
**Primary Dependencies**: Existing Cargo.lock and go.mod; no upgrades.
**Storage**: Existing protected ownership/installed records; no schema changes.
**Testing**: Cargo unit/integration tests, formatter, strict Clippy; existing native CI.
**Target Platform**: Ubuntu 24.04 amd64 product; both architectures for release builds.
**Project Type**: Root-only CLI and private services with repository release tooling.
**Performance Goals**: Unchanged 90-second initial details qualification budget.
**Constraints**: No cached authority, relaxed validation, new live attempt or disposition.
**Scale/Scope**: One Owner/host; all eight current capability areas reviewed.

## Constitution Check

Pre-research and post-design: PASS against existing AGENTS/current ADRs. The local
constitution is a consolidation with pending ratification, not new policy. Main,
clean-install scope, fresh admission, protected secrets, exact owned cleanup and
separate live/publication authority remain unchanged. No justified deviations.

## Project Structure

Feature artifacts: spec.md, research.md, data-model.md, contracts/owner-details.md,
quickstart.md, tasks.md and review.md under specs/001-project-review/.

Source: src/proxyinstallation/owner.rs and adjacent owner_tests.rs. Native source
opening/admission remains src/host/owner.rs and src/host/admission.rs. Public menu
callers remain src/terminal.rs and tests/menu.rs. Evidence summaries belong in
docs/rust-acceptance.md and docs/acceptance/reports/.

**Structure Decision**: Use existing modules and test seams; no new runtime abstraction.

## Complexity Tracking

No constitution violation or additional runtime mechanism proposed.

## Continuation design

Add Interface::review_status -> (Review, subscription display status), with a
default retaining existing review(Status) then subscription_status behavior.
HttpInstallation factors its existing review so combined reads share one state().
Owner retains its aggregate action logic, collecting subscription status from
Identity when first in the fresh journey list, otherwise Http. If that adapter
cannot be opened, retain the existing fallback lookup/refusal behavior. Neither
modules nor observations persist for reuse across input. Native BoundJourney
checks its retained proof before delegating the combined read. The terminal uses
the result for the first and every later frame. Other action reviews are unchanged.

Files: src/proxyinstallation.rs, proxyinstallation/{owner,subscription}.rs,
host/admission.rs, terminal.rs and their adjacent/integration tests. No new schema,
dependency, CLI, policy, or remote operation. Constitution check remains PASS.


## Approved build 212 reservation continuation

Use the existing retained-candidate model and validators; append one exact record
in cmd/sbxr-release/candidate_reservations.go and update its fixed count plus
.github/scripts/check-candidate-reservations.sh. Keep all nine earlier records,
unknown-signing semantics and historical replay unchanged. No schema, product
Rust, workflow permission, gate or remote mutation changes are needed.

Adjacent candidate-reservation and qualification fixtures must use a fresh
unreserved candidate (prospectively 139/213) where appropriate. Isolated tag,
sequence and release-ID collision tests must not accidentally collide on another
field. Preserve historical initial facts/decisions. Add exact-record regression
before the policy change, then run focused, release-tool and root integration
checks, formatting, vet and final-source CI. Fresh authenticated GET/hash checks
precede adoption; full observation replay verifies all ten reservations together.

Record the approved policy in ADR-0032 and a dated indexed reservation report.
Keep T018 live validation open. This continuation uses existing Spec Kit artifacts;
setup-plan preserves the existing plan and setup-tasks resolves its template.
Constitution check: PASS against existing rules and the explicit new exact-identity
approval; the local unratified consolidation is unchanged.

## Separately approved CI cleanup-fixture repair

Investigate the existing protected-cleanup fixture failure exposed by Verify run
42003224687, separately from the reservation policy. This continuation serves
existing FR-005/FR-009 and SC-002; it adds no requirement or project rule. The
production menu-session driver, cleanup budgets and release policy stay unchanged.

Replace only the five SIGUSR1 cleanup fixtures' indefinite stdin reads with a
short periodic idle loop. Those reads merely keep the child alive; their tests do
not depend on stdin data or EOF. Keep the real signal handler, large stderr writes,
normal exit and complete-cleanup assertions. Add failure context to the spawn
relay test without weakening its assertions. Leave other stdin-based fixtures alone.

The controlled pending-signal experiment exercises the actual child process and
production stop path: old idle is killed after the unchanged cleanup budget,
whereas periodic idle handles the signal and drains all output. This establishes
a fixture susceptibility, not proof of the original Linux CI cause. Run focused
and complete Python checks plus the relevant Go race wrapper, review the bounded
diff, and obtain final-source CI. A retry of unchanged a3d01a9 is diagnostic evidence
only; it cannot validate changed fixtures. Record evidence and limits in the dated
cleanup-fixture report. T024 and T027 remain open pending final-source CI, and T018
remains independent and open. The local constitution remains unratified/unchanged.


## Build 213 failure-boundary continuation (2026-11-06)

The preserved run establishes an operator sequencing error: terminal failure
submission ended the collector and its caller tore down candidate authentication
before supported removal was attempted. Public entry correctly requires real
authentication before showing the menu. Do not change that rule or keep temporary
transport alive beyond its existing deadline. Details output was observed, but
return-menu completion and the final driver result are missing after disconnect.
No additional product defect is established by that truncated observation.

Add a fixed secret-safe stderr diagnostic immediately before publishing a typed
failure in the existing submit_result helper. Document safe/authorized cleanup
before terminal submission while the original authentication/window is valid;
when cleanup is blocked, preserve and report its actual incomplete/unknown state.
Do not require a claimed cleanup success, introduce a new handshake or suppress
failure reporting. Success submissions remain unchanged. Test the actual Bash
submission and publication subprocess boundary with local files, including both
completed and unresolved cleanup facts and absence of the diagnostic for success.

Update the dated outcome, Spec Kit task/CI records and current evidence pointer.
Preserve the q213 raw capture and candidate unchanged. No dependencies, schemas,
product code, workflow gates, trust settings, windows or project rules change.
Constitution check: PASS against existing AGENTS/ADRs; its local unratified
consolidation remains unchanged. T018's live criterion stays unsatisfied.

## Approved build 213 reservation continuation — 2026-11-06

Extend the existing model and retained-candidate contract by one exact member;
no schema, dependency, product Rust, workflow permission or signing gate changes.
Append the approved q213 record in cmd/sbxr-release/candidate_reservations.go and
change the strict policy and .github/scripts/check-candidate-reservations.sh
collector counts from ten to eleven. Preserve the preceding ten records and
historical replay. Shared current-candidate fixtures must use an unreserved
identity (prospectively v3.1.140/214); isolated collision tests must exercise only
the intended tag, sequence or release-ID collision. This fixture value allocates
no real candidate and does not override fresh global admission.

Prove the missing-record boundary before implementation, then run exact-record,
omission/relabel, collision, changed/missing/duplicate observation, present/unknown
ref and sequence checks through the actual policy/collector callers. Reuse the
existing focused, release-tool and root integration checks, vet and final-source
CI. Recheck retained metadata/bytes/signature read-only; replay all eleven records
and twenty-two explicit absent refs. Stop on drift or unavailable authority.

Update ADR-0032, the dated indexed reservation report and current count references;
keep historical q212 results scoped to their original ten-record policy. Spec,
research, contract, data model and tasks below map this continuation to FR-012,
SC-008 and US3. The requirements checklist and unratified local constitution are
unchanged. Existing AGENTS/ADRs plus the exact Owner approval supply authority;
no new policy gates or operational permissions are inferred. T018 stays open.

## Bounded failure-cleanup continuation — 2026-11-06

Use the existing recorder and supervised menu driver; do not add a general runner.
Add a read-only `cleanup-deadline` command in .github/scripts/mvp-observe.py.
Require the original private, unsealed, request-matching draft. Its deadline is
conservatively the original request deadline plus actual completed waits, capped
by the signed finish and existing handoff deadline. A pending wait adds no
technical credit and stays unchanged. Missing, sealed, expired or malformed
authority refuses. Normal `operation-deadline` and success/sealing behavior stay
unchanged; no new schema, handoff state, response event or signed-clock rule.

Add explicit `safety-cleanup` mode to .github/scripts/v3-menu-session.py, closed
to Complete removal / Finish removal with their fixed expected result and existing
confirmation. Always require hash-bound clock bytes, an absolute cleanup cutoff,
a post-action verification reserve and the protected candidate runtime-deadline
file. Before spawning, require the full configured action timeout cap plus reserve
to fit the remaining minimum of the original cleanup clock, runtime limit and
cutoff. The reserve includes process supervision and final verification; defaults
are bounds, not measurements. Recheck before each launch and pass the same
absolute limits through the whole sequence. Never reset a clock, bypass fresh
product authentication/ownership, or use this route for setup,
identity mutation, details or automatic retries.

The thin `menu_session_safety_cleanup` helper in existing
.github/scripts/v3-packaged-live.sh invokes one reviewed removal action through
that mode, binding the exact result code and confirmation from its selected label.
Its cutoff/reserve and existing driver options do not add arbitrary action scope.
Keep legacy `remote_failure_cleanup` historical; current guidance names this
bounded route for fresh Rust qualification. Surrounding read-only state and
final-verification steps use the existing bounded SSH mechanism and a freshly
prepared caller sharing the cutoff;
there is no independent general-purpose cleanup runner. A successful menu result
is not whole-cleanup proof: separately verify owned absence, outside rejection,
client/secret restoration and transport cleanup within their actual authority.
Blocked or uncertain cleanup stays reportable without changing the original
failure evidence or converting the failed qualification into a pass.

Tests must exercise actual recorder and driver subprocesses and private files:
permitted actions and confirmation, pending/completed waits, rejected ordinary
pending actions, malformed/sealed/mismatched/expired authority, reserve exhaustion,
expiry between steps, failure/cancellation and process reaping. Hold source clock
bytes and protected runtime-file identity to existing ownership/hash expectations.
Run focused and relevant broad suites, independent review, and exact-source CI.
No numeric full-cleanup duration or live readiness is established by this design.
T018 stays open. Existing rules and the unratified constitution remain unchanged.

## Release-tool test-build continuation — 2026-11-06

Address the repeated fixture setup cost in cmd/sbxr-release test sources only.
Add `buildReleaseTestBinary` and its regression in
cmd/sbxr-release/release_test_binary_test.go. Synchronize one package-process
construction of immutable CLI bytes, then materialize a fresh executable in each
requesting test's temporary directory. The initial build directory may disappear
without invalidating later copies. Do not share a writable executable or use a
TestMain-owned external lifecycle. Surface build/copy failures instead of hiding
them. Retain the existing go build arguments, environment and working directory.

Replace the 23 equivalent build sites across the ten audited qualification test
files; keep buildQualificationDeclarationBinary as a thin delegate. The static
audit found 51 builds during the current fixture paths without CLI/source, build
environment or working-directory mutation or parallel callers. This is a bounded
reuse assumption, not a general compiler cache: distinct builds/flags and actual
released-reader subprocesses remain unchanged. Preserve every downstream command,
input, assertion and original fixture lifetime. Review synchronization correctness
and retain race checking; current audited callers are sequential. No new concurrent
caller or dedicated concurrent performance test is required by this repair.

First demonstrate a regression for repeated construction, independent executable
copies and failure visibility at real process/filesystem boundaries; then compare
focused before/after results under the same pinned toolchain. Use focused normal
acceptance, the same focused race comparison, a full local release-tool race run,
vet and independent review. If the local unsplit run exhausts its cumulative
budget, retain that failed result and complete unfinished checks in a separate
bounded race batch without presenting combined coverage as an unsplit pass.
Reuse valid unchanged repository integration evidence; full unsplit normal/race
suites on both native architectures run in final-source CI as usual.
Keep the existing race command and default 600-second
package timeout unchanged. Do not infer Linux CI savings from local build timings.
This continuation does not establish a sole timeout cause or fix until its checks
pass; product, release rules, workflow permissions and all live limits stay intact.
