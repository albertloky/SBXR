# Tasks: Existing SBXR project review

Input: [spec.md](spec.md), [plan.md](plan.md), research, data model and contracts.
Tests are required by FR-005. No task authorizes live work. Phase 7 records the
separately approved exact build-212 preservation; no remote disposition mutation
is authorized.

## Phase 1: Setup

- [x] T001 Resolve installed templates and preserve main in .specify/feature.json.

## Phase 2: Foundation

- [x] T002 Record current scope and trace evidence in specs/001-project-review/research.md.

## Phase 3: US1 — Readiness (P1)

Independent check: all eight capabilities have requirements, boundaries, checks and gaps.

- [x] T003 [US1] Write eight-area review and classify findings in specs/001-project-review/review.md.
- [x] T004 [US1] Add secret-safe q212 closeout in docs/acceptance/reports/q212-details-timeout-2026-11-05.md and index it in docs/acceptance/reports/README.md.
- [x] T005 [US1] Refresh latest dated evidence pointer in docs/rust-acceptance.md without rewriting historical evidence.

## Phase 4: US2 — Details efficiency (P1)

Independent check: actual Owner selection regression fails before repair and passes after;
prepared authority, output failure, fallback and fresh disclosure remain protected.

- [x] T006 [US2] Add bounded details selection/refusal regressions in src/proxyinstallation/owner_tests.rs and record pre-fix failures under .scratch/acceptance/project-review/.
- [x] T007 [US2] Specialize output-only details selection in src/proxyinstallation/owner.rs preserving fresh checks and module lifetime.
- [x] T008 [US2] Verify Owner, menu, admission and disclosure regressions using tests/menu.rs and adjacent source suites; record limits in specs/001-project-review/review.md.

## Phase 5: US3 — Bounded improvements (P2)

Independent check: every finding has an evidence classification and disposition;
no unsupported feature or unauthorized operation enters the plan.

- [x] T009 [US3] Reconcile requirements/design/tasks and decisions in specs/001-project-review/analysis.md.
- [x] T010 [US3] Record remaining native/live, failure-disposition and publication decisions in specs/001-project-review/review.md.

## Final Phase: Cross-cutting validation

- [x] T011 Run formatting, strict Clippy and applicable checks; review the final diff and record results in specs/001-project-review/review.md.
- [x] T012 Commit reviewed changes on main and verify CI; record source/run references in specs/001-project-review/review.md.

## Dependencies and execution order

T001 -> T002 -> US1/US2; US3 reconciles both; final validation follows implementation.
US1 documentation can be prepared while US2 tests run. Within US1, report precedes
index refresh. Within US2, regression precedes repair, then integration checks.
US3 final reconciliation follows both stories. No same-file edits run concurrently.

## Implementation strategy

Deliver accurate readiness first, then the bounded tested performance correction,
then the final review. SC-003 requires a separately authorized future live test
and is explicitly deferred, not a completed task. Do not create a candidate to test
this change for the first time.

Post-commit closeout: approved push of 6e87493 succeeded; Verify run 41973179692
passed all four jobs. That checklist closeout was included in 6c2b287; it did not
change the earlier tested code. The continuation CI result is recorded in review.md.

## Continuation: remaining menu-frame cost

- [x] T013 [US2] Trace and specify repeated HTTP inspection in research.md and spec.md (FR-010/SC-006).
- [x] T014 [US2] Add failing combined-status and fresh-input regressions in src/proxyinstallation/owner_tests.rs, subscription_tests.rs, host/admission_tests.rs and tests/menu.rs.
- [x] T015 [US2] Implement in-call combined observation through src/proxyinstallation.rs, owner.rs, subscription.rs, host/admission.rs and terminal.rs.
- [x] T016 [US2] Run focused and broader checks, review the diff and report measured limits in review.md.

Dependency: T013 -> T014 -> T015 -> T016. Tests use existing protected files and
runtime observation boundaries; no live qualification is part of this continuation.


## Phase 6: Convergence

- [x] T017 [US1] Reconcile successful exact-source CI, workflow provenance, and the existing release prerequisites in spec.md, review.md and analysis.md per FR-009, SC-005 and T012 (partial; HIGH, C001).
- [ ] T018 [US2] Verify the unchanged 90-second details/menu criterion on a separately authorized exact candidate and record the actual result, five-journey outcome and scoped cleanup in a dated report per SC-003 and US2/AC1 (partial; HIGH, C002).

T017 is independent offline documentation work. T018 is blocked by missing
specific live authorization and fresh readiness; it grants no candidate dispatch,
failure disposition, host/client/security mutation, cleanup or publication authority.
The five existing live journeys and their cleanup are prerequisites to a release
claim, not new requirements introduced by convergence. Leave T018 unchecked until
the criterion is met and the actual outcome and cleanup are recorded; failed or
missing observations cannot satisfy it.


## Phase 7: US3 — Approved build 212 preservation

- [x] T019 [US3] Recheck exact failed identity/assets/signature/refs and record FR-011/SC-007 plus the preservation contract in spec.md, plan.md, research.md and contracts/retained-candidate.md.
- [x] T020 [US3] Add an exact build-212 reservation regression and demonstrate failure against the nine-record policy in cmd/sbxr-release/candidate_reservation_q212_test.go.
- [x] T021 [US3] Add the tenth exact record, strict collector count and coherent current-candidate/refusal fixtures in cmd/sbxr-release/candidate_reservations.go, adjacent tests and .github/scripts/check-candidate-reservations.sh.
- [x] T022 [P] [US3] Record the approved preservation in docs/adr/0032-qualified-publication-retry.md, docs/acceptance/reports/q212-retained-reservation-2026-11-05.md and its report index; reconcile review.md.
- [x] T023 [US3] Validate focused/full release-tool and root integration checks, vet, full current reservation observations and the final diff; record results in the dated reservation report.
- [x] T024 [US3] Commit/push the reviewed preservation on main and verify exact-source CI; retain results under .scratch/acceptance/q212res/.

Dependency: T019 -> T020 -> T021 -> T023 -> T024. T022 can run independently after
T019 and is finalized with T023 results. The invariant is exact retained identity
and refusal of changed/reused authority, not a live qualification claim. T018
remains open and independent. No existing task is retroactively marked live-passed.

## Phase 8: US3 — Separately approved CI cleanup-fixture repair

The preservation push a3d01a9 succeeded, but Verify run 42003224687 attempt 1
failed the amd64 protected-cleanup fixture. T024 therefore remains open. Its
unchanged-source attempt 2 was pending at this checkpoint; either outcome is
separate from validation of the repaired fixtures.

- [x] T025 [US3] Diagnose the failed cleanup assertion and affected callers; record the controlled real-signal old/new idle comparison and original-CI uncertainty from .scratch/acceptance/cf1/, cf2/ and cf3/ in review.md and docs/acceptance/reports/cleanup-signal-fixture-2026-11-05.md.
- [x] T026 [US3] Repair the five signal-cleanup idle fixtures and add spawn-relay failure context in .github/scripts/test_v3_menu_session.py; preserve production behavior, assertions and budgets, then validate the focused/full Python tests, relevant Go race wrapper and final diff.
- [x] T027 [US3] Commit/push the reviewed bounded repair on main and verify exact-source CI; retain the original failure and unchanged-source retry outcome, and record final validation in the dated cleanup-fixture report.

Dependency: T025 -> T026 -> T027. Successful final-source CI is also required to
close T024; a local pass or unchanged-source retry is insufficient for the repaired
source. T018 remains unchecked. This continuation grants no live attempt, cleanup
execution, release publication or security-setting authority.


## Phase 9: US1/US3 — Build 213 failure-boundary diagnosis

This offline continuation follows the separately approved and verified build-213
administrative cleanup. It serves FR-005/006/007/008/009 and SC-002/004/005;
no product requirement, authentication rule or qualification budget changes.

- [x] T028 [US1] Trace the preserved details/removal evidence against current driver, public admission, collector and workflow; distinguish confirmed sequencing from uncertain details completion in research.md.
- [x] T029 [US3] Add a failing real-subprocess regression at the terminal failure publication boundary in release_collector_test.go, then add the fixed secret-safe diagnostic in .github/scripts/v3-recurring-evidence.sh without gating honest incomplete-cleanup reports.
- [x] T030 [P] [US1] Clarify existing cleanup/submission ordering in docs/acceptance/http-subscription-live.md and .github/scripts/README.md; add an indexed dated q213 report and refresh docs/rust-acceptance.md.
- [x] T031 [US3] Verify focused/full relevant collector and menu regressions, review the diff independently, and record results and remaining qualification prerequisites in review.md and the dated report.
- [x] T032 [US3] Commit/push the reviewed continuation on main and verify exact-source CI; preserve build 213 draft/assets/signature and failed outcome.

Dependency: T028 -> T029 -> T031 -> T032; T030 can run after T028 and is
finalized with T031. T018 remains open: the interrupted details capture cannot
establish either complete 90-second success or an observed timeout. No live
attempt, administrative cleanup replay or release disposition is part of Phase 9.

Prior CI closeout, freshly read 2026-11-06: f067ca2 reached GitHub main and
Verify run 42009536182 passed all four native/assembly jobs. T024 and T027
are therefore complete. The unchanged a3d01a9 retry (42003224687, attempt 2)
ended cancelled; it does not validate the later fixture repair.

Phase 9 closeout: bf72f30064b14aa3128ef69d409a2e6abdd0c88b reached main;
Verify 42189134454 passed all four jobs, recorded in
.scratch/acceptance/q3f/push-ci-completed.json. This completes T032 and supplies
no live qualification evidence.

## Phase 10: US3 — Approved build 213 preservation

Independent check: the exact eleventh reservation is enforced while all ten
prior records, historical semantics and refusal boundaries remain intact.

- [x] T033 [US3] Record the separately approved FR-012/SC-008 identity and bounded design in spec.md, plan.md, research.md, data-model.md and contracts/retained-candidate.md using .scratch/acceptance/q213disp/ evidence; preserve previous decisions.
- [x] T034 [US3] Add exact q213 and omission/relabel regressions in cmd/sbxr-release/candidate_reservation_q213_test.go and demonstrate failure against the ten-record policy; retain .scratch/acceptance/q13t/red-pinned.log.
- [x] T035 [US3] Append only the exact record and eleven-record validation in cmd/sbxr-release/candidate_reservations.go and .github/scripts/check-candidate-reservations.sh; preserve ten prior records, historical replay and coherent current-candidate/collision fixtures in adjacent tests.
- [x] T036 [P] [US3] Record the approved disposition in docs/adr/0032-qualified-publication-retry.md and an indexed dated report under docs/acceptance/reports/; reconcile current counts and specs/001-project-review/review.md without rewriting historical outcomes.
- [x] T037 [US3] Validate exact pins, focused/full release-tool and root integration checks, vet, all eleven current observations and twenty-two absent refs, plus independent final-diff review; record evidence and limits in the dated reservation report.
- [x] T038 [US3] Commit/push the reviewed reservation on main and verify exact-source CI; record source/run/results in specs/001-project-review/review.md and the dated reservation report.

Dependency: T033 -> T034 -> T035 -> T037 -> T038. T036 can proceed independently
of production/test changes after T033, then incorporates T037 evidence before
T038. The smallest complete increment is this single approved reservation.
T035–T038 are complete; the exact-source CI receipt is recorded below. T018 remains open.
No live attempt, signing, failed-finalizer replay, remote release mutation, cleanup
execution or publication is part of Phase 10.

Phase 10 closeout: c60efd0306ebf92aaad7dce930fa3bfaab2549ed reached main;
Verify 42208919789 passed all four jobs, as recorded in
.scratch/acceptance/q213res/{push-result,ci-completed}.json. T038 is complete;
this establishes no live qualification or current cleanup readiness.

## Phase 11: US3 — Bounded state-specific failure cleanup

Independent check: the two existing removal actions retain fresh authority and
process supervision while the cleanup-only clock preserves original limits and
pending/failure evidence. No whole-cleanup/live claim follows from menu success.

- [x] T039 [US3] Specify and clarify FR-013/SC-009 and the agreed cleanup-only deadline/action boundary in spec.md, plan.md, research.md and data-model.md; preserve prior rules and close only evidenced T038.
- [x] T040 [US3] Add and demonstrate failing boundary regressions in .github/scripts/test_mvp_observe.py, .github/scripts/test_v3_menu_session.py and relevant root caller tests for pending/expired/mismatched authority, action allow-list, shared cutoff/reserve, failure preservation and process cleanup.
- [x] T041 [US3] Implement read-only cleanup-deadline in .github/scripts/mvp-observe.py, explicit safety-cleanup in .github/scripts/v3-menu-session.py and menu_session_safety_cleanup in .github/scripts/v3-packaged-live.sh; preserve normal actions, confirmations, clock semantics and original failure evidence.
- [x] T042 [P] [US3] Document the bounded caller and separate final-verification prerequisites in .github/scripts/README.md and docs/acceptance/http-subscription-live.md, with a dated indexed report under docs/acceptance/reports/ and limits in review.md.
- [x] T043 [US3] Validate focused and relevant broad recorder/driver/caller checks, independent final-diff review and secret-safe evidence; record actual results, unavailable boundaries and duration limits in review.md and the dated report.
- [x] T044 [US3] Commit/push the reviewed bounded repair on main and verify exact-source CI; record source/run/results in review.md and the dated report.

Dependency: T039 -> T040 -> T041 -> T043 -> T044. T042 can proceed after T039
on separate documentation files and incorporates final T043 evidence before
T044. T040–T043 are complete from the local evidence recorded in review.md;
T044 remains pending exact-source push/CI. T018 remains open. No live attempt, cleanup execution, new signing, remote release mutation,
security change, deletion or publication is authorized by this offline work.

Phase 11 CI checkpoint: commit 335769cc1b27694d10065fa88eccc09cdeeccd80 was
pushed, but Verify 42217521869 failed at the amd64 release-tool race package's
600-second alarm. The active test had just begun its CLI build; no individual
ten-minute hang is established. T044 remains open until the repaired source's
required CI succeeds. The separate authorized investigation follows below.

## Phase 12: US3 — Equivalent release-tool test-build reuse

Independent check: repeated fixture setup builds once per unchanged package-test
process while independent executable copies retain every real CLI/reader check.
No timeout, race coverage, assertions or release authority is relaxed.

- [x] T045 [US3] Record the CI timeout, comparison/local-build evidence and bounded FR-014/SC-010 design in spec.md, plan.md and research.md; preserve the original failed outcome and T044/T018 limits.
- [x] T046 [US3] Add a failing real-process/filesystem reuse/isolation/failure regression in cmd/sbxr-release/release_test_binary_test.go and retain red evidence under .scratch/acceptance/.
- [x] T047 [US3] Implement synchronized immutable-byte construction and fresh per-test executables in cmd/sbxr-release/release_test_binary_test.go; adapt the equivalent qualification test callers, retaining the declaration helper and every downstream command/reader check.
- [x] T048 [P] [US3] Record the bounded diagnosis/repair and timing limitations in docs/acceptance/reports/release-test-build-reuse-2026-11-06.md, its index and specs/001-project-review/review.md; preserve original CI observations.
- [x] T049 [US3] Verify focused red/green and comparable timing, applicable local normal/race checks and complete release-tool test coverage, reusable integration evidence, vet and independent final-diff review without changing timeout/coverage; retain any unsplit package failure separately from bounded remainder results in review.md and the dated report.
- [x] T050 [US3] Commit/push the reviewed test-only repair on main and verify exact-source CI; record the source/run/outcome in review.md and the dated report before closing T044.

Dependency: T045 -> T046 -> T047 -> T049 -> T050. T048 can proceed after T045
on separate documentation files and incorporates T049 evidence before T050.
T046/T047 are complete from the real-process red/green and reviewed caller
evidence in review.md. T048/T049 are complete with all 127 listed local tests
accounted for: 126 passed and one existing macOS skip. The unsplit race run failed
at 600.359s; a separate 18-test remainder passed in 45.658s. Combined coverage
is not an unsplit pass. T050/T044 require successful final-source native CI. T018
remains unverified. No live test, signing, VPS/security change, deletion or publication
is part of this test-tooling repair.

## Phase 12 CI closeout

The reviewed repair reached main as `2634a9cb2b48920e04f7ae4c9b8752c86b951a71`.
[Verify 42225366942](https://github.com/albertloky/SBXR/actions/runs/42225366942),
attempt 1, passed all four native and assembly jobs. The unchanged full normal
and race commands passed on both architectures; release-tool race times were
399.908s on amd64 and 463.059s on arm64, under the unchanged 600-second limit.
The original failed run and unsplit Mac failure remain preserved. This closes
T044/T050 from the repaired source's successful CI, superseding their pre-push
checkpoint above. T018 remains the only open task; live proof is still missing.
Evidence: `.scratch/acceptance/c5g/ci-completed.json` and the dated repair report.
