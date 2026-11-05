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
- [ ] T024 [US3] Commit/push the reviewed preservation on main and verify exact-source CI; retain results under .scratch/acceptance/q212res/.

Dependency: T019 -> T020 -> T021 -> T023 -> T024. T022 can run independently after
T019 and is finalized with T023 results. The invariant is exact retained identity
and refusal of changed/reused authority, not a live qualification claim. T018
remains open and independent. No existing task is retroactively marked live-passed.
