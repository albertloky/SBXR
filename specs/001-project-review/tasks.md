# Tasks: Existing SBXR project review

Input: [spec.md](spec.md), [plan.md](plan.md), research, data model and contracts.
Tests are required by FR-005. No task authorizes live work or failure disposition.

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
- [ ] T012 Commit reviewed changes on main and verify CI; record source/run references in specs/001-project-review/review.md.

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
