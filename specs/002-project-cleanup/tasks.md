# Tasks: Project cleanup

Input: [spec.md](spec.md), [plan.md](plan.md), [research.md](research.md).

## Phase 1: Setup

- [x] T001 Inspect AGENTS.md, docs/README.md, triggered guides, working tree, and installed .agents/skills/speckit-* workflows.
- [x] T002 Create specs/002-project-cleanup/spec.md and checklists/requirements.md while preserving .specify/feature.json.

## Phase 2: Foundation

- [x] T003 Inventory the tracked tree and record decisions in specs/002-project-cleanup/research.md; resolve plan and task templates without changing the active feature.

## Phase 3: US1 — Accurate navigation

Independent check: all new/changed local targets exist and each path's role matches the tree.

- [x] T004 [US1] Correct the mixed-language layout and add a work-index route in docs/README.md.
- [x] T005 [US1] Add specs/README.md with scope-qualified links to existing review and new cleanup records.

## Phase 4: US2 — Evidence and preservation

Independent check: every top-level area has a disposition and no unrelated bytes change.

- [x] T006 [US2] Record inventory, observed defects, preserved areas, and deferred work in specs/002-project-cleanup/assessment.md.
- [x] T007 [US2] Record baseline and final link/scope/whitespace checks in specs/002-project-cleanup/assessment.md and .scratch/acceptance/cl11/validation.txt.

## Phase 5: Completion

- [x] T008 Review final diff, verify selector preservation and task coverage, and update specs/002-project-cleanup/spec.md status.

## Dependencies and execution

T001 -> T002 -> T003 -> T004 -> T005 -> T006 -> T007 -> T008.
US1 is the smallest useful navigation increment. US2 supplies independently readable
assessment evidence. Execute sequentially to avoid shared-document races. Read-only
link resolution and syntax checks are parallelizable, but no extra agent is needed.
No new automated test source was needed for the initial documentation phase.
The source continuation retains and exercises existing independent tests.

## Coverage

FR-001: T003/T006; FR-002: T004/T005; FR-003: T002/T006/T008;
FR-004: T003/T006; FR-005: T007/T008; FR-006: T001/T008.
SC-001: T006; SC-002: T007; SC-003: T008; SC-004: T006/T007.

## Phase 6: US3 — Remove redundant pure transformations

- [x] T009 [US3] Reconcile specs/002-project-cleanup/{spec,plan,research,tasks}.md and run Spec Kit consistency/prerequisite checks for the source continuation.
- [x] T010 [US3] Record baseline RFC encoding vectors and tests/subscription_artifact.rs plus tests/server_configuration.rs results under .scratch/acceptance/cl12/.
- [x] T011 [US3] Replace the custom encoder in src/subscription_artifact.rs with the existing standard padded engine, retaining the RFC vector assertions and golden artifacts.
- [x] T012 [US3] Replace the duplicate digest helper in src/server_configuration.rs with records::sha256_hex at both callers; preserve validation and public signatures.
- [x] T013 [US3] Run focused before/after checks, full offline Rust tests and strict all-target Clippy; retain results in .scratch/acceptance/cl12/.
- [x] T014 Review final source diff and update specs/002-project-cleanup/assessment.md, task completion and scope limitations.

Dependencies: T009 -> T010 -> T011 -> T012 -> T013 -> T014.
Coverage: FR-007/SC-005 -> T011/T012; FR-008/SC-006 -> T010/T013;
FR-003/FR-005 -> T009/T014. No new dependency or behavioral feature.

Closeout: 19 focused tests passed before and after; wrong-padding mutation rejected
by two existing integration tests and restored. Full product suite: 690 passed, two
existing ignored entries, zero failures. Packaging: 12 passed. Strict all-target
Clippy, formatting, link checks and whitespace pass. Source commit: `799e236`.
See [assessment.md](assessment.md) for precise limits and preserved areas.

## Phase 7: CI fixture repair

- [x] T015 Preserve failed job 130454055008 evidence in .scratch/acceptance/cf11/ and inspect src/proxyinstallation/subscription_tests.rs teardown callers and unchanged serving implementation.
- [x] T016 Add an adjacent real-service/socket regression in src/proxyinstallation/subscription_tests.rs and record the original assertion failure in .scratch/acceptance/cf11/red.log.
- [x] T017 Remove the invalid rebind assertion in src/proxyinstallation/subscription_tests.rs while retaining cancellation/join/code checks; pass regression, full affected module, serving/handoff tests, Clippy and formatting.
- [ ] T018 Record evidence and uncertainty in specs/002-project-cleanup/assessment.md, commit/push the bounded repair and verify exact-source native CI.

Dependencies: T015 -> T016 -> T017 -> T018. FR-009/SC-007 map to T015–T018.
The failed run remains a failed run; this phase adds no live or publication authority.
