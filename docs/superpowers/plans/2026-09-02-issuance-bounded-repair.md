# Issuance-bounded repair implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development for the code task and its independent reviews.

**Goal:** Apply Albert's approved automated-only coverage change without waiving the retained production and Karing checks.

**Architecture:** Reuse the repair scope, existing signed attempt, exact scenario validator, native workflow and public Acceptance Record. Add explicit policy/list binding; do not add a runtime mode, trust root, or test harness.

**Tech Stack:** Go 1.26.6, existing GitHub Actions and shell collector.

## Task 1: Policy, signed matrix, and public record

Files: `internal/softwarelifecycle/release_support.go`,
`internal/softwarelifecycle/adapter/github/release_support.go` and its tests,
`cmd/sbxr-release/qualification_scope.go`, `qualification_recurring.go`, and
`qualification_scope_test.go`; existing fixture callers only if necessary.

- [ ] Extend the existing repair command regression first: set
  `evidence_policy` to `repair-issuance-bounded-v1`, set
  `automated_only_scenarios` to ADR-0019's exact ordered list, and remove those IDs
  from `required_scenarios`. Run
  `GOTOOLCHAIN=go1.26.6 go test ./cmd/sbxr-release -run TestQualificationCommandBindsCleanInstallRepair -count=1`;
  expect refusal before implementing support.
- [ ] Add two shared immutable string constants for the policy and space-separated
  list. Add optional signed attempt fields `EvidencePolicy string` and
  `AutomatedOnlyScenarios []string`. In `validAttemptSupport`, repair requires
  exact policy and `slices.Equal` to the fixed list. All other scopes require
  absence of both fields. In `attemptScenarios`, filter only that exact list for
  repair. Do not change per-scenario evidence, clocks, or other scopes.
- [ ] Emit exact public lines `Evidence policy: <policy>`,
  `Automated-only scenarios (not live): <space-separated list>` and
  `Automated-only result: Passed in native amd64/arm64 workflow`. The embedded
  Acceptance Record already includes the signed attempt. Require these exact
  unique lines in the public repair-support reader; reject them on other scopes.
- [ ] Extend regression mutations: missing/unknown policy, missing/reordered/extra
  automated-only IDs, claiming an excluded case live, omitted Karing or managed
  renewal, and policy on first/recurring scope must refuse. Assert exact public
  disclosure and absence of `Scenario:` entries for automated-only cases.
- [ ] Run focused package tests, review diff, and commit only intended code/tests.

## Task 2: Review, verification, and integration

- [ ] Independent spec review, then code-quality review of Task 1 and ADR-0019.
- [ ] Run full normal and race suites with `-p 1 -timeout 30m ./... -count=1`,
  `go vet ./...`, `go mod verify`, both Linux cross-builds and diff/format checks.
- [ ] Point ADR-0016, ADR-0018 and the packaged acceptance procedure to ADR-0019.
  Record the approved change on the parent spec and qualification ticket without
  inventing live passes or reopening the Owner-closed ticket.
- [ ] Commit explicit paths; recheck ancestry and fast-forward main. Verify native
  CI before live work. No stable publication merely from code verification.

## Task 3: Retained live execution

- [ ] Freshly verify public baseline/history/unused identity, VPS absence and locks,
  exact Certbot/snap planned refresh, latest official Karing bytes and Mac controls.
- [ ] Prepare the canonical attempt with the exact retained list and three planned
  issuances. Use only the existing candidate workflow and protected approval.
- [ ] Drive the unchanged packaged scenarios in order through supported operations.
  Use protected temporary comparison channels and secret-safe observations. Final
  Karing remains last, with its actual due refresh and complete owned removal.
- [ ] At an unexpected failure stop test mutations, preserve safe failure facts,
  perform supported cleanup, diagnose and fix the cause, and use a fresh identity.
  Never substitute simulated evidence for an unperformed retained live case.
