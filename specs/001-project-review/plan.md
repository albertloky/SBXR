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
