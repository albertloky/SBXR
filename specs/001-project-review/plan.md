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
