# Feature Specification: Project cleanup

**Feature Branch**: `main`
**Created**: 2026-11-11
**Status**: Cleanup pushed; CI teardown-fixture repair in progress
**Input**: User description: "use spec kit to cleanup the whole sbxr project"

## User Scenarios & Testing

### User Story 1 - Find the right project area (Priority: P1)

A maintainer can distinguish the current rewrite, retained reference, release tooling,
and work records before starting a change.

**Why this priority**: An incomplete directory map sends maintainers to the wrong implementation.
**Independent Test**: Follow the documentation index to each maintained area and check that its stated role matches the checkout.

**Acceptance Scenarios**:

1. **Given** the mixed implementation checkout, **When** a maintainer opens its directory map, **Then** both implementations, tests, packaging, and specifications are named with their roles.
2. **Given** current and historical work records, **When** a maintainer follows the work index, **Then** they can find each specification without mistaking a report for current policy or a conversation transcript.

### User Story 2 - Preserve useful work during cleanup (Priority: P2)

The Owner receives an evidence-based maintenance assessment covering every top-level
project area, with useful fixes and explicit reasons for preserved areas.

**Why this priority**: Broad cleanup must not destroy reference code, fixtures, or another thread's evidence.
**Independent Test**: Compare the final change list and assessment against the initial inventory and confirm every change is explained.

**Acceptance Scenarios**:

1. **Given** existing work and private evidence, **When** cleanup completes, **Then** unrelated bytes and historical outcomes remain unchanged.
2. **Given** an unverified improvement or conflicting ownership, **When** it is assessed, **Then** it is recorded as deferred rather than treated as a completed fix.

### User Story 3 - Maintain fewer equivalent implementations (Priority: P2)

A maintainer can use the project's established encoding and digest facilities
without maintaining duplicate implementations of the same output format.

**Why this priority**: Removing redundant pure transformations reduces maintenance
surface without changing installation, recovery, or qualification behavior.
**Independent Test**: Existing independent output fixtures, encoding vectors, and
digest comparisons pass before and after each replacement.

**Acceptance Scenarios**:

1. **Given** a supported proxy profile, **When** its client artifact is rendered,
   **Then** the bytes, field order, padding, line endings and size refusal remain identical.
2. **Given** server configuration and dedicated-unit bytes, **When** their digests
   are rendered, **Then** the exact existing lowercase digest values remain identical.

### Edge Cases

- Private historical evidence links can be absent from this checkout without being broken public navigation.
- Both implementations and root integration tests can be intentional; age or location alone is not a deletion reason.
- Another thread may change shared files; reread before writing and review only this task's changes.
- Local tool availability and offline checks do not establish native or live qualification.

## Requirements

### Functional Requirements

- **FR-001**: Assess all top-level project areas and identify confirmed maintenance defects separately from possible improvements.
- **FR-002**: Provide accurate navigation for the current implementation, retained reference, tests, packaging, and work specifications.
- **FR-003**: Preserve unrelated work, historical evidence, fixtures, current release gates, and existing work ownership.
- **FR-004**: Make only evidence-supported, behavior-preserving cleanup changes; record deferred proposals and their reasons.
- **FR-005**: Check changed navigation and final change scope, recording observed results and limitations.
- **FR-006**: Do not install tools, run live operations, change credentials, delete data irreversibly, or publish releases as part of this maintenance pass.
- **FR-007**: Replace confirmed redundant pure output transformations with established equivalents while preserving exact rendered bytes and all validation/error contracts.
- **FR-008**: Prove source simplifications using existing independent fixtures and applicable offline checks before and after changes.

- **FR-009**: Fixture teardown MUST join its own serving work and close its clients without assuming a released network address remains unallocated; repair CI failures without changing product behavior or weakening owned-resource checks.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every maintained top-level area has a recorded assessment disposition.
- **SC-002**: Every added or changed local navigation link resolves in the checkout.
- **SC-003**: Zero unrelated files, existing work records, or private artifacts are deleted or overwritten.
- **SC-004**: Every delivered change has a stated reason and verification result; deferred work is clearly identified.
- **SC-005**: Two identified redundant output implementations are removed with unchanged independent fixture and digest results.
- **SC-006**: Applicable focused and broad offline source checks pass, with platform omissions stated.

- **SC-007**: A deterministic occupied-address regression fails before the repair and passes after; focused local checks and exact-source CI pass.

## Assumptions

- "Cleanup" means maintenance with preserved behavior, not product redesign or removal of retained reference implementations.
- The existing qualification thread retains its work; this pass uses a separate specification and preserves the shared feature selector. Agnes confirmed that its latest turn is completed and it is not actively editing, allowing this source continuation.
- Assessment is a repository-wide maintenance inventory, not a claim of an exhaustive security audit or every-line correctness review.
