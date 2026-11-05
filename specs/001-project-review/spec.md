# Feature Specification: Existing SBXR project review and improvement

**Feature Branch**: `main` (required by AGENTS.md; no feature branch created)

**Created**: 2026-11-05

**Status**: Offline implementation and native CI verified at `6c2b287`; live criterion unverified

**Input**: Owner requested the full Spec Kit process to review and improve the entire
existing SBXR project after the failed live run, including requirements and design.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Understand actual readiness (Priority: P1)

The Owner can distinguish supported behavior, verified behavior and unresolved
work across clean install/Standard, HTTP subscription, identity/disclosure, optional
tunnel, removal/retained authority, lifecycle Status/Check, lifecycle Recover, and
public entry/release qualification.

**Why this priority**: Incomplete live qualification must not be confused with the
large body of implementation and offline checks.

**Independent Test**: Trace every current product capability to its governing
requirement, implementation boundary, relevant test and remaining evidence gap.

**Acceptance Scenarios**:

1. **Given** current source and dated evidence, **When** readiness is reviewed,
   **Then** each capability identifies its supported scope and evidence limits.
2. **Given** the failed build 212, **When** its outcome is reported, **Then** setup
   success, details timeout, unreached journeys and verified cleanup remain distinct.

### User Story 2 - Complete the existing reviewed journey reliably (Priority: P1)

The Owner can inspect current details and perform the existing supported actions
without avoidable repeated work, while preserving fresh authority checks.

**Why this priority**: Build 212 cannot proceed past its initial details check.

**Independent Test**: Reproduce an identified cause at an offline boundary, then
show the repair passes the same regression and relevant refusal tests.

**Acceptance Scenarios**:

1. **Given** a supported installation, **When** details are requested, **Then** the
   complete details/menu response meets the unchanged 90-second qualification
   budget on an authorized exact-candidate live test; offline results remain provisional.
2. **Given** changed ownership, executable, credential or cancellation facts,
   **When** an action or disclosure is requested, **Then** it refuses unsafe effects.
3. **Given** cancellation or interrupted changes, **When** recovery or removal is
   used, **Then** only the existing proved direction and owned resources are affected.

### User Story 3 - Improve the project without expanding product scope (Priority: P2)

The Owner receives a prioritized, traceable set of existing-contract corrections,
with verification and explicit decisions for unsupported or unverified work.

**Why this priority**: A whole-project review must cover more than the latest
failure without inventing new features or rewriting established rules.

**Independent Test**: Audit findings against current requirements and verify every
implemented correction, deferred decision and untouched external action.

**Acceptance Scenarios**:

1. **Given** a confirmed documentation or implementation mismatch, **When** fixed,
   **Then** its requirement, change and appropriate check are linked.
2. **Given** a question requiring new product policy or a live operation, **When**
   encountered, **Then** it is recorded for decision rather than silently executed.

### Edge Cases

- Historical evidence describes a gate that has since changed: retain its dated
  meaning and distinguish current behavior.
- Stale or foreign installed authority: preserve bytes and refuse adoption.
- Interrupted setup, credential change or removal: retain the proved recovery direction.
- Optional tunnel locally ready but outside access unverified: report pending honestly.
- A local performance improvement passes but real-host timing remains unknown:
  do not claim the live deadline is met.
- Failed candidate requires disposition: retain draft/assets unchanged pending authorization.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Review MUST cover all eight capability areas listed in Story 1,
  with requirement, implementation, tests and evidence gaps for each.
- **FR-002**: Review MUST preserve the current clean-install-only product scope,
  existing recovery exclusions, HTTP risk disclosure and optional tunnel boundaries.
- **FR-003**: Build 212 MUST be recorded as failed after successful install/setup;
  no outside proxy, subscription, credential or Karing qualification may be inferred.
- **FR-004**: Details improvements MUST preserve fresh ownership, process identity,
  cancellation and disclosure checks and the existing 90-second live budget.
- **FR-005**: Each implemented defect fix MUST have a relevant regression showing
  failure before and success after, or an explicit explanation of the unavailable boundary.
- **FR-006**: Every review finding MUST be classified as confirmed defect,
  documentation mismatch, unverified behavior or decision required.
- **FR-007**: Existing unrelated changes and failed candidate bytes MUST be preserved.
- **FR-008**: No new live test, failure disposition, security change or publication
  may be performed under this offline review authorization.
- **FR-009**: Reports MUST distinguish implemented, regression-tested and
  live-validated behavior, and identify exact remaining prerequisites.

### Key Entities

- **Capability**: Existing Owner-visible behavior with a governing requirement.
- **Finding**: Evidence-backed discrepancy or gap, severity, scope and disposition.
- **Verification**: A named check tied to source and a requirement, including limits.
- **Candidate**: Exact release identity and immutable bytes with its own observed outcome.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All eight capability areas have traceable review coverage with no
  unclassified findings.
- **SC-002**: Every implemented correction has passing relevant checks and a
  documented before/after result or verification limitation.
- **SC-003**: The initial details journey completes within its unchanged 90-second
  live budget before any future claim that this failure is live-resolved.
- **SC-004**: Zero unauthorized live attempts, disposition actions or publications;
  failed candidates and unrelated work remain preserved.
- **SC-005**: The Owner can identify all remaining release blockers from the final
  review without consulting raw private logs.

## Assumptions

- The existing accepted rules are authoritative; this review does not ratify new policy.
- Build 212 evidence establishes a timeout, not yet its complete causal explanation.
- Local tests can establish bounded repairs but cannot replace real outside/Karing evidence.
- Existing toolchains and fixtures will be reused; dependencies are not upgraded merely for review.
- A new exact-candidate live attempt and failed-candidate disposition need separate authorization.

## Continuation: coherent menu status (2026-11-05)

Owner instruction: continue the fix using Spec Kit. This refines US2 and FR-004;
all existing scope and authorization limits remain unchanged.

- **FR-010**: A displayed menu frame MUST obtain proxy and subscription status
  together without repeating the same HTTP inspection solely for presentation.
  Every subsequent frame and action MUST still observe fresh state. No status
  or authority may be reused across Owner input.
- **SC-006**: A running HTTP fixture MUST demonstrate one HTTP inspection per
  combined status read, with new observations after input/state changes. The
  public menu/action selection and independent removal availability stay intact.

Acceptance: given a running installation, rendering the frame uses one combined
status read; given changed facts at the next input boundary, the next frame shows
fresh facts or refusal. An earlier Prepared Action expires on the combined read.
Unavailable HTTP authority must not hide separately admitted removal actions.
