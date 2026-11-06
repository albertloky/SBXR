# Feature Specification: Existing SBXR project review and improvement

**Feature Branch**: `main` (required by AGENTS.md; no feature branch created)

**Created**: 2026-11-05

**Status**: Prior repairs and q213 reservation CI verified; bounded failure-cleanup repair locally verified; repair push/CI pending; live criterion unverified

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
  may be performed under the original offline review authorization. The separately
  approved reservation-only continuation below does not authorize any live or
  remote release mutation.
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


## Approved continuation: retain failed build 212 (2026-11-05)

The Owner separately approved preserving build 212 through the exact fixed
reservation mechanism, including source, tests, documentation, commit/push and CI.
This resolves the policy decision in F004 only for that identity; it does not
expand the original review authorization to live operations or publication.

- **FR-011**: The existing fixed reservation policy MUST additionally bind failed
  v3.1.138/212, draft 434759360, source 13431bc29500bf20dc108dc325590403d0ca056c,
  run 41958829811, as signed-unqualified, including its verified manifest, index
  and four exact asset identities. The preceding nine records MUST remain unchanged.
  Missing/changed/unknown authority or refs MUST refuse. Its tag, sequence and
  release ID MUST remain unavailable for reuse or promotion. Existing admission
  and historical evidence semantics MUST remain intact.
- **SC-007**: Fresh read-only checks match the approved record; regression checks
  prove the ten-record policy, preserved refusals and next-sequence admission
  without remote mutation. Final-source checks/CI pass. The failed run, draft,
  assets and signature remain unchanged and no live attempt is made.

US3 acceptance: given the exact approved failed identity, the supported workflow
can retain it and evaluate a fresh candidate above all published, burned and
reserved sequences. Given any changed identity, omitted reservation or attempted
reuse, it refuses. A reservation never makes the failed candidate qualified.

## Approved continuation: retain failed build 213 (2026-11-06)

The Owner separately approved exactly one further signed-unqualified reservation,
including its bounded code, tests, documentation, review, commit/push and CI.
This continuation preserves the previous build-212 decision and all original
product and authority limits; the original read-only proposal is evidence, not
itself the approval.

- **FR-012**: Retention MUST additionally bind failed v3.1.139/213, draft
  435196915, source f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3, run
  42023983739 attempt 1, as signed-unqualified, with its exact signed manifest,
  release index and four asset identities. The previous ten reservations MUST
  remain unchanged. The tag, sequence and release ID MUST be unavailable for
  reuse or promotion; missing, changed, duplicated or unavailable observations,
  or present release/burn refs, MUST refuse. Historical signed evidence MUST
  retain its original meaning.
- **SC-008**: Read-only evidence matches the approved identity; relevant checks
  prove the exact eleven-reservation set, preserved refusals and fresh candidate
  admission above all observed release/burn/reservation sequences. Final-source
  checks and CI pass. The original failed draft, body, four assets, signature and
  outcome remain preserved, without a remote release mutation or new live attempt.

US3 acceptance: given all eleven exact retained identities and explicitly absent
release/burn refs, the supported tooling can evaluate a fresh candidate. Given
omission, relabelling or reuse of build 213, it refuses. Retention supplies neither
qualification evidence nor permission to alter or finalize the failed release.
No new signing, finalizer rerun, burn, deletion, VPS/client/security change,
cleanup execution or publication is authorized by this continuation.

## Approved continuation: bounded failure cleanup — 2026-11-06

The Owner authorized offline repair of the existing failure-cleanup callers and
pending-response handling. This implements the existing requirement that safe
cleanup must not depend on a missing client reply; it authorizes no live execution
or change to product authentication, ownership rules or qualification deadlines.

- **FR-013**: After a failed or stopped journey, the explicit failure-cleanup
  route MUST admit only the currently supported Complete removal or Finish
  removal action, with fresh product authority, existing confirmation and bounded
  process supervision. It MUST preserve the original failure evidence and its
  timestamps. A pending response MUST remain pending and grant no extra cleanup
  time. Cleanup MUST use the original request plus only actual completed waits,
  capped by the signed finish, existing handoff deadline, explicit absolute
  cleanup cutoff and existing protected runtime limits, leaving the required
  post-action verification reserve. The full configured action cap plus that
  reserve MUST fit the remaining original window before launch. Missing,
  mismatched, sealed, expired or unsafe timing authority MUST refuse before
  product launch. The
  whole cleanup sequence MUST share its original budget and recheck it before
  each launch; no per-command reset or automatic retry is permitted.
- **SC-009**: Relevant real-process/filesystem regressions fail before the repair
  and pass afterward for both permitted actions, pending and completed response
  states, expiry between steps and invalid authority. Refusals launch no product
  action; pending records and original failure bytes/timestamps remain unchanged.
  Normal qualification action and sealing behavior, confirmation, cancellation
  and process cleanup remain protected. Final-source local checks and CI pass;
  actual client, secret, transport and owned-absence checks remain separate from
  a successful menu result and from any future live qualification.

US3 acceptance: given valid unsealed timing authority and an admitted removal
state, bounded cleanup can use that state's existing removal action without a
client response. Given uncertainty or exhausted time, it refuses and leaves the
actual incomplete/unknown outcome to the existing failure-reporting path. Given
another action, a pending normal qualification action or sealing a pending draft,
the existing refusal remains. Cleanup
cannot synthesize a response, continue setup, rotate identity, request details,
retry mutations, recreate authentication or turn the failed journey into a pass.
