# Owner Console acceptance

This file defines stable checks for issues #135, #136, #137, and #138. It contains no run results, Client Access Values, Infrastructure Secrets, raw terminal contents from an Owner session, or claim of Integrated, Live, Owner, or Release acceptance.

## Module Verification

### OC-ENTER-01 — Refuse unsafe startup before drawing

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunRefusesUnsafeTerminalBeforeDrawing$' -count=1
go test ./cmd/sbxr -run '^TestDefaultRunRefusesRedirectedTerminal$' -count=1
```

Require redirected or non-interactive input/output, missing alternate screen, missing cursor addressing, unreadable encoding, missing standard keyboard input, and startup below `80×24` to name the exact failed capability, give the correction, exit safely, and emit no Client Access Value.

### OC-ENTER-02 — Style A frame at both approved sizes

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunRendersCanonicalStyleAFixturesAtBothApprovedSizes$' -count=1
go test ./internal/ownerconsole -run '^TestCanonicalFramesRemainExact$' -count=1
```

Require all sixteen canonical scenarios at exact `80×24` and `120×36`. Require stable persistent navigation at both sizes, the approved relevant-detail column only at `120×36`, dedicated Access without `PgDn`, and no missing minimum-size action.

### OC-ENTER-03 — Keyboard, paste, resize, and legal help

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(NavigationUsesSafeKeysAndNeverQ|EveryPersistentNavigationItemOpensItsScreen|PausesAndResumesAfterResize|AllowsSafeExitWhileUndersized|WrapsSafetyTextAndShowsOnlyLegalShortcuts)$' -count=1
```

Require arrows, `Tab`, `Shift+Tab`, `Enter`, `Space`, and `Esc` to use the same navigation model. Require `Q`, `q`, multiline bracketed paste, and confirmation-like pasted text not to exit or authorize an action. Require `Ctrl+C` to open the visible confirmation. Require resize below `80×24` to pause and report exact current and required dimensions, then resume the same scenario. Require long safety text to wrap and every footer to show only legal actions; forward-only removal must not show Back.

### OC-ENTER-04 — Palette, Unicode, and meaning without color

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunDegradesColorAndUnicodeWithoutLosingMeaning$' -count=1
```

Require true-color, 256-color, 16-color, and `NO_COLOR` sessions to retain explicit text for health, focus, risk, and exit. Require Unicode separators only when readable Unicode is available and ASCII fallbacks otherwise. No test may depend on a terminal product allowlist or color alone.

### OC-ENTER-05 — Presentation-only architecture

Run:

```sh
go test . -run '^Test(RepositoryDependencies|OwnerConsolePresentationBoundary)$' -count=1
```

Require only the approved Bubble Tea v2, Lip Gloss v2, and reviewed QR production stack. The pseudo-terminal package is test-only. Reject product-Module imports, host mutation, arbitrary commands, State persistence, provider logic, release verification, diagnostics collection, recovery algorithms, or privileged logic inside Owner Console.

### OC-ACCESS-01 — Privacy and ordinary system authentication

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunMakesThePerLaunchPrivacyAndAuthenticationDecisionBeforeAccess$' -count=1
go test ./cmd/sbxr -run '^TestSystemAuthenticationReportsEveryOutcome$' -count=1
```

Require the warning on every launch before sudo or a Client Access Value. Require all three choices, one normal system authentication only after the authenticated choice on an existing installation, and no authentication before fresh-install Apply. Require successful authentication to enter authenticated Overview. Require denied, cancelled, failed, or expired authentication to enter explained limited mode without Client Access Values or privileged presentation.

### OC-ACCESS-02 — Dedicated Access, copy, and QR

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(RevealsOnlyAuthenticatedDedicatedAccessValues|RejectsInfrastructureSecretMarkerAtTheAccessBoundary|CopiesEveryApprovedAccessValueWithExactFeedback|ReportsUnconfirmedAndFailedCopyWithoutLosingManualSelection|MouseClickAndEnterUseTheSameExplicitCopyAction|ShowsQRFromTheSameValueOnlyWhenItFits)$' -count=1
```

Require all six typed profile share URIs and the universal, v2rayN, Shadowrocket, Karing, Mihomo, and sing-box links only in authenticated Access. Require actual counts, omissions, and candidate-only Shadowrocket Owner Acceptance facts. Require every value to remain visibly selectable with the exact copy label, exact named confirmed result, exact unconfirmed result, and manual failure fallback. Require mouse and keyboard activation to request the same value. Require QR output to use that exact value and disappear safely when it cannot fit.

### OC-ACTIVE-01 — Hostile paste remains input data

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunKeepsHostilePasteAsVisibleInputData$' -count=1
```

Require typed `Q` and `q`, single-line or multiline bracketed paste, confirmation words, escape-like bytes, untrusted control characters, and bytes after a hostile embedded paste terminator to remain inert input data. Require a safe visible form or an explicit neutralization marker, no verbatim control output, no screen change, and no approval or exit until the explicit key action.

### OC-ACTIVE-02 — Refresh and confirmation stability

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunBackgroundRefreshKeepsConfirmationUntilExplicitDismissal$' -count=1
```

Require a typed background update not to dismiss the visible exit confirmation. Require the refreshed facts to appear only after explicit dismissal, with the same viewed screen, focus, input, and selection.

### OC-ACTIVE-03 — Truthful typed progress

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(PresentsOnlyTypedTruthfulProgress|ContinuingUnknownProgressNeverRestartsElapsedTime|TypedProgressNeverConflictsWithLargeDetails)$' -count=1
```

Require measured bars only for real completed and total units. Require unknown work and an unmeasured current step to show a spinner plus monotonic elapsed time without a percentage. Require a mixed measured step to identify that step without inventing overall progress. Reject invalid, unsupported, or screen-incompatible typed progress with fixed secret-safe wording while retaining safe close and cancellation actions. At `120×36`, require the detail column to agree with the current typed facts.

### OC-CHANGE-01 — Complete one-use Plan and Correction Flow

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(ReviewsCompleteTypedPlanWithoutStartingWork|ReviewsEveryPlanSectionAtMinimumSizeBeforeApply|PresentsCompleteCorrectionFlowWithoutBypass|SubmitsCorrectionInputAndSelectionOnlyToASeparateFixPlan|RequiredCorrectionInputCannotBeSubmittedEmpty|FixPlanBackRestoresCorrectionEditingState|CheckAgainReturnsToTheOwningModule|PlanBackReturnsToSafeEditing|PagesLongValidReviewsAtLargeSize|CopiesCorrectionEvidenceThroughAnExplicitAction|RefusesUnsafeTypedPlanEvidence|RefusesIncompletePlanFacts|RefusesIncompleteCorrectionFlow|ReadOnlyChoiceCreatesNothingAndFreshInstallReviewsWithoutSudo)$' -count=1
```

Require read-only review and pre-approval disconnect to start no work. Require a complete typed Plan with revision, checksums, observations, verified external inputs, effects, Required and Advisory checks, interruption, cancellation, and rollback. Require Correction Flow Problem, Found, Required, stop reason, separate Fix Plan, current Owner steps, input or selection, Check again, Back, and redacted evidence. Require Back to restore an operable typed editing field and build a separate updated Plan. Keep every fact and action reachable without clipping at both `80×24` and `120×36`. Reject incomplete or unsafe presentation facts without rendering their marker.

### OC-CHANGE-02 — Approval, durable Change Set result, and cancellation

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(RejectsStaleApprovalAndRebuildsAPlan|ShowsChangeSetProgressAndRequestsSafeCancellation|RelaunchShowsOnlyTypedChangeSetResult|ApprovedWorkUsesAnOperationContextIndependentOfTheConsole|DisconnectCancelsPendingAuthenticationBeforeApply|MalformedOutcomeFactsNeverInventADomainResult)$' -count=1
```

Require Apply to receive only the exact reviewed Plan identity after authentication. Require stale or reused refusal to rebuild a fresh Plan. Require approved work to remain independent of Console exit, explicit cancellation to wait for a safe rollback checkpoint, and relaunch to show only typed active Change Set, success, rollback, or Recovery Required facts without inference from process exit or service reachability.

## Seam Verification

### OC-ENTER-PTY-01 — Real pseudo-terminal lifecycle

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(ThroughPseudoTerminalRestoresTerminal|RefusesUnconfirmedDrawingModesBeforeAFrame)$' -count=1
```

Require unfamiliar terminal names to be judged by replies rather than a product allowlist. Require an unconfirmed drawing mode to be refused before a frame. Require one real `80×24` pseudo-terminal to report its capabilities, reset contaminated mouse and paste modes before drawing, enter the alternate screen, use the real Bubble Tea input loop, leave the alternate screen, and restore the exact prior cursor, mouse, paste, and keyboard settings after a manageable exit.

### OC-ACTIVE-PTY-01 — Resize-resume preserves active state

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(PausesAndResumesAfterResize|AllowsSafeExitWhileUndersized|PreservesInteractionStateThroughResizeAndRefresh)$' -count=1
```

Require resize below `80×24` to pause normal drawing and activation, show exact current and required sizes, preserve input, focus, navigation selection, Plan screen, operation screen, prompt, error, and result, and resume the same state. Require safe exit while undersized and no mutation approval or partial redraw.

### OC-ACCESS-PTY-01 — Sudo and clipboard terminal handoff

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunHandsSudoAndClipboardRequestsThroughTheRealPseudoTerminal$' -count=1
```

Require the real pseudo-terminal to leave the alternate screen for the normal system password prompt without echoing its marker, re-enter only after success, keep Access values out of ordinary Overview, emit the Owner-requested clipboard transfer for the exact selected value, retain the exact unconfirmed fallback, and visibly underline the selected value.

### OC-ACTIVE-PTY-02 — Forced termination boundary

Run:

```sh
go test ./internal/ownerconsole -run '^Test(RunCannotPromiseRestorationAfterForcedTermination|ForcedTerminationDocumentationNamesExactResetCommand)$' -count=1
```

Require a child Owner Console killed after entering the alternate screen not to produce a false manageable-restoration claim. Require documentation to distinguish this forced boundary and name exactly:

```sh
reset
```

SSH-disconnect and integrated product journeys remain separate acceptance work. Codex Live Acceptance and Owner Acceptance require an explicitly approved Acceptance Run and must not be inferred from these checks.
