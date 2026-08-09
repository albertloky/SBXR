# Owner Console acceptance

This file defines stable checks for issues #135 and #136. It contains no run results, Client Access Values, Infrastructure Secrets, raw terminal contents from an Owner session, or claim of Integrated, Live, Owner, or Release acceptance.

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

Require only the approved Bubble Tea v2 and Lip Gloss v2 production UI stack. The pseudo-terminal package is test-only. Reject product-Module imports, host mutation, arbitrary commands, State persistence, provider logic, release verification, diagnostics collection, recovery algorithms, or privileged logic inside Owner Console.

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

### OC-ACTIVE-PTY-02 — Forced termination boundary

Run:

```sh
go test ./internal/ownerconsole -run '^Test(RunCannotPromiseRestorationAfterForcedTermination|ForcedTerminationDocumentationNamesExactResetCommand)$' -count=1
```

Require a child Owner Console killed after entering the alternate screen not to produce a false manageable-restoration claim. Require documentation to distinguish this forced boundary and name exactly:

```sh
reset
```

Clipboard-request, sudo-handoff, SSH-disconnect, and integrated product journeys that require later Owner Console slices remain separate acceptance work. Codex Live Acceptance and Owner Acceptance require an explicitly approved Acceptance Run and must not be inferred from these checks.
