# Owner Console acceptance

### OC-STAGED-01 — Guided staged onboarding

Authority: OWNER-CONSOLE-001–014, PROFILE-005–010, CLOUDFLARE-AUTH-001–007, CLOUDFLARE-SETUP-010–017, TEST-010–012, and TEST-015.

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(DrivesOneTypedCloudflareProfileSetupJourney|BackMovesOneTypedSetupScreenWithoutApply|SubmitsTypedSetupCorrectionInputAndSelection|NeverInventsCloudflareSetupAuthorityWithoutModule|ShowsStagedOnboardingDecisionScreensAtExactTerminalSizes|ShowsTypedCloudflareSetupTerminalResultsAtExactSizes|OverviewShowsOnlyTheCurrentStagedCapability|RoutesNotSetUpProfilesOnlyToCollectiveCloudflareSetup)$' -count=1
```

Require `Run` through the real Bubble Tea event loop to show `INSTALLATION COMPLETE`, optional setup entry, masked broad-token guidance, exact Plan review, the separate irreversible confirmation, Recovery Required, and `CLOUDFLARE PROFILE SETUP COMPLETE` at `80×24` and `120×36`. Require revision `1` to show one of six set up and five exact `Not set up` profiles without a warning, degraded state, or percentage. Require a `Not set up` profile to expose only collective Cloudflare Profile Setup. Require completed setup to show six Enabled profiles, no Client Access Value, and no setup action.

These checks record Module acceptance only. They do not perform or claim human usability, real Cloudflare, provider mutation, live VPS, maintained-client, Owner Acceptance, or Release Qualification.

This file defines stable checks for issues #135 through #142. It contains no run results, Client Access Values, Infrastructure Secrets, raw terminal contents from an Owner session, or claim of Integrated, Live, Owner, or Release acceptance.

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

### OC-ACCESS-01 — Authenticated root launch and Access privacy

Run:

```sh
go test ./cmd/sbxr-release -run '^TestGeneratedBootstrap(AdmitsARootOwnerLaunchIdentityWithoutSudo|RoutesOwnerLaunchThroughThePrivateUbuntuAdapter|ReturnsOneFixedRefusalWhenLaunchAuthenticationFails)$' -count=1
go test ./cmd/sbxr -run '^TestRootOwnerConsoleStartsManagedWorkWithoutASecondSudo$' -count=1
go test ./internal/ownerconsole -run '^TestSecurityPresentationUsesTheAuthenticatedRootRuntimeModel$' -count=1
```

Require root to start the complete Owner Console directly. Require a non-root Owner Launch Identity to authenticate before SBXR shows a Console screen, and require refusal to make no change. Require the root Console to start managed work without a second sudo handoff. Require the Security presentation to describe one authenticated runtime without a root warning banner. Client Access Values remain behind the privacy choice inside that already authenticated Console.

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

### OC-ACTIVE-01A — Safe-editing focus equals activation

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunSafeEditingFocusMatchesThePublicActionInARealPseudoTerminal$' -count=1
```

Require a real pseudo-terminal to prove that physical `Enter` submits the focused field, `Space` remains input data, and `Tab` moves to the visible action area. Require arrows or `Tab` to change the persistent action selection, `Enter` or `Space` to activate only that selection, and `Shift+Tab` to return to the unchanged field. Require Bubble Tea's native blinking bar and block cursors without an application blink timer, persistent non-color focus markers, no selected persistent-navigation item while safe editing owns activation, and hostile pasted control content to remain data without a public action.

### OC-ACTIVE-01B — Typed field Help

Run:

```sh
go test ./internal/ownerconsole -run '^Test(RunShows(TheSameCompleteDomainHelp|EveryInstallationHelpSource)AtExactTerminalSizes|RunFieldChangeClearsEditingStateThroughThePublicOutcome|EditingHelpRefusesANonAllowlistedLink)$' -count=1
```

Require the owning Module's complete Help for every non-Cloudflare first-Installation input at exact `120×36` in the detail column and at exact `80×24` through **Help for this field**. Each Help result includes purpose, instructions, accepted format, common mistakes, field-specific recovery, a marked synthetic example, an allowlisted official HTTPS source, and Public or Personal Information sensitivity. Require `Esc` to return to the unchanged field, exact focus/action activation, the static allowlisted HTTPS terminal hyperlink with its exact plain URL, and refusal of any other link target. A field change clears stale input, feedback, Help selection, and correction state. Owner Console renders bounded typed facts. It does not fetch documentation or execute a browser command.

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
go test ./internal/ownerconsole -run '^TestRun(ReviewsCompleteTypedPlanWithoutStartingWork|ReviewsEveryPlanSectionAtMinimumSizeBeforeApply|PresentsCompleteCorrectionFlowWithoutBypass|SubmitsCorrectionInputAndSelectionOnlyToASeparateFixPlan|RequiredCorrectionInputCannotBeSubmittedEmpty|FixPlanBackRestoresCorrectionEditingState|CheckAgainReturnsToTheOwningModule|CorrectionInputReachesOwnerAndFreshCorrectionClearsStaleState|CorrectionInputCannotConfirmAReclamationPlan|ScenarioReturnClearsStaleCorrectionState|ShowsReclamationHelpAtBothSizesWithoutConfirming|PlanBackReturnsToSafeEditing|PagesLongValidReviewsAtLargeSize|CopiesCorrectionEvidenceThroughAnExplicitAction|RefusesUnsafeTypedPlanEvidence|RefusesIncompletePlanFacts|RefusesIncompleteCorrectionFlow|ReadOnlyChoiceCreatesNothingAndFreshInstallReviewsWithoutSudo)$' -count=1
```

Require read-only review and pre-approval disconnect to start no work. Require a complete typed Plan with revision, checksums, observations, verified external inputs, effects, Required and Advisory checks, interruption, cancellation, and rollback. Require Correction Flow Problem, Found, Required, stop reason, separate Fix Plan, current Owner steps, input or selection, Check again, Back, and redacted evidence. Require Back to restore an operable typed editing field and build a separate updated Plan. Keep every fact and action reachable without clipping at both `80×24` and `120×36`. Reject incomplete or unsafe presentation facts without rendering their marker.

For a Reclaimable VPS review, require Installation-owned Help to name the exact Reclamation Boundary, Protected Host Foundation, and consequence of `RECLAIM THIS VPS` at both approved sizes. Help and hostile paste grant no authority. Require the exact phrase `RECLAIM THIS VPS` through the interactive terminal path. Pass only an opaque, exact-Plan and facts-digest-bound, one-use approval to the owning Module. Caller booleans, environment variables, command arguments, redirected input, and an incorrect phrase grant no authority. Confirmation remains review-only: it starts no Change Set and reports that no host change was made.

### OC-CHANGE-02 — Approval, durable Change Set result, and cancellation

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(RejectsStaleApprovalAndRebuildsAPlan|ShowsChangeSetProgressAndRequestsSafeCancellation|RelaunchShowsOnlyTypedChangeSetResult|ApprovedWorkUsesAnOperationContextIndependentOfTheConsole|MalformedOutcomeFactsNeverInventADomainResult)$' -count=1
```

Require Apply to receive only the exact reviewed Plan identity from the already authenticated root Console. Require stale or reused refusal to rebuild a fresh Plan. Require approved work to remain independent of Console exit, explicit cancellation to wait for a safe rollback checkpoint, and relaunch to show only typed active Change Set, success, rollback, or Recovery Required facts without inference from process exit or service reachability.

### OC-PROFILES-01 — Six profile states and actions

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(ShowsAllSixTypedConnectionProfilesWithOnlyCompleteActions|ReviewsEachCompleteProfileChangeWithoutStartingIt|ShowsOnlyTheTypedNativeValidationResult|OpensOnlyTheSelectedProfileInAuthenticatedAccess|ProfileAndSubscriptionPlanBackRestoreTheirSelection)$' -count=1
go test ./cmd/sbxr -run '^TestProductionProfileActionSeamRefusesHiddenPortAndRepairValues$' -count=1
```

Require each named profile to show only typed enabled state, service and listener health, public address or hostname, port and transport, settings, exposure, and publication facts. Require disabled state to retain settings and credential, close exposure, omit publication, and remain distinct from failure. Require Open in Access to focus only the selected profile after authentication. Require rotate one credential, native validation, enable, and disable to return through the Profiles Module without starting work before exact Plan approval. Require `Change port` and per-profile `Repair` to be absent from production actions, and require their reserved typed values to fail closed at the production action seam.

### OC-PROFILES-02 — Subscription and distinct Client Access changes

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(ShowsNamedSubscriptionCountsAndOmissionsWithoutValues|ReviewsDistinctRotateAllTokenOnlyAndRevokeAllChangeSets|UnavailableSubscriptionHasNoHiddenActions)$' -count=1
```

Require the universal, v2rayN, Shadowrocket, Karing, Mihomo, and sing-box representations to show their actual named counts and exact omissions without rendering their values. Require rotate all six profile credentials, rotate only the subscription token, and Revoke all client access to produce separate review identities and exact effects. Revoke all must replace the subscription token, all six profile credentials, and every representation with no dual-credential grace.

### OC-PROFILES-03 — Optional session-only Live Profile Check

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(LiveProfileCheckRequiresPrivacyChoiceAndShowsAutomaticPerProfileTraffic|LiveProfileCheckShowsURLAndAutomaticProgressWhileRunning|LongLiveProfileCheckURLKeepsEveryResultAndBackAtMinimumSize|BackCancelsAndErasesSessionOnlyLiveProfileCheck|CompletedLiveProfileCheckWaitsBehindExitConfirmation|LateProfileResultsNeverMoveOrRelabelTheCurrentScreen|CancelledLiveProfileCheckCannotOverwriteANewerRun|RefusesUnsafeProfileAndLiveCheckFacts|RefusesInvalidLiveProfileCheckStreams|NilLiveStreamFailsSafeAndBackCancelsANonClosingStream)$' -count=1
```

Require Live Profile Check to remain unavailable before this root Console launch's Client Access privacy choice and outside Managed state. Require one typed Module request to stream one temporary test URL while the check is active, same-source QR only when it fits, spinner and monotonic elapsed time, and automatic pending then authenticated uplink and downlink results for all six profiles. Require an explicit session-only and memory-only explanation, cancellation and erasure on Back, no manual success action, no effect on Managed state, and fail-safe refusal of Infrastructure Secret markers or malformed typed facts.

### OC-PROVIDER-01 — Cloudflare walkthrough, credential, and correction journeys

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunCloudflare(WalkthroughUsesCurrentAccountTokenPathAndMasksByDefault|CredentialOffersOnlyTheFiveExactActions|ReplacementKeepsTheOldTokenUntilCandidateReview|ReplacementRevealIsFocusedAndRemasks|CheckNowRefreshesWithoutAcceptingALateResultOnAnotherVisit|ActionsShowWaitingStateAndQueueExitResult|RemovalRefusesWhileDependentsRemain|MissingPermissionAndPendingZoneHaveExactCorrectionActions)$' -count=1
go test ./internal/ownerconsole -run '^TestRunResizeRemasksInitialAndManagedCloudflareTokens$' -count=1
```

Require the current `My Profile > API Tokens`, selected-domain `DNS > Records`, and Cloudflare One `Networks > Tunnels & Mesh` walkthrough at exact `80×24` and `120×36`. Require User API Tokens Edit, Cloudflare Tunnel Edit, DNS Edit, and Zone Read with all-account and all-zone resources, no expiry, and no client-IP restriction. Reject Global API Keys and Account API Tokens. Keep token input masked and memory-only by default. Focused `Ctrl+R` alone toggles Reveal or Mask, changes the footer, and shows an exposure warning. Focus loss, submission, screen change, and exit remask. Paste cannot activate Reveal, submission, navigation, or approval. The complete token can appear only in the controlled Reveal frame and never in evidence, errors, failure paths, or copy actions. Require the credential view to show only status, first and last four characters, binding, last verification, optional expiry, and current uses. Require exactly Check now, Replace token, Remove from SBXR, genuine Tunnel run-token rotation, and Rotate management token. Require real checks, verification, and the 10-minute wait to show a spinner plus monotonic elapsed time, prevent duplicate activation, allow safe Back or Exit, and queue completion behind Exit confirmation. Require replacement to keep the old token active until candidate verification and exact Plan approval, and removal to refuse while any Tunnel, DNS, certificate, or profile dependency would remain falsely Managed or Healthy. Require Cloudflare Tunnel-owned correction Help to name the exact failed requirement. Require pending-zone Help to use current Cloudflare nameserver steps and provider-neutral registrar instructions without a guessed registrar link. The ordinary credential screen can offer the reviewed `Rotate management token` action, but it must not tell the Owner to rotate or revoke a provider token before Plan approval. Only the post-approval forward-only state after the irreversible checkpoint may show rotation Help, which names only `Networking > Tunnels > selected committed SBXR Tunnel > Rotate token`. Every link is fixed, allowlisted HTTPS and exact plain text. No Help fetches runtime documentation, automates a registrar, or bypasses Check again, Plan review, or approval.

### OC-PROVIDER-02 — Certificate lineages, scheduler, and safe outcomes

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(CertificatesShowsBothLineagesAndReviewsIssuanceOrRenewal|CertificateCorrectionAndTypedRollbackRemainSecretSafe|ProviderPlansBackRestoreTheirOriginAndUnsafeFactsNeverRender)$' -count=1
```

Require the IP and Direct TLS Hostname lineages, `shortlived` and `tlsserver` profiles, truthful serving expiry, IP due at `72 hours` or less, ordinary retry every `6 hours`, busy-lock retry within `1 hour` or `15 minutes` below `24 hours`, domain ACME Renewal Information with `15 days` fallback, one serial persistent randomized scheduler running at least twice daily, and typed activation or rollback facts. Require issuance and renewal to stop at separate exact reviewed Plans, Back to restore the originating screen, and Certificate Correction Flows to retain Check again, Back, and copyable redacted evidence at the minimum size. Require no Cloudflare token, DNS-01 authority, CAA creation, private key, ACME account material, unsafe typed fact, contradictory expiry, or Infrastructure Secret marker to render.

### OC-OPERATIONS-01 — Diagnostics, release review, and Recovery Required

Run:

```sh
go test ./internal/ownerconsole -run '^(TestValidatedSupportBundleBindsTheExactReplacement|TestRecoveryViewMapsEachKindToItsExactStatusScreen|TestRun(ShowsInstallationAndModuleHealthAsSeparateTypedFacts|CreatesOrExplicitlyReplacesACompletedSupportBundle|SupportBundleIsSingleFlightAndWaitsBehindExitConfirmation|ReviewsExactUpdateAndCompatibleDowngradeBeforeApply|RecoveryRequiredOffersOnlyActionsProvenByCurrentMaterial|ForwardOnlyRotationShowsExactHelpOnlyAfterTheCheckpoint|RetryRollbackPresentsEveryTypedDurableResult|OperationsRefuseInfrastructureSecretMarkers|OperationsKeepFactsAndActionsReachableAtApprovedSizes|LateLifecycleAndRecoveryResultsNeverStealFocus))$' -count=1
```

Require exact installation status separately from Module and service health, stable findings and next actions, `30 days` or `50 MiB` event retention, three completed bundles, explicit fourth-bundle replacement, and the external-copy warning. Require update and downgrade discovery to show both freshly verified Release Identities, authenticated sequence, migrations, regenerated representations, affected services, checks, interruption, cancellation, and rollback, and to stop at a separate exact Plan review. Require Recovery Required to offer rollback only with valid unfinished material, current-State repair only from current proven State, and otherwise safe evidence, read-only diagnostics, Check again, Complete removal, and rebuild. After the run-token irreversible checkpoint only, require exact Cloudflare Tunnel-owned rotation Help with the fixed official HTTPS URL and exact plain URL. Refuse unsafe typed facts and every historical restore, old-secret restore, Recovery Point, adoption, force-start, force-unlock, manual completion, and parcel path.

### OC-REMOVAL-01 — Two acts, checkpoint truth, and proven completion

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunCompleteRemoval' -count=1
```

Require the complete owned local and Cloudflare inventory, irreversible Certificate Transparency and DNS-cache remnants, Albert's token-revocation responsibility, pre-checkpoint rollback, and post-checkpoint forward-only behavior at exact `80×24` and `120×36`. Require Software Lifecycle-owned Help to name the exact deletion authority, irreversible boundary, and consequence of `COMPLETE REMOVAL`; Help and hostile paste cannot type the phrase or select the action. Require exact `COMPLETE REMOVAL` input followed by a separately selected `Permanently remove SBXR` action; refuse case or whitespace changes, partial and hostile paste, ordinary Enter, one act, unrelated approval, and unsafe markers. Before durable `Irreversible removal started`, require Back and Cancel and preserve the exact Managed or Recovery Required starting status. After it, remove Back and Cancel. At awaiting revocation, show `My Profile > API Tokens`, the exact Dedicated Broad Cloudflare User API Token ID recorded by SBXR, the excluded unrelated credential types, and the fixed official API-token URL. Pause automatic progress. Require one explicit `Check again` through the same operation identity before token-rejection verification, local-token deletion, restart continuation, and durable progress. Require success to be proven Not installed with no SBXR recovery material and no retained-recovery uninstall, backup, Recovery Point, or post-Complete restore path.

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

Require complete managed downgrade and certificate guidance at both supported sizes with:

```sh
go test ./internal/ownerconsole -run '^TestRunShowsCompleteDowngradeAndCertificateGuidanceAtExactTerminalSizes$' -count=1
```
