# SBXR release acceptance

This file defines integrated installed-product procedures only. It contains no run result; one exact Release Identity receives results in its release Acceptance Record.

## `RELEASE-STATE-LINEAGE` — Integrated Verification — Codex

Through the complete `sbxr` executable, verify clean installation publication, ordinary change, repair, credential rotation, software migration, certificate renewal, stale Plan refusal, interruption before and after publication, automatic rollback, Recovery Required for unprovable lineage, and Complete removal. Scan every artifact and output with unique Client Access Value and Infrastructure Secret markers.

Until the integrated executable and those owning Modules exist, record `Pending — integrated release`. This check cannot be satisfied by the State Module test suite.

## `RELEASE-NETWORK-POLICY` — Integrated Verification — Codex

Through the complete `sbxr` executable, verify a reviewed Network Policy result binds the installation or repair Plan; changed observations make it stale; System Changes applies only the approved `inet sbxr` table; the SSH watchdog restores prior rules on failure; temporary TCP 80 is exact and removed on every outcome; disabled Connection Profiles lose exposure; and rollback restores the prior proven policy.

System Changes and the controlled Adapter checks now exist, but until the complete executable exercises them with all owning Modules, record `Pending — integrated release`. Module and controlled Adapter checks in `internal/networkpolicy/ACCEPTANCE.md` cannot satisfy this row.

## `RELEASE-SYSTEM-CHANGES` — Integrated Verification — Codex

Through the complete `sbxr` executable, verify every mutation enters one `Apply` path, holds one installation-wide kernel lock, durably prepares and resolves one Change Set, publishes Desired State only at its declared checkpoint, rolls back ordinary unfinished work, resumes only irreversible Complete removal, and leaves no transaction-scoped rollback material after durable `Complete`.

SC-01 through SC-09 now exist at Module level, but until the complete executable exercises them with all owning Modules, record `Pending — integrated release`. Module and controlled Adapter checks in `internal/systemchanges/ACCEPTANCE.md` cannot satisfy this row.

## `RELEASE-STAGED-INSTALL-REVISION-1` — Integrated Verification — Codex

This procedure has no result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record.

1. Build the packaged executable and start the default `sbxr` Owner Console on a proven Clean or Reclaimable VPS in `Not installed`. Run `Review`, `Confirm Reclamation` when required, `Apply`, `Inspect`, `Request Cancellation`, and `Recover` through the public Installation Interface. Enter no Cloudflare account, zone, token, DNS, Tunnel, route, or domain-certificate value. Confirm the Plan shows VLESS REALITY Vision `Enabled` and VLESS XHTTP, VLESS WebSocket, Hysteria2, TUIC, and AnyTLS `Not set up`.
2. Apply through `/usr/bin/sudo --preserve-fds=3 -- /proc/self/fd/3 private install-apply`. Require the root child to rebuild the exact release candidate and generated inputs, prepare before `READY`, accept one `APPLY`, and reject replay, malformed input, changed executable or candidate, parent death, changed Plan, or any Cloudflare handoff value.
3. Require the exact release tree, fixed systemd definitions, SSH preservation, REALITY credentials, one `sbxr-ip` certificate lineage, Subscription Serving, three persistent timers, owned `inet sbxr` policy, root-owned runtime material, reclamation authority when used, and recovery material. Require only `xray.service` and `sbxr-subscription.service` to run. Require `sing-box.service` and `cloudflared.service` to stay disabled and inactive. Open TCP `80` only for the temporary `sbxr-ip` HTTP-01 step and remove it on every outcome.
4. Require the authenticated HTTPS subscription to publish only one VLESS REALITY Vision representation. It must omit all five `Not set up` profiles. Require exactly one Desired State publication from `Not installed` to revision `1` `Managed` after every required gate and publication check passes. Require Cloudflare settings and the domain-certificate lineage to remain absent. Delete transaction-scoped rollback material only after durable `Complete`.
5. Inject stale-plan, pre-publication, post-publication, cancellation, forward-death, rollback-death, restart, and cleanup cases. Each proven reversible case must restore `Not installed`. A failed post-publication agreement must restore `Not installed`. A valid interrupted rollback must resume to `Not installed`; use `Recovery Required` only when current or rollback lineage cannot be proved. Restart after `Complete` must keep revision `1` without a second publication.
6. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run '^(TestProductionInstallationJourneyReturnsInvalidAgreementToItsExactField|TestProductionInstallationJourneyHasNoCloudflareInput)$' -count=1
   go test ./internal/softwarelifecycle/adapter/ubuntu -run '^(TestInstallApplyHandoffIsOneBoundedStrictRequestAndOneUseApproval|TestInstallApplyHandoffRefusesMalformedOversizeEOFAndParentDeath|TestInstallApplyCancellationReachesTheActivePreparedApply|TestInstallApplyReportsRecoveryRequiredAsAnExactSecretSafeTerminal|TestInstallExecutableMustMatchTheReviewedCandidate|TestInstallApplyUsesOnlyTheApprovedRootCommandAndInheritedDescriptors)$' -count=1
   go test ./internal/installation -run '^TestInstallationInterfaceOwnsRootRuntimeTransactionOutcomes$' -count=1
   go test ./internal/systemchanges -run '^TestRecoveryUnitRunsThePrivateRollbackBeforeManagedServices$' -count=1
   go test ./internal/state -run '^(TestSoftwareLifecycleInstallPublishesRevisionOneOnlyAfterCompleteAgreement|TestExplicitCancellationWaitsForSafeCheckpointThenRollsBack|TestPostPublicationFailureRestoresPriorDesiredState|TestPublicationFailureBeforeOrAfterReplacementRestoresPriorDesiredState|TestFailedInstallationRestoresProvenNotInstalledBaseline|TestFreshSystemChangesInstanceResumesInterruptedRollbackFromDurableEvidence|TestRollbackCanSurviveASecondProcessDeath|TestRestartAfterCompleteCleansUpWithoutRollback)$' -count=1
   go test ./internal/networkpolicy ./internal/certificatelifecycle ./internal/cloudflaretunnel ./internal/connectionprofiles/... ./internal/subscriptionpublication ./internal/subscriptionserving ./internal/systemchanges/... ./internal/softwarelifecycle/... ./internal/state ./cmd/sbxr -count=1
   go test ./... -count=1
   ```

7. Scan the packaged executable test transcript, handoff, transaction journal, prepared manifests, State refusal and result rendering, Owner Console transcript, and redacted Acceptance Record for every generated test Client Access Value, Infrastructure Secret, installation entropy seed, private key, complete subscription URL, and injected external-error marker. Any match outside its owning protected State or service artifact fails `RELEASE-INSTALL-SECRET-SCAN`.

   ```bash
   set -euo pipefail
   evidence_root=${SBXR_INSTALL_ACCEPTANCE_EVIDENCE:?set SBXR_INSTALL_ACCEPTANCE_EVIDENCE to the protected acceptance evidence directory}
   artifacts=(packaged-executable-test-transcript.txt install-handoff.json transaction-journal.jsonl prepared-manifests.json state-refusal-and-result.txt owner-console-transcript.txt acceptance-record.md)
   marker_files=(client-access-values.txt infrastructure-secrets.txt installation-entropy-seeds.txt private-keys.txt subscription-urls.txt external-error-markers.txt)
   for file in "${artifacts[@]}"; do test -f "$evidence_root/$file"; done
   marker_args=()
   for file in "${marker_files[@]}"; do test -s "$evidence_root/$file"; ! rg -q '^$' "$evidence_root/$file"; marker_args+=(--file "$evidence_root/$file"); done
   set +e
   rg --fixed-strings "${marker_args[@]}" "${artifacts[@]/#/$evidence_root/}"
   scan_status=$?
   set -e
   test "$scan_status" -eq 1
   ```

Stable evidence codes for this procedure are `RELEASE-STAGED-INSTALL-REVISION-1`, `RELEASE-INSTALL-STALE-PLAN`, `RELEASE-INSTALL-PRE-PUBLICATION-ROLLBACK`, `RELEASE-INSTALL-POST-PUBLICATION-ROLLBACK`, `RELEASE-INSTALL-CANCELLATION`, `RELEASE-INSTALL-RESTART`, `RELEASE-INSTALL-CLEANUP`, and `RELEASE-INSTALL-SECRET-SCAN`.

## `RELEASE-STAGED-ONBOARDING-TERMINAL` — Seam Verification — Codex

Through `ownerconsole.Run` and the real Bubble Tea event loop, verify the exact `80 × 24` and `120 × 36` `INSTALLATION COMPLETE`, setup entry, masked token, Plan review, irreversible confirmation, Recovery Required, and `CLOUDFLARE PROFILE SETUP COMPLETE` screens. Require revision `1` to show one of six profiles set up, five exact `Not set up` profiles, one-profile publication, and no Cloudflare requirement. Require completed setup to show six Enabled profiles, no setup action, and no Client Access Value. Keep all generic terminal, keyboard, paste, resize, masking, focus, and restoration checks in `internal/ownerconsole/ACCEPTANCE.md`.

Run:

```sh
go test ./internal/ownerconsole -run '^TestRun(DrivesOneTypedCloudflareProfileSetupJourney|ShowsStagedOnboardingDecisionScreensAtExactTerminalSizes|ShowsTypedCloudflareSetupTerminalResultsAtExactSizes|OverviewShowsOnlyTheCurrentStagedCapability|RoutesNotSetUpProfilesOnlyToCollectiveCloudflareSetup|ResizeRemasksInitialAndManagedCloudflareTokens)$' -count=1
```

Record Module and Seam Verification only. Real Cloudflare, provider mutation, live VPS, outside-client, maintained-client, current-documentation, Codex Live Acceptance, Owner Acceptance, and Release Qualification are not performed by this procedure.

## `RELEASE-CLIENT-ACCESS-N-TO-N+1` — Integrated Verification — Codex

This procedure has no live or Owner result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record. Unperformed VPS, provider, client, and Owner checks remain Pending.

1. Begin from one proven `Managed` revision `N`. After the Owner chooses authenticated access, require the fixed `/usr/bin/sudo --preserve-fds=3 -- /proc/self/fd/3 private client-access` boundary to verify root, peer, parent executable, inherited socket, one bounded strict typed request, and one exact reviewed Plan before `APPLY`. Reject an unknown action, profile, field, command, path, replay, changed Plan, malformed or oversized input, EOF, changed executable, wrong peer, and parent loss without mutation.
2. Run profile enable, profile disable, one-profile credential rotation, all-profile credential rotation, subscription-token-only rotation, and revoke-all. Each action must use one reviewed global Change Set, one lock, and one State publication from revision `N` to `N+1`. Token-only rotation must leave all six profile credentials unchanged. Revoke-all must replace the subscription token and all six profile credentials with no dual-credential grace.
3. For enable and disable, require the exact selected listener, `inet sbxr` exposure, core configuration, service activation, Cloudflare XHTTP or WebSocket route when applicable, subscription representations, HTTPS Serving snapshot, typed health, Owner Console profile view, authenticated Access values, and committed Desired State to agree. A disabled profile retains its settings and credential but has no listener, exposure, Tunnel route, or published representation. Karing and sing-box omit XHTTP rather than substituting another profile.
4. For every rotation, require all seven explicit Subscription Publication representations and the six Owner Console link choices to switch atomically with Serving. Concurrent trusted HTTPS requests may observe only the complete prior snapshot or complete candidate snapshot. After candidate activation, the old token receives the same plain `404`; there is no grace, alias, fallback credential, or secret-bearing diagnostic trail.
5. Inject failure during native core validation, core activation, firewall or Tunnel route activation, publication preparation, atomic publication, Serving proof, every required pre-publication gate, State publication, and every post-publication agreement check. Each failure must restore the complete prior `Managed` revision, including State, both core configurations, services, listeners, firewall, Tunnel routes, all representations, token authorization, and Access presentation. Use `Recovery Required` only when complete rollback or lineage proof is impossible.
6. Kill the privileged worker during forward work and rollback, then run `private recover`. Require the durable journal to finish or restore the same proven revision without a second publication. After `Complete`, require transaction rollback material to be absent and the old token and old credentials to remain refused.
7. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run '^(TestClientAccessPlan|TestClientAccessHandoff)' -count=1
   go test ./internal/connectionprofiles -run '^TestPrepareRegistryMutation' -count=1
   go test ./internal/cloudflaretunnel -run '^TestPrepareClientAccessRoutes' -count=1
   go test ./internal/networkpolicy -run '^TestPrepareProfileEnablement' -count=1
   go test ./internal/state -run '^(TestManagedClientAccessLease|TestSubscriptionArtifactSetUsesOneSystemChangesTransaction|TestConnectionProfileLifecycleArtifactsUseStatePublicationAndRollback)' -count=1
   go test ./internal/subscriptionpublication -run '^(TestPrepareClientAccessMutation|TestPlan)' -count=1
   go test ./internal/subscriptionserving -run '^Test(ServeSwitchesAuthorizationAndCompleteBodiesTogether|ConcurrentRequestsObserveOnlyOneCompleteServingSnapshot|ServePreservesDeliberateProfileDisablementAcrossActivation|ServeRestartAndRollbackUseOnlyAProvenCompleteSnapshot)$' -count=1
   go test ./internal/ownerconsole -run '^(TestAccessProviderRunsOnlyAfterSuccessfulAuthentication|TestRunReviewsDistinctRotateAllTokenOnlyAndRevokeAllChangeSets|TestRunShowsNamedSubscriptionCountsAndOmissionsWithoutValues)' -count=1
   go test ./... -count=1
   ```

8. Scan the private request, Plan review, transaction journal, rollback snapshots, prepared core and publication manifests, State results, Serving responses, Owner Console transcript, typed health, and redacted Acceptance Record for unique old/new profile credentials, subscription tokens, complete URLs, Cloudflare management/run tokens, private keys, authorization values, and injected external-error markers. Protected service and State artifacts are checked for exact ownership and placement; any marker in a diagnostic, log, command line, environment, terminal-safe review, or Acceptance Record fails.

Stable evidence codes are `RELEASE-CLIENT-ACCESS-N-TO-N+1`, `RELEASE-CLIENT-ACCESS-ENABLE`, `RELEASE-CLIENT-ACCESS-DISABLE`, `RELEASE-CLIENT-ACCESS-ROTATE-ONE`, `RELEASE-CLIENT-ACCESS-ROTATE-ALL`, `RELEASE-CLIENT-ACCESS-TOKEN-ONLY`, `RELEASE-CLIENT-ACCESS-REVOKE-ALL`, `RELEASE-CLIENT-ACCESS-OLD-TOKEN-REFUSED`, `RELEASE-CLIENT-ACCESS-CONCURRENT-SNAPSHOT`, `RELEASE-CLIENT-ACCESS-PRE-PUBLICATION-ROLLBACK`, `RELEASE-CLIENT-ACCESS-POST-PUBLICATION-ROLLBACK`, `RELEASE-CLIENT-ACCESS-RESTART`, `RELEASE-CLIENT-ACCESS-RECOVERY-REQUIRED`, and `RELEASE-CLIENT-ACCESS-SECRET-SCAN`.

## `RELEASE-PROVIDER-CERTIFICATES-N-TO-N+1` — Integrated Verification — Codex

This procedure has no live or Owner result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record. No real Cloudflare, ACME, VPS, DNS, certificate, or outside-client action was authorized by issue #146; every such unperformed check remains Pending.

1. Begin from one proven `Managed` revision `N`. After authenticated Owner access, require the verified `private client-access` root handoff to accept only one bounded Cloudflare or certificate request, return one exact reviewed Plan, and consume one exact `APPLY`. Reject malformed actions, token fields, email or agreement fields, changed executable, stale State, replay, EOF, and parent loss without mutation.
2. Exercise scoped management-token replacement, deliberate removal with the exact dependency inventory, and genuine Tunnel run-token rotation. Require the selected account, zone, immutable Tunnel and DNS IDs, two routes, final `404`, Direct DNS, local origins, protected token file, cloudflared activation, State, and health to agree. Run-token rotation must cross its irreversible checkpoint before Owner action and then recover only forward; the old token must not remain in rollback material after that checkpoint.
3. Exercise `sbxr-ip` and `sbxr-domain` issuance and renewal as separate Change Sets. Require the committed Direct TLS Hostname, DNS-only A/AAAA facts, effective CAA, exact selected address, fixed logical certificate IDs and pointer paths, staged candidate, production order, one pointer switch, and one revision publication to agree. SBXR must not create DNS-01 or CAA records.
4. For each order, open only the typed temporary `tcp dport 80` rule and remove its exact recorded handle on success, refusal, rollback, interruption, and restart recovery. An unrelated port-80 owner must stop the Plan without being stopped, adopted, or flushed.
5. For `sbxr-ip`, activate only Subscription Serving and prove normal-trust HTTPS for the selected IP. For `sbxr-domain`, validate the complete sing-box configuration before switching the shared pointer, restart only `sing-box.service`, and prove Hysteria2, TUIC, and AnyTLS separately with the selected VPS address and committed hostname. A failed required check restores the prior pointer and prior service agreement without a second order.
6. Run `private certificate-renewal` with the one persistent serial scheduler. Prove IP is evaluated before domain, each due lineage obtains the global lock separately, and every Plan is built fresh only after the lock is held. Busy, ordinary failure, ARI, 72-hour, 24-hour, six-hour, one-hour, fifteen-minute, and fifteen-day fallback behavior must match the Certificate Lifecycle acceptance contract.
7. Inject provider, ACME, firewall, Certbot, candidate validation, service, listener, certificate, pre-publication, publication, and post-publication failures. Kill the worker during forward work and rollback, then run `private recover`. Every reversible case must restore the exact prior Managed revision; an irreversible run-token rotation must continue only forward; use `Recovery Required` only when current or prior agreement cannot be proved.
8. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run '^(TestManagedProvider|TestClientAccessHandoff)' -count=1
   go test ./internal/cloudflaretunnel ./internal/certificatelifecycle/... ./internal/networkpolicy ./internal/connectionprofiles/... -count=1
   go test ./internal/state -run 'Test(ManagementToken|RunToken|Certificate|SystemChanges)' -count=1
   go test ./internal/systemchanges/... ./internal/subscriptionpublication ./internal/subscriptionserving -count=1
   go test ./... -count=1
   ```

9. Scan the private request, Plan review, journal, rollback snapshots, prepared manifests, protected service files, State results, certificate candidates, Owner Console transcript, typed health, and redacted Acceptance Record for management and run tokens, Owner email, ACME account data, Client Access Values, private keys, authorization values, complete subscription URLs, raw Certbot or provider output, and injected error markers. Any marker outside its owning protected artifact fails.

Stable evidence codes are `RELEASE-PROVIDER-CERTIFICATES-N-TO-N+1`, `RELEASE-CLOUDFLARE-MANAGEMENT-TOKEN`, `RELEASE-CLOUDFLARE-RUN-TOKEN`, `RELEASE-CLOUDFLARE-IMMUTABLE-OWNERSHIP`, `RELEASE-DIRECT-TLS-HOSTNAME`, `RELEASE-CERTIFICATE-IP-HTTP01`, `RELEASE-CERTIFICATE-DOMAIN-HTTP01`, `RELEASE-CERTIFICATE-SERIAL-RENEWAL`, `RELEASE-CERTIFICATE-POINTER-ROLLBACK`, `RELEASE-PROVIDER-CERTIFICATE-RESTART`, `RELEASE-PROVIDER-CERTIFICATE-RECOVERY-REQUIRED`, and `RELEASE-PROVIDER-CERTIFICATE-SECRET-SCAN`.

## `RELEASE-HEALTH-DIAGNOSTICS` — Integrated Verification — Codex

This procedure has no live or Owner result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record. No real VPS, reboot, provider, client, or Owner-console acceptance was authorized by issue #147; every such unperformed check remains Pending.

1. From each exact installation status — `Not installed`, `Managed`, `Change in progress`, and `Recovery Required` — run the authenticated Diagnostics screen and `sbxr private health-check`. Require both paths to call the same Health and Diagnostics `Check`, return all thirteen named Modules once, keep installation status separate from Module health, and show only fixed safe explanations, next actions, service summaries, retention limits, and bundle names. Require the Connection Profiles result to include six typed rows from the last committed revision. `Not set up` rows have no individual Health Result and state that Cloudflare Profile Setup is required.
2. Start `sbxr-health-check.timer`, miss one weekly run while the Acceptance VPS is off, and reboot. Require `Persistent=true` to run the missed check once. Compare State, the active transaction journal, Rollback Snapshot, firewall, services, publication, provider resources, and every credential before and after; any mutation outside the root-only diagnostic event history fails.
3. Exercise cancellation, an active reversible Change Set, rollback, worker death during forward work and rollback, restart recovery, an unprovable transaction, and Complete removal. Require diagnostics to preserve System Changes' exact status, progress, rollback/forward-only availability, and next action without opening, replacing, or deleting transaction evidence.
4. Create three support bundles through the authenticated verified root handoff. Require exactly `manifest.json`, `report.txt`, and `facts.json`; root-owned `0700` directories; root-owned single-link `0600` archives; at most three completed bundles; and the external-copy warning. Before a fourth, review the exact three safe names and replace only the selected archive.
5. Inject unique Client Access Value, Infrastructure Secret, journal, Rollback Snapshot, raw-output, environment, command-argument, client-address, destination, crash-report, and `SECRET-MARKER` values into every rejected input source. Require no marker in a completed archive, event history, Owner Console transcript, command line, environment, or Acceptance Record. Keep active System Changes evidence byte-for-byte unchanged.
6. Inject short writes, changed reads, malformed history, unsafe ownership/modes, links, duplicate names, compression failure, every bundle transaction crash phase, final-sync failure, cleanup failure, and concurrent fourth-bundle publication. Require no partial completed archive, exact rollback or completion of the reviewed replacement, empty staging before later work, and fail-closed stable codes.
7. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run '^(TestPrivateScheduledHealthCommandCallsScheduledCheck|TestProductionDiagnosticsPresentationUsesTheSameElevenModuleCheck|TestScheduledInspectionsUseOwningModuleManagedResults|TestExecutableBundleCompositionUsesOnlyOpaqueStateAndSafeCheckFacts|TestDiagnosticsHandoffAcceptsOnlyViewOrReviewedBundleReplacement|TestClientAccessHandoffAcceptsOnlyExactTypedRequests|TestPreinstallOutcomeProvidesRestrictedFailSafeDiagnostics)$' -count=1
   go test ./internal/healthdiagnostics/... -count=1
   go test ./internal/state -run '^TestHealthReleaseInspectionComesOnlyFromTheExactFreshManagedLoad$' -count=1
   go test ./internal/systemchanges/... -run 'Health|Recovery|Rollback|Restart|CompleteRemoval' -count=1
   go test ./internal/networkpolicy -run '^TestCleanVPSAuthorityRechecksTheExactNetworkPolicyBaseline$' -count=1
   go test ./internal/softwarelifecycle -run 'HealthCheck|ManagedUnit' -count=1
   go test ./internal/ownerconsole -run '^(TestAccessProviderRunsOnlyAfterSuccessfulAuthentication|TestRunSupportBundleIsSingleFlightAndWaitsBehindExitConfirmation|TestValidatedSupportBundleBindsTheExactReplacement|TestRunCreatesOrExplicitlyReplacesACompletedSupportBundle)$' -count=1
   go test ./... -count=1
   ```

8. Record separate redacted evidence for the automated run, the exact Acceptance VPS reboot and permissions run, and any required Owner Acceptance. Automated checks do not satisfy the unperformed VPS, provider, client, or Owner rows.

Stable evidence codes are `RELEASE-HEALTH-DIAGNOSTICS`, `RELEASE-HEALTH-THIRTEEN-MODULES`, `RELEASE-HEALTH-SCHEDULED-PERSISTENT`, `RELEASE-HEALTH-NO-MUTATION`, `RELEASE-HEALTH-LIFECYCLE-STATUS`, `RELEASE-DIAGNOSTIC-EVENT-RETENTION`, `RELEASE-SUPPORT-BUNDLE-THREE-FILE`, `RELEASE-SUPPORT-BUNDLE-REPLACEMENT`, `RELEASE-SUPPORT-BUNDLE-PERMISSIONS`, `RELEASE-SUPPORT-BUNDLE-NO-PARTIAL`, `RELEASE-SUPPORT-BUNDLE-TRANSACTION-EXEMPT`, and `RELEASE-HEALTH-SECRET-SCAN`.

## `RELEASE-SOFTWARE-CHANGE-N-TO-N+1` — Integrated Verification — Codex

This procedure has no live or Owner result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record. No real VPS, reboot, release publication, provider, client, or Owner-console acceptance was authorized by issue #148; every such unperformed check remains Pending.

1. Begin from one proven `Managed` revision `N`. Through the authenticated privileged Managed dashboard and the root-owned `private update-check` timer path, run stable discovery and retain only the newest verified unapplied candidate at the documented protected boundary. Require both paths to perform no Apply, State, publication, service, firewall, provider, or executable change; require the Owner Console to show both exact Release Identities and one `Review update` action. Selecting review uses one verified `software-review` helper that reads protected facts, builds and returns the complete exact secret-safe executable Plan, performs no Managed-system mutation, and exits. Cancelling the review changes nothing.
2. Apply the reviewed update through a separate verified `software-apply` helper and one `Update` Change Set. Require it to freshly rebuild the complete Plan and match the exact reviewed identity and SHA-256 before accepting `APPLY`, then perform the State schema migration when declared by the authenticated release, regenerate Xray and sing-box configurations, Cloudflare service material, and all Subscription Publication representations, publish State once from `N → N+1`, restart only cloudflared, Xray, sing-box, and Subscription Serving, and pass pre- and post-publication agreement. At durable `Complete`, require the prior live release, rollback snapshot, journal, and exact applied retained candidate to be absent.
3. Select one exact older tag explicitly. Require fresh six-asset public verification, a lower authenticated sequence, current-State schema compatibility, and the same reviewed update machinery. Refuse the installed identity, a higher or equal sequence, incompatible schema, automatic downgrade, local release history, stale approval, changed prepared material, or a tag not freshly selected by the Owner without mutation.
4. Drift exactly one SBXR-owned Managed resource while preserving the current proven State, Release Identity, secrets, and ownership identifiers. Require `Recovery Required` with `Current State drift` to offer one typed owning-Module repair contribution. Apply one `Repair` Change Set that republishes the unchanged Owner intent as revision `N+1`. Refuse missing or corrupt State, missing secrets, ambiguous or unowned resources, unfinished rollback material, replacement VPS evidence, old revision, and Owner regret; never adopt Observed State or recreate a secret.
5. For update, downgrade, and repair, inject failure before rollback capture, after each forward checkpoint, during configuration validation, each affected service restart, publication preparation, publication, and every post-publication check. Request cancellation during an active reversible step. Each provable case must restore the exact prior executable, release tree, units, State revision, configurations, services, publication, and provider agreement.
6. Kill the privileged worker during forward work and again during rollback, then reboot and run `private recover`. Require the validated journal to inspect the exact attempted steps and finish rollback without downloading a release or publishing State twice. Tampered, incomplete, linked, broadly readable, marker-bearing, or contradictory candidate, snapshot, manifest, journal, release, configuration, or service evidence must stop at `Recovery Required`; it must never be replaced, adopted, or guessed.
7. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run '^(TestManagedOwnerConsolePresentsFreshlyVerifiedUpdateWithoutApplying|TestManagedSoftwareLifecyclePresentationSeparatesStagingFromDiscovery|TestManagedUpdateUsesReadOnlyPlanningSudoThenSeparateApplySudo|TestManagedRepairUsesReadOnlyPlanningSudoThenSeparateApplySudo|TestComposedSoftwareApplyCarriesCancellationAndRestartIdentity|TestSoftwareLifecycleHandoff)' -count=1
   go test ./internal/softwarelifecycle -run '^Test(ViewOffersOnlyAFreshCompatibleExplicitDowngrade|PlanUpdate|PlanDowngrade|ApplyUpdate|ViewRepair|PlanRepair|ApplyRepair|SoftwareRepair)' -count=1
   go test ./internal/softwarelifecycle/adapter/ubuntu -run '^Test(CandidateStore|Updater|Downgrader)' -count=1
   go test ./internal/connectionprofiles -run '^(TestRegistryPlanRegeneratesBothCompleteConfigurationsForAReleaseUpdate|TestRegistryPlansOnlyAuthorizedForwardRepairOfCurrentLineage)$' -count=1
   go test ./internal/cloudflaretunnel -run '^(TestPlanReleaseUpdateRestartsOnlyTheVerifiedOwnedCloudflaredService|TestManagedRepairPlansOnlyCommittedOwnedDriftAndBlocksConflicts)$' -count=1
   go test ./internal/subscriptionpublication -run '^(TestPlanBindsOneCompleteValidatedArtifactSetWithoutRenderingSecrets|TestPlanContributesOnlyAnExplicitCurrentStateRepair)$' -count=1
   go test ./internal/systemchanges/... -run 'Update|Repair|Rollback|Restart|Recovery|Complete' -count=1
   go test ./internal/state -run 'Migration|Software|Rollback|Restart|Recovery' -count=1
   go test ./... -count=1
   ```

8. Scan the private request, exact Plan review, retained candidate, prepared release and Module artifacts, journal, rollback snapshot, State result, publication, service output, Owner Console transcript, diagnostics, and redacted Acceptance Record for unique Client Access Values, Infrastructure Secrets, release-signing test markers, archive payload markers, private keys, complete subscription URLs, authorization values, raw external errors, and injected `SECRET-MARKER` values. Any marker outside its owning protected artifact fails.

Stable evidence codes are `RELEASE-SOFTWARE-CHANGE-N-TO-N+1`, `RELEASE-SOFTWARE-DISCOVERY-NO-APPLY`, `RELEASE-SOFTWARE-CANDIDATE-RETENTION`, `RELEASE-SOFTWARE-UPDATE`, `RELEASE-SOFTWARE-DOWNGRADE`, `RELEASE-SOFTWARE-REPAIR`, `RELEASE-SOFTWARE-INCOMPATIBLE-REFUSED`, `RELEASE-SOFTWARE-PRE-PUBLICATION-ROLLBACK`, `RELEASE-SOFTWARE-POST-PUBLICATION-ROLLBACK`, `RELEASE-SOFTWARE-CANCELLATION`, `RELEASE-SOFTWARE-RESTART`, `RELEASE-SOFTWARE-RECOVERY-REQUIRED`, `RELEASE-SOFTWARE-CLEANUP`, and `RELEASE-SOFTWARE-SECRET-SCAN`.

## `RELEASE-COMPLETE-REMOVAL` — Integrated Verification — Codex

This procedure has no live or Owner result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record. No real VPS destruction, Cloudflare deletion, token revocation, reboot, client, or Owner-console acceptance was authorized by issue #149; every such unperformed check remains Pending.

1. From proven `Managed` and from `Recovery Required` with no valid unfinished transaction, require authenticated Owner Console to show safe evidence, diagnostics, rebuild guidance, and the separately confirmed Complete removal path. With one valid unfinished reversible transaction, offer only its exact automatic rollback first. Refuse corrupt, linked, broadly readable, duplicate, contradictory, or multiple transaction evidence.
2. Require the exact typed `COMPLETE REMOVAL` field and the separate `Permanently remove SBXR` selection. Run one read-only `removal-review` privileged helper that returns the complete secret-safe Plan and exits. Apply only through a separate `removal-apply` helper that freshly rebuilds and matches the exact Plan identity and SHA-256 before accepting the two exact post-review Owner acts followed by `APPLY`.
3. Before `Irreversible removal started`, remove only SBXR-owned public exposure and exact Tunnel routes. Keep the exact immutable-ID DNS records, Tunnel, management token, State, local material, journal, and Rollback Snapshot. Fail, cancel, or kill the worker before and after every safe checkpoint; require a fresh `private recover` to restore the exact proven Managed baseline or preserve the exact raw Recovery Required baseline.
4. Prove the fixed local cleanup is ready, then durably record `Irreversible removal started`. Only afterward delete the exact immutable-ID DNS records and Tunnel, recording `Owned Cloudflare DNS records deleted`, `Owned Cloudflare Tunnel deleted`, and `Owned external deletion verified`. Preserve unrelated Cloudflare and local resources. Back, Cancel, automatic rollback, and restore are unavailable from this point.
5. Require Albert to revoke the scoped Cloudflare token only after provider deletion is durable. Accept only an explicit unauthorized response as revocation proof; forbidden, timeout, malformed, ambiguous, or other errors remain forward-only at the last durable checkpoint. Then delete local State, Infrastructure Secrets, and certificates; durably record `Transaction material deletion authorized` before deleting checksummed transaction material except the journal; then delete releases, units, identities, listeners, prepared artifacts, and owned firewall state in the fixed recorded order.
6. Kill the worker immediately before and after every irreversible checkpoint and reboot. Each fresh `private recover` must replay an uncertain provider deletion idempotently, skip only durably recorded work, never run reverse, never restart affected services, and delete the removal journal and recovery runner last. Success requires exact `Not installed`, no local token, no owned resources, and no retained SBXR recovery material.
7. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run 'Test(CompleteRemoval|ClientAccessHandoff)' -count=1
   go test ./internal/ownerconsole -run 'CompleteRemoval' -count=1
   go test ./internal/cloudflaretunnel -run 'Test(RevocationProof|RemovalDeletes|RemovalAuthority)' -count=1
   go test ./internal/softwarelifecycle -run 'CompleteRemoval' -count=1
   go test ./internal/systemchanges/... -run 'CompleteRemoval|Removal' -count=1
   go test ./internal/state -run 'CompleteRemoval|Removal' -count=1
   go test ./... -count=1
   ```

8. Scan the private requests, exact Plan, Owner Console transcript, State and raw-baseline binding, provider observations, journal, snapshot, step evidence, recovery result, native errors, command line, environment, and redacted Acceptance Record for Client Access Values, Infrastructure Secrets, complete URLs, authorization values, private keys, raw provider output, and injected `SECRET-MARKER` values. Any marker outside its owning protected artifact fails.

Stable evidence codes are `RELEASE-COMPLETE-REMOVAL`, `RELEASE-REMOVAL-TWO-STEP-CONFIRMATION`, `RELEASE-REMOVAL-PLAN-BINDING`, `RELEASE-REMOVAL-PRE-CHECKPOINT-ROLLBACK`, `RELEASE-REMOVAL-IRREVERSIBLE-STARTED`, `RELEASE-REMOVAL-DNS-DELETED`, `RELEASE-REMOVAL-TUNNEL-DELETED`, `RELEASE-REMOVAL-TOKEN-REVOKED`, `RELEASE-REMOVAL-FORWARD-RESTART`, `RELEASE-REMOVAL-NOT-INSTALLED`, `RELEASE-REMOVAL-RUNNER-LAST`, and `RELEASE-REMOVAL-SECRET-SCAN`.

## `RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1` — Integrated Verification — Codex

Through the packaged `sbxr` composition, start from one proven Managed revision `N` with VLESS REALITY Vision Enabled and five profiles `Not set up`. Use only Cloudflare Profile Setup `View`, `Plan`, and `Apply`. Require one fresh contribution from each of Network Policy, Cloudflare Tunnel, Certificate Lifecycle, Connection Profiles, Subscription Publication, State, and System Changes. Reject mismatched lineage, stale or reused authority, partial setup, and caller-made dependency results.

Apply exactly one Change Set. Prepare revision `N+1`, all five profile credentials, `sbxr-domain`, one Tunnel, two routes, DNS records, service artifacts, firewall policy, and publication before provider exposure. Cross `Irreversible Cloudflare setup started` before the first Cloudflare write. Publish revision `N+1` exactly once and last, with all six profiles Enabled. Before the checkpoint, cancellation or failure restores revision `N`. After the checkpoint, recovery continues forward or enters Recovery Required; it never rolls back to revision `N`.

Run:

```sh
go test ./internal/cloudflareprofilesetup -count=1
go test ./internal/state -run '^(TestCloudflareProfileSetupCrossesIrreversibleBoundaryBeforeFirstWrite|TestCloudflareProfileSetupCancellationBeforeCheckpointRestoresStartingRevision|TestCloudflareProfileSetupFailureAfterCheckpointNeverRollsBack|TestCloudflareProfileSetupRestartIsReversibleBeforeAndForwardOnlyAfterCheckpoint|TestUbuntuCloudflareProfileSetupDeletesRollbackSnapshotAndRecoversForwardAfterDeath|TestUbuntuCloudflareProfileSetupRestartAfterPublicationDoesNotWriteAgain)$' -count=1
go test ./internal/networkpolicy ./internal/cloudflaretunnel ./internal/certificatelifecycle ./internal/connectionprofiles ./internal/subscriptionpublication ./internal/state ./internal/systemchanges -count=1
```

Stable evidence codes are `RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1`, `RELEASE-CLOUDFLARE-PROFILE-SETUP-CHECKPOINT`, `RELEASE-CLOUDFLARE-PROFILE-SETUP-PUBLICATION-LAST`, `RELEASE-CLOUDFLARE-PROFILE-SETUP-ROLLBACK`, `RELEASE-CLOUDFLARE-PROFILE-SETUP-FORWARD-RECOVERY`, and `RELEASE-CLOUDFLARE-PROFILE-SETUP-RECOVERY-REQUIRED`.

## `RELEASE-STAGED-ONBOARDING-CHAIN` — Integrated Verification — Codex

Run `RELEASE-STAGED-INSTALL-REVISION-1` and `RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1` in order against one exact packaged Release Identity. Prove revision `1` is a complete long-term Managed state before optional setup. Prove one publication per successful Change Set and publication-last order. In both capability states, verify update, downgrade, repair, diagnostics, Access, Live Profile Check skips, and conditional Complete removal. No supported partial Cloudflare setup can appear.

Run all twelve affected Module suites and unchanged Subscription Serving:

```sh
go test ./internal/installation ./internal/cloudflareprofilesetup ./internal/state ./internal/networkpolicy ./internal/systemchanges/... ./internal/cloudflaretunnel ./internal/certificatelifecycle/... ./internal/connectionprofiles/... ./internal/subscriptionpublication/... ./internal/healthdiagnostics ./internal/softwarelifecycle/... ./internal/ownerconsole ./internal/subscriptionserving -count=1
go test ./cmd/sbxr -count=1
```

Stable evidence code is `RELEASE-STAGED-ONBOARDING-CHAIN`.

## `RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT` — Seam Verification — Codex

Verify the universal route and `/sing-box` at revision `1` and after Cloudflare Profile Setup. Revision `1` publishes only VLESS REALITY Vision. The completed setup publishes every compatible Enabled profile. `/sing-box` keeps the intentional VLESS XHTTP omission and passes the exact sing-box `1.13.16` native check. Refuse placeholders, empty credentials, fake Disabled entries, secret markers, and stale six-profile assumptions.

Run:

```sh
go test ./internal/subscriptionpublication -run '^(TestRevisionOnePublishesOnlyRealityAndNamesFiveNotSetUpProfiles|TestRevisionOnePlanApplyCompletesAfterAtomicActivationAndStatePublication|TestPinnedSingBoxAcceptsCompleteDocument)$' -count=1
```

`TestPinnedSingBoxAcceptsCompleteDocument` must run with `SBXR_SING_BOX_BIN` set to the qualified binary and `SBXR_SING_BOX_VERSION=1.13.16`. A skipped native check does not pass this procedure.

Stable evidence code is `RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT`.

## `RELEASE-STAGED-ONBOARDING-GUIDE-TEXT` — Seam Verification — Codex

Verify the fixed packaged guide names the Dedicated Broad Cloudflare User API Token, User API Tokens Edit, Cloudflare Tunnel Edit, DNS Edit, Zone Read, all-account and all-zone scopes, no expiry, no client-IP restriction, Global API Key refusal, Account API Token refusal, the authority warning, and use restricted to the selected immutable SBXR identifiers. This procedure does not validate current Cloudflare documentation, dashboard labels, paths, or URLs.

Run:

```sh
go test ./internal/ownerconsole -run '^TestRunCloudflareWalkthroughUsesDedicatedBroadUserTokenPathAndMasksByDefault$' -count=1
```

Stable evidence code is `RELEASE-STAGED-ONBOARDING-GUIDE-TEXT`.

## `RELEASE-STAGED-ONBOARDING-SECRET-SCAN` — Seam Verification — Codex

Use unique markers for the management token and token IDs, Tunnel run token, profile credentials, subscription token and complete URLs, private keys, setup entropy and approval, raw provider responses, and external errors. Scan presentation, transaction, diagnostic, HTTP, test, acceptance, bootstrap, index, and decompressed archive surfaces. A marker can exist only in its exact protected owning artifact. Any other match fails.

The candidate and stable workflows must scan `install.sh`, `release-index.json`, all four safely streamed archives, the Acceptance Record, and the workflow summary. The focused Module checks must scan typed errors, Plans, journal evidence, terminal output, subscription responses, and recovery results. No raw secret-bearing evidence archive is created.

Stable evidence code is `RELEASE-STAGED-ONBOARDING-SECRET-SCAN`.

## `RELEASE-IMMUTABLE-CANDIDATE` — Automated Qualification — Codex

This procedure records no result. It mints one acceptance candidate, not a stable, latest, automatically discoverable, live-accepted, Owner-accepted, or qualified release.

1. Require issues #145, #146, and #149 closed with their automated implementation evidence while every unperformed live and Owner row remains Pending under #151 and #152. Require repository immutable releases enabled before creating the candidate.
2. From one clean exact commit, manually dispatch `Mint immutable candidate` with the next unused safe opaque tag and version and the next monotonic sequence. The initial candidate used `v1.0.0`, version `1.0.0`, and sequence `1`; this reset uses `v1.0.1`, version `1.0.1`, and sequence `2`. Require native `ubuntu-24.04` amd64 and `ubuntu-24.04-arm` arm64 jobs using pinned Go `1.26.6` and `CGO_ENABLED=0` to create `sbxr-linux-amd64.tar.gz`, `sbxr-linux-arm64.tar.gz`, `sbxr-components-linux-amd64.tar.gz`, and `sbxr-components-linux-arm64.tar.gz`. Each application archive contains exactly one stamped `sbxr`; each component archive passes its matching native validators.
3. Generate the exact release-specific `install.sh` from the repository, tag, commit, version, sequence, supported architectures, and six names, then build `release-index.json` only from it and those exact four regular archives. The bootstrap intentionally does not embed the index digest because the index binds the complete bootstrap bytes. Require schema `1`, product `sbxr`, repository `albertloky/SBXR`, the exact version, sequence, tag, commit, State schema, minimum updater schema, exact five roles and fixed names, calculated sizes, and calculated SHA-256 values. Refuse caller-supplied digests, missing, duplicate, extra, linked, occupied, changed, or oversized material.
4. Before publication, run every repository Module, Seam, and Integrated automated test available before GitHub attestation against the exact commit, execute each packaged application on its matching native runner, run the generated bootstrap's non-interactive fixed-refusal check, and scan the bootstrap, index, and decompressed contents of every application/component archive for injected secret markers, private-key blocks, and authorization values. The prepublication stage matrix must leave GitHub-attestation-dependent Seam and Integrated rows Pending. A failure publishes nothing.
5. Download the workflow's exact six-file artifact, then use Owner-authenticated read-only repository administration to prove immutable releases are still enabled before creating any tag or release. Publish only the six fixed paths as an immutable prerelease with `latest=false`; never use a glob. Publication automatically starts the public HTTPS and Sigstore release verifier plus both architecture staging paths. Require repository, immutable tag, commit, release-index digest, exact six names, exact six digests, one GitHub release attestation, and every safely downloaded byte to verify without GitHub login, a personal token, or an installed GitHub CLI. Require the attested, indexed, downloaded, embedded, and reported repository, tag, commit, role, architecture, size, payload digest, asset digest, schema, migration, systemd definition, qualified artifact, and version facts to agree before those Pending rows become Passed.
6. Record one redacted identity-bound stage matrix on issue #150: Module Verification, Seam Verification, and Integrated Verification are Passed only from their actual workflow evidence; Codex Live Acceptance and Owner Acceptance remain Pending. Record the exact repository, tag, commit SHA, release-index SHA-256, workflow URL, stable codes, commands, tool versions, and safe findings. Never attach raw configurations, credentials, complete URLs, private keys, authorization values, provider output, proxy traffic, client addresses, or a secret-bearing archive.
7. Any artifact-bearing source, embedded asset, migration, schema, unit, compatibility definition, index, or payload change creates a new Release Identity and resets affected automated and later evidence. Do not mark the candidate stable/latest or enable automatic discovery before #153 records final Release Qualification.

Stable evidence codes are `RELEASE-CANDIDATE-SOURCE`, `RELEASE-CANDIDATE-AMD64`, `RELEASE-CANDIDATE-ARM64`, `RELEASE-CANDIDATE-INDEX`, `RELEASE-CANDIDATE-EXACT-SIX-ASSETS`, `RELEASE-CANDIDATE-GITHUB-ATTESTATION`, `RELEASE-CANDIDATE-ASSET-VERIFICATION`, `RELEASE-CANDIDATE-MODULE-VERIFICATION`, `RELEASE-CANDIDATE-SEAM-VERIFICATION`, `RELEASE-CANDIDATE-INTEGRATED-VERIFICATION`, `RELEASE-CANDIDATE-SECRET-SCAN`, and `RELEASE-CANDIDATE-LIVE-PENDING`.

## `RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION` — Release Qualification — Codex

This procedure applies only to one exact six-asset staged-onboarding Release Identity. It qualifies the changed Connection Profile, Subscription Publication, Owner Console, and controlled transaction outputs only through the complete package and public-seam tests above.

1. Publish one immutable prerelease with exactly `install.sh`, `release-index.json`, and the four fixed architecture archives. The release event must resolve to one exact 40-character commit.
2. Verify the public release through `cmd/sbxr-release verify` without GitHub login or a personal token. Require the exact repository, immutable tag, commit, release-index digest, six names, six digests, and six attestations with no extra asset.
3. Download the six public assets into one private directory. Run the complete package suites at the Pasteable Install Command and owning Module Interfaces, all twelve affected Module suites, unchanged Subscription Serving, the supported race suite, `go vet ./...`, native amd64 and arm64 runners, native Xray, sing-box `1.13.16`, certificate, HTTP/TLS, nftables, filesystem, systemd, process, restart, controlled Cloudflare fixtures, complete Subscription Publication parsing, the pseudo-terminal seam, hostile fixtures, four representative process-death cases, second-death cases, and simulated reboot cases from the exact release commit.
4. Require `RELEASE-STAGED-INSTALL-REVISION-1`, `RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1`, `RELEASE-STAGED-ONBOARDING-CHAIN`, `RELEASE-STAGED-ONBOARDING-SECRET-SCAN`, `RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT`, `RELEASE-STAGED-ONBOARDING-TERMINAL`, and `RELEASE-STAGED-ONBOARDING-GUIDE-TEXT` to pass for the exact commit. Do not freeze or compare away the staged Connection Profile or Subscription Publication changes that this policy qualifies.
5. Scan the exact bootstrap, index, safely streamed archive contents, generated Acceptance Record, and workflow summary for secret markers, private-key blocks, and authorization values.
6. Run `go run ./cmd/sbxr-release acceptance` only after every required check passes. It must reopen one unchanged directory containing exactly the six regular assets, compare the index identity and every indexed size and digest, and write one exclusive redacted record. Publish that record in the workflow summary, the retained workflow artifact, and the prerelease body without adding a seventh release asset.
7. Mark Module, Seam, and Integrated Verification `Passed`. Mark Codex Live Acceptance and each real VPS, Cloudflare, ACME, outside-client, maintained-client, current-documentation, and provider-mutation row exactly `Not required — staged-onboarding package and controlled-seam qualification scope`. Mark Owner Acceptance exactly `Not required — staged-onboarding package and controlled-terminal qualification scope`. State that none of those checks was performed.
8. Any changed asset, commit, tag, release-index digest, acceptance procedure, guide text, selected output, or required test resets its affected result and blocks stable publication until the new exact Release Identity passes. Stable publication must run the package checks from the exact release commit, byte-compare the release body with the retained Acceptance Record, reverify the public bytes, prove latest and pinned `install.sh` equality, scan all six assets, and recheck the generated bootstrap package gates. Automatic stable discovery must require the record repository, tag, commit, qualification results, and release-index digest to agree with the immutable release metadata and downloaded index. Historical results remain bound to their original Release Identity.

Stable evidence codes are `RELEASE-STAGED-ONBOARDING-PACKAGE-QUALIFICATION`, `RELEASE-INSTALLER-EXACT-SIX-ASSETS`, `RELEASE-INSTALLER-PUBLIC-ATTESTATION`, `RELEASE-INSTALLER-MODULE-PASSED`, `RELEASE-INSTALLER-SEAM-PASSED`, `RELEASE-INSTALLER-INTEGRATED-PASSED`, `RELEASE-STAGED-ONBOARDING-SECRET-SCAN`, `RELEASE-INSTALLER-LIVE-NOT-REQUIRED`, and `RELEASE-INSTALLER-OWNER-NOT-REQUIRED`.
