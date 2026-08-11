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

## `RELEASE-INSTALL-REVISION-1` — Integrated Verification — Codex

This procedure has no result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record.

1. Build the exact release executable and start the default `sbxr` Owner Console on a proven Clean VPS. Enter only the reviewed release tag, installation draft, scoped Cloudflare account/zone token, and REALITY target. Confirm the Console shows one revision-1 Plan and no Client Access Value or Infrastructure Secret.
2. Apply through the ordinary command `/usr/bin/sudo --preserve-fds=3 -- /proc/self/fd/3 private install-apply`. Require the root child to rebuild the exact candidate and generated installation inputs, prepare before `READY`, accept one `APPLY`, and reject replay, malformed input, changed executable/candidate, parent death, or changed Plan.
3. Require `NETWORK-CERTIFICATE-DNS-PENDING` only when Direct DNS is absent on the Clean VPS and effective CAA already permits `letsencrypt.org` HTTP-01. Require the reviewed Cloudflare Plan to create and verify the exact Direct A/AAAA records before either production certificate order. Any conflicting or changed DNS must stop and roll back.
4. Require exactly one Desired State publication from `Not installed` to revision `1` `Managed`, finalized Cloudflare Tunnel/DNS IDs and run token, both certificate lineages, six profiles, all subscription representations, HTTPS Serving, four public services, three timers, exact ownership/modes, required health gates, and durable post-publication agreement.
5. Inject one failure before publication and one after publication. Request cancellation while a step is active. Kill the worker once during forward work and once during rollback, then restart the exact executable. Each reversible case must restore proven `Not installed`; an unprovable retry must report `Recovery Required`. After `Complete`, require the transaction directory and rollback material to be absent and require restart to keep revision 1 without republishing.
6. Run the focused automated evidence:

   ```sh
   go test ./cmd/sbxr -run '^(TestComposedInstallBuildsAndPreparesTheCompleteRevisionOnePlan|TestInstallApplyObservationFailsClosedAndKeepsProvenStateLineage)$' -count=1
   go test ./internal/softwarelifecycle/adapter/ubuntu -run '^(TestInstallApplyHandoffIsOneBoundedStrictRequestAndOneUseApproval|TestInstallApplyHandoffRefusesMalformedOversizeEOFAndParentDeath|TestInstallApplyCancellationReachesTheActivePreparedApply|TestInstallApplyReportsRecoveryRequiredAsAnExactSecretSafeTerminal|TestInstallExecutableMustMatchTheReviewedCandidate|TestInstallerCreatesAndRollsBackOnlyItsFreshServiceIdentities)$' -count=1
   go test ./internal/systemchanges -run '^TestRecoveryUnitRunsThePrivateRollbackBeforeManagedServices$' -count=1
   go test ./internal/state -run '^(TestSoftwareLifecycleInstallPublishesRevisionOneOnlyAfterCompleteAgreement|TestDeferredCloudflareFinalizationPublishesProviderValuesInRevisionOne|TestExplicitCancellationWaitsForSafeCheckpointThenRollsBack|TestPostPublicationFailureRestoresPriorDesiredState|TestPublicationFailureBeforeOrAfterReplacementRestoresPriorDesiredState|TestFailedInstallationRestoresProvenNotInstalledBaseline|TestFreshSystemChangesInstanceResumesInterruptedRollbackFromDurableEvidence|TestRollbackCanSurviveASecondProcessDeath|TestRestartAfterCompleteCleansUpWithoutRollback)$' -count=1
   go test ./internal/networkpolicy ./internal/certificatelifecycle ./internal/cloudflaretunnel ./internal/connectionprofiles/... ./internal/subscriptionpublication ./internal/subscriptionserving ./internal/systemchanges/... ./internal/softwarelifecycle/... ./internal/state ./cmd/sbxr -count=1
   go test ./... -count=1
   ```

7. Scan the built executable test transcript, transaction journal, prepared manifests, State refusal/result rendering, Owner Console transcript, and redacted Acceptance Record for every generated test Client Access Value, Infrastructure Secret, Cloudflare run token, installation entropy seed, private key, complete subscription URL, and injected external-error marker. Any match outside its owning protected State/service artifact fails `RELEASE-INSTALL-SECRET-SCAN`.

Stable evidence codes for this procedure are `RELEASE-INSTALL-REVISION-1`, `RELEASE-INSTALL-STALE-PLAN`, `RELEASE-INSTALL-PRE-PUBLICATION-ROLLBACK`, `RELEASE-INSTALL-POST-PUBLICATION-ROLLBACK`, `RELEASE-INSTALL-CANCELLATION`, `RELEASE-INSTALL-RESTART`, `RELEASE-INSTALL-CLEANUP`, and `RELEASE-INSTALL-SECRET-SCAN`.

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

1. From each exact installation status — `Not installed`, `Managed`, `Change in progress`, and `Recovery Required` — run the authenticated Diagnostics screen and `sbxr private health-check`. Require both paths to call the same Health and Diagnostics `Check`, return all eleven named Modules once, keep installation status separate from Module health, and show only fixed safe explanations, next actions, service summaries, retention limits, and bundle names.
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

Stable evidence codes are `RELEASE-HEALTH-DIAGNOSTICS`, `RELEASE-HEALTH-ELEVEN-MODULES`, `RELEASE-HEALTH-SCHEDULED-PERSISTENT`, `RELEASE-HEALTH-NO-MUTATION`, `RELEASE-HEALTH-LIFECYCLE-STATUS`, `RELEASE-DIAGNOSTIC-EVENT-RETENTION`, `RELEASE-SUPPORT-BUNDLE-THREE-FILE`, `RELEASE-SUPPORT-BUNDLE-REPLACEMENT`, `RELEASE-SUPPORT-BUNDLE-PERMISSIONS`, `RELEASE-SUPPORT-BUNDLE-NO-PARTIAL`, `RELEASE-SUPPORT-BUNDLE-TRANSACTION-EXEMPT`, and `RELEASE-HEALTH-SECRET-SCAN`.

## `RELEASE-SOFTWARE-CHANGE-N-TO-N+1` — Integrated Verification — Codex

This procedure has no live or Owner result in this file. Record results only against one exact Release Identity in its redacted Acceptance Record. No real VPS, reboot, release publication, provider, client, or Owner-console acceptance was authorized by issue #148; every such unperformed check remains Pending.

1. Begin from one proven `Managed` revision `N`. Through the authenticated privileged Managed dashboard and the root-owned `private update-check` timer path, run stable discovery and retain only the newest verified unapplied candidate at the documented protected boundary. Require both paths to perform no Apply, State, publication, service, firewall, provider, or executable change; require the Owner Console to show both exact Release Identities and one `Review update` action. Selecting review uses one verified `software-review` helper that reads protected facts, builds and returns the complete exact secret-safe executable Plan, performs no Managed-system mutation, and exits. Cancelling the review changes nothing.
2. Apply the reviewed update through a separate verified `software-apply` helper and one `Update` Change Set. Require it to freshly rebuild the complete Plan and match the exact reviewed identity and SHA-256 before accepting `APPLY`, then perform the State schema migration when declared by the authenticated release, regenerate Xray and sing-box configurations, Cloudflare service material, and all Subscription Publication representations, publish State once from `N → N+1`, restart only cloudflared, Xray, sing-box, and Subscription Serving, and pass pre- and post-publication agreement. At durable `Complete`, require the prior live release, rollback snapshot, journal, and exact applied retained candidate to be absent.
3. Select one exact older tag explicitly. Require fresh five-file verification, a lower authenticated sequence, current-State schema compatibility, and the same reviewed update machinery. Refuse the installed identity, a higher or equal sequence, incompatible schema, automatic downgrade, local release history, stale approval, changed prepared material, or a tag not freshly selected by the Owner without mutation.
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

## `RELEASE-IMMUTABLE-CANDIDATE` — Automated Qualification — Codex

This procedure records no result. It mints one acceptance candidate, not a stable, latest, automatically discoverable, live-accepted, Owner-accepted, or qualified release.

1. Require issues #145, #146, and #149 closed with their automated implementation evidence while every unperformed live and Owner row remains Pending under #151 and #152. Require repository immutable releases enabled before creating the candidate.
2. From one clean exact commit, manually dispatch `Mint immutable candidate` with tag `v1.0.0`, version `1.0.0`, and sequence `1`. Require native `ubuntu-24.04` amd64 and `ubuntu-24.04-arm` arm64 jobs using pinned Go `1.26.5` and `CGO_ENABLED=0` to create `sbxr-linux-amd64.tar.gz`, `sbxr-linux-arm64.tar.gz`, `sbxr-components-linux-amd64.tar.gz`, and `sbxr-components-linux-arm64.tar.gz`. Each application archive contains exactly one stamped `sbxr`; each component archive passes its matching native validators.
3. Build `release-index.json` only from those exact four regular files. Require schema `1`, product `sbxr`, repository `albertloky/SBXR`, the exact version, sequence, tag, commit, State schema, minimum updater schema, exact four roles and fixed names, calculated sizes, and calculated SHA-256 values. Refuse caller-supplied digests, missing, duplicate, extra, linked, occupied, changed, or oversized material.
4. Before publication, run every repository Module, Seam, and Integrated automated test available before GitHub attestation against the exact commit, execute each packaged application on its matching native runner, and scan the index plus the decompressed contents of every application/component archive for injected secret markers, private-key blocks, and authorization values. The prepublication stage matrix must leave GitHub-attestation-dependent Seam and Integrated rows Pending. A failure publishes nothing.
5. Download the workflow's exact five-file artifact, then use Owner-authenticated read-only repository administration to prove immutable releases are still enabled before creating any tag or release. Publish only the five fixed paths as an immutable prerelease with `latest=false`; never use a glob. Publication automatically starts the production GitHub verification and both architecture staging paths. Require `gh release verify v1.0.0 --repo albertloky/SBXR --format json` and `gh release verify-asset v1.0.0 <file>` for every local asset. Require the attested, indexed, downloaded, embedded, and reported repository, tag, commit, role, architecture, size, payload digest, asset digest, schema, migration, systemd definition, qualified artifact, and version facts to agree before those Pending rows become Passed.
6. Record one redacted identity-bound stage matrix on issue #150: Module Verification, Seam Verification, and Integrated Verification are Passed only from their actual workflow evidence; Codex Live Acceptance and Owner Acceptance remain Pending. Record the exact repository, tag, commit SHA, release-index SHA-256, workflow URL, stable codes, commands, tool versions, and safe findings. Never attach raw configurations, credentials, complete URLs, private keys, authorization values, provider output, proxy traffic, client addresses, or a secret-bearing archive.
7. Any artifact-bearing source, embedded asset, migration, schema, unit, compatibility definition, index, or payload change creates a new Release Identity and resets affected automated and later evidence. Do not mark the candidate stable/latest or enable automatic discovery before #153 records final Release Qualification.

Stable evidence codes are `RELEASE-CANDIDATE-SOURCE`, `RELEASE-CANDIDATE-AMD64`, `RELEASE-CANDIDATE-ARM64`, `RELEASE-CANDIDATE-INDEX`, `RELEASE-CANDIDATE-EXACT-FIVE-ASSETS`, `RELEASE-CANDIDATE-GITHUB-ATTESTATION`, `RELEASE-CANDIDATE-ASSET-VERIFICATION`, `RELEASE-CANDIDATE-MODULE-VERIFICATION`, `RELEASE-CANDIDATE-SEAM-VERIFICATION`, `RELEASE-CANDIDATE-INTEGRATED-VERIFICATION`, `RELEASE-CANDIDATE-SECRET-SCAN`, and `RELEASE-CANDIDATE-LIVE-PENDING`.
