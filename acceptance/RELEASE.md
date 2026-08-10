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
