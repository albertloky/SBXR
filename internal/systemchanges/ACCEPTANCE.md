# System Changes acceptance

This record covers the System Changes Module only. It is not Release Qualification.

## Stable checks

- `SYSTEM-CHANGES-INSPECT`: `go test ./internal/systemchanges -run TestInspectReportsOnlyFourSecretSafeTransactionStates`
- `SYSTEM-CHANGES-ADMISSION`: `go test ./internal/state ./internal/systemchanges -run 'Test(EveryMutationClassUsesOneSystemChangesLockBeforeLiveWork|ApplyRefusesUnsafeWorkBeforeMutation|ApplyRejectsCallerMadePreparedState)'`
- `SYSTEM-CHANGES-LOCK`: `go test ./internal/systemchanges/adapter/ubuntu -run TestKernelLockIsReadOnlyToInspectAndReleasedByProcessExit -v`
- `SYSTEM-CHANGES-QUEUE-EXCLUSION`: `go test ./internal/systemchanges -run TestApplyNeverQueuesOrStealsHeldLock`
- `SYSTEM-CHANGES-DISK-TIME`: `go test ./internal/systemchanges -run TestApplyRefusesUnsafeWorkBeforeMutation`
- `SYSTEM-CHANGES-ENTRY-POINT`: `go test ./internal/systemchanges -run TestChangeSetRejectsUntypedMutationSurfaces`
- `SYSTEM-CHANGES-SUCCESS`: `go test ./internal/state -run TestPreparedCommitDurablyCompletesOneSystemChangesChangeSet`
- `SYSTEM-CHANGES-GATES`: `go test ./internal/state -run TestSuccessfulChangeSetEnforcesFreshRequiredAndAdvisoryGates`
- `SYSTEM-CHANGES-SNAPSHOT-JOURNAL`: `go test ./internal/state -run TestUbuntuAdapterDurablyProtectsAndCleansSuccessfulTransaction`
- `SYSTEM-CHANGES-TRANSACTION-PATH`: `go test ./internal/state -run TestUbuntuAdapterRefusesUnsafeTransactionPathsBeforeLiveWork`
- `SYSTEM-CHANGES-ROLLBACK`: `go test ./internal/state -run 'Test(LiveStepFailureRestoresBaselineInSafeReverseOrder|ExplicitCancellationWaitsForSafeCheckpointThenRollsBack|PostPublicationFailureRestoresPriorDesiredState|PublicationFailureBeforeOrAfterReplacementRestoresPriorDesiredState|UnprovableReversePathEntersRecoveryRequired|FailedInstallationRestoresProvenNotInstalledBaseline)'`
- `SYSTEM-CHANGES-SUPERVISION`: `go test ./internal/state -run 'TestUbuntuAdapter(KeepsSupervisedWorkAliveUntilExplicitCancellation|BoundsLiveStepAndRollsBackOnTimeout)'`
- `SYSTEM-CHANGES-STATE-ROLLBACK`: `go test ./internal/state/adapter/filesystem -run TestAtomicRollbackRestoresManagedOrNotInstalledBaseline`
- `SYSTEM-CHANGES-FORWARD-DEATH`: `go test ./internal/state -run TestFreshSystemChangesInstanceNeverResumesOrdinaryForwardWork`
- `SYSTEM-CHANGES-RECOVERY-RUNNER`: `go test ./internal/state -run TestUbuntuRecoveryAcquiresProcessReleasedLockBeforeServicesAndRollsBack`
- `SYSTEM-CHANGES-SERVICE-START`: `go test ./internal/state -run TestRecoveryKeepsAffectedServicesStoppedWithoutStartingStateAgreement`
- `SYSTEM-CHANGES-ROLLBACK-RESUME`: `go test ./internal/state -run 'Test(FreshSystemChangesInstanceResumesInterruptedRollbackFromDurableEvidence|RollbackCanSurviveASecondProcessDeath|UbuntuRecoveryResumesProcessDeathDuringRollback|UbuntuRecoveryRefusesMissingRollbackEvidence)'`
- `SYSTEM-CHANGES-COMPLETE-CLEANUP`: `go test ./internal/state -run 'Test(RestartAfterCompleteCleansUpWithoutRollback|UbuntuRecoveryAfterCompleteOnlyCleansResolvedMaterial|UbuntuRecoveryRefusesContradictoryCompleteEvidence)'`
- `SYSTEM-CHANGES-RECOVERY-REQUIRED`: `go test ./internal/systemchanges -run TestRecoveryRequiredExposesOnlyItsExactSafeActions`
- `SYSTEM-CHANGES-RECOVERY-RETRY`: `go test ./internal/state -run TestRetryAutomaticRollbackUsesOnlyTheAuthorizedRecoveryPath`
- `SYSTEM-CHANGES-RECOVERY-REFUSAL`: `go test ./internal/systemchanges -run 'Test(RecoveryOptionsRequireExactEligibilityFacts|RecoveryRequiredBlocksNormalMutationAndAdmitsOnlyValidForwardRepair)'`
- `SYSTEM-CHANGES-FORWARD-REPAIR`: `go test ./internal/state -run TestValidCurrentStateDriftCreatesOnlyAFreshForwardRepairChangeSet`
- `SYSTEM-CHANGES-FIREWALL-WATCHDOG`: `go test ./internal/state ./internal/systemchanges/adapter/ubuntu -run 'Test(UbuntuFirewallSeamPreservesSSHAndCleansOnlyExactHTTP01Rule|UbuntuFirewallRestartRepeatsOnlyItsRecordedReverse|NativeFirewallUsesWatchdogAndExactHTTP01Handle|ProductionFirewallSeam)' -v`
- `SYSTEM-CHANGES-SSH-PROOF`: `go test ./internal/state -run TestUbuntuFirewallSeamPreservesSSHAndCleansOnlyExactHTTP01Rule/SSH -v`
- `SYSTEM-CHANGES-HTTP01-RULE`: `go test ./internal/state ./internal/systemchanges/adapter/ubuntu -run 'Test(UbuntuFirewallSeamPreservesSSHAndCleansOnlyExactHTTP01Rule|NativeFirewallUsesWatchdogAndExactHTTP01Handle)' -v`
- `SYSTEM-CHANGES-RENEWAL-SCHEDULER`: `go test ./internal/certificatelifecycle ./internal/state -run 'Test(SystemdUnitsOwnOnePersistentRandomizedTwiceDailyRenewal|CertificateRenewalSchedulerUsesRealOneUseSystemChangesLock)'`
- `SYSTEM-CHANGES-RENEWAL-LINEAGE`: `go test ./internal/state -run TestCertificateRenewalSchedulerUsesRealOneUseSystemChangesLock`
- `SYSTEM-CHANGES-SCHEDULED-LOCK`: `go test ./internal/systemchanges -run TestApplyNeverQueuesOrStealsHeldLock`
- `SYSTEM-CHANGES-REMOVAL-CONFIRMATION`: `go test ./internal/systemchanges -run TestCompleteRemovalRequiresBothExactConfirmations`
- `SYSTEM-CHANGES-RUN-TOKEN-ROTATION`: `go test ./internal/cloudflaretunnel ./internal/state -run 'Test(ExecutorRemovesTheOldTokenAtCheckpointAndRestartsOnlyWithTheNewToken|RunTokenRotationCancellationImmediatelyBeforeTheCheckpointRollsBack|OwnerAssistedRunTokenRotationPausesThenRecoversForwardWithBothRoutes)'`
- `SYSTEM-CHANGES-REVERSIBLE-REMOVAL`: `go test ./internal/state -run 'Test(CompleteRemovalDurablyCrossesIrreversibleBoundaryAfterCloudflareDeletion|CompleteRemovalKeepsCloudflareDeletionRollbackSafeUntilVerified|CompleteRemovalCancellationAfterExternalDeletionStillRollsBack|UbuntuAdapterReversesOnlyTypedCompleteRemovalResourcesAfterRestart)'`
- `SYSTEM-CHANGES-EXTERNAL-ORDERING`: `go test ./internal/systemchanges ./internal/state -run 'Test(CompleteRemovalAcceptsOnlyOrderedTypedOwnedResources|UbuntuAdapterReversesOnlyTypedCompleteRemovalResourcesAfterRestart)'`
- `SYSTEM-CHANGES-REMOVAL-STARTING-STATUS`: `go test ./internal/state -run TestCompleteRemovalFailureOrCancellationRestoresItsProvenStartingStatus`
- `SYSTEM-CHANGES-IRREVERSIBLE-CHECKPOINT`: `go test ./internal/state -run 'Test(CompleteRemovalDurablyCrossesIrreversibleBoundaryAfterCloudflareDeletion|CompleteRemovalRefusesTheIrreversibleCheckpointUntilLocalDeletionIsReady|CompleteRemovalFailureAfterTheIrreversibleBoundaryResumesForward|IrreversibleCompleteRemovalRefusesAnAutomaticRollbackRequest|UbuntuAdapterRollsBackBeforeTheIrreversibleCheckpointWhenLocalDeletionIsUnready)'`
- `SYSTEM-CHANGES-TOKEN-REVOCATION`: `go test ./internal/state -run 'Test(CompleteRemovalWaitsForVerifiedRevocationBeforeDeletingTheLocalToken|UbuntuAdapterRefusesRemovalRollbackAfterScopedTokenDisappears)'`
- `SYSTEM-CHANGES-REMOVAL-RESTART`: `go test ./internal/state -run 'Test(CompleteRemovalResumesForwardAfterEveryIrreversibleCheckpointDeath|CompleteRemovalResumesForwardAfterDeathAtTheIrreversibleBoundary|UbuntuAdapterRemovalResumesForwardDeletionAfterProcessDeathAtEveryCheckpoint|UbuntuAdapterRemovalResumesAfterDeathBetweenFinalJournalAndDirectoryDeletion|UbuntuAdapterLeftoverRunnerSelfCleansAfterJournalDeletion)'`
- `SYSTEM-CHANGES-FORWARD-DELETION-ORDER`: `go test ./internal/state -run TestCompleteRemovalContinuesForwardOnlyInItsFixedDeletionOrder`
- `SYSTEM-CHANGES-REMOVAL-OUTCOME`: `go test ./internal/state -run TestCompleteRemovalForwardFailureNamesTheLastDurableCheckpointWithoutSecrets`
- `SYSTEM-CHANGES-FINAL-ABSENCE`: `go test ./internal/state -run 'TestUbuntuAdapter(CompletesForwardOnlyRemovalAfterVerifiedTokenRevocation|KeepsOrphanRunnerWhileOwnedResourcesRemain)'`
- `SYSTEM-CHANGES-REPOSITORY`: `go test ./...`

## SC-01 procedure

1. Run `Inspect` against Not installed, Managed, Change in progress, and Recovery Required facts. Confirm it returns only typed identity, checkpoint, progress, lock, rollback, action, and finding fields.
2. Hold the kernel lock in another process. Confirm scheduled health defers, discovery and verification remain read-only and allowed, certificate renewal defers with fresh-plan instructions, ordinary Apply refuses, and no queue, lock stealing, force unlock, PID guess, or wall-time guess appears.
3. Release or kill the owning process. Confirm the kernel releases the same lock and exactly one fresh Apply can acquire it.
4. Apply each mutation class with one opaque prepared State marker, exact starting lineage, reviewed Plan and volatile checksums, typed forward and rollback steps, Required and Advisory checks, positive bounds, and the six-part disk reservation.
5. Change each State or volatile binding after review; repeat an authority; submit no-op or untyped material; lower available disk below reservation plus the larger of `1 GiB` or `10%`; fail wall or monotonic time; and vary Required and Advisory results. Every refusal must say `nothing_changed`, burn the Plan, close the lock, and expose only secret-safe typed evidence.

## SC-02 procedure

1. Apply one valid Managed setting Change Set. Confirm the old Desired State remains current through the ordered live step, then pre-publication Required health passes before the single atomic State publication.
2. Confirm protected preparation writes and verifies the prior opaque State, exact affected host material, candidate State, prepared service files and manifests, typed forward and rollback steps, health gates, Plan checksum, State checksums, and Release Identity before the durable `Prepared` entry.
3. Confirm transaction and snapshot directories are owner-only `0700`; every file is owner-only `0600`; symbolic links, unexpected files, unsafe modes, duplicate artifacts, checksum disagreement, and out-of-order checkpoints stop without being treated as success.
4. Confirm the journal reaches `Prepared`, each `Step started` and `Step completed` with typed durable evidence, `Pre-publication health passed`, `Desired State publication started`, `Desired State published`, `Post-publication health passed`, and `Complete` in that order. Required results other than Healthy and Advisory Failed or Unknown do not pass; reviewed Advisory Needs attention may pass. Only `Server-side` checks enter these gates; `Client device` results cannot hold or satisfy them.
5. Confirm fresh post-publication agreement covers State readback, prepared manifests, active files, service effects, and owning-Module checks. Only after durable `Complete`, permanently delete the completed journal and Rollback Snapshot; no transaction history remains.

## SC-03 procedure

1. Fail each attempted live step and each pre-`Complete` health, publication, and agreement boundary. Confirm automatic rollback starts immediately, restores the exact prior Desired State, runs every attempted Module-supplied reverse operation in descending step order, and cannot be cancelled.
2. Request explicit cancellation before Apply and confirm nothing changes. Request it during a live step and confirm the worker records `Cancellation requested` only after that step reaches its declared safe checkpoint, then records `Rollback started`, each `Rollback step started` and `Rollback step completed`, `Rollback verified`, and `Rolled back`.
3. Drop the presentation session without requesting cancellation. Confirm supervised Apply remains active; a later `Inspect` shows only secret-safe progress and `Inspect` as the allowed action, without joining, duplicating, or mutating the worker.
4. Force publication failure both before and after atomic replacement. Confirm State resolves the exact prior or candidate bytes without guessing, then restores Managed revision `N` or the proven Not installed baseline before host rollback is verified.
5. Bound a controlled native step and force its timeout. Confirm deterministic stop, safe reverse work, permanent cleanup after `Rolled back`, and only the outcomes nothing changed, `Rollback succeeded`, or `Recovery Required`. Inject secret-bearing errors and confirm results expose only stable code, owner, safe checkpoint, cause, and next action.

## SC-04 procedure

1. End the forward worker immediately after each durable ordinary checkpoint from `Prepared` through `Post-publication health passed`. Construct a fresh System Changes instance over the same durable Adapter and confirm it never executes another forward step.
2. Start the private recovery runner before affected public services and timers. Confirm it acquires only the kernel-released global lock, rejects PID and wall-time guesses, verifies exactly one protected journal and Rollback Snapshot, and accepts current State only when its revision/checksum pair matches the transaction's starting or candidate lineage.
3. Treat every `Step started` without durable completion as potentially applied. Confirm the Adapter runs the step's declared inspection contract, then its idempotent reverse from the checksum-bound snapshot before the prior baseline can be reported restored.
4. Hold affected services before step inspection or reversal. Confirm unrelated services may remain available only through a proven starting-State agreement; affected services remain stopped when that agreement is Unknown or fails.
5. Kill a controlled worker process after its durable forward checkpoint. Confirm the kernel releases the real lock, a new recovery runner restores the State and host baseline from protected files, writes the normal rollback checkpoints, and removes the resolved transaction material.

## SC-05 procedure

1. End rollback immediately before and after `Rollback started`, `Rollback step started`, `Rollback step completed`, `Rollback verified`, and `Rolled back`. Construct a fresh System Changes instance over the same durable Adapter and confirm it continues only from proven journal evidence.
2. Reinspect and repeat a reverse step when its completion is not durable. Skip a reverse step only when its valid completion evidence is durable, and preserve descending reverse order across another process death.
3. Keep affected services stopped until exact prior-State and Observed-State agreement passes. Remove the resolved journal and Rollback Snapshot after `Rolled back`, leaving no transaction history.
4. Restart after durable `Complete` with cleanup material still present. Confirm services start only from candidate-State agreement, cleanup removes the completed journal and Rollback Snapshot, State remains at the successful revision, and no reverse or prior-State restoration runs.
5. Remove rollback evidence or append contradictory post-`Complete` journal evidence. Confirm recovery stops without reversing, starting unproven affected services, deleting the unresolved transaction, or guessing a resolution.

## SC-06 procedure

1. Make current State lineage, Rollback Snapshot integrity, journal integrity, a forward checkpoint, a rollback step, and final prior-State agreement unprovable in turn. Confirm each result is Recovery Required, ordinary mutation remains blocked, and secret-bearing Adapter errors never appear in inspection or recovery results.
2. Supply exact valid unfinished transaction material. Confirm Retry automatic rollback appears and invokes the existing authorized rollback path. Remove or contradict that material and confirm Retry disappears without adoption, journal bypass, manual completion, forced service start, evidence deletion, force unlock, historical selection, restore menu, lost-secret reconstruction, or in-place repair of missing Desired State.
3. With no valid rollback material, confirm the exact actions are secret-safe inspection, read-only diagnostics, Check again, Back, and separately confirmed Complete removal. Confirm every external or Owner-controlled blocker includes its exact Owner work plan and never offers Continue anyway or a dead end.
4. Prove current State lineage and checksum while reporting only current-State drift. Confirm a Repair mutation may create one fresh reviewed forward-repair Change Set and never consumes an old snapshot or completed journal.
5. Report missing or corrupt State, missing secrets, a replacement or dead VPS, an older revision, and Owner regret. Confirm the recovery plan is Complete removal and rebuild, not restore.

## SC-07 procedure

1. Submit one typed Network Policy step with the complete approved `inet sbxr` candidate and detected non-default SSH port. Confirm arbitrary nftables text, another table, whole-ruleset flush, a missing SSH port, and an untyped Network Policy operation are refused before preparation.
2. Capture the exact prior `inet sbxr` policy in the protected transaction snapshot, pass native `nft --check`, arm the root rollback watchdog, and atomically replace only `inet sbxr`. Confirm an existing SSH session remains established and the resulting policy admits the detected port before cancelling the watchdog. Fail or time out either proof and confirm automatic rollback restores only prior `inet sbxr` while unrelated tables remain unchanged.
3. Open HTTP-01 with exactly one `sbxr:acme-http-01` 80/TCP rule. Confirm its native handle identity becomes durable step evidence before later work. On success close only that recorded handle and prove no 80/TCP exposure remains; on failure, explicit cancellation, interrupted reverse, and fresh restart recovery restore the transaction baseline without deleting unrelated rules.
4. Confirm the Certificate Lifecycle-owned scheduling contract names exactly one persistent randomized service and one timer, evaluates IP then domain serially at least twice daily, creates a separate one-use Change Set for each due lineage, and sends every Apply through the global lock. Hold the lock and confirm each renewal is deferred without a queue or Plan construction; after release, the scheduler must rebuild observations and a fresh Plan under that lock within its own due and retry policy.
5. On an explicitly approved isolated Ubuntu host, set `SBXR_CONTROLLED_FIREWALL_SEAM=1` and run the firewall-watchdog stable check. Confirm native validation, the real watchdog, non-default SSH proof, atomic application, exact rollback, and unrelated-table preservation. Do not run this mutation check on an Owner VPS.

## SC-08 procedure

1. Admit Complete removal only when the Owner typed exact `COMPLETE REMOVAL` and selected `Permanently remove SBXR` after reviewing every resource category. Reject missing text, partial or pasted substitutes, ordinary Enter, a single confirmation, command-line flags, and confirmation attached to any other mutation.
2. Under the existing global lock and protected transaction snapshot, bind the Plan to each owning Module's complete immutable-ID inventory for all six reviewed categories. Require the typed steps to cover those inventories exactly, including multiple resources in one category and typed empty-category evidence. Remove and verify typed owned public and Cloudflare exposure before the irreversible boundary. Preserve unrelated resources, and keep the scoped token active and its local copy available. Never place the token in process arguments, environment, journal evidence, or typed results.
3. Fail or cancel before Apply and after each public or Cloudflare safe checkpoint. From a proven Managed start, restore Managed. From a proven Recovery Required start, restore that exact status. Reverse only attempted typed resources in descending order and remove resolved transaction material.
4. End the process before `Irreversible removal started` and construct a fresh System Changes instance over the protected journal. Confirm recovery reverses every recorded public and Cloudflare resource, preserves the still-available scoped token and unrelated resources, and proves the exact starting status. Keep destructive VPS and real-token checks Pending without an approved Acceptance Run.

## SC-09 procedure

1. Delete and verify only the exact committed Cloudflare identifiers while protected rollback remains available. A changed identifier, deletion failure, absence failure, cancellation, or process death before the checkpoint restores the exact proven starting status.
2. After the required absence gate passes, record `Owned external deletion verified`. Require the Ubuntu removal owner to prove that the fixed remaining sequence and ownership evidence are ready, then record `Irreversible removal started` immediately before asking the Owner to revoke the scoped Cloudflare token. A readiness failure rolls back while that remains possible. After the irreversible record, cancellation, Retry automatic rollback, and restore cannot reverse or restore anything; recovery can only continue forward.
3. Verify through the still-present local token copy that Cloudflare rejects the revoked token. Do not delete that local copy or any later local resource until the verification passes. A usable token waits for Owner action; missing or unprovable token evidence enters forward-only Recovery Required and never rollback.
4. Continue in this fixed order: local State, Infrastructure Secrets, certificates, transaction material except the journal, releases, units, identities, listeners, prepared artifacts, owned firewall state, and finally the removal journal and private recovery runner. Record durable evidence after every deletion phase. Repeat an uncertain phase idempotently; skip it only when its completion record is durable.
5. End the worker immediately before and after every irreversible deletion checkpoint. Construct a fresh System Changes instance and confirm it resumes at the exact next unproven forward phase, never starts affected services, never runs a reverse operation, and never restores prior State.
6. Report success only after the production Adapter observes exact `Not installed`, every owned resource is absent, the local token copy is absent, the snapshot and prior release are absent, the transaction manifest and artifacts are absent, and finalization removes the journal and recovery runner. A stopped post-checkpoint attempt reports `Removal remains forward-only` and the last checkpoint actually written; it never pretends rollback is available or copies a native error into evidence. Report that Certificate Transparency entries and DNS caches cannot be erased. The controlled Ubuntu seam proves ordering, restart-safe evidence, typed secret-safe outcomes, and final cleanup; destructive VPS and real-token checks remain Pending without an approved Acceptance Run.

## SC-10 procedure

1. Admit Tunnel run-token rotation as its own one-step Change Set. Before the irreversible boundary, cancel or fail preparation and confirm ordinary rollback restores the exact starting State and service token.
2. Record `Irreversible run-token rotation started` before asking the Owner to select **Rotate token**. If that record is missing or unprovable, stop without deleting the old token or asking for provider action. Once durable, delete the old token and every rollback copy and never offer automatic rollback.
3. Keep waiting while Cloudflare's documented token GET returns the original fingerprint. When it changes, pass the opaque token only to State, replace the protected transaction artifacts, restart `cloudflared.service`, and require the connected Tunnel plus both routes at the pre- and post-publication gates.
4. Fail or end the worker after each forward checkpoint. Confirm a fresh recovery runner resumes the exact next unproved phase, reports Recovery Required on failure, never executes a reverse operation, and never restores, writes, or reconnects with the old token.
5. Remove transaction material only after durable `Complete`. Keep real Cloudflare rotation, live reconnect, and real forward-recovery evidence Pending without an approved Acceptance Run.

## Current status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | SC-01 checks cover four-state inspection and safe admission. SC-02 checks cover durable success. `SYSTEM-CHANGES-ROLLBACK` covers SC-03 cancellation and failure. `SYSTEM-CHANGES-FORWARD-DEATH` and `SYSTEM-CHANGES-SERVICE-START` cover SC-04 restart rollback. SC-05 checks cover interrupted rollback continuation, a second death, exact service holdback, cleanup-only restart after `Complete`, and corrupt-evidence refusal. SC-06 checks cover the Recovery Required action boundary, exact retry eligibility, refusal, secret safety, and fresh forward repair. SC-07 checks cover typed firewall admission, watchdog ordering, non-default SSH proof, exact HTTP-01 identity and cleanup, interrupted reverse, restart recovery, unrelated-rule preservation, and renewal serialization ownership. SC-08 checks cover exact two-part confirmation, typed reversible public and immutable-ID external deletion, token availability, cancellation and failure at every logical boundary, both starting statuses, durable handoff, and pre-checkpoint restart rollback. SC-09 checks cover the irreversible boundary, verified token revocation, refusal of rollback and restore, fixed forward deletion, checkpoint restart continuation, final Not installed observation, and recovery-material cleanup. SC-10 checks cover the owner-assisted run-token checkpoint, protected replacement, controlled restart, both-route gates, and forward-only recovery. |
| Seam Verification — controlled kernel lock | Passed | `SYSTEM-CHANGES-LOCK` uses a real kernel file lock, proves held-lock refusal, process-exit release, exact protected lock-file identity, and read-only host observation. |
| Seam Verification — controlled transaction filesystem | Passed | SC-02 filesystem checks cover protected durable success. SC-03 checks prove rollback and cleanup. `SYSTEM-CHANGES-RECOVERY-RUNNER` proves forward-death recovery. SC-05 kills rollback in a separate process, reopens the production Adapter's protected evidence, repeats the uncertain reverse, proves service holdback, and removes only durably resolved transaction material. |
| Seam Verification — controlled native firewall | Passed | Deterministic production-Adapter command-boundary checks prove native validation, watchdog-before-Apply ordering, cancellation only after both SSH proofs, exact recorded-handle cleanup, generic-error redaction, and unrelated-rule preservation. |
| Seam Verification — controlled reversible removal | Passed | Protected Ubuntu-Adapter fixtures use typed replacement resources, preserve unrelated external identity, require live token availability without storing credentials, refuse lineage-less Recovery Required, and prove restart rollback to Managed from exact earlier-baseline evidence. |
| Seam Verification — controlled irreversible removal | Passed | The production Ubuntu Adapter verifies token rejection before local secret deletion, keeps the protected journal while deleting transaction material, completes the fixed forward-only sequence, observes exact Not installed, and removes the final journal and recovery runner. |
| Seam Verification — production Ubuntu | Passed | GitHub Actions run `31128547757` ran the complete race-enabled suite and `go vet` on isolated Ubuntu 24.04, then ran `TestProductionFirewallSeam` as root with real nftables, systemd transient watchdog units, socket/SSH proof, unrelated-table preservation, exact rollback, and a forced post-mutation failure whose durable snapshot remained available through recovery. |
| Integrated Verification | Pending — integrated release | All-Module wiring, Certificate Lifecycle unit installation/private-command wiring, and complete executable native removal are not yet qualified as one integrated release. Controlled SC-04 through SC-09 checks do not satisfy integrated verification. |
| Codex Live Acceptance | Pending — approved Acceptance Run | No Acceptance VPS was used. |
| Owner Acceptance | Pending — first v1 release | Albert's maintained workflow is outside this Module Verification. |
