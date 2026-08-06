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

## Current status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | SC-01 checks cover four-state inspection and safe admission. SC-02 checks cover durable success. `SYSTEM-CHANGES-ROLLBACK` covers SC-03 cancellation, deterministic failure, reverse order, publication ambiguity, Managed and Not installed restoration, typed outcomes, and secret-safe findings. |
| Seam Verification — controlled kernel lock | Passed | `SYSTEM-CHANGES-LOCK` uses a real kernel file lock, proves held-lock refusal, process-exit release, exact protected lock-file identity, and read-only host observation. |
| Seam Verification — controlled transaction filesystem | Passed | SC-02 filesystem checks cover protected durable success. `SYSTEM-CHANGES-SUPERVISION` and `SYSTEM-CHANGES-STATE-ROLLBACK` use real timers and files to prove explicit cancellation, presentation-loss continuation, later-session inspection, timeout, reverse execution, atomic State restoration, `Rolled back`, and transaction-only cleanup. |
| Seam Verification — production Ubuntu | Pending | Run the same Adapter checks on the assigned controlled Ubuntu environment; this local run does not claim Ubuntu/systemd acceptance. |
| Integrated Verification | Pending — integrated release | SC-04 through SC-09, all-Module wiring, restart recovery, watchdog work, and Complete removal do not exist yet. Controlled SC-03 rollback does not satisfy integrated verification. |
| Codex Live Acceptance | Pending — approved Acceptance Run | No Acceptance VPS was used. |
| Owner Acceptance | Pending — first v1 release | Albert's maintained workflow is outside this Module Verification. |
