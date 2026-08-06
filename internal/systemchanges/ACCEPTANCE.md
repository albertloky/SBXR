# System Changes acceptance

This record covers the System Changes Module only. It is not Release Qualification.

## Stable checks

- `SYSTEM-CHANGES-INSPECT`: `go test ./internal/systemchanges -run TestInspectReportsOnlyFourSecretSafeTransactionStates`
- `SYSTEM-CHANGES-ADMISSION`: `go test ./internal/state ./internal/systemchanges -run 'Test(PreparedCommitIsTheOneUseSystemChangesAuthorityForEveryMutationClass|ApplyRefusesUnsafeWorkBeforeMutation|ApplyRejectsCallerMadePreparedState)'`
- `SYSTEM-CHANGES-LOCK`: `go test ./internal/systemchanges/adapter/ubuntu -run TestKernelLockIsReadOnlyToInspectAndReleasedByProcessExit -v`
- `SYSTEM-CHANGES-QUEUE-EXCLUSION`: `go test ./internal/systemchanges -run TestApplyNeverQueuesOrStealsHeldLock`
- `SYSTEM-CHANGES-DISK-TIME`: `go test ./internal/systemchanges -run TestApplyRefusesUnsafeWorkBeforeMutation`
- `SYSTEM-CHANGES-ENTRY-POINT`: `go test ./internal/systemchanges -run TestChangeSetRejectsUntypedMutationSurfaces`
- `SYSTEM-CHANGES-REPOSITORY`: `go test ./...`

## SC-01 procedure

1. Run `Inspect` against Not installed, Managed, Change in progress, and Recovery Required facts. Confirm it returns only typed identity, checkpoint, progress, lock, rollback, action, and finding fields.
2. Hold the kernel lock in another process. Confirm scheduled health defers, discovery and verification remain read-only and allowed, certificate renewal defers with fresh-plan instructions, ordinary Apply refuses, and no queue, lock stealing, force unlock, PID guess, or wall-time guess appears.
3. Release or kill the owning process. Confirm the kernel releases the same lock and exactly one fresh Apply can acquire it.
4. Apply each mutation class with one opaque prepared State marker, exact starting lineage, reviewed Plan and volatile checksums, typed forward and rollback steps, Required and Advisory checks, positive bounds, and the six-part disk reservation.
5. Change each State or volatile binding after review; repeat an authority; submit no-op or untyped material; lower available disk below reservation plus the larger of `1 GiB` or `10%`; fail wall or monotonic time; and vary Required and Advisory results. Every refusal must say `nothing_changed`, burn the Plan, close the lock, and expose only secret-safe typed evidence.

## Current status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | `SYSTEM-CHANGES-INSPECT`, `SYSTEM-CHANGES-ADMISSION`, `SYSTEM-CHANGES-QUEUE-EXCLUSION`, `SYSTEM-CHANGES-DISK-TIME`, and `SYSTEM-CHANGES-ENTRY-POINT` cover SC-01's four states, one-use admission, all mutation classes, stale/no-op/disk/time/check refusals, activity policy, typed input, and secret-safe output. |
| Seam Verification — controlled kernel lock | Passed | `SYSTEM-CHANGES-LOCK` uses a real kernel file lock, proves held-lock refusal, process-exit release, exact protected lock-file identity, and read-only host observation. |
| Seam Verification — production Ubuntu | Pending | Run the same Adapter checks on the assigned controlled Ubuntu environment; this local run does not claim Ubuntu/systemd acceptance. |
| Integrated Verification | Pending — integrated release | SC-02 through SC-09, all-Module wiring, durable transaction execution, publication, rollback, restart recovery, watchdog work, and Complete removal do not exist yet. |
| Codex Live Acceptance | Pending — approved Acceptance Run | No Acceptance VPS was used. |
| Owner Acceptance | Pending — first v1 release | Albert's maintained workflow is outside this Module Verification. |
