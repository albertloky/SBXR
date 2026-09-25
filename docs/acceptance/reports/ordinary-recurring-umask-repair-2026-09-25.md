# Ordinary recurring update — approved mask repair and isolated rehearsal

## Scope and status

The Owner approved repair of the
[wrapper/update incompatibility](ordinary-recurring-rehearsal-stop-2026-09-25.md),
preserving the exact v3.1.81 binary, then resuming the approved qualification
sequence. The eight-scenario policy remains that of ADR-0025; no deadline,
metadata check, source requirement, trust rule or failure handling was relaxed.

The mask repair is implemented and locally regression-tested. **The resumed
sequence stops in isolated rehearsal:** an extended early-deadline check exposed
a separate startup-cancellation cleanup gap in the unchanged wrapper/menu
combination. No repair to that gap was silently added. No commit/push, new hosted
CI run, candidate dispatch, signing or publication was performed.

The Linux results below use isolated fixtures, including frozen release source;
they are **not packaged live upgrade proof**. Fresh public source verification
passed, but target verification, a genuinely signed candidate, complete fresh
host/package/CA checks, attended Karing and all eight live checks remain.
Publication retains its separate approval requirement. The new controller is
not cleared for live use.

## Repair

- `mvp-protected-menu.sh` keeps the pinned permission wrapper and supervisor
  unchanged. Inside their product child, a shell sets `umask 022` and execs the
  unchanged `/usr/local/bin/sbxr`. The wrapper's private state/control files
  keep `077`; explicitly requested `0600` product files remain private.
- The next updater's `writeUpdateFile` sets the exact requested mode on its own
  newly `O_EXCL`-created inode before synchronization. Existing files/symlink
  targets remain refused and untouched. This also repairs direct invocation
  under a restrictive caller mask, including rollback writes. It does not
  retrofit the released binary or rewrite existing transaction material.

## Red/green evidence

The new `update_umask_test.go` failed before the writer fix: `077` created a
`0700` candidate executable; `777` removed all requested mode bits; update and
recovery could not complete. After the fix, exact executable/private modes,
existing-file/symlink refusal, normal update, automatic rollback, public rollback
recovery and forward recovery pass. The required exact checks were not weakened.

The real launcher/menu/process regression failed against the original launcher
when a `0755` creation request inherited `077`. It passes with the repaired
launcher, including unchanged private `0600` creation, unsafe/missing log-child
refusals, exit-status propagation, protocol failure, deadline, cancellation,
escaped-child/lock cleanup and original permission restoration. The unchanged
wrapper still refuses restoration while its command group is live and refuses
changed log-parent topology.

For the released source comparison, a disposable archive of
`ed759a0ccaef5d1ffd14be5a41a0e915a6268ff7` received only a diagnostic `TestMain`
selector. Its existing lifecycle implementation/tests were unchanged. The same
Go 1.26.6 ARM64 test binary, SHA-256
`26dd776ad0b445036c634b9867edcab54d1003723d47e11e18a0e5d0a5d63ea8`, was run through
the actual wrapper:

| Launcher | Inherited mask | Existing lifecycle tests |
|---|---|---|
| Original | `0077` | All four fail |
| Repaired | `0022` | All four pass |

Those tests cover normal update, both precommit rollback-link shapes, and
committed forward recovery, using the release's existing synthetic
release/runtime seams. They do not run its packaged binary, network trust,
real subscription runtime or live outside traffic. An initial test-harness run
lacked the owning package's relative JSON fixture; its original failure was
retained, then the correct unchanged fixture/cwd was supplied. No release test
or assertion was altered to obtain green results.

## Resumed controller and SSH rehearsal

The previously unadopted interruption prototype was reviewed and implemented
as `mvp-update-interrupt.py`, with adjacent tests and the current operator
procedure. It observes successful directory `fsync` exit plus the exact bound
schema-2 checkpoint/material and held mutation lock, then terminates the actual
traced source threads/children before subsequent product work. It does not
modify syscall results, source bytes or product authority. The permission
wrapper remains alive to restore its own window after successful control.

The synthetic Go fixture now deliberately **does not chmod its staged files**;
both direct and wrapped controller paths set `022` only for the product child.
The eighteen-case Linux controller suite covers both checkpoints,
wrong source/record/request, missing mutation lock, visible records without
directory fsync, refusal/prompt mismatch, deadline/cancellation, original
request caps, pre-existing transcript preservation, descendant cleanup and
not-before refusal and no bytecode/staging pollution. All eighteen passed on
ARM64. The amd64 run failed the early-deadline cleanup assertion; a later complete
repeat passed, which does not resolve the timing-dependent failure described
below. These are process-kill controls, not simulated power-loss durability or
packaged recovery proof.

The documented incremental recorder function was replayed over actual SSH.
Its complete flow, incomplete submission refusal, changed-request binding and
refusal to republish consumed output pass. The complete SSH suite now has 25
cases; its locked-caller success/failure tests also pass and preserve host and
caller account state. Observations in these fixtures are synthetic, never live
acceptance records.

## Validation and artifacts

The primary isolated run used Ubuntu 24.04 ARM64/QEMU-HVF with restricted egress,
loopback-only pinned-key SSH and the same verified base image as the previous
rehearsal. The actual current Linux lifecycle update/recovery tests also ran.
The ordinary full local Go suite and vet passed; changed-package final checks
and focused lifecycle race checks are retained in the run directory. macOS
skips are not counted as Linux validation.

The additional amd64/QEMU-TCG run uses the verified official image SHA-256
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`.
Its slower startup exposed a fixture assumption that every cancelled permission
window had already reached `0755`: the unchanged wrapper also legitimately
retains state at the exact original `0775` identity before opening or after
restoration. The test now proves either exact safe identity and requires the
wrapper's own restoration/cleanup to succeed. The visible-but-unsynced tests
now wait for the requested fixture checkpoint and cancel explicitly, rather
than hoping a three-second deadline reaches it. Their marker is atomically
published to avoid observing its partially written body. These are fixture
corrections, not longer live deadlines or relaxed product metadata assertions.
Original failure logs remain with the final runs.

## Unresolved startup-cancellation finding

After fourteen passing amd64 cases, the two-second request case failed because
`window.state` or one of its channels remained after cancellation/explicit
restoration. The assertion was retained and given artifact-identity diagnostics;
no deadline or cleanup requirement was relaxed. One complete repeat passed all
eighteen cases. This is timing-dependent, not evidence that the first failure
was harmless or fixed.

The unchanged wrapper creates both private FIFOs before creating `window.state`
and installing its cleanup trap. The unchanged `MenuSession.stop` implementation
kills the owned process group on deadline/cancellation. A targeted one-shot
diagnostic stopped the real wrapper at that artifact boundary, then invoked the
actual menu-session cleanup. It confirmed:

- both `window.state.control` and `window.state.result` remained root:root `0600`;
- no `window.state` existed, and the wrapper's explicit `restore` refused it as
  an unsafe/missing state file;
- no child remained and `/var/log` retained its exact original identity/mode;
- no product command, update, CA request or live qualification was involved.

The wrapper SHA-256 was still
`4358cb1ec189bd33518a081702355405e9110892cf2be7e8235671005e2959eb`.
This isolates the pre-existing startup cleanup gap; it is not a failed packaged
upgrade or evidence of a damaged live installation. The diagnostic removed only
its absent-at-entry disposable fixture after proving child absence and unchanged
log identity. That destruction is not a reviewed operational orphan-channel
recovery route. The original suite failure, full repeat and
[targeted diagnostic](../../../.scratch/acceptance/u82b/startup-cancel-probe.log)
are retained.

Recommended next bounded scope: review and repair startup/cancellation cleanup
across the permission wrapper and its actual menu/controller callers; preserve
the exact log identity, process ownership, lock, metadata and deadline checks;
cover cancellation before/after state creation on both Linux architectures.
Preserve the released v3.1.81 executable. Do not merely increase the deadline,
ignore/delete orphan channels on the VPS or change pinned wrapper bytes without
reviewing affected callers. After that separately approved repair is qualified,
resume the existing commit/push, native CI and signed-candidate/live sequence.

## Source preparation and retained evidence

Fresh v3.1.81 source preparation is recorded separately under
[u82c](../../../.scratch/acceptance/u82c/): four assets were redownloaded and
checked against immutable metadata, both architecture packages passed the
repository verifier, and `verify-public-latest` accepted the exact source
identity/sequence through the real public release-attestation reader. An
initial generic per-file SLSA lookup returned 404 because that is not SBXR's
public release-attestation path; that failed command is retained and is not
counted as verification.

A fresh read-only SSH probe of the existing live host found the queried SBXR and
operator-owned paths absent, `/var/log` at root:syslog `0775`, synchronized time,
and SSH/rsyslog/snapd active. The package/timer observations were retained, not
treated as a completed package/CA/outside-client readiness review. No live VPS
mutation, certificate request or Karing action occurred.

[Run artifacts](../../../.scratch/acceptance/u82b/) include original red logs,
frozen-source comparisons, Linux controller/SSH logs and final validation.
The test binaries/records are synthetic artifacts. No live mutation, CA request
or Karing action occurred, and no successful live Acceptance Record was produced.

Both disposable guests finished with all queried product/transaction/lock/window
and log-child fixture paths absent, their original root:syslog `0775` log-parent
identities restored, SSH/rsyslog active, and empty test temporary directories.
Guest staging was removed and both VMs powered off. Their exact local QEMU
processes and loopback listeners were verified absent before removing the task
disks, seeds and keys. Disposable copied source/test binaries were removed after
recording their hashes; local temporary directories were empty and removed.
Logs, the bounded diagnostic source, source-verification material and base-image
caches remain. See the [cleanup receipt](../../../.scratch/acceptance/u82b/cleanup.json).

All changes remain uncommitted on `main`. Coordinate actual Karing attendance
again immediately before any eventual dispatch; the earlier answer was
willingness to participate, not a reserved live session.
