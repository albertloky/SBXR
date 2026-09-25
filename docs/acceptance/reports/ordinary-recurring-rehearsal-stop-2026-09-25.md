# Ordinary recurring rehearsal — stopped on wrapper/update incompatibility

## Result

The Owner approved the three-step execution plan: isolated Linux rehearsal,
commit/push plus native CI, then a normally signed candidate and the eight live
checks. The Owner also confirmed availability for an attended Karing session.

**Stopped during step 1.** A targeted Linux reproduction using the unchanged
v3.1.81 Software Lifecycle source confirms that the qualified permission
wrapper's `umask 077` is incompatible with update staging. This is a pre-existing
integration defect, not a failed live release attempt. Per the implementation
guide, no separate product/operator repair was silently added.

No commit or push, new hosted CI run, candidate dispatch, signing, live VPS
mutation, certificate request, Karing operation or publication was performed.
The earlier eight-scenario policy implementation remains uncommitted and has
its [previous local validation](ordinary-recurring-implementation-2026-09-25.md).

## Evidence and limits

Fresh read-only GitHub metadata still identified immutable Latest v3.1.81/159,
source `ed759a0ccaef5d1ffd14be5a41a0e915a6268ff7`, with the expected four assets
and release-index SHA-256
`91782e8cebbb649971989883687911479798f2411e6c49055ed7f06dd277c27f`.
This was metadata inspection, not a new complete asset/attestation verification.

The isolated guest was Ubuntu 24.04 ARM64 on local QEMU/HVF, with restricted
egress and a loopback-only authenticated SSH forward. Its image matched retained
SHA-256 `7b682958a67ff5de068e36de6af8b75fa645d296af5a70d6500527f6a33781db`.
An outside TCP connection was refused; no public CA was contacted. This guest
does not satisfy the required real Ubuntu amd64 live host.

A diagnostic test was added only to a disposable `git archive` copy of the
v3.1.81 source, cross-compiled with Go 1.26.6, and executed as root in that guest.
It invokes the real lifecycle `Update` and `Recover` implementation through
existing synthetic release/runtime seams. It does **not** run the released
packaged binary, GitHub trust/transport, real subscription runtime or outside
traffic. Both the released and current `update_transaction.go` have SHA-256
`ba554454f0c0e6202ae023ee420cb313e1e57d743b1834141d6625cd3bb08c15`.

| Process mask | Update | Recover | Remaining transaction material |
|---|---|---|---|
| `022` control | `SOFTWARE-LIFECYCLE-UPDATE-INSTALLED` | `SOFTWARE-LIFECYCLE-RECOVER-NOT-REQUIRED` | None |
| `077` wrapper environment | `SOFTWARE-LIFECYCLE-UPDATE-RECOVERY-REQUIRED` | `SOFTWARE-LIFECYCLE-RECOVER-REFUSED` | Candidate executable `0700`, prior executable link `0755`, both staged Installed Records `0600` |

The `077` case retains the prior active pair but never publishes an Update
Record. The desired-success assertion fails; its failure is retained, not
relabelled as a passing update/recovery test.

The direct cause is visible in the unchanged code:

- The [permission wrapper](../../../.github/scripts/sbxr-snapshot-recovery/with-protected-log-parent.sh)
  sets `umask 077`, inherited by its product command.
- [`writeUpdateFile`](../../../internal/softwarelifecycle/update_transaction.go)
  requests `0755` when creating the staged executable but does not subsequently
  set its exact mode. With that mask, the file is `0700`.
- `prepareUpdate` requires `0755`; its pre-Prepared cleanup also requires that
  exact mode and refuses the mismatched file. Without a durable Update Record,
  public `Recover` has no proved rollback/forward authority.

This is sufficient to stop the proposed wrapper/update route. It does not show
that ordinary `022` packaged updates have passed their actual live contract.

## Interruption prototype

A prototype exercised real ptrace syscall-entry/exit observation, Go threads,
fork/exec, file locks, expected checkpoint hashes, product-child termination,
and the unchanged permission wrapper. It stops at a successful directory
`fsync` return, not an elapsed sleep or terminal progress message. It does not
write product authority or modify the source executable.

The initial wrapped synthetic case refused executable metadata under `077`.
After making the **synthetic fixture** set its intended exact file mode,
12 controller cases passed: both checkpoints directly and through the wrapper,
wrong record, missing lock, visible-but-not-directory-synced records, menu
refusal/prompt mismatch, deadline and cancellation. The fixture correction is
not a fix to SBXR, and those passes do not resolve the released-source failure.
The targeted unchanged-source reproduction above was therefore required.

The prototype is **not adopted or qualified for live use**. Its new files and
menu-driver argv experiment were preserved as
[unadopted local drafts](../../../.scratch/archives/u82a/local-drafts/), and the
tracked menu driver was restored exactly. Incremental recorder real-SSH replay,
final controller review and actual packaged Update/Recover proof remain undone.

## Cleanup and next decision

The fixture's product, staged executable/record, lock, log-child and wrapper
paths were removed. `/var/log` returned to the original root:syslog `0775`
identity; SSH and rsyslog were active; temporary test directories were empty.
Guest staging was removed and the VM powered off. The local VM process and
forward were checked absent before deleting its disposable disk and keys.

[Reproduction log](../../../.scratch/acceptance/u82a/released-umask.log),
[diagnostic test](../../../.scratch/acceptance/u82a/u82_umask_reproduction_test.go),
[prototype logs and cleanup](../../../.scratch/acceptance/u82a/).

Recommended next scope: separately review and qualify an operator invocation
that preserves the existing permission-window safeguards while giving the
**unchanged v3.1.81 executable** an appropriate creation mask, and assess exact
mode handling for the next updater. Changing only the next binary cannot repair
the already released source's staging behavior. Do not edit protected authority,
use a helper updater, relax metadata checks or call reinstall an upgrade.
No particular workaround is authorized or proven by this report.

After that bounded repair passes its actual Linux integration checks, resume
the approved CI/signing/live sequence. Coordinate Karing immediately before
dispatch; today's availability confirmation is not a reserved six-hour session.
