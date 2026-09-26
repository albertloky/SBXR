# Recovery-window and menu-review repairs — 2026-09-26

## Scope and present result

The Owner first approved a narrowly scoped recovery-aware precheck and isolated
rehearsal. When it exposed a separate menu-driver defect, work stopped and the
Owner separately approved the bounded Update/Recover confirmation repair and
resumed isolated rehearsal. Neither approval authorizes another live attempt
or stable publication. These local results were established on `main`, based
on `316ddfa43535273f4793ca99a5f3a3fcc4963e46`, before the separately authorized
commit/push and hosted-CI follow-through.

Both repairs are implemented. The root-Linux regressions and full isolated
interruption → observer → public Recover rehearsal pass for Prepared rollback
and Committed forward recovery. These are diagnostic fixtures, **not packaged
upgrade proof or live qualification**. Expected protocol-failure and both
injected-checkpoint failure cleanups also pass.

## Original stop and bounded repair

The preceding attended attempt, run
[36222805759](https://github.com/albertloky/SBXR/actions/runs/36222805759), passed
native builds and independent release/signature checks. Before its live gate,
review found that the mandatory Running observer requires a one-link executable
but the planned durable Prepared checkpoint deliberately retains two links to
the unchanged source executable. The live gate was rejected. Normal workflow
cleanup burned v3.1.82/160 as an immutable failed prerelease; stable was not
published. No product install, certificate request or Karing import started.
The five staged operator files were removed and the VPS cleanup verified.
[Session evidence](../../../.scratch/acceptance/l26/session-result.md) separates
that stop from this repair.

`mvp-inspect-window.py` now has two explicit recovery phases:

- `recovery-precommit`: exact schema-2 Prepared authority, independently bound
  source/candidate executables and Installed Records, unchanged schema-2
  Ownership Record, and the active/prior executable on the **same device/inode
  with exactly two links**, root:root `0755`.
- `recovery-postcommit`: exact Committed authority, distinct one-link active
  candidate/prior executable, and consumed candidate slots absent.

Every private record remains root-owned, one-link `0600`, without symlinks or
xattrs. Bound reads check descriptor/path identity before and after reading;
request, schema, digest, route, metadata or staging drift refuses. Independent
expectations are the same five reviewed hashes used by the controller, never
values learned from transaction staging. The current request must match the
verified signed manifest digest, source tag, named scenario and unchanged
30-minute deadline, including the proposed window duration.

The ordinary package/snap, log-parent/child, timer, idle-writer and released-lock
checks still run. The default protected-file rule remains one link; normal
Running now refuses update transaction residue rather than admitting a partial
state. The documented SSH handoff selects a recovery phase only before the
separate public Recover window and returns to Running after successful recovery.
No installed product or released v3.1.81 bytes were changed.

## Validation completed and limits

- Eleven recovery-observer test methods passed on an isolated root amd64 Ubuntu
  24.04 guest, including real hard-link relationships, permissions, owners/groups,
  xattrs, symlink/FIFO refusal, changed bytes, schema/duplicate members, request
  binding/deadlines and read/path races. The otherwise unchanged default guard
  still refuses the Prepared two-link file. These are constructed checkpoint
  fixtures, not an observed live interruption.
- All seventeen existing observer methods passed on root Linux, including real
  snap-cache hard links and their refusal boundaries. The streamed SSH/dpkg
  integration passed its existing package, timer, lock, writer, metadata,
  changed-receipt and empty-stdin refusal checks before reaching the new path.
- All eighteen menu-driver methods passed on root Linux, including actual
  subprocess confirmation inputs, wrong/missing/duplicate review codes,
  mismatched prompts, deadlines and descendant cleanup. New tests fail with
  the original driver and pass with the repair. The controller's eighteen real
  Linux syscall/wrapper success, refusal, cancellation and deadline cases also
  passed with the corrected review-before-prompt fixture.
- The final local Go suite and vet passed after the driver repair. macOS-skipped
  Linux cases are not counted as Linux proof. Final root-Linux checks reran both
  observer suites against the final code; no earlier cached-request variant is
  substituted for that check. No hosted/native CI run is claimed.
- Both diagnostic Go fixtures built with Go 1.26.6. One uses the unmodified
  v3.1.81 source tree (`ed759a0ccaef5d1ffd14be5a41a0e915a6268ff7`), with only
  the new test fixture copied into its disposable archive; the other uses the
  current tree. They call the real terminal and public lifecycle Interface but
  supply synthetic release, proxy admission/runtime and snap seams. They are
  **not** the original packaged source, a trusted candidate, real subscription
  runtime, network trust, outside traffic or live qualification.

The combined rehearsal uses the actual streamed documented commands, loopback
pinned-key SSH, real pinned DEB/dpkg hold/purge, systemd timer, controller,
permission wrapper and public terminal code. The repaired stack observed both
successful directory `fsync` returns, admitted only their exact bound checkpoint,
and completed separate public Recover invocations. Prepared restored the exact
prior executable/Installed Record; Committed retained the exact candidate pair
and completed the synthetic runtime callback under the real mutation lock.
Ownership stayed unchanged, transaction slots disappeared, normal Running
observations passed again, and permission windows restored their old metadata.
Wrong request scenarios, held locks and active controllers refused before Recover.

At the actual Prepared checkpoint, streaming the **original** observer reproduced
`unsafe-file:/usr/local/bin/sbxr`. The repaired ordinary Running observer also
refused the transaction; only the explicit, independently bound recovery phase
admitted it. This is a red/green demonstration at the changed integration
boundary, not merely a constructed hard-link test. No timeout or refusal check
was weakened to continue.

## Separately approved menu-driver repair

The actual released terminal's Update review prints:

```text
Code: SOFTWARE-LIFECYCLE-CHECK-UPDATE-AVAILABLE
```

before `Update SBXR? [y/N]`. The original `MenuSession.expect_prompt` rejected any
`Code: ` line before a confirmation as `action-refused`. The unchanged
controller calls that method, so it exits with `ProtocolError` on the normal
review. Recover similarly emits its reviewed lifecycle status before its
prompt; the ordinary menu-driver caller must be considered in the same repair.
The former synthetic syscall fixture jumped directly to a prompt and did not
cover this real terminal sequence.

The original stdout, error and retained transcript are preserved under
[w26](../../../.scratch/acceptance/w26/). Only after separate Owner approval, the
shared helper gained an optional exact review code. Both the ordinary action
caller and interruption controller supply it for Update/Recover. It requires
one expected code before the exact prompt; missing, wrong, duplicate or refusal
codes fail without `y`. Other confirmations still reject every result code.
Final action-result matching is unchanged; the prompt loop also checks the
existing deadline before consuming already-buffered lines.

The original driver/controller pair was replayed through the same real source
terminal on the second VM. It failed before confirmation exactly as before,
while the corrected test cleanup successfully restored the retained wrapper
state and removed fixture resources. This expected regression is retained in
`driver-original-cleanup.log`; it is not counted as an accepted Update.

## Fixture cleanup and operational limits

The first new fixture's failure cleanup asserted that no wrapper state could
remain. A protocol failure legitimately retains valid state after descendant
termination. Its outer cleanup then removed other fixture resources, preventing
an exact restoration of that guest's old log-parent link count. This is a
**test-harness cleanup defect**, not damage to the RackNerd VPS or a bypass route.

The corrected fixture cleanup retains original output and remaining transaction
bytes first, checks dead processes and released locks, and uses the existing
explicit wrapper restore before fixture disposal. The parent fixture preserves
its staged helpers, product and log child if wrapper state or channels remain.
Replaying the original
protocol failure now proves that retained-state cleanup works. The successful
combined rehearsal also proved full fixture cleanup and unrelated-package
preservation. Separate injected failures after Prepared and Committed recovery
observations each reached their intended assertion, preserved the transaction
material, and completed cleanup. Independent checks after each run proved the
fixture's product, staging, controller, package, temporary paths and processes
absent with the log-parent back at `0775`. These expected assertions are cleanup
tests, not successful journeys; no recovery success is inferred from disposal.

For the first failed guest, original state/transcript/metadata were archived,
no test process remained, and the VM was shut down without forced chmod or
invented authority. Its exact QEMU process and loopback listener were proved
absent before disposing its task disk, seed and ephemeral keys. This is isolated
VM disposal, **not** a successful permission-restoration observation. The
verified base image and diagnostic logs are retained. The second VM's completed
rehearsal and failure artifacts were collected and checksum-verified; all tested
guest script/fixture sources match the final local implementation. Its QEMU
process and loopback listener were proved absent after guest shutdown, then its
disk, seed and ephemeral keys were disposed. QEMU removed its own PID file;
the local disposal script's redundant existence assertion was recorded and the
remaining seed cleanup completed after another absence check. Both disposal
records are retained. The disposable frozen source copy and empty local
temporary directory were also removed. No live VPS mutation,
CA request, Karing action, commit/push, hosted CI or publication occurred during
this repair. Native CI, all fresh live prerequisites and a new attended attempt
remain separate gates; a successful local rehearsal does not authorize dispatch.

## Evidence locations

Private artifacts are under [w26](../../../.scratch/acceptance/w26/):

- `driver-before.log`, `driver-after.log`, `final-root-contracts.log` — portable
  red/green and final root-Linux observer/menu tests.
- `rehearsal-first.log`, `first-failure-retained-host.tar`,
  `first-vm-shutdown.json` — original discovery and first-guest disposal.
- `driver-original-cleanup.log`, `driver-original-cleanup-proof.log` — expected
  original protocol failure with corrected cleanup.
- `rehearsal-second.log` — complete two-direction real-boundary rehearsal,
  original observer refusal, normal Running rechecks and package preservation.
- `final-controller-linux.log` — all eighteen syscall-controller cases.
- `injected-{precommit,postcommit}-cleanup.log` and matching `-proof.log` —
  expected checkpoint assertions and independent cleanup checks.
- `final-go-test.log`, `final-go-vet.log`, `tested-source-identities.json` —
  final local suite/vet and exact tested script/fixture identities.
- `second-rehearsal-artifacts.tar.gz`, `second-artifact-sha256.txt` — retained
  transcripts, bound inputs and expected-failure transaction material.
- `second-vm-shutdown.json`, `local-disposal.json` — final guest process/listener
  absence and task-owned disk/key/source/temp disposal.

The source/candidate diagnostic binaries, their identities and verified image
digest remain recorded. Ephemeral VM disks/keys are disposable, not release
evidence. No secret, synthetic fixture result or private transcript belongs in
a public Acceptance Record.
