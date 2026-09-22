# MVP SSH fixture readiness repair — 2026-09-22

## Outcome

**The separate local SSH readiness failure is diagnosed, repaired and
regression-tested.** The temporary SSH server inherited the cloud image's locked
root shadow record while using `UsePAM no`. Its own diagnostic was:

```text
User root not allowed because account is locked
```

The fixture now binds a synthetic, non-expired, password-disabled root shadow
record read-only inside its existing private mount namespace. It does not
unlock the host account, copy real password records, enable password login or
change the system SSH server. All **21 real-SSH boundary cases** pass. A new
regression additionally proves those cases under a deliberately locked caller
account and checks preservation after an intentional post-readiness failure.

This closes the SSH replay gap recorded by the
[deadline investigation](mvp-driver-deadline-investigation-2026-09-22.md).
The preceding [observer repair](mvp-operator-observer-repair-2026-09-22.md)
and deadline results remain evidence for their unchanged paths; they were not
rerun or relabelled here. These are local regression results, **not live MVP
qualification**.

Work stayed on `main` at base
`477a0d7a32da683b0a0b00551696e363cfbc4e6c`. No commit, push, candidate dispatch,
VPS contact, CA request, real proxy installation or Karing action occurred.

## Reproduction and causal evidence

Artifacts are under [`.scratch/acceptance/s22/`](../../.scratch/acceptance/s22/).
A fresh disposable Ubuntu 24.04 ARM64 VM used the retained, checksum-verified,
read-only public cloud image, hardware acceleration (HVF), two CPUs, 2 GiB RAM,
restricted egress and pinned-key loopback SSH. Guest Python was 3.12.3 and
OpenSSH was `9.6p1 Ubuntu-3ubuntu13.19`. The normal guest SSH service worked;
`passwd -S root` reported `L` before and after the work.

1. The unchanged source reproduced exactly
   `SSH_BOUNDARY_REFUSED case=sshd-ready`, before any of its 21 cases. Capturing
   the temporary server's existing `ERROR` log before normal fixture cleanup
   yielded no further diagnostic.
2. A diagnostic-only change to the disposable guest copy raised that server's
   log level to `VERBOSE`. It showed a listening server followed by explicit
   locked-account refusals. No authentication setting, retry count, deadline or
   account data changed in this probe. The source-owned fixture retains its
   original `ERROR` log level.
3. Before applying the fix, the new regression forced a synthetic `root:!:`
   record in a separate caller mount/PID namespace and ran the actual fixture.
   Both cases failed at the same `sshd-ready` refusal, rather than reaching
   their expected success or post-readiness failure. See `account-red.log`.
4. Only the fixture's account preparation changed. With the same SSH settings,
   the existing 21-case suite and both locked-caller cases passed.

The prior successful SSH run remains historical evidence for its named
environment; its removed VM account state was not reconstructed or assumed.

## Focused change and regression boundary

- [`test_ssh_boundary.py`](../../.github/scripts/test_ssh_boundary.py): seven
  lines create a mode-0600 synthetic `root:*:20000:0:99999:7:::` record and bind
  it read-only onto `/etc/shadow` after mount propagation is made private. The
  existing namespace lifetime and temporary-directory cleanup remove it.
  Root's home/key isolation, strict pinned host-key checking, `UsePAM no`,
  disabled password/keyboard-interactive authentication and deadlines stay
  unchanged. No installed-product or operator-helper source changes.
- [`test_ssh_boundary_account.py`](../../.github/scripts/test_ssh_boundary_account.py):
  runs the real fixture beneath a deliberately locked caller account. The
  success case requires exactly `SSH_BOUNDARY_CASES_PASSED count=21`. The
  failure case omits the copied documentation example and requires exactly
  `candidate-handoff-example`, which can only be reached after actual SSH
  readiness. Both cases verify the caller's locked shadow record survives, and
  compare the real host shadow contents and device/inode/mode/owner/group/link
  count/modification time without printing password records. Cleanup checks
  remain registered even if an assertion fails.
- [`v3_ssh_boundary_test.go`](../../v3_ssh_boundary_test.go): includes both
  fixtures as Linux/root subtests, rejects skipped Python cases and retains
  the existing two-minute subprocess budget for each invocation. No existing
  readiness, driver or namespace timeout was lengthened.

The regression uses real OpenSSH and nested mount/PID namespaces, not a mock
authentication result. The original fixture also verifies that its PID
namespace has no surviving process before returning. Each validation phase
used a fresh workspace-local `TMPDIR`; its final `rmdir` succeeded on both red
and green runs.

## Checks and limits

| Check | Result |
|---|---|
| Original fixture, unchanged | Reproduced `sshd-ready`; no cases reached. |
| Diagnostic guest copy, verbose SSH log only | Same refusal; explicit locked-account cause recorded in `readiness-verbose.log`. |
| New locked-account regression before fix | Both tests failed at `sshd-ready` in 20.724 s. Host-preservation cleanup assertions passed. |
| Linux ARM64 root Go integration, built with Go 1.26.6 | `TestV3RealSSHBoundaries/boundaries` passed in 8.69 s; `locked-account` passed in 9.00 s. See `account-green-go.log`. |
| Final source-owned account regression, direct Linux invocation | Both tests passed in 8.622 s; includes all 21 transport cases and the intentional refusal/cleanup case. Exact source hashes are in `account-final.log`. |
| Native macOS root-package checks | `GOTOOLCHAIN=go1.26.6 go test . -count=1` passed in 50.260 s; `go vet .`, Python syntax parsing and `git diff --check` passed. Linux/root-only tests skip on macOS; the separate VM run is their evidence. |

The Go integration was cross-compiled on the Mac with `GOOS=linux`,
`GOARCH=arm64`, `CGO_ENABLED=0`, then actually executed as root in the VM.
This was not a compile-only Linux check. The whole Go repository was not rerun
on Linux, and the changed fixture was not replayed on amd64 in this task.
Earlier valid checks for unchanged code are reused rather than claimed as new
runs. No live host or release acceptance claim follows from these results.

Final changed test-source hashes:

```text
dbca7e6a3301953675d0287efa3b554613f49231c37a1d7f440db6c94eabe9f3  test_ssh_boundary.py
256951659aa50bb462a0690a33a60365e4a48594e01c4e7ce11b0ccee15aca79  test_ssh_boundary_account.py
47fd9ff43dc117cc517bf774a3ba76b8f748ae9796eacd1abd10f2dad00fd12c  v3_ssh_boundary_test.go
```

## Preservation and cleanup

The independent final guest audit found no fixture process, temporary directory,
synthetic installed executable/record or qualification directory. Root remained
locked, SSH and rsyslog were active, and `/var/log` retained the prepared 0775
mode. Exact shadow preservation is proved by the regression's before/after
comparisons, not inferred from the account-status display alone.

At `2026-09-22T04:27:28Z`, the QEMU process and loopback listener were absent;
the configured disk, seed, ephemeral client/host keys and compiled test fixture
had been removed. Only useful diagnostics/source snapshots and the unchanged
public read-only base image remain. `cleanup.json` records the final checks and
the harmless cleanup correction for QEMU removing its own PID file. The guest
audit invocation was also corrected to stream its code over stdin, avoiding a
false self-match in process argv; that observation is retained separately.

The retained debug capture is explicitly under `debug/`; no debug hook or
verbose logging remains in repository test source. The 27 preexisting modified
or untracked files not intentionally extended are byte-identical, including
the pending observer implementation and historical reports. Only the script
README, code map and current operator plan were extended for navigation and
current local status. Nothing was staged or committed.
