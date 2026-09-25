# Ordinary recurring startup-cancellation cleanup — 2026-09-25

## Scope and status

This report records the pre-CI repair qualification, not a live pass.

The Owner approved a bounded cleanup repair, then CI and an attended live
session. This follows the [mask-repair stop](ordinary-recurring-umask-repair-2026-09-25.md).
The exact released v3.1.81 executable is unchanged. No live host mutation,
certificate request, candidate dispatch, signing or publication is part of this
repair's validation. The eight-scenario policy, artifact/trust checks, observation
and scenario deadlines, lock checks, and failure/burn handling are unchanged.

## Repair and caller review

The wrapper previously created its two FIFOs before installing an EXIT/signal
cleanup trap. `MenuSession.stop` immediately killed the wrapper group, so a
startup cancellation could leave both private channels with no recovery state.
The explicit restore operation correctly refused that orphan shape.

The repaired wrapper installs cleanup before creating artifacts. Each exclusive
creation and its inode capture complete in one shell assignment before a managed
signal is handled. Pre-admission cleanup closes all opened descriptors, proves
its child group quiescent, checks the exact original log identity and each owned
channel's device/inode/metadata and open-descriptor absence, and removes only
its own artifacts. Existing, replaced, contended or uncertain paths are not
adopted. Valid state continues through the unchanged strict restore operation.

The menu driver's explicit `--protected-wrapper` opt-in sends USR1 to the
unreaped leader only. It allows bounded startup cleanup, then retains its
existing forced group termination and adopted-descendant reaping. The controlled
updater selects this opt-in for `--protected-log-parent`. At or after possible
product admission the wrapper retains its state without restoring permissions;
only after caller-owned descendant/lock cleanup may explicit restore proceed.
This avoids restoring while an escaped product child could still be alive.
Normal direct-wrapper completion/managed signals retain their existing behavior.

The provisional five-second handshake was too short on the slower amd64 VM:
one case left the second FIFO during cleanup. A separate six-second delayed
cancellation reproduced the insufficient allowance deterministically. The final
allowance is twenty seconds, matching the existing explicit-restore command
budget and allowing the wrapper's own five-second quiescence check plus metadata
and process-descriptor scans. This is failure-only safety cleanup, not extra
product, observation, submission or live-journey time. A stalled/unproved cleanup
still fails; forced death is not promised automatic restoration.

Reviewed callers include the launcher, current update controller, ordinary menu
driver, generic packaged interruption helper, direct wrapper VM qualification,
protected-log-parent systemd test, historical snapshot-recovery test, real
SSH/dpkg observer, and frozen-source mask test. Generic/direct-product callers
keep their existing termination behavior. Current pins and staging instructions
were updated together. The old v3.1.75 runbook explicitly retains its historical
wrapper identity rather than silently claiming requalification.

Wrapper SHA-256:
`56fab3f89dbed0dbb668f296a33ac8b512e8676edb5962a796a45bbc649123de`.
Supervisor SHA-256 remains:
`9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc`.

## Evidence and limits

The original FIFO leak reproduced on both Ubuntu 24.04 ARM64/HVF and
amd64/TCG. The regression stops the actual Bash wrapper at artifact boundaries
using a test-only DEBUG trap; it does not change wrapper bytes, substitute
cleanup, manufacture product results or use a guessed delay to select an update
checkpoint. The old driver/wrapper leaves both channels without state. The final
suite covers the first FIFO, both FIFOs, ready supervisor, created state and
START admission boundary under deadline/cancellation/managed TERM, plus delayed
cancellation, replacement-inode refusal and open-channel contention.

Passed with Go 1.26.6 and workspace-local temporary directories:

| Check | Result |
|---|---|
| Startup cancellation/refusal regression | 18 cases on ARM64 and amd64 |
| Actual ptrace/update controller fixture | 18 cases on ARM64 and amd64 |
| Real launcher/menu processes, escaped children, locks and restoration | Both architectures |
| Wrapper's full managed-signal/refusal qualification | ARM64; original state format and supervisor retained |
| Real systemd/exclusion/lock/TLS protected-window test | Both architectures |
| Generic menu-driver subprocess suite | 14 cases on both architectures |
| Existing packaged interruption helper | 12 cases on ARM64 |
| Real pinned-DEB/dpkg/SSH observer and protected menu/purge | amd64; all refusals, package preservation and final cleanup passed |
| Actual SSH and locked-caller preservation | 25 boundary cases plus 2 locked-account cases on ARM64 |
| Full local Go suite and vet | Passed; Linux skips are not counted as Linux proof |
| Final focused root/proxy tests, pin/syntax checks and diff review | Passed |

The observer's first invocation lacked its documented-source file in guest
staging; its fixture cleaned up, then the unchanged required document was
supplied and the complete rehearsal passed. The original staging failure is
retained, not counted as a product result.

The public source reader freshly accepted immutable v3.1.81/159 with its original
commit and index digest. This does not verify a not-yet-created target.

The pre-existing full-menu fixture's artificial 15-second success limit expired
on amd64 after the fixture had produced its correct result but before wrapper
exit. A direct comparison measured the unchanged wrapper alone at 14.96 seconds
and the repaired wrapper at 7.81 seconds on that TCG guest; this is not evidence
of a product slowdown. The full-menu cases now use the controller fixture's
30-second budget so the descendant-deadline case reaches its intended boundary.
They still require all three descendants, released locks and exact restoration;
no assertions were removed. Dedicated startup-deadline tests and the two-second
request-cap controller case retain short whole-invocation coverage. Test harness
communication allows that operation budget plus bounded safety cleanup.

These are isolated filesystem/process/systemd/SSH fixtures, not packaged live
Update/Recover proof, public CA issuance, outside proxy traffic or Karing
acceptance. The original-source reader and package preparation evidence remains
separate. Native hosted CI, fresh host/package/CA readiness, exact target trust,
concrete attended-session authorization and all eight actual live scenarios
remain gates. Publication still needs separate approval.

## Artifacts and cleanup

Original failures and final logs are retained under
[the private run directory](../../../.scratch/acceptance/u82d/). The VMs use
restricted egress, loopback-only pinned-key SSH, and verified base images. No
operational orphan-channel deletion procedure is added; fixture disposal is
limited to absent-at-entry disposable paths after process absence and exact log
restoration are proved.

Both guests finished with the queried product/transaction/lock/window/Certbot
fixtures absent, exact original log identities and 0775 mode, SSH/rsyslog active,
no test processes and empty test temporary directories. Guest staging and
local disposable disks/keys are removed only after shutdown and exact local
process/listener absence checks. See the guest and local cleanup receipts in
the run directory; verified base-image caches and diagnostic logs are retained.

The Owner chose a separate attended session, tentatively 26 September at 11:00
Hong Kong time. A one-time task check-in is arranged; it is not permission for
unattended dispatch or confirmation of a full availability window. Tonight's
follow-through is commit/push and exact-commit native CI only.
