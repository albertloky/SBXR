# Scheduling investigation and shared menu deadlines — 2026-09-26

## Scope

The Owner requested investigation of the missing snap schedule without candidate
dispatch or stable publication. He then asked for a combined bug/integration
review rather than another attendance negotiation, confirming availability only
through 18:00 HKT today. No longer/future session is confirmed or scheduled.
Work is on `main`, based on `484c65065901e055198e3e4b6f1b74665cbb264d`.

## Snap scheduling: recovered without intervention

The preceding x26 inspection saw `next: n/a` through 07:22:35 UTC. Fresh read-only
inspection at 07:28:35 UTC found the next refresh at **17:25 UTC** (01:25 HKT on
September 27), with the ordinary Certbot timer at 14:18 UTC. CLI and the local
snapd system-info API agreed. The daemon was still PID 580, with its original
07:14:39 UTC startup and zero restarts. The journal records a 07:19:42 automatic
check finding no updates; snap changes and refresh candidates were empty.
Refresh configuration remained empty/default. No store-offline setting was set.

The version-matched upstream implementation explains why a temporary unknown
time is possible: [snapd 2.76.3 automatic refresh](https://github.com/canonical/snapd/blob/2.76.3/overlord/snapstate/autorefresh.go#L282-L395)
keeps its next time in memory, clears it after an ordinary refresh attempt,
and recomputes it on a later scheduler pass. The
[daemon loop](https://github.com/canonical/snapd/blob/2.76.3/overlord/overlord.go#L67-L69)
uses a five-minute default interval. The
[CLI](https://github.com/canonical/snapd/blob/2.76.3/cmd/snap/cmd_snap_op.go#L1007-L1035)
renders a missing/zero next time as `n/a`.

The retained sequence is consistent with startup/check/recalculation settling,
not evidence of a stuck daemon. The exact internal transition time was not
traced; no restart was induced to reproduce it. The earlier bounded poll ended
less than three minutes after the automatic check, before a full default loop
interval had elapsed. Its refusal was safe, but was not a confirmed host defect.

The final read-only host snapshot preserved the preceding snap version/revision/
size/digest and metadata, log parent/children, Certbot directories, absent owned
footprint, unheld locks and idle relevant processes. These are point-in-time
observations, not a future refresh reservation or complete dispatch readiness.
No host setting, service, timer, package, certificate or client was changed.

## Confirmed shared-driver defect

The existing prompt-specific fix checked time in `expect_prompt`, but other
`LineStream` consumers could accept a complete buffered line after expiry.
There was also no deadline check in `MenuSession.write`, allowing a confirmation
after a timely prompt if execution crossed the deadline before replying.
A transcript flush could similarly finish late and return a usable prompt.

Four focused tests reproduce six failures against the original driver: expired
launch, buffered result consumption, delayed transcript flush, and late input
for Update, Recover and Complete removal. Pipe reads/writes and child processes
are real; the transcript test advances only the clock at its flush boundary.
These are reproduced test defects, not claims of observed late live actions.

The shared session now checks the unchanged deadline before launch/input and
before consuming buffered output and after transcript output. The local
`expect_prompt` check is replaced by this shared enforcement, covering all
consumers. Cancellation, exact prompts/review/result codes and failure cleanup
remain intact. No product code, signed source executable, timeout, evidence
policy or release gate is changed.

## Combined execution-path review and validation

Review covered declaration/source-reader compatibility, transport handoff,
staged-file inventory, package/window observer, ordinary menu actions,
interruption controller, both public Recover directions, observation/collector
handoff and cleanup. Current tracked source was used, not copied historical
operator programs. The legacy shared-menu caller was checked for compatibility,
not executed as a new live procedure.

The completed checks are:

- Full local Go suite and vet passed. A final uncached focused root-package
  run passed after the last test edit, including menu, observer, recorder,
  evidence assembly and wrapper-pin contracts.
- All 22 driver tests passed on root Linux, including the four new methods,
  actual subprocess confirmation inputs and escaped-descendant cleanup. The
  portable run passed too, with its two Linux-only cases explicitly skipped.
- All 17 package/window observer and 11 recovery-observer tests passed on root
  Linux. Real launcher/wrapper success, refusal, deadline, cancellation,
  restoration and startup-cleanup tests passed, as did all 18 real-syscall
  interruption-controller cases.
- The combined root-amd64 Ubuntu 24.04 rehearsal passed precommit interruption
  and public rollback, then **ordinary public Update from that restored source**,
  followed by postcommit interruption and public forward recovery. The fixture
  verified exact selected executable/Installed Record bytes, unchanged ownership,
  runtime completion where applicable, no transaction residue, normal Running
  observations and full package/fixture cleanup with unrelated packages preserved.

The combined rehearsal uses actual terminal/lifecycle code, SSH, ptrace/fsync,
wrapper and package hold/purge, but synthetic release/proxy/snap seams. The
frozen source diagnostic binary and current diagnostic binary were reused only
after confirming their fixture/product source had not changed. They are not
original packaged-source execution, trusted target delivery, outside traffic,
real TLS, Karing or live qualification.

One earlier combined run correctly refused `active-writer-pid` because the
operator mistakenly ran a separate driver test concurrently in the same VM.
Its failed output is retained in `combined-first-interference.log`; independent
cleanup checks passed. The tests were then run sequentially with the same
observer and driver, and the complete combined rehearsal passed. No refusal
was suppressed, timeout lengthened or product fix invented for that test
orchestration error. The script guide now explicitly calls for serial execution
of these shared-host fixtures.

## Evidence and remaining limits

Private artifacts are retained in [s26](../../../.scratch/acceptance/s26/),
including original red-test output, corrected tests, host observations and
isolated Linux logs. Prior x26/w26 evidence remains unchanged. All staged Python
and shell scripts matched the exact checkout. Diagnostic artifacts were archived
and checksummed; independent fixture cleanup passed. The guest shut down normally,
its exact QEMU process and loopback listener were proved absent, and its task-owned
disk, seed and ephemeral keys were disposed. The verified base image is unchanged.

At the end of this repair validation, the changes were local and uncommitted;
no push or new hosted CI is claimed by this report. Subsequent commit/push and
hosted-CI follow-through must identify its exact commit. The previous native
CI receipt covers the base commit, not this changed driver.

No candidate was dispatched, release identity allocated or stable published.
The proposed v3.1.83/161 is not an attempt. No new attendance commitment,
reminder or automation was created. Future actual live work still needs fresh
prerequisites and concrete dispatch authorization; this report adds no gates
or claim that the software is bug-free.
