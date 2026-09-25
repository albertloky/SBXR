# Certificate-state and ordinary-start repairs — 2026-09-19

Implemented on `main`, based on `cf2e89aae5cfa56ae316505d24f16d50b8a25069`.
The initial local-only phase below is repair validation, not release acceptance.
During that phase the VPS was not contacted or changed, no CA certificate was
requested, and no candidate or release workflow was dispatched. The later
Owner-authorized continuation is recorded in the next section. The current [MVP procedure](../mvp-live-acceptance.md)
and its five journeys are unchanged. Existing untracked reports were preserved.
The follow-up handoff work is recorded below and in
[the exact VPS runbook](../v3.1.75-snapshot-recovery-runbook.md).

[Run artifacts](../../../.scratch/acceptance/c19/) contain the before/after logs,
source overlays used to reproduce the original defects, VM observations, and
the final diff and file identities. Synthetic certificates were generated
locally for tests; they were not issued by a public CA.

## Authorized continuation — repair and maintenance complete, MVP waiting

The Owner subsequently authorized continued repairs, subagent coordination,
VPS acceptance and cleanup, commits and push. The Owner chose to finish
preparation and wait for fresh CA capacity rather than use another host.
[Continuation artifacts](../../../.scratch/acceptance/r20/) retain diagnostics,
read-only VPS observations and Linux/systemd results. No new candidate has been
dispatched and no CA issuance has been performed in this continuation.

The formerly unclassified repeated helper refusal is now reproduced as HTTP 429
from the original verified subscription server, with `Retry-After: 10`. The
failure occurs in loaded-response verification in about 400 ms, with unchanged
identities, renewal evidence and service fingerprints. Diagnostic overlays
printed status/timing only. This establishes the cause of the reproduced
post-publication refusal; the older uncategorized log cannot independently prove
its own response code. The original limit is six requests per source, refilling
one per ten seconds. A helper `check` consumes one and a successful `apply` three.
The exact rehearsal now budgets requests before each success sequence; it does
not retry failed assertions or change production admission or deadlines.
The active-serving driver retains its original ten-minute work allowance plus
exactly 210 seconds for three 60-second refills and one 30-second refill. The
earlier ten-minute driver reached its context deadline during the final planned
refill, after all helper cases had passed but before the menu checks; that
[incomplete run](../../../.scratch/acceptance/r20/active-budget-failure.log) is
retained as a failure. Helper and individual subprocess deadlines are unchanged.

A further startup ordering bug was reproduced with real systemd: an ordinary
ExecCondition can begin waiting before the Owner's authenticated handoff socket
exists. A one-shot handoff attempt misses that later socket. The wait loop now
retries the same authenticated, role-bound, one-use handoff within its existing
bound. The one-shot negative overlay failed the Linux/systemd regression in
26.08 seconds; the corrected code passed in 27.19 seconds, including three
simultaneous restarts and trusted local TLS. Focused host/race checks also passed.

A test-fixture race in renewal cancellation published its readiness filename
before completing its bytes. Atomic staged publication removed that race:
83/400 stress failures before, 0/400 afterward. Product renewal behavior,
assertions, cancellation and timeouts are unchanged.

Fresh read-only VPS observations reverified the four pinned executable/record/
source-snapshot hashes, but found a new service shape after reboot. The volatile
whole-host lock is absent; the original proxy is active, serving failed with
status 1, the managed recorder failed with status 125 before issuance, and the
timer/firewall remain active. The explicit post-reboot helper mode passed its
full executable rehearsal. It preserves normal trust and exclusion checks, creates only the
protected missing runtime lock when applying that plan, and requires published
accepted TLS plus serving quiescence. It does not claim loaded TLS.

The same read-only preflight found `/var/log` reverted to root:syslog 0775.
Existing protected-parent checks correctly refuse it. The earlier host-specific
0755 prerequisite is documented in [the September 2 report](v3.1.0-live-acceptance-2026-09-02.md).
The exact maintenance window uses a protected restoration record, a bounded
private command group and temporary 0755 permissions, then restores the same
directory to 0775. The final wrapper and supervisor passed the complete
[root Linux qualification](../../../.scratch/acceptance/r20/log-parent-wrapper/final/qualification.log),
including stdin, nonzero status, timeout, delayed descendants, leak escalation,
SIGKILL/live-group refusal, explicit recovery, channel contention, partial
cleanup, unsafe state, changed boot/PID identity and three cancellation-before-
admission cases. The original directory identity and mode were restored.
No product trust exception or persistent tmpfiles override is introduced.

The qualified wrapper SHA256 is
`4358cb1ec189bd33518a081702355405e9110892cf2be7e8235671005e2959eb`,
supervisor SHA256 is
`9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc`,
and final qualification source SHA256 is
`f67c298e3bf3d0162c99b3f988d0d6874572f9fc64014cb165edf054908f134f`.
Independent review caught and corrected queued cancellation/START ordering and
controller acknowledgement races. Test readiness now uses atomic publication;
its earlier empty-PGID observation failure and pre-final logs remain separately
labelled. No failed run is attributed to the qualified final source.

A targeted systemd observation confirmed that stopping a failed unit retains
its failure state. Final cleanup therefore distinguishes removed files and
quiescent processes from the remembered failure. After successful original-menu
removal, the handoff admits only the exact deleted subscription unit's known
exit-1 failure, clears it with a named `reset-failed`, and requires the unloaded
inactive state. It never resets the shared Certbot unit. The full helper
rehearsal captured that exact post-removal tuple before clearing it; this does
not change the product or the MVP procedure.

The final helper SHA256
`f1d8beeb915c7c5fd7525f7641d15749cc2ee5ba5e94504c90d85060ceb237e4`
passed the complete
[post-reboot executable handoff](../../../.scratch/acceptance/r20/post-reboot-final.log)
in 444.56 seconds. The exact original executable first refused removal for the
mismatch. The actual helper then passed changed-input/unsafe-file refusal,
all six real lock-contention cases, interruption after runtime-lock creation,
before/after the actual rename, and repeated forward completion. Normal
publication with initially absent Certbot locks removed only its own lock
inodes; killed publication left exactly the safe inodes preserved on retry.
Executable, record, configuration, credential, certificate and service
identities were preserved across correction. The original menu allowed decline
without changes, then confirmed Complete removal and the Not installed result.
The exact wrapper restored the log directory and removed its recovery state.

The same final helper passed the complete
[active-serving executable handoff](../../../.scratch/acceptance/r20/active-final.log)
in 648.16 seconds. It exercised the original accepted-generation-2 / snapshot-
generation-1 state with loaded TLS, all changed-input, unsafe-file and real-lock
refusals, interruptions around publication, idempotent completion, preservation
of original identities and service state, and successful Complete removal through
the original verified executable. Both final passes use helper hash
`f1d8beeb915c7c5fd7525f7641d15749cc2ee5ba5e94504c90d85060ceb237e4`;
neither substitutes a source build for the original v3.1.75 menu executable.

The executable fixture's untrusted-CA case removes the common local CA used by
both certificate validation and the local public-IP discovery endpoint. It
proves fail-closed behavior but does not isolate which trust check refuses
first. `TestCertificateStatePublicationRefusesUnknownOrUntrustedMaterial`
separately covers target trust at the source/real-filesystem boundary. No
executable rehearsal uses the VPS's real private certificate material.

New clean setups now own `sbxr-mutation-lock.service`, which provisions only the
canonical safe volatile lock before ordinary service startup. Its private role
checks the Ready Installed Record before creation and the same identity while
holding the lock. Ordinary proxy, serving and recorder roles remain existing
only. Optional canonical ownership authority preserves legacy record bytes and
removal; setup, update capability admission, cleanup and packaged footprint
checks cover the new unit and enablement link. Focused checks and independent
caller review passed. The [exact systemd/reboot rehearsal](../../../.scratch/acceptance/r20/boot-provisioning/vm-results/vm-validation-summary.txt)
also passed: ordinary roles refused a missing lock, the new unit created only
the canonical safe lock, repeated starts preserved it, real contention and an
unsafe 0640 inode refused, and an actual reboot produced a new boot identity
with the unit active and the safe lock present. Executable and Installed Record
identities stayed unchanged. Fixture cleanup restored absent owned paths and
unit, original log-parent mode, and active SSH/rsyslog. This uses a stamped local
product build and Installed Record; it validates the provisioning/boot boundary,
not a full installed proxy and subscription journey after reboot.

The fresh read-only maintenance preflight caught an incorrect runbook pin for
renewal evidence before any VPS mutation. That draft pin came from the local
VM fixture. The VPS's actual SHA256
`e7973e94a7090482f378c9a23e6017ec77cb434da9c5e321f1953d1ab1360389`
matches the retained September 18 host inventory, with the same 128-byte size,
modification time and empty attempt list. The runbook pin was corrected from
that host evidence; the failed preflight and diagnostic summary are retained.
No product check or host file was changed to accommodate the error.

The bootstrap's interrupted-removal reader previously refused stable records
containing `proxy_startup`. It now admits the canonical Startup authority,
resources and provenance, including coexistence with the new lock authority.
The original parser failed the retained negative fixture; all stable variants
and malformed-authority/count refusals pass. Active Client Identity rotation
remains a preexisting bootstrap limitation; this repair does not extend it.

`GOTOOLCHAIN=go1.26.6 go test ./... -count=1` and `go vet ./...` pass in this
continuation. The bootstrap package also passed independently in 194.866 seconds.
A later test-only correction makes the provenance negative remove one complete
creator identity; the affected final variants passed in 12.69 seconds. The first
release-build refusal under local Go 1.27.1 was the expected pinned-toolchain
check, confirmed before compilation; it was resolved by using the required
1.26.6 toolchain. Tagged Linux amd64 helper build/vet and Python syntax pass.

The CA evidence currently supports fewer than the two operations required for
the unchanged MVP procedure. The conservative fresh recheck is
`2026-09-21T03:38:39Z` (11:38:39 a.m. Hong Kong). This is a recheck time, not a
reservation or proof of future capacity. Live acceptance remains unproved.
The final exact helper, wrapper and boot rehearsals are complete. Independent
review cleared the repair/handoff files and affected callers. The additional
listener-comparison regression below brings the completed commit scope to 49
files. The current MVP procedure's bytes are unchanged, and 17 unrelated
untracked historical/research documents remain outside the commit scope.
A quiet follow-up is scheduled for September 21 at 11:39 a.m. Hong Kong time;
it must recheck capacity and host state before any further acceptance action.
The historical blocked result below is preserved as evidence.

### Executed VPS maintenance

The corrected seven-block fresh read-only preflight passed before transfer or
host mutation. The exact helper, plan, permission wrapper and supervisor then
passed their on-host hash checks. Initial `check` refused the missing volatile
lock without creating it. A root-only backup and private preservation manifests
were captured before the bounded permission window.

The actual final helper completed the state-only correction and checked the
exact target hash. Staging was empty. Executable, Installed/Ownership Records,
credential, configuration and both certificate generations retained their
hashes and file identities. Exact service states, PIDs and monotonic start
identities were unchanged. No certificate was requested, service restarted,
record rewritten or executable replaced during correction.

The original verified v3.1.75 menu displayed **Complete removal**. Its actual
owned-resource plan was reviewed, then confirmed with `REMOVE SBXR`. It reported
`SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED` and `SBXR is not installed.`
The subsequent checks proved owned files, package, account/group, hooks, units,
rules and listeners absent. The deleted subscription unit retained only the
expected exit-1 failure memory; the rehearsed named `reset-failed` cleared it.
The shared Certbot service's historical failure state was not reset.

The first final listener comparison refused PID 1's inherited SSH descriptor
numbers changing from 181/182 to 168/169 across removal's systemd daemon-reload.
It closed the permission window and retained the backup. Read-only inspection
proved the same SSH PID/start identity, endpoints, queues, SSH descriptors and
DNS listeners; every other preservation comparison had passed. This was an
overly strict runbook assertion. The corrected comparison permits only that
PID-1 descriptor renumbering on preserved port-22 rows after an identical SSH
service fingerprint. The adjacent
[runbook regression](../../../.github/scripts/sbxr-snapshot-recovery/test_runbook.py)
executes the real documented Python program: the original predicate fails the
captured case, the corrected predicate passes, and changed processes, endpoints,
queues, SSH descriptors, non-SSH descriptors, unit fingerprints, and extra or
missing listeners refuse. Independent review and the actual retained VPS
comparison both passed; fresh SSH, timer and listener observations also matched.

Unrelated ACME/SSH files and accounts, other packages/snaps/holds, the original
SSH process, renewal timer and unrelated firewall rules were preserved. The
same `/var/log` directory was restored to root:syslog 0775 without extended
attributes; rsyslog validation, logrotate debug and an actual syslog marker
passed. All helper/wrapper state, transferred inputs and the protected backup
were deleted only after the final checks and retention of 35 secret-safe
observations. No private-key backup was copied to this run's local evidence.

[Final read-only checks](../../../.scratch/acceptance/r20/vps-execution/final-readonly.log)
passed at `2026-09-19T08:08:10Z`: the installation and handoff directory are
absent, owned units are unloaded/inactive with zero PIDs, 443/8443 have no
listeners, SSH/rsyslog/the shared timer are active, and the original log-parent
identity and 0775 mode are restored. The safe empty shared runtime lock remains
by design. [Execution evidence](../../../.scratch/acceptance/r20/vps-execution/)
retains both initial refusals and their reviewed corrections. These observations
are historical after capture. This validates maintenance and original-menu
cleanup; it does not qualify a new candidate or complete the MVP journeys.

The disposable Linux VM was shut down normally after its fixture cleanup.
Its exact QEMU PID exited and loopback SSH port closed; its disk, seed,
credentials, copied binaries and test executables were removed. Useful logs,
manifests, diagnostic source and the local future-reference helper/plan remain
under the private [run directory](../../../.scratch/acceptance/r20/).

## Initial certificate and ordinary-start changes

Both reviewed replacement/repair and forward certificate activation now retain
their accepted completion checkpoint until `subscription-serving.json` has
been published and synchronized. Publication uses the existing protected-file
and expected-current atomic writer, synchronizes both directories when moving
from staging, and verifies empty staging and the resulting serving files before
completion. Finishing resumes the exact source/target publication after an
interruption or late directory-sync failure; it does not repeat a successful
certificate request or restart merely to complete the snapshot.

An already accepted certificate with a proved older snapshot is reported as
Change incomplete. Reviewed **Finish subscription change** can synchronize it
when the accepted certificate is still published and loaded. The old snapshot
must be canonical, protected, for the same Link ID and credential digest, and
match all four protected archive files. Missing, unsafe, future, conflicting,
unknown, or untrusted material is refused. Reading status does not repair it.
Staging is admitted only for an existing pending certificate operation; a matching stray
staging file does not make an idle installation healthy.

Ordinary proxy and serving starts now acquire the same existing protected lock
and freshly validate installed/operation facts while holding it. A contender
first tries the existing authenticated Owner descriptor handoff, then waits
for actual lock acquisition, bounded by cancellation or 15 seconds. Busy is
never authorization. Missing or unsafe lock files are not recreated. The
one-use Client Identity cutover route additionally requires borrowed authority;
an ordinary acquired lock cannot satisfy it.

Final caller review covered Owner repair/replacement, deploy-hook activation,
Finish, link retrieval, removal, serving dispatch, proxy ExecCondition, and the
software-update runtime handoff. A draft activation exclusion would have
blocked a deploy hook inside its still-live Certbot attempt. The strengthened
`TestLiveRenewalTakesStatusPrecedenceButDeployHookStillActivates` reproduced that
regression, and the exclusion was removed. Certificate activation retains the
existing whole-host authority and repeated publication checks. Repair and
destructive operations retain their existing renewal exclusions.

The initial repair relaxed no ownership schema, release trust policy, TLS trust
rule, unit text, certificate request policy, startup gate, or MVP qualification
contract. The later boot repair adds explicit optional ownership for its new
unit; it does not modify legacy records.

## Validation

| Check | Evidence and result |
|---|---|
| Original certificate defect | The new acceptance regression failed for both replacement and activation. A Linux filesystem test using the original `activation.go` and `repair.go` also failed: real files remained inconsistent after replacement. |
| Fixed certificate paths | Focused tests passed for replacement, forward activation, old-generation recovery, decline/stale review refusal, pending publication, repeated finishing, late sync failures, and changed loaded-certificate refusal. |
| Filesystem and trust boundaries | Real files, modes, symlinks, archive hashes, atomic publication, directory sync, link retrieval and serving-resource removal passed. Unsafe modes, missing/symlink/hardlink state, unknown data, changed link/credential/hash, mixed live links, foreign staging and untrusted certificates refused. Unrelated lineage material remained intact. |
| Original startup defect | In a disposable Linux/systemd VM, restoring the original proxy authorization code made a forced overlap return from `systemctl start` without starting the proxy. The repaired version waits for serving's real lock to be released. |
| Fixed systemd startup | Forced overlap and three simultaneous two-unit restarts passed, with both services active, a successful proxy condition, and trusted local TLS serving the expected subscription. A held mutation lock still refused the gate on cancellation, and the unchanged gate worked after release. |
| Existing-host maintenance design | With the original certificate code restored through a source overlay, the state-only transaction preserved executable, Installed Record, Ownership Record, configuration and token bytes, was idempotent, and allowed reviewed Complete removal with the proxy inactive. |
| Repository checks | `GOTOOLCHAIN=go1.26.6 go test ./...` and `go vet ./...` passed. Focused packages were rerun after the final caller-review corrections; focused certificate/startup race checks and stalled-handoff cancellation passed. Linux native host, proxy and Software Lifecycle package tests passed with their source-relative fixtures. Linux amd64 executable cross-build passed. |

The isolated VM used Ubuntu 24.04.5 arm64, Linux 6.8 and systemd 255. It was
created locally with QEMU/HVF, a checksum-verified Ubuntu cloud image, loopback
SSH forwarding, and restricted outbound networking. This was not the VPS.

The systemd fixture uses the production subscription unit/sandbox, real
ExecCondition, filesystem lifecycle inspection, lock acquisition, private
serving dispatch, TLS validation, and listener. A test wrapper supplies the
fixture's address and holds startup at an explicit coordination barrier. The
proxy workload is a TCP listener stand-in, not sing-box traffic. Certificate
integration tests supply publication/loaded-runtime observations; they exercise
the real snapshot writer, file admission, link reader, Certbot POSIX exclusion
and serving removal. Package/resource effects outside that boundary remain
controlled fixtures.

Initial harness failures were corrected without changing product admission:
the macOS artifact path was shortened to fit Unix socket limits; Linux package
testdata was copied with its expected relative paths; fixture cleanup now handles
units already removed by the tested action; and Type=simple readiness waits for
the actual listener using the production 15-second bound, retrying connection
refusal only. The cloud image's `/var/log` was root:syslog 0775, so the isolated
fixture temporarily established the adapter's required protected-parent mode
0755 and restored 0775 afterward. This does not establish support for arbitrary
unprotected parent directories.

Final inspection proved the fixture paths, listeners, address and group absent
and the original `/var/log` mode restored. The VM was shut down; its disk,
download, private SSH key, generated fixture material and test executables were
removed after retaining useful logs, source overlays and hashes.

These earlier source-level results do not establish packaged amd64 VPS behavior, real sing-box
traffic, public CA issuance, natural timer execution, outside HTTPS, Karing,
a supported upgrade into the failed installation, or successful VPS cleanup.
The historical startup rejection branch remains an inference: reproducing its
mechanism does not recover the missing historical lock-owner trace.

## Repeating the isolated Linux checks

`coordination_linux_test.go` skips by default. Run it only in a fresh,
disposable root Linux/systemd VM with no SBXR, sing-box, or Certbot installation.
It refuses pre-existing fixture paths. Set `/run/sbxr-isolated-test-host` to
the exact bytes `disposable SBXR test VM\n`, mode 0600, and set
`SBXR_ISOLATED_SYSTEMD=1` for the selected test process. Do not set this on a
real installation.

Build the proxy package test executable with Go 1.26.6 for the VM architecture.
Run each of these in a separate process so the generated test CA does not reuse
another fixture's cached system trust pool:

```text
-test.run=^TestCertificateAcceptanceAndRecoveryWithRealFilesystem$ -test.v
-test.run=^TestExistingMismatchMaintenancePreservesInstalledIdentityAndAllowsRemoval$ -test.v
-test.run=^TestOrdinaryStartsUnderIsolatedSystemd$ -test.v
```

The tests clean their services, listeners, address, group, files and trust root
even after assertion failure. The second test was also executed with original
activation/repair source from the base commit; the third was executed with the
original proxy gate to retain the negative reproduction. Go overlays select
those original files without changing the checkout. Test binaries and their
synthetic installed records are never deployment artifacts.

## One-time executable recovery handoff — local follow-up

The standalone maintenance helper is implemented under
[`.github/scripts/sbxr-snapshot-recovery`](../../../.github/scripts/sbxr-snapshot-recovery/main.go).
It is build-tag isolated from the installed product and pins the retained verified
v3.1.75 amd64 executable. A canonical protected plan binds the Installed Record,
complete Ownership Record, exact source snapshot and exact target hash. The
helper derives the target from accepted `serving` authority. It accepts only the
proved generation-1 / accepted-generation-2 transaction and its exact forward
retry states. It writes no executable or ownership/installed record, invokes no
Certbot operation and changes no service state.

`check` acquires existing whole-host and renewal exclusion and observes Certbot
locks without creating them. `apply` additionally retains all three Certbot
POSIX locks, repeats identity/configuration/certificate/operation/service checks,
and uses the same protected expected-current publication code as the repair.
Accepted certificate trust/validity, canonical credentials and live links are
checked. Active-serving mode also checks loaded TLS and the actual returned
subscription; post-reboot mode instead requires the exact failed-serving tuple
and proves quiescence. Both archive generations stay
pinned even on a retry after publication. Unknown state and contention refuse;
partial staging is preserved for inspection rather than deleted or adopted.

[Follow-up run artifacts](../../../.scratch/acceptance/c19h/) retain the executable
identities, exact helper commands, VM results, original menu transcripts,
reviewed diff and test results. The historical VPS plan and expected snapshots
remain private local handoff files; the runbook publishes only their hashes.
The Installed Record expectation was reconstructed from the original installer's
serialization and verified together with the original executable in the fixture.
It is not presented as a new VPS observation.

### Historical c19h blocked attempt

**At the end of c19h, validation was blocked and no commit was created.**
That helper was implemented, but its final executable had not passed the whole
handoff. The authorized r20 continuation above supersedes its current status;
this paragraph preserves the original failure and its evidence. Its SHA256 is
`2e99660b922146c0b480a05fa89e13db4ec0b894898c25dea36e11727261b81c`.
The earlier helper, before the final protected-plan fsync was added, had SHA256
`a60eebb8059c194f8416e12679bdabbfc32462591e7c182a7956a04af67f95b6`
and passed two complete rehearsals. Those passes are retained as preliminary
evidence and do not qualify the final helper.

| Boundary | Exact executable evidence |
|---|---|
| Original mismatch | The original verified v3.1.75 executable's public menu refused Complete removal with `PROXY-INSTALLATION-ACTION-REFUSED` / `Subscription absence`; the file inventory remained unchanged. |
| Protected backup and preflight | The actual backup command at `/root/sbxr-v3175-recovery/before.tar` and the final helper's `check` passed. The backup was mode 0600. |
| Changed inputs and unsafe files | The final helper refused changed executable, Installed Record, Ownership Record, configuration, credential, snapshot, target certificate and target binding; missing whole-host lock; untrusted accepted TLS; unsafe snapshot/staging modes; symlink/hardlink snapshot; foreign and partial staging. Refusal checks preserved the inventoried files. |
| Contention | The final helper refused actual whole-host and renewal admission/writer flock contention, and separate-process POSIX contention on each of the three Certbot locks. |
| Actual process interruption | `ptrace` stopped the final helper at the real Linux rename syscall and SIGKILL ended it before or after publication. Exact source plus target staging, and exact target plus empty staging, both passed the same helper's check and forward retry. Successful calls preserved executable/record/configuration/credential/certificate/unit bytes and file identities, with the helper rechecking service state and PID identity under exclusion. |
| Repeated final application | A further application to the already-published target exited 1 with `snapshot recovery refused: post-publication verification; preserve target and investigate`. The test stopped at `rehearse.py:281` after 311.38 seconds. This final repetition did not pass. |
| Original-menu Complete removal | Both preliminary full rehearsals passed repeated completion, changed old-archive refusal, menu decline and confirmed removal through the original executable. The latter also proved owned renewal-configuration removal and preservation of unrelated lineage/shared ACME sentinels, SSH, renewal timer and reused dependencies. The final-helper run stopped before these menu checks, so they remain unproved for its final bytes. |

At that point the final refusal was a new validation failure, distinct from the reproduced
generation mismatch. The retained systemd journal shows the subscription service
and timer running until fixture cleanup, with no intervening service failure or
restart. It does not identify which post-publication predicate failed. The
evidence does not establish whether this is a helper defect, an existing
inspection/timing issue, or a fixture limitation. No assertion or timeout was
weakened, and the failure was not replaced with a passing retry. Isolating it
required another investigation; work stopped under the Owner's explicit stop
condition. The helper, draft runbook and existing repairs were left uncommitted.

Evidence: [final failed run](../../../.scratch/acceptance/c19h/rehearsal-final.log),
[first preliminary pass](../../../.scratch/acceptance/c19h/rehearsal-sixth.log),
[second preliminary pass](../../../.scratch/acceptance/c19h/rehearsal-seventh.log),
[exact build and execution identities](../../../.scratch/acceptance/c19h/execution-identities.json),
and [final systemd journal](../../../.scratch/acceptance/c19h/vm-results/systemd-final.log).
The preliminary menu transcripts are explicitly named `preliminary-*` in the
private VM results directory; they must not be attributed to the final run.

The amd64 rehearsal used checksum-verified Ubuntu 24.04.5, Linux
6.8.0-139-generic and systemd 255, under local QEMU/TCG with restricted networking
and authenticated loopback SSH. It used the original packaged executable and
real systemd units/sandbox, local trusted TLS, filesystem operations, kernel
locks, package installation/removal and the ordinary public menu. The certificate
authority, certificate generations, configuration, complete Ownership Record and
plan were synthetic local fixtures. Public-IP discovery and snap metadata were
local fixtures too. The production VPS plan's exact historical record/certificate
bytes were not exercised on a current host. No ACME issuance, natural renewal,
outside traffic, real proxy traffic, power loss, supported upgrade or VPS cleanup
is established. Directory-sync failure coverage remains source-level fault
injection; the exact executable interruption tests use process death.

`GOTOOLCHAIN=go1.26.6 go test ./...`, ordinary `go vet ./...`, the tagged Linux
amd64 helper/package vet check and cross-build passed. Python syntax and all 11
runbook shell blocks passed syntax checks. The full suite uses the shorter local
`TMPDIR=.scratch/acceptance/h/t` so Unix sockets fit the macOS path limit. The
helper was moved out of `cmd/` after the architecture test correctly rejected a
new product entry point. No product admission changed to satisfy a test.

Earlier repaired product source and unchanged regression-test hashes match the
retained `c19` manifest. The only changed earlier Linux test code is cleanup that
accepts `getent` exit 2 when actual Complete removal has already deleted its
fixture group, and still rejects other errors. Existing ARM/systemd, native Linux,
race and negative-reproduction results were reused for unchanged components.
Final caller review covered the snapshot writer/inspector, activation and repair,
ordinary start/borrowed-lock paths, software-update contracts, prepared serving
activation, link retrieval and removal. No separate code fix was attempted after
the final executable failure.

Initial amd64 harness failures were corrected at the fixture boundary: install
the real package before restoring the managed configuration, move the local
ipify fixture away from port 443, exercise the original menu's refusal at Execute,
keep a temporary whole-host lock backup on the same filesystem, use an independent
POSIX-lock holder process, and recognize Go's actual renameat syscall. These
changes did not relax product checks. The final failure is not explained by those
already-corrected harness problems.

Fixture cleanup passed after the final failure. A separate read-only audit
confirmed all fixture paths absent, no sing-box user/group, no test address or
listeners, no owned firewall/NAT rules, restored `/etc/hosts` and `/var/log` mode,
and active SSH. See [cleanup observations](../../../.scratch/acceptance/c19h/linux-cleanup-final.json).
The VM was shut down and its process and loopback SSH port were proved absent.
Its disk, temporary fixtures, test executable, duplicate input assets and
ephemeral keys were removed. Useful logs and the blocked private handoff remain;
see the [local run notes](../../../.scratch/acceptance/c19h/README.md).

The [future VPS runbook](../v3.1.75-snapshot-recovery-runbook.md) contains fresh
read-only preflight checks, pinned identities, protected backups, exact invocation,
interruption recovery, postchecks, original-menu Complete removal and final
preservation/cleanup checks. Its operational objective is removal without first
restarting the proxy or requesting a certificate. Any unexpected live state
requires refusal and replanning. The original binary, Installed Record,
Ownership Record, configuration, credentials, certificates and services must
remain unchanged throughout the snapshot correction.

No VPS connection or mutation, public CA issuance, candidate dispatch, release
mutation or push was performed in the c19h follow-up. At that point VPS execution
remained a separately authorized step. The current MVP procedure and the v3.1.75 burn are
unchanged.
