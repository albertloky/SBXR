# V4 operator procedures

These procedures complete the operator map for `repair-issuance-bounded-v4`.
They prepare a future signed live attempt; they are not evidence that any
scenario ran. Scenario numbers follow ADR-0022: scenarios 01–08 use the split
operator entries. This document specifies their scenario 07 outside-runner
exchange and the remaining procedures for 09–25.

The controlling contract is the signed manifest and collector request for the
new attempt. Never substitute values from an older candidate. The action under
test is always the installed candidate's zero-argument `/usr/local/bin/sbxr`
menu. `--certbot-recorder`, hook, and serving roles are product-owned service
entry points, not operator or test interfaces.

## Common operator contract

The complete initialization block below applies to scenarios 09–25, which start
with SBXR installed. Scenario 07 uses the same environment paths, but its start
entry owns the initial Not installed proof and subsequent candidate installation;
do not run `operator_exact_candidate` before that installation.

Run server commands as root in the SSH control session that existed before the
scenario. Keep that session on physical `en0`. Source only the workflow-attested
shell libraries:

```sh
set -euo pipefail
umask 077
export SBXR_V3_PACKAGED_LIVE_MODULE=/run/sbxr-qualification/v3-packaged-live.sh
export SBXR_QUALIFICATION_MANIFEST=/root/sbxr-qualification-v3/qualification-manifest.json
export SBXR_QUALIFICATION_REQUEST=/root/sbxr-qualification-evidence/request.json
export SBXR_INSTALLED_RECORD=/var/lib/sbxr/installed.json
export SBXR_EXECUTABLE=/usr/local/bin/sbxr
export SBXR_OPERATOR_STATE_DIR=/run/sbxr-qualification
export SBXR_OPERATOR_EVIDENCE_DIR=/root/sbxr-qualification-evidence
export SBXR_TRANSPORT_ROOT=/root/sbxr-qualification-v3
export SBXR_TRANSPORT_UNIT=sbxr-qualification-v3.service
source /run/sbxr-qualification/operator-support.sh
OBS=/run/sbxr-qualification/observations.py
test "$SCENARIO_START" = "$STARTED_AT"
load_candidate_identity
operator_exact_candidate
preflight initial
```

Keep extra read-only status probes outside the scenario's required assertions.
Run those probes through the sourced helper, for example:

```sh
operator_observe 'printf "0\n" | "$SBXR_EXECUTABLE" | grep -F "Proxy status:"'
```

Check the emitted `OPERATOR_OBSERVATION_EXIT` and saved
`OPERATOR_OBSERVATION_STATUS`. The wrapper keeps the original strict SSH shell
alive while a separate strict Bash child runs the probe. It does not turn a
failed observation into evidence. An unexpected result still ends the attempt;
retain the failure and use the supported cleanup procedure. Export probe inputs
explicitly and keep output secret-safe. Never wrap required assertions or whole
scenario scripts, and never infer a pass from the wrapper's successful return.
See the [operator README](../../.github/scripts/v3-operator/README.md#extra-observations-in-the-original-ssh-session)
for the complete observation contract.

For scenarios that exercise the official Certbot route, resolve and hash the
revision-specific interpreter after the scenario preflight. The helpers reject
the moving `current` symlink and independently repeat the collector, package,
candidate, route, and deadline checks:

```sh
CERTBOT_INTERPRETER=$(readlink -f /snap/certbot/current/usr/bin/python3)
CERTBOT_INTERPRETER_SHA256=$(sha256sum "$CERTBOT_INTERPRETER" | cut -d' ' -f1)
export CERTBOT_INTERPRETER CERTBOT_INTERPRETER_SHA256
```

After scenario 14, use `preflight after-snap-refresh`; using the initial package
declaration after that point is a failure. Copy `observations.py` from the exact
candidate checkout, verify its digest against the retained workflow copy, and
run it with Python 3. It reports metadata, hashes, Linux process identity, and
POSIX lock holders without reading protected values into evidence or acquiring a
lock:

```sh
python3 "$OBS" process "$PID"
python3 "$OBS" locks
python3 "$OBS" flocks /run/lock/sbxr.lock
python3 "$OBS" absence
```

`unknown`, an unsafe object, a missing expected holder, or `all_absent:false`
never counts as absence or exclusion. Preserve the JSON output and the command's
start/end timestamps. The helper does not prove network behavior, application
behavior, or an interruption boundary.

For every scenario, record the validator's common checks in this exact order
before the scenario-specific checks:

```text
fresh-disposable-vps-preflight unchanged-candidate-bytes initial-state-proved
boundary-observed final-state-proved original-ssh-continuity
capture-coverage-complete exact-secrets-absent prohibited-patterns-absent
supported-effective-route-inspected
```

Then add the family checks required by `requiredV3Checks`. Hash protected files
and credentials; never retain their contents.

For the nonbaseline common `supported-effective-route-inspected` check, observe
the actual **Certbot timer-to-service route before any scenario-specific timer
stop or fault injection**, while its timer is active and enabled:

```sh
SCENARIO_ID=$(jq -er .scenario_id "$SBXR_QUALIFICATION_REQUEST")
python3 /run/sbxr-qualification/effective-route.py \
  --output "$SBXR_OPERATOR_STATE_DIR/$SCENARIO_ID-effective-route.json"
```

Set `SCENARIO_ID` from the current collector request. Scenarios 07 and 08 do
this in their start/setup entry. The helper binds the exact manifest, request,
candidate and current Ownership Record. Before subscription enablement it
requires the official snap command and absence of owned interception. With
renewal authority it requires the exact effective recorder command, drop-in,
deploy/post hooks, generated service path, and official twice-daily timer route.
Retain the protected receipt with its real timestamps and digest. An inactive
timer, stale reload, extra drop-in or wrong command is a refusal. For scenario
15, retain this healthy-route receipt before hiding the unit and the separate
fault/restoration observations required below; the fault cannot satisfy the
healthy common check. This check observes renewal integration; the separate
identity startup checks below observe the proxy cutover gate.

At the end of scenarios 09–24:

```sh
operator_exact_candidate
test "$(systemctl is-active sing-box.service)" = active
scan_journal
scan_transport_captures
```

For scenario 25, run `operator_exact_candidate`, journal, and transport scans
immediately before Complete removal. After removal, require the scenario's full
owned-absence checks instead of an installed candidate or active proxy service.

Submit one canonical cumulative evidence prefix within five minutes, wait for
collector acceptance, and do nothing further until the collector asks for the
next scenario. An unexpected result, an unproved boundary, package drift, SSH
loss, or failed scan ends the attempt. Record the failure, allow the candidate to
burn, and use the separately recorded supported cleanup path. Cleanup never
turns a failed scenario into a pass.

`interrupt_at` may terminate the zero-argument menu after a real progress line,
but the signal and line alone are not boundary proof. Each procedure below also
requires the stated durable record, process, listener, lock, or outside-client
observation. If the durable observation cannot be made before the action moves
on, stop the attempt.

## 07 — `identity-absent` outside-session exchange

The signed candidate's existing Ubuntu amd64 `acceptance-vps` job owns the
outside driver. The collector starts `identity-outside.py` from that job's exact
checkout when the start entry publishes its distinct identity request. Do not
start another workflow, invoke the baseline one-shot probe for this scenario,
or author an outside receipt by hand.

In the original SSH control session, run:

```sh
bash /run/sbxr-qualification/07-identity-absent-start.sh
```

The start entry performs supported installation/setup, proves subscription
absence, and obtains the old client configuration through the public confirmed
Show client configuration action. The collector transfers that protected
configuration to its outside driver. The driver checks the exact official
client package, starts a private loopback client, proves the outside route, and
establishes one TLS connection with successful traffic. Only then does it publish
`07-outside-ready.json` in the protected operator state directory.

After that receipt appears, run:

```sh
bash /run/sbxr-qualification/07-identity-absent-rotate.sh
```

The rotation entry checks the bound ready receipt and sends a fresh challenge.
The same driver must successfully use the same old connection after seeing the
challenge and acknowledge it before the entry invokes the public reviewed
Rotate Client Identity action. A stale file without a live driver cannot satisfy
that exchange. The driver stays alive through rotation and records actual
closure of that connection. It then attempts one fresh connection with the old
credential, requires refusal, checks the outside target directly, and uses the
new configuration obtained through confirmed public manual disclosure to prove
replacement traffic. A timeout alone is not closure or refusal evidence.

The entry invokes `transition-operator.py rotate identity-absent`. This starts
one installed zero-argument UI in a unique cgroup and retains tracing across
five ordered `before-open` stops at the next Ownership Record publication.
The current durable checkpoints are `target prepared`, `startup integration
published`, `systemd reloaded`, `startup route verified`, and `source quiescent`.
At the first three stops the publication, reload, and route-verification effect
has completed but its next checkpoint has not yet been published. The helper
separately inspects exact drop-in bytes/protection and the loaded systemd route.
At the fourth it proves unchanged canonical source and source process, with
the target only staged. Its ordinary `start` is a no-op on that active source;
it is not evidence of source admission while the action owns the mutation lock.
At the last stop it attempts ordinary `start` and `restart`, requires the actual
ExecCondition refusal after each, and proves no source/target process,
descendant or listener remains. The action then resumes and must complete the
prepared target through its own authorized startup route.

`transition-identity-absent.json` binds every observation to the same actual
UI PID/start tick/executable/cgroup, ordered boundary, Ownership Record digest,
manifest and current request. Keep its full-resolution source timestamps.
Missing/reordered checkpoints or uncertain startup denial stop the attempt.

The driver removes its client processes, listeners, temporary package and
secret-bearing files before publishing `07-outside.json`. The collector validates
the full result and publishes `07-outside-collected.json` with its receipt hash.
Once both files exist, run:

```sh
bash /run/sbxr-qualification/07-identity-absent-finish.sh
```

The finish entry validates the producer's full receipt and challenge against the
exact manifest, collector request, action timestamps and original deadline. It
then performs reviewed Complete removal and proves Not installed. Preserve the
safe typed observations and capture-scan result for scenario 24 coverage; no
raw client configuration, credential digest or secret-bearing runner output
belongs in the ordinary evidence. Missing acknowledgments, changed phase files,
SSH loss, failed traffic or uncertain cleanup stop the attempt. The exchange
never resets the original 30-minute scenario clock or five-minute submission
grace and never requests a certificate.

## 09 — `link-precommit`

Keep the original scenario clock and prepare the manifest, boundary, validator,
and accepted-prefix verification receipt described in `evidence-assembly.md`
before the start entry. Initial state must be healthy schema-2 `Running` with an
available Subscription Link. Run in the original SSH control session:

```sh
bash /run/sbxr-qualification/09-10-link-start.sh link-precommit
```

The entry checks the installed candidate and supported renewal route, retains
the initial disclosure in a mode-0600 file, and publishes the protected trigger
for the collector's outside runner. Wait for `link-link-precommit-ready.json`
to prove the initial old URL returns HTTP 200 with the expected artifact over
trusted TLS. The collector uses the signed outside runner and verifies its
direct egress differs from the VPS. Do not launch a second outside driver.

Before rotation, start `connection-probe.py` through the existing outside proxy
client as in scenario 08, bound to this request digest and deadline. Retain its
private JSONL trace and `connection-observation.py` summary through interruption
and recovery. This independently proves that the same proxy connection survives;
the HTTP subscription probe does not prove proxy traffic continuity.

Record the preflight, initial-state, and effective-route operator observations
before starting the controller. The controller opens the zero-argument menu,
reviews and confirms `Rotate subscription link`, and holds the actual action
process after exactly one target is prepared, while the source still serves:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt link-precommit --timeout 90
```

At this first hold, the controller challenges the outside runner to open a TLS
connection and send incomplete HTTP headers. Only after the matching acknowledgment
does it allow the stop. At the next hold, the durable checkpoint is `stop
authorized`, source process/cgroup descendants and owned or active accepted
sockets must be gone, and the outside request must have closed in under five
seconds. Timeout, response bytes, or a TLS failure is not closure evidence. The
controller then interrupts the held UI process, before commitment. It preserves
the source/target authority, actual process identities, runtime observations,
and outside receipt bindings in `transition-link-precommit.json`.

Record the boundary, prepared-target, and quiescence observations while still
interrupted, before invoking recovery. The source remains authoritative; a
`committed` record is a failed precommit scenario. Recover through the same
public zero-argument menu:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  recover link-precommit --timeout 90
```

The menu must show `Subscription status: Change incomplete` and
offer `Finish subscription change`. Review its printed plan; it must select
restoring the proved old generation and removing the unused replacement. Confirm
with `y` through the controller. Require `PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP`. Prove the
rotation field and staging entries absent, the old token/state hashes restored,
the old link usable outside, no replacement link disclosed, and unchanged proxy
PID/configuration/Client Identity and proxy traffic. The controller verifies the
selected source and empty staging. Complete the outside exchange:

```sh
bash /run/sbxr-qualification/09-10-link-finish.sh link-precommit
```

The finish entry privately discloses the selected old link, publishes the
recovery-bound finalizer, waits for outside HTTP 200 and unchanged artifact and
certificate, then retains `link-link-precommit-entry-final.json`. Finish the
independent proxy trace and capture scans, record the remaining observations,
and assemble `link-precommit` using `evidence-assembly.md`. Submit only the
validator-accepted facts through the existing collector submission path.

Append family checks `proxy-and-traffic-unchanged client-identity-unchanged` and:

```text
one-prepared-target old-serving-quiesced old-generation-restored
unused-target-removed old-link-usable no-replacement-disclosure
```

The `old-serving-quiesced` observation must show no accepted request or owned
serving descendant at the stop gate. A staged file alone does not prove it.

## 10 — `link-postcommit`

Repeat the preparation, initial outside HTTP 200, independent proxy connection,
and pre-action observations from scenario 09, using this request and scenario:

```sh
bash /run/sbxr-qualification/09-10-link-start.sh link-postcommit
# Wait for link-link-postcommit-ready.json; start the independent proxy trace.
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt link-postcommit --timeout 90
# Record the interrupted boundary and prepared-target/quiescence observations.
python3 /run/sbxr-qualification/transition-operator.py \
  recover link-postcommit --timeout 90
bash /run/sbxr-qualification/09-10-link-finish.sh link-postcommit
```

The controller first observes the same prepared-target and source-stop holds,
including outside pending-request closure, then advances to a third hold.
Interrupt only after the Ownership Record durably contains
`subscription_rotation.checkpoint == "committed"`, direction `forward`, and its
authoritative `serving` equals the recorded target. This hold is before opening
`/var/lib/sbxr/subscription-token` to publish the replacement. The next Ownership
Record write would be too late: target publication and activation precede it.
The controller rechecks source quiescence while the target is still staged,
before observing any target request.

The next zero-argument menu must offer `Finish subscription change`; its plan
must select only the committed target. Confirm `y`. Require
`PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED`, capture the new link only through
the protected pipe, and prove staging/rotation residue absent. The old URL must
return HTTP 404 from the outside runner, the new URL must return exactly one
valid artifact, and proxy configuration, Client Identity, and traffic must be
unchanged. The finish entry and outside runner produce these final observations
and `link-link-postcommit-entry-final.json`; retain the separate proxy trace,
complete capture scans, and assemble `link-postcommit` with `operation-10`.
Submit the validator-accepted facts. Do not copy either private link disclosure
into the result facts or workflow captures.

Append the same link family checks and:

```text
one-prepared-target no-old-process-or-request-overlap target-only-finishing
old-link-404 new-link-usable
```

## Shared retained-source clock for scenarios 11–25

After the collector creates one current request, start each later scenario once
from the original SSH control session:

```sh
bash /run/sbxr-qualification/11-25-scenario-start.sh <scenario>
```

The wrapper repeats the manifest, request, candidate, package-phase, Running,
secret-memory, and supported effective-route checks. It creates protected
`scenario-<scenario>-begin.json` and
`scenario-<scenario>-effective-route.json`. Scenarios 11–14 start against the
initial package declaration. Scenarios 15–25 start against
`after_snap_refresh`. A mismatch is a failed attempt, not permission to edit the
request or phase record.

Record the action boundary around the exact public or official operation named
by the scenario:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start <scenario>
# Run the reviewed action, helper coordination, or manual Karing journey.
python3 /run/sbxr-qualification/scenario-entry.py action-complete <scenario>
```

`action-start` belongs immediately before the action under test, after any
required initial outside connection is ready. `action-complete` belongs after
the action has completed, refused, or reached the scenario's required result,
and before final outside, preservation, cleanup, and capture-coverage checks.
These commands advance one immutable current-request chain; they do not accept a
different scenario, request, start time, skipped phase, replaced prior file, or
time outside the original deadline.

Run every machine helper that supplies an assembler source through the reviewed
capture wrapper, using the exact helper identity and output filename in the
family evidence guide:

```sh
python3 /run/sbxr-qualification/capture-source.py \
  --helper <allowlisted-helper> \
  --output "$SCENARIO_SOURCE_DIRECTORY/<exact-name>.json" -- <helper-arguments>
```

The wrapper keeps an interactive helper's stdin attached, streams its real
stdout events, rejects stderr on a successful helper, and retains a canonical
`sbxr-v4-captured-source-v1` document bound to the current manifest, request,
helper, interval, exit code, and event timestamps. A wrapper success is not a
scenario pass. The family adapter must validate the actual records, retained
bytes, and timing rules. Keep the source directory mode 0700 and every source
file mode 0600.

After all final checks, close the entry clock:

```sh
bash /run/sbxr-qualification/11-25-scenario-finish.sh <scenario>
```

The finish wrapper rechecks initial packages for scenarios 11–13, refreshed
packages for 14–24, and `Not installed` for scenario 25. It creates
`scenario-<scenario>-finish.json`, which is the assembler `--state` input.
Scenario 14 intentionally starts with initial packages and finishes with the
refreshed declaration. Do not run the finish wrapper before post-action checks,
and do not treat local wrapper rehearsal as evidence that any live action ran.

Retained source schemas, exact filenames, and live limitations are in
[`evidence-managed.md`](evidence-managed.md),
[`evidence-identity.md`](evidence-identity.md), and
[`evidence-final.md`](evidence-final.md). The common assembly flags and proof
contract are in [`evidence-assembly.md`](evidence-assembly.md).

## 11 — `managed-renewal`

For every scenario 11–15, create a new private source directory and start the
collector-owned outside witness before the action:

```sh
export SCENARIO_SOURCE_DIRECTORY=/absolute/private/scenario-sources
install -d -m 0700 "$SCENARIO_SOURCE_DIRECTORY"
bash /run/sbxr-qualification/scenario-subscription-input.sh "$SCENARIO" before
deadline_unix=$(jq -er .deadline_unix "$SBXR_QUALIFICATION_REQUEST")
while test ! -f "/run/sbxr-qualification/${SCENARIO_NUMBER}-outside-ready.json"; do
  test "$(date +%s)" -lt "$deadline_unix" || exit 1
  sleep 1
done

python3 /run/sbxr-qualification/capture-source.py --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/${SCENARIO_NUMBER}-managed-before.json" -- \
  snapshot --phase before \
  --subscription "/run/sbxr-qualification/${SCENARIO_NUMBER}-subscription-before.json"
python3 /run/sbxr-qualification/capture-source.py --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/${SCENARIO_NUMBER}-renewal-before.json" -- history
```

Set `SCENARIO` and `SCENARIO_NUMBER` to the exact row being run (`managed-renewal`
and `11` through `unsupported-route` and `15`). The collector starts the signed
outside client, establishes one proxy TLS
connection, and probes that same connection throughout the action. Wait for the
ready receipt before `action-start`; it is published only after the initial TLS
and proxy requests succeed. The collector writes
`${SCENARIO_NUMBER}-proxy-trace.json` after a successful request following
`action-complete` and removes its temporary client before reporting completion.

After the scenario-specific action, record `action-complete`, provide the fresh
final public disclosure, and wait for the same collector before taking final
snapshots:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-complete "$SCENARIO"
bash /run/sbxr-qualification/scenario-subscription-input.sh "$SCENARIO" final
while test ! -f "/run/sbxr-qualification/${SCENARIO_NUMBER}-outside-result.json"; do
  test "$(date +%s)" -lt "$deadline_unix" || exit 1
  sleep 1
done

python3 /run/sbxr-qualification/capture-source.py --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/${SCENARIO_NUMBER}-renewal-final.json" -- history
python3 /run/sbxr-qualification/capture-source.py --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/${SCENARIO_NUMBER}-managed-final.json" -- \
  snapshot --phase final \
  --subscription "/run/sbxr-qualification/${SCENARIO_NUMBER}-subscription-final.json"
```

Copy the collector-owned `NN-outside-ready.json`, `NN-outside-result.json`, and
`NN-proxy-trace.json` unchanged into the source directory. Do not wrap or recreate
those receipts. The complete source inventory and producer details are in
[`evidence-managed.md`](evidence-managed.md).

Record the effective timer/service/drop-ins and package identities. Start the
reviewed coordinator in the original protected SSH control session; it installs
the persistent cgroup egress deny before starting the official unit and holds the
actual revision-specific Certbot image before its first userspace instruction:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start managed-renewal
coproc MANAGED_HOLD {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper managed-hold \
    --output "$SCENARIO_SOURCE_DIRECTORY/11-managed.json" -- \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
managed_pid=$MANAGED_HOLD_PID
exec {managed_read}<&"${MANAGED_HOLD[0]}"
exec {managed_write}>&"${MANAGED_HOLD[1]}"
IFS= read -r MANAGED_HELD <&"$managed_read"
```

Require the actual chain to reach the owned recorder and an actual Certbot child,
with a live receipt in `/var/lib/sbxr/renewal-attempts.json` matching recorder
PID/start tick/boot ID and no completion. Prove the child is blocked before any
socket connect or packet. Then interrupt through the coordinator; it keeps the
deny attached while systemd stops the official service and verifies the receipt
cannot report success:

```sh
printf 'interrupt\n' >&"$managed_write"
IFS= read -r MANAGED_FINAL <&"$managed_read"
exec {managed_write}>&-
exec {managed_read}<&-
wait "$managed_pid"
```

The streamed lines are only the coordination display. The single
`11-managed.json` capture is the retained `held`/`interrupted` source;
`11-managed-final.json` is reserved for the final managed snapshot.

Never invoke Certbot directly. The helper's kernel and harmless snap fixtures
establish mechanics only; the observations above are the required live route,
ancestry, receipt, and no-egress evidence.

Through the zero-argument menu, review `Repair subscription`. Its plan must name
certificate renewal, not runtime-only repair. Confirm once. This is the second
and final planned production issuance. Prove one new lineage generation,
canonical publication, accepted activation, outside trusted TLS and unchanged
link/Client Identity/proxy traffic. Preserve the failed/unknown receipt alongside
the later successful attempt; do not rewrite history.

Before confirming the repair, arm the actual pre-clear producer through
`capture-source.py --helper syscall-gate` as specified in
[`evidence-managed.md`](evidence-managed.md). Its output is
`11-repair-boundary.json`. At `boundary-held`, capture the still-present repaired
history through `--helper managed-evidence` as `11-renewal-repaired.json`, then
send `release` to that same capture. Capture `11-renewal-interrupted.json`
immediately after the first coordinator interruption. Do not substitute the
healthy cleared final history for either ephemeral source.

Append managed family checks `proxy-and-traffic-unchanged
client-identity-unchanged unchanged-link` and:

```text
supported-managed-attempt-interrupted recorder-unknown-or-failed
reviewed-repair-targeted-production-replacement fault-retained-until-proof
official-schedule-integration recorder-start recorder-outcome production-issuance
canonical-publication accepted-activation outside-tls
natural-timer-not-observed naturally-due-renewal-not-observed
```

## 12 — `recorder-live`

Start a fresh coordinator and retain this scenario's held record:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start recorder-live
coproc MANAGED_HOLD {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper managed-hold \
    --output "$SCENARIO_SOURCE_DIRECTORY/12-managed.json" -- \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
managed_pid=$MANAGED_HOLD_PID
exec {managed_read}<&"${MANAGED_HOLD[0]}"
exec {managed_write}>&"${MANAGED_HOLD[1]}"
IFS= read -r MANAGED_HELD <&"$managed_read"
```

While the actual child is held, require a live receipt whose PID/start tick
matches the recorder and whose completion is absent. Independently observe the
child identity and cgroup. Compare with every prior receipt and prove this one is
`live`, not `abandoned`; do not infer completion from process presence.

Release the helper's controlled gate while its egress deny remains attached and
the service and recorder remain under systemd:

```sh
printf 'release\n' >&"$managed_write"
IFS= read -r MANAGED_FINAL <&"$managed_read"
exec {managed_write}>&-
exec {managed_read}<&-
wait "$managed_pid"
```

Wait for their real exit, then require the same receipt to acquire
the real exit code and hook outcome. Prove final local serving health, outside
TLS, unchanged link/Client Identity/proxy traffic, and no false second receipt.
This scenario must not force renewal and must not consume another issuance.

Append recorder family checks and:

```text
live-attempt live-and-abandoned-distinguished live-not-completed
```

The required family prefix is `proxy-and-traffic-unchanged
client-identity-unchanged unchanged-link`.

## 13 — `recorder-locks`

Start the exact shared-admission boundary coordinator. It attaches the egress
guard, starts the official unit, and holds the recorder after whole-host release
while shared renewal admission remains held:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start recorder-locks
coproc RECORDER_BOUNDARY {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper recorder-boundary \
    --output "$SCENARIO_SOURCE_DIRECTORY/13-admission.json" -- \
    admission "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
recorder_pid=$RECORDER_BOUNDARY_PID
exec {recorder_read}<&"${RECORDER_BOUNDARY[0]}"
exec {recorder_write}>&"${RECORDER_BOUNDARY[1]}"
IFS= read -r RECORDER_HELD <&"$recorder_read"
```

Require its protected observation to identify the actual recorder and matching
live receipt, report the renewal writer lock `unlocked`, the shared admission
lock held by that recorder, and the whole-host lock free. File existence is not
lock proof. Release the boundary while the egress guard remains attached and
require healthy, non-issuing completion:

```sh
printf 'release\n' >&"$recorder_write"
IFS= read -r RECORDER_FINAL <&"$recorder_read"
exec {recorder_write}>&-
exec {recorder_read}<&-
wait "$recorder_pid"
```

For a second, distinct invocation, open `/run/lock/sbxr.lock` in a separate root
process without symlinks and hold the same BSD `flock(2)` exclusive lock used by
SBXR. In the second pre-existing root SSH control session, run:

```sh
coproc WHOLE_HOST {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper hold-flock \
    --output "$SCENARIO_SOURCE_DIRECTORY/13-whole-host.json" -- \
    /run/lock/sbxr.lock --timeout 60
}
whole_host_pid=$WHOLE_HOST_PID
exec {whole_host_read}<&"${WHOLE_HOST[0]}"
exec {whole_host_write}>&"${WHOLE_HOST[1]}"
IFS= read -r WHOLE_HOST_HELD <&"$whole_host_read"
python3 /run/sbxr-qualification/capture-source.py --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/13-wait-renewal-before.json" -- history
```

After its `held` record, start the official service again from the original
control session while that lock remains held:

```sh
systemctl start --no-block snap.certbot.renew.service
python3 /run/sbxr-qualification/capture-source.py --helper observations \
  --output "$SCENARIO_SOURCE_DIRECTORY/13-whole-host-wait.json" -- \
  flocks /var/lib/sbxr/renewal-writer.lock /run/lock/sbxr.lock
# Wait for terminal ExecMainStatus=125, then retain the unchanged history.
python3 /run/sbxr-qualification/capture-source.py --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/13-wait-renewal-final.json" -- history
printf 'release\n' >&"$whole_host_write"
IFS= read -r WHOLE_HOST_RELEASED <&"$whole_host_read"
exec {whole_host_write}>&-
exec {whole_host_read}<&-
wait "$whole_host_pid"
```

The recorder must refuse within 30 seconds with `ExecMainStatus=125`, without
creating a new receipt or Certbot child and without holding the renewal writer
flock while it waits for the whole-host flock. Observe BSD flock holders through
`observations.py flocks`; `F_GETLK` observes POSIX record locks and is not valid
for these files. Record `systemctl show snap.certbot.renew.service -p
ActiveState,ExecMainStatus`; require an inactive or failed terminal state and
exact status 125. Enter `release` in the second control session only after that
proof, require the helper's `released` record, then prove final health and
unchanged proxy/link/identity. The first guarded completion and the second
refused admission must consume no issuance. A harmless lock fixture establishes
only helper mechanics; it is not live official-unit evidence.

Append recorder family checks and:

```text
lock-order-contention no-evidence-lock-held-during-child-or-whole-host-wait
bounded-refusal
```

## 14 — `snap-refresh`

Before refresh, retain package version/revision/size/digest for certbot, snapd,
and core24; hash the effective timer, service, owned drop-in, both hooks, recorder
executable, renewal evidence, Ownership Record, certificate, token, configuration,
and all unrelated Certbot lineages. Prove no apt/dpkg/snap/Certbot work and no
SBXR writer is active.

Run the supported refresh, naming only the declared snap:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start snap-refresh
snap refresh certbot
```

The command must produce exactly the `after_snap_refresh.certbot` identity from
the signed manifest. Immediately run `preflight after-snap-refresh`. Require
snapd/core24 and every undeclared package unchanged. Re-read the generated unit
and effective merged `ExecStart`; require the official timer route, exact owned
drop-in, hooks, recorder bytes, locks, evidence history, certificate, link,
Client Identity, proxy and outside TLS to remain valid. Any automatic extra snap
change or equal before/after Certbot identity is failure, not evidence.

Append snap family checks `proxy-and-traffic-unchanged
client-identity-unchanged unchanged-link` and:

```text
supported-snap-refresh effective-generated-route-preserved
recorder-and-hooks-verified planned-package-change-only
```

All later scenarios use the post-refresh package declaration.

## 15 — `unsupported-route`

This is a bounded detection test. Capture byte hashes, modes, owners, device and
inode for `/etc/systemd/system/snap.certbot.renew.service`, its timer and all
drop-ins; capture `systemctl cat` and `systemctl show -p FragmentPath,DropInPaths,
ExecStart` for the supported service. Stop the timer without starting its service
and record whether it was active/enabled.

Invoke the reviewed route helper, which records the exact unit inode/hash and
timer state before stopping the timer and renaming the unit on the same
filesystem. It refuses an active service or persistent timer, records the
service invocation/start markers, and never starts that service:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start unsupported-route
python3 /run/sbxr-qualification/capture-source.py --helper route-control \
  --output "$SCENARIO_SOURCE_DIRECTORY/15-route-inject.json" -- inject
```

Run the packaged
zero-argument menu and View details. It must report `Problem detected` for the
effective managed-renewal route and explicitly leave the historical outcome
unknown. This observation proves detection after drift; it does not prove that a
new route could never execute.

Restore through the same helper:

```sh
python3 /run/sbxr-qualification/capture-source.py --helper route-control \
  --output "$SCENARIO_SOURCE_DIRECTORY/15-route-restore.json" -- restore
```

It returns the same inode to the exact original path, reloads systemd, and
restores the timer's exact prior enabled/active states. It refuses if the service
invocation/start markers changed. Compare bytes,
metadata, `FragmentPath`, `DropInPaths`, and `ExecStart`. Prove health and no
service execution occurred. If snapd recreates or changes the file, stop rather
than choosing one copy.

Append unsupported family checks `proxy-and-traffic-unchanged
client-identity-unchanged unchanged-link` and:

```text
new-or-renamed-route-detected problem-detected accounting-gap-explicit
bypass-prevention-not-claimed historical-outcomes-unknown
```

## 16 — `identity-precommit`

Use the exact cleanup-side quiescence boundary and later recovery commands:

```sh
python3 /run/sbxr-qualification/identity-entry.py prepare identity-precommit
# Wait for identity-precommit-outside-ready.json before action-start.
python3 /run/sbxr-qualification/scenario-entry.py action-start identity-precommit
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt identity-precommit --timeout 90
# retain the required outside/process observations while interrupted
python3 /run/sbxr-qualification/transition-operator.py \
  recover identity-precommit --timeout 90
```

The interrupt helper first performs the same five ordered startup observations
as scenario 07 on this scenario's real reviewed action. It then kills that
action at the proved source-quiescent boundary. Retain the observations in
`transition-identity-precommit.json`; do not reuse scenario 07 evidence.

Establish an independent outside proxy session and record its process/session
identity and traffic. Hash the current UUID, noncredential configuration fields,
subscription artifact, token/link, certificate and startup units. Start reviewed
`Rotate Client Identity` and interrupt only after durable source quiescence and
before the next publication. Require
`client_identity_rotation.checkpoint == "source quiescent"`, direction `cleanup`,
the source configuration still authoritative, the old process group and
descendants empty, the established source session ended, and no target accepted
by the outside runner. Prove effective startup publication/reload/route
separately; a unit file alone is insufficient.

The zero-argument menu must offer `Finish Client Identity rotation` with the
cleanup direction. Confirm `y`. Require the cancellation result, source
configuration/session availability restored, unused target and staged artifact
absent, ordinary source start allowed, and link/noncredential fields unchanged.
Do not disclose or test the replacement credential.

Append the identity family prefix:

```text
old-established-outside-session outside-target-healthy startup-publication
reload effective-route source-only-before-gate ordinary-start-denied-after-gate
unchanged-link-and-noncredential-fields
```

Then append:

```text
owned-process-groups-and-descendants-terminated
source-restoration-only-before-revocation unused-target-removed
source-traffic-restored rotation-reported-cancelled
```

## 17 — `identity-postcommit`

The interrupt helper repeats the same five startup observations on this
scenario's action, continues tracing that same process to the additional durable
`source revoked` checkpoint, and only then interrupts it. Its protected
`transition-identity-postcommit.json` preserves the current request and ordered
startup observations; scenario 16 receipts cannot satisfy this scenario.

Use the exact forward-side revocation boundary and later recovery commands:

```sh
python3 /run/sbxr-qualification/identity-entry.py prepare identity-postcommit
# Wait for identity-postcommit-outside-ready.json before action-start.
python3 /run/sbxr-qualification/scenario-entry.py action-start identity-postcommit
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt identity-postcommit --timeout 90
# retain the required outside/process observations while interrupted
python3 /run/sbxr-qualification/identity-entry.py selected identity-postcommit
python3 /run/sbxr-qualification/transition-operator.py \
  recover identity-postcommit --timeout 90
```

Repeat the independent old session and private hashes. Start reviewed rotation.
Interrupt only after the Ownership Record durably says direction `forward` and
checkpoint `source revoked`, and after the old proxy process group and descendants are
empty. Prove the established old session ended and a fresh old-credential
connection is refused while the outside target itself remains healthy. Never
restore the source after this point.

The next zero-argument menu must select forward-only `Finish Client Identity
rotation`. Confirm `y`, capture replacement configuration only through the
protected outside-runner pipe, and prove replacement traffic. Require the old
credential still refused, exactly one target published, ordinary startup open
only after completion, staged target absent, and unchanged link and
noncredential fields.

Append the identity prefix from scenario 16 and:

```text
owned-process-groups-and-descendants-terminated old-new-connections-refused
one-target-forward-after-revocation replacement-traffic-proved
```

## 18 — `identity-unavailable`

Record the exact owned INPUT rules and public IPv4. Use the reviewed helper to
insert one qualification rule at INPUT position 1, outside the
`sbxr-subscription` namespace. It stores the original `iptables-save -t filter`
bytes and rejects any pre-existing qualification rule:

```sh
python3 /run/sbxr-qualification/capture-source.py --helper firewall-control \
  --output "$SCENARIO_SOURCE_DIRECTORY/18-firewall-added-capture.json" -- add "$PUBLIC_IPV4" \
  | tee /run/sbxr-qualification/18-firewall-added.json
python3 /run/sbxr-qualification/identity-entry.py prepare identity-unavailable
# Wait for identity-unavailable-outside-ready.json before action-start.
python3 /run/sbxr-qualification/scenario-entry.py action-start identity-unavailable
```

Immediately verify exactly one such rule with `iptables-save`. Prove both outside
link retrieval and local public-IP HTTPS fail, while independent TCP 443 proxy
traffic and outside-target health remain good. Certificate bytes and healthy
renewal history must not change.

Run the same observed public rotation through:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  rotate identity-unavailable --timeout 120
```

Retain this action's five startup observations in
`transition-identity-unavailable.json`. Prove old session/process
termination, old and fresh old-credential refusal, replacement proxy traffic,
and the separate subscription status fault. Because the link is unavailable,
use the menu's separately confirmed `Show client configuration`; never read the
configuration file as a client-delivery shortcut.

Retain that confirmed replacement through the same public helper:

```sh
python3 /run/sbxr-qualification/identity-entry.py selected identity-unavailable
```

Delete exactly one qualification rule and require byte-for-byte restoration of
the original filter table:

```sh
python3 /run/sbxr-qualification/capture-source.py --helper firewall-control \
  --output "$SCENARIO_SOURCE_DIRECTORY/18-firewall-restored-capture.json" -- remove \
  | tee /run/sbxr-qualification/18-firewall-restored.json
```

Review `Repair subscription`; its plan must say runtime-only
serving repair. Confirm once. Prove no Certbot child, no issuance, unchanged
certificate lineage, restored same-link retrieval, and healthy proxy.

After the repair succeeds, record `action-complete` and provide the restored
public Subscription Link to the already-running collector:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-complete identity-unavailable
bash /run/sbxr-qualification/scenario-subscription-input.sh identity-unavailable final
while test ! -f /run/sbxr-qualification/identity-unavailable-repair-outside.json; do sleep 1; done
```

Only then capture `identity-unavailable-repair` as `identity-repair.json`. The
collector-owned `identity-unavailable-repair-outside.json` binds the same
outside runner, original request, restored link, trusted TLS, artifact, and
certificate. Never create it from the VPS helper or stdin.

Append the identity prefix and:

```text
owned-process-groups-and-descendants-terminated old-new-connections-refused
replacement-traffic-proved subscription-fault-reported-separately
unavailable-subscription-fallback
```

On any early failure, remove only that exact qualification rule before supported
product cleanup and retain the removal observation.

## 19 — `lifecycle-menu`

Bracket the whole public-menu helper with the generic action clock. The helper's
internal `19-state.json` is diagnostic only; assembly uses the canonical shared
`scenario-lifecycle-menu-finish.json`:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start lifecycle-menu
python3 /run/sbxr-qualification/capture-source.py \
  --helper 19-lifecycle-menu.sh \
  --output "$SCENARIO_SOURCE_DIRECTORY/19-lifecycle-menu.json"
python3 /run/sbxr-qualification/scenario-entry.py action-complete lifecycle-menu
bash /run/sbxr-qualification/11-25-scenario-finish.sh lifecycle-menu
```

Use `/usr/local/bin/sbxr` with no arguments and no scripted private role. Record
the first frame so action numbers are bound to their displayed labels; never
assume fixed numbers. Choose `Check` and require a real public latest check plus
`Software Lifecycle: Ready` and the safe no-update result for the exact
candidate. Return to the redrawn menu, select `Update`, and require it is
reachable but performs no replacement when Check has no compatible higher
target. Return again, select `Recover`, and require `No recovery is available`.
Prove executable and Installed Record unchanged after each selection.

Under v4, `explicit-confirmation` and `clean-install-target-refused` are the two
declared automated-only checks. Do not stage a clean-install release, answer a
confirmation, or report either as a live pass. Append only these live checks:

```text
packaged-zero-argument-menu check-reachable update-reachable recover-reachable
safe-no-update safe-no-recovery no-replacement-on-refusal
```

## 20 — `remove-certbot`

Start a fresh coordinator and retain this scenario's held record:

```sh
coproc MANAGED_HOLD {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper managed-hold --output "$SCENARIO_SOURCE_DIRECTORY/20-managed.json" -- \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
managed_pid=$MANAGED_HOLD_PID
exec {managed_read}<&"${MANAGED_HOLD[0]}"
exec {managed_write}>&"${MANAGED_HOLD[1]}"
IFS= read -r MANAGED_HELD <&"$managed_read"
```

Prove child executable/arguments/cgroup/PID/boot ID/start tick and the matching
live recorder receipt. Hash every owned product resource.

Open the zero-argument menu, review `Complete removal`, and enter the exact
`REMOVE SBXR` confirmation. It must refuse within the bound because active
Certbot is proved; no resource hash, service state, link, certificate,
configuration, package, account, or firewall rule may change. Interrupt through
the coordinator and retain its final record:

```sh
python3 /run/sbxr-qualification/capture-source.py --helper removal-refusal \
  --output "$SCENARIO_SOURCE_DIRECTORY/remove-certbot-removal-refusal.json" -- \
  remove-certbot
```

```sh
printf 'interrupt\n' >&"$managed_write"
IFS= read -r MANAGED_FINAL <&"$managed_read"
exec {managed_write}>&-
exec {managed_read}<&-
wait "$managed_pid"
```

Require the official service's real receipt outcome and return to healthy
`Running`. Do not kill a process by name or use recorder PID as Certbot proof.

Append remove checks:

```text
active-certbot-proved removal-refused owned-resources-preserved
```

## 21 — `remove-writer`

Start the reviewed real outcome-write coordinator:

```sh
coproc RECORDER_BOUNDARY {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper recorder-boundary --output "$SCENARIO_SOURCE_DIRECTORY/21-writer.json" -- \
    writer "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
recorder_pid=$RECORDER_BOUNDARY_PID
exec {recorder_read}<&"${RECORDER_BOUNDARY[0]}"
exec {recorder_write}>&"${RECORDER_BOUNDARY[1]}"
IFS= read -r RECORDER_HELD <&"$recorder_read"
```

It must observe actual child completion first, then hold the actual recorder
before it opens `/var/lib/sbxr/.renewal-attempts.json.next`; pausing an arbitrary
PID or fabricating a `.next` file is invalid.

While held, prove the writer PID/executable/start tick, completed child identity,
matching unfinished receipt, POSIX writer-lock holder, and that
`/run/lock/sbxr.lock` is unlocked. Review and confirm Complete removal. Require a
bounded refusal and unchanged owned resources. Release the writer and require
the real outcome to be durably recorded:

```sh
python3 /run/sbxr-qualification/capture-source.py --helper removal-refusal \
  --output "$SCENARIO_SOURCE_DIRECTORY/remove-writer-removal-refusal.json" -- \
  remove-writer
```

```sh
printf 'release\n' >&"$recorder_write"
IFS= read -r RECORDER_FINAL <&"$recorder_read"
exec {recorder_write}>&-
exec {recorder_read}<&-
wait "$recorder_pid"
```

Then prove healthy Running.

Append:

```text
active-writer-proved removal-refused owned-resources-preserved
```

## 22 — `remove-admission-race`

Run the bounded coordinator directly in the original SSH control session. It
records and stops the initially active/enabled official timer, repeats the exact
request/package/candidate preflight, and starts the installed candidate's real
zero-argument menu in a unique transient unit. It binds that menu's exact
PID/start tick, executable device/inode, unit and cgroup before preparation and
again after the recorder hold. It dynamically selects the
displayed `Complete removal` action and holds the actual prepared review at its
exact `REMOVE SBXR` confirmation without submitting it:

```sh
python3 /run/sbxr-qualification/capture-source.py \
  --helper admission-race-operator \
  --output "$SCENARIO_SOURCE_DIRECTORY/22-admission-race.json" -- \
  "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
```

The coordinator then invokes the existing `recorder-boundary.py admission`
control. Before it sends the held menu's confirmation, require that control to
bind the actual recorder PID/executable/start tick and live receipt, observe the
whole-host BSD flock released, the renewal writer flock unlocked, and the shared
renewal admission BSD flock held by that recorder through `/proc/locks`. It
retains that event as `22-admission-held.json`.

Only after those observations does the coordinator submit `REMOVE SBXR` to the
same still-running menu process and Prepared Action. Require
`PROXY-INSTALLATION-ACTION-REFUSED`, a nonempty failed safety check, and no
`Progress: Removal committed`. Compare a secret-safe digest of the full owned
product/subscription/lineage/firewall inventory and relevant service states
immediately before and after that refusal while the recorder remains held. It
retains the bound result as `22-removal-refusal.json`.

The coordinator then releases the recorder, requires its real successful receipt
outcome with the egress guard retained until the official unit stops, and saves
`22-admission-final.json`. It proves the exact candidate and healthy `Running`,
scans journal/transport captures, verifies the official service and cgroup are
absent, and restores the official timer to its exact initial active/enabled state.
On a refusal before the public confirmation it closes the held menu without
mutation; after the recorder is held, every failure still releases/stops that
control and restores the timer. Such cleanup is not a scenario pass or retry.

Append:

```text
writer-admission-race-proved removal-refused owned-resources-preserved
```

## 23 — `remove-directory-lock`

For each real Certbot lock path, require absence or a root-owned, one-link regular
file with no group/other write bit. Start the qualification holder. It creates an
absent lock with `O_CREAT|O_EXCL` mode 0600, otherwise opens the existing file
with `O_NOFOLLOW`; it acquires POSIX `lockf` write locks, revalidates
device/inode, and remains alive. `flock` is invalid:

```sh
coproc CERTBOT_LOCKS {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper directory-locks --output "$SCENARIO_SOURCE_DIRECTORY/23-locks.json"
}
IFS= read -r LOCK_HOLDER_JSON <&"${CERTBOT_LOCKS[0]}"
```

Confirm all three holder locks through:

```sh
python3 "$OBS" locks /etc/letsencrypt/.certbot.lock \
  /var/lib/letsencrypt/.certbot.lock /var/log/letsencrypt/.certbot.lock
```

Hash contents and metadata before review. Confirm Complete removal; require a
bounded refusal, all owned resources unchanged, and the same three lock
device/inodes, contents, metadata and holder PIDs. End only the qualification
holder, require clean exit, prove helper-created paths returned to absence and
pre-existing paths kept their exact inode/content/metadata, confirm each
remaining lock is `unlocked`, and prove healthy Running:

```sh
python3 /run/sbxr-qualification/capture-source.py --helper removal-refusal \
  --output "$SCENARIO_SOURCE_DIRECTORY/remove-directory-lock-removal-refusal.json" -- \
  remove-directory-lock
```

```sh
printf 'release\n' >&"${CERTBOT_LOCKS[1]}"
wait "$CERTBOT_LOCKS_PID"
python3 "$OBS" locks /etc/letsencrypt/.certbot.lock \
  /var/lib/letsencrypt/.certbot.lock /var/log/letsencrypt/.certbot.lock
```

Do not
delete shared lock files.

Append:

```text
supported-directory-lock-held bounded-contention-refusal
owned-resources-preserved
```

## 24 — `secret-containment`

Bracket the whole containment helper with the shared action clock. Its internal
`24-state.json` is diagnostic only; assembly uses
`scenario-secret-containment-finish.json`:

```sh
python3 /run/sbxr-qualification/scenario-entry.py action-start secret-containment
python3 /run/sbxr-qualification/capture-source.py \
  --helper 24-secret-containment.sh \
  --output "$SCENARIO_SOURCE_DIRECTORY/24-secret-containment.json"
python3 /run/sbxr-qualification/scenario-entry.py action-complete secret-containment
bash /run/sbxr-qualification/11-25-scenario-finish.sh secret-containment
```

Use the protected V2 attempt inventory. It must bind exact, root-owned private
operator-state, operator-evidence and transport roots. Those three roots must be
pairwise disjoint. Keep the root-owned specification directly below the evidence
root and outside every capture root and keep Scenario 24 result receipts there as
well. Bind one distinct staged capture root for each runner, VPS, Mac, terminal,
workflow and retained surface. For every capture, compare the opened file
descriptor's device/inode and full metadata with the declaration, read and hash
that descriptor, and recheck that the path still names the same inode. Every
regular file below each staged root must have one inventory entry with its exact
path, surface, metadata and SHA-256. An unlisted file, invented entry, symlink,
path replacement or changed digest is incomplete coverage.

Independently walk every descendant of the state and transport roots. Classify
each discovered regular file, FIFO and directory exactly once as qualification
cleanup or retained; reject every omission, invention, symlink and unsupported
object kind. Bind cleanup objects by device/inode and full metadata. A retained
regular file must have a SHA-256 and must either be scanned as a safe retained
file or be the exact bound manifest or transport credential. Retained directories
declare structure only. Before cleanup, bind their full metadata; after deleting
children, require the same device/inode, owner and mode and use a fresh exhaustive
walk to prove the exact remaining child set. The known-secret file remains a real,
nonempty cleanup member. Cover every private FIFO that the walk finds, but do not
invent a FIFO when none exists.

Discover live attempt processes independently of the declaration from protected
or dedicated systemd cgroups and from executables, working directories or exact
absolute argument paths rooted in the attempt. A root-name substring inside an
arbitrary argument is not process authority. Exclude the scanner's own process
and ancestor control session. Bind each discovered process by PID, start tick,
executable device/inode, cgroup, discovery source and cleanup/retained
classification. Only the exact product and attempt transport cgroups may be
retained; every other discovered helper must be cleanup-class. The original SSH
or controller ancestry is outside cleanup and must survive. Immediately recheck
both identity and mechanical discovery provenance before signaling a cleanup
process. An empty helper set is valid when discovery finds none.
After removal, repeat both independent walks, require every cleanup member absent
and every retained member present, and reject any new object or process. Require
exactly `sing-box.service`, `sbxr-subscription.service`,
`snap.certbot.renew.service` and the bound attempt transport service.

The operator must separately attest that the six staged roots contain every
external capture and log available for this attempt and that external client
cleanup completed at its actual source. This attestation is required source
evidence: the VPS scanner cannot discover hidden runner, Mac, terminal or
workflow logs or external client processes. It does not excuse an omission from
an inventoried root, and the scanner must not infer external completeness from
six chosen labels or from its local root walks.

The entry retains the separate `sandbox-token-probe.py` check against the actual
`sbxr-subscription.service` process, executable and mount namespace. Require its
two permission refusals for the token and staging paths. The fresh-account probe
below adds coverage for the full protected inventory; both probes are required.

Root must prove the fixed subscription token, Ownership Record, configuration,
collector manifest, transport credential, the canonical private-key symlink, its
resolved actual file below the owned Certbot archive, the known-secret file and
every inventoried private pipe. Require their canonical paths, kinds, one-link
rules, owners, modes and file SHA-256 values before probing. Then run
`protected-open-probe.py` against every one of those paths. It creates a fresh
system account with no supplementary groups and an empty private `/run` directory,
drops every capability, sets `NoNewPrivs`, and performs read-only nonblocking
opens. Every path must exist and return only `EACCES` or `EPERM`; a missing path or
successful open fails. Require the same safe lstat/resolved-target metadata after
the probe. Its `finally` path must remove that exact account and empty runtime even
when a probe fails, without placing secret values in output or arguments.

Scan, without printing matches, every inventoried capture, every scan-retained
file, `/proc/*/cmdline` and environment, and the complete required-unit
`ExecStart`, unit text and environment surface for every exact known private key,
old/new Client UUID, old/new subscription credential, qualification secret,
private-key header and Authorization header. Remove only exact inventoried
qualification objects and cleanup-class processes after revalidating their
identities; then prove all are absent and retained files remain byte-for-byte
identical. The later journal checks may create only their bounded temporary files
in operator-state and must remove them before the entry finishes. Preserve
unrelated user data, the product, transport and original control session. A
missing or unreadable surface, failed external attestation, inventory drift,
unknown root object/process or cleanup omission is a refusal. Append:

```text
sandbox-cannot-read-token canonical-and-candidate-protection
units-arguments-environment-safe runner-vps-mac-terminal-workflow-retained-scans
qualification-secrets-and-client-processes-cleaned unrelated-data-preserved
```

## 25 — `karing-final`

This final scenario has a two-hour clock and must end in Complete removal. Before
touching the SBXR test profile, capture privately in Karing the selected server,
profile list, DNS, routing, TUN and application settings. Record the installed
Karing version and package digest and compare them with the signed manifest.
The selected server must never become the SBXR node.

Import the one real HTTPS Subscription Link through the protected Mac channel.
In Karing, open the imported profile and its server list. Require exactly one
remote profile containing exactly one VLESS Reality node. Compare its displayed
name and all nonsecret fields to the protected expected artifact. Recheck the
Owner's selected server and settings after any automatic configuration reload.

Perform the ordered UI observations:

1. Press the node's latency control and wait for a new result timestamp. Require
   success against Karing's configured URL; a displayed cached number, selector,
   another node, ICMP, or a TCP-only probe is invalid.
2. Perform one manual refresh of the same subscription and prove the profile
   remains one node with identical fields.
3. Set Karing's profile update interval to five minutes if the imported profile
   does not already have that exact interval. Record the last-update time, then
   do not press refresh. Wait until the next five-minute update is genuinely due
   and observe Karing update it automatically. The five-minute value is the due
   interval, not Karing's polling frequency: pinned official v1.2.24.2709 checks
   due subscriptions three seconds after app resume and on its 30-minute PC
   periodic timer ([pinned source](https://github.com/KaringX/karing/blob/v1.2.24.2709/lib/app/modules/server_manager.dart)).
   Triggering an app resume only after the profile is genuinely
   due is acceptable and is not a manual refresh; otherwise wait for the actual
   periodic check. In either route, require the profile's update time to advance.
   Elapsed time or an app resume without that advance is not proof. Recheck the
   selected server/settings.
4. Disable only that test profile's automatic refresh before coordinating the
   server's reviewed Client Identity rotation; do not change global routing or
   the selected server. This must happen before the negative cached-UUID proof
   because an app resume can itself refresh a due enabled profile. After server
   rotation and before any Karing refresh, privately prove the cached node still
   has the old UUID. Press latency and require a fresh failure. Independently
   prove the target URL is healthy and the server refuses the old credential;
   timeout alone is invalid.
5. Refresh the exact same real link, prove the UUID changes to the one replacement
   while name and every other field remain unchanged, restore the exact five-minute
   interval, and require a new successful latency result. Preserve the actual
   timestamps in order: initial success, revoked failure, same-link refresh,
   replacement success.
6. Insert the exact qualification INPUT REJECT for recorded IPv4 TCP 8443 from
   scenario 18. Without deleting or editing the Karing profile, require same-link
   refresh failure while the cached node remains present and a new node latency
   succeeds. Delete only that rule, refresh the same link successfully, and
   recheck selected server/settings.
7. On the server, use reviewed Complete removal and enter `REMOVE SBXR`. Require
   `SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED`. Prove outside old/new proxy
   access and link access unusable, run a fresh failed Karing node latency, and
   use `observations.py absence` plus package/account/unit/listener/firewall
   checks to prove full owned absence.
8. Delete only the SBXR test profile and restore its prior per-profile interval
   if necessary. Prove the original selected server, unrelated profiles, DNS,
   routing, TUN and application settings equal the initial capture. Remove the
   protected test credentials and helper processes.

Under v4, omit the four policy-excluded checks; never report them as passed:

```text
direct-and-proxied-traffic old-established-session-terminated traffic-restored
direct-refresh-correction-or-confirmed-fallback
```

Append the remaining `karing-final` checks in validator order, then the five v4
latency observations:

```text
latest-official-stable-macos-package one-real-remote-profile
one-vless-reality-node all-fields-and-name-match settings-preserved
manual-refresh genuinely-due-five-minute-auto-refresh
owned-process-groups-and-descendants-terminated old-new-connections-refused
outside-target-healthy unchanged-real-link replacement-uuid-adopted
other-fields-preserved https-outage-preserves-node same-link-recovery
complete-removal outside-access-unusable full-owned-absence
temporary-secret-and-process-cleanup current-connection-preserved
fresh-initial-node-latency fresh-revoked-identity-latency-refused
same-link-refresh-before-replacement-latency fresh-replacement-node-latency
```

Automatic reload is permitted. Manual disconnect, selecting SBXR, changing
persistent DNS/routing/TUN, or claiming uninterrupted browsing/session behavior
is outside the approved policy.

## Helper verification boundary

The exact commands above use external OS control and the installed public or
official systemd routes. Before signing, bind every helper byte hash into the
reviewed operator bundle and require its isolated local/kernel fixtures. Those
fixtures establish syscall, cgroup, lock, timeout, and fail-closed mechanics;
they do not pass a live scenario. Scenarios 11, 12, 13 and 20 still require the
actual deployed snap/systemd ancestry, matching receipt, lock and no-egress
observations. Scenarios 21 and 22 still require the actual recorder boundary and
the public removal refusal. No signal, fixture result, or source argument can be
promoted into those live observations.
