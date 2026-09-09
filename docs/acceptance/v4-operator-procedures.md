# V4 operator procedures for scenarios 09–25

These procedures complete the operator map for `repair-issuance-bounded-v4`.
They prepare a future signed live attempt; they are not evidence that any
scenario ran. Scenario numbers follow ADR-0022: scenarios 01–08 are handled by
the existing split operator entries, and this document covers 09–25.

The controlling contract is the signed manifest and collector request for the
new attempt. Never substitute values from an older candidate. The action under
test is always the installed candidate's zero-argument `/usr/local/bin/sbxr`
menu. `--certbot-recorder`, hook, and serving roles are product-owned service
entry points, not operator or test interfaces.

## Common operator contract

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
and credentials; never retain their contents. At the end of scenarios 09–24:

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

## 09 — `link-precommit`

Arm the reviewed transition helper before the zero-argument UI. It starts the
UI in a unique transient cgroup, selects the displayed action number, and holds
the actual process before the next Ownership Record publication only after the
durable `stop authorized` checkpoint exists. Its protected pipes remain attached
to the original SSH control process and it retains only record hashes and safe
process/checkpoint metadata. Original-SSH continuity and all outside behavior
still require independent observations:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt link-precommit --timeout 90
```

Initial state is healthy schema-2 `Running` with an available Subscription Link.
Privately hash the current token, serving state, Ownership Record, configuration,
and Client Identity; prove the old link returns the expected artifact from the
outside runner and record the serving PID/start tick and active accepted-request
set.

Start `Rotate subscription link` through `/usr/local/bin/sbxr`, enter `y`, and
interrupt only after the real `Preparing subscription credential` phase and a
durable Ownership Record with `subscription_rotation.checkpoint == "stop
authorized"`. Prove exactly one target in `subscription-staging`, the old token
and serving generation unchanged, and the target credential different by hash.
If the checkpoint is already `committed`, this scenario failed; do not roll back.

After the separately retained outside/process observations at the interrupted
durable state,
recover through the same public zero-argument UI:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  recover link-precommit --timeout 90
```

The menu must show `Subscription status: Change incomplete` and
offer `Finish subscription change`. Review its printed plan; it must select
restoring the proved old generation and removing the unused replacement. Confirm
with `y`. Require `PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-CLEANED-UP`. Prove the
rotation field and staging entries absent, the old token/state hashes restored,
the old link usable outside, no replacement link disclosed, and unchanged proxy
PID/configuration/Client Identity and proxy traffic.

Append family checks `proxy-and-traffic-unchanged client-identity-unchanged` and:

```text
one-prepared-target old-serving-quiesced old-generation-restored
unused-target-removed old-link-usable no-replacement-disclosure
```

The `old-serving-quiesced` observation must show no accepted request or owned
serving descendant at the stop gate. A staged file alone does not prove it.

## 10 — `link-postcommit`

Use the corresponding durable committed boundary and later recovery commands:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt link-postcommit --timeout 90
# retain the required outside/process observations while interrupted
python3 /run/sbxr-qualification/transition-operator.py \
  recover link-postcommit --timeout 90
```

Repeat the private initial hashes and outside old-link success. Start the same
reviewed rotation, but interrupt only after the Ownership Record durably contains
`subscription_rotation.checkpoint == "committed"`, direction `forward`, and its
authoritative `serving` equals the recorded target. Also prove the source serving
PID and accepted requests are gone before observing any target request.

The next zero-argument menu must offer `Finish subscription change`; its plan
must select only the committed target. Confirm `y`. Require
`PROXY-INSTALLATION-SUBSCRIPTION-LINK-ROTATED`, capture the new link only through
the protected pipe, and prove staging/rotation residue absent. The old URL must
return HTTP 404 from the outside runner, the new URL must return exactly one
valid artifact, and proxy configuration, Client Identity, and traffic must be
unchanged.

Append the same link family checks and:

```text
one-prepared-target no-old-process-or-request-overlap target-only-finishing
old-link-404 new-link-usable
```

## 11 — `managed-renewal`

Record the effective timer/service/drop-ins and package identities. Start the
reviewed coordinator in the original protected SSH control session; it installs
the persistent cgroup egress deny before starting the official unit and holds the
actual revision-specific Certbot image before its first userspace instruction:

```sh
coproc MANAGED_HOLD {
  python3 /run/sbxr-qualification/managed-hold.py \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
managed_pid=$MANAGED_HOLD_PID
exec {managed_read}<&"${MANAGED_HOLD[0]}"
exec {managed_write}>&"${MANAGED_HOLD[1]}"
IFS= read -r MANAGED_HELD <&"$managed_read"
printf '%s\n' "$MANAGED_HELD" > "$SBXR_OPERATOR_EVIDENCE_DIR/11-managed-held.json"
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
printf '%s\n' "$MANAGED_FINAL" > "$SBXR_OPERATOR_EVIDENCE_DIR/11-managed-final.json"
```

Never invoke Certbot directly. The helper's kernel and harmless snap fixtures
establish mechanics only; the observations above are the required live route,
ancestry, receipt, and no-egress evidence.

Through the zero-argument menu, review `Repair subscription`. Its plan must name
certificate renewal, not runtime-only repair. Confirm once. This is the second
and final planned production issuance. Prove one new lineage generation,
canonical publication, accepted activation, outside trusted TLS and unchanged
link/Client Identity/proxy traffic. Preserve the failed/unknown receipt alongside
the later successful attempt; do not rewrite history.

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
coproc MANAGED_HOLD {
  python3 /run/sbxr-qualification/managed-hold.py \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
managed_pid=$MANAGED_HOLD_PID
exec {managed_read}<&"${MANAGED_HOLD[0]}"
exec {managed_write}>&"${MANAGED_HOLD[1]}"
IFS= read -r MANAGED_HELD <&"$managed_read"
printf '%s\n' "$MANAGED_HELD" > "$SBXR_OPERATOR_EVIDENCE_DIR/12-managed-held.json"
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
printf '%s\n' "$MANAGED_FINAL" > "$SBXR_OPERATOR_EVIDENCE_DIR/12-managed-final.json"
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
coproc RECORDER_BOUNDARY {
  python3 /run/sbxr-qualification/recorder-boundary.py admission \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
recorder_pid=$RECORDER_BOUNDARY_PID
exec {recorder_read}<&"${RECORDER_BOUNDARY[0]}"
exec {recorder_write}>&"${RECORDER_BOUNDARY[1]}"
IFS= read -r RECORDER_HELD <&"$recorder_read"
printf '%s\n' "$RECORDER_HELD" > "$SBXR_OPERATOR_EVIDENCE_DIR/13-admission-held.json"
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
printf '%s\n' "$RECORDER_FINAL" > "$SBXR_OPERATOR_EVIDENCE_DIR/13-admission-final.json"
```

For a second, distinct invocation, open `/run/lock/sbxr.lock` in a separate root
process without symlinks and hold the same BSD `flock(2)` exclusive lock used by
SBXR. In the second pre-existing root SSH control session, run:

```sh
python3 /run/sbxr-qualification/hold-flock.py /run/lock/sbxr.lock \
  --timeout 60 | tee "$SBXR_OPERATOR_EVIDENCE_DIR/13-whole-host-lock.json"
```

After its `held` record, start the official service again from the original
control session while that lock remains held:

```sh
systemctl start --no-block snap.certbot.renew.service
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
python3 /run/sbxr-qualification/route-control.py inject \
  > /run/sbxr-qualification/15-route-injected.json
```

Run the packaged
zero-argument menu and View details. It must report `Problem detected` for the
effective managed-renewal route and explicitly leave the historical outcome
unknown. This observation proves detection after drift; it does not prove that a
new route could never execute.

Restore through the same helper:

```sh
python3 /run/sbxr-qualification/route-control.py restore \
  > /run/sbxr-qualification/15-route-restored.json
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
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt identity-precommit --timeout 90
# retain the required outside/process observations while interrupted
python3 /run/sbxr-qualification/transition-operator.py \
  recover identity-precommit --timeout 90
```

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

Use the exact forward-side revocation boundary and later recovery commands:

```sh
python3 /run/sbxr-qualification/transition-operator.py \
  interrupt identity-postcommit --timeout 90
# retain the required outside/process observations while interrupted
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
python3 /run/sbxr-qualification/firewall-control.py add "$PUBLIC_IPV4" \
  > /run/sbxr-qualification/18-firewall-added.json
```

Immediately verify exactly one such rule with `iptables-save`. Prove both outside
link retrieval and local public-IP HTTPS fail, while independent TCP 443 proxy
traffic and outside-target health remain good. Certificate bytes and healthy
renewal history must not change.

Run reviewed `Rotate Client Identity` to completion. Prove old session/process
termination, old and fresh old-credential refusal, replacement proxy traffic,
and the separate subscription status fault. Because the link is unavailable,
use the menu's separately confirmed `Show client configuration`; never read the
configuration file as a client-delivery shortcut.

Delete exactly one qualification rule and require byte-for-byte restoration of
the original filter table:

```sh
python3 /run/sbxr-qualification/firewall-control.py remove \
  > /run/sbxr-qualification/18-firewall-restored.json
```

Review `Repair subscription`; its plan must say runtime-only
serving repair. Confirm once. Prove no Certbot child, no issuance, unchanged
certificate lineage, restored same-link retrieval, and healthy proxy.

Append the identity prefix and:

```text
owned-process-groups-and-descendants-terminated old-new-connections-refused
replacement-traffic-proved subscription-fault-reported-separately
unavailable-subscription-fallback
```

On any early failure, remove only that exact qualification rule before supported
product cleanup and retain the removal observation.

## 19 — `lifecycle-menu`

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
  python3 /run/sbxr-qualification/managed-hold.py \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
managed_pid=$MANAGED_HOLD_PID
exec {managed_read}<&"${MANAGED_HOLD[0]}"
exec {managed_write}>&"${MANAGED_HOLD[1]}"
IFS= read -r MANAGED_HELD <&"$managed_read"
printf '%s\n' "$MANAGED_HELD" > "$SBXR_OPERATOR_EVIDENCE_DIR/20-managed-held.json"
```

Prove child executable/arguments/cgroup/PID/boot ID/start tick and the matching
live recorder receipt. Hash every owned product resource.

Open the zero-argument menu, review `Complete removal`, and enter the exact
`REMOVE SBXR` confirmation. It must refuse within the bound because active
Certbot is proved; no resource hash, service state, link, certificate,
configuration, package, account, or firewall rule may change. Interrupt through
the coordinator and retain its final record:

```sh
printf 'interrupt\n' >&"$managed_write"
IFS= read -r MANAGED_FINAL <&"$managed_read"
exec {managed_write}>&-
exec {managed_read}<&-
wait "$managed_pid"
printf '%s\n' "$MANAGED_FINAL" > "$SBXR_OPERATOR_EVIDENCE_DIR/20-managed-final.json"
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
  python3 /run/sbxr-qualification/recorder-boundary.py writer \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
recorder_pid=$RECORDER_BOUNDARY_PID
exec {recorder_read}<&"${RECORDER_BOUNDARY[0]}"
exec {recorder_write}>&"${RECORDER_BOUNDARY[1]}"
IFS= read -r RECORDER_HELD <&"$recorder_read"
printf '%s\n' "$RECORDER_HELD" > "$SBXR_OPERATOR_EVIDENCE_DIR/21-writer-held.json"
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
printf 'release\n' >&"$recorder_write"
IFS= read -r RECORDER_FINAL <&"$recorder_read"
exec {recorder_write}>&-
exec {recorder_read}<&-
wait "$recorder_pid"
printf '%s\n' "$RECORDER_FINAL" > "$SBXR_OPERATOR_EVIDENCE_DIR/21-writer-final.json"
```

Then prove healthy Running.

Append:

```text
active-writer-proved removal-refused owned-resources-preserved
```

## 22 — `remove-admission-race`

First open a zero-argument menu and reach the displayed Complete removal review,
but do not submit `REMOVE SBXR`. Separately start the admission coordinator:

```sh
coproc RECORDER_BOUNDARY {
  python3 /run/sbxr-qualification/recorder-boundary.py admission \
    "$CERTBOT_INTERPRETER" "$CERTBOT_INTERPRETER_SHA256" --timeout 90
}
recorder_pid=$RECORDER_BOUNDARY_PID
exec {recorder_read}<&"${RECORDER_BOUNDARY[0]}"
exec {recorder_write}>&"${RECORDER_BOUNDARY[1]}"
IFS= read -r RECORDER_HELD <&"$recorder_read"
printf '%s\n' "$RECORDER_HELD" > "$SBXR_OPERATOR_EVIDENCE_DIR/22-admission-held.json"
```

Require it to hold the real recorder after whole-host release while shared
renewal admission remains held. Prove those two BSD flock states through
`/proc/locks`, plus PID/executable/start tick and receipt.

Only then submit the removal confirmation in the original menu session. The
prepared review must be revalidated and refuse because writer admission won the
race. Compare all owned resource hashes and service states. Release the recorder,
then retain its final record:

```sh
printf 'release\n' >&"$recorder_write"
IFS= read -r RECORDER_FINAL <&"$recorder_read"
exec {recorder_write}>&-
exec {recorder_read}<&-
wait "$recorder_pid"
printf '%s\n' "$RECORDER_FINAL" > "$SBXR_OPERATOR_EVIDENCE_DIR/22-admission-final.json"
```

Require its real outcome and return to healthy Running.

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
  python3 /run/sbxr-qualification/directory-locks.py
}
IFS= read -r LOCK_HOLDER_JSON <&"${CERTBOT_LOCKS[0]}"
printf '%s\n' "$LOCK_HOLDER_JSON" \
  > /run/sbxr-qualification/23-lock-holder.json
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

Create a new unprivileged qualification account with no supplementary groups and
a private empty runtime directory. From that account, attempt read-only opens of
the subscription token, Ownership Record, configuration, certificate private
material, collector manifest, transport credential and retained private pipes;
every protected open must fail. Root must separately prove canonical and staged
objects are regular, one-link, expected owner/mode, and in their intended
directory. Remove only the qualification account/runtime after capture.

Scan, without printing secret matches, all retained VPS captures, journals,
workflow logs, Mac captures, outside-runner logs, terminal scrollback export,
`/proc/*/cmdline`, relevant systemd `ExecStart`/environment, and process
environments. Search for every exact known private key, every old/new Client UUID,
every old/new subscription credential, private-key headers, and Authorization
headers. A missing capture or unreadable required surface is `capture coverage
incomplete`, not a clean scan.

Prove qualification-only tokens, FIFOs, tmpfs client files, helper processes,
temporary accounts and captures containing protected material are absent.
Preserve unrelated user data and system services. Append secret checks:

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
