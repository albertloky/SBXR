# Ordinary recurring live acceptance

This is the `mvp-recurring-live-v1` procedure approved in
[ADR-0025](../adr/0025-ordinary-recurring-live-acceptance.md): five ordinary MVP
journeys plus three packaged upgrade/recovery checks. **No live pass is recorded
by this procedure.** The first approved route is v3.1.81/159 to the next
candidate. A removal plus reinstall is never an upgrade proof.

The [September 25 wrapper/update incompatibility](reports/ordinary-recurring-rehearsal-stop-2026-09-25.md)
has a separately approved [child-mask repair and Linux rehearsal](reports/ordinary-recurring-umask-repair-2026-09-25.md).
Those results do not establish packaged upgrade proof or present live readiness.
The separately approved [startup cleanup repair](reports/ordinary-recurring-cleanup-repair-2026-09-25.md)
qualifies the revised wrapper/menu cancellation boundary on isolated Linux.
That clears the named startup blocker, not the native CI, fresh source/target,
host/package/CA and attended-session prerequisites below. No live pass or
operational orphan-channel deletion route is added.

The [September 26 recovery-window and menu-review repairs](reports/ordinary-recurring-recovery-window-repair-2026-09-26.md)
add exact checkpoint observations and separately approved Update/Recover
confirmation handling. Both isolated terminal/controller/observer/Recover
directions and failure cleanups pass. This clears those named local blockers,
not the native CI, fresh release/host/CA checks, attended-session availability
or new attempt authorization below. It is not packaged upgrade or live proof.

## Prepare before dispatch, not during a failing attempt

1. Refresh public release state and verify the source's immutable metadata,
   four assets, attestations, Acceptance Record, index and packaged executable.
   Initially require v3.1.81, commit
   `ed759a0ccaef5d1ffd14be5a41a0e915a6268ff7`, sequence `159`, index SHA-256
   `91782e8cebbb649971989883687911479798f2411e6c49055ed7f06dd277c27f`.
   A changed Latest is a new source decision, not permission to silently test
   another release. The publication report is not a current verification.
2. Prepare a complete declaration with support scope
   `recurring-subscription-upgrade`, contract `sbxr-subscription-update-v1`,
   `evidence_policy: "mvp-recurring-live-v1"`, one exact source with
   `ownership_schema: 2`, and matching `support.sources`. Omit Owner exceptions
   and `automated_only_scenarios`. Keep `after_snap_refresh` equal to `packages`.
   The validator requires then-current stable; it does not admit an empty or
   extra incoming source set.
3. Use this exact scenario order for the initial source:

   ```text
   source-v3.1.81-precommit
   source-v3.1.81-upgrade
   source-v3.1.81-postcommit
   mvp-install
   mvp-subscription
   mvp-credentials
   mvp-renewal
   mvp-removal
   ```

4. Run the focused qualification/reader/collector tests and the ordinary native
   regressions. Before dispatch, exercise changed controller/menu, real SSH,
   process cleanup and permission-wrapper boundaries on isolated Linux. Fixtures
   may establish those controls, not packaged upgrade or recovery proof. Do not
   fabricate a trusted target to make pre-dispatch testing possible: the actual
   unchanged source's public Update/Recover proof needs the genuinely signed
   candidate delivered through the normal trust path. A source-reader test or a
   guessed sleep then kill cannot substitute for that proof. Preserve unchanged
   source executable bytes throughout.
5. Review fresh host/package/SSH/outside-client/Karing prerequisites and actual
   CA capacity for all source preparations **and** the clean candidate's
   enablement/replacement. The old two-operation clean-install CA budget does
   not cover this expanded run. Do not assume snapshots, reused issuance, or
   protected-state copies are allowed. Keep source assets available outside the
   candidate transport so source preparation does not accidentally select the
   candidate. Review any use of the existing transport's routing controls.
6. Review [log-parent prerequisites](mvp-protected-log-parent-2026-09-19.md)
   where applicable. Its earlier qualification does not prove the new
   interruption/wrapper combination: killing the wrapper instead of the product
   would not prove the intended update boundary or safe permission restoration.
7. Have the operator, outside client and Karing available for one planned session,
   including the final client/secret cleanup. The six-hour transport and hosted
   job limits remain. Seven 30-minute ceilings, a two-hour Karing ceiling and
   submission windows cannot all be consumed within that session: budget the
   real rehearsed journey times, signing/handoff, source preparations and cleanup.
   Do not dispatch if the plan does not fit. Do not lengthen deadlines to save
   a failed attempt.

Use the existing `v3-candidate-dispatch.sh check|dispatch` path only after these
prerequisites and the concrete live authorization are satisfied. Do not restore
the retired V4 producer or invoke its old readiness checklist.

## Execute and observe the exact source route

The collector immediately issues each timed request; preparations and human
availability must account for that. Start an observation only after reading the
current request and before the named update/journey. Source scenario `Running`
states describe the update's precondition and verified result, not an assertion
that separate source preparation/removal never happened. Preparatory work must
not be used to borrow observations from a different attempt.

1. **Precommit:** install/setup the exact source through its supported package,
   establish a healthy subscription and outside access, and prove the actual
   installed pair. Through its reviewed public Update, observe an interruption
   while durable update authority still selects rollback. Use that unchanged
   source's public Recover. Require exact prior executable/Installed Record
   restoration, unchanged ownership/provenance/credentials/link, healthy outside
   access and no transaction residue. Preserve the original interruption receipt.
2. **Normal update:** from that healthy restored source, review and confirm
   Update to the exact signed candidate. Require the exact candidate installed
   pair, runtime completion, no transaction residue, unchanged ownership,
   credentials/link and proxy process, and fresh outside HTTPS/proxy traffic.
3. **Postcommit:** after reviewed removal and fresh supported source setup,
   repeat Update, this time interrupting only after actual durable commitment
   selects the candidate. Recover through the installed candidate's public
   route. Require forward runtime completion without rollback, verified serving,
   exact candidate pair, no residue, unchanged ownership/provenance/credentials/
   link and proxy runtime, and fresh outside access.
4. Use reviewed Complete removal to prepare the clean candidate journey; prove
   owned absence before installation. Follow all five
   [ordinary MVP journeys](mvp-live-acceptance.md#observing-the-journeys), including
   its exact-candidate SSH check and certificate replacement procedure. Finish
   with the candidate removed and test-client/secret cleanup actually observed.

The request lists the required checks. Observe each one; the collector does not
do the work. Keep private credentials out of observations and committed reports.
Unexpected failure, missed boundary, unexplained drift or incomplete cleanup
stops the attempt. Preserve the original failure and keep safety cleanup separate.
Neither recovery after an unexpected failure nor a late human reply rescues its
qualification result.

## Controlled update interruption

The following is the reviewed invocation after the startup cleanup repair.
It is not authorization to skip the pre-dispatch gates above.

Use the reviewed `mvp-update-interrupt.py` only for the two named source
interruption requests, not the normal update. It observes the real product's
successful `fsync` of `/var/lib/sbxr`, with the mutating thread still stopped at
syscall exit. It requires the exact schema-2 checkpoint and bound material,
then kills only traced product threads/children. It neither changes syscall
results nor writes/reconstructs any product authority. Missed boundaries,
refusals and deadline/cancellation are failures, not successful interruptions.

Before the live session, stage its reviewed source bytes as root:root `0600`
at `/root/sbxr-update-control/mvp-update-interrupt.py` inside a new protected
`0700` directory. Keep the existing four-file menu directory unchanged; the
controller imports its already reviewed `v3-menu-session.py`. Verify all staged
hashes against the exact checkout. This is an operator controller, not a helper
updater or an installed product replacement. Remove its staging at final cleanup.

Prepare a private expectation JSON containing exactly these five SHA-256 fields:

| Field | Independently reviewed input |
|---|---|
| `prior_executable_sha256` | Installed executable matching the verified source package |
| `prior_installed_record_sha256` | Exact verified source Installed Record bytes |
| `candidate_executable_sha256` | Extracted executable from the genuinely signed, verified candidate package |
| `candidate_installed_record_sha256` | Exact schema-1 candidate Installed Record serialization used by the updater, including its final newline |
| `ownership_sha256` | Current proved source Ownership Record bytes |

Do not take expected candidate hashes from newly observed staging to make them
match. Bind the candidate record to the signed manifest's repository, tag,
commit, release-index hash, sequence, architecture and verified executable hash.
This expectation is an observation comparison, not a substitute trust authority.

After fresh request, source, package, log-parent and idle-writer checks, invoke
over the reviewed SSH connection with the current request exported. For example,
the precommit request uses:

```sh
export SBXR_QUALIFICATION_REQUEST=/root/sbxr-qualification-evidence/request.json
python3 /root/sbxr-update-control/mvp-update-interrupt.py precommit \
  --expectation /root/sbxr-update-control/expected.json \
  --transcript /root/sbxr-update-control/precommit.transcript \
  --timeout 900 --protected-log-parent
```

For postcommit select `postcommit` and a fresh transcript/expectation. The
original request deadline caps the whole invocation; neither initial hashing
nor wrapper startup extends it. Both controlled and ordinary launcher paths
give only the product child `umask 022` while preserving private wrapper files.
Require exit 0, the matching interruption receipt, dead product processes, and
the wrapper's original-mode restoration before subsequent outside observations
or public Recover. The controller does not authorize or execute recovery itself.
Before that separate Recover window, use the source-owned observer's
[`recovery-precommit` / `recovery-postcommit` phase](mvp-protected-log-parent-2026-09-19.md#controlled-update-recovery-windows)
with the same independently reviewed five-field expectation and the verified
manifest digest. Do not mislabel the interrupted transaction as `running`:
Prepared deliberately retains the exact two-link prior executable. Only the
proved bound relationship is admitted; other files keep their one-link rules.
After successful public Recover, use the normal `running` observation, including
transaction-residue absence, before continuing the journey.
On failure preserve the transcript/checkpoint and assess legal cleanup; use the
existing explicit wrapper restoration only after its quiescence checks pass.

The isolated syscall fixture is not execution of packaged Update/Recover or a
power-loss simulation. Actual source/candidate public recovery and outside
traffic remain mandatory live observations.

## Record observations when they happen

The existing JSON handoff remains supported. Prefer the small repository-owned
recorder to avoid hand-editing timestamps. It does not drive the product, assert
checks on its own, or accept caller-supplied times. It binds a private draft to
the exact request bytes and refuses stale requests, duplicate checks, incomplete
submission, expiry and overwritten evidence.

From the reviewed checkout, with the authenticated `acceptance_host` and
`ssh_options` array (no `-n`/`StdinNull=yes`), stream the recorder without staging
another host helper:

<!-- mvp-incremental-observer-ssh -->
```sh
mvp_observe() {
  ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
    "${ssh_options[@]}" "$acceptance_host" python3 - "$@" \
    --request /root/sbxr-qualification-evidence/request.json \
    --draft /root/mvp-observation-draft.json \
    < .github/scripts/mvp-observe.py
}
mvp_observe start
mvp_observe status
```

After **actually observing** one required outcome, record that check immediately:

```sh
# Example for mvp-install only, after the packaged installation was observed:
mvp_observe observe --check packaged-install
```

Never loop over the checklist to mark everything observed. For human-only
observations, wait for the actual observation/confirmation and record its real
time. Arrange that availability before dispatch, not after the deadline.

After all required outcomes and the journey's cleanup are actually observed:

```sh
mvp_observe finish --output /root/sbxr-qualification-evidence/observation.json
```

`finish` seals the draft before atomically publishing mode-0600 observation JSON.
The collector still assembles and validates it with the real release validator
before submission. Require its accepted scenario receipt; file creation is not
acceptance. After acceptance, remove only this sealed draft before the next
journey. If publication/transport is interrupted, inspect the sealed draft,
output and collector receipt instead of rerunning `finish` or editing times.
The final Acceptance Record requires all eight scenarios; no prefix can publish.

## What establishes completion

The implementation/reader tests establish format compatibility only. The actual
fresh packaged run must produce an ordinary accepted eight-scenario record,
with no Owner exception or reused live evidence. Stable publication requires
its separate approval and all existing rechecks. Record implementation,
regression, isolated Linux rehearsal and real live results separately.
