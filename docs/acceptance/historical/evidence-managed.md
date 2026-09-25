# Managed scenario evidence sources

This is historical V4 material. Its producer was retired from the working tree;
retrieve its source from [commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator)
when interpreting a named V4 record.

Scenarios 11–15 use current-request captured sources. A passing observation is
accepted only when its source bytes are mode-0600 evidence in the scenario's
mode-0700 source directory, the capture wrapper binds those bytes to the signed
manifest and request, and the observation time lies within the source event
bounds. The operator capture remains the authority for human review, SSH
continuity, capture coverage, and the explicit limits reported for unsupported
routes and natural renewal.

`managed-evidence.py` supplies `rules(timing, scenario)` and `sources(ctx)` for
`managed-renewal`, `recorder-live`, `recorder-locks`, `snap-refresh`, and
`unsupported-route`. It compares retained before/final snapshots instead of
accepting check names as proof. Each `sbxr-v4-managed-snapshot-v1` record binds
the non-secret Subscription Link ID and hash, configuration and Client Identity
hashes, artifact hash, four certificate-file hashes and generation, Ownership
Record, the archive leaf's DER hash, renewal-history hash, package declaration, unrelated package and
lineage inventories, the effective timer/service/drop-in/hooks/recorder route,
quiescence, and local activation result.

The capture wrapper must allow these exact helper identities:

- `managed-evidence` for one managed snapshot record per invocation;
- `managed-hold` for scenarios 11 and 12;
- `syscall-gate` for scenario 11's actual repair pre-clear boundary;
- `recorder-boundary`, `hold-flock`, and `observations` for scenario 13;
- `route-control` for scenario 15.

Invoke the managed helper as `managed-evidence.py snapshot --phase before
--subscription <protected-subscription-observation.json>` (and `--phase final`)
for the machine snapshot and
`managed-evidence.py history` for the fixed protected recorder history. The
snapshot producer reads the protected Ownership Record, serving authority,
token, configuration, renewal history, certificate files, managed route,
package inventory, unrelated lineage inventory, service states, and BSD writer
lock directly. It rechecks the declared package phase and candidate through the
existing operator support. The history producer hashes the exact protected
source bytes before emitting the typed envelope. Run the snapshot and history
producers through `capture-source.py` so their stdout and execution interval
receive the same current-request binding.

Run `scenario-subscription-input.sh SCENARIO before` before the action. It writes
the protected initial disclosure and publishes the current-request
`managed-outside-request.json` trigger. The recurring collector verifies the
signed source checkout and matching protected source files, then launches
`renewal-outside.py run` on the manifest's signed outside runner. Wait for
`NN-outside-ready.json` before recording `action-start`. The runner proves that
its direct public IP differs from the VPS address, performs the initial
trusted-TLS/artifact request, and starts the signed outside client using the
confirmed public configuration. It establishes one TLS connection through that
client before publishing the typed ready record, probes that same connection
throughout the action, and makes a final successful request after
`action-complete`. It publishes `NN-proxy-trace.json` using the existing
`sbxr-v4-captured-source-v1` envelope and `connection-probe` helper identity;
the VPS does not launch a local proxy or recapture this outside evidence. After
`action-complete`, run `scenario-subscription-input.sh SCENARIO final`. The same
runner waits for both the request-bound action-complete record and protected
final disclosure, rechecks the unchanged request and manifest, performs the
final request, removes the temporary outside client, and publishes
`NN-outside-result.json`. The adapter consumes the
two typed records directly and requires ready before `action_started_at`, the
exact action-complete time in the result, and the final request after it.

The retained filenames are:

| Scenario | Required source files |
| --- | --- |
| 11 `managed-renewal` | `11-managed-before.json`, `11-managed-final.json`, `11-renewal-before.json`, `11-renewal-interrupted.json`, `11-renewal-repaired.json`, `11-renewal-final.json`, `11-managed.json`, `11-repair-boundary.json`, `11-outside-ready.json`, `11-outside-result.json`, `11-proxy-trace.json` |
| 12 `recorder-live` | `12-managed-before.json`, `12-managed-final.json`, `12-renewal-before.json`, `12-renewal-final.json`, `12-managed.json`, `12-outside-ready.json`, `12-outside-result.json`, `12-proxy-trace.json` |
| 13 `recorder-locks` | `13-managed-before.json`, `13-managed-final.json`, `13-renewal-before.json`, `13-renewal-final.json`, `13-admission.json`, `13-whole-host.json`, `13-wait-renewal-before.json`, `13-whole-host-wait.json`, `13-wait-renewal-final.json`, `13-outside-ready.json`, `13-outside-result.json`, `13-proxy-trace.json` |
| 14 `snap-refresh` | `14-managed-before.json`, `14-managed-final.json`, `14-renewal-before.json`, `14-renewal-final.json`, `14-outside-ready.json`, `14-outside-result.json`, `14-proxy-trace.json` |
| 15 `unsupported-route` | `15-managed-before.json`, `15-managed-final.json`, `15-renewal-before.json`, `15-renewal-final.json`, `15-route-inject.json`, `15-route-restore.json`, `15-outside-ready.json`, `15-outside-result.json`, `15-proxy-trace.json` |

Each scenario also retains private `NN-subscription-before.json` and
`NN-subscription-final.json` disclosures. `renewal-outside.py` reads them only
through protected inputs and performs a default-trust HTTPS request for each. Its
receipt retains the disclosure hashes, link/configuration hashes, initial/final
certificate hashes, signed outside runner ID, distinct direct-route result,
trusted-TLS result, artifact-field result, and event times;
it never retains the URL credential or configuration.

The renewal captures contain the actual schema-1 recorder history. The adapter
validates the recorder ID, timestamps, lineage targets, completion outcomes,
hook roles and outcomes, and ordering using the same semantics as the Go host
adapter. The snapshot hashes bind the before and final documents. Scenarios 12
and 13 append exactly one healthy `no-op` guarded attempt; exit code zero with an
`incomplete` owned outcome is refused. Scenarios 14 and 15 append none.

Scenario 11 retains two intermediate runtime documents because successful
repair clears diagnosed attempts after the replacement is published, accepted,
loaded, and freshly validated. `11-renewal-interrupted.json` must contain the
coordinator receipt named by `11-managed.json`.
`11-renewal-repaired.json` must preserve that exact prefix and append exactly
one successful owner renewal with a later generation. Only then may
`11-renewal-final.json` show the healthy cleared attempt list and later
`established_at`. These captures preserve the ephemeral receipts that Git and
the final runtime file do not retain.

Arm `syscall-gate.py` through `capture-source.py --helper syscall-gate` before
starting the reviewed zero-argument menu process. Select `after-close` on
`/var/lib/sbxr/.renewal-attempts.json.next`, with protected record
`/var/lib/sbxr/renewal-attempts.json`, field
`attempts.<N>.completion.owned_outcome`, and value `renewed`, where `<N>` is the
attempt count in the already captured interrupted history. Use the menu
process's existing cgroup and a timeout within the original request. When the
gate emits `boundary-held`, capture `11-renewal-repaired.json`, then send
`release` to the gate. The adapter requires the gate's `record_sha256` to equal
the repaired history hash and requires that history capture to lie between the
gate's held and released events. The intercepted close is the clear document's
temporary write; the protected current record still contains both receipts at
that boundary.

In the second protected root session, after retaining the interrupted history,
derive the zero-based repair index and arm the capture. Substitute the cgroup
printed by `cat /proc/self/cgroup` in the original menu session:

```sh
repair_index=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["events"][0]["record"]["history"]["attempts"]))' \
  "$SCENARIO_SOURCE_DIRECTORY/11-renewal-interrupted.json")
menu_cgroup=/the/original/session/cgroup
coproc REPAIR_GATE {
  python3 /run/sbxr-qualification/capture-source.py \
    --helper syscall-gate \
    --output "$SCENARIO_SOURCE_DIRECTORY/11-repair-boundary.json" -- \
    /usr/local/bin/sbxr "$menu_cgroup" after-close \
    /var/lib/sbxr/.renewal-attempts.json.next \
    --record /var/lib/sbxr/renewal-attempts.json \
    --field "attempts.${repair_index}.completion.owned_outcome" \
    --value renewed --timeout 120
}
repair_gate_pid=$REPAIR_GATE_PID
exec {repair_gate_read}<&"${REPAIR_GATE[0]}"
exec {repair_gate_write}>&"${REPAIR_GATE[1]}"
IFS= read -r REPAIR_ARMED <&"$repair_gate_read"
```

Run and confirm `Repair subscription` in the original session. Back in the
second session, retain the record while the clear write is stopped, then release
the exact process:

```sh
IFS= read -r REPAIR_HELD <&"$repair_gate_read"
python3 /run/sbxr-qualification/capture-source.py \
  --helper managed-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/11-renewal-repaired.json" -- history
printf 'release\n' >&"$repair_gate_write"
IFS= read -r REPAIR_RELEASED <&"$repair_gate_read"
exec {repair_gate_write}>&-
exec {repair_gate_read}<&-
wait "$repair_gate_pid"
```

Scenario 11 requires the captured `managed-hold` sequence `held` then
`interrupted`, matching renewal receipt identifiers and positive egress denial.
The snapshots must show exactly one next certificate generation, different
certificate bytes, a healthy cleared renewal history, accepted local activation,
and the same link, Client Identity, configuration, and artifact. Each snapshot
also hashes the DER form of its protected archive leaf; the outside witness must
serve that exact DER certificate at the matching before/final observation. The explicit operator
observations still record the reviewed repair choice and that neither a natural
timer firing nor a naturally due renewal was observed.

Scenario 12 requires `held` then `completed` from one guarded official-unit
invocation. Scenario 13 requires the shared-admission `boundary-held` then
`completed` sequence and a distinct whole-host `held` then `released` capture.
While that whole-host lock remains held, capture the actual recorder history,
run `observations.py flocks /var/lib/sbxr/renewal-writer.lock
/run/lock/sbxr.lock`, then capture the history again. The adapter requires the
writer flock unlocked, the whole-host flock held by the PID from
`13-whole-host.json`, and byte-identical histories on both sides of that
observation, all within the signed request action and the lock-held interval.
This proves that the status-125 wait created no receipt and held no evidence
writer lock. The final snapshot records only terminal status 125 and actual
Certbot-child absence. Both scenarios require unchanged certificate generation
and bytes, unchanged product/subscription facts, and outside health.

Scenario 14 requires the before package declaration to equal `packages` and the
final declaration to equal `after_snap_refresh`. Certbot must differ while the
effective managed route, hooks, recorder, history, certificate, unrelated
packages, and unrelated lineages remain equal and final package/Certbot/writer
activity is quiescent.

Scenario 15 binds separate route-control inject and restore captures. The
restored result must name the exact injected unit identity and timer state; the
before/final snapshots must agree on the full route and installation. The final
human observations explicitly record `Problem detected`, the accounting gap,
the bounded prevention claim, and unknown historical outcomes. They remain
explicit because the helper proves route drift/restoration mechanics and
unchanged service invocation markers, not what the packaged UI displayed.

The outside witness and connection trace are live acceptance inputs. Local unit
tests exercise producer/checker shape, ordering, binding, and refusal behavior;
they do not claim a VPS, CA, outside network, or packaged-product result.
