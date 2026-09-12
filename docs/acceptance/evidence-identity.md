# Identity transition evidence (scenarios 16–18)

This is historical V4 material. Its producer was retired from the working tree;
retrieve its source from [commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator)
when interpreting a named V4 record.

`identity-evidence.py` is the assembler adapter for `identity-precommit`,
`identity-postcommit`, and `identity-unavailable`. It returns only family-owned
sources. The shared assembler supplies `entry`, `state`, and `route` from the
independently typed operator capture, scenario clock, and effective-route
receipt.

The adapter exposes:

```python
rules(timing, scenario) -> tuple[ObservationRule, ...]
sources(context) -> dict[str, EventSource]
```

Rules are the ten `later_common_rules()` followed by the eight ordered identity
prefix checks and the scenario suffix from the qualification procedure. Every
rule has an authenticated source event on both sides of its accepted time
interval. The adapter does not turn labels, operator prose, or a successful
exit status into an observation.

## Outside handoff

On the VPS, invoke the entry helper. It runs the installed public `Show client
configuration` action and its confirmation itself, and consumes that process's
output through a private pipe. It accepts no client JSON from stdin.

```sh
python3 identity-entry.py prepare identity-precommit
```

The helper preserves `SCENARIO_START`, binds the current manifest and request,
stores the disclosed client file as mode 0600, and publishes
`identity-transition-outside-request.json`. Its schema is
`sbxr-v4-identity-transition-outside-request-v1` with exactly:

```text
schema scenario_id qualification_manifest_sha256 request_sha256 deadline_unix
request_id operator_directory state_directory source_configuration_sha256
```

The outside-runner command is:

```sh
python3 identity-transition-outside.py run \
  --config /absolute/path/to/mode-0600-config.json \
  --scenario identity-precommit
```

The exact config keys are `host`, `ssh_key`, `known_hosts`,
`remote_state_dir`, `remote_request`, `remote_manifest`, `manifest`, `request`,
and `outside_runner_id`. Paths are absolute. The helper downloads and verifies
the declared official outside-client package, establishes one old TLS session
before the reviewed action, and publishes `<scenario>-outside-ready.json`.
`transition-operator.py` refuses to launch the action without that current
ready receipt.

At the selected durable boundary the controller publishes
`<scenario>-action.json` (`sbxr-v4-identity-transition-action-v1`), binding the
ready receipt and exact source/target configuration digests. The outside runner
then distinguishes EOF/reset of the established session from a timeout or HTTP
failure, makes one fresh old-credential attempt, checks the direct target, and
publishes `<scenario>-outside-closed.json`. Recovery refuses until that exact
receipt is present, so it cannot race ahead of the interrupted termination and
refusal observation. The outside runner then
exercises the final selected configuration. Postcommit and unavailable flows
must provide the replacement only through a separately confirmed disclosure:

```sh
python3 identity-entry.py selected identity-postcommit
```

Precommit refuses this command, so the replacement cannot be disclosed or
tested. Its successful final request uses the restored source configuration.

## Retained source files

Copy the protected controller and outside receipts into the scenario source
directory using these names:

```text
identity-controller.json
identity-outside-ready.json
identity-outside-closed.json
identity-outside-result.json
identity-private.json
identity-runtime.json
```

Scenario 18 additionally requires `identity-subscription.json` and
`identity-repair.json`. The last four names use
`sbxr-v4-captured-source-v1` and must be produced by the current-request capture
wrapper with helper identities `identity-private-observation`,
`identity-runtime-observation`, `identity-unavailable-subscription`, and
`identity-unavailable-repair`. Each event is exactly
`{"observed_at": ..., "record": {"event": ..., "result": "observed",
"facts": {...}}}`. The adapter requires the complete event set and exact typed
facts; hand-written pass documents and omitted runtime observations refuse.

The capture wrapper runs the bundled producers directly:

```sh
python3 capture-source.py --helper identity-private-observation \
  --output "$SCENARIO_SOURCE_DIRECTORY/identity-private.json"
python3 capture-source.py --helper identity-runtime-observation \
  --output "$SCENARIO_SOURCE_DIRECTORY/identity-runtime.json"
python3 capture-source.py --helper identity-unavailable-subscription \
  --output "$SCENARIO_SOURCE_DIRECTORY/identity-subscription.json"
python3 capture-source.py --helper identity-unavailable-repair \
  --output "$SCENARIO_SOURCE_DIRECTORY/identity-repair.json"
```

The first two helpers read the protected baseline, controller, Ownership
Record, confirmed disclosure, canonical configuration bytes, and actual staging
paths themselves. The unavailable subscription helper reads the installed
qualification rule, outside ready receipt, pre-action local outage receipt,
current public status, active proxy unit, and confirmed fallback disclosure.
The repair helper reads the add/remove firewall receipts, current filter table,
certificate/serving lineage, issuance-log count, process table, reviewed plan,
public result, active proxy, and outside same-link receipt. They accept no
caller-supplied pass flags.

The private observation binds unchanged Subscription Link and noncredential
client fields while proving source and target credentials differ. Runtime
observation proves either source restoration plus absent unused target, or one
forward target plus absent staging and no source restoration.

For scenario 18, retain `firewall-control.py add` output before the action and
`remove` output after it. The add receipt records one rule and its installation
time. Removal records zero qualification rules, the original filter digest,
the restored digest, and restoration time; those digests must agree. The
subscription capture must observe outside and local-public HTTPS failure while
TCP 443 proxy traffic stays healthy and certificate bytes stay unchanged. The
repair capture must bind the reviewed runtime-only plan, no Certbot child, no
issuance, unchanged lineage, same-link recovery, healthy proxy, and exact
firewall restoration.

After firewall restoration and the reviewed repair, store the confirmed public
Subscription Link/configuration envelope for the already-running collector:

```sh
bash /run/sbxr-qualification/scenario-subscription-input.sh identity-unavailable final
```

The collector's identity runner waits for `18-subscription-final.json` after
publishing its proxy result. It calls `identity-repair-outside.py` on that same
outside host, verifies the original link, trusted TLS, artifact and certificate,
and writes `identity-unavailable-repair-outside.json` back to the VPS. Wait for
that receipt before capturing `identity-unavailable-repair`. The producer binds
the original request and declared runner; it has no standalone stdin-only CLI.

`transition-operator.py` writes
`sbxr-v4-identity-transition-controller-v1`. It retains the actual action
process identity, five ordered startup observations, source-quiescent or
source-revoked checkpoint, direction, source/target digests, and action times.
Scenario 16 accepts only the cancellation code and source authority. Scenario
17 never restores the source and accepts only forward completion. Scenario 18
uses the normal rotation code and keeps the subscription fault and repair as
separate sources.

These helpers provide mechanism and strict evidence validation. They do not
constitute VPS, outside-network, SSH, client, certificate, or owner acceptance
until the real protected receipts are collected and the complete assembler and
Go validator accept them within the original 1800-second window and 300-second
validation grace.
