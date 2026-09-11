# Scenario 07–25 evidence assembly

`assemble-evidence.py` formats retained scenario 07–25 evidence into the existing `v3-scenario-result` Go wire
contract. It performs no network or live-system operation. Run it only after
the scenario entry scripts have produced and checked their private receipts.

All input paths must be absolute, one-link, non-symlink, mode-0600 regular
files. The validator must be a mode-0700 regular file and its SHA-256 must be
passed explicitly. Ordinary JSON receipts are limited to 1,000,000 bytes. The
signed qualification boundary may contain the retained release history and uses
the collector's existing 16 MiB evidence limit. The compiled validator has a
separate 64 MiB limit.

## Operator provenance

The preparation and observation documents are operator verification receipts.
Their hashes bind the exact files reviewed by the operator; a hash by itself
does not prove who performed a check and is not cryptographic authentication.
Do not create these receipts from unreviewed labels or infer their timestamps
from the scenario start. `observed_at` records the actual check time at full
resolution.

The preparation receipt uses schema `sbxr-v4-evidence-preparation-v1` and has
these exact fields:

- `schema`, `scenario_id`, and `prepared_at`
- `qualification_manifest_sha256`
- `qualification_boundary_facts_sha256`
- `request_sha256`
- `accepted_prior_prefix_sha256`
- `validator_sha256`
- `verifications`, in this exact order:
  `fresh-signed-manifest`, `qualification-boundary`, `pinned-validator`

Each verification has exactly `check`, `artifact_sha256`, `observed_at`, and
`result`, where `result` is `verified`. Every digest must match the exact bytes
passed to the same assembler invocation. Verification must occur within the
current request and preparation must finish no later than `entry_started_at`, the separately recorded instant immediately before the first product mutation. The original collector `started_at` remains unchanged and continues to bound the scenario and deadline.

The operator observation receipt uses schema
`sbxr-v4-operator-observations-v1` and has exactly `schema`, `scenario_id`,
`qualification_manifest_sha256`, `request_sha256`, `capture_sha256`, and
`observations`. Each observation has exactly `check`, `event`, `observed_at`,
`result`, and `capture_sha256`. The assembler prints the required check order:

```sh
python3 .github/scripts/v3-operator/assemble-evidence.py required-checks identity-absent
python3 .github/scripts/v3-operator/assemble-evidence.py required-checks enable-schema1
python3 .github/scripts/v3-operator/assemble-evidence.py required-checks link-precommit
python3 .github/scripts/v3-operator/assemble-evidence.py required-checks link-postcommit
```

The separate operator capture file must contain the exact reviewed capture
bytes. Its SHA-256 must equal both the receipt-level digest and every
observation digest.

The final proof uses schema `sbxr-v4-scenario-07-08-observation-input-v2`
for 07/08 and `sbxr-v4-link-observation-input-v1` for 09/10. It has exactly `schema`,
`scenario_id`, `operation_id`, `link_id`, `completed_at`, and `observations`.
`link_id` is empty in the Go scenario wire record. Each observation has the
existing exact wire shape: `check`, whole-second `observed_at`, and
`result: observed`. The assembler validates those whole-second times against
the retained full-resolution source events and does not rewrite source times.

## Inputs

All four scenario commands require:

```text
--manifest --boundary --request --accepted-prior-prefix
--preparation-receipt --operator-observations --operator-capture
--effective-route --state --proof
--validator --validator-sha256 --output
```

`identity-absent` also requires:

```text
--controller-receipt --outside-receipt --outside-collected
--rotation-request --rotation-ready
```

Scenario 07 finish retains the already checked outside files under these names
and removes the six original names required absent by the collector:

```text
07-retained-outside-started.json
07-retained-outside-ready.json
07-retained-outside-rotation-request.json
07-retained-outside-rotation-ready.json
07-retained-outside-collected.json
07-retained-outside.json
```

Use `07-retained-outside.json` for `--outside-receipt`,
`07-retained-outside-collected.json` for `--outside-collected`, and the two
retained rotation files for `--rotation-request` and `--rotation-ready`.
`transition-identity-absent.json` is the controller receipt.

`enable-schema1` also requires:

```text
--safe-state --connection-observation --connection-summary
--subscription-observation
```

Generate the scenario 08 outside result with `check-subscription.py --bound`, passing the secret-bearing observation document only on standard input. Its `binding` object contains exactly `scenario_id`, `qualification_manifest_sha256`, `request_sha256`, `not_before`, and `deadline_unix`. Bound output schema `sbxr-v4-subscription-check-v2` records the actual TLS check start and completion plus link, configuration, and certificate snapshot hashes. The verifier requires that interval to begin after enablement and finish inside the original request deadline.

`08-safe-state.json` binds the exact subscription receipt SHA-256, private state bytes, manifest, request,
final Ownership Record digest, Ownership Record schema and phase, safe link
identifier, subscription observation time, and completion time. The private
state remains a separate input and is never copied into the assembled facts.

`link-precommit` and `link-postcommit` also require:

```text
--controller-receipt --outside-directory
--connection-observation --connection-summary
```

For either link scenario, use `link-<scenario>-entry-final.json` for `--state`
and `transition-<scenario>.json` for `--controller-receipt`. The effective-route
receipt is `link-<scenario>-effective-route.json`. The mode-0700
`--outside-directory` must retain these mode-0600 files under their exact names:

```text
link-<scenario>-initial.json
link-<scenario>-ready.json
link-<scenario>-challenge.json
link-<scenario>-ack.json
link-<scenario>-closed.json
link-<scenario>-final.json
link-<scenario>-finalize.json
link-<scenario>-result.json
```

For example, `<scenario>` is literally `link-precommit`, so its initial file is
`link-link-precommit-initial.json`. The initial and final disclosures contain
credentials and client configuration. Keep them private for assembly; never
copy them into workflow logs or public result facts. All other link receipts
contain only identifiers, hashes, times, and observed facts.

The collector starts `link-outside.py` when the start entry publishes its
protected trigger. The outside runner proves an initial HTTP 200, acknowledges
one pending TLS request at the prepared-target hold, and records shutdown before
the service's five-second request deadline. Timeout, response data, or a TLS
failure cannot substitute for closure. The controller separately observes the
source process, cgroup descendants, listener, and accepted sockets. Unowned
kernel `TIME-WAIT` remnants are allowed; live requests are not. The postcommit
hold occurs before the first serving-token read used to publish the target,
after the committed Ownership Record is durable.

After public recovery, the finish entry publishes the final disclosure and a
finalizer bound to the recovered controller receipt. The outside runner then
requires the old URL to return 200 for precommit, or the old URL to return 404
and the new URL to return 200 for postcommit, with unchanged configuration and
certificate. Assembly validates the entire retained exchange, the original
request deadline, event order, unchanged proxy process, and the separate
action-spanning proxy connection trace and summary.

Use `operation-9` / `operation-10` in the proof. The generated wire boundaries
are `before-commitment` / `after-commitment`, with `rollback` / `forward`
recovery respectively. Operator capture observations still prove SSH continuity,
capture scans, and reviewed disclosure behavior; machine receipts do not invent
those observations. Record pre-action and interrupted-state observations before
recovery, using `required-checks` and the source events in `evidence-timing.py`.

The output path must be new and its parent must be a non-symlink mode-0700
directory. The assembler writes the output only after the pinned validator
returns the exact canonical accepted decision for those output bytes.
Scenario operations and proof completion must finish inside the original request
deadline. Retained evidence may then be assembled within the signed 300-second
validation grace after proof completion; this never permits an outside probe or
product action after the scenario deadline.

## Scenarios 11–25

For each later scenario, run `11-25-scenario-start.sh <scenario>` once, record
`scenario-entry.py action-start <scenario>` immediately before the action under
test, record `action-complete` immediately after its real result, perform the
final checks, and run `11-25-scenario-finish.sh <scenario>`. Use the resulting
`scenario-<scenario>-finish.json` as `--state` and
`scenario-<scenario>-effective-route.json` as `--effective-route`. The earlier
phase files remain protected source history; do not edit or replace them.

Use a distinct absolute mode-0700 source directory for the scenario. Populate it
only with the exact mode-0600 inputs named by the applicable guide:

- scenarios 11–15: [`evidence-managed.md`](evidence-managed.md);
- scenarios 16–18: [`evidence-identity.md`](evidence-identity.md);
- scenarios 19–25: [`evidence-final.md`](evidence-final.md).

VPS helper sources must be produced with `capture-source.py`; a handwritten
document with the same fields is not equivalent. The family adapter validates
the wrapper's helper identity, current request, execution interval, actual stdout
records, retained source bytes, and event-specific timing. Local fixtures can
exercise those validators, but they cannot provide a live VPS, outside route,
certificate, public menu, or Karing UI event.

The managed outside witnesses are the exception to helper wrapping. For
scenarios 11–15, `scenario-subscription-input.sh <scenario> before` stores
`NN-subscription-before.json` and starts the collector handoff. The collector
publishes raw `NN-outside-ready.json`; wait for it before `action-start`. After
`action-complete`, the `final` invocation stores `NN-subscription-final.json`,
and the same collector publishes raw `NN-outside-result.json` plus the captured
`NN-proxy-trace.json` from its one outside-client connection. Retain those five
exact protected files; do not run the root-only wrapper on the outside runner.
Scenario 18 permits only the restored `final` disclosure
and requires the collector-owned `identity-unavailable-repair-outside.json`
before its repair evidence is captured.

Whole-helper captures for scenarios 19 and 24 may produce an internal diagnostic
state file. The common `scenario-lifecycle-menu-finish.json` or
`scenario-secret-containment-finish.json` supplied as `--state` is authoritative.

List the exact ordered proof checks before recording operator observations:

```sh
python3 /run/sbxr-qualification/assemble-evidence.py required-checks <scenario>
```

The two lifecycle automated-only checks and the four policy-excluded Karing
checks do not appear in these live lists. Never add them to make a fixture or
proof resemble the historical policy.

All scenario 11–25 commands use the common inputs plus `--sources-directory`:

```sh
python3 /run/sbxr-qualification/assemble-evidence.py <scenario> \
  --manifest /absolute/private/qualification-manifest.json \
  --boundary /absolute/private/qualification-boundary.json \
  --request /absolute/private/request.json \
  --accepted-prior-prefix /absolute/private/accepted-prior-prefix.json \
  --preparation-receipt /absolute/private/evidence-preparation.json \
  --operator-observations /absolute/private/operator-observations.json \
  --operator-capture /absolute/private/operator-capture \
  --effective-route "/run/sbxr-qualification/scenario-<scenario>-effective-route.json" \
  --state "/run/sbxr-qualification/scenario-<scenario>-finish.json" \
  --sources-directory /absolute/private/scenario-sources \
  --proof /absolute/private/scenario-proof.json \
  --validator /absolute/private/sbxr-release \
  --validator-sha256 <exact-validator-sha256> \
  --output /absolute/private/scenario-facts.json
```

The later proof schema is `sbxr-v4-scenario-observation-input-v1`; its other fields
and observation records use the common proof contract above. `operation_id` is
the scenario's one-based position in the signed `required_scenarios` list, for
example `operation-11` only when the signed scenario at index 10 is the command
being assembled. Never infer an operation number from this document if the
manifest differs.

The signed limit is 1800 seconds for scenarios 11–24 and 7200 seconds for
`karing-final`. The Karing allowance exists for real manual UI work and the
genuinely due five-minute automatic refresh; it does not permit stale captures
or observations outside the current request. Assembly itself must still finish
within the manifest's validation grace after proof completion.

Scenario 14 is the package handoff: it starts with `packages` and finishes with
`after_snap_refresh`. Scenarios 15–25 use the refreshed packages. Scenarios
20–24 preserve `Running`; the four removal-contention scenarios have a refusal
boundary. Only scenario 25 has final state `Not installed`. The Go validator
checks those outcomes, cumulative prior hashes, exact package transition, and
ordered evidence before accepting the output.
