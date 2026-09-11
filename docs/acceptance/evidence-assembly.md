# Scenario 07 and 08 evidence assembly

`assemble-evidence.py` formats retained `identity-absent` and
`enable-schema1` evidence into the existing `v3-scenario-result` Go wire
contract. It performs no network or live-system operation. Run it only after
the scenario entry scripts have produced and checked their private receipts.

All input paths must be absolute, one-link, non-symlink, mode-0600 regular
files. The validator must be a mode-0700 regular file and its SHA-256 must be
passed explicitly. JSON inputs are limited to 1,000,000 bytes. The compiled
validator has a separate 64 MiB limit.

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
```

The separate operator capture file must contain the exact reviewed capture
bytes. Its SHA-256 must equal both the receipt-level digest and every
observation digest.

The final proof uses schema
`sbxr-v4-scenario-07-08-observation-input-v2`. It has exactly `schema`,
`scenario_id`, `operation_id`, `link_id`, `completed_at`, and `observations`.
`link_id` is empty in the Go scenario wire record. Each observation has the
existing exact wire shape: `check`, whole-second `observed_at`, and
`result: observed`. The assembler validates those whole-second times against
the retained full-resolution source events and does not rewrite source times.

## Inputs

Both scenario commands require:

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

The output path must be new and its parent must be a non-symlink mode-0700
directory. The assembler writes the output only after the pinned validator
returns the exact canonical accepted decision for those output bytes.
