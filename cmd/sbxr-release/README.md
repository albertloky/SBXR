# Release qualification stages

`cmd/sbxr-release` builds release assets and evaluates release qualification.
The qualification code is divided by stage while retaining the established
declarations and wire formats.

| Stage | File | Responsibility |
|---|---|---|
| Dispatch and canonical JSON | [qualification.go](qualification.go) | Routes qualification work and owns shared canonical document handling. |
| Candidate | [qualification_candidate.go](qualification_candidate.go) | Candidate preflight and draft construction. |
| Boundary | [qualification_boundary.go](qualification_boundary.go) | Signed-manifest and native-approval boundary checks. |
| Legacy live records | [qualification_legacy_live.go](qualification_legacy_live.go) | Installer-Updater and first-V3 historical record readers and shared record shapes. |
| Publication | [qualification_publication.go](qualification_publication.go) | Stable publication and no-update evaluation. |
| Failure | [qualification_failure.go](qualification_failure.go) | Failure and withdrawal records. |
| Scope and recurring evidence | [qualification_scope.go](qualification_scope.go), [qualification_recurring.go](qualification_recurring.go) | Scope selection and recurring/historical live evidence validation. |
| Ordinary live evidence | [qualification_mvp.go](qualification_mvp.go) | The five policy-specific HTTPS/HTTP journeys and exact-source packaged update/recovery checks. |
| Declaration and exception | [qualification_declaration.go](qualification_declaration.go), [qualification_exception.go](qualification_exception.go) | Attempt declarations and the explicit Owner exception. |
| Late human confirmation | [qualification_late_confirmation.go](qualification_late_confirmation.go) | Exact r24 archival supplement; does not grant release eligibility or emit an Acceptance Record. |
| live89 operator-recording correction | [qualification_live89_correction.go](qualification_live89_correction.go) | Accepted prior HTTP evidence for only fresh v3.1.90/168, with unchanged product source/payloads and preserved original failure/burn. |

The current scope is `subscription-clean-install-only`, with
`sbxr-subscription-update-v1`, explicit empty support/attempt sources and
`mvp-http-live-v1`. The five HTTP journeys produce a clean-install-only Acceptance
Record; verified public history remains a publication baseline, not an incoming
source. The historical repair scope's exact baseline is unchanged. See
[ADR-0028](../../docs/adr/0028-clean-install-only.md).

The current producer is the ordinary collector described in
[HTTP subscription acceptance](../../docs/acceptance/http-subscription-live.md).
The HTTPS policies retain their meaning in
[ordinary recurring acceptance](../../docs/acceptance/ordinary-recurring-live.md),
with the retained [five-journey procedure](../../docs/acceptance/mvp-live-acceptance.md).
Historical V4 producer code is retired; its records remain readable through the
current validators and the source can be retrieved from commit `0859e96`.

## Approved r24 supplement

The `qualification` JSON interface also accepts stage
`mvp-late-confirmation-supplement`. Supply canonical JSON with exactly `evidence`,
`exception_id`, `schema`, and `stage`; each evidence item has `content` (the exact
archived JSON text) and `name`. The implementation pins the closed set of names
and content hashes. The secret-safe fixture under
`testdata/r24-late-confirmation.json` contains the approved historical inputs.

From the repository root:

```sh
go run ./cmd/sbxr-release qualification < cmd/sbxr-release/testdata/r24-late-confirmation.json
```

This returns `accepted-supplement`, not `accepted`. The output is bound to the
input digest, preserves the failed run/burn, and grants no actions. It cannot be
supplied as a successful live result to stable preflight. See
[ADR-0024](../../docs/adr/0024-r24-late-confirmation-supplement.md) for the exact target-bound
new-target applicability and release-integration boundary. No GitHub workflow
automatically invokes this stage or promotes its output.

The integrated exception is restricted to v3.1.81/159. Its signed
`late_confirmation_review` is generated from committed Git inputs by
`.github/scripts/late-confirmation-review.py` and rechecked in the workflow.
`owner-exception-result` additionally requires the exact canonical archival
supplement and matching historical package/host/client declarations. It emits an
explicit reuse record, not fresh live scenarios. Normal native qualification,
attestations, burns and separate publication approval still apply. Public readers
and stable finalization understand the same bounded profile.

## Approved live89 operator-recording correction

Stage `live89-evidence-correction-result` is restricted to fresh v3.1.90/168.
Its signed `live89_correction_review` binds the tested live89 base, approved
archive, unchanged installed source/build tree, policy diff and exact fresh
target. The workflow independently reproduces the source review and proves both
unstamped executable payload digests in fresh native builds. The stage checks
the complete closed set of pinned archival contents and the new signed boundary;
it does not accept caller-supplied replacement pins or an Owner exception.

The approved inputs are retained in `testdata/live89-correction.json`.
`.github/scripts/live89-correction-review.py` reproduces the exact Git source
review; its `payload ARCHIVE` mode verifies the fresh archive's canonical
identity trailer and its pinned unstamped payload. The target must be the
reviewed committed source, rather than the current dirty working tree.

The resulting ordinary clean HTTP Acceptance Record retains the four original
scenario references and a fifth reference to the approved correction bundle.
Explicit provenance discloses reused live89 evidence, the original failed
workflow/burn, actual timestamps and null callback, and no fresh live run. New
release identity stamps and asset/index/installer metadata differ. Installed
product and public readers remain unchanged; fresh native checks, attestations,
normal failure/burn handling and separate stable-publication approval remain.
See [ADR-0029](../../docs/adr/0029-live89-operator-recording-correction.md) for the
exact applicability and audit boundary.
