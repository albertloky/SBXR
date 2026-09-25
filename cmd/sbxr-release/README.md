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
| Ordinary live evidence | [qualification_mvp.go](qualification_mvp.go) | The five `mvp-live-v1` journeys and `mvp-recurring-live-v1` packaged update/recovery checks. |
| Declaration and exception | [qualification_declaration.go](qualification_declaration.go), [qualification_exception.go](qualification_exception.go) | Attempt declarations and the explicit Owner exception. |
| Late human confirmation | [qualification_late_confirmation.go](qualification_late_confirmation.go) | Exact r24 archival supplement; does not grant release eligibility or emit an Acceptance Record. |

The current producer is the ordinary collector described in
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
