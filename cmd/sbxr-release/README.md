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
| MVP live evidence | [qualification_mvp.go](qualification_mvp.go) | The five `mvp-live-v1` journey checks. |
| Declaration and exception | [qualification_declaration.go](qualification_declaration.go), [qualification_exception.go](qualification_exception.go) | Attempt declarations and the explicit Owner exception. |

The current producer is the MVP collector described in
[docs/acceptance/mvp-live-acceptance.md](../../docs/acceptance/mvp-live-acceptance.md).
Historical V4 producer code is retired; its records remain readable through the
current validators and the source can be retrieved from commit `0859e96`.
