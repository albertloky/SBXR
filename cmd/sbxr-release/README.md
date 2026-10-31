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
| Publication recovery | [qualification_publication_recovery.go](qualification_publication_recovery.go) | Authenticated prepublication recovery, preserved burn history and original failed-record audit. |
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
Candidate dispatch accepts one V3 candidate; the normal/rescue two-release
producer is retired. Stable replay still reads historical manifests, records
and checklist bytes from their original Git revisions.
Historical HTTPS, recurring and V4 records remain readable through the existing
validators. Retired procedures and producer source remain in Git history; they
add no source-update or certificate journeys to the current HTTP scope.

## Public release verification

`verify-public-latest` checks canonical Latest through the production GitHub
Adapter. Repository-only `verify-public-release -tag vX.Y.Z` applies the same
checks to an exact immutable public stable tag for failure cleanup; it does not
change installed-software discovery. Both emit the existing `outcome`,
`release_identity` and `sequence` JSON fields. A refused or unavailable result
still exits successfully when the result was written, so callers must require
`outcome: accepted` and the expected full identity and sequence.

[ADR-0031](../../docs/adr/0031-equivalent-native-release-proofs.md)
permits equivalent native proofs while retaining signature and byte checks.
This verification policy does not qualify a live release.

## Qualified publication and retry

Successful required tests and cleanup qualify the exact unchanged candidate for
stable publication under [ADR-0032](../../docs/adr/0032-qualified-publication-retry.md).
After the Owner approves publication, explicitly dispatch `stable.yml` with the
successful `qualification_run_id`. The workflow binds the verified facts and decision
automatically, without a separate `stable-publication` environment ceremony or
another `acceptance-vps` host probe. Authentication, exact asset digests and the
complete successful acceptance chain remain required on every publication attempt.
Successful completion of the official `Construct qualified drafts` workflow does
not start publication. Stable publication has only `workflow_dispatch`; the
`qualification_run_id` remains required for first publication, retry or explicit
abandonment. Main divergence still pauses for the exact review below.

A publication job failure preserves qualification and its actual failure evidence
for retry of the same candidate run. Observe the current release state first if a
request may already have succeeded. Only explicit abandonment invokes the stable
failure finalizer and burn path. No failed test or incomplete cleanup can be
converted into a pass by retrying publication.

Candidate failure decisions are proposals only: `candidate.yml` retains them and
fails without automatic draft/tag deletion, burn signing or failed-prerelease
publication. Outstanding drafts block new draft creation except the exact
source-controlled reservation described in ADR-0032. Later effects need an explicit action-time Owner decision and fresh
identity/authentication checks; there is no automatic resume switch. See
[ADR-0032](../../docs/adr/0032-qualified-publication-retry.md).

An old clean-install-only candidate already finalized as an immutable failed
prerelease can recover only with its authenticated `prepublication-failure` burn,
original complete successful acceptance chain and exact unchanged identity,
release ID and assets. The stable workflow authenticates the existing signed
qualification and burn, then archives validated recovery facts before promoting
that same release through metadata. No new signing permissions are required. Its notes contain the original
qualified Acceptance Record plus an audit footer with the complete original failed
record in base64 and its SHA-256 digest; the burn tag and signed qualification
record remain untouched. It creates no new candidate, tag, sequence or asset bytes
and needs no replacement live run when the original evidence remains complete
and applicable. Other burns and integrity failures still refuse. See ADR-0032 for
the v3.1.95/173 applicability and historical limits.

Stable preflight refusals print a fixed `stable-preflight/<gate>` name without
input values. Optional `stable-preflight-diagnostics-<run>` artifacts contain only
fixed outcome values, counts and exact input sizes/SHA-256 digests. Raw facts,
release bodies and arbitrary strings are excluded rather than trusted to a
marker-only secret scan. Collection/upload failures skip unsafe uploads and emit
a fixed warning; they cannot change the validator result or trigger a burn.
The successful verified-input artifact and provenance checks remain required.
A reconstruction using refreshed observations does not
establish the historical rejecting gate.

The qualification CLI also reports `qualification-input/<check>` for reads,
empty/oversize input, invalid or duplicate-key JSON, envelope/schema and stage;
recognized stages report `<stage>/canonical-facts` for their wire contract.
Stable publication reports `stable-publication/<check>` for approval, action
index, replay/binding, history and observation failures, retaining a nested
`stable-preflight/<gate>` when preflight replay fails. Check those exact inputs
and bindings before retrying. Numeric bounds/counts are safe to print; rejected
field values and private parser/I/O cause text are excluded. Causes remain
available through Go error unwrapping.

The generated installer keeps its existing stdout result codes and emits
`install/<check>` on stderr for host admission, download, index contract and
archive/executable integrity checks. Download diagnostics retain the asset name,
curl exit status and a three-digit HTTP status (or `unknown`), excluding curl
stderr and URLs. Expected-versus-observed labels identify the authority being
compared without exposing payloads. These diagnostics do not cover every older
qualification evaluator, publication propagation/finalization branch, installer
removal-restoration or filesystem mutation failure; some still return generic
results. They cannot reconstruct a previously unrecorded rejecting check.

### Main divergence

Stable preflight validates the existing exact qualification chain before treating
main drift as `pending-review`. Its `review-stable-release` actions retain the
candidate/assets and authorize only review. The optional `main_review` binds
`candidate_commit`, `reviewed_main`, `divergence_sha256`, `security_assessment`
and the evidence-applicability `rationale`. The helper
`.github/scripts/release-main-review.py` reproduces the committed divergence.

The workflow's `reviewed_main`, `security_assessment` and `divergence_rationale`
inputs prepare the review; its automatic `approval.decision_chain` binds the
stable-preflight facts and decision.
Publication facts carry fresh `remote_main`. Only `no-security-fixes-missing` for
the exact reviewed main can advance a divergent candidate. Further main drift or
stale review returns `pending-review` with no publication actions. The workflow
also rechecks main immediately before each publication request and skips burn and
finalization on a review pause. Failed publishing attempts preserve qualification;
explicit abandonment retains burn handling. Current publication and propagation
verification always require fresh main and the bound decision chain.
Historical accepted publication records use the explicit
`stable-publication-record-verification` stage, which takes canonical
`publication_verification_facts` and `publication_verification_decision`, returns
`accepted-record` with no actions, and cannot authorize publication or propagation.
Omitting current fields does not select that route. Historical signed records
retain their interpretation. See [ADR-0030](../../docs/adr/0030-reviewed-release-main-divergence.md)
with ADR-0032's publication and retry refinement.

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
attestations and qualification failure handling still apply. Current publication
follows ADR-0032. Public readers and stable finalization understand the same
bounded profile.

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
review; its `payload ARCHIVE FULL_COMMIT` mode verifies the fresh archive's canonical
identity trailer and its pinned unstamped payload. The target must be the
reviewed committed source, rather than the current dirty working tree.

The resulting ordinary clean HTTP Acceptance Record retains the four original
scenario references and a fifth reference to the approved correction bundle.
Explicit provenance discloses reused live89 evidence, the original failed
workflow/burn, actual timestamps and null callback, and no fresh live run. New
release identity stamps and asset/index/installer metadata differ. Installed
product and public readers remain unchanged; fresh native checks, attestations and
normal qualification failure handling remain. Current publication/retry follows
ADR-0032.
See [ADR-0029](../../docs/adr/0029-live89-operator-recording-correction.md) for the
exact applicability and audit boundary.


`candidate-reservations` validates canonical read-only GitHub observations against
the five fixed reservations and emits their exact records for `reserved_identities` in
new preflight facts. `-policy` exposes the compiled record for observation collection;
it is not an authorization result. `-allowed-draft-tags` names only the current
workflow's candidate tags for later rechecks and cannot allow the reserved tag.
The shell adapter collects metadata and explicit HTTP404 ref observations; it
performs no signing, mutation or cleanup. Missing/changed state refuses.
