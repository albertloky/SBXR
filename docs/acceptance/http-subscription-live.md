# HTTP subscription live qualification

Use [ADR-0026](../adr/0026-http-subscription.md) for this checkout's fresh HTTP
subscription behavior. This procedure specifies evidence; it neither reports a
live pass nor authorizes live operations or publication.

The current direction is [clean installation only](../adr/0028-clean-install-only.md).
Declare `mvp-http-live-v1` with support scope `subscription-clean-install-only`,
contract `sbxr-subscription-update-v1`, `support.sources: []` and `sources: []`.
Omit Owner exceptions and `automated_only_scenarios`. Preserve signed attempt,
unchanged candidate assets, verified release-history baseline, runner/package
facts, request/hash chain, actual observations and validation/submission deadlines.
The baseline is release-order evidence, not a source to install. Historical repair
scope keeps its original baseline/history restriction.

Only v3.1.90/168 may use the approved
[live89 operator-recording correction](../adr/0029-live89-operator-recording-correction.md).
Its signed `live89_correction_review` and dedicated correction-result stage bind
the exact accepted v3.1.89 archive, unchanged product/build source and identical
unstamped executable payloads. It records reused evidence with the original
failed workflow and burn intact, performs no new live journey and requires fresh
native qualification, attestations and separate stable-publication approval.
It is distinct from an Owner exception; all other candidates use this procedure.

Use exactly these five journeys in order:

1. `mvp-install`: prove owned absence, then clean packaged candidate install/setup
   and genuinely outside REALITY proxy traffic. Exercise lifecycle status and
   Check/Update refusal without replacement. An already absent host needs no old
   source setup or removal.
2. `mvp-subscription`: confirm HTTP enablement and its interception/tampering
   disclosure. Prove outside authenticated HTTP on the emitted TCP 8443 link,
   exact one-node REALITY artifact, wrong-token refusal, protected local files
   and secret-safe captures, no certificate/renewal resources or Certbot install,
   actual Karing import, fresh node latency, manual refresh, and preserved
   selected client connection/settings.
3. `mvp-credentials`: retain all existing Client Identity/session revocation,
   replacement traffic, unchanged-link refresh, link rotation/old-link rejection
   and fresh Karing replacement-latency evidence.
4. `mvp-serving`: restart only the owned serving service through the supported
   ordinary systemd route. Verify the unchanged link and current artifact,
   outside authenticated HTTP, no certificate or renewal resources, and working
   proxy traffic. Do not manufacture a certificate replacement observation.
5. `mvp-removal`: retain ordinary restart/access proof, reviewed Complete
   removal, exact owned absence and outside rejection, unrelated-resource/SSH
   preservation, and actual client, process, capture and secret cleanup.

The collector emits the exact policy-specific checklist. Use the existing
`mvp-observe.py` recorder and `v3-mvp-evidence.py` assembler with original
timestamps and facts; never convert an old HTTPS observation into HTTP proof.
The public Acceptance Record explicitly discloses HTTP and its lack of transport
protection. Its normal immutable release/attestation trust remains required.

## Existing state and certificate capacity

There are no incoming sources or source upgrade/recovery journeys in this scope.
New Update and automatic legacy HTTPS migration are unsupported. An existing
installation requires its exact release's reviewed removal and interrupted-removal
recovery before fresh setup. The installer must refuse remaining authority or
resources; exact same-release no-op and proved removal-finisher restoration retain
their existing meanings.

Fresh HTTP enablement and serving restart obtain no subscription certificates.
The two legacy HTTPS preparations and their CA wait belonged to the discarded
source route. Do not install the old source merely to uninstall it on an absent
host. Retain relevant transaction, setup, rotation and removal recovery regressions
as ordinary tests. The historical recurring policies remain readable and are not
qualification claims for the current product.

Before recommending Latest, prove that the unchanged old updater refuses the new
scope and the installer refuses installation over existing state without changing
it. Otherwise keep the candidate non-Latest. Local tests do not establish current
host cleanliness or a successful packaged live run.

## Retained safeguards and limits

Apply the non-certificate prerequisites, operator/outside/Karing attendance,
temporary qualification transport and protected-log-parent procedure, 30-minute technical scenarios, two-hour subscription journey,
five-minute submission/validation, no-prefix-publication rule, stop/burn handling
and actual safety/final cleanup from
[ordinary recurring acceptance](ordinary-recurring-live.md). Qualification
transport TLS, GitHub/asset TLS and software attestations remain separate.

Apply the non-certificate artifact, client, credential, disclosure and evidence
handling requirements from [MVP acceptance](mvp-live-acceptance.md). Its old
certificate-replacement procedure and trusted-subscription-TLS requirements
apply to legacy HTTPS policies only. Do not run CA dry runs, replacement or
renewal actions for a fresh HTTP candidate. Root-only isolated Linux/systemd
fixtures and native CI remain required where applicable; local fixtures do not
prove the VPS, outside route, real Karing's HTTP acceptance, or a live release.

Bearer-token protection prevents unauthenticated retrieval at the server.
Plain HTTP still lets a network observer steal the link and proxy UUID or alter
the downloaded configuration. No claim of secret containment on the network is
made. Preserve protections for local files, logs and retained evidence.

## Attended Karing response windows

For a future attempt, explicitly declare `karing_response_limit_seconds: 3600`
and `attended_finish_by` (an actual RFC3339 UTC attendance cutoff) in the
unsigned declaration and verify both in the signed manifest. This opt-in is
limited to ordinary HTTP MVP qualification. An omitted field preserves the old
request, observation and deadline contract exactly. It cannot extend or qualify
an expired attempt, including r02 / v3.1.86.

The unchanged 30-minute technical budget (two hours for `mvp-subscription`)
counts preparation, automated checks and submission preparation. Only the
actual interval waiting for an attended Karing response pauses that budget.
Each eligible handoff gives the Owner a full hour after the link is ready and
readiness has actually been communicated. A copied clipboard link alone does
not start the response clock. The five-minute validation/submission limits,
signed attendance cutoff and six-hour transport/job ceilings remain. Refuse a
handoff if its full response hour cannot fit; arrange a future session before
another approved attempt rather than extending the current session.

Prepare the exact callback and final observation commands before asking for
input. Coordinate the main assistant's visible readiness message and actual UTC
notification timestamp with the operator. Record that timestamp promptly (within
five minutes and while the technical request remains active); never substitute
the link-preparation time or invent an earlier notification. The self-contained
recorder can still be streamed through the existing SSH path. For menu/
recovery operations after a completed wait, also stage its exact reviewed bytes
as a root-owned `0600`, one-link file in the separately inventoried update-control
directory (keep the protected-menu directory's four-file inventory unchanged).
Pass `SBXR_QUALIFICATION_CLOCK` as that absolute path,
`SBXR_QUALIFICATION_CLOCK_SHA256` as the reviewed checkout's digest, and
`SBXR_QUALIFICATION_DRAFT` as the current absolute draft path. All maintained
menu, interruption and recovery drivers verify those bytes and call
`operation-deadline`. It refuses pending/expired/sealed handoffs before a product
process starts. Inventory and remove the additional staged recorder during
owned operator cleanup. Private callers must use this computed deadline, not
read the original `deadline_unix` as the post-response deadline.

Record the readiness event with:

```sh
python3 mvp-observe.py ready --request request.json --draft draft.json \
  --phase http-profile-refresh --prepared-at "$actual_prepared_at" \
  --notified-at "$actual_user_notification_at"
```

For the current scope, allowed phases are `profile-import` and `profile-refresh` for
`mvp-subscription`; `credential-refresh` and `rotated-link-refresh` for
`mvp-credentials`; and `test-profile-removal` for `mvp-removal`. They are each
single-use within their scenario and cannot overlap. Keep secret links and
credentials out of the timing records and visible readiness message.

On an actual attended response, invoke `responded` immediately, then record the
required observed checks and seal/submit the complete scenario. `responded`
records the actual current time and does not mark any check passed. Defer extra
callback reports and diagnostics until this handoff is recorded. A pending or
late response cannot be sealed, replayed, or backdated. The collector reads only
private, request-bound timing/check facts and uses the same recorder calculation;
the Go validator independently verifies those waits and the original technical
budget. Retire a consumed draft after confirming collector advancement. Until
then, the collector ignores only the exact sealed draft that matched its immediately
preceding accepted scenario; altered, unsealed and older replayed drafts still
refuse. The retained draft never extends the next request's technical deadline.

This is a future tooling/procedure change, not Karing acceptance or publication.
Before another live attempt, validate the changed collector/SSH boundary with an
isolated Linux fixture, refresh all existing prerequisites and obtain approval
for the exact new signed declaration and candidate.
