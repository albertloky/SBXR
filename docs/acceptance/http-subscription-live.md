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
native qualification and attestations. Current publication follows
[ADR-0032](../adr/0032-qualified-publication-retry.md).
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
five-minute submission/validation, no-prefix-publication rule, stop/cleanup handling
and actual safety/final cleanup from
[ordinary recurring acceptance](ordinary-recurring-live.md). Qualification
transport TLS, GitHub/asset TLS and software attestations remain separate.
The pre-effect input correction below is the only exception to stopping on a
recoverable UI input error; failed or incomplete required checks still stop.

Apply the non-certificate artifact, client, credential, disclosure and evidence
handling requirements from [MVP acceptance](mvp-live-acceptance.md). Its old
certificate-replacement procedure and trusted-subscription-TLS requirements
apply to legacy HTTPS policies only. Do not run CA dry runs, replacement or
renewal actions for a fresh HTTP candidate. Root-only isolated Linux/systemd
fixtures and native CI remain required where applicable; local fixtures do not
prove the VPS, outside route, real Karing's HTTP acceptance, or a live release.

After all required tests and actual host/client/secret cleanup pass, the exact
unchanged candidate qualifies for stable publication under
[ADR-0032](../adr/0032-qualified-publication-retry.md). Successful completion of the
official main-branch qualification starts the stable workflow automatically;
main divergence still pauses for exact review. Publication replays that successful
evidence and rechecks authentication, integrity and current release state; it
requires no second human `stable-publication` approval or new
`acceptance-vps` host probe. A publication job failure preserves qualification
and accurate failure evidence for retry. Explicit abandonment retains the burn
path. Failed or incomplete live checks and cleanup still stop qualification.
The ADR also defines the narrow authenticated recovery of an old prepublication
failure without rewriting its original burn or repeating already proved journeys.

Bearer-token protection prevents unauthenticated retrieval at the server.
Plain HTTP still lets a network observer steal the link and proxy UUID or alter
the downloaded configuration. No claim of secret containment on the network is
made. Preserve protections for local files, logs and retained evidence.

## Future native settings comparison

The Owner approved this prospective correction on 2026-10-19. New preparations
may explicitly bind `sbxr-karing-settings-preservation-v2` for Karing 1.2.25,
build 2802. It permits differences only at `/window/x`, `/window/y`, and
`/dns/client_subnet_latest_update`. Both position values must remain integers;
the timestamp must be Karing's empty initial value or a valid persisted Dart
date/time string. Missing paths, changed types and malformed values refuse.

The pinned upstream code saves [window position](https://github.com/KaringX/karing/blob/v1.2.25.2802/lib/main.dart#L92-L117)
and records the [direct-IP refresh timestamp before its HTTP result](https://github.com/KaringX/karing/blob/v1.2.25.2802/lib/screens/home_screen.dart#L800-L835).
That timestamp proves no successful DNS or traffic check. The actual
`dns.client_subnet` value, every other DNS field, window width/height, routing,
selector, TUN, unknown fields and all other settings remain strict. Preserve
the original selected connection and connected/TUN values and types. Preserve
unrelated complete profiles, their order and non-item store fields through the
separate full-store baseline checks; this settings policy grants them no exception.
Saved URLs, credentials, node fields, TLS and REALITY still require their exact
native readback checks.

Fresh preparation copies the canonical `native-receipts.py` and uses its shared
`settings_binding`, `settings_readback`, `compare_settings`, `capture_settings`
and explicit `preserved_v2` functions. Before dispatch, bind the actual supported
app version/build, executable and Info.plist digests, fixed policy, canonical
helper digest, baseline and all prepare/capture/recording caller bytes in the
reviewed inputs. Consumers obtain both the trusted binding and original baseline
source record from the frozen inputs, never from a receipt's choice of policy
or baseline. The explicit `preserved_v2(facts, binding, baseline_source_record)`
API requires exact agreement with that original record. Rehearse the actual future baseline,
capture and all three M2/M3/M5 consumers together before live use. A new actual
native readiness cycle and separately authorized live plan remain prerequisites.

Retain complete normalized before/current snapshots, full raw and canonical
source digests, source metadata and the recomputed three-field change audit.
Compare a separate fixed projection; never write baseline bytes as the current
capture or discard the complete audit. Re-read the current actual source at
consumption: even an otherwise permitted change after capture invalidates that
observation. No caller-defined exclusion list is accepted.

This versions the native settings comparison only, not the signed HTTP journey
policy. `preserved(facts)` remains byte-strict, and absent/v1, unknown or mixed
contracts cannot opt into v2. Historical helpers, receipts and the failed
v3.1.112 qualification retain their original interpretation and outcome. This
offline correction supplies no live pass or publication authority.

## Future original-profile comparison

The Owner approved this prospective policy on 2026-10-20 for explicitly versioned
future preparations. Bind `original-profiles-refresh-cache-v3` separately from
settings v2. The built-in original profile with group ID `custom` must still match
exactly. For the other original profile, permit differences only at its immediate
`updateTime` and existing `servers[index].latency` fields:

- A changed timestamp requires both values to be valid native date/time strings,
  parsed unambiguously using the retained exact native TZif rules. Reject a local
  time in a DST gap or fold. The new value must advance and lie within the actual
  recorded baseline-to-current observation window. Empty, malformed, regressing
  or out-of-window changes refuse.
- A changed latency requires both values to be positive ASCII-decimal strings.
  It proves no successful refresh, traffic or journey outcome.

Profile/node identities, count/order, URLs, credentials, TLS/REALITY/Vision,
routes, all other fields and all non-item store fields remain exact. The existing
settings policy, selected connection, connection state and TUN checks remain
required. Any observed selection change fails. Latency may affect automatic
selection; before/after observations cannot prove every intermediate choice.

Fresh preparation freezes the supported app/helper identity, fixed profile
policy, complete original store, producer-recorded baseline UTC observation,
native timezone identity and retained TZif bytes, selected connection and every
prepare/capture/recording consumer. Do not infer an effective refresh timer from
raw null/default values; no all-profile timer proof is a prerequisite here.
The producer independently records the current UTC read time and retains the
complete actual raw store plus the full private before/after change audit,
including refusals, before producing any passing receipt. Neither a UI observation
nor a receipt may choose or widen the comparison window or its baseline.

`original_profiles_audit_v3` recomputes the comparison from those retained inputs.
Consumers reuse the captured immutable window, then separately re-read actual
current sources; a permitted change after capture invalidates that observation.
Bind policy, timezone, window and complete audit provenance through the normal
producer, finalizer, verifier and candidate closure. Generic failure cleanup
validates static retained authority and must remain reachable if the current app
or timezone changes. Full M2/M3 stores contain the test credentials: normal and
failure cleanup must remove or redact those owned captures while preserving
complete original-profile data, raw source digests and the private change audit.
Later M5/cleanup validation must not depend on already removed test secrets.

The historical strict APIs, helpers and receipts retain their meaning. The failed
v3.1.113 result stays failed. This policy changes no signed HTTP journey requirement
and supplies no live qualification, new-attempt or publication authority.

## Karing input and bounded correction

For the initial `mvp-subscription` import, focus the currently rendered link
field by coordinates, type the Subscription Link through native input events,
Tab to the remark, type it, then Tab to blur. Derive coordinates from the current
form. Check the complete rendered values after blur before one Save. AX
`setValue` or a displayed AX value alone does not prove form-model commitment;
after Save, verify the actual saved URL and exact native profile/node readbacks.
A successful import still requires fresh node latency, manual refresh and all
other required checks, with the selected connection and settings preserved.

Before submitting terminal failure for a demonstrated automation input error
(for example, an empty-link error despite displayed text), allow at most two
corrective attempts after the initial attempt, subject to all of these limits:

1. Retain the initial diagnostic and every attempt in private run evidence,
   bound to the same candidate and request: actual times, input method, error,
   rendered/committed-input readbacks, effect/profile absence and correction
   count. Preserve secret-safe summaries; keep credentials out of public records.
2. Before each correction, prove the input was not committed and the intended
   import had no effects, including no test profile/node creation and unchanged
   selected connection/settings. Observe any uncertain Save outcome read-only
   before repeating a mutation; if absence cannot be proved, do not retry. An
   existing profile must be verified through the normal checks, never imported
   again to resolve uncertainty or obtain a better result.
3. Repeat the native focus/type/blur sequence, check the rendered values, and
   use at most one Save per correction. Count corrections across form reopening;
   reopening cannot reset the allowance. Stop after two unsuccessful corrections.
   Keep the original action/repetition budget (including any five-repetition
   ceiling), request, computed operation deadline and submission/cleanup limits;
   use the stricter remaining limit and do not reset or extend any clock.
4. This permits correcting uncommitted input only. Do not retry a genuine
   product/security failure, a partial import, or any enablement, refresh,
   credential rotation or removal under this allowance. Once input is committed,
   require the ordinary import/product checks; an empty-field correction is not
   proof of subscription acceptance. Autonomous correction creates no attended
   human wait or paused interval.

If correction is inadmissible, its allowance/budget expires, or required checks
remain incomplete, use the existing terminal failure and safety-cleanup path.
Report a demonstrated automation input failure as such, with subscription
acceptance unverified; report actual product/security failures separately. Keep
all earlier errors even if a correction succeeds. A submitted terminal failure
or burned attempt cannot resume or become passed through this procedure.

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
