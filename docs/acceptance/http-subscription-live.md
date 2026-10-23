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

The signed attempt may select `proxy_profile: "vless-vmess"` for the optional
two-node setup. Omit `proxy_profile` for the existing VLESS-only qualification;
its checks remain unchanged. No other nonempty profile is accepted. The two-node
profile requires attempt schema v3, this exact clean-install-only HTTP scope,
empty sources and no exception, archival correction or automated-only claim.
Historical repair, HTTPS and recurring scopes cannot select it. Bind the profile
before signing; changing it requires a new qualification, not reused observations.

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
   Check without replacement; Update is absent from the menu. An already absent host needs no old
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

For `vless-vmess`, the same five journeys require the following additional exact
evidence. A one-or-two-node condition is never sufficient:

- Install through the guided VMess setup. Prove the dedicated owned connector
  is running and real outside traffic independently through VLESS REALITY and
  VMess WebSocket, with no direct or other-node fallback. A server-originated
  setup probe does not satisfy outside traffic or Karing evidence.
- Subscription replaces `one-correct-subscription-node` with
  `exact-vless-reality-and-vmess-websocket-nodes`: exactly one correct VLESS
  REALITY Vision node and one correct VMess AEAD WebSocket node, no extras.
  Compare actual emitted/imported fields, shared current UUID, VLESS endpoint,
  REALITY key/SNI/flow and VMess hostname, TLS TCP 443 and `/sbxr-vmess` path to
  the reviewed installation. Require fresh actual Karing latency for each node,
  manual refresh and the existing selected connection/settings preservation.
- Credentials must terminate established sessions and reject the old UUID on
  each protocol. Prove replacement traffic independently through both nodes,
  refresh both identities on the unchanged link, then rotate the link and prove
  the new link refreshes both nodes with unchanged proxy identities. Reject the
  old link and obtain fresh Karing replacement latency separately for both nodes.
- Serving restart must preserve both nodes' traffic and the exact dedicated
  connector, as well as the unchanged link and correct current two-node artifact.
- Before removal, prove ordinary restart preserves access on each protocol.
  After reviewed Complete removal, prove owned connector unit/enablement-link
  absence and outside rejection on both protocols. Preserve the Owner-provided
  `cloudflared` binary, protected token and unrelated resources; do not change
  Cloudflare account, DNS or tunnel resources. Complete actual cleanup of both
  test clients, processes, captures and temporary secrets, and restore the
  original client settings/connection. Preserved prerequisite secrets are not
  disposable test secrets.

The generated checklist names each protocol's traffic, latency, revocation,
replacement and removal checks separately. Generic observations cannot stand in
for a missing per-node check. The public Acceptance Record discloses the selected
profile. This procedure defines future evidence; it records no two-node live pass.

The native helper's `subscription_nodes` and file-backed `readbacks` APIs require
the explicit attempt from the authenticated signed manifest for the two-node
profile and verify the strict node contract against candidate wire bytes.
Default one-node VLESS checks retain their meaning. The VMess native field set
follows the saved Karing 1.2.25/2802 baseline representation: zero `alter_id` is
omitted, while the URI must specify `aid: "0"`.
The combined profile also fixes VLESS Vision, TCP 443 and Chrome uTLS; matching
incorrect native and wire values cannot satisfy that contract.

Use the existing actual primary-store capture route with its protected stable
source, exact source hash/size/mtime, unique complete profile and distinct private
URL/profile readbacks. Separate client-process/store isolation is not required;
preservation of the original connection, settings and profiles remains required.
Bind the existing app/helper identity and all updated capture/recording callers
before signing. Callers must pass the authenticated attempt; neither receipt
claims nor an old one-node helper copy may select the new profile.
The saved baseline structure supplies serialization evidence only. It and the
baseline latency observations do not prove a new candidate URI import, refresh,
traffic or latency, and cannot substitute for candidate-bound observations or
the five-journey qualification.

For a fresh preparation, copy the repository's `capture-native.py` beside its
existing `native-inputs.json`, and the canonical native helper under
`operator-source/`. Retain the normal reviewed caller/input bindings. After
actually observing the current home-screen connection/TUN state, use:

```sh
python3 -B "$prepared/capture-native.py" capture --inputs "$prepared/native-inputs.json" \
  --phase m2 --connected true --tun-enabled true
python3 -B "$prepared/capture-native.py" verify --inputs "$prepared/native-inputs.json" \
  --phase m2 --connected true --tun-enabled true
```

The booleans must report actual observations, including TUN off if that is the
preserved baseline. Repeat this capture/verification path for `m3-identity`,
`m3-link` and `m5` when those states actually exist. Both callers resolve the
explicit attempt from the authenticated manifest/current request; verification
re-reads the actual source and recomputes preservation before recording. The
existing capture envelope retains its private audit and complete file inventory.
No file is overwritten. A refusal retains partial private evidence for reviewed
cleanup; inspect existing outputs rather than recapturing an uncertain outcome.
This command does not operate Karing or mark any journey check observed. Fresh
import, manual refresh and each latency result still require their own actual
observations and the existing recorder/collector acceptance. Baseline-check phases
are readiness only. Historical copies and receipts remain frozen.

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
host. The historical recurring policies remain readable and are not
qualification claims for the current product.

Before recommending Latest, prove that the unchanged old updater refuses the new
scope and the installer refuses installation over existing state without changing
it. Otherwise keep the candidate non-Latest. Local tests do not establish current
host cleanliness or a successful packaged live run.

## Retained safeguards and limits

Use the exact verified package on a disposable Ubuntu Server 24.04 amd64 host,
with a genuinely outside client and actual Karing. Before dispatch, confirm fresh
host/package/SSH readiness, operator and client availability, and time for final
cleanup. Review the existing [temporary log-parent procedure](mvp-protected-log-parent-2026-09-19.md)
where applicable; it adds no journey or permission to change another host.

The technical scenario limit is 30 minutes, or two hours for subscription/Karing;
validation and submission retain five minutes. Arrange attended response windows
before dispatch using the policy below. Keep all work and cleanup inside the
approved transport window. Failed or incomplete required checks stop the attempt;
only the documented pre-effect Karing correction permits input correction.

Use the packaged public menu for product effects. Keep credentials, links,
client configuration and raw captures private; retain secret-safe observations
with original timestamps. Preserve unrelated resources, the existing client
connection/settings and SSH. Finish reviewed product removal and verify owned
absence, outside rejection, client restoration, stopped clients and removal of
temporary secrets, transport, trust and routing. A workflow conclusion alone does
not prove cleanup. Qualification transport TLS and software attestations remain
required. Fresh HTTP subscriptions need no CA dry run, replacement or renewal.

After all required tests and actual host/client/secret cleanup pass, the exact
unchanged candidate qualifies for stable publication under
[ADR-0032](../adr/0032-qualified-publication-retry.md). Successful completion of the
official main-branch qualification makes the candidate eligible but does not
start publication. Obtain the Owner's explicit publication approval before manual
`stable.yml` dispatch with the successful `qualification_run_id`; main divergence
still pauses for exact review. Publication replays that successful evidence and
rechecks authentication, integrity and current release state. It adds no separate
`stable-publication` environment ceremony or new `acceptance-vps` host probe. A publication job failure preserves qualification
and accurate failure evidence for retry. Explicit abandonment retains the burn
path. Failed or incomplete live checks and cleanup still stop qualification.
Hosted trigger behavior follows the workflow version on GitHub; local edits
alone do not change it.
The ADR also defines the narrow authenticated recovery of an old prepublication
failure without rewriting its original burn or repeating already proved journeys.

Bearer-token protection prevents unauthenticated retrieval at the server.
Plain HTTP still lets a network observer steal the link and proxy UUID or alter
the downloaded configuration. No claim of secret containment on the network is
made. Preserve protections for local files, logs and retained evidence.

## Checking the installed candidate over SSH

The manifest-v3 workflow stages its transport under
`/root/sbxr-qualification-v3`. It does **not** stage
`/run/sbxr-qualification/v3-packaged-live.sh`. Do not assume that historical
helper location exists or add another host-side copy to work around its absence.

Use the unchanged `exact_candidate` function from the reviewed source checkout.
Before installation, confirm the local `.github/scripts/v3-packaged-live.sh`
is present and passes `bash -n`. After the packaged installer succeeds, run the
following from that checkout's repository root, before Start setup. Reuse the
authenticated `acceptance_host` and `ssh_options` Bash array from the reviewed
connection; the array must not contain `-n` or `StdinNull=yes`, because this call
carries the module on standard input.

<!-- mvp-exact-candidate-ssh -->
```sh
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
  "${ssh_options[@]}" "$acceptance_host" \
  'bash -c "set -euo pipefail; source /dev/stdin; exact_candidate"' \
  < .github/scripts/v3-packaged-live.sh
```

Require exit 0 before proceeding. The remote Bash sources the complete module
without entering its standalone journey dispatcher, then runs only its read-only
identity check. It reads the current collector request, its bound manifest, the
Installed Record and executable at their existing paths; it neither stages a
helper nor executes the product. No candidate identity is inherited from a
previous SSH shell. Missing source/input, failed transport or an identity
mismatch stops the handoff; retain the original failure rather than bypassing
the check or continuing setup.

This check binds the installation to the **already verified** candidate. It does
not replace artifact/attestation review, complete `mvp-install`, or authorize a
new attempt. It needs no log-parent permission window. The later public menu
processes still use the applicable [log-parent plan](mvp-protected-log-parent-2026-09-19.md).

## Recording the five journeys

The existing JSON handoff remains supported. Prefer the small repository-owned
recorder to avoid hand-editing timestamps. It does not drive the product, assert
checks on its own, or accept caller-supplied times. It binds a private draft to
the exact request bytes and refuses stale requests, duplicate checks, incomplete
submission, expiry and overwritten evidence.

From the reviewed checkout, with the authenticated `acceptance_host` and
`ssh_options` array (no `-n`/`StdinNull=yes`), stream the recorder without staging
another host helper:

<!-- mvp-incremental-observer-ssh -->
```sh
mvp_observe() {
  ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
    "${ssh_options[@]}" "$acceptance_host" python3 - "$@" \
    --request /root/sbxr-qualification-evidence/request.json \
    --draft /root/mvp-observation-draft.json \
    < .github/scripts/mvp-observe.py
}
mvp_observe start
mvp_observe status
```

After **actually observing** one required outcome, record that check immediately:

```sh
# Example for mvp-install only, after the packaged installation was observed:
mvp_observe observe --check packaged-install
```

Never loop over the checklist to mark everything observed. For human-only
observations, wait for the actual observation/confirmation and record its real
time. Arrange that availability before dispatch, not after the deadline.

After all required outcomes and the journey's cleanup are actually observed:

```sh
mvp_observe finish --output /root/sbxr-qualification-evidence/observation.json
```

`finish` seals the draft before atomically publishing mode-0600 observation JSON.
The collector still assembles and validates it with the real release validator
before submission. Require its accepted scenario receipt; file creation is not
acceptance. After acceptance, remove only this sealed draft before the next
journey. If publication/transport is interrupted, inspect the sealed draft,
output and collector receipt instead of rerunning `finish` or editing times.
The final Acceptance Record requires all five HTTP journeys; no prefix can publish.

Failed or incomplete journeys use the existing typed failure and safety-cleanup
path. Never mark an unobserved check as observed. A disconnected product action
has an uncertain outcome: inspect its state before further action. Do not retry
mutations to replace the original failure. Keep the accepted scenario receipts;
only the complete five-journey result can qualify the candidate.

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
exactly. For each other original profile, permit differences only at its immediate
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
baseline may contain any nonempty number of unique profile IDs, including the
built-in `custom`; two was an incidental historical count. A saved RackNerd
baseline profile can remain as a protected original. Add and later remove only
the new candidate profile; do not remove originals to fit a fixture count. The
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

On 2026-10-04 the Owner replaced the full-hour response guarantee for future
SBXR tests with short, present-user checks. A response window is a **timeout**
for a required manual client action, never a mandatory wait or an extra approval
for every scenario. Continue immediately after the actual result is observed.
Historical signed attempts retain their original timing interpretation.

Use **five minutes for a simple prepared client action, ten minutes for a grouped
import/latency/manual-refresh check** while the Owner is present. Prepare commands,
private links and evidence callbacks before notifying. Start the timeout when
readiness is actually communicated, not when a link is copied. If the exact real
client can be operated and observed through an already authorized, working tool,
record that direct evidence without requesting a redundant Owner reply. A tool's
availability alone does not prove that client interaction is working.

The operator performs supported objective checks directly: package/installed
identity, public-menu operations, safe lifecycle refusal/no-recovery results,
outside HTTP/REALITY probes, artifact/credential comparisons, resource inventories,
and cleanup. Inspect their actual outputs before recording each result. The
recorder and assembler only record/validate evidence; they do not execute or
prove the checks. All five scenario records remain required and sequential.

| Scenario | Client attendance that may need a manual handoff |
|---|---|
| Install | None if the outside REALITY probe is operator-controlled; actual outside traffic still required. |
| Subscription | One prepared client visit for import, fresh latency, manual refresh and settings/selection preservation; record every required check. |
| Credentials | Identity rotation/unchanged-link refresh is operator-verifiable with the outside client; request help only where direct observation is unavailable. Then prove actual Karing replacement latency after link rotation. Keep the two mutations ordered, and establish the old outside session before rotation. |
| Serving | None: ordinary serving restart and outside HTTP/proxy checks are operator-controlled. |
| Removal | Remove only test profiles/secrets and verify preserved client settings; combine the final client tasks in one visit. Product/process/transport cleanup remains operator work. |

Plan three client visits when the operator can prove unchanged-link identity
refresh directly: subscription import/refresh, replacement-link refresh, and
test-profile cleanup. If that identity refresh needs a client reply, add its
`credential-refresh` handoff before rotating the link. These are observations,
not separate scenario approvals. Group nearby actions only where the required
state exists. Do not overlap waits, perform later-scenario checks
early, reuse an earlier observation, or infer browsing from node latency.
For subscription, one actual `profile-import` handoff can encompass import and
manual refresh of that ready link; both check records remain mandatory. Open a
separate `profile-refresh` handoff only if there is a separate actual wait;
account for the additional handoff in the pre-attempt budget.

Stop qualification mutations immediately on a failed action, or when silence
or incomplete evidence reaches the stated short timeout. Preserve the original
incomplete/failed result. Use the existing lawful recovery and cleanup path; report inaccessible cleanup as
unproved. Do not mark checks observed, extend the timeout automatically, reset
timestamps, continue another destructive step, or retain a running installation
for a later reply. A later reply cannot rescue that stopped attempt. Recovery
and cleanup access must already be available before starting; they cannot depend
on the missing client reply.

### Compatibility with the committed timing contract

At `b7a6f3a69710f3aea7b9b42f3cf9f82fde8ac3e9`, the supported signed opt-in is
still `karing_response_limit_seconds: 3600` plus an actual `attended_finish_by`.
The recorder and Go validator accept immediate responses and deduct only actual
recorded waiting. The allowed phase list does not require a handoff per phase
or per scenario. Do not invent a handoff/response for a directly observed tool
action. However, every opened handoff still requires **notification +
60 minutes <= attended_finish_by**, and the signed finish must be within six
hours of attempt start (and at least one hour after start; that is not a minimum
actual session duration). Build/sign/handoff time after that start consumes the
bound. The transport and hosted-job six-hour limits are independent.

A committed-only attempt can therefore use the short **operator stop rule**
without code changes, provided every handoff satisfies that retained one-hour
admission guard. Keep `3600` in its declaration; do not insert `300`/`600`, claim
machine-enforced short expiry, omit timing to evade the guard, or change a signed
manifest. An omitted opt-in still has its original unpaused technical contract.
The 30-minute technical scenarios, two-hour subscription ceiling and five-minute
validation/submission limits are maxima, not planned durations. Only actual
recorded response waits pause technical time. Machine work and coordination
remain charged; there is no due-refresh wait.

The short timeout is an operator stop rule. Runtime enforcement retains the
original signed contract; changing it is outside this cleanup.

Prepare the exact callback and final observation commands before asking for
input. Coordinate the main assistant's visible readiness message and actual UTC
notification timestamp with the operator. Record that timestamp promptly (within
five minutes and while the technical request remains active); never substitute
the link-preparation time or invent an earlier notification. The self-contained
recorder can still be streamed through the existing SSH path. For menu operations after a completed wait, also stage its exact reviewed bytes
as a root-owned `0600`, one-link file in the separately inventoried recorder
directory (keep the protected-menu directory's four-file inventory unchanged).
Pass `SBXR_QUALIFICATION_CLOCK` as that absolute path,
`SBXR_QUALIFICATION_CLOCK_SHA256` as the reviewed checkout's digest, and
`SBXR_QUALIFICATION_DRAFT` as the current absolute draft path. All maintained
menu and packaged-action drivers verify those bytes and call
`operation-deadline`. It refuses pending/expired/sealed handoffs before a product
process starts. Inventory and remove the additional staged recorder during
owned operator cleanup. Private callers must use this computed deadline, not
read the original `deadline_unix` as the post-response deadline.

Record the readiness event with:

```sh
python3 mvp-observe.py ready --request request.json --draft draft.json \
  --phase profile-refresh --prepared-at "$actual_prepared_at" \
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

This procedure records no Karing acceptance or publication. Before another live
attempt, refresh the existing prerequisites and obtain approval for the concrete
signed declaration and candidate. If tooling changes, qualify its changed
collector/SSH boundary in isolation before using it live.
