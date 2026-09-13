# MVP live acceptance

This is the current practical procedure for a candidate declaring
`mvp-live-v1`. It is a clean-install scope. It does not prove an incoming
upgrade, a natural Certbot timer firing, or naturally due client auto-refresh.
The five journey identifiers are listed in [ADR-0023](../adr/0023-mvp-live-acceptance.md):
`mvp-install`, `mvp-subscription`, `mvp-credentials`, `mvp-renewal`, and
`mvp-removal`.

Prepare the candidate using the normal supported artifact and trust checks, and
run the ordinary focused regressions for changed product paths. Use the exact
packaged candidate on a real disposable Ubuntu Server 24.04 `amd64` host with a
genuinely outside client. Retain enough secret-safe evidence to identify the
candidate, each journey, and its actual result. Do not substitute the historical
V4 operator/tracer procedure for this handoff; the existing collector selects
the MVP observation path from the declared policy.

## Preparing the reduced scope

In the complete unsigned attempt declaration, select `evidence_policy:
"mvp-live-v1"`, list the five `required_scenarios` above in order, and retain
the existing `subscription-clean-install-repair` support scope with no incoming
sources. Omit `automated_only_scenarios`: this record makes no blanket claim
that the historical excluded matrix passed. Set `after_snap_refresh` equal to
`packages`; that retained field does not request a package refresh. Record the
actual tested Karing package; MVP does not expire its check at five minutes.

The existing `v3-candidate-dispatch.sh check|dispatch TOOL PREFLIGHT DECLARATION`
path validates this declaration and skips the V4 `check-readiness.py`
prerequisite. Normal release identity, artifact verification and failed-run
handling remain. Do not rewrite a signed historical attempt into this policy.

## Observing the journeys

Run the following normal product journeys in one practical session where their
state permits:

1. **`mvp-install` — install, set up, and use it.** Use the packaged install
   and public menu to install and set up SBXR, inspect useful status/details,
   exercise Check and its safe no-update/no-recovery result, and send real
   traffic through the proxy from the outside client. Confirm ordinary SSH
   access remains usable.
2. **`mvp-subscription` — get a usable subscription into Karing.** Enable HTTPS
   through the supported route with real trusted TLS. Retrieve the one-node
   subscription, import it into Karing, obtain fresh node latency, and manually
   refresh the same link. Confirm a wrong token is rejected and check ordinary
   installed secret permissions and output/log exposure. Preserve Karing's
   selected connection and settings. Node latency does not prove browsing;
   outside traffic is proved in `mvp-install`.
3. **`mvp-credentials` — change credentials once.** Rotate the proxy UUID and
   prove old credentials fail, an already-established outside session ends,
   and refreshed access works through the unchanged subscription link.
   Then rotate the subscription URL credential, prove the old URL fails and the
   new URL works, confirm the proxy identity is unchanged, and refresh the same
   Karing session to obtain fresh replacement-node latency. Do not induce an
   interruption to create this evidence.
4. **`mvp-renewal` — keep HTTPS working after certificate replacement.** On
   the healthy subscription, use the reviewed **Replace subscription
   certificate** menu action once. This invokes the existing managed Certbot
   replacement and activation path for the owned lineage, even when the current
   certificate is not due. Observe the replacement through outside trusted TLS
   while the same subscription link and proxy identity remain usable. Follow the
   [replacement procedure below](#certificate-replacement-procedure). This Owner
   action does not claim the natural timer fired.
5. **`mvp-removal` — restart and remove it.** Perform an ordinary service restart
   and confirm usable configuration and credentials remain. Then use reviewed
   Complete removal, confirm owned services, listeners, and resources are gone
   while unrelated resources remain, and confirm old outside access fails.

## Certificate replacement procedure

The starting state is a Running proxy with an Available subscription, matching
published/loaded certificate, and healthy idle renewal evidence. If that state
cannot be established, inspect the displayed problem; do not induce a fault to
make Repair subscription available.

1. Retain the current certificate identity from a real outside TLS connection
   and confirm the current subscription link and proxy traffic work. Keep the
   credential values private.
2. Choose **Replace subscription certificate** in the packaged SBXR menu. Read
   its plan and confirm once. Public TCP 80 must be reachable for the existing
   HTTP-01 issuance route. The action requests one replacement for the owned
   `sbxr-subscription` lineage and activates the verified result. It preserves
   the subscription link and proxy identity. Serving can be interrupted during
   certificate activation; repeated requests can consume CA issuance limits.
3. Require `PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED`, then inspect
   status/details for Available serving and healthy renewal evidence. Verify a
   different certificate through a new outside TLS connection with normal
   trust validation. Check the same link, unchanged proxy identity, and fresh
   outside proxy traffic. Local success alone does not prove outside acceptance.
4. If the action refuses or needs completion, retain its original result and
   diagnose the displayed cause. Use **Finish subscription change** only for
   supported cleanup/completion. Do not count a failed first action as passed
   after recovery, and do not automatically request another certificate.

`systemctl start snap.certbot.renew.service` exercises ordinary scheduled
renewal semantics. Exit 0 can mean no renewal was needed, so it cannot substitute
for the replacement check on a fresh installation. Do not run a direct forced
Certbot command or private hook around SBXR's managed operation. The checklist
names and evidence format are unchanged; `official-renewal-route` records the
supported managed Certbot Owner action in this journey. See Certbot's
[renewal behavior](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

## Evidence handoff

For the current journey, the collector publishes the root-owned request at
`/root/sbxr-qualification-evidence/request.json`. It contains `scenario_id`,
`not_before`, `deadline_unix`, `scenario_limit_seconds`,
`qualification_manifest_sha256`, and `required_checks`. Perform the named
journey first, through the actual packaged menu, outside client, and Karing where
applicable. The request is a checklist and timing boundary; it does not observe
or pass any check.

After actually observing every required outcome, prepare a root-owned,
mode-0600 file and rename it to
`/root/sbxr-qualification-evidence/observation.json`. It may be
ordinary or pretty JSON and must contain exactly:

```json
{
  "scenario_id": "…",
  "started_at": "YYYY-MM-DDTHH:MM:SSZ",
  "completed_at": "YYYY-MM-DDTHH:MM:SSZ",
  "checks": [
    {"check": "…", "observed_at": "YYYY-MM-DDTHH:MM:SSZ", "result": "observed"}
  ]
}
```

Copy `scenario_id` and the check names from the current request. The `checks`
array must use the exact `request.required_checks` order and contain every item
once. `started_at`, `completed_at`, and every `observed_at` value are RFC3339 UTC
seconds within the requested journey: the journey starts no earlier than
`not_before`, finishes by `deadline_unix`, and each observation falls between
its start and completion. Check timestamps do not need to be monotonic.

This creates an incomplete local template. Fill its null values with actual
timestamps and results before submission; the collector refuses an incomplete
template. Never place URLs, tokens, UUIDs or private keys in these observations.

```sh
umask 077
request=/root/sbxr-qualification-evidence/request.json
jq '
  {
    scenario_id,
    started_at: null,
    completed_at: null,
    checks: [required_checks[] | {
      check: ., observed_at: null, result: null
    }]
  }
' "$request" > /root/mvp-observation-draft.json
```

After filling and reviewing the draft, copy it into the evidence directory
under a temporary name with mode `0600`, then rename it to `observation.json`.
This lets the collector read the completed document. Remove the local draft
after submission. Writing the completed file triggers `.github/scripts/v3-mvp-evidence.py`, real
release-validator validation, and the existing result submission. Invocation
never fabricates evidence. After a successful submission, the collector removes
`observation.json`; retain the resulting acceptance record. A failed or
incomplete journey uses the existing failure path and must never be submitted as
an all-`observed` `observation.json`.

Do not add forced interruption, contention, route-drift, outage, snap-refresh,
five-minute auto-refresh, V4 rehearsal, or six-surface capture work to this
live checklist. Keep applicable regression and integration checks at their
ordinary test level. The historical scenario 03 refusal remains unresolved and
must be investigated separately if pursued; do not treat its absence here as a
release result.

The existing transport retains the 30-minute journey limit, two-hour
subscription/Karing limit and five-minute validation/submission window. There
is no due-refresh wait. A failed or incomplete attempt does not produce a
successful Acceptance Record. A passing record establishes only the five
journeys above and discloses the omitted live variants.
