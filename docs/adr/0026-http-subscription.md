---
status: accepted
---

# Use HTTP for subscriptions and migrate legacy HTTPS

On 2026-10-01 the Owner explicitly approved changing the HTTPS subscription
feature to HTTP after being informed that HTTP exposes subscription credentials
and downloaded proxy credentials to interception and permits response tampering.
This decision authorizes source implementation and safe validation. It does not
authorize deployment, CA requests, live certificate deletion, or publication.

New Enable subscription operations create `http://<recorded IPv4>:8443/s/<token>`.
Keep the existing random bearer token, constant-time verification, GET-only
request contract, concealed refusals, bounds, rate limiting, protected files,
review/confirmation, rotation/recovery, and exact owned cleanup. The fixed port
remains 8443; HTTP does not imply port 80. Create only the exact TCP 8443 firewall
contribution. Do not install snapd/Certbot, issue certificates, create renewal
resources, or reserve TCP 80 for these subscriptions.

The VLESS/REALITY proxy on TCP 443 continues to use its own REALITY keys and TLS
configuration. Its configuration, client verification, and release asset
attestation/signing trust are unchanged. HTTP subscription authentication does
not provide confidentiality or authenticate the server to the client.

## Existing HTTPS installations

Supported HTTPS upgrades must finish on HTTP without reinstalling. Preserve the
IPv4, port 8443, path, bearer token, Client Identity, proxy configuration, client
settings, certificate bytes/live links, and their creating-release provenance.
Only the URL scheme changes. The Owner displays the replacement link through
confirmed View details, changes the URL in the existing client profile and
refreshes it. Do not restart sing-box or issue, renew, revoke or delete a
certificate during migration.

The frozen v3.1.81 updater proves unchanged Ownership Record bytes and normal
trusted HTTPS through transaction cleanup. Its private candidate runtime cannot
migrate authority. After Update or committed Recover finishes, exit the old menu
and launch the newly installed `sudo sbxr` with no arguments. That first eligible
root launch performs the mandatory HTTP handoff before the menu. New lifecycle
code also performs the same handoff after Update/committed Recover has removed
its journal and released runtime exclusions, while retaining the whole-host
mutation lock. Prepared rollback restores exact TLS without migration. Existing
unfinished proxy operations keep their Finish/Complete removal menu; handoff
waits until the installation is idle. Private roles never migrate.

Under the existing whole-host, package, renewal and shared Certbot exclusions,
the handoff records its forward direction before any effect. It quarantines the
exact owned renewal configuration, drop-in and hooks, removes only the owned
TCP 80 rule, publishes the HTTP firewall/state, and starts authenticated HTTP.
Interrupted publications and runtime changes resume forward on the next root
launch or supported Recover. Foreign bytes, links, modes or staging refuse.
Shared CA accounts, snapd/Certbot, their official timer and unrelated lineages
remain unchanged. No live migration is executed by this source change.

Fresh HTTP authority contains no certificate or renewal authority. A migrated
HTTP record instead retains an explicit `https_retirement` object with exact
certificate and retired-resource cleanup authority, configuration/evidence
hashes and original resource provenance. These inactive certificates are never
loaded by HTTP or checked for expiry. Reviewed Complete removal later cleans
only proved owned retained resources and can resume partial cleanup. HTTP
records require the target's HTTP capability; migrated records and legacy TLS
sources additionally require its retirement capability. Schema 2 alone cannot
establish compatibility. The pending migration flag and exact staging disappear
at completion; historical cleanup authority remains.

## Live acceptance

This supersedes the subscription transport requirements for fresh enablement
and completed legacy migration in
ADR-0016 and ADR-0023/0025 for the new `mvp-http-live-v1` and
`mvp-http-recurring-live-v1` policies. Historical HTTPS policies retain their
original interpretation. The new five journeys replace `mvp-renewal` with
`mvp-serving`, proving an ordinary serving restart with the unchanged link,
current artifact, outside authenticated HTTP, absence of certificate/renewal
resources, and preserved proxy traffic. HTTP enablement requires an explicit
transport-exposure disclosure and actual Karing import/manual refresh.

Recurring acceptance retains all three exact-source update/recovery journeys.
Precommit proves exact source/TLS restoration. Upgrade and postcommit prove
updater ownership preservation until cleanup, then the mandatory HTTP handoff,
unchanged address/port/path/token, retained certificate/provenance bytes, retired
owned renewal/TCP 80, existing client profile refresh, zero migration CA actions
and no pending migration or staging. There is no TLS-verification override. The initial unchanged v3.1.81 source
still needs two fresh HTTPS preparations and their certificate issuances. The
fresh HTTP candidate needs zero production issuances, replacing the former
four-operation total with two for that initial route. Future HTTP-only sources
need no subscription CA issuance; fresh readiness must establish the actual
source and host facts before an attempt.

Keep every other artifact/signature, native check, real host/outside/Karing,
credential revocation, exact-source/recovery, deadline, hash-chain, secret-safe
capture, cleanup, failure/burn, and stable-publication safeguard. No previous
evidence qualifies changed candidate bytes. See the
[HTTP procedure](../acceptance/http-subscription-live.md).
