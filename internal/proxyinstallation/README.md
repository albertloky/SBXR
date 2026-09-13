# Proxy Installation source guide

This package owns the installed V3 proxy journey: legal actions, proxy and
subscription status, review and confirmation, durable mutation direction,
runtime lifecycle, recovery, and Complete removal. Read
[ADR 0016](../../docs/adr/0016-v3-proxy-product-and-modules.md) before changing
those contracts. The package's Owner Interface remains
`Review(context.Context, Action)` and
`Execute(context.Context, PreparedAction, Confirmation, ProgressReporter)` in
[proxyinstallation.go](proxyinstallation.go).

`Review` freshly inspects the installation and may return an opaque, in-memory,
single-use Prepared Action. `Execute` consumes that action, requires the
applicable confirmation, and revalidates its facts under mutation authority
before effects. Keep status and View details read-only: observation does not
finish pending work, convert durable authority, or create missing authority.

## Find the owning code

| Task | Start here |
|---|---|
| Owner actions, statuses, `Review`/`Execute`, setup, cleanup, and removal sequencing | [proxyinstallation.go](proxyinstallation.go) |
| Ownership Record schemas, validation, compatibility, and update admission | [ownership.go](ownership.go) |
| Owner-facing details and observation formatting | [details.go](details.go) |
| Subscription enablement and interrupted-enable cleanup | [subscription.go](subscription.go) |
| Subscription-link replacement and finishing | [rotation.go](rotation.go) |
| Reviewed healthy certificate replacement, fault repair, and their recovery direction | [repair.go](repair.go) |
| Certificate-generation inspection and forward activation | [activation.go](activation.go) |
| Client Identity replacement and startup protection | [client_identity.go](client_identity.go) and [client_identity_subscription.go](client_identity_subscription.go) |
| Managed renewal dispatch and hook recording | [renewal.go](renewal.go) |
| Serving dispatch, serving/removal exclusion, and resource cleanup | [serving.go](serving.go) |
| Software Lifecycle compatibility and runtime collaboration | [software_update.go](software_update.go) |
| Linux filesystem, systemd, Certbot, firewall, process, and lock mechanics | [adapter/host](adapter/host) |
| sing-box configuration and UUID-only Client Identity replacement | [adapter/singbox/singbox.go](adapter/singbox/singbox.go) |
| Numbered Owner menu and Software Lifecycle choices | [adapter/terminal/run.go](adapter/terminal/run.go) and [adapter/terminal/lifecycle.go](adapter/terminal/lifecycle.go) |
| Private authenticated HTTPS serving behavior | [subscriptionserving/README.md](subscriptionserving/README.md) and [subscriptionserving/serving.go](subscriptionserving/serving.go) |

Focused tests live beside their owning files. Adapter tests cover OS and
sing-box mechanics; package tests cover Review/Execute behavior, interruption,
restart recovery, refusal, and cleanup.

## Durable behavior to preserve

The Ownership Record is the sole durable authority for proxy and subscription
resources. Schema 1 retains the original proxy contract. Schema 2 retains that
provenance and adds exact resource creators, serving and renewal authority,
startup integration, and at most one unfinished subscription or Client Identity
operation. It contains no raw Subscription Link credential, Client Identity, or
served artifact. Validate the whole supported record and resource contract;
the schema number alone does not establish compatibility.

Convert schema 1 only inside a confirmed supported operation: subscription
enablement, Client Identity rotation, or commitment of Complete removal. Reads,
cancellation, and ordinary software updates do not convert it. Every unfinished
operation records its source and target, checkpoint, authorized effects, and
recovery direction before the corresponding effect. Unknown or contradictory
direction refuses mutation rather than choosing cleanup or forward completion.

Ordinary proxy starts pass through the owned startup integration. Client
Identity rotation closes every supported start route during cutover, restores
only the proved source before revocation, and finishes only the selected target
after revocation. Boot and private dispatch do not choose recovery direction or
create authority.

Complete removal is forward-only once committed. It binds the verified
finishing Release Identity, preserves each resource's creating identity, obtains
serving and renewal exclusion, removes only exactly proved owned resources, and
preserves unrelated Certbot lineages, the shared ACME account, and unrelated
system configuration. Unknown residue is not recursively erased. The final
Ownership Record moves through `/var/lib/.sbxr-removal.json`; exactly one copy is
authoritative until executable and Installed Record removal completes and the
final authority is durably unlinked. Exact-release restoration may restore only
the executable and Installed Record needed to finish removal, never proxy
resources or revoked credentials.

Renewal Attempt Evidence is bounded diagnostic evidence, not stored status,
mutation authority, or a recovery journal. The managed recorder and hooks record
the exact official Certbot route and outcome. Missing, live, failed, stale, or
contradictory evidence remains visible until a supported reviewed operation
proves the accepted generation or performs the diagnosed repair. Renewal writers
use their dedicated exclusion; Ownership Record and runtime mutations still use
whole-host authority.

## Evidence boundary

The source implements setup/removal, subscription enablement, link rotation,
repair and certificate activation, Client Identity rotation, managed renewal,
serving, and compatible Software Lifecycle collaboration. Unit, adapter,
integration, or package checks establish only the boundary they exercise. They
do not by themselves establish packaged Ubuntu VPS behavior, outside HTTPS or
proxy traffic, exact Karing behavior, stable publication eligibility, or Owner
acceptance. Keep implementation, regression evidence, packaged/live
qualification, and release acceptance distinct when changing this package or
reporting results.
