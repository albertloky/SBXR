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

Setup refusals retain `PROXY-INSTALLATION-ACTION-REFUSED` and name the failed
check. The existing correction text includes a `SETUP-PREFLIGHT-*` or
`SETUP-REVALIDATION-*` diagnostic with safe expected/observed facts. Destination
failures show completed DNS/TCP/TLS/HTTP2/certificate checks; they do not print
raw network errors, addresses learned from the host, identity material, or
subprocess output. Revalidation still requires every original check and exact
fact equality. A diagnostic identifies the observed refusal, not the historical
cause of a prior run without these observations.

## Find the owning code

| Task | Start here |
|---|---|
| Owner actions, statuses, `Review`/`Execute`, setup, cleanup, and removal sequencing | [proxyinstallation.go](proxyinstallation.go) |
| Ownership Record schemas, validation, compatibility, update admission, and exact rotation checkpoint publication | [ownership.go](ownership.go) |
| Owner-facing details and observation formatting | [details.go](details.go) |
| Subscription enablement and interrupted-enable cleanup | [subscription.go](subscription.go) |
| Subscription-link replacement and finishing | [rotation.go](rotation.go) |
| Reviewed healthy certificate replacement, fault repair, and their recovery direction | [repair.go](repair.go) |
| Certificate-generation inspection and forward activation | [activation.go](activation.go) |
| Client Identity replacement and startup protection | [client_identity.go](client_identity.go) and [client_identity_subscription.go](client_identity_subscription.go) |
| Managed renewal dispatch and hook recording | [renewal.go](renewal.go) |
| Serving dispatch, serving/removal exclusion, and resource cleanup | [serving.go](serving.go) |
| Software Lifecycle compatibility and runtime collaboration | [software_update.go](software_update.go) |
| New-setup boot provisioning of the volatile whole-host lock | [lock_provision.go](lock_provision.go), [adapter/host/lock_provision.go](adapter/host/lock_provision.go), and [softwarelifecycle/mutation_lock.go](../softwarelifecycle/mutation_lock.go) |
| Linux filesystem, systemd, Certbot, firewall, process, and lock mechanics | [adapter/host](adapter/host) |
| Subscription firewall unit, effective commands, and exact enablement-link ownership | [adapter/host/subscription_firewall.go](adapter/host/subscription_firewall.go) |
| sing-box configuration, shared Client Identity replacement, and subscription URI encoding | [adapter/singbox](adapter/singbox) |
| Numbered Owner menu and Software Lifecycle choices | [adapter/terminal/run.go](adapter/terminal/run.go) and [adapter/terminal/lifecycle.go](adapter/terminal/lifecycle.go) |
| Authenticated HTTP serving and legacy TLS transaction compatibility | [subscriptionserving/README.md](subscriptionserving/README.md) and [subscriptionserving/serving.go](subscriptionserving/serving.go) |

Focused tests live beside their owning files. Adapter tests cover OS and
sing-box mechanics; package tests cover Review/Execute behavior, interruption,
restart recovery, refusal, and cleanup.

## Subscription transport

Fresh setup also offers an optional VMess WebSocket origin for the Owner's
dedicated remotely managed Cloudflare Tunnel. The hostname is bound in the protected
configuration's `vmess-ws@<hostname>` inbound tag. Both inbounds share the current
UUID and rotate together. Optional tunnel authority records only the dedicated
`sbxr-tunnel.service` unit/staging file/enablement link, reviewed prerequisite
digests and tunnel ID. It preserves the Owner's token, cloudflared package and
Cloudflare resources. Failed starts retain forward setup; precommit failure and
Complete removal clean only proved owned resources. The public connection check
is separate from local Running and uses a short-lived VMess-only client with
PID-proved loopback listener ownership. See [tunnel.go](tunnel.go), the
[host connector](adapter/host/tunnel.go), [probe](adapter/host/vmess_probe.go),
[ADR-0033](../../docs/adr/0033-optional-vmess-websocket-tunnel.md) and the
[setup guide](../../docs/setup-vmess-tunnel.md).

Fresh Enable subscription uses HTTP on fixed TCP 8443 with the existing bearer
credential and artifact contract. Its explicit HTTP authority owns no certificate,
Certbot dependency, renewal writer or TCP 80 firewall contribution. Legacy HTTPS
records and retired-resource authority retain their historical repair/removal
meaning. [ADR-0028](../../docs/adr/0028-clean-install-only.md) limits the current
product to clean installation. Transport-conversion writers and automatic migration
entrypoints are removed. Readers still recognize existing legacy and unfinished
transport authority so reviewed Complete removal can clean only its owned resources.

Subscription enablement and recorded resource removal prove the canonical main
firewall file, absence of foreign fragments and drop-ins, and the effective
systemd commands before starting or stopping that unit. Reload the verified file before using a loaded removal route. Removal
stops only that unit and deletes only its exact owned enablement link; it does
not use broad unit disablement to remove administrator-created links. If the
main file is already absent, require a quiescent unit with no main or control process and remove only the
proved dangling link. Foreign or uncertain routes refuse while
retaining recovery authority. These checks do not protect against concurrent
reconfiguration by another root process.

The certificate-specific behavior below applies to legacy HTTPS records.

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

Certificate acceptance retains its completion checkpoint until the protected
serving snapshot matches accepted authority and publication is durable. A proved
older snapshot for the same link can be synchronized through reviewed Finish
subscription change when the accepted certificate is still published and loaded.
Inspection does not write it. See the [repair validation and existing-host
recovery plan](../../docs/acceptance/reports/certificate-start-coordination-repair-2026-09-19.md).

Ordinary proxy starts pass through the owned startup integration. Client
Identity rotation closes every supported start route during cutover, restores
only the proved source before revocation, and finishes only the selected target
after revocation. Boot and private dispatch do not choose recovery direction or
create authority.

Ordinary proxy and serving starts serialize on the existing protected lock,
with a bounded, cancellable wait. Each revalidates installed and operation facts
after acquisition. Owner-controlled starts retain the authenticated descriptor
handoff; an ordinary acquired lock does not authorize a one-use cutover start.

New clean setups bind an exact boot-provisioning authority into the Ownership
Record and install an owned early systemd unit. After a reboot, its private role
may create only the absent `/run/lock/sbxr.lock` inode after verifying the
Installed Record, then rechecks that identity while holding the lock. A safe
existing inode is reused; unexpected parents, files, links, metadata, identity,
or contention refuse. Legacy records are not migrated. Ordinary proxy, serving,
renewal, and recorder roles remain existing-only and never create the lock.
Complete removal deletes only the exact owned unit, staged path, and enablement
link through the normal recorded removal sequence.

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

Failed managed Certbot attempts can retain an allowlisted CA rate-limit diagnosis
and a validated retry time in that existing receipt. View details and reviewed
certificate Repair/Finish plans show the latest failed attempt's guidance.
Unknown failures do not imply a firewall or lineage fault. Diagnostic text never
authorizes a retry or changes the recovery direction; raw issuer output is not
stored in the receipt or displayed by SBXR.

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
