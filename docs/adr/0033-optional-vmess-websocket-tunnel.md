---
status: accepted
---

# Add optional VMess WebSocket through an external named tunnel

## Guided connector refinement, 2026-10-22

The Owner's follow-on implementation request supersedes this decision's original
connector boundary below for new clean VMess setups. Cloudflare account/domain,
tunnel creation/selection and DNS remain Owner actions in the dashboard. The
guided menu identifies those prerequisites and binds the tunnel ID from a
protected Owner-provisioned token before confirmation. There are no account API
calls, hardcoded personal domains, account certificates or automatic DNS changes.

Proxy Installation now owns only a dedicated `sbxr-tunnel.service`, its staging
file and exact enablement link through optional Ownership Record authority.
The Owner-installed official `/usr/bin/cloudflared` and root-owned mode-0600
`/etc/cloudflared/sbxr.token` remain prerequisites and are preserved on removal.
Their reviewed digests and tunnel ID are recorded without the token. Foreign
units, links, drop-ins or changed prerequisites refuse; existing connector
services are neither adopted nor changed. The unit uses `DynamicUser`,
`LoadCredential`, `--token-file`, an empty configuration source and loopback-only
metrics, with no token in arguments, subscriptions or diagnostic output.

Authority precedes effects. Precommit failure cleans the recorded connector;
postcommit start failure retains Finish setup direction. Complete removal
revalidates and removes only its exact dedicated unit/link without requiring
the token, binary or Cloudflare access. Historical records have no connector
authority and cannot acquire it through inspection or ordinary software updates.
Compatible update admission additionally requires the dedicated-tunnel capability
marker; the product still refuses new Update operations under ADR-0028.

Local Running remains separate from public readiness. Confirmed VMess setup
and the repeatable Check VMess connection action perform bounded local/public
WebSocket upgrades and authenticated VMess-only HTTPS egress checks. The probe
uses normal TLS validation, a PID-proved authenticated loopback listener, no
direct/VLESS fallback, memory/stdin-only credentials and guaranteed process reap.
A missing/failed check reports connection pending. A server-originated pass
does not establish outside-client/Karing or packaged release qualification.

This refines source behavior only. It authorizes no new live host, credential,
account, DNS, security, Karing or publication action. See the
[setup and recovery guide](../setup-vmess-tunnel.md).

## Original boundary in commit 1bc15c7

The Owner's 2026-10-22 request authorizes source implementation and offline
tests for VMess over WebSocket through a named Cloudflare Tunnel alongside
VLESS REALITY Vision. Deployment, account/DNS/tunnel changes, credentials,
publication and live qualification are outside this authorization.

For clean setup, retain the existing Start setup action and add an explicit
VMess variant accepting a validated public DNS hostname. The variant adds a
VMess AEAD inbound on `127.0.0.1:10000` with WebSocket path `/sbxr-vmess`.
A separately managed `cloudflared` connector forwards the named hostname to
that HTTP origin. Outside clients use TLS on the hostname's TCP 443. SBXR owns
only its existing configuration, service and lifecycle resources. It does not
install, configure, inspect, stop or remove the connector or Cloudflare resources.

This deliberately refines ADR-0016's single endpoint and single subscription
node restrictions and permits the hostname input needed for the requested
transport. One Proxy Profile still has one Client Identity: VLESS and VMess
share a UUID, and the existing sequential identity rotation replaces both
together. There are no independent users, profiles, rotation transactions or
new cleanup authorities. The existing protected configuration digest binds the
additional inbound and its hostname tag. The HTTP Subscription Artifact keeps
the default VLESS URI unchanged and appends one VMess URI only when enabled.
Client configuration keeps VLESS as its default outbound.

The embedded sing-box 1.14.3 cloudflared inbound is packaged, but requires a
tunnel token inline in general runtime configuration. The external connector
keeps that Infrastructure Secret outside SBXR and avoids adding connector
installation, credential storage and lifecycle ownership. See the
[source and package checks](../research/vmess-cloudflare-tunnel.md).

Keep ADR-0028's clean-install-only policy and ADR-0026's HTTP subscription
authentication and exposure contract. A local Running result does not prove
the named tunnel, DNS, edge TLS, or VMess client traffic. No existing five-journey
live pass certifies the optional two-node subscription or tunnel route; these
remain explicit missing deployment/qualification evidence.
