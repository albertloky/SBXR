---
status: accepted
---

# Add optional VMess WebSocket through an external named tunnel

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
