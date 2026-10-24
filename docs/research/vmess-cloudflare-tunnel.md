# Optional VMess WebSocket and named Cloudflare Tunnel

The original connector boundary below describes commit `1bc15c7`. The later
guided implementation adds dedicated local connector ownership and public
connection checks; see the [current setup guide](../setup-vmess-tunnel.md) and
[ADR-0033 refinement](../adr/0033-optional-vmess-websocket-tunnel.md#guided-connector-refinement-2026-10-22).
The pinned sing-box option/package observations below remain applicable. They do
not qualify the later connector code or supply release/Karing acceptance.

## Connector choice and verified 1.14.3 support

The [official cloudflared inbound documentation](https://sing-box.sagernet.org/configuration/inbound/cloudflared/)
describes an embedded connector introduced in 1.14.0. The tagged
[1.14.3 registration](https://github.com/SagerNet/sing-box/blob/v1.14.3/include/cloudflared.go)
is guarded by `with_cloudflared`; its
[options](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/cloudflared.go)
accept an inline token and have no token-file option. The
[inbound implementation](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/cloudflare/inbound.go)
passes connector connections through sing-box routing. Existence alone would
not establish HTTP/WebSocket origin behavior or secure credential handling.

On 2026-10-22 the actual pinned APT `amd64` DEB and official macOS `arm64`
archive matched the [recorded 1.14.3 hashes](sing-box-1.14.3-compatibility.md).
`go version -m` on the extracted Linux executable and `sing-box version` on
macOS both showed `with_cloudflared`, revision
`7054cac5124465ffdb145870d7c01885566711b1`. The Linux package was inspected,
not installed or executed. Packaging support is confirmed; no embedded tunnel
connection was attempted.

SBXR uses a separate, Owner-managed `cloudflared` connector forwarding to a
loopback VMess WebSocket origin. This keeps tunnel tokens and credential files
out of SBXR configuration, subscriptions and logs. It adds no Go dependency,
managed daemon, credential store or account API. Inclusion in both binaries
does not make embedded credential/lifecycle management necessary for this task.

The tagged [VMess options](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/vmess.go)
and [WebSocket options](https://github.com/SagerNet/sing-box/blob/v1.14.3/option/v2ray_transport.go)
support the generated inbound and client outbound. The official macOS 1.14.3
binary accepted six actual generated configurations without warnings: default,
VMess-enabled and identity-rotated server/client pairs. `check` does not open
listeners or prove proxy traffic. Local artifacts are in
`.scratch/acceptance/w1/`; no tunnel token or live account input was used.

## Configuration and deployment inputs

For fresh setup, select **Start setup**, then **Standard + Cloudflare**. Follow
the preparation steps, supply a lowercase hostname such as `tunnel.example.com`,
review the plan and tunnel ID, then Apply. The default **Standard** choice needs
no domain or token. The optional setup checks that TCP 10000 is
unused at review and execution, and adds:

| Boundary | Configuration |
|---|---|
| Named tunnel hostname | Owner-supplied DNS name, never a URL, IP or credential |
| Connector origin | `http://127.0.0.1:10000` on the same host/network namespace |
| Origin WebSocket path | `/sbxr-vmess` |
| Outside VMess client | hostname TCP 443, TLS enabled, matching SNI and Host, WebSocket |
| Authentication | VMess AEAD (`alterId` zero), same generated UUID as VLESS |
| VLESS | Existing IPv4 TCP 443, REALITY and Vision unchanged |
| Subscription | Existing authenticated HTTP endpoint; VLESS URI plus optional VMess v2 URI |

This is a fresh-setup choice, not an in-place extension of an installed profile.
An existing installation must complete reviewed removal/recovery through its
exact installed release, then clean-install a qualified VMess-capable release
and select this setup variant. Expect downtime, new client credentials, a new
Subscription Link and client reconfiguration. The implementation in this checkout
has not been published or live-qualified; no existing release acquires it from
these source changes.

Future deployment still needs an existing or separately created named tunnel,
its connector installation and protected credential provisioning, a published
hostname/DNS route, edge TLS and forwarding to the origin above. These must be
configured through secure account/host channels; never paste tokens in chat or
place them in subscription artifacts. A random Quick Tunnel is not this design.
The connector must have outbound Cloudflare connectivity and restart management.
Any Access policy must allow the chosen VMess client to connect without an
interactive browser login. Cloudflare documents the HTTP published-origin
model in its [protocol reference](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/protocols/).
Its [WebSocket reference](https://developers.cloudflare.com/network/websockets/)
confirms proxy support and describes connection restarts and idle timeouts.
Cloudflare Tunnel is the connector service used here; paid Argo Smart Routing
is a separate product documented as incompatible with WebSockets.

Select either imported node in the client. The disclosed sing-box JSON includes
both outbounds; VLESS stays the default, and a client choosing VMess can use
`vmess-ws-out` as its routing final. Rotation updates both protocol credentials
and subscription nodes through the existing transaction. Rotating the HTTP
Subscription Link remains independent. HTTP subscription interception and
tampering risks remain, including exposure of both client credentials.

Complete removal stops the managed sing-box process and removes its exact
configuration through existing ownership authority. It preserves the separate
connector, its credentials, DNS and named tunnel. The Owner must separately
retire or repoint that connector/route; an unused forwarding origin should not
be reassigned casually. No live host, Cloudflare, DNS, TLS edge, outside traffic
or Karing acceptance has been performed. See [ADR-0033](../adr/0033-optional-vmess-websocket-tunnel.md).
