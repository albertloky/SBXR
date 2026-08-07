# Cloudflare Tunnel

This Module owns Cloudflare meaning. `View` verifies one least-authority account token and the selected account, zone, delegation, and Network Policy path. The installation `Plan` contributes typed, secret-free Tunnel, route, DNS, and protected-service steps to the one System Changes transaction; it owns no second lock, journal, rollback store, or State publisher.

## Installation Plan and Apply

The one-use Plan creates one remote-managed named Tunnel. It starts with `xhttp.`, `ws.`, and `direct.` under the selected zone and accepts only a freshly rechecked eight-hex-character suffix after a conflict. It publishes only XHTTP to `http://127.0.0.1:11080` and WebSocket to `http://127.0.0.1:11081`, then terminates unmatched requests with `http_status:404`. It creates proxied CNAME records for those two hostnames and DNS-only `A` and/or `AAAA` records for the Direct TLS Hostname only when Network Policy committed that address family. A conflicting resource is never overwritten, adopted, or deleted by name.

Cloudflare creates the Tunnel ID, DNS record IDs, and run token during Apply. System Changes records each non-secret identifier before the next provider step. State alone consumes the opaque run token, fills only the Plan-bound empty fields, recalculates every candidate and service checksum, reruns all semantic validators, and durably records `Deferred State finalized`. Only then may the fixed `cloudflared.service` activate and State revision `1` publish.

The service runs as `User=cloudflared` and `Group=cloudflared`. Its token is supplied only with `--token-file /etc/sbxr/cloudflared/token`; token-valued arguments and environment variables are forbidden. The Ubuntu Adapter proves the installed binary is exactly `cloudflared 2026.7.3`, streams the protected `prepared/cloudflared.json` through the existing System Changes transaction, atomically creates the fixed token, ingress configuration, and unit files, runs `cloudflared tunnel ingress validate` before starting the unit, and then checks the `0755 root:root` shared parent, exact root-owned and `cloudflared`-readable `0750` service directory and `0640` files, and link-safe parents. Fresh-install rollback stops the unit and restores the transaction's exact absent-directory baseline.

XHTTP and WebSocket keep different hostnames, immutable DNS identifiers, profile credentials, local listeners, and Health evidence; WebSocket also keeps its own high-entropy profile path. `EvaluateTunnelHealth` returns separately identifiable XHTTP and WebSocket rows before the whole-Tunnel rollup. The production Cloudflare Adapter accepts only the exact ordered XHTTP route, WebSocket route, and final 404 publication contract; it refuses malformed or contradictory Tunnel, configuration, connection, and DNS identities before they cross the Adapter.

Whole-Tunnel health requires the committed Tunnel ID, connected status, both independent hostname routes, matching immutable DNS records, the exact loopback origins, and the 404 terminator. `CLOUDFLARE-XHTTP-ORIGIN-UNREACHABLE` and `CLOUDFLARE-WEBSOCKET-ORIGIN-UNREACHABLE` keep the two local failures separate; contradictory immutable identifiers and wrong or public origins use redacted typed findings rather than provider text. A running process, DNS alone, one healthy route, or a reconnect without both exact routes is not Healthy. Convergence stops after five minutes; temporary observations stop after three failures.

After those owned records converge, the Executor binds its observation to the journaled Direct record IDs, then exposes a typed Certificate DNS handoff containing only the committed Direct TLS Hostname, its qualified addresses, and the closest CAA set at that hostname or the selected zone. It reads but never changes CAA, ignores unrelated `_acme-challenge` records, and does not expose the management token or any Cloudflare resource ID. Missing expected addresses are treated as provider delay; extra, changed-ID, changed-address, or proxied Direct records are DNS drift.

## View

`View` accepts one selected account ID, zone ID, zone name, memory-only Cloudflare account API token, and the typed Cloudflare Tunnel path from Network Policy. It returns only allowlisted account, zone, delegation, activation, credential, capability, expiry, last-check, walkthrough, and Health facts.

The token must use Cloudflare's current `cfat_` account-token format. The exact accepted policy is:

| Permission | Resource |
|---|---|
| `Account API Tokens Read` | only the selected account |
| `Cloudflare Tunnel Edit` | only the selected account |
| `DNS Write` | only the selected zone |

The current dashboard renders those as `Account > Account API Tokens > Read`, `Account > Cloudflare Tunnel > Edit`, and `Zone > DNS > Edit`.

`Account API Tokens Read` lets SBXR read the presented token's policy and reject extra permissions or wildcard resources. SBXR does not request `Account API Tokens Write`, cannot create or revoke tokens, and accepts no unrelated permission. `Cloudflare Tunnel Edit` and `DNS Write` include the reads needed by `View`; their effective write behavior remains unproved until a later approved transaction performs and health-checks the real changes.

The production Adapter uses only Bearer authentication and the selected resource paths:

- `GET /accounts/{account_id}/tokens/verify`
- `GET /accounts/{account_id}/tokens/{token_id}`
- paginated `GET /zones?account.id={account_id}&name={zone_name}`
- public DNS nameserver lookup for the selected zone

Provider response text and unknown fields do not cross the Module Interface. Malformed, ambiguous, unauthorized, forbidden, permanent, and temporary failures become stable typed Health results. Temporary checks stop after three attempts and two 30-second waits inside one 60-second bound.

## Current onboarding labels

The walkthrough was qualified on `2026-08-07` against these Cloudflare dashboard labels:

- `Manage Account > Account API Tokens`
- `selected domain > DNS > Records`
- `Cloudflare One > Networks > Tunnels & Mesh`

Every release containing onboarding changes must requalify these labels. The fixed resource boundary and permissions do not change merely because Cloudflare renames a page.

## Secret and network boundary

The complete token remains in the `ManagementToken` value supplied by the caller and is sent only in the HTTP `Authorization` header. Its ordinary string and Go formatting are masked. General `View` output contains no token marker; the dedicated credential detail may return only the first and last four characters.

`View` has no persistence path. Before `Apply`, abandonment, TUI closure, SSH loss, failed preflight, or process exit therefore leaves no stored token. Only a Healthy result exposes an opaque `VerifiedManagementToken` handoff to State. The existing State/System Changes transaction stores that handoff only when fresh-install revision `1` publishes; rollback to the proven Not installed baseline removes it.

Cloudflare Tunnel consumes Network Policy's typed proof for verified Cloudflare HTTPS and outbound TCP and UDP `7844`. It cannot edit the resolver, outbound network, provider firewall, or Network Policy result.

## Correction Flow

Missing or broader permission, wildcard or changed scope, inactive status, and unproved binding return exactly:

1. `Check current token again`
2. `Enter replacement token`
3. `Verify replacement`
4. `Back`

There is no `Continue anyway` path. A pending zone instead offers `Check again`, `Wait another 10 minutes`, and `Back and continue later` with assigned and publicly observed nameserver facts, a 10-minute activation-check window, and exact registrar guidance.
