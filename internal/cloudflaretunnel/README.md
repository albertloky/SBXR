# Cloudflare Tunnel

This Module owns Cloudflare meaning. `CFT-01` provides the read-only authority `View`. `CFT-02` adds one deterministic Plan-to-Apply path for the initial named Tunnel and XHTTP publication. WebSocket, direct-hostname DNS, token lifecycle, repair, and removal remain in `#87`–`#92`.

## XHTTP Plan and Apply

`Plan` re-runs `View`, reads the exact selected Tunnel name and XHTTP hostname, rejects any existing matching Tunnel or DNS record instead of adopting it, and binds the account, zone, active token identity, fresh provider observation, starting revision, Desired State checksum, fixed origin, and qualified `cloudflared 2026.7.3` baseline. Its preview is deterministic and contains no token or secret-derived value.

`Apply` burns the Plan on its first attempt and refuses a changed Desired State or provider observation. Through the one System Changes transaction handoff it creates exactly one remotely managed `cfd_tunnel`, durably records its returned UUID, publishes only `xhttp.<owned-domain>` to `http://127.0.0.1:11080` followed by `http_status:404`, creates the exact proxied CNAME and durably records its returned ID, then prepares `cloudflared.service`. A later provider step cannot run before the preceding new identifier is recorded.

The service contract is fixed to the distinct `cloudflared` identity and `--token-file /etc/sbxr/cloudflared/token`. The complete run token is protected transaction material, never an argument, environment value, Plan field shown to the Owner, or event. Service-readable directories and files are `0750` and `0640`; the System Changes Adapter must also refuse symlinks, wrong ownership, writable parents, or wider modes before acknowledging preparation.

Required health waits no longer than five minutes and proves one connected Tunnel, the exact route plus final 404, the exact proxied DNS record, and the loopback HTTP origin. Process state or DNS alone cannot pass. Failure reverses the DNS record then Tunnel by the immutable IDs created and recorded by that Change Set; failure to prove reversal is `Recovery Required`.

## View

`View` accepts one selected account ID, zone ID, zone name, memory-only Cloudflare account API token, and the typed Cloudflare Tunnel path from Network Policy. It returns only allowlisted account, zone, delegation, activation, credential, capability, expiry, last-check, walkthrough, and Health facts.

The token must use Cloudflare's current `cfat_` account-token format. The exact accepted policy is:

| Permission | Resource |
|---|---|
| `Account API Tokens Read` | only the selected account |
| `Cloudflare Tunnel Edit` | only the selected account |
| `DNS Write` | only the selected zone |

The current dashboard renders those as `Account > Account API Tokens > Read`, `Account > Cloudflare Tunnel > Edit`, and `Zone > DNS > Edit`.

`Account API Tokens Read` lets SBXR read the presented token's policy and reject extra permissions or wildcard resources. SBXR does not request `Account API Tokens Write`, cannot create or revoke tokens, and accepts no unrelated permission. `CFT-02` proves the effective `Cloudflare Tunnel Edit` and `DNS Write` behavior only when the approved Apply completes and required health passes.

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
