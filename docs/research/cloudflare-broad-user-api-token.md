# Dedicated broad Cloudflare User API Token

**Decision:** SBXR can use one broad **User API Token** for the Cloudflare Profile Setup flow. The token can cover all accounts and all zones that the Cloudflare user can access. It must grant only these capabilities:

- `Account` → `Cloudflare Tunnel` → `Edit` for `Include` → `All accounts`;
- `Zone` → `DNS` → `Edit` for `Include` → `All zones`;
- `Zone` → `Zone` → `Read` for `Include` → `All zones`.

The first two labels are the current dashboard-guide labels. Cloudflare's current endpoint contracts call the equivalent accepted permissions `Cloudflare Tunnel Write` and `DNS Write`. Cloudflare documents permission names as cosmetic and subject to change. The implementation must therefore keep stable internal capability names, requalify the visible dashboard labels for each release, and prove the supplied token through the exact API operations that SBXR needs. [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/) · [Create tokens via API](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/) · [Set up Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)

Do not accept a Global API Key. Do not add `API Tokens Read`, `API Tokens Edit`, `API Tokens Write`, Account Settings, Billing, Memberships, Workers, WAF, email, or another unrelated permission. This note records current Cloudflare documentation and API contracts as checked on `2026-08-16`. It is not live proof from an Owner account.

## Exact current dashboard guide

The Cloudflare Profile Setup screen can give this guide:

1. Sign in to the Cloudflare dashboard.
2. Go to **My Profile** → **API Tokens**. This location creates a User API Token. Do not use **Manage Account** → **API Tokens**, which creates an Account API Token.
3. Select **Create Token**.
4. Select **Custom token**. Do not use the **Edit zone DNS** template because SBXR also needs Tunnel permission.
5. Enter the token name `SBXR broad automation`.
6. Add these permission rows:

   | Type | Item | Permission |
   | --- | --- | --- |
   | Account | Cloudflare Tunnel | Edit |
   | Zone | DNS | Edit |
   | Zone | Zone | Read |

7. Under **Account Resources**, select **Include** → **All accounts**.
8. Under **Zone Resources**, select **Include** → **All zones**.
9. Do not add other permissions.
10. Optional: in **Client IP Address Filtering**, restrict use to the VPS public egress IP only if that IP is fixed. A changed egress IP would block later repair and removal.
11. Leave the token without an expiry if SBXR must retain it for later health, repair, rotation, and Complete removal. If the Owner sets a TTL, SBXR must show its expiry and require replacement before provider mutations.
12. Select **Continue to summary**.
13. Confirm that the summary contains only the three permission rows and the two all-resource scopes above.
14. Select **Create Token**.
15. Copy the secret immediately. Cloudflare shows it only once. Store a second copy in the Owner's password manager.
16. Return to **Set up Cloudflare profiles**, paste the token into the masked field, and continue.

Cloudflare's generic creation guide explicitly gives **My Profile** → **API Tokens**, **Create Token**, template or custom-token selection, permissions, resources, optional IP and TTL restrictions, **Continue to summary**, **Create Token**, and one-time secret copying. It says `Edit` is full create, read, update, delete, and list access. Cloudflare's Tunnel guide gives the current dashboard rows `Account` / `Cloudflare Tunnel` / `Edit` and `Zone` / `DNS` / `Edit`. `Zone` / `Zone` / `Read` is additionally required by the List Zones endpoint used for SBXR discovery. [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [Set up Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/) · [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)

Cloudflare supports the required broad scopes in its token-policy model:

```text
All accounts:             "com.cloudflare.api.account.*": "*"
All zones in all accounts: "com.cloudflare.api.account.zone.*": "*"
```

A User API Token acts as its user and cannot exceed that user's effective Cloudflare access. "All" means all resources in the selected wildcard scope that are visible to that user. It does not grant access to an account or zone that the user cannot access. [Create tokens via API](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/) · [Account API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/)

## Authentication and credential recognition

Every Cloudflare API request made with this token uses one header:

```text
Authorization: Bearer <API_TOKEN>
```

Do not request or send the Cloudflare user email. Do not send `X-Auth-Email` or `X-Auth-Key`; those headers belong to the legacy Global API Key scheme. New User API Tokens use a `cfut_` scannable prefix. Pre-2026 unprefixed User API Tokens still work, so the prefix can distinguish and reject new Global API Keys but is not a complete compatibility rule by itself. SBXR must use the verification endpoint as the authoritative credential-type check. [Make API calls](https://developers.cloudflare.com/fundamentals/api/how-to/make-api-calls/) · [Token formats](https://developers.cloudflare.com/fundamentals/api/get-started/token-formats/) · [Verify Token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify)

The first call must be:

```text
GET /client/v4/user/tokens/verify
```

It returns only the token identifier, status, optional expiry, and optional not-before time. Require `success: true` and `result.status: active`. Persist the token identifier and any returned time limits with the root-only secret so health can identify expiry or replacement. Client IP filtering does not apply to this verification endpoint, so a successful verification call alone does not prove that normal API calls from the VPS are allowed. [Verify Token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify) · [Restrict tokens](https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/)

## Zone and account discovery without a Global API Key

Do not call `GET /accounts`. Cloudflare's current List Accounts contract documents only the legacy API Email plus API Key security scheme. The broad User API Token does not need that endpoint. [List Accounts](https://developers.cloudflare.com/api/resources/accounts/methods/list/)

Use this endpoint instead:

```text
GET /client/v4/zones?status=active&page=<n>&per_page=50
```

`Zone` → `Zone` → `Read` authorizes this call. Each returned zone contains the zone `id`, zone `name`, status, type, and an `account` object with its `id` and name. SBXR can therefore let the Owner select an active Cloudflare DNS zone, then derive both immutable IDs from that selected result. It does not need the Owner to copy an Account ID or Zone ID. Follow pagination. Cloudflare currently does not allow listing zones across more than 500 accounts; this limit must produce a Correction Flow, not a request for the Global API Key. [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)

The all-account Tunnel policy applies when SBXR later uses the selected zone's `account.id` in Tunnel calls. Zone discovery therefore proves the link between the selected zone and account without separate account discovery.

## Required API operations

The token must support only the provider operations below.

### Cloudflare Tunnel

- list and inspect owned Tunnels: `GET /accounts/{account_id}/cfd_tunnel` and `GET /accounts/{account_id}/cfd_tunnel/{tunnel_id}`;
- create one remotely managed Tunnel: `POST /accounts/{account_id}/cfd_tunnel` with `config_src: "cloudflare"`;
- read and replace ingress configuration: `GET` and `PUT /accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations`;
- obtain the run token: `GET /accounts/{account_id}/cfd_tunnel/{tunnel_id}/token`;
- delete the owned Tunnel during rollback or Complete removal: `DELETE /accounts/{account_id}/cfd_tunnel/{tunnel_id}`.

The endpoint contracts accept `Cloudflare Tunnel Write`; the current dashboard guide names it `Cloudflare Tunnel Edit`. The returned Tunnel run token is a separate secret. It runs that Tunnel but does not grant DNS or provider-management authority. [Cloudflare Tunnel API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/) · [Get a Cloudflare Tunnel token](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/subresources/token/methods/get/) · [Set up Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)

### DNS

- list records to reject conflicts and verify immutable ownership: `GET /zones/{zone_id}/dns_records`;
- create SBXR-owned A, AAAA, and proxied Tunnel CNAME records: `POST /zones/{zone_id}/dns_records`;
- read, replace or patch only a record whose immutable ID is owned by SBXR: `GET`, `PUT`, or `PATCH /zones/{zone_id}/dns_records/{dns_record_id}`;
- delete only an SBXR-owned record: `DELETE /zones/{zone_id}/dns_records/{dns_record_id}`.

The endpoint contracts accept `DNS Write`; the current dashboard guide names it `DNS Edit`. Cloudflare token scope stops at a zone. It cannot restrict the token to SBXR record names or record types. SBXR must enforce that narrower ownership boundary through reviewed Plans and immutable record IDs. [DNS Records API](https://developers.cloudflare.com/api/resources/dns/subresources/records/) · [Create DNS Record](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/) · [List DNS Records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)

## What SBXR can and cannot inspect

`GET /user/tokens/verify` proves only whether the supplied User API Token works and reports its identifier and time status. It does not return the token's policies, permission groups, resource scopes, IP restrictions, name, or last-use time. [Verify Token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify)

The full token-detail endpoint does return policies and resources, but it requires `API Tokens Read` or `API Tokens Write`:

```text
GET /user/tokens/{token_id}
```

Adding token-management permission solely so SBXR can inspect its own policy would materially enlarge authority. Do not add it. The Cloudflare Profile Setup screen must require the Owner to confirm the exact summary before creation. SBXR must then perform read-only functional probes against zone discovery, DNS listing, Tunnel listing, and any configured IP restriction. Apply proves write capability when it creates the reviewed owned resources; a failure remains inside the atomic Change Set. [Token Details](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get) · [Create tokens via API](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/)

Because the token cannot inspect its own wildcard policy, SBXR cannot cryptographically prove from the pasted secret alone that **all accounts** and **all zones** were selected. It can prove access only to the resources returned or exercised by API calls. The guide and Owner confirmation are the configuration evidence; endpoint probes and Apply are the automated evidence. Do not claim that one substitutes for the other.

## Storage, expiry, rotation, and revocation

Cloudflare says the token secret is shown once, must be copied to a secure location, and must not be stored in plaintext where others can access it or committed to a repository. Cloudflare does not define a Linux filesystem layout or a `root-only` storage mechanism. Root-only storage, exclusion from logs and support bundles, redaction, and process-delivery rules remain SBXR security requirements, not Cloudflare claims. [Create API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) · [Make API calls](https://developers.cloudflare.com/fundamentals/api/how-to/make-api-calls/)

Cloudflare tokens are long lived by default. Optional TTL and client-IP restrictions are supported. If SBXR retains the broad token, health must use the stored verification facts and bounded API checks. It must treat `disabled`, `expired`, rejection from the VPS IP, or a changed token identifier as a credential Correction Flow. [Restrict tokens](https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/) · [Verify Token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify)

Cloudflare supports **Roll** from **My Profile** → **API Tokens** → the token's three-dot menu → **Roll** → **Confirm**. Rolling creates a new secret with the same access and permissions and immediately invalidates the previous secret. SBXR cannot roll this token because the roll endpoint requires `API Tokens Write`, which the SBXR token must not have. After an Owner roll, SBXR must accept and verify the replacement secret as one reviewed credential change before discarding the old stored value. [Roll tokens](https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/) · [Roll Token API](https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/value/methods/update)

Revocation is deletion of the token. The API endpoint `DELETE /user/tokens/{token_id}` also requires `API Tokens Write`, so SBXR cannot revoke itself. The Owner must delete or revoke it through Cloudflare's API Tokens page or with a separate token-management credential that SBXR never receives. Complete removal can delete the SBXR-owned DNS and Tunnel resources using the retained broad token, then instruct the Owner to revoke the User API Token after SBXR no longer needs it. [Delete Token](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/delete/)

## Exact Global API Key comparison

| Property | Dedicated broad User API Token | Legacy Global API Key |
| --- | --- | --- |
| Dashboard location | **My Profile** → **API Tokens** → **Create Token** | **User Profile/My Profile** → **API Tokens** → **API Keys** → **Global API Key** → **View** |
| SBXR input | One token secret | Cloudflare user email plus key |
| API authentication | `Authorization: Bearer <API_TOKEN>` | `X-Auth-Email: <EMAIL>` and `X-Auth-Key: <GLOBAL_API_KEY>` |
| Resource scope | Explicit all-account and all-zone wildcards, still limited by the user's effective access | All Cloudflare resources available to the user |
| Permission scope | Tunnel write, DNS write, and Zone read only | Exactly the same permissions as the user |
| Token count | Cloudflare currently permits up to 50 User API Tokens | One Global API Key per user |
| Runtime restrictions | Optional IP ranges and TTL | No equivalent advanced IP or time limits |
| Independent roll or revocation | Yes; affects this token | Changing the one key can affect every system using it |
| Current Cloudflare position | Preferred API authorization | Previous scheme; not recommended for new customers |

Cloudflare explicitly says a Global API Key has access to all resources available to the user, has the user's exact permissions, is limited to one per user, lacks the API token's advanced limits, and is not recommended for new customers. New Global API Keys have a `cfk_` prefix. SBXR must reject this credential type and must never request the Cloudflare user email. [Get Global API key (legacy)](https://developers.cloudflare.com/fundamentals/api/get-started/keys/) · [Token formats](https://developers.cloudflare.com/fundamentals/api/get-started/token-formats/) · [API rate limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/)

## Specification requirements from this research

1. Specify one User API Token and the exact three capabilities and broad scopes at the start of this note.
2. Use the current dashboard labels in the guide, but define capability identities separately because Cloudflare uses both `Edit` and `Write` in current first-party documentation.
3. Requalify dashboard navigation, labels, and summary wording at release time. Current documentation is not proof of a future dashboard.
4. Reject the Global API Key, Account API Token, email-plus-key authentication, and unrelated permissions.
5. Verify the token with `/user/tokens/verify`, then discover zones and their accounts through paginated `/zones`; do not depend on `/accounts`.
6. Require Owner confirmation of the exact token summary. Do not add token-management authority only for policy introspection.
7. Prove normal API use from the VPS after verification because Verify Token ignores client-IP filtering.
8. Keep configuration evidence, functional endpoint evidence, atomic Apply evidence, and live Cloudflare acceptance separate.
9. Store the broad management token and Tunnel run token as separate root-only secrets. Never expose either in Desired State displays, logs, diagnostics, journals, support bundles, command arguments, or environment variables.
10. Make replacement, expiry, roll, and revocation explicit Owner journeys. SBXR can replace its stored token but cannot roll or revoke it with the approved permission set.

## Unresolved first-party documentation ambiguity

Cloudflare's official documents currently use two names for write permissions. Dashboard-oriented guides use `Cloudflare Tunnel` → `Edit` and `DNS` → `Edit`. API endpoint contracts and newer permission tables use `Cloudflare Tunnel Write` and `DNS Write`, while the permission reference currently exposes both old and new wording in parts of the same page. The underlying permission-group ID is the stable API identity, but the approved SBXR token cannot query permission groups or its own full policy without adding `API Tokens Read` or `API Tokens Write`. The product guide must therefore treat exact visible labels as release-qualified content and fail clearly if Cloudflare changes them.

The first-party docs also do not document a User API Token security scheme for `GET /accounts`, even though they do for `GET /zones`. This research therefore rejects `/accounts` as an SBXR dependency and derives the account from the selected zone response.
