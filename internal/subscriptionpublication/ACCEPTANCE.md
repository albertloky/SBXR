# Subscription Publication acceptance

This procedure covers issues #109–#114: deterministic representations and catalog metadata from one complete typed Connection Profile source, one reviewed immutable artifact set, and coordinated Client Access Value rotation and revocation.

## Module Verification — automated — Codex

Run:

```sh
go test ./internal/subscriptionpublication/... -count=1
```

Pass only when these stable checks all pass:

- `SUBSCRIPTION-PUBLICATION-RAW`: one URI per enabled Connection Profile, canonical order, UTF-8, LF separators, and no wrapper text.
- `SUBSCRIPTION-PUBLICATION-BASE64`: standard padded base64 decodes to the exact raw bytes.
- `SUBSCRIPTION-PUBLICATION-V2RAYN`: v2rayN bytes equal the complete base64 URI list.
- `SUBSCRIPTION-PUBLICATION-URI-FIELDS`: every fixed scheme, user-info value, address, port, query key, fragment, TLS verification value, REALITY value, XHTTP `mode=auto`, Hysteria2 obfuscation choice, and TUIC congestion value agrees with the typed source; disabled obfuscation and zero-RTT fields are absent.
- `SUBSCRIPTION-PUBLICATION-ENCODING`: IPv4, bracketed IPv6, reserved characters, spaces, non-ASCII labels, paths, and passwords survive a URI parse without changing value.
- `SUBSCRIPTION-PUBLICATION-DETERMINISM`: rendering the same source twice produces byte-identical raw, base64, and v2rayN output.
- `SUBSCRIPTION-PUBLICATION-OMISSION`: a disabled Connection Profile's exact omission fact produces no URI and no substituted Connection Profile.
- `SUBSCRIPTION-PUBLICATION-SECRETS`: independent credential and path markers reach only their own URI; ordinary formatting, JSON rendering, and errors expose no body or Client Access Value.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-COUNT`: exactly the enabled Connection Profiles appear once with unique stable names.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-FIELDS`: all six exact top-level and nested field contracts agree with the typed source; unknown or unsupported fields are refused.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-GROUP`: the stable `SBXR` select group refers only to rendered Connection Profile names and `MATCH,SBXR` is the final route.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-TLS`: every direct Connection Profile uses the canonical Direct TLS Hostname, verification remains enabled, TUIC 0-RTT remains disabled, and disabled Hysteria2 obfuscation is absent.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-VALIDATION`: a full-document validator must accept before `Render` returns any artifact; refusal and malformed output produce one secret-safe failure.
- `SUBSCRIPTION-PUBLICATION-MIHOMO-OMISSION`: a disabled Connection Profile disappears from both `proxies` and group references without substitution; when all six are disabled, the valid document contains an empty `proxies` list and no group or rule.
- `SUBSCRIPTION-PUBLICATION-SING-BOX-COUNT`: exactly five supported enabled Connection Profiles appear once in canonical order; VLESS XHTTP never appears as an outbound.
- `SUBSCRIPTION-PUBLICATION-SING-BOX-FIELDS`: the local `mixed` inbound, local DNS, route, final `SBXR` selector, and every required VLESS REALITY Vision, VLESS WebSocket, Hysteria2, TUIC, AnyTLS, TLS, transport, congestion, and zero-RTT field agree with the typed source.
- `SUBSCRIPTION-PUBLICATION-SING-BOX-OMISSION`: enabled VLESS XHTTP is `Not offered` without substitution; deliberate disablement takes precedence for any Connection Profile, including XHTTP, which is then absent and reported as `Disabled`; the all-disabled document has no listener, outbound, selector, or final route.
- `SUBSCRIPTION-PUBLICATION-SING-BOX-VALIDATION`: the complete document must pass the pinned full-document validator before `Render` returns any artifact; refusal and malformed JSON produce one secret-safe failure.
- `SUBSCRIPTION-PUBLICATION-KARING`: Karing receives byte-identical validated sing-box JSON, reports five supported Connection Profiles, and says VLESS XHTTP is `Not offered` because it is unavailable in the Karing core.
- `SUBSCRIPTION-PUBLICATION-CATALOG`: `View` returns exactly `/base64`, `/raw`, `/v2rayn`, `/shadowrocket`, `/karing`, `/mihomo`, and `/sing-box` in stable order, and each identity maps one-to-one to one validated artifact body.
- `SUBSCRIPTION-PUBLICATION-CATALOG-COUNT`: v2rayN and Mihomo report every enabled Connection Profile; sing-box and Karing omit XHTTP and report the actual supported enabled count; every other disabled Connection Profile is deliberately `Disabled`, never `Failed` or substituted.
- `SUBSCRIPTION-PUBLICATION-VIEW`: publication status, the token-free selected HTTPS subscription address, compatibility definition, and proven Desired State revision/SHA-256 determine agreement without returning a token or generated body; stale compatibility requires regeneration.
- `SUBSCRIPTION-PUBLICATION-FALLBACK`: an unknown or ambiguous client receives `/base64`; User-Agent is convenience only and never authentication, authorization, or compatibility proof.
- `SUBSCRIPTION-PUBLICATION-SHADOWROCKET-CANDIDATE`: Shadowrocket bytes equal the complete six-URI base64 candidate, while every rendered Connection Profile remains pending exact pinned maintained-app Owner Acceptance.
- `SUBSCRIPTION-PUBLICATION-NAMED-ACCESS`: catalog labels and suffixes support only the dedicated authenticated Access surface; no separate format-selection menu or ordinary-dashboard Client Access Value is introduced.
- `SUBSCRIPTION-PUBLICATION-PLAN`: one deterministic secret-safe Plan binds revision `N+1`, starting lineage, relevant managed-input checksums, compatibility definition, selected address, exact typed source, Release Identity, seven representation identities, counts, omissions, full validation, complete replacement, and exact rollback intent.
- `SUBSCRIPTION-PUBLICATION-PLAN-ONE-USE`: stale, changed, malformed, incomplete, or reused Plan and prepared-artifact authority is refused without exposing a body, token, Client Access Value, complete URL, credential, or secret marker.
- `SUBSCRIPTION-PUBLICATION-CANDIDATE-SET`: State accepts only the owning Module's complete reviewed bundle; that bundle validates and enumerates the exact eight-file set, protected metadata binds every named body by SHA-256, and System Changes durably binds the complete bundle SHA-256 before live work.
- `SUBSCRIPTION-PUBLICATION-ATOMIC-ACTIVATION`: the filesystem Adapter writes one root-only candidate generation and atomically exchanges it into the real `/var/lib/sbxr/subscriptions/current/` directory on supported Ubuntu targets; readers observe the complete prior or complete candidate set, never a mixture.
- `SUBSCRIPTION-PUBLICATION-TRANSACTION`: one System Changes transaction activates the candidate, passes Required pre-publication health, publishes Desired State exactly once, proves post-publication agreement, records durable `Complete`, and refuses Plan reuse.
- `SUBSCRIPTION-PUBLICATION-ROLLBACK`: incomplete preparation, storage, directory activation, pre-publication, post-publication, and Subscription Serving health failures leave nothing activated or restore the exact prior artifact set and Desired State; an unprovable reverse remains `Recovery Required`.
- `SUBSCRIPTION-PUBLICATION-RESTART`: inactive candidate directories and rollback retry resolve from durable inspection; unprovable lineage or rollback remains `Recovery Required`.
- `SUBSCRIPTION-PUBLICATION-SERVING-BOUNDARY`: the real `current/` directory contains only the seven named bodies and metadata at `0640` under the sole group-traversable `0750` directory; `sets/` and inactive generations are root-only `0700`, parent and final symlinks are refused, and Subscription Serving receives no Desired State, renderer, typed source, validator, or arbitrary file path.
- `SUBSCRIPTION-PUBLICATION-TOKEN-STRENGTH`: each subscription token contains 256 bits from operating-system cryptographic randomness, two rotations are independent, and no injectable randomness Adapter exists.
- `SUBSCRIPTION-PUBLICATION-TOKEN-ONLY`: token-only rotation replaces only the subscription token and truthfully states that prior future downloads stop while already downloaded Connection Profile credentials remain valid.
- `SUBSCRIPTION-PUBLICATION-REVOKE-ALL`: coordinated revocation replaces the subscription token and every credential across all six Connection Profiles, including REALITY key material and Hysteria2 obfuscation authority, in one candidate Desired State.
- `SUBSCRIPTION-PUBLICATION-DISABLED-PRESERVED`: a disabled Connection Profile remains disabled and omitted while its settings and freshly revoked credential remain present in candidate Desired State.
- `SUBSCRIPTION-PUBLICATION-REGENERATION`: credential, listener port, selected address, certificate, compatibility definition, enablement, and managed software-version changes all require complete regeneration; unchanged inputs do not.
- `SUBSCRIPTION-PUBLICATION-ACCESS-ROUTE`: only `/s/<256-bit-subscription-token>` and its seven approved named suffixes are produced at HTTPS port `10443`; IPv6 is bracketed and no `/<token>` alias exists.
- `SUBSCRIPTION-PUBLICATION-ACCESS-REDACTION`: ordinary formatting, JSON, Plans, findings, transaction results, and evidence expose no token, credential, complete URL, body, or unique secret marker.
- `SUBSCRIPTION-PUBLICATION-ACCESS-TRANSACTION`: complete revocation publishes the candidate Desired State and artifact set once, or a post-publication failure restores the exact prior Desired State and artifact set without a partial revocation.

## Seam Verification — reviewed fixtures — Codex

Run the atomic filesystem and coordinated transaction Seams:

```sh
go test ./internal/subscriptionpublication/... ./internal/connectionprofiles ./internal/state -run 'TestPrepareClientAccessMutation|TestPlanBindsTheTruthfulClientAccessEffect|TestHysteria2Obfuscation|TestSubscriptionPublicationIsRequired|TestPrepareCommitRefusesAffectedInput|TestAtomicArtifactSet|TestActivationFailsClosed|TestActivationRejects|TestRestartInspection|TestStorageFailure|TestSubscriptionArtifactSet|TestSubscriptionServingFailure|TestSubscriptionRollbackFailure|TestAllClientAccessRevocation' -count=1
```

These tests cover token strength, token-only rotation, all-client revocation, disabled Connection Profile preservation, the complete regeneration trigger set, exact route shape, complete-set validation, exact Plan and State agreement, hostile-symlink refusal, deterministic generation identity, current-only serving traversal modes, whole-directory activation, storage failure, exact rollback, one Desired State publication, post-publication agreement, reuse refusal, restart inspection, serving-health refusal, Subscription-owned Recovery Required on an unprovable reverse, and secret-safe evidence. They use controlled local files and a controlled health probe; they do not prove an installed release, real HTTPS retrieval, prior-URL refusal by an installed Subscription Serving process, maintained-client import, or Connection Profile connectivity.

`TestRenderProducesDeterministicRawBase64AndV2RayN` parses every complete URI with Go's maintained `net/url` parser and compares it with literal reviewed fixtures for all six contracts. This is `SUBSCRIPTION-PUBLICATION-PARSER` evidence. It proves URI syntax and field preservation, not import or connectivity in v2rayN or any other maintained client.

Run the complete Mihomo document through one exact acceptance binary:

```sh
SBXR_MIHOMO_BIN=/path/to/pinned/mihomo \
SBXR_MIHOMO_VERSION=vX.Y.Z \
go test ./internal/subscriptionpublication -run TestPinnedMihomoAcceptsCompleteDocument -count=1
```

The test first checks that `mihomo -v` reports the exact required version token, then runs `mihomo -t` against the complete generated document, the all-disabled document, and malformed output in isolated temporary directories. This is `SUBSCRIPTION-PUBLICATION-MIHOMO-PINNED` evidence. A local fixture or skipped test cannot replace this command, and a pass does not prove HTTP retrieval, maintained-client import, or Connection Profile connectivity.

Run the complete sing-box document through the exact qualified acceptance binary:

```sh
SBXR_SING_BOX_BIN=/path/to/pinned/sing-box \
SBXR_SING_BOX_VERSION=1.13.16 \
go test ./internal/subscriptionpublication -run TestPinnedSingBoxAcceptsCompleteDocument -count=1
```

The test requires the exact `1.13.16` version token, runs `sing-box check -c /dev/stdin` against the complete five-Connection-Profile document and the all-disabled document, and requires malformed JSON to be rejected. This is `SUBSCRIPTION-PUBLICATION-SING-BOX-PINNED` evidence. It does not prove Karing retrieval or import, maintained-client behavior, or Connection Profile connectivity.

## Evidence record

The issue comment records only the command, Passed or Failed status, stable check codes, Connection Profile counts, omission counts, parser/validator identity, exact pinned Mihomo version, exact pinned sing-box version, and commit SHA. It must not contain a URI, YAML body, JSON body, credential, subscription token, complete URL, QR data, secret-derived checksum, raw validator output, or client-support claim.

| Acceptance stage | Owner | Status for this slice |
|---|---|---|
| Module Verification | Codex | Passed — the focused Module command covers all stable checks above. |
| Seam Verification | Codex | Passed — reviewed URI fixtures, Mihomo `v1.19.29`, and sing-box `1.13.16` accepted the complete generated documents; malformed output was refused. |
| Integrated Verification | Codex | Pending — integrated release. The local State, System Changes, and atomic filesystem transaction passes, but no installed release with real Subscription Serving was exercised. |
| Codex Live Acceptance | Codex | Pending — no maintained client import or connection was run here. |
| Owner Acceptance | Albert | Pending — every rendered Shadowrocket Connection Profile requires separate import and connection acceptance in the exact pinned maintained app; every offered Karing Connection Profile and workflow also remain Pending. No maintained Owner client or device was used here. |

The exact Owner Acceptance rows remain separate:

| Owner Acceptance check | Owner | Status |
|---|---|---|
| Shadowrocket — VLESS REALITY Vision | Albert | Pending — exact pinned maintained-app import and connection not performed. |
| Shadowrocket — VLESS XHTTP | Albert | Pending — exact pinned maintained-app import and connection not performed. |
| Shadowrocket — VLESS WebSocket | Albert | Pending — exact pinned maintained-app import and connection not performed. |
| Shadowrocket — Hysteria2 | Albert | Pending — exact pinned maintained-app import and connection not performed. |
| Shadowrocket — TUIC | Albert | Pending — exact pinned maintained-app import and connection not performed. |
| Shadowrocket — AnyTLS | Albert | Pending — exact pinned maintained-app import and connection not performed. |
| Karing — VLESS REALITY Vision | Albert | Pending — maintained-client import and connection not performed. |
| Karing — VLESS WebSocket | Albert | Pending — maintained-client import and connection not performed. |
| Karing — Hysteria2 | Albert | Pending — maintained-client import and connection not performed. |
| Karing — TUIC | Albert | Pending — maintained-client import and connection not performed. |
| Karing — AnyTLS | Albert | Pending — maintained-client import and connection not performed. |
| Karing — maintained Access workflow | Albert | Pending — retrieval, import visibility, selection, and workflow acceptance not performed. |

This record establishes Module Acceptance for parent issue #108 and its completed issues #109–#114. It is not Release Qualification.

Module accepted; Release Qualification pending. Integrated Verification, Codex Live Acceptance, and Owner Acceptance remain Pending until each exact row is performed and recorded.
