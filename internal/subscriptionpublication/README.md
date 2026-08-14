# Subscription Publication

Subscription Publication turns one complete typed `connectionprofiles.PublicationSource` into client artifacts. The current slices own seven representations:

- `Raw`: UTF-8 URI text in canonical Connection Profile order, with one URI per line and LF separators.
- `Base64`: standard padded base64 of the exact `Raw` bytes, with no wrapper or explanatory text.
- `V2RayN`: the same six-Connection-Profile base64 URI list as `Base64`.
- `Shadowrocket`: the same six-URI base64 body as a candidate only; every rendered Connection Profile remains pending Albert's Owner Acceptance in the exact pinned maintained app.
- `Mihomo`: one deterministic YAML document containing every enabled Connection Profile, one `SBXR` select group that names only those Connection Profiles, and the final rule `MATCH,SBXR`.
- `SingBox`: one complete deterministic JSON client configuration with a local `mixed` inbound on `127.0.0.1:2080`, local DNS, route, `SBXR` final selector, and every enabled supported Connection Profile.
- `Karing`: the same validated sing-box JSON bytes, with metadata that reports enabled VLESS XHTTP as `Not offered` because it is unavailable in the Karing core; deliberate disablement is instead reported as `Disabled`.

`Render` omits a disabled Connection Profile only when the typed source contains its exact omission fact. It preserves the selected address, port, independent Client Access Values, path, TLS name, REALITY fields, transport fields, normal TLS verification, and TUIC congestion choice. Go's standard `net/url` and `net.JoinHostPort` provide component escaping and bracketed IPv6 syntax; no converter, template system, or format plugin exists.

The six fixed URI contracts are:

- VLESS REALITY Vision: `vless://` with `encryption=none`, `flow=xtls-rprx-vision`, `security=reality`, `sni`, `fp=chrome`, `pbk`, `sid`, and `type=tcp`.
- VLESS XHTTP: `vless://` with `encryption=none`, `security=tls`, `sni`, `type=xhttp`, `host`, `path`, and client `mode=auto`; the typed server source must remain `packet-up`.
- VLESS WebSocket: `vless://` with `encryption=none`, `security=tls`, `sni`, `type=ws`, `host`, and `path`.
- Hysteria2: `hysteria2://` with `sni` and `insecure=0`; enabled obfuscation uses `obfs=salamander` plus the independent `obfs-password`, while disabled obfuscation emits neither field.
- TUIC: `tuic://` with independent UUID and password, `sni`, `congestion_control`, and `insecure=0`; no zero-RTT option is emitted.
- AnyTLS: `anytls://` with `security=tls`, `sni`, `type=tcp`, and `insecure=0`.

Human names remain URI fragments. `Artifacts` deliberately refuses JSON rendering and redacts ordinary Go formatting; callers must explicitly select a secret-bearing body. Rendering failure returns one fixed secret-safe error.

The Mihomo document uses safely double-quoted YAML scalars and these exact Connection Profile mappings:

- VLESS REALITY Vision: VLESS/TLS/TCP with Vision flow, Chrome client fingerprint, and nested REALITY public key and short ID.
- VLESS XHTTP: VLESS/TLS/XHTTP with nested path, host, and client `mode: auto`.
- VLESS WebSocket: VLESS/TLS/WebSocket with nested path and `Host` header.
- Hysteria2: password, Direct TLS Hostname, and `skip-cert-verify: false`; enabled obfuscation uses `obfs: salamander` plus `obfs-password`, while disabled obfuscation emits neither field.
- TUIC: independent UUID/password, Direct TLS Hostname, selected congestion controller, `reduce-rtt: false`, and `skip-cert-verify: false`.
- AnyTLS: password, Direct TLS Hostname, and `skip-cert-verify: false`.

`Render` succeeds only after its `MihomoValidator` accepts the complete document. Module tests use exact reviewed fixtures; Seam Verification uses one exact pinned Mihomo binary. This proves document compatibility only, not real retrieval, import, or Connection Profile connectivity.

The complete sing-box and Karing document contains VLESS REALITY Vision, VLESS WebSocket, Hysteria2, TUIC, and AnyTLS in canonical order. It preserves every exact credential, address, port, Direct TLS Hostname, REALITY field, WebSocket path and `Host`, normal TLS verification, TUIC congestion choice, and `zero_rtt_handshake: false`; enabled Hysteria2 obfuscation uses the exact `salamander` secret and disabled obfuscation remains absent. Enabled VLESS XHTTP has no supported sing-box transport mapping, so it is explicitly `Not offered` and is never replaced by WebSocket. Any disabled Connection Profile, including XHTTP, is omitted and reported as `Disabled`. When every Connection Profile is disabled, the document has no inbound, outbound, selector, or final route and cannot silently provide direct access.

`Render` also requires its `SingBoxValidator` to accept the complete document before any artifact is returned. The Karing body is a byte-identical copy of that validated document, but native sing-box acceptance does not prove Karing import, maintained-client behavior, or real Connection Profile connectivity.

`View` returns no token and no generated body. It reports `Current`, `Not published`, `Needs regeneration`, or `Unavailable`; the selected token-free HTTPS subscription address; agreement with the proven Desired State revision and SHA-256; and this exact named-link catalog for the dedicated authenticated Access surface: `/base64`, `/raw`, `/v2rayn`, `/shadowrocket`, `/karing`, `/mihomo`, and `/sing-box`. Each identity maps to exactly one validated artifact body through `RepresentationBody` and carries its actual count and omission metadata. These named links do not create a separate format-selection menu or place Client Access Values on the ordinary dashboard.

Unknown or ambiguous clients receive `/base64` as the conservative representation identity. User-Agent may later be a routing convenience in Subscription Serving, but it is never authentication, authorization, or proof of compatibility. A changed or stale `sbxr-subscription-representations-v1` compatibility definition reports `Needs regeneration` and cannot agree with the published Desired State. Disabled Connection Profiles are reported as deliberately `Disabled`, never `Failed`.

`PrepareClientAccessMutation` creates a new 256-bit subscription token directly from operating-system cryptographic randomness. There is no injectable randomness Adapter. Token-only rotation changes no Connection Profile credential and its review text states that old future downloads stop while already downloaded Connection Profile credentials remain valid. `Revoke all client access` also replaces the complete credential set for all six Connection Profiles, including a disabled Connection Profile, without changing its settings or enabling it. The resulting candidate still goes through the same full rendering, pinned validation, State preparation, one-use Plan, atomic activation, post-publication agreement, and exact rollback transaction described below.

State compares the typed inputs that affect publication and refuses an affected commit without the reviewed Subscription Publication Plan and complete eight-file bundle. Any credential, listener port, selected public address, certificate, Connection Profile enablement, compatibility release, or managed software version change therefore requires all seven representations to be regenerated and validated before activation. Unchanged inputs do not create publication work.

The only access routes produced by this Module are `https://<IPv4>:10443/s/<256-bit-subscription-token>` and `https://[<IPv6>]:10443/s/<256-bit-subscription-token>`, optionally followed by exactly one of `/base64`, `/raw`, `/v2rayn`, `/shadowrocket`, `/karing`, `/mihomo`, or `/sing-box`. There is no `/<token>` alias. Complete routes are returned only by an explicit secret-bearing call and are redacted from ordinary formatting, JSON, Plans, findings, logs, and evidence.

`Plan` renders and validates all seven representations, adds one metadata file, and binds that complete candidate to revision `N+1`, the starting Desired State lineage, relevant managed-input checksums, `sbxr-subscription-representations-v1`, the selected address, the exact typed Connection Profile source, and the Release Identity. The protected metadata carries the SHA-256 of every named body so Subscription Serving can reject any changed file without importing or calling Subscription Publication. The Plan summary still reports only identities, counts, omissions, validation status, complete replacement, and rollback intent; bodies, tokens, Client Access Values, complete URLs, and body checksums never enter that summary or ordinary output.

`Apply` is one-use and contributes one reversible Subscription Publication step to the existing System Changes transaction. Its Plan also identifies the exact `sbxr-subscription.service` contribution that State prepares in the root-runtime form. State carries one opaque, SHA-256-bound bundle owned by Subscription Publication plus its separately protected minimum Subscription Serving configuration. The bundle validates and enumerates the exact eight Publication files. The filesystem Adapter rejects hostile parent, final, and prepared-configuration symlinks, writes the configuration as `serving.json` beside those eight `root:root 0644` files in one root-only generation under `/var/lib/sbxr/subscriptions/sets/`, then atomically exchanges the complete nine-file candidate into `/var/lib/sbxr/subscriptions/current/` on supported Ubuntu `linux/amd64` and `linux/arm64` targets. `sets/` and every inactive generation remain non-traversable outside root at `0700`; only `current/` uses `root:root 0755`. Subscription Serving therefore observes either the complete prior authorization-and-body set or complete candidate and cannot traverse a generation path. System Changes runs Required candidate and activation checks, publishes Desired State exactly once, runs the post-publication Subscription Serving agreement check, records durable `Complete`, and only then removes older generations.

Any rendering, validation, preparation, storage, activation, pre-publication, post-publication, or Subscription Serving health failure fails closed. Before activation, nothing changes. After activation, the exact prior complete serving directory and Desired State are restored from durable evidence. Restart inspection treats an inactive candidate directory as recoverable transaction work; unprovable lineage or rollback becomes `Recovery Required`. Subscription Serving receives only that active immutable snapshot and the separate active certificate pointer. It does not receive Desired State, Connection Profile credentials outside the rendered bodies, validators, renderer access, the typed source, or arbitrary file access.

Subscription Serving implementation, Shadowrocket support claims, and maintained-client compatibility claims remain separate acceptance work under issue #108.

See [ACCEPTANCE.md](ACCEPTANCE.md) for the exact checks and evidence boundary.
