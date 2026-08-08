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
- Hysteria2: `hysteria2://` with `sni` and `insecure=0`; disabled obfuscation emits no obfuscation fields.
- TUIC: `tuic://` with independent UUID and password, `sni`, `congestion_control`, and `insecure=0`; no zero-RTT option is emitted.
- AnyTLS: `anytls://` with `security=tls`, `sni`, `type=tcp`, and `insecure=0`.

Human names remain URI fragments. `Artifacts` deliberately refuses JSON rendering and redacts ordinary Go formatting; callers must explicitly select a secret-bearing body. Rendering failure returns one fixed secret-safe error.

The Mihomo document uses safely double-quoted YAML scalars and these exact Connection Profile mappings:

- VLESS REALITY Vision: VLESS/TLS/TCP with Vision flow, Chrome client fingerprint, and nested REALITY public key and short ID.
- VLESS XHTTP: VLESS/TLS/XHTTP with nested path, host, and client `mode: auto`.
- VLESS WebSocket: VLESS/TLS/WebSocket with nested path and `Host` header.
- Hysteria2: password, Direct TLS Hostname, and `skip-cert-verify: false`, with no disabled obfuscation fields.
- TUIC: independent UUID/password, Direct TLS Hostname, selected congestion controller, `reduce-rtt: false`, and `skip-cert-verify: false`.
- AnyTLS: password, Direct TLS Hostname, and `skip-cert-verify: false`.

`Render` succeeds only after its `MihomoValidator` accepts the complete document. Module tests use exact reviewed fixtures; Seam Verification uses one exact pinned Mihomo binary. This proves document compatibility only, not real retrieval, import, or Connection Profile connectivity.

The complete sing-box and Karing document contains VLESS REALITY Vision, VLESS WebSocket, Hysteria2, TUIC, and AnyTLS in canonical order. It preserves every exact credential, address, port, Direct TLS Hostname, REALITY field, WebSocket path and `Host`, normal TLS verification, TUIC congestion choice, and `zero_rtt_handshake: false`; disabled obfuscation remains absent. Enabled VLESS XHTTP has no supported sing-box transport mapping, so it is explicitly `Not offered` and is never replaced by WebSocket. Any disabled Connection Profile, including XHTTP, is omitted and reported as `Disabled`. When every Connection Profile is disabled, the document has no inbound, outbound, selector, or final route and cannot silently provide direct access.

`Render` also requires its `SingBoxValidator` to accept the complete document before any artifact is returned. The Karing body is a byte-identical copy of that validated document, but native sing-box acceptance does not prove Karing import, maintained-client behavior, or real Connection Profile connectivity.

`View` returns no token and no generated body. It reports `Current`, `Not published`, `Needs regeneration`, or `Unavailable`; the selected token-free HTTPS subscription address; agreement with the proven Desired State revision and SHA-256; and this exact named-link catalog for the dedicated authenticated Access surface: `/base64`, `/raw`, `/v2rayn`, `/shadowrocket`, `/karing`, `/mihomo`, and `/sing-box`. Each identity maps to exactly one validated artifact body through `RepresentationBody` and carries its actual count and omission metadata. These named links do not create a separate format-selection menu or place Client Access Values on the ordinary dashboard.

Unknown or ambiguous clients receive `/base64` as the conservative representation identity. User-Agent may later be a routing convenience in Subscription Serving, but it is never authentication, authorization, or proof of compatibility. A changed or stale `sbxr-subscription-representations-v1` compatibility definition reports `Needs regeneration` and cannot agree with the published Desired State. Disabled Connection Profiles are reported as deliberately `Disabled`, never `Failed`.

Atomic artifact activation, serving, token rotation, Shadowrocket support claims, and maintained-client compatibility claims belong to later slices and acceptance work under issue #108.

See [ACCEPTANCE.md](ACCEPTANCE.md) for the exact checks and evidence boundary.
