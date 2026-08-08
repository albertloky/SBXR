# Subscription Publication

Subscription Publication turns one complete typed `connectionprofiles.PublicationSource` into client artifacts. The current slices own four representations:

- `Raw`: UTF-8 URI text in canonical Connection Profile order, with one URI per line and LF separators.
- `Base64`: standard padded base64 of the exact `Raw` bytes, with no wrapper or explanatory text.
- `V2RayN`: the same six-Connection-Profile base64 URI list as `Base64`.
- `Mihomo`: one deterministic YAML document containing every enabled Connection Profile, one `SBXR` select group that names only those Connection Profiles, and the final rule `MATCH,SBXR`.

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

Atomic artifact activation, serving, token rotation, sing-box, Karing, Shadowrocket support, and maintained-client compatibility claims belong to later slices of issue #108.

See [ACCEPTANCE.md](ACCEPTANCE.md) for the exact checks and evidence boundary.
