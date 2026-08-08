# Subscription Publication

Subscription Publication turns one complete typed `connectionprofiles.PublicationSource` into client artifacts. This slice owns three representations only:

- `Raw`: UTF-8 URI text in canonical Connection Profile order, with one URI per line and LF separators.
- `Base64`: standard padded base64 of the exact `Raw` bytes, with no wrapper or explanatory text.
- `V2RayN`: the same six-profile base64 URI list as `Base64`.

`Render` omits a disabled Connection Profile only when the typed source contains its exact omission fact. It preserves the selected address, port, independent Client Access Values, path, TLS name, REALITY fields, transport fields, normal TLS verification, and TUIC congestion choice. Go's standard `net/url` and `net.JoinHostPort` provide component escaping and bracketed IPv6 syntax; no converter, template system, or format plugin exists.

The six fixed URI contracts are:

- VLESS REALITY Vision: `vless://` with `encryption=none`, `flow=xtls-rprx-vision`, `security=reality`, `sni`, `fp=chrome`, `pbk`, `sid`, and `type=tcp`.
- VLESS XHTTP: `vless://` with `encryption=none`, `security=tls`, `sni`, `type=xhttp`, `host`, `path`, and client `mode=auto`; the typed server source must remain `packet-up`.
- VLESS WebSocket: `vless://` with `encryption=none`, `security=tls`, `sni`, `type=ws`, `host`, and `path`.
- Hysteria2: `hysteria2://` with `sni` and `insecure=0`; disabled obfuscation emits no obfuscation fields.
- TUIC: `tuic://` with independent UUID and password, `sni`, `congestion_control`, and `insecure=0`; no zero-RTT option is emitted.
- AnyTLS: `anytls://` with `security=tls`, `sni`, `type=tcp`, and `insecure=0`.

Human names remain URI fragments. `Artifacts` deliberately refuses JSON rendering and redacts ordinary Go formatting; callers must explicitly select a secret-bearing body. Rendering failure returns one fixed secret-safe error.

Atomic artifact activation, serving, token rotation, Mihomo, sing-box, Karing, Shadowrocket support, and client compatibility claims belong to later slices of issue #108.

See [ACCEPTANCE.md](ACCEPTANCE.md) for the exact checks and evidence boundary.
