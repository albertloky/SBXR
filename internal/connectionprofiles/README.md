# Connection Profiles

Connection Profiles owns the six server-side connection choices. Issue #100 delivers the first vertical slice: VLESS REALITY Vision through `View`, `Plan`, and `Apply`. The remaining five profiles stay pending in #101–#105; the exact six-profile registry and coordinated lifecycle stay pending in #106–#107.

`View` fails closed unless the selected target is `443/TCP`, the accepted name agrees, `xray tls ping` and normal TLS name verification pass, and the target is neither Cloudflare-fronted nor Apple or iCloud. On an existing Managed installation it also requires the fixed `xray.service`, distinct `xray` identity, exact protocol-aware listener, protected `/etc/sbxr/xray/config.json`, and only the `CAP_NET_BIND_SERVICE` capability required by a selected port below `1024`.

`Plan` generates one complete Xray `v26.3.27` configuration using VLESS, RAW, REALITY, `xtls-rprx-vision`, and bounded fallback upload and download. It passes those exact bytes to `xray run -test -config stdin:` before producing a deterministic, secret-safe, one-use Plan. State accepts those exact reviewed bytes through the Plan's short-lived secret reader and stores them as the protected prepared `xray.service` artifact. `Apply` contributes one reversible prepared-configuration step and Required configuration, listener, service, and security gates to System Changes; it never mutates the host or publishes Desired State directly.

The REALITY UUID, X25519 private key, public key, and short ID are checked as one matching credential set. State may supply the protected UUID, private key, and short ID only through its short-lived Connection Profiles secret reader. Interface results, findings, Plan rendering, native errors, and typed observations never contain those values or raw generated configuration.

See [ACCEPTANCE.md](ACCEPTANCE.md) for automated, native, live, and Owner evidence boundaries.
