# Connection Profiles acceptance

This procedure covers issues #100–#105: VLESS REALITY Vision, VLESS XHTTP, independent VLESS WebSocket, Hysteria2, TUIC, and AnyTLS. It does not accept the exact six-profile registry and coordinated lifecycle still pending in #106–#107.

## Module Verification — automated

Run:

```sh
go test ./internal/connectionprofiles/... -run 'TestReality'
go test ./internal/connectionprofiles/... -run 'TestXHTTP|TestGenerateXHTTP'
go test ./internal/connectionprofiles/... -run 'TestWebSocket|TestGenerateWebSocket'
go test ./internal/connectionprofiles/... -run 'TestHysteria2|TestGenerateHysteria2'
go test ./internal/connectionprofiles/... -run 'TestTUIC|TestGenerateTUIC'
go test ./internal/connectionprofiles/... -run 'TestAnyTLS|TestGenerateAnyTLS'
```

The focused checks cover:

- `CONNECTION-PROFILES-REALITY-TARGET`, `-NAME`, `-TARGET-CLASS`, `-PROBE`: exact target `443/TCP`, matching accepted name, Cloudflare and Apple or iCloud rejection, and failed or inconclusive probe refusal;
- `CONNECTION-PROFILES-REALITY-NATIVE`: complete native-validator refusal without raw output;
- `CONNECTION-PROFILES-REALITY-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, `-SECURITY`: protected material, selected TCP listener, fixed non-root service, narrow capability, REALITY binding, and Required Change Set gates;
- deterministic secret-safe Plan rendering without secret-derived configuration hashes, matching UUID/X25519/short-ID credentials, State's revoked-after-use secret-reader handoff into the protected native Xray artifact, changed-observation and stale/reused Apply rejection, exact activation and rollback step, and unique secret-marker exclusion.
- `CONNECTION-PROFILES-XHTTP-ORIGIN`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, and `-ROUTE`: exact `127.0.0.1:11080/TCP`, native validity, fixed non-root Xray service, loopback-only listener, and a typed Cloudflare hostname-to-origin binding;
- independent generated UUID and 32-byte path, server `packet-up`, no local TLS, no client `auto`, no initial `stream-up` or `stream-one`, complete REALITY-plus-XHTTP native configuration, exact reviewed State handoff, stale/reused Plan rejection, rollback input, and secret-marker exclusion.
- `CONNECTION-PROFILES-WEBSOCKET-ORIGIN`, `-HOST`, `-PATH`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, and `-ROUTE`: exact `127.0.0.1:11081/TCP`, selected hostname/TLS name/HTTP Host agreement, protected active path agreement, native validity, fixed non-root Xray service, exactly one loopback listener, and a typed Cloudflare hostname-to-origin binding;
- an independent UUID and independently generated 32-byte path that cannot equal XHTTP, complete REALITY-plus-XHTTP-plus-WebSocket native configuration, no local TLS, exact reviewed State handoff, stale/reused Plan rejection, post-mutation rollback to the prior complete Xray configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-HYSTERIA2-INPUT`, `-NETWORK`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, `-CERTIFICATE`, and `-FUNCTION`: sing-box `1.13.16`, independent password, public `443/UDP`, intentional coexistence with REALITY `443/TCP`, protected native-valid active configuration, fixed non-root service, narrow capability, exact shared Direct TLS identity, and authenticated TCP plus UDP server function;
- required TLS using the exact reviewed hostname and shared certificate pointer, no `insecure`, no obfuscation, no zero-RTT field, fixed HTTP/3 `404 Not Found` unauthenticated behavior, exact reviewed State handoff for both Xray and sing-box artifacts, stale Plan rejection, post-mutation rollback to the prior complete sing-box configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-TUIC-INPUT`, `-NETWORK`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, `-CERTIFICATE`, and `-FUNCTION`: independent UUID/password, public `8443/UDP`, exact Hysteria2-plus-TUIC active agreement, fixed non-root service, the shared protected Direct TLS pair, and authenticated TCP plus UDP server function;
- explicit `zero_rtt_handshake: false`, fixed `congestion_control: cubic`, no BBR, no `insecure`, the product name TUIC without a server-side “v5” label, exact reviewed State handoff, credential-drift rejection, post-mutation rollback to the prior complete sing-box configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-ANYTLS-INPUT`, `-NETWORK`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, `-CERTIFICATE`, and `-FUNCTION`: sing-box floor `1.12.0`, initially qualified `1.13.16`, independent password, public `9443/TCP`, exact Hysteria2-plus-TUIC-plus-AnyTLS active agreement, fixed non-root service, the shared protected Direct TLS pair, and authenticated TCP server function;
- required normal TLS verification with the exact reviewed hostname, no `insecure`, no copied `padding_scheme`, rejection of fields from an uninstalled later sing-box release, exact reviewed State handoff, preservation of Hysteria2 and TUIC health, post-mutation rollback to the prior complete sing-box configuration, and protected-value marker exclusion.

Run the full repository suite once before committing:

```sh
go test ./...
```

## Seam Verification — pinned native Xray

Download and independently verify the official Xray-core `v26.3.27` asset for the test platform, then run:

```sh
SBXR_XRAY_BIN=/absolute/path/to/xray go test ./internal/connectionprofiles -run TestPinnedNativeXrayAcceptsPreparedRealityConfiguration -count=1
SBXR_XRAY_BIN=/absolute/path/to/xray go test ./internal/connectionprofiles -run TestPinnedNativeXrayAcceptsCompleteXHTTPConfiguration -count=1
SBXR_XRAY_BIN=/absolute/path/to/xray go test ./internal/connectionprofiles -run TestPinnedNativeXrayAcceptsCompleteWebSocketConfiguration -count=1
SBXR_SING_BOX_BIN=/absolute/path/to/sing-box go test ./internal/connectionprofiles -run TestPinnedNativeSingBoxAcceptsCompleteHysteria2Configuration -count=1
SBXR_SING_BOX_BIN=/absolute/path/to/sing-box go test ./internal/connectionprofiles -run TestPinnedNativeSingBoxAcceptsCompleteTUICConfiguration -count=1
SBXR_SING_BOX_BIN=/absolute/path/to/sing-box go test ./internal/connectionprofiles -run TestPinnedNativeSingBoxAcceptsCompleteAnyTLSAndRefusesLaterField -count=1
```

The Xray tests send the exact configurations produced through `Plan` to `xray run -test -config stdin:`. The sing-box tests pass the exact generated bytes to the native seam, substitute only controlled temporary certificate-file locations so the local parser can load a disposable pair, and run `sing-box 1.13.16 check -c /dev/stdin`. Passing proves parser acceptance for VLESS, RAW, REALITY, Vision, fallback limits, XHTTP `packet-up`, WebSocket Host/path, Hysteria2 fields, TUIC fields, AnyTLS fields, required TLS, fixed HTTP/3 response, cubic congestion control, disabled zero-RTT, core-owned AnyTLS padding, both loopback origins, and no local Xray TLS. The AnyTLS native check also proves the pinned release refuses an intentionally added later-release TLS field. It does not prove service activation, Cloudflare edge behavior, outside connectivity, reconnect, idle, keepalive, or sustained traffic.

## Codex Live Acceptance — Pending

On an explicitly approved Acceptance VPS and exact Release Identity:

1. Prove the Ubuntu release, installed Xray `v26.3.27`, fixed `xray.service`, distinct `xray` identity, `/etc/sbxr/` ownership and modes, and selected capability.
2. Use a suitable target in the VPS provider network. Record only typed results proving target route, accepted name, `443/TCP`, non-Cloudflare and non-Apple or iCloud classification, and bounded `xray tls ping` success.
3. Activate the prepared configuration through one Change Set. Prove the selected public TCP listener, running service, REALITY security binding, and server-side authenticated function.
4. Inject native validation, service, listener, and post-publication health failures separately. Prove complete rollback to the Acceptance Baseline with no credential or raw configuration in evidence.
5. From an approved disposable Acceptance Client outside the VPS, prove authenticated uplink and downlink. Keep this row separate from native validation and local service proof.
6. Prove XHTTP is bound only to `127.0.0.1:11080/TCP`, the selected Cloudflare hostname maps exactly to `http://127.0.0.1:11080`, edge TLS works, and no public route exposes the local listener.
7. Through the real Cloudflare hostname, run separate idle, reconnect, sustained-upload, and sustained-download checks. A local origin check, native validator pass, or generated configuration cannot satisfy these rows.
8. Keep client rendering separate: server `packet-up` remains fixed here; client `mode=auto`, import behavior, and maintained-client compatibility belong to Subscription Publication and Owner Acceptance.
9. Prove WebSocket is bound only to `127.0.0.1:11081/TCP`, the selected Cloudflare hostname maps exactly to `http://127.0.0.1:11081`, edge TLS name and HTTP Host agree, the protected active path matches the reviewed path, and no public route exposes the local listener.
10. Through the real WebSocket Cloudflare hostname, run separate reconnect and keepalive checks. Keep these rows separate from parser proof, local-origin reachability, and XHTTP edge behavior.
11. Import the independently rendered WebSocket compatibility profile into each maintained client. Do not substitute XHTTP success or infer compatibility from the shared VLESS protocol.
12. Prove sing-box `1.13.16`, `/etc/sbxr/sing-box/config.json`, the fixed `sing-box.service`, distinct non-root `sing-box` identity, `0750`/`0640` service-readable material, the shared active certificate pair, and only `CAP_NET_BIND_SERVICE` for public `443/UDP`. Refuse symbolic links, additional links, or wrong ownership and modes.
13. Prove the active Hysteria2 configuration has one public `443/UDP` listener, required TLS, the reviewed Direct TLS Hostname, no obfuscation, no zero-RTT field, and a fixed ordinary HTTP/3 `404 Not Found` response for unauthenticated traffic. Prove Network Policy still treats REALITY `443/TCP` and Hysteria2 `443/UDP` as separate listeners.
14. Use the selected VPS address as destination and the exact Direct TLS Hostname as the normally verified TLS name. Prove the DNS record, certificate SAN, shared active pointer, Hysteria2 configuration, publication input, and health row agree; do not use `insecure`, a custom trust anchor, or certificate pinning.
15. Inject native validation, wrong certificate identity, service, listener, and post-publication function failures separately. Prove the prior complete Xray and sing-box artifacts are restored exactly and no password or raw configuration enters evidence.
16. From an approved disposable Acceptance Client outside the VPS, run authenticated Hysteria2 TCP and UDP uplink and downlink separately. Local parser, listener, certificate, or same-VPS probe success cannot satisfy these rows.
17. Prove the active complete sing-box configuration keeps Hysteria2 on `443/UDP` and adds exactly one TUIC listener on public `8443/UDP`, with an independent UUID/password, `zero_rtt_handshake: false`, `congestion_control: cubic`, no BBR, and no insecure TLS option.
18. Prove the TUIC destination is the selected VPS address and its normally verified TLS name is the exact Direct TLS Hostname. Prove the DNS record, certificate SAN, shared active pointer, TUIC configuration, publication input, and health row agree.
19. Inject wrong TLS identity, listener, service, native validation, and post-publication function failures separately. Prove exact rollback to the prior complete Hysteria2 sing-box artifact with no credential or raw configuration in evidence.
20. From an approved disposable Acceptance Client outside the VPS, run authenticated TUIC TCP and UDP uplink and downlink separately. Record maintained-client import and real-network replay/idle behavior separately; parser and same-VPS proof cannot satisfy these rows.
21. Prove sing-box is at least `1.12.0` and exactly the qualified `1.13.16` release, then prove the complete active configuration preserves Hysteria2 and TUIC and adds exactly one AnyTLS listener on public `9443/TCP`. Confirm the active AnyTLS configuration omits `padding_scheme`, uses an independent 32-byte password, and contains no field from an uninstalled later release.
22. Prove the AnyTLS destination is the selected VPS address and its normally verified TLS name is the exact Direct TLS Hostname. Prove the DNS record, certificate SAN, shared active pointer, AnyTLS configuration, publication input, and health row agree; do not use `insecure`, a custom trust anchor, or certificate pinning.
23. Inject wrong TLS identity, listener, service, native validation, copied padding, and post-publication function failures separately. Prove exact rollback to the prior complete Hysteria2-plus-TUIC sing-box artifact with no password or raw configuration in evidence.
24. From an approved disposable Acceptance Client outside the VPS, run authenticated AnyTLS TCP uplink and downlink separately. Record maintained-client import and real-network reconnect, idle, and sustained-traffic behavior separately; parser and same-VPS proof cannot satisfy these rows.

## Owner Acceptance — Pending

Albert accepts import and outside connection on each affected maintained client and real network. No automated, native, local-VPS, or disposable-client result satisfies this row.

The redacted ticket evidence must mark Module Verification and pinned-native Seam Verification independently. For WebSocket it must keep parser proof separate from real Cloudflare reconnect and keepalive behavior. For Hysteria2 and TUIC it must keep native parser and same-VPS server proof separate from real outside authenticated TCP and UDP uplink and downlink. For AnyTLS it must keep the pinned parser/core-padding proof separate from real outside authenticated TCP uplink, downlink, reconnect, idle, and sustained traffic. Leave Codex Live Acceptance, maintained-client acceptance, and Owner Acceptance Pending until actually performed.
