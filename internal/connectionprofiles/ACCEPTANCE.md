# Connection Profiles acceptance

This procedure covers issues #100–#102: VLESS REALITY Vision, VLESS XHTTP, and independent VLESS WebSocket. It does not accept the complete six-profile Module in #99.

## Module Verification — automated

Run:

```sh
go test ./internal/connectionprofiles/... -run 'TestReality'
go test ./internal/connectionprofiles/... -run 'TestXHTTP|TestGenerateXHTTP'
go test ./internal/connectionprofiles/... -run 'TestWebSocket|TestGenerateWebSocket'
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
```

The tests send the exact configurations produced through `Plan` to `xray run -test -config stdin:`. Passing proves parser acceptance for VLESS, RAW, REALITY, Vision, fallback limits, XHTTP `packet-up`, WebSocket Host/path, both loopback origins, and no local TLS. It does not prove service activation, Cloudflare edge behavior, connectivity, reconnect, idle, keepalive, or sustained traffic.

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

## Owner Acceptance — Pending

Albert accepts import and outside connection on each affected maintained client and real network. No automated, native, local-VPS, or disposable-client result satisfies this row.

The redacted ticket evidence must mark Module Verification and pinned-native Seam Verification independently. For WebSocket it must keep parser proof separate from real Cloudflare reconnect and keepalive behavior, and leave Codex Live Acceptance, maintained-client acceptance, and Owner Acceptance Pending until actually performed.
