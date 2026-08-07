# Connection Profiles acceptance

This procedure covers only issue #100, VLESS REALITY Vision. It does not accept the complete six-profile Module in #99.

## Module Verification — automated

Run:

```sh
go test ./internal/connectionprofiles/... -run 'TestReality'
```

The focused checks cover:

- `CONNECTION-PROFILES-REALITY-TARGET`, `-NAME`, `-TARGET-CLASS`, `-PROBE`: exact target `443/TCP`, matching accepted name, Cloudflare and Apple or iCloud rejection, and failed or inconclusive probe refusal;
- `CONNECTION-PROFILES-REALITY-NATIVE`: complete native-validator refusal without raw output;
- `CONNECTION-PROFILES-REALITY-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, `-SECURITY`: protected material, selected TCP listener, fixed non-root service, narrow capability, REALITY binding, and Required Change Set gates;
- deterministic secret-safe Plan rendering without secret-derived configuration hashes, matching UUID/X25519/short-ID credentials, State's revoked-after-use secret-reader handoff into the protected native Xray artifact, changed-observation and stale/reused Apply rejection, exact activation and rollback step, and unique secret-marker exclusion.

Run the full repository suite once before committing:

```sh
go test ./...
```

## Seam Verification — pinned native Xray

Download and independently verify the official Xray-core `v26.3.27` asset for the test platform, then run:

```sh
SBXR_XRAY_BIN=/absolute/path/to/xray go test ./internal/connectionprofiles -run TestPinnedNativeXrayAcceptsPreparedRealityConfiguration -count=1
```

The test sends the exact configuration produced through `Plan` to `xray run -test -config stdin:`. Passing proves parser acceptance for VLESS, RAW, REALITY, Vision, and fallback limits. It does not prove service activation or connectivity.

## Codex Live Acceptance — Pending

On an explicitly approved Acceptance VPS and exact Release Identity:

1. Prove the Ubuntu release, installed Xray `v26.3.27`, fixed `xray.service`, distinct `xray` identity, `/etc/sbxr/` ownership and modes, and selected capability.
2. Use a suitable target in the VPS provider network. Record only typed results proving target route, accepted name, `443/TCP`, non-Cloudflare and non-Apple or iCloud classification, and bounded `xray tls ping` success.
3. Activate the prepared configuration through one Change Set. Prove the selected public TCP listener, running service, REALITY security binding, and server-side authenticated function.
4. Inject native validation, service, listener, and post-publication health failures separately. Prove complete rollback to the Acceptance Baseline with no credential or raw configuration in evidence.
5. From an approved disposable Acceptance Client outside the VPS, prove authenticated uplink and downlink. Keep this row separate from native validation and local service proof.

## Owner Acceptance — Pending

Albert accepts import and outside connection on each affected maintained client and real network. No automated, native, local-VPS, or disposable-client result satisfies this row.

The redacted ticket evidence must mark Module Verification and pinned-native Seam Verification independently, and leave Codex Live Acceptance, maintained-client acceptance, and Owner Acceptance Pending until actually performed.
