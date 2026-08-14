# Connection Profiles acceptance

This procedure covers issues #100–#107 and #174: VLESS REALITY Vision, VLESS XHTTP, independent VLESS WebSocket, Hysteria2, TUIC, AnyTLS, their truthful six-profile registry, root-runtime contribution, and the coordinated profile lifecycle.

## Module Verification — automated

Run:

```sh
go test ./internal/connectionprofiles/... -run 'TestReality'
go test ./internal/connectionprofiles/... -run 'TestXHTTP|TestGenerateXHTTP'
go test ./internal/connectionprofiles/... -run 'TestWebSocket|TestGenerateWebSocket'
go test ./internal/connectionprofiles/... -run 'TestHysteria2|TestGenerateHysteria2'
go test ./internal/connectionprofiles/... -run 'TestTUIC|TestGenerateTUIC'
go test ./internal/connectionprofiles/... -run 'TestAnyTLS|TestGenerateAnyTLS'
go test ./internal/connectionprofiles/... -run 'TestRegistry|TestGenerateRegistry'
go test ./internal/connectionprofiles/... -run 'TestRegistryUsesEveryReviewedAlternativePort|TestRegistryPlanPropagatesReviewedAlternativePorts|TestRegistryPlansSingleAndCoordinatedCredentialReplacement|TestRegistryPlansOnlyAuthorizedForwardRepair|TestCoreUpdateRequalification|TestLiveProfileCheck'
```

The focused checks cover:

- `CONNECTION-PROFILES-REALITY-TARGET`, `-NAME`, `-TARGET-CLASS`, `-PROBE`: exact target `443/TCP`, matching accepted name, Cloudflare and Apple or iCloud rejection, and failed or inconclusive probe refusal;
- `CONNECTION-PROFILES-REALITY-NATIVE`: complete native-validator refusal without raw output;
- `CONNECTION-PROFILES-REALITY-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, `-SECURITY`: root:`root` `0755`/`0644` material, selected TCP listener, contained root service, narrow capability, typed REALITY health, and exact prepared-configuration Change Set gates;
- deterministic secret-safe Plan rendering without secret-derived configuration hashes, matching UUID/X25519/short-ID credentials, State's revoked-after-use secret-reader handoff into the protected native Xray artifact, changed-observation and stale/reused Apply rejection, exact activation and rollback step, and unique secret-marker exclusion.
- `CONNECTION-PROFILES-XHTTP-ORIGIN`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, and `-ROUTE`: exact `127.0.0.1:11080/TCP`, native validity, contained root Xray service, loopback-only listener, and a typed Cloudflare hostname-to-origin binding;
- independent generated UUID and 32-byte path, server `packet-up`, no local TLS, no client `auto`, no initial `stream-up` or `stream-one`, complete REALITY-plus-XHTTP native configuration, exact reviewed State handoff, stale/reused Plan rejection, rollback input, and secret-marker exclusion.
- `CONNECTION-PROFILES-WEBSOCKET-ORIGIN`, `-HOST`, `-PATH`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, and `-ROUTE`: exact `127.0.0.1:11081/TCP`, selected hostname/TLS name/HTTP Host agreement, protected active path agreement, native validity, contained root Xray service, exactly one loopback listener, and a typed Cloudflare hostname-to-origin binding;
- an independent UUID and independently generated 32-byte path that cannot equal XHTTP, complete REALITY-plus-XHTTP-plus-WebSocket native configuration, no local TLS, exact reviewed State handoff, stale/reused Plan rejection, post-mutation rollback to the prior complete Xray configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-HYSTERIA2-INPUT`, `-NETWORK`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, and `-FUNCTION`: sing-box `1.13.16`, independent password, public `443/UDP`, intentional coexistence with REALITY `443/TCP`, root-runtime native-valid active configuration, contained root service, narrow capability, typed shared Direct TLS identity, and authenticated TCP plus UDP server function;
- required TLS using the exact reviewed hostname and shared certificate pointer, no `insecure`, no obfuscation, no zero-RTT field, fixed HTTP/3 `404 Not Found` unauthenticated behavior, exact reviewed State handoff for both Xray and sing-box artifacts, stale Plan rejection, post-mutation rollback to the prior complete sing-box configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-TUIC-INPUT`, `-NETWORK`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, and `-FUNCTION`: independent UUID/password, public `8443/UDP`, exact Hysteria2-plus-TUIC active agreement, contained root service, the typed shared Direct TLS identity, and authenticated TCP plus UDP server function;
- explicit `zero_rtt_handshake: false`, fixed `congestion_control: cubic`, no BBR, no `insecure`, the product name TUIC without a server-side “v5” label, exact reviewed State handoff, credential-drift rejection, post-mutation rollback to the prior complete sing-box configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-ANYTLS-INPUT`, `-NETWORK`, `-CONFIGURATION`, `-LISTENER`, `-SERVICE`, `-CAPABILITY`, and `-FUNCTION`: sing-box floor `1.12.0`, initially qualified `1.13.16`, independent password, public `9443/TCP`, exact Hysteria2-plus-TUIC-plus-AnyTLS active agreement, contained root service, the typed shared Direct TLS identity, and authenticated TCP server function;
- required normal TLS verification with the exact reviewed hostname, no `insecure`, no copied `padding_scheme`, rejection of fields from an uninstalled later sing-box release, exact reviewed State handoff, preservation of Hysteria2 and TUIC health, post-mutation rollback to the prior complete sing-box configuration, and protected-value marker exclusion.
- `CONNECTION-PROFILES-REGISTRY-HEALTHY`, `-DISABLED`, `-EXPOSURE`, and `-PLAN-READY`: exactly the three named VLESS profiles plus Hysteria2, TUIC, and AnyTLS; all six enabled by fresh defaults; independent credentials and paths; safe readiness, selected listener, hostname, qualified-version, desired-enablement, and fresh-health facts; and rejection of a seventh profile;
- every sequential single-profile disable and reverse re-enable through a new one-use reviewed Plan, including native-valid empty-inbound core configurations; exact setting and credential preservation; Disabled rather than Failed classification; native inbound, Network Policy exposure, Cloudflare route material, and publication omission; multiple-toggle and changed-credential refusal; fresh Network Policy revision/digest binding; capability removal after the last privileged listener; reversible activation, State preparation, rollback input, and protected-marker exclusion;
- one typed `PublicationSource` containing only enabled profile facts plus exact disabled omission facts. General rendering is refused, protected values remain redacted, and Connection Profiles produces no URI, YAML, JSON, QR payload, client wording, unsupported-client substitution, or compatibility claim.
- reviewed fresh-install alternatives propagate all six selected ports through native configurations, Network Policy exposure, active health, State service material, publication, and Cloudflare route health. Once committed, a later conflict stops in Network Policy's exact Correction Flow; it never silently selects another port;
- one-profile or coordinated six-profile credential replacement produces one `Rotation` Change Set. A valid current-State drift may instead produce one `Repair` Change Set only from fresh System Changes forward-repair authority for the same revision and checksum. Both reuse the same reversible two-core activation and required health gates;
- a core update must pass both native validators with the complete six-profile candidate. That proof resets automated, live, and Owner acceptance to `Pending` and cannot by itself replace the known-good version;
- `Live Profile Check` is available only from fresh `Managed` authority. It consumes one universal subscription URL once, requests authenticated uplink and downlink for every enabled profile, returns only typed pass/fail evidence, refuses JSON rendering, and retains no URL, client address, destination, counter, log, or traffic history.

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
SBXR_XRAY_BIN=/absolute/path/to/xray SBXR_SING_BOX_BIN=/absolute/path/to/sing-box go test ./internal/connectionprofiles -run TestPinnedNativeValidatorsAcceptEveryRegistryDisableAndReenable -count=1
```

The Xray tests send the exact configurations produced through `Plan` to `xray run -test -config stdin:`. The sing-box tests pass the exact generated bytes to the native seam, substitute only controlled temporary certificate-file locations so the local parser can load a disposable pair, and run `sing-box 1.13.16 check -c /dev/stdin`. Passing proves parser acceptance for VLESS, RAW, REALITY, Vision, fallback limits, XHTTP `packet-up`, WebSocket Host/path, Hysteria2 fields, TUIC fields, AnyTLS fields, required TLS, fixed HTTP/3 response, cubic congestion control, disabled zero-RTT, core-owned AnyTLS padding, both loopback origins, and no local Xray TLS. The registry native test validates the complete candidate after every one-profile disable and re-enable. The AnyTLS native check also proves the pinned release refuses an intentionally added later-release TLS field. It does not prove service activation, Cloudflare edge behavior, outside connectivity, reconnect, idle, keepalive, or sustained traffic.

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
12. Prove sing-box `1.13.16`, `/etc/sbxr/sing-box/config.json`, the fixed root `sing-box.service`, `0755`/`0644` root:`root` material, exact systemd containment, the shared active certificate pair, and only `CAP_NET_BIND_SERVICE` for public `443/UDP`. Refuse symbolic links, additional links, or wrong ownership and modes.
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
25. On a fresh installation candidate, prove the registry contains exactly VLESS REALITY Vision, VLESS XHTTP, VLESS WebSocket, Hysteria2, TUIC, and AnyTLS; all six are enabled; every credential is independent; and the two generated paths are independent and not credential-derived. Confirm VMess and every seventh profile are absent.
26. Disable each profile separately through its reviewed Plan. After each Apply, prove its complete setting and credential remain in Desired State, its native inbound is absent, its public or loopback Network Policy exposure is absent, its Cloudflare route is absent when applicable, its health is `Disabled`, and `PublicationSource` contains its one omission fact. Prove all other five profiles remain unchanged and Healthy.
27. Re-enable each profile separately through a new reviewed forward Plan. Prove the preserved setting and credential return, the complete Xray and sing-box candidates pass their native validators before mutation, the exact exposure returns, the omission disappears, and a controlled failure restores the prior disabled complete artifacts without rotating any credential.
28. Pass the canonical typed source to Subscription Publication during Integrated Verification. Prove enabled facts and disabled omissions arrive exactly once while Connection Profiles emits no client format or wording. Keep every renderer, support matrix, maintained-client import, and unsupported-client disclosure result owned and evidenced by Subscription Publication.
29. Occupy every preferred profile port on a fresh candidate and prove the reviewed alternatives propagate through all named artifacts. After commit, occupy one selected port and prove the exact Correction Flow offers only `Change the SBXR port`, `Stop the other service`, and `Back`; no automatic reselection or bypass is allowed.
30. Rotate one profile, then all six profiles together. Prove each selection creates one State publication and one reversible `Rotation` Change Set, restarts only affected cores, and preserves every unselected credential. Inject a post-mutation failure and prove rollback restores the prior complete artifacts.
31. Drift one proven active artifact and run forward repair. Prove repair is admitted only for the exact current State revision/checksum, publishes no adopted drift, uses one `Repair` Change Set, and enters Recovery Required if rollback or restart proof cannot complete.
32. Before replacing either core binary, validate the complete six-profile configuration with the candidate version. Confirm prior automated, live, and Owner rows all become `Pending`; the known-good replacement remains blocked until each new row is explicitly accepted.
33. After the system is freshly `Managed`, consume one universal subscription in `Live Profile Check`. From one approved disposable client, prove authenticated uplink and downlink for every enabled profile. Confirm the URL is one-use and no raw subscription, client address, destination, traffic counter, or persistent history is retained.

## Owner Acceptance — Pending

Albert accepts import and outside connection on each affected maintained client and real network. No automated, native, local-VPS, or disposable-client result satisfies this row.

The redacted ticket evidence must mark Module Verification and pinned-native Seam Verification independently. For WebSocket it must keep parser proof separate from real Cloudflare reconnect and keepalive behavior. For Hysteria2 and TUIC it must keep native parser and same-VPS server proof separate from real outside authenticated TCP and UDP uplink and downlink. For AnyTLS it must keep the pinned parser/core-padding proof separate from real outside authenticated TCP uplink, downlink, reconnect, idle, and sustained traffic. For the registry it must not turn local omission, native validation, typed publication handoff, or simulated Live Profile Check into a maintained-client claim. Karing XHTTP remains **Not offered** until separately qualified. Leave Codex Live Acceptance, integrated Subscription Publication, maintained-client acceptance, and Owner Acceptance Pending until actually performed.

## Current acceptance status

| Stage | Owner | Status | Evidence |
|---|---|---|---|
| Module Verification | Codex | Passed for all eight slices #100–#107 | Focused Connection Profiles, Network Policy, Cloudflare Tunnel, Certificate Lifecycle contribution, State, and System Changes checks cover the complete six-profile registry, independent credentials and paths, native candidates, health, lifecycle changes, rollback, restart resolution, typed publication handoff, and Live Profile Check privacy. |
| Seam Verification — pinned native validators and controlled Ubuntu fixtures | Codex | Passed | Official Xray `v26.3.27` and sing-box `1.13.16` accept the complete generated candidates before mutation. Controlled Ubuntu fixtures cover root-runtime files, contained root services, protocol-aware listeners, narrow capabilities, shared Direct TLS binding, authenticated server probes, and exact rollback without claiming outside connectivity. |
| Integrated Verification | Integrated release runner | Pending — integrated release | Subscription Publication must consume the typed source in the complete executable, and private-command, systemd installation, cross-Module service coordination, and one exact Release Identity remain unperformed. |
| Codex Live Acceptance | Codex, only during an approved Acceptance Run | Pending — approved Acceptance Run | No approved Acceptance VPS, real Cloudflare edge route, outside Acceptance Client, or authenticated outside traffic was used. |
| Owner Acceptance | Albert | Pending if the first release or an affected maintained-client surface requires it | Maintained-client import, device, network, reconnect, idle, keepalive, sustained-traffic, and workflow acceptance cannot be inferred from automated or native checks. Karing XHTTP is Not offered, not Failed. |
| Release Qualification | Release qualification runner | Pending | Module Acceptance is not one exact qualified Release Identity. |

Module accepted; Release Qualification pending. The exact six-profile registry, complete native Xray and sing-box candidates, per-profile health and security bindings, reviewed disablement and re-enable, credential rotation, stable port correction, proven-lineage repair, rollback and restart resolution, typed publication handoff, core requalification input, and privacy-preserving optional Live Profile Check are verified locally. Integrated Verification, Codex Live Acceptance, maintained-client and required Owner Acceptance, and Release Qualification remain Pending. Unperformed rows stay Pending.
