# Cloudflare Tunnel acceptance

This record covers automated Cloudflare authority and installation checks. Management-token lifecycle, run-token rotation, managed repair, complete executable removal, real Cloudflare behavior, Owner Acceptance, and Release Qualification remain Pending.

## Stable checks

- `CLOUDFLARE-MODULE`: `go test ./internal/cloudflaretunnel`
- `CLOUDFLARE-AUTHORITY`: `go test ./internal/cloudflaretunnel -run 'TestView(VerifiesOneScopedCloudflareAuthority|FailsClosedWithoutLeakingAuthority)'`
- `CLOUDFLARE-SEAM`: `go test ./internal/cloudflaretunnel -run 'TestHTTPAPI(ParsesOfficialShapesWithScopedAuthenticationAndPagination|RefusesMalformedAmbiguousAndUnsafeResponses)'`
- `CLOUDFLARE-PLAN`: `go test ./internal/cloudflaretunnel -run 'Test(Plan|Executor|WholeTunnel|CloudflaredService|InstalledCloudflared|LocalOrigin)'`
- `CLOUDFLARE-SERVICE-SEAM`: `go test ./internal/cloudflaretunnel -run 'TestExecutorInstallsAndRollsBackProtectedCloudflaredService|TestLocalOriginObserverRequiresHTTP'`
- `CLOUDFLARE-DEFERRED-STATE`: `go test ./internal/state -run TestDeferredCloudflareFinalizationPublishesProviderValuesInRevisionOne`
- `CLOUDFLARE-TRANSACTION`: `go test ./internal/systemchanges ./internal/systemchanges/adapter/ubuntu`
- `CLOUDFLARE-NETWORK-PATH`: `go test ./internal/networkpolicy -run TestEvaluateBoundsOutboundAndRenewalFreshness`
- `CLOUDFLARE-STATE-COMMIT`: `go test ./internal/state -run TestFreshInstallationPublishesRevisionOneOnlyAtPublication && go test ./internal/state/adapter/filesystem -run 'TestProductionPlacement|TestAtomicRollbackRestoresManagedOrNotInstalledBaseline'`
- `CLOUDFLARE-REPOSITORY`: `go test ./...`

## Procedure

1. Create a memory-only `cfat_` token fixture containing a unique marker. Confirm a Global API Key, missing Adapter, missing clock, malformed immutable ID, invalid zone name, and missing Network Policy proof stop before a provider call.
2. Return the exact selected account and zone, active token, future expiry, assigned nameservers, matching public nameservers, `Account API Tokens Read`, `Cloudflare Tunnel Edit`, and `DNS Write` policies scoped only to the selected account and zone. Confirm `CLOUDFLARE-AUTHORITY-VERIFIED` is Healthy while `WritesProven` remains false.
3. Remove each permission, add an unrelated permission, use an all-zone wildcard, add a second resource, change an immutable ID, disable the token, expire it, and change the zone binding in turn. Confirm each result fails before mutation with `CLOUDFLARE-TOKEN-PERMISSION` and exactly `Check current token again`, `Enter replacement token`, `Verify replacement`, and `Back`.
4. Fail Cloudflare HTTPS, TCP `7844`, and UDP `7844` in turn. Confirm Cloudflare Tunnel consumes the typed Network Policy result, returns `CLOUDFLARE-NETWORK-PATH`, makes no API request, and offers no network or provider-firewall mutation.
5. Return a pending or incorrectly delegated zone. Confirm `CLOUDFLARE-ZONE-PENDING` includes assigned and publicly observed nameserver facts and exactly `Check again`, `Wait another 10 minutes`, and `Back and continue later`.
6. Through controlled official-shape HTTP fixtures, confirm Bearer authentication appears only in `Authorization`; selected account and zone filters remain in every path/query; pages are consumed once and in order; exact immutable IDs survive parsing; and duplicate, malformed, contradictory, oversized, or unbounded results fail safely.
7. Return unauthorized, forbidden, rate-limited, server, malformed, false-success, DNS, and transport failures with unique raw-output markers. Confirm the Interface exposes only stable error kinds and typed Health text. Temporary failure receives at most three attempts and two 30-second waits inside 60 seconds.
8. Inspect ordinary and Go formatting of the token, requests, result, Health, policies, errors, and walkthrough. Confirm the complete token, authorization value, provider marker, raw provider output, and secret-derived hash are absent. Confirm only dedicated credential detail contains the first and last four characters.
9. Confirm a failed or pending `View` returns no verified State handoff and one Healthy `View` returns only the opaque Infrastructure Secret type accepted by State. Separately confirm the existing State/System Changes transaction keeps storage absent before publication, places its Cloudflare management token in revision `1` only after publication, keeps the filesystem path and modes State-owned, and restores the proven Not installed baseline without the token on rollback. `View` still owns no file, publication, lock, journal, Rollback Snapshot, token creation/revocation, DNS mutation, Tunnel mutation, or provider-firewall path. The complete-executable coordination remains Integrated Verification, so it stays Pending below.
10. Build the installation Plan twice from the same fixture and confirm the identity and checksum are deterministic while all rendered values omit the management and run-token markers. Change the bound token ID, account, zone, hostname observation, Desired State checksum, or cloudflared baseline and confirm Apply refuses before mutation.
11. Run the controlled deferred-finalization transaction. Confirm every returned Tunnel/DNS ID appears in a `Step completed` checkpoint before the next provider step, `Deferred State finalized` appears before `Activate prepared configuration`, and revision `1` contains each ID and the provider-issued run token exactly once. Confirm ordinary events and results contain no token marker.
12. Check a connected two-route observation, every partial route/DNS combination, wrong and public origins, disconnected state, delayed convergence, and stopped loopback origins. Only the exact Tunnel, two independent routes, owned DNS, final 404, and both reachable loopback origins may be Healthy.
13. Stream the protected prepared Cloudflare service artifact through the Ubuntu transaction Adapter. Confirm native ingress validation occurs before `systemctl enable --now`, the complete token appears only in the `0640` token file, fresh-install rollback removes only the installed unit/config/token, and an arbitrary TCP listener cannot satisfy the HTTP-origin check. Wrong owner, wider mode, unsafe parent or link, missing journaled ID, stale Plan, or contradictory finalization evidence must stop safely.

## Current status

| Stage | Owner | Status | Expected safe evidence |
|---|---|---|---|
| Module Verification | Codex | Passed for authority and installation | `CLOUDFLARE-MODULE`, `CLOUDFLARE-AUTHORITY`, `CLOUDFLARE-PLAN`, `CLOUDFLARE-NETWORK-PATH`, and `CLOUDFLARE-STATE-COMMIT` pass with marker-safe results. Token lifecycle, repair, and removal remain Pending. |
| Seam Verification — controlled fixture | Codex | Passed for authority and installation | Official-shape HTTP, Plan freshness, provider steps, protected service installation and rollback, HTTP-origin proof, whole-Tunnel health, deferred State finalization, and restart-generation checks pass without an Owner credential. |
| Integrated Verification | Integrated release runner | Pending — integrated release | The complete executable still needs token lifecycle, repair, removal, and real service/provider coordination. |
| Codex Live Acceptance | Codex, only during an approved Acceptance Run | Pending — approved Acceptance Run | No Acceptance VPS, real Cloudflare token, provider resource, or outside client was used. |
| Owner Acceptance | Albert | Pending — first v1 release | Albert has not yet created a scoped token or accepted the onboarding walkthrough in the maintained Cloudflare dashboard. |

The implementation result is `Installation foundation verified; Cloudflare Module and Release Qualification pending`. Issues `#89`–`#92` remain open for token lifecycle, managed repair, and Complete removal. Unperformed rows stay Pending.
