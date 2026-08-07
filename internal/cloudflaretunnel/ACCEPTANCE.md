# Cloudflare Tunnel acceptance

This record covers issue `#85`, the read-only Cloudflare authority `View` slice. It is not Integrated Verification, Codex Live Acceptance, Owner Acceptance, or Release Qualification.

## Stable checks

- `CLOUDFLARE-MODULE`: `go test ./internal/cloudflaretunnel`
- `CLOUDFLARE-AUTHORITY`: `go test ./internal/cloudflaretunnel -run 'TestView(VerifiesOneScopedCloudflareAuthority|FailsClosedWithoutLeakingAuthority)'`
- `CLOUDFLARE-SEAM`: `go test ./internal/cloudflaretunnel -run 'TestHTTPAPI(ParsesOfficialShapesWithScopedAuthenticationAndPagination|RefusesMalformedAmbiguousAndUnsafeResponses)'`
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

## Current status

| Stage | Owner | Status | Expected safe evidence |
|---|---|---|---|
| Module Verification | Codex | Passed | `CLOUDFLARE-MODULE`, `CLOUDFLARE-AUTHORITY`, `CLOUDFLARE-NETWORK-PATH`, and `CLOUDFLARE-STATE-COMMIT` pass with marker-safe results. |
| Seam Verification — controlled fixture | Codex | Passed | `CLOUDFLARE-SEAM` passes official-shape request, pagination, parsing, classification, and redaction checks without an Owner credential. |
| Integrated Verification | Integrated release runner | Pending — integrated release | The complete executable does not yet coordinate Cloudflare `View`, State revision `1`, later `Plan`/`Apply`, and all Modules. |
| Codex Live Acceptance | Codex, only during an approved Acceptance Run | Pending — approved Acceptance Run | No Acceptance VPS, real Cloudflare token, provider resource, or outside client was used. |
| Owner Acceptance | Albert | Pending — first v1 release | Albert has not yet created a scoped token or accepted the onboarding walkthrough in the maintained Cloudflare dashboard. |

The implementation result is `Module slice accepted; Cloudflare Module and Release Qualification pending`. Later issues `#86`–`#92` own mutation, connected routes, DNS, token lifecycle, drift, and removal. Unperformed rows stay Pending.
