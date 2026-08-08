# Subscription Serving acceptance

This file defines procedures only. Record results, exact commit, runner, time, software versions, and redacted evidence in the issue tracker. Never record the subscription token, complete URL, artifact body, authorization value, certificate private key, client IP, User-Agent paired with a token, or raw TLS or filesystem output.

## Module Verification

### SS-SERVE-01 — Trusted full-TLS base request

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeReturnsTheExactBase64ArtifactOverTrustedTLS$' -count=1
```

Require a normal trusted IP-identity TLS handshake, exact base64 bytes, the base64 representation disclosure, User-Agent negotiation metadata, and the fixed media and security headers.

### SS-SERVE-02 — Exact authenticated route

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeRefusesEveryOtherBasicRouteAndTokenShape$' -count=1
```

Require the exact `/s/<256-bit-subscription-token>` route family. Near tokens, aliases, unknown or case-changed suffixes, queries, encoded paths, extra components, and disallowed methods must receive the same plain non-secret `404`.

### SS-SERVE-03 — Storage and certificate refusal

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeFailsClosedOnUnsafeInputs$' -count=1
```

Require short authorization input, wider artifact or parent permissions, wrong ownership, unauthorized symbolic links, unavailable certificate files, expired certificates, mismatched IP identity, and untrusted chains to stop before serving. Require Certificate Lifecycle's one approved relative `current` pointer to its exact versioned `0750`/`0640` set.

### SS-SERVE-04 — No insecure fallback

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeHasNoPlainHTTPOrUntrustedTLSFallback$' -count=1
```

Require plain HTTP to receive no HTTP response and an untrusted certificate input to stop before serving. No self-signed or insecure server mode exists.

### SS-SERVE-05 — Selected address family

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeSupportsTheSelectedIPv6Family$' -count=1
```

Require the bracketed IPv6 request shape and selected-family TLS verification where IPv6 loopback is available. The IPv4 path is covered by `SS-SERVE-01`. Production must additionally bind the exact selected qualified IP at `10443/TCP`.

### SS-SERVE-06 — Separate read-only service identity

Run:

```sh
go test ./internal/subscriptionserving -run '^Test(ServiceUnitHasOnlyReadOnlySubscriptionAuthority|ServeRefusesTheWrongServiceIdentity)$' -count=1
```

Require the `sbxr-subscription` user and group, fixed private startup mode, read-only allowlisted runtime paths, hidden unrelated process information, no service capability or writable SBXR path, disabled core dumps, and the fixed systemd protections. Require `Serve` itself to refuse a changed effective service identity.

### SS-SERVE-07 — Owning storage boundaries

Run:

```sh
go test ./internal/subscriptionpublication/adapter/filesystem ./internal/certificatelifecycle/adapter/ubuntu -count=1
```

Require the owning Modules to preserve root-only `0700`/`0600` candidates and only the active root-owned, `sbxr-subscription`-readable `0750`/`0640` artifact and certificate sets.

### SS-SERVE-08 — Exact named representations

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeReturnsEveryPublishedRepresentationExactly$' -count=1
```

Require all seven literal suffixes to override a conflicting User-Agent and return the byte-for-byte complete Subscription Publication fixture with its exact media type, representation identity, omission disclosure, and security headers. Require six enabled URI/base64/Mihomo profiles, five Karing/sing-box profiles with XHTTP omitted, the Shadowrocket candidate identity, deliberate disablement across every response, percent encoding, and bracketed IPv6 literals.

### SS-SERVE-09 — Conservative User-Agent negotiation

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeNegotiatesOnlyTheUnsuffixedRoute$' -count=1
```

Require reviewed case-insensitive v2rayN, Mihomo/Clash Meta, and sing-box format hints only on the unsuffixed route. Require unknown and conflicting hints to return base64 with `X-SBXR-Representation: base64-uri-list`. Require exactly the negotiated responses to send `Vary: User-Agent`.

### SS-SERVE-10 — Indistinguishable hostile-request refusal

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeReturnsOneIndistinguishableRefusalForEveryHostileRequestShape$' -count=1
```

Require empty, short, long, prefixed, suffixed, aliased, repeated-slash, traversal, encoded-separator, malformed-escape, query, extra-component, missing-representation, unsupported-route, and disallowed-method requests to receive the same plain secret-safe `404` and fixed security headers. A `HEAD` response has the same status and headers but no body as required by HTTP.

### SS-SERVE-11 — Fixed public resource bounds

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeEnforcesFixed(ResourceBounds|ConnectionTimeouts)$' -count=1
```

Require exactly 60 parsed requests per one-minute window, including hostile requests while preserving their plain `404`, at most eight simultaneous TCP/TLS connections, at most 16 KiB of headers, no accepted request body with a 1 KiB defensive reader, at most 1 MiB per response, a five-second TLS handshake and header-read timeout, ten-second request-read and response-write timeouts, a 15-second total-operation timeout, and a 30-second idle timeout. These constants must remain fixed service rules rather than Owner configuration or client tracking.

### SS-SERVE-12 — Complete immutable artifact refusal

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeRejectsEveryUnsafeArtifactSet$' -count=1
```

Require unexpected, missing, non-regular, symbolic-link, permission-widened, changed, cross-representation-inconsistent, invalid-JSON, empty-required, invalid-metadata, and oversized snapshot inputs to stop `Serve` with only `SUBSCRIPTION-SERVING-ARTIFACT`. Certificate failures use only `SUBSCRIPTION-SERVING-CERTIFICATE`.

### SS-SERVE-13 — Secret-safe operational output

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeNeverExposesSecretOrOperationalMarkers$' -count=1
```

Require token, complete-route, authorization, User-Agent, artifact, generated-configuration, profile-credential, selected-address, and injected external-error markers to remain absent from hostile responses and typed failures. The systemd checks in `SS-SERVE-06` separately require discarded output, no writable authority, hidden unrelated processes, and disabled core dumps.

### SS-SERVE-14 — Atomic serving-state transition

Run:

```sh
go test ./internal/subscriptionserving -run '^Test(ServeSwitchesAuthorizationAndCompleteBodiesTogether|ConcurrentRequestsObserveOnlyOneCompleteServingSnapshot|ServePreservesDeliberateProfileDisablementAcrossActivation|ServeRestartAndRollbackUseOnlyAProvenCompleteSnapshot)$' -count=1
```

Require concurrent full-TLS requests to observe only the complete old token/body snapshot or complete candidate token/body snapshot. Require the old token to receive the same plain `404` after candidate activation, deliberate profile disablement and re-enablement to preserve Publication's exact bodies and counts, restart to load only the active complete snapshot, and rollback to restore only the prior proven snapshot.

### SS-SERVE-15 — Certificate failure and normal transaction ownership

Run:

```sh
go test ./internal/subscriptionserving -run '^TestServeKeepsThePreviousProvenHTTPSStateWhenCertificateActivationFails$' -count=1
go test ./internal/subscriptionserving -run '^TestPublicationGateAndRollbackPassThroughServe$' -count=1
go test ./internal/subscriptionpublication/adapter/filesystem -run 'Test(ProductionExecutorRequiresServingProof|AtomicArtifactSetActivationRollbackAndServingAgreement|ActivationRejectsAnUnsafePreparedServingConfiguration|RestartInspection|RestartReconciles|RestartRestores)' -count=1
go test ./internal/state -run 'TestSubscription(ArtifactSetUsesOneSystemChangesTransaction|ServingFailureRestoresStateAndPriorArtifactSet|RollbackFailureEntersRecoveryRequired)$' -count=1
go test ./internal/certificatelifecycle/adapter/ubuntu -run 'TestIP(ActivationFailureRestoresPriorPointerAndReprovesService|ActivationRestartInspectionAndCompleteCleanup|RollbackAcceptsNoPriorPointer)$' -count=1
```

Require the previous verified certificate to remain usable when a candidate pointer fails, expose the rejected candidate through the typed `Health` result, and require Certificate Lifecycle to restore and re-prove its one pointer. Require the real Publication activation, serving-agreement gate, and rollback to pass through a running `Serve` endpoint. Require Subscription Publication and State/System Changes to own the one-use Plan, Required gates, one Desired State publication, durable `Complete`, exact rollback, restart inspection, and Recovery Required decision. Serving must add no private transaction or recovery framework.

### SS-SERVE-16 — Module architecture boundary

Run:

```sh
go test . -run '^Test(RepositoryDependencies|SubscriptionServingMutationBoundary)$' -count=1
```

Require every production dependency to remain in the Go standard library and reject direct filesystem mutation or arbitrary-command APIs. Together with `SS-SERVE-06`, this keeps the public runtime independent of every product Module and unable to mutate artifacts, certificates, services, firewall, Desired State, or the VPS.

## TLS Seam Verification

Run all focused checks together:

```sh
go test ./internal/subscriptionserving ./internal/subscriptionpublication/adapter/filesystem ./internal/certificatelifecycle/adapter/ubuntu -count=1
```

Use only generated test Client Access Values and a generated trusted test chain. Confirm the marker scan contains no token, complete URL, artifact body, private key, or injected external-error marker.

## Integrated Verification

Status must remain `Pending — integrated release` until installation through one complete Change Set proves the real user/group, unit, selected-IP firewall and listener, prepared service configuration, immutable artifact activation, certificate activation, restart, rollback, post-publication agreement, and durable `Complete` together.

## Codex Live Acceptance

Requires a separately approved Acceptance Run and proven Acceptance Baseline. From an approved Acceptance Client outside the Acceptance VPS, retrieve the literal selected-IP HTTPS base route and every explicit representation with normal public trust and no insecure option. Verify the other family, HTTP absence, old-token refusal, and real client imports when their owning slices are implemented. Remove or rotate temporary Client Access Values afterward.

## Owner Acceptance

Pending for the first release. Automated TLS requests do not prove maintained-client import, displayed workflow, or Connection Profile connectivity.
