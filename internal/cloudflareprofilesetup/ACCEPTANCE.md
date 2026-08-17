# Cloudflare Profile Setup acceptance

This record covers Module Acceptance for the `View`, `Plan`, and `Apply` seam. It does not claim a real VPS, real Cloudflare, client, terminal, Owner Acceptance, or Release Qualification result.

## Stable checks

- `CLOUDFLARE-PROFILE-SETUP-MODULE`: `go test ./internal/cloudflareprofilesetup`
- `CLOUDFLARE-PROFILE-SETUP-ARCHITECTURE`: `go test . -run 'Test(ModuleRegistry|RepositoryDependencies|ArchitecturePolicyRejectsForbiddenShapes)'`
- `CLOUDFLARE-PROFILE-SETUP-CONTRIBUTIONS`: `go test ./internal/networkpolicy ./internal/cloudflaretunnel ./internal/certificatelifecycle ./internal/connectionprofiles ./internal/subscriptionpublication ./internal/state -run 'Test(EvaluatePlansOneBoundCloudflareProfileSetupWithoutMutation|ManagedSetupPlanSuppliesTheBoundCertificateDNS|StateProfileSetupCertificateIsExactAndOneUse|CloudflareSetupPlanCreatesAllFiveDeferredProfilesAtomically|PrepareCommitRequiresTypedCloudflareAuthorityForCompleteProfileSetup)'`
- `CLOUDFLARE-PROFILE-SETUP-TRANSACTION`: `go test ./internal/state ./internal/systemchanges/adapter/ubuntu -run 'Test(CloudflareProfileSetup|UbuntuCloudflareProfileSetup)'`
- `CLOUDFLARE-PROFILE-SETUP-RACE`: `go test -race ./internal/cloudflareprofilesetup ./internal/state ./internal/systemchanges`
- `CLOUDFLARE-PROFILE-SETUP-STATIC`: `go vet ./...`
- `CLOUDFLARE-PROFILE-SETUP-REPOSITORY`: `go test ./...`

## Procedure

1. Through `View`, prove one Managed revision with five profiles `Not set up` returns `Available`; six set-up profiles return `Complete`; active transaction, Recovery Required, partial setup, and unavailable State return one typed Correction Flow. No complete Infrastructure Secret is accepted or rendered.
2. Through `Plan`, require one fresh observation from Network Policy, Cloudflare Tunnel, Certificate Lifecycle, Connection Profiles, Subscription Publication, State, and System Changes. Change the starting revision, candidate revision, Change Set, starting State SHA-256, Desired State SHA-256, or one contribution and require refusal.
3. Require one deterministic, secret-safe Plan to name provider authority, hostnames, ports, Tunnel, routes, DNS, `sbxr-domain`, five profile credential categories, six-profile publication, exposure, gates, interruption, residue, rollback, forward-only recovery, and the exact irreversible checkpoint without rendering a secret.
4. Require State to prepare one complete `N+1` candidate from the typed Cloudflare Tunnel and Certificate Lifecycle authorities. Reject stale, reused, partial, caller-made, or mismatched contributions.
5. Through `Apply`, consume only the opaque approval, submit one `Cloudflare Profile Setup` Change Set to System Changes exactly once, and return only `Complete`, `Rolled back`, `Recovery Required`, or a typed refusal. Reuse must not make a second Apply call.
6. Run the transaction checks for cancellation before `Irreversible Cloudflare setup started`, forward-only failure after it, process death before and after it, restart, wrong provider identity, rollback-snapshot deletion, publication-last completion, and no repeated provider write after publication.
7. Use unique secret markers in State errors and protected inputs. Scan ordinary formatting, Plan review, Correction Flows, Apply results, transaction evidence, and restart evidence. A marker is allowed only in its protected owning artifact.

## Status

Module Verification and controlled transaction Seam Verification are automated by the stable checks above. Packaged executable integration remains owned by issue #222. Real VPS, real Cloudflare, outside-client, maintained-client, terminal, Owner Acceptance, and Release Qualification are not performed by this record.
