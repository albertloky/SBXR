# Software Lifecycle acceptance

This procedure defines stable checks for issues #125, #126, #127, and #128. It contains no run results, raw GitHub verifier output, Client Access Values, Infrastructure Secrets, or Owner-managed configuration.

## Module Verification

### SL-VERIFY-01 — One exact verified Release Identity

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestViewReportsOneExactVerifiedReleaseWithoutUsingIt$' -count=1
```

Require one strict index, both application roles, both component roles, exact downloaded and attested equality, one `sbxr` executable per application archive, one strict complete offline component manifest per matching component archive, repository `albertloky/SBXR`, the selected immutable tag, the 40-character commit, index SHA-256, authenticated sequence, UTC verification time, all four asset digests, safe migration summary, and only `Review install` from Not installed. Require zero extraction to the host, execution, or product mutation.

### SL-VERIFY-02 — One-fact mutation and secret-safe refusal

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestView(FailsClosedForEveryChangedReleaseFact|RejectsEveryMissingOrWrongIndexFieldAndType|RejectsEveryMaliciousOrAmbiguousArchive|TreatsVersionAndTagAsSafeOpaqueStrings|NeverReusesAnEarlierSuccessfulProof)$' -count=1
```

Require source, verifier-distribution, verifier-version, fingerprint, release, repository, tag, commit, every missing or wrongly typed index field, schema, sequence, role, name, size, digest, duplicate, missing, extra, unsafe, malformed, earlier-proof, changed-file, and hostile archive failures to return only `SOFTWARE-LIFECYCLE-RELEASE-REFUSED`. Hostile archives include absolute paths, traversal, links, special files, duplicate or extra destinations, unsafe modes, Owner-managed paths, and concatenated gzip members. Raw errors and injected markers must remain absent. No failed candidate may expose an action or be extracted, executed, or used for mutation. Safe opaque version and tag strings must not be restricted to Semantic Versioning.

### SL-VERIFY-03 — Installation-state action boundary

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestViewReportsOnlyEligibleActionsForCurrentInstallationState$' -count=1
```

Require a higher authenticated sequence from Managed to offer only `Review update`. `Change in progress` and `Recovery Required` may report a verified candidate but no install or update action. Invalid installed proof must fail closed without exposing its value.

### SL-VERIFY-04 — Verification-only architecture

Run:

```sh
go test . -run '^Test(RepositoryDependencies|SoftwareLifecycleVerificationBoundary)$' -count=1
```

Require the Software Lifecycle core to use no host mutation, process execution, syscall, unsafe capability, or other product Module before later tickets approve those dependencies. The GitHub process and temporary-download behavior must remain inside its genuine external Adapter.

### SL-STAGE-01 — Authenticated selected-architecture handoff

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestView(StagesOnlyTheSelectedVerifiedArchitecture|RefusesWrongArchitectureOrInvalidStagingWithoutLeakingDetails)$' -count=1
```

Require `View` to authenticate and hand off only the archive whose indexed role matches the selected `amd64` or `arm64` architecture. Caller-authored requests, unsupported architectures, missing staging, and secret-bearing failures must fail closed with no candidate or action.

## Seam Verification

### SL-GITHUB-01 — Exact official GitHub CLI contracts

Run:

```sh
go test ./internal/softwarelifecycle/adapter/github -run '^TestSourceUsesExactGitHubReleaseAndPerAssetVerificationContracts$' -count=1
```

Require `/usr/bin/gh`, the exact qualified Debian package version, unchanged installed package files, the official APT origin and signed-by configuration, reviewed fingerprint `7F38BBB59D064DBCB3D84D725612B36462313325`, `gh release verify <tag> --repo albertloky/SBXR --format json`, bounded same-tag downloads, one same-tag `gh release verify-asset <tag> <file>` call for the index and each payload, strict attestation parsing, and only typed proof crossing the Adapter.

### SL-GITHUB-02 — External verifier refusal

Run:

```sh
go test ./internal/softwarelifecycle/adapter/github -run '^TestSourceFailsClosedOnDistributionVerifierDownloadAssetOrAttestationFailure$' -count=1
```

Require signed-distribution, version, package-integrity, APT-origin, fingerprint, bounded-download, verifier, per-asset, malformed-output, wrong-repository, wrong-tag, and raw-error failures to produce no `ReleaseEvidence` and disclose no raw output.

### SL-STAGE-02 — Safe extraction and complete embedded proof without candidate execution

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestStager' -count=1
```

Require a fresh private directory, exact archive size and digest, one safe root-owned regular `sbxr`, selected 64-bit Linux ELF architecture, Go `1.26.5`, `GOOS=linux`, selected `GOARCH`, `CGO_ENABLED=0`, no ELF interpreter, and no imported native library. Refuse caller-authored requests, unsafe names, links, special files, duplicate destinations, wrong ownership or mode, wrong architecture, and non-Go/runtime-dependent content. Require embedded repository, tag, commit, independent ELF payload digest, the complete exact State schema `1`, its zero-edge migration path, exact units, exact managed paths, exact baselines, exact qualified generated core configurations, and every exact qualified subscription representation. Reject any invented predecessor migration. Bind those embedded facts to the already authenticated external complete Release Identity. Never execute the candidate.

### SL-STAGE-03 — Both pure-Go release payloads and version output

Run:

```sh
go test ./cmd/sbxr-release -run '^Test(BuildArchiveProducesOneQualifiedExecutableForBothArchitectures|VerifiedGitSourceBindsTheCleanExactCommit)$' -count=1
go test ./cmd/sbxr -run '^TestVersionReportsOnlyEmbeddedBuildFacts$' -count=1
```

Require the production `cmd/sbxr-release` entry point to bind the requested commit to a clean tracked `HEAD`, export only that exact commit, and refuse mismatched or dirty source. Require pinned Go `1.26.5` and `CGO_ENABLED=0` to build exactly one stamped `sbxr` executable for each of `linux/amd64` and `linux/arm64`. Require each application archive to contain only that executable, with no native library dependency or language runtime. The matching production component-archive builder remains Pending until reviewed upstream distribution identities and pinned artifact provenance are canonical; an arbitrary local tree cannot satisfy this row. Require `sbxr version` and `sbxr version --json` to report only authenticated embedded repository, tag, commit, architecture, payload digest, and State schema; the executable must not invent or accept an index digest.

### SL-STAGE-04 — Exact native configuration and subscription validators

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestNativeValidator' -count=1
```

Require release-build-time validators for Xray-core `v26.3.27`, sing-box `v1.13.16` with AnyTLS floor `v1.12.0`, cloudflared `2026.7.3`, Certbot `5.4` or newer from either the supported snap or a proved pip virtual environment, and Mihomo `v1.19.29`. Require native checks for both core configurations, cloudflared ingress, Mihomo, and sing-box subscription output before an archive can be written. Require raw, base64, v2rayN, Shadowrocket, Karing, Mihomo, and sing-box outputs to be the exact bytes generated together from one typed six-profile qualification fixture. Any changed baseline or representation fails the build or staging hash check and requires affected requalification. Clean VPS staging must not require these tools to be preinstalled.

### SL-INSTALL-01 — Complete secret-safe review and exact recheck

Run:

```sh
go test ./internal/softwarelifecycle -run '^Test(PlanInstall|ApplyInstall|NetworkInstallContribution)' -count=1
```

Require one exact staged Release Identity, revision `1`, owned files and ownership categories, ten units, six profiles, seven subscription representations, typed Cloudflare and certificate effects, ports, the complete `inet sbxr` candidate, all disk categories, checks, interruption, cancellation, and rollback to `Not installed` before approval. Require every Plan object to be one-use. After approval, require one root-verified Network Policy contribution whose reviewed stable digest is unchanged; independently derive the fresh volatile digest from every owning contribution. Any changed candidate, listener, port, firewall, address, resource, provider fact, component contribution, State binding, or checksum returns only a secret-safe stale-Plan refusal.

### SL-INSTALL-02 — Ordinary sudo and non-secret draft boundary

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^Test(Approval|DraftStore)' -count=1
```

The draft portion currently requires the fixed Owner path, strict allowlisted fields, canonical JSON, an Owner-owned `0600` single-link regular file beneath an Owner-owned `0700` directory, atomic replacement, safe discard, and refusal of links, broad modes, unknown fields, malformed values, and outside-file replacement. Infrastructure Secrets and Client Access Values never enter the draft. The production approval portion remains Pending: it must replace `/usr/bin/sudo -v` with the approved inherited read-only executable descriptor, private Unix socket, verified peer/executable identity, bounded canonical typed envelope, independent Plan rebuild, and root recheck before Apply.

### SL-INSTALL-03 — Exact software activation and partial rollback

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestInstaller' -count=1
```

Require the exact authenticated staged executable, exact manifest-bound component tree, exact ten embedded unit templates rendered only with the authenticated versioned destination, and fixed active symlink. Capture the complete addition list before mutation. Refuse every occupied target. Full and partially completed activation rollback removes only absent-or-byte-exact targets recorded by that attempt; any changed target refuses deletion. Final inspection must prove either the complete release present or every recorded file absent.

### SL-INSTALL-04 — One global revision-1 transaction

Run:

```sh
go test ./internal/state -run '^TestSoftwareLifecycleInstallPublishesRevisionOneOnlyAfterCompleteAgreement$' -count=1
```

Require the real Software Lifecycle Plan, State prepared commit, and System Changes transaction to start from the proven Clean VPS/`Not installed` baseline. Revision `1` becomes readable only after pre-publication health, State publication, post-publication health, agreement, and durable `Complete`, in that order. The completed transaction leaves no active Rollback Snapshot or completed journal.

### SL-INSTALL-05 — Approved dependency boundary

Run:

```sh
go test . -run '^Test(RepositoryDependencies|SoftwareLifecycleVerificationBoundary)$' -count=1
```

Require Software Lifecycle to depend only on the approved Network Policy and System Changes coordination seams. Every other owning Module contributes through the typed `systemchanges.InstallContribution`; no eleven-value positional handoff, product-module cycle, generic plugin framework, or caller-authored step bypass is accepted.

### SL-UPDATE-01 — Stable channel and explicit alternate

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestViewDiscovery(HonorsStableAndReviewedAlternateChannels|RejectsSameOlderAndIncompatibleReleases|AcceptsACompleteForwardStateMigrationPath)$' -count=1
go test ./internal/softwarelifecycle -run '^TestPayloadMetadataAcceptsOnlyCompleteSequentialNoNetworkMigrationMaterial$' -count=1
go test ./internal/softwarelifecycle/adapter/github -run '^TestSourceDiscover' -count=1
```

Require the default GitHub request to select only the current stable release, ignore drafts and unintended prereleases before asset verification, and never cross to another tag. One explicitly reviewed alternate may select only that exact safe tag. Require duplicate keys, unknown fields, trailing documents, unsafe tags, and raw command failures to return no listing. Require same Release Identity, automatic downgrade, non-higher sequence, newer updater schema, and a changed State schema without the complete embedded forward path to expose no candidate or action. Require an authenticated higher sequence with the installed schema or a complete sequential deterministic no-network forward path embedded identically in both application archives to expose only `Review update`.

### SL-UPDATE-02 — One newest verified unapplied candidate

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestView(DiscoversVerifiesAndRetainsOneHigherStableCandidate|DiscoveryReplacesOnlyWithNewerAndSurvivesRestart|ReportsTheOneDiskRetainedCandidateAfterRestart|RefusesTamperedRetainedEvidenceWithoutLeakingIt)$' -count=1
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestCandidateStore' -count=1
```

Require one higher compatible release to be reverified through `View`, retained once, and exposed only as `Review update`. A directory lock makes compare-and-replace monotonic across overlapping checks: a newer candidate atomically replaces the older candidate and an older discovery cannot replace it. Restart and temporary-write interruption retain only the current candidate. Require one root-owned `0600` regular single-link tar beneath a root-owned `0700` directory, a non-linked correctly owned non-writable parent chain, an exact whole-file bound and ending, strict bounded entries, safe names, canonical metadata, refusal of links/broad modes/trailing bytes/tampering, and no history files.

### SL-UPDATE-03 — Timer remains review-only

Run:

```sh
go test ./cmd/sbxr -run '^TestScheduledUpdateCheckInvokesOnlyStableSoftwareLifecycleView$' -count=1
```

Require the scheduled seam to call only `Software Lifecycle.View` with Managed installed proof and stable discovery. It must not request architecture staging, Apply, approval, State publication, migrations, binary replacement, service restart, configuration change, or any product mutation. Production `private update-check` wiring and a real Clean-VPS timer run remain Pending on issue #127's installed verified completion receipt and complete production four-asset release.

### SL-UPDATE-04 — One-use reviewed update and exact schema migration

Run:

```sh
go test ./internal/softwarelifecycle -run '^Test(PlanUpdate|ApplyUpdate)' -count=1
go test ./internal/connectionprofiles -run '^TestRealityViewAndPlanProduceOneSafeNativeConfiguration$' -count=1
go test ./internal/cloudflaretunnel -run '^TestPlanReleaseUpdateRestartsOnlyTheVerifiedOwnedCloudflaredService$' -count=1
go test ./internal/subscriptionpublication -run '^TestPlanBindsOneCompleteValidatedArtifactSetWithoutRenderingSecrets$' -count=1
go test ./internal/state -run '^Test(LoadReportsDeterministicSchemaOneToTwoMigrationReview|PrepareCommitReportsSchemaOneToTwoReleaseCompatibility|ReleaseMigrationsExposeOnly)' -count=1
go test ./internal/softwarelifecycle -run '^TestPayloadMetadataAcceptsOnlyCompleteSequentialNoNetworkMigrationMaterial$' -count=1
```

Require one Plan to bind the current Release Identity, revision and State checksum, the higher candidate, exact `1 → 2` migration, and real managed-update contributions from Connection Profiles, Cloudflare Tunnel, and Subscription Publication, plus disk, interruption, cancellation, and rollback. Require one use, an exact post-approval recheck, one prepared revision `N → N+1`, and exact State/release/migration/Plan checksums before System Changes receives an `Update` Change Set. The only accepted migration replaces `/schema_version` with `2`, performs no network access, preserves every typed Owner value and secret, and forces release-bound core configuration and all subscription representations to regenerate and validate.

### SL-UPDATE-05 — Atomic release switch, restart inspection, and rollback

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestUpdater' -count=1
go test ./internal/cloudflaretunnel -run '^TestExecutorSnapshotsRestartsAndRestoresManagedCloudflaredService$' -count=1
go test ./internal/systemchanges/adapter/ubuntu -run '^TestSoftwareLifecycleUpdateChecksUseTheAuthenticatedExecutor$' -count=1
go test ./internal/softwarelifecycle -run '^TestApplyUpdateHandsOneExactlyBoundChangeSetToSystemChanges$' -count=1
go test ./internal/state -run '^(TestPreparedCommitDurablyCompletesOneSystemChangesChangeSet|TestPostPublicationFailureRestoresPriorDesiredState|TestRollbackCanSurviveASecondProcessDeath|TestRestartAfterCompleteCleansUpWithoutRollback)$' -count=1
```

Require the update executor to capture the authenticated prior release tree, exact ten units, and active executable link in the transaction snapshot before mutation. Require the candidate release, components, units, and active link to switch together; cloudflared, Xray, sing-box, and subscription serving are the only affected services in the update Plan. Require inspection to distinguish exact prior from exact candidate after restart, strict refusal of tampered or trailing snapshot bytes, rollback of a partial switch, and no prior release outside the active snapshot after activation. The update-specific handoff must form one `Update` Change Set; the shared System Changes transaction proof covers one lock, one State publication, pre- and post-publication failure rollback, a second process death during rollback, restart after durable `Complete`, and deletion of the snapshot and journal.

External valid-release success, Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending. These automated checks do not claim any of those later stages.
