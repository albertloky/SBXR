# Software Lifecycle acceptance

This procedure defines stable checks for issues #125, #126, #127, #128, #155, and #156. It contains no run results, raw GitHub verifier output, Client Access Values, Infrastructure Secrets, or Owner-managed configuration.

## Module Verification

### SL-VERIFY-01 — One exact verified Release Identity

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestViewReportsOneExactVerifiedReleaseWithoutUsingIt$' -count=1
```

Require one strict index binding `install.sh`, both application roles, and both component roles; exact downloaded and attested equality across all six public release assets; one `sbxr` executable per application archive; one strict complete offline component manifest per matching component archive; repository `albertloky/SBXR`; the selected immutable tag; the 40-character commit; index SHA-256; authenticated sequence; UTC verification time; all five indexed asset digests; safe migration summary; and only `Review install` from Not installed. Require zero extraction to the host, execution, or product mutation.

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

Require the Software Lifecycle core to use no host mutation, process execution, syscall, unsafe capability, or other product Module before later tickets approve those dependencies. Public GitHub HTTPS, bounded download, Snappy decoding, and Sigstore verification must remain inside its genuine external Adapter.

### SL-STAGE-01 — Authenticated selected-architecture handoff

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestView(StagesOnlyTheSelectedVerifiedArchitecture|RefusesWrongArchitectureOrInvalidStagingWithoutLeakingDetails)$' -count=1
```

Require `View` to authenticate and hand off only the archive whose indexed role matches the selected `amd64` or `arm64` architecture. Caller-authored requests, unsupported architectures, missing staging, and secret-bearing failures must fail closed with no candidate or action.

## Seam Verification

### SL-GITHUB-01 — Exact public GitHub and Sigstore contracts

Run:

```sh
go test ./internal/softwarelifecycle/adapter/github -run '^(TestSourcePubliclyVerifiesTheExactSixAssetReleaseWithoutCredentials|TestSigstoreVerifierAuthenticatesTheOfficialGitHubReleaseFixture)$' -count=1
```

Require no GitHub login, personal token, or installed GitHub CLI. Require public HTTPS to prove the exact immutable tag commit and exact six names; Sigstore `1.3.0` to authenticate one GitHub release bundle with one RFC 3161 timestamp, exact `https://dotcom.releases.github.com` identity, and trusted-root SHA-256 `26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485`; bounded same-release downloads; exact digest equality among GitHub metadata, signed subjects, the index, and downloaded bytes; and only typed proof crossing the Adapter.

### SL-GITHUB-02 — External verifier refusal

Run:

```sh
go test ./internal/softwarelifecycle/adapter/github -run '^TestSourceRefusesHostilePublicReleaseFactsWithOneSafeError$' -count=1
```

Require mutable, missing, duplicate, extra, changed, replaced, wrong-commit, wrong-repository, wrong-tag, wrong-digest, malformed-bundle, bounded-download, and signature failures to produce no `ReleaseEvidence` and disclose no raw output.

### SL-STAGE-02 — Safe extraction and complete embedded proof without candidate execution

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestStager' -count=1
```

Require a fresh private directory, exact archive size and digest, one safe root-owned regular `sbxr`, selected 64-bit Linux ELF architecture, Go `1.26.5`, `GOOS=linux`, selected `GOARCH`, `CGO_ENABLED=0`, no ELF interpreter, and no imported native library. Refuse caller-authored requests, unsafe names, links, special files, duplicate destinations, wrong ownership or mode, wrong architecture, and non-Go/runtime-dependent content. Require embedded repository, tag, commit, independent ELF payload digest, the complete exact State schema `1`, its zero-edge migration path, exact units, exact managed paths, exact baselines, exact qualified generated core configurations, and every exact qualified subscription representation. Reject any invented predecessor migration. Bind those embedded facts to the already authenticated external complete Release Identity. Never execute the candidate.

### SL-STAGE-03 — Both pure-Go release payloads and version output

Run:

```sh
go test ./cmd/sbxr-release -run '^Test(BuildCompleteReleaseWritesApplicationAndQualifiedComponentsTogether|BuildArchiveProducesOneQualifiedExecutableForBothArchitectures|VerifiedGitSourceBindsTheCleanExactCommit|VerifyCandidateRefusesInvalidTagBeforeExternalVerification)$' -count=1
go test ./cmd/sbxr-release -run '^TestBuildReleaseIndexFile' -count=1
go test ./internal/softwarelifecycle -run '^TestBuildReleaseIndexBindsInstallAndTheExactFourQualifiedArchives$' -count=1
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^Test(RepositoryComponentSourceLockIsExact|AssembleReleaseComponentsUsesOnlyVerifiedSourceBytes)$' -count=1
go test ./cmd/sbxr -run '^TestVersionReportsOnlyEmbeddedBuildFacts$' -count=1
```

Require the production `cmd/sbxr-release` entry point to bind the requested commit to a clean tracked `HEAD`, export only that exact commit, and refuse mismatched or dirty source. Require pinned Go `1.26.5` and `CGO_ENABLED=0` to build exactly one stamped `sbxr` executable for each of `linux/amd64` and `linux/arm64`. Require each application archive to contain only that executable, with no native library dependency or language runtime. Require the matching component archive to come only from the repository-owned reviewed source manifest, whose exact official source, version, architecture, filename, byte size, SHA-256, and URL facts fail closed on any change. Require the complete Certbot `5.4.0` Ubuntu 24.04 / CPython 3.12 wheel closure plus qualification-only Mihomo `v1.19.29`, safe extraction, exact native qualification, removal of Mihomo before runtime archive assembly, and transaction-like two-output publication. An arbitrary local component tree, URL, command, script, package-manager behavior, caller-supplied asset size, or caller-supplied asset digest cannot satisfy this row. Require the index builder's directory to contain exactly `install.sh` and the four fixed archive names with no extra entry, calculate each size and SHA-256 itself, bind the exact five roles, repository, tag, commit, sequence, State schema, and minimum updater schema, and refuse missing, duplicate, linked, occupied, changed, or mismatched material. Require `sbxr version` and `sbxr version --json` to report only authenticated embedded repository, tag, commit, architecture, payload digest, and State schema; the executable must not invent or accept an index digest.

### SL-BOOTSTRAP-01 — Real generated Pasteable Install Command

Run:

```sh
go test ./cmd/sbxr-release -run '^Test(BuildBootstrapFile|GeneratedBootstrap)' -count=1
```

Require one executable release-specific `install.sh` to embed the exact repository, immutable tag, commit, version, sequence, `amd64 arm64`, and all six fixed names without recreating the impossible index-digest self-reference. Require zero arguments to represent GitHub's stable selection and `--tag <tag>` to accept only the embedded immutable tag. Require Ubuntu Server 24.04, `amd64` or `arm64`, one real input/output terminal, fixed absolute launch tools, and a non-root Owner. Require one fresh Owner-only directory, HTTPS-only bounded redirects to the exact GitHub release asset boundary, one strict exact index, selected archive size and SHA-256, exactly one extracted `sbxr`, matching reported repository, tag, commit, architecture, payload digest, and State schema, then launch as the same Owner with an allowlisted environment. Require cleanup after success, ordinary refusal, and interruption; cleanup failure must become `SBXR-BOOTSTRAP-CLEANUP-FAILED`. Changed index/archive/identity, extra archive material, path or redirect substitution, wrong tag/platform, environment injection, non-interactive use, interruption, and injected secret markers must expose only fixed bootstrap codes. Issue #156 begins on its specified prepared supported host and the script refuses a missing launch tool without mutation. Bootstrap Prerequisite Repair and its bounded pre-Plan `sudo` are implemented only by the immediately dependent issue #157. This slice never receives provider authority, invokes `sudo`, or performs Destructive Reclamation.

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
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^Test(Approval|DraftStore|InstallApply|InstallExecutable)' -count=1
```

Require the fixed Owner draft path, strict allowlisted fields, canonical JSON, an Owner-owned `0600` single-link regular file beneath an Owner-owned `0700` directory, atomic replacement, safe discard, and refusal of links, broad modes, unknown fields, malformed values, and outside-file replacement. Infrastructure Secrets and Client Access Values never enter the draft. Require the exact ordinary-sudo command `/usr/bin/sudo --preserve-fds=3 -- /proc/self/fd/3 private install-apply`, one already-open verified executable descriptor, one inherited Unix socket, root and peer/executable identity checks, one bounded strict typed JSON request, independent candidate restaging, prepare-before-`READY`, one final `APPLY`, and safe refusal of duplicate/unknown/malformed/oversized input, replay, EOF, wrong peer, changed executable or candidate, and parent death before mutation. Production composition of the complete owning-Module Plan and its command entry remains Pending; this row proves the private transport, not a completed Clean-VPS install.

### SL-INSTALL-03 — Exact software activation and partial rollback

Run:

```sh
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^TestInstaller' -count=1
```

Require the exact authenticated staged executable, exact manifest-bound component tree, exact eleven embedded unit templates including `sbxr-recovery.service` rendered only with the authenticated versioned destination, and fixed active symlink. Capture the complete addition list before mutation. Refuse every occupied target. Full and partially completed activation rollback removes only absent-or-byte-exact targets recorded by that attempt; any changed target refuses deletion. Final inspection must prove either the complete release present or every recorded file absent.

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

Require the scheduled seam to call only `Software Lifecycle.View` with Managed installed proof and stable discovery. It must not request architecture staging, Apply, approval, State publication, migrations, binary replacement, service restart, configuration change, or any product mutation. Production `private update-check` must freshly bind the installed Release Identity, refuse while a Change Set is unfinished, and use only the documented root-owned one-candidate store. A real Clean-VPS timer run remains Pending Release Qualification.

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

Require the update executor to capture the authenticated prior release tree, exact eleven units, and active executable link in the transaction snapshot before mutation. Require the candidate release, components, units, and active link to switch together; cloudflared, Xray, sing-box, and subscription serving are the only affected services in the update Plan. Require inspection to distinguish exact prior from exact candidate after restart, strict refusal of tampered or trailing snapshot bytes, rollback of a partial switch, and no prior release outside the active snapshot after activation. The update-specific handoff must form one `Update` Change Set; the shared System Changes transaction proof covers one lock, one State publication, pre- and post-publication failure rollback, a second process death during rollback, restart after durable `Complete`, and deletion of the snapshot and journal.

External valid-release success, Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending. These automated checks do not claim any of those later stages.

### SL-DOWNGRADE-06 — Explicit compatible downgrade

Run:

```sh
go test ./internal/softwarelifecycle -run '^Test(ViewOffersOnlyAFreshCompatibleExplicitDowngrade|PlanDowngrade|ApplyDowngrade)' -count=1
go test ./internal/softwarelifecycle/adapter/ubuntu -run '^Test(Downgrader|Updater)' -count=1
go test ./internal/state -run '^(TestPreparedCommitDurablyCompletesOneSystemChangesChangeSet|TestPostPublicationFailureRestoresPriorDesiredState|TestRollbackCanSurviveASecondProcessDeath|TestRestartAfterCompleteCleansUpWithoutRollback)$' -count=1
```

Require an explicitly selected older tag to pass the same fresh six-asset release verification and architecture staging as any other selected release. Disclose the installed and selected Release Identities side by side and offer only `Review downgrade` when the identities differ, the authenticated sequence is lower, the updater schema is supported, and both installed and selected releases use the currently publishable State schema `2`. Refuse same identity, non-lower sequence, incompatible State, stale approval, changed contributions, or changed prepared State.

Require `PlanDowngrade` to reuse the update Plan's one-use approval, exact recheck, three affected Module contributions, one `Update` Change Set, health and agreement gates, single `N → N+1` State publication, four-service restart, rollback, process-restart inspection, retention, and durable cleanup. Stable discovery and `PlanUpdate` must continue rejecting lower sequences. No reverse migration, automatic downgrade, local history selector, old State revision, old secret, retained snapshot, or recovery parcel is accepted. Evidence remains secret-safe. External valid-release success, Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending on the inherited #127/#128 prerequisites.

### SL-REPAIR-07 — Repair only current Desired State drift

Run:

```sh
go test ./internal/softwarelifecycle -run '^Test(ViewRepair|PlanRepair|ApplyRepair|SoftwareRepair)' -count=1
go test ./internal/connectionprofiles -run '^TestRegistryPlansOnlyAuthorizedForwardRepairOfCurrentLineage$' -count=1
go test ./internal/cloudflaretunnel -run '^TestManagedRepairPlansOnlyCommittedOwnedDriftAndBlocksConflicts$' -count=1
go test ./internal/subscriptionpublication -run '^TestPlanContributesOnlyAnExplicitCurrentStateRepair$' -count=1
go test ./internal/state -run '^Test(ValidCurrentStateDriftCreatesOnlyAFreshForwardRepairChangeSet|PostPublicationFailureRestoresPriorDesiredState|RollbackCanSurviveASecondProcessDeath|RestartAfterCompleteCleansUpWithoutRollback|RetryAutomaticRollbackUsesOnlyTheAuthorizedRecoveryPath|RecoveryRequiredCoversEveryIntegrityAndLineageFailure)$' -count=1
go test ./internal/systemchanges -run '^TestRecoveryRequired(ExposesOnlyItsExactSafeActions|BlocksNormalMutationAndAdmitsOnlyValidForwardRepair)$' -count=1
```

Require `ViewRepair` to expose one protected `Review repair` candidate only after a fresh `Recovery Required` inspection proves valid current Desired State drift, exact revision and checksum, a released lock, no unfinished Change Set, and a complete Observed State digest. Require valid unfinished transaction material to expose `Retry automatic rollback` instead. Missing or corrupt Desired State, lost secrets, dead or replacement VPS, old completed revision, and Owner regret expose only secret-safe evidence, separately confirmed Complete removal, and Clean-VPS rebuild guidance.

Require one deterministic `PlanRepair` to consume the fresh observation and exactly one typed owning-Module contribution. Bind the unchanged current Owner intent, exact reversible steps, required pre- and post-publication checks, disk, rollback, and affected Module without rendering protected material. Apply must consume the Plan once, recheck State, observation, and contribution after approval, accept only State's exact unchanged-intent revision `N → N+1`, and hand one `Repair` Change Set to System Changes. Required failure, cancellation, process death, or disagreement uses the normal transaction rollback and restart rules; unprovable resolution remains Recovery Required.

No repair path may adopt Observed State, unowned resources, arbitrary files or commands; recreate State or secrets; select old revisions; transfer to another VPS; use retained history, backups, snapshots, or recovery parcels; force-unlock; bypass the journal; or manually complete an unfinished transaction. External Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending on issue #127 and the inherited production prerequisites.

### SL-REMOVAL-08 — Complete removal remains rollback-safe through public and Tunnel-route removal

Run:

```sh
go test ./internal/softwarelifecycle -run 'CompleteRemoval' -count=1
go test ./internal/systemchanges -run 'CompleteRemoval' -count=1
go test ./internal/state -run 'CompleteRemoval|Removal' -count=1
```

Require `ViewCompleteRemoval` to expose one protected `Review Complete removal` candidate only from a fresh Managed or Recovery Required observation with volatile facts, a released lock, and no unfinished Change Set or automatic rollback. Bind exact valid State lineage when available; raw bytes or absence may be preserved only as the exact rollback baseline and must never become Cloudflare ownership or token authority. Require one deterministic one-use Plan to authenticate the genuine Owner Console review, full local inventory, exact Network Policy public resources, exact Cloudflare DNS, route, and Tunnel identifiers, active locally available scoped token, disk, ordinary sudo, both irreversible remnants, cancellation boundary, rollback to the exact starting status, token-revocation responsibility, and final Not installed proof without rendering protected values. Refuse stale or reused observations, missing categories, caller-made reviews, changed identifiers, incomplete ownership, unavailable token authority, or a competing unfinished transaction. A Recovery Required review without independent immutable-ID and token proof returns a typed refusal with safe diagnostics, manual provider-cleanup, and Clean-VPS rebuild guidance instead of adopting raw State.

Apply must require the genuine exact interactively typed `COMPLETE REMOVAL` authority and the separate genuine `Permanently remove SBXR` selection, recheck every fact after approval, accept only State's exact rollback binding, and hand one Complete-removal Change Set to System Changes. Failure, cancellation, or restart through public-exposure and Tunnel-route removal restores Managed to Managed and Recovery Required to Recovery Required unless transaction-bound State genuinely proves the exact earlier Managed baseline. Record `Irreversible removal started` only after that rollback-capable absence gate and local readiness pass; only then delete exact immutable-ID DNS records and the Tunnel, record `Owned external deletion verified`, and ask Albert to revoke the scoped token. Issue #133 owns every forward-only phase after that checkpoint. External Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending on issue #127 and the inherited production prerequisites.

### SL-REMOVAL-09 — Complete removal finishes forward-only

Run:

```sh
go test ./internal/systemchanges ./internal/state -run 'Test(CompleteRemoval|IrreversibleCompleteRemoval|UbuntuAdapter.*Removal)' -count=1
```

After rollback-capable public and Tunnel-route absence is durable, require exact local-deletion readiness before recording `Irreversible removal started`. Delete the immutable-ID-proven DNS records and Tunnel forward-only, record `Owned external deletion verified`, and keep the scoped token copy protected until Cloudflare rejection is verified. A still-usable token waits for Albert; an unavailable proof reports the last durable forward checkpoint without rollback or secret-bearing native errors.

Delete only in this order: State, Infrastructure Secrets, certificates, durable `Transaction material deletion authorized`, transaction material except the journal, releases, units, identities, listeners, prepared artifacts, and owned firewall state. Every phase is idempotent and durably recorded. Process death immediately before or after any record resumes at the first phase not durably proved, including a crash during checksummed snapshot/manifest deletion after its authorization record. Report success only after exact `Not installed` and complete recovery-material absence are observed, then remove the journal and private restart runner last. External Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending on issue #127 and the inherited production prerequisites.
