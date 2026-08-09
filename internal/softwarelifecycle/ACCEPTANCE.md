# Software Lifecycle acceptance

This procedure defines stable checks for issue #125. It contains no run results, raw GitHub verifier output, Client Access Values, Infrastructure Secrets, or Owner-managed configuration.

## Module Verification

### SL-VERIFY-01 — One exact verified Release Identity

Run:

```sh
go test ./internal/softwarelifecycle -run '^TestViewReportsOneExactVerifiedReleaseWithoutUsingIt$' -count=1
```

Require one strict index, both architecture roles, exact downloaded and attested equality, one `sbxr` executable per archive, repository `albertloky/SBXR`, the selected immutable tag, the 40-character commit, index SHA-256, authenticated sequence, UTC verification time, both asset digests, safe migration summary, and only `Review install` from Not installed. Require zero extraction to the host, execution, or product mutation.

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

The controlled seam proves command construction and parsing. A real SBXR immutable release does not yet exist, so external valid-release success, complete executable integration, Integrated Verification, Codex Live Acceptance, Owner Acceptance, and Release Qualification remain Pending. The exact GitHub CLI version must be reviewed and recorded for the exact future Release Identity before any candidate can qualify; a later approved signing-key rotation requires an explicit code and acceptance update rather than accepting an arbitrary caller-supplied fingerprint.
