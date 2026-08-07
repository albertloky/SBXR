# State Module acceptance

This file defines procedures and owners only. Run results belong in the implementation issue or the one release Acceptance Record. Evidence must contain stable finding codes and commands, but no raw `state.json`, Client Access Value, Infrastructure Secret, checksum, or secret-derived value.

## `STATE-MODULE-LOAD` — Module Verification — Codex

Run:

```sh
go test ./internal/state
```

Pass when the `Load` Interface proves clean absence, valid Managed and Change in progress snapshots, a complete typed Desired State, exact field names, duplicate-key and unknown-field refusal, supported Release Identity, checksum integrity, every lineage outcome, cross-section validation, complete secret-safe findings, and marker absence. This check owns the `Load` and Correction Flow behavior.

## `STATE-MODULE-PREPARE` — Module Verification — Codex

Run:

```sh
go test -v ./internal/state -run '^(TestPrepareCommit|TestPrepared|TestFirstApply|TestEveryApply|TestEveryApproved|TestPreparation|TestReviewedPlan)'
```

Pass when a fresh installation prepares revision `1`, every Managed revision `N` prepares exactly `N+1`, and preparation binds the exact loaded bytes and checksum, candidate checksum, six managed-input checksums, approved Plan identity and checksum, prepared service manifests, and Change Set. The first Apply attempt must consume the opaque authority. A changed input, observation, checksum, starting State, repeated Plan, or second use must require a fresh Load, Plan, review, and preparation. Refusal, failure, cancellation, rollback, retry, and success must never advance State during preparation and must never permit replay. Change in progress must expose only the last committed revision and typed current operation and must refuse another preparation.

The same check must prove that prior Desired State bytes pass through opaquely for later rollback, all prepared bytes are byte-stable, protected values cannot be rendered, and setting, unchanged-state repair, credential rotation, software migration, and automatic certificate renewal all obey the same `N` to `N+1` rule. Cloudflare management-token replacement or deliberate removal must additionally require the exact one-use Cloudflare Plan, preserve the old token through pre-publication, distinguish approved absence from a missing secret, and restore the prior token after failure or restart rollback. Preparation must perform no publication or mutation; System Changes owns when publication is invoked plus the global journal, Rollback Snapshot, and host rollback.

## `STATE-MODULE-MIGRATION` — Module Verification — Codex

Run:

```sh
go test -v ./internal/state ./internal/state/adapter/filesystem -run '^(TestLoadReportsDeterministicZeroEdgeMigrationReview|TestPrepareCommitReportsZeroEdgeReleaseCompatibility|TestFilesystemSeam)$'
```

Pass when the one actual persisted schema fixture, schema `1`, passes through the production storage Seam repeatedly with an exact zero-step path; Load and PrepareCommit report starting and target schema, ordered steps, meaning or representation changes, generated-service effects, interruption, required Owner input, and starting-release readability without exposing protected values. Schema `1` has no real predecessor, so migration failure and required-input scenarios are `Not required`; no fake schema is added for tests. Every other schema, unknown or deprecated field, and unsupported Release Identity must be refused without changing current State. The first real successor schema must add one explicit embedded `N` to `N+1` transformation, its persisted predecessor fixture, failure and required-input cases when applicable, and proof that no intermediate edge can be skipped. Downgrade has no reverse migration; Software Lifecycle must prove the target release can read current Desired State before it creates a Plan.

## `STATE-MODULE-PUBLISH` — Module Verification — Codex

Run:

```sh
go test -v ./internal/state -run '^(TestPreparedTransactionPublishes|TestFreshInstallationPublishes|TestPublication|TestTransactionAllows|TestPostPublication)'
```

Pass when the consumed opaque transaction preserves the exact prior State or proven Not installed baseline, publishes revision `1` or exactly `N+1` only on its single publication attempt, rejects a changed starting State, and returns exact readback plus typed candidate sections and prepared manifests for post-publication agreement. Simulated failure before replacement must leave the complete prior document current; failure after replacement must leave the complete candidate current and the exact prior bytes available for System Changes rollback. Wrong readback must be refused. The agreement must remain protected and must not claim durable `Complete`; the global journal, Required gates, rollback, `Complete`, and transaction cleanup remain System Changes responsibilities.

The exact ownership contract is:

| Persisted meaning | Semantic validator and secret owner |
| --- | --- |
| Installation identity and pinned software | Software Lifecycle |
| Six Connection Profiles and their Client Access Values | Connection Profiles |
| Subscription settings and token | Subscription Publication |
| Cloudflare authority, immutable bindings, management token, and tunnel run token | Cloudflare Tunnel |
| Certificate policy, identities, and serving pointers | Certificate Lifecycle |
| Network Policy inputs | Network Policy |

State owns structural and cross-section validation, typed persistence, protected serialization, and secret-safe refusal. It invokes the owning validators but does not replace them, test or rotate credentials, expose values through general rendering, or adopt Observed State. During those calls only, Connection Profiles receives readers for its Client Access Values and Infrastructure Secrets, Subscription Publication receives a Client Access Value reader, and Cloudflare Tunnel receives an Infrastructure Secret reader; readers cannot be upgraded to another secret category and are revoked after return or panic. Modules without owned secrets receive no reader. `xray.service` and `sing-box.service` copies belong to Connection Profiles; `cloudflared.service` belongs to Cloudflare Tunnel; `sbxr-subscription.service` belongs to Subscription Serving. Each private manifest binds the owning Module, candidate revision, Change Set, exact serialized bytes, owner `root`, service group, directory mode `0750`, file mode `0640`, and SHA-256. Prepared bytes and their full checksum-bearing manifests remain opaque and non-renderable through the one-use System Changes handoff.

## `STATE-ARCHITECTURE` — Module Verification — Codex

Run:

```sh
go test .
```

Pass when the root registry contains exactly the eleven approved Modules; the repository contains only approved product-package shapes; dependencies are standard-library-first, acyclic, and downward; production code cannot import tests, fixtures, evidence, acceptance tooling, generic dumping grounds, or unregistered Modules; and only State's production filesystem Adapter can construct the Interface from raw `Storage`. This check owns repository placement and rejects any second persistence path.

## `STATE-SEAM-STORAGE` — Seam Verification — Codex

Run the controlled filesystem check as root on the supported Linux environment:

```sh
go test -v ./internal/state/adapter/filesystem
```

Pass only when `TestRootOwnershipSeam` runs rather than skips and the complete check proves fixed `state.json` placement, root ownership, exact `0700`/`0600` modes, stable durable reads, and refusal of symbolic links, hard links, path substitution, unexpected types, broader modes, wrong owners, and corruption. `TestAtomicPublicationSeam`, `TestAtomicPublicationInterruptionPoints`, `TestFreshPublicationDirectoryInterruptionPoints`, and `TestStaleCandidateCleanupInterruptionPoints` must additionally prove real candidate write and flush, checksum verification, atomic replacement, containing-directory flush, exact readback, fresh revision-`1` publication, no half-written current document at every checkpoint, durable cleanup, and safe restart recovery from a stale `state.json.next` without retaining history. Redacted evidence records test names and status only.

## `STATE-SEAM-SERVICE-MATERIAL` — Seam Verification — Codex

Run:

```sh
go test -v ./internal/state -run '^TestPrepareCommit'
```

Pass when protected JSON serialization produces every required byte-stable service copy and no copy for an unused service. Every produced manifest must carry the exact owning Module, owner, group, `0750` directory mode, `0640` file mode, candidate revision, later Change Set, and matching SHA-256. Marker checks must prove unrelated secrets, comments, provenance, complete Desired State, and disabled-profile credentials are absent.

This is preparation proof only. Applying the owner and modes to live service paths is part of the later System Changes seam. If that seam has not run, record it `Pending`; this check does not prove publication or live service behavior.

## `STATE-INTEGRATED-PUBLICATION` — Integrated Verification — Pending

Through the complete `sbxr` executable, System Changes must preserve and verify the Rollback Snapshot and journal, run planned live steps and Required pre-publication gates while the old State remains current, invoke the one-use State publication, prove the returned candidate sections and manifests agree with active files, services, and fresh owning-Module Observed State, then durably write `Complete` and delete transaction material without creating history. An integrated software update must additionally prove its exact migration review and release compatibility before mutation. Until that integration exists and runs against the exact release, this row remains `Pending`.

## `STATE-LIVE-STORAGE` — Codex Live Acceptance — Pending

During one explicitly approved Acceptance Run, use the exact Release Identity and an Acceptance VPS with a proven Acceptance Baseline. Verify the real `/var/lib/sbxr/state/state.json` boundary, root ownership, exact `0700`/`0600` modes, corruption refusal, restart read, and absence of protected content in findings. The later Integrated Verification must also prove that prepared service material reaches each owning service without unrelated values. Destructive corruption must use only the transaction-scoped Acceptance Run procedure and restore or reimage the disposable VPS afterward.

If no approved Acceptance Run occurred, record `Pending`; automated results do not satisfy this check.

## `STATE-OWNER` — Owner Acceptance — Albert

Normally `Not required` because this slice has no maintained-client or Owner-visible workflow. The first SBXR v1 release still follows the release-level risk decision. A later Owner-visible migration or Correction Flow change must name its exact Owner procedure.
