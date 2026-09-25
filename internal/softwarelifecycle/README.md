# Software Lifecycle

Software Lifecycle is one of SBXR's two product Modules. Its Owner-facing Interface remains exactly:

```go
Status(context.Context) Result
Check(context.Context, ProgressReporter) Result
Update(context.Context, ProgressReporter) Result
Recover(context.Context, ProgressReporter) Result
```

The Module owns installed-state proof, GitHub's qualified Latest release, Release Sequence ordering, the mutation lock, two-checkpoint update, rollback, forward completion, and recovery. The V3 numbered terminal menu calls Proxy Installation for proxy Actions and Software Lifecycle for Check/Update/Recover.

Production construction uses `NewInstalledWithUpdateRuntime`: updates require
Proxy Installation admission plus runtime exclusion and completion checks.
Tests use the private `newInstalledInterface` seam for controlled filesystem and
release-source evidence.

The durable MVP paths are `/usr/local/bin/sbxr` and `/var/lib/sbxr/installed.json`. Transaction work stays under `/var/lib/sbxr` and is removed at a verified terminal result.

New update files receive their exact required mode on the newly `O_EXCL`-created
inode before synchronization. A caller's restrictive umask must not turn a
`0755` staged executable into unrecoverable `0700` material. Existing files and
symlink targets are never chmodded by this writer. The released v3.1.81 binary
predates this fix and remains unchanged; the temporary operator launcher gives
only its product child the ordinary `022` mask. See `update_umask_test.go` and the
[wrapper repair](../../docs/acceptance/reports/ordinary-recurring-umask-repair-2026-09-25.md).

The public GitHub Adapter admits exactly four release assets and keeps
`github.com/sigstore/sigstore-go` plus `github.com/klauspost/compress` behind that
boundary. Use the [code map](../../docs/agents/code-map.md) to locate lifecycle
entry points and tests, and the [current operator procedure](../../docs/acceptance/mvp-live-acceptance.md)
for live qualification. [The historical Installer-Updater release procedure](../../docs/acceptance/historical/installer-updater-release.md)
documents the historical Installer-Updater release-pair procedure.

## Subscription update contract (#355)

[ADR-0025](../../docs/adr/0025-ordinary-recurring-live-acceptance.md) adds the
`mvp-recurring-live-v1` qualification profile for one exact then-current stable
source. It retains the support/index and runtime contracts below. Public records
use explicitly named recurring-scope disclosures and five `Journey:` references
alongside the three existing source `Scenario:` references, so v3.1.81 can read
them without changing its released bytes. New readers validate all eight
references. Compatibility tests do not prove an actual packaged update.

The existing menu includes `Check`, `Update`, and `Recover`. `ConfirmReview`
privately binds the displayed source/target or proved recovery direction; it adds
no operation to the Interface. Empty input and `n` cancel. Changed release or
recovery facts require a new review. Unproved recovery direction permits no effect.

Release-index schema 1 retains its historical interpretation. Schema 2 adds one
required `support` object, after `assets`. The repository index builder currently
emits the first subscription scope:

```json
{"scope":"first-subscription-clean-install","sources":[],"contract":"sbxr-subscription-update-v1"}
```

Recurring candidates use `recurring-subscription-upgrade`, the same contract, and
a nonempty array of exact Release Identities (`Repository`, `Tag`, `Commit`,
`IndexSHA256`). Duplicate, unknown, missing, or unlisted sources refuse. The
production lifecycle refuses a newer candidate with no declaration. Same-release
no-update behavior remains supported. This declaration is authenticated by the
attested index; an executable capability marker alone does not admit an update.

The GitHub Adapter requires the Acceptance Record's `Release support: ` line to
repeat the compact JSON object exactly. First-scope records use result code
`RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION` and role
`Clean-installed subscription-capable V3 release`; recurring records retain
`RELEASE-V3-SUBSCRIPTION-QUALIFICATION` and require each declared source's
`source-<tag>-upgrade`, `source-<tag>-precommit`, and `source-<tag>-postcommit`
scenario references. Both require exact Karing and existing secret-safe evidence.
#356 must bind this same declaration to its signed attempt, baseline check,
scenario matrix, and publication revalidation. This reader contract does not
itself establish qualification or authorize publication.

Schema-2 Update Records add `ownership_sha256` to the six existing fields. It
binds unchanged Ownership Record bytes, or SHA-256 of empty bytes for proved
absence. It requires private runtime admission and completion; schema 1 retains
its original rollback/cleanup meaning and cannot carry the added field. Both
source and candidate in any qualified route must understand schema 2.

Before replacement, the existing whole-host lock plus package, renewal admission,
writer, and Certbot directory locks exclude competing mutations. Admission checks
actual package/configuration, provenance, startup, credential/certificate,
firewall, recorder/hook, dependency, and serving contracts. After `Committed`,
only Subscription Serving can restart. The parent verifies the private child's
executable before lending the lock. Runtime completion verifies the exact active
executable, current artifact and certificate, service/listener, and unchanged
ownership before transaction cleanup reopens renewal. Recovery observes an
already completed restart. Diagnostic renewal evidence is never recovery authority
and is not cleared by update.

The first subscription release admits no incoming update from `v3.0.21` or any
other release. Existing Owners must use reviewed Complete removal and its exact
release recovery if interrupted, then install/setup fresh. This entails downtime,
new proxy credentials, and new client setup. The installer refuses remaining
installation paths/resources and retains exact removal-finisher restoration.
No live removal is performed by this implementation. Packaged first-release menu
proof belongs to #357; a later recurring release must qualify its actual source
package before declaring that source supported.
