# Health and Diagnostics acceptance

This file defines procedures for typed checks, retained diagnostic events, and support bundles. Record run results, commit, runner, time, software versions, stable codes, and redacted evidence in the issue tracker. Never record raw external output, Client Access Values, Infrastructure Secrets, generated configurations, transaction evidence, client IPs, destinations, or traffic facts.

### HD-CAPABILITY-01 — Committed Connection Profile capability and expected absence

Run:

```sh
go test ./internal/healthdiagnostics -run '^Test(CheckReportsCommittedConnectionProfileCapabilityWithoutIndividualNotSetUpHealth|CheckKeepsCapabilityLifecycleSeparateFromExpectedAbsenceHealth|CheckRejectsMalformedOrCandidateConnectionProfileCapability|BuildSupportBundleIncludesOnlyTypedCapabilityAndOmissionFacts)$' -count=1
go test ./cmd/sbxr -run '^Test(ProductionDiagnosticsPresentationUsesTheSameThirteenModuleCheck|PrivateScheduledHealthCommandCallsScheduledCheck|CommittedStateCapabilityRowsSurviveManagedChangeAndRecoveryPresentation|HealthCapabilityInspectionComesFromValidatedCommittedState)$' -count=1
```

Require one Connection Profiles Module Health Result and six fixed capability rows from the last committed revision. Lifecycle is exactly `Not set up`, `Enabled`, or `Disabled`. A `Not set up` row has no individual Health Result, is omitted from publication, and states that Cloudflare Profile Setup is required. Expected absence can be Healthy; exact inert owned residue is Needs attention; active exposure or credential-bearing configuration is Failed; unproved meaning or ownership is Unknown. Repair guidance can remove only exact proved SBXR-owned local residue. It cannot perform setup, create deferred values, adopt provider resources, or delete unproved provider resources.

Require Change in progress and Recovery Required to label these rows with the last committed revision. Candidate settings, credentials, Client Access Values, URLs, provider identifiers, raw responses, and transaction secrets cannot enter `Check`, events, or support bundles. Invalid capability facts fail closed to one `Unknown` Connection Profiles result with no capability rows.

## Module Verification

### HD-CHECK-01 — Exact installation and health matrix

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheckReportsEveryInstallationAndModuleHealthCombination$' -count=1
```

Require all four installation statuses independently from all four health results across all thirteen named Modules. Installation facts must come from System Changes' opaque validated `InstallationHealthInspection`; malformed or contradictory lineage must become `Recovery Required`. Require the UTC check time, owning Module, stable code, role, safe explanation, next action, and complete Correction Flow facts without a fifth status or result.

### HD-CHECK-02 — Fail-closed typed boundary

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheckFailsClosedOnMalformedContradictoryTimedOutOrUnexpectedResults$' -count=1
```

Require malformed, contradictory, timed-out, panicking, erroring, and non-allowlisted inspection output to become Required `Unknown` with `HEALTH-DIAGNOSTICS-CHECK-UNKNOWN` and a stopping gate fact. Raw output and injected markers must not cross the Interface.

Require the current State reclamation policy to produce one persistent Advisory naming only the exact held package/version, deleted executable, native hold status, and no-rollback fact. A returned executable is typed `NETWORK-RECLAMATION-EXECUTABLE-RETURNED` drift and is never deleted by Diagnostics. Missing hold or unreadable evidence remains typed safe drift/Unknown.

### HD-CHECK-03 — Required and Advisory facts

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheckClassifiesRequiredAndAdvisoryFactsWithoutOrchestrating$' -count=1
```

Require every Required non-Healthy result and Advisory Failed or Unknown result to report `Stops`; Advisory Needs attention must report `Disclose in reviewed Plan`; Healthy must report `Passes`. System Changes still owns gate ordering and the mutation or rollback decision.

### HD-CHECK-04 — Fresh observation and contradiction refusal

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheck(UsesFreshOwningModuleInspectionsAndNeverAdoptsTheirState|ReturnsOneUnknownResultForAContradictoryDuplicateInspection)$' -count=1
```

Require each Check to invoke the owning inspection again without caching or adoption. Duplicate ownership must produce one `Unknown` result rather than contradictory Module facts.

### HD-CHECK-05 — Owning Module inspection handoff

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheckConsumesEveryAvailableOwningModuleInspection$' -count=1
```

Require the current State, Network Policy, System Changes, Cloudflare Tunnel, Certificate Lifecycle, Connection Profiles, Subscription Publication, and Subscription Serving Interfaces to reduce their typed results to the exact allowlisted Module-and-result code before `Check`. Health and Diagnostics self-checks through the same seam. Software Lifecycle, Owner Console, Installation, and Cloudflare Profile Setup must remain typed `Unknown` until those Modules supply their named checks. No raw owning-Module error may cross the Interface.

### HD-CHECK-06 — Read-only architecture

Run:

```sh
go test . -run '^Test(RepositoryDependencies|HealthDiagnosticsReadOnlyBoundary)$' -count=1
```

Require the Module core to accept only typed inspections and clock input. Reject product-Module imports, arbitrary commands, direct file access, service control, and generic command, file, path, log, or service capabilities.

### HD-EVENT-01 — Allowlisted construction and forbidden-marker refusal

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestEventHistoryRetainsOnlyAllowlistedCheckFacts$' -count=1
```

Require retained Check events to contain only time, Module, `Check` operation ID, severity, exact stable code, fixed safe explanation, and the fixed typed Connection Profile capability and omission rows from the last committed revision when the event belongs to Connection Profiles. Change Set ID and mutation outcome must be absent for read-only checks. Capability rows are invalid for every other Module. Persisted input containing an arbitrary capability name, lifecycle, explanation, candidate fact, Change Set ID, or mutation outcome must be rejected. Inject unique markers representing every forbidden secret, traffic, Live Profile Check, raw output, environment, argument, journal, and Rollback Snapshot category through owning-inspection failures. Require all markers to be discarded. A caller-forged `CheckResult` must create no event.

### HD-EVENT-02 — Exact bounded deterministic retention

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestEventHistoryAppliesExactAgeAndSizeLimitsOldestFirst$' -count=1
```

Use a controlled clock and storage size. Require an event exactly 30 days old to remain eligible until the 50 MiB boundary requires its removal; require an event older by one nanosecond to expire. Require rotation to remove the oldest eligible UTC event first and leave encoded storage at or below exactly 50 MiB.

### HD-EVENT-03 — Reboot, storage refusal, and transaction-evidence separation

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestEventHistorySurvivesReconstructionAndFailsClosedOnStorageErrors$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestEventStorage' -count=1
```

Require a new `EventHistory` instance over the same storage to read the retained event after reconstruction. Require unavailable, malformed, marker-bearing, broadly readable, wrongly owned, linked, or otherwise unsafe history to fail closed without replacement. Require production storage to be the exact root-only `/var/lib/sbxr/diagnostics/events.json` boundary and prove a planted active journal and Rollback Snapshot marker outside that boundary is unchanged by retention.

### HD-EVENT-04 — One weekly scheduled Check path

Run:

```sh
go test ./internal/healthdiagnostics -run '^Test(ScheduledCheckUsesTheSameCheckInterfaceAndClassification|ScheduledHealthUnitsUseOneWeeklyPersistentCheckEntry)$' -count=1
go test ./cmd/sbxr -run '^TestPrivateScheduledHealthCommandCallsScheduledCheck$' -count=1
```

Require `ScheduledCheck` to return the same typed Module result and classification as `Check`, then retain the event produced by that call. Require `sbxr-health-check.timer` to contain exactly `OnCalendar=weekly`, `Persistent=true`, and `Unit=sbxr-health-check.service`. Require the service to invoke only `/usr/local/bin/sbxr private health-check`, and require that executable path to construct the production root-only history, invoke all currently available owning-Module inspections, represent unavailable owning Adapters as typed `Unknown`, pass all thirteen named Modules to `ScheduledCheck`, and retain thirteen safe events. No competing pre-command, post-command, classifier, repair, mutation, synthetic `Healthy`, or second timer trigger may exist.

### HD-BUNDLE-01 — Exact allowlist and equivalent views

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestBuildSupportBundlePublishesOnlyAllowlistedTypedFacts$' -count=1
```

Require one completed archive containing exactly `manifest.json`, `report.txt`, and `facts.json`. Require the plain and structured views to carry the same typed finding, selected safe event, release, platform, unit, and external-copy warning facts. Inject a forbidden marker through discarded inspection error text and require it to remain absent.

### HD-BUNDLE-02 — Fail-closed inputs, bounds, and publication

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestBuildSupportBundleFailsClosedOnHostileInputsBoundsAndPublication$' -count=1
go test ./internal/healthdiagnostics -run '^TestBuildSupportBundleFailsClosedOnCompressionAndIndependentBounds$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBuildSupportBundleRejectsHostileManagedStorageAndLeavesNoPartialOutput$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBuildSupportBundleRejectsChangingFilesAndReadFailures$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStorageRollsBackFinalDurabilityAndTransactionCleanupFailures$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStorageRecoversCrashDuringLateRollback$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStorageRejectsRollbackMaterialAndCommitPhaseFailures$' -count=1
```

Require forged Check results, unknown fields or files, malformed release or platform facts, traversal, links, non-regular files, broad modes, wrong ownership, changing or short reads, forbidden names or markers, item or total overflow, archive overflow, and publication failure to create no completed bundle and leave no staging artifact.

### HD-BUNDLE-03 — Root-only publication and transaction-evidence separation

Run:

```sh
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStoragePublishesRootOnlyArchiveAndPreservesTransactionEvidence$' -count=1
```

Require exact root-owned `0700` staging and bundle directories, a root-owned single-link `0600` completed archive, an empty staging directory, and unchanged active System Changes journal and Rollback Snapshot evidence outside the diagnostics boundary.

### HD-BUNDLE-04 — Three-bundle retention and reviewed deletion

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestBuildSupportBundleRequiresReviewedDeletionBeforeFourthBundle$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStorageKeepsThreeBundlesAndDeletesOnlyTheReviewedOne$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStorageRecoversEveryReplacementCrashPhase$' -count=1
go test ./internal/healthdiagnostics/adapter/filesystem -run '^TestBundleStorageSerializesConcurrentPublication$' -count=1
```

Require the fourth bundle to stop and return only the exact safe existing bundle names until the Owner selects one. Require successful replacement to delete only that reviewed bundle, retain exactly three completed bundles, leave an external copy unchanged, and return the fixed warning that copied or moved bundles are outside SBXR control.

## Seam Verification

First run one complete protected-storage and certificate seam through its owning check and then through `Check`:

```sh
go test ./internal/subscriptionserving -run '^TestHealthDiagnosticsCheckConsumesSubscriptionServingHealth$' -count=1
```

Require Subscription Serving to validate its active root-owned artifact and certificate inputs, return only its typed health result, and let Health and Diagnostics publish only the allowlisted Module-and-result code and fixed safe facts. The subscription token and artifact body must not cross the seam.

Then run the other owning Modules' controlled read-only seams:

```sh
go test ./internal/state/adapter/filesystem ./internal/networkpolicy/adapter/ubuntu ./internal/systemchanges/adapter/ubuntu ./internal/cloudflaretunnel ./internal/certificatelifecycle/adapter/ubuntu ./internal/connectionprofiles/adapter/ubuntu ./internal/subscriptionpublication/adapter/filesystem ./internal/subscriptionserving -count=1
```

Require official State, filesystem-permission, systemd, listener, Cloudflare, certificate, native-core, publication, and serving formats to remain inside their owning Modules. The owning checks must reduce those facts to `HealthStatus` plus their exact `NamedCheckCode` before calling `Check`; raw format content must never cross the typed seam. Software Lifecycle release-fact and complete-executable wiring are later integrated procedures, not results recorded here.
