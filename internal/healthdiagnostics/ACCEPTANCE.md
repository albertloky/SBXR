# Health and Diagnostics acceptance

This file defines procedures for the typed `Check` slice only. Record run results, commit, runner, time, software versions, stable codes, and redacted evidence in the issue tracker. Never record raw external output, Client Access Values, Infrastructure Secrets, generated configurations, transaction evidence, client IPs, destinations, or traffic facts.

## Module Verification

### HD-CHECK-01 — Exact installation and health matrix

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheckReportsEveryInstallationAndModuleHealthCombination$' -count=1
```

Require all four installation statuses independently from all four health results across all eleven named Modules. Installation facts must come from System Changes' opaque validated `InstallationHealthInspection`; malformed or contradictory lineage must become `Recovery Required`. Require the UTC check time, owning Module, stable code, role, safe explanation, next action, and complete Correction Flow facts without a fifth status or result.

### HD-CHECK-02 — Fail-closed typed boundary

Run:

```sh
go test ./internal/healthdiagnostics -run '^TestCheckFailsClosedOnMalformedContradictoryTimedOutOrUnexpectedResults$' -count=1
```

Require malformed, contradictory, timed-out, panicking, erroring, and non-allowlisted inspection output to become Required `Unknown` with `HEALTH-DIAGNOSTICS-CHECK-UNKNOWN` and a stopping gate fact. Raw output and injected markers must not cross the Interface.

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

Require the current State, Network Policy, System Changes, Cloudflare Tunnel, Certificate Lifecycle, Connection Profiles, Subscription Publication, and Subscription Serving Interfaces to reduce their typed results to the exact allowlisted Module-and-result code before `Check`. Health and Diagnostics self-checks through the same seam. Software Lifecycle and Owner Console must remain typed `Unknown` until those later Modules supply their named checks. No raw owning-Module error may cross the Interface.

### HD-CHECK-06 — Read-only architecture

Run:

```sh
go test . -run '^Test(RepositoryDependencies|HealthDiagnosticsReadOnlyBoundary)$' -count=1
```

Require the Module core to accept only typed inspections and clock input. Reject product-Module imports, arbitrary commands, direct file access, service control, and generic command, file, path, log, or service capabilities.

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
