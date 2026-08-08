# Health and Diagnostics

Health and Diagnostics assembles read-only typed facts behind `Check`. It reports installation status separately from Module health:

- installation status is exactly `Not installed`, `Managed`, `Change in progress`, or `Recovery Required`;
- Module health is exactly `Healthy`, `Needs attention`, `Failed`, or `Unknown`.

`Check` receives an `InstallationSummary` and one `NamedInspection` for each Module being checked. Each owning Module performs its own protected inspection and returns only a health result plus that Module-and-result pair's allowlisted `NamedCheckCode`. Health and Diagnostics adds one UTC check time, fixed safe wording, the Required or Advisory gate fact, and a complete Correction Flow. Free-form inspection text cannot cross this boundary. It never receives raw command output, arbitrary paths, service controls, credentials, generated configuration, or Desired State contents.

Malformed, contradictory, timed-out, panicking, duplicate, or secret-like inspection results become `HEALTH-DIAGNOSTICS-CHECK-UNKNOWN`. The original error, output, or panic text is discarded. Repeating `Check` calls every owning inspection again; no observation is cached or adopted as Desired State.

Installation summaries come only from System Changes' opaque `InstallationHealthInspection`. That proof carries its already validated Change Set ID, completed and total step counts, rollback and forward-repair availability, and closed Recovery cause into `InstallationSummaryFrom`. Callers cannot construct those lineage fields directly. Contradictory or unavailable lineage fails safe to `Recovery Required` without copying unverified input.

## Gate facts

`Check` reports gate meaning but does not order gates or decide whether a Change Set continues:

| Role | Result | Gate fact |
|---|---|---|
| Required | Healthy | Passes |
| Required | Needs attention, Failed, or Unknown | Stops |
| Advisory | Healthy | Passes |
| Advisory | Needs attention | Disclose in reviewed Plan |
| Advisory | Failed or Unknown | Stops |
| Not applicable | Any valid result | Not a gate |

System Changes alone owns ordering and the continue, rollback, or Recovery Required decision.

## Correction Flow

Every non-Healthy result contains Problem, exact Found, exact Required, why SBXR stopped, either one separately reviewable SBXR correction or exact Owner steps, Check again, Back, and copyable evidence generated only from the stable code and validated safe facts. A correction is explanatory only. Health and Diagnostics cannot build a Plan, apply a correction, repair a resource, adopt Observed State, restart a service, force a lock, run rollback, or recreate State or secrets.

`Change in progress` and `Recovery Required` receive fixed safe lineage Correction Flow wording. Missing or malformed installation status fails safe to `Recovery Required`; health never substitutes for lineage.

## Scheduled checks

The Owner Console and the future `sbxr-health-check.timer` must call this same `Check` Interface with the same owning-Module inspections. No second classifier and no unresolved schedule setting exists here.

This package already owns the `DiagnosticEvent` and `BundleResult` types required by the shared Interface. Diagnostic-event construction and retention belong to #122. Support-bundle construction and `BuildSupportBundle` belong to #123. Neither later slice may broaden `Check` into a generic command, file, path, log, or service reader.
