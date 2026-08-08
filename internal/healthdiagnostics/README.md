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

The Owner Console calls `Check` directly. `sbxr-health-check.timer` invokes `sbxr-health-check.service` weekly through systemd's exact `OnCalendar=weekly` schedule, with `Persistent=true` for a run missed while the VPS was off. The executable's private `health-check` command constructs the production root-only event history, invokes every currently available owning-Module read-only inspection, and passes all eleven named Module results to `ScheduledCheck`. Unavailable owning Adapters become typed `Unknown`; the command never substitutes a synthetic `Healthy` result. `ScheduledCheck` delegates classification to the same `Check` method and then records its opaque safe events. The units and executable dispatch contain no second classifier, repair, mutation, or additional timer trigger.

## Retained events

`Check` privately constructs one event per returned Module result. A caller cannot turn a forged `CheckResult`, inspection error, raw output, Live Profile Check fact, token, counter, client address, destination, access event, environment value, command argument, journal, Rollback Snapshot, key, configuration, or credential into a retained event.

The complete retained allowlist is time, Module, operation ID, Change Set ID, severity, stable code, fixed safe explanation, and mutation or rollback outcome. The implemented Check events use operation `Check`; Change Set ID and outcome are absent because a read-only check performs no mutation. Persisted input containing either field is rejected until System Changes supplies an opaque typed event proof; free-form strings cannot create fresh transaction evidence. Restored events must reproduce one exact Module, stable code, severity, and fixed explanation combination or the whole history is rejected without replacement.

`EventHistory` keeps exactly 30 days or 50 MiB, whichever limit arrives first. It orders events by UTC time, Module, and stable code, removes expired events and then the oldest eligible events, and atomically replaces one JSON history. The production filesystem Adapter stores only `/var/lib/sbxr/diagnostics/events.json`, requires `/var/lib/sbxr` and `diagnostics` to be root-only `0700`, requires the history to be a root-owned single-link regular file with mode `0600`, and has no capability to open or remove System Changes journals, Rollback Snapshots, rollback proof, or other transaction evidence.

This package also owns the `BundleResult` type required by the shared Interface. Support-bundle construction and `BuildSupportBundle` belong to #123. That later slice may not broaden `Check` into a generic command, file, path, log, or service reader.
