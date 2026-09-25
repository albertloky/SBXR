# Ordinary recurring acceptance — implementation and local validation

## Result and limits

Implemented the Owner-approved **five ordinary journeys plus three packaged
upgrade/recovery checks**, initially scoped to v3.1.81 to the next release.
See [ADR-0025](../../adr/0025-ordinary-recurring-live-acceptance.md) and the
[operator procedure](../ordinary-recurring-live.md).

This is local implementation/regression evidence on macOS, based on main
`9e4c71f3a04ad955e51e5162572404f0e4f7d629`, with the changes in the working tree.
It is **not a live acceptance pass or a proven packaged upgrade**. No candidate
was dispatched, no release published, no VPS changed, no certificate requested,
and no real Karing journey performed. Release/host readiness was not refreshed.

## Before and after

Before, `mvp-live-v1` was limited to the exact clean-install repair scope. The
current producer refused recurring attempts, while the old recurring validator
required its historical matrix. The unchanged v3.1.81 public reader also refuses
the clean-install MVP disclosure format when used with recurring support.

The new `mvp-recurring-live-v1` policy binds one verified then-current source,
its exact supported-source declaration and all eight ordered scenarios. It
retains the existing signed manifest, deadlines, strict evidence validation,
failure/burn handling and publication rechecks. No old policy or one-release
exception acquired broader meaning.

The public record names the new recurring coverage explicitly. Its five
`Journey:` references coexist with the three existing exact source `Scenario:`
references. A frozen copy of v3.1.81's **support-reader functions**, with only
mechanical function renaming and a source-byte hash check, accepts a record
actually emitted by the new validator. New readers additionally enforce the
new coverage disclosures and all five journey references. This is source-level
parser compatibility, not execution of the released Linux binary, network
attestation verification or a successful installed update.

The incremental `mvp-observe.py` helper records each explicit observation at
the current time, binds it to the exact request and refuses duplicate checks,
stale requests, incomplete/late submissions and existing output. It seals the
draft before publication. It does not drive the product or automatically prove
an observation. The existing manual JSON handoff remains supported.

## Validation

With `GOTOOLCHAIN=go1.26.6` and workspace-local temporary directories:

- Full `go test ./... -count=1`: passed.
- `go vet ./...`: passed.
- `go test -race ./cmd/sbxr-release ./internal/softwarelifecycle/adapter/github -count=1`: passed.
- Real recorder CLI/filesystem → assembler → qualification-command checks:
  all eight synthetic scenario prefixes accepted without issuing a record;
  only the complete result emitted one. The original five-journey path passed.
- Each required observation is independently necessary. Tests refuse missing
  source evidence, wrong recovery/boundary, failed/late observations, changed
  source identities, extra/empty sources, historical-policy relabelling and
  exception reuse. Stable preflight refuses source drift, altered records and
  failed candidates. The original stop/burn path accepts a new-source timeout.
- The real shell checklist function agrees with assembler/validator checks.
  Both producer policies reach the workflow dispatch boundary; historical
  producer policies still refuse before GitHub is called.
- Recorder tests cover permissions, symlinks, hard links, duplicate JSON,
  incomplete evidence, repeated submission, expiry and cleanup of temporary
  publication files. Python tests also run through the root Go checks.
- Final diff and whitespace review: passed.

During development the cross-language test caught a new local variable
shadowing the assembler's boundary facts; it was corrected and the full path
rerun. A new source-drift negative test initially wrote the fixture's existing
commit rather than a different one; it was corrected to make an actual change,
without weakening the refusal assertion. The final full and focused runs passed.

[Final validation logs](../../../.scratch/acceptance/u81j/),
[focused final-boundary checks](../../../.scratch/acceptance/u81i/).
Fixtures and their Acceptance Record strings are synthetic and are not release
evidence. Temporary test directories were removed.

## Remaining proof before dispatch

1. Reverify the real source package and current release state.
2. Rehearse the actual packaged Update/Recover execution boundaries on isolated
   Linux, including precommit and postcommit interruption, the permission
   wrapper where needed, and real SSH handoff. No new interruption driver was
   implemented or qualified here. macOS skips do not establish these results.
3. Review fresh host/outside/Karing availability, source preparation and CA
   capacity. The old two-operation CA plan does not cover all new preparations.
   Budget actual rehearsed timings inside the unchanged six-hour session;
   adding every per-scenario maximum would exceed it.
4. Qualify one fresh exact candidate with all eight real journeys, no borrowed
   passes or late-confirmation exception. Obtain separate publication approval
   only after its ordinary qualification succeeds.

Until those steps are complete, describe the state as **implemented and locally
regression-tested**, not live-validated or upgrade-proven.
