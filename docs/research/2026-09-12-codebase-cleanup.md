# Codebase cleanup after the MVP live-scope reduction

The five live journeys replace the recurring 25-scenario operator run. Removing
a live test does not retire the product behavior it exercised. This cleanup
therefore removes the old test producer and demonstrably unused functions,
while preserving working product paths and historical release-record readers.

## What was reviewed

The review covered both commands, all product packages and adapters, release
qualification and publication, workflows, script callers, tests, and source
navigation. The starting commit was `0859e96`; existing uncommitted source and
navigation work was inspected and preserved. Local `.scratch/` was treated as
run history rather than current source.

| Area | Decision and reason |
|---|---|
| Proxy Installation and host/sing-box/terminal adapters | Keep setup, review/execute, credentials, renewal, ownership, recovery and removal. They have production callers and support the retained journeys or ordinary recovery. |
| Private Subscription Serving | Keep serving, authentication and bounded network behavior. These serve real client requests; they were not created solely to satisfy the retired operator. Correct the obsolete guide that claimed enablement was disabled. |
| Software Lifecycle | Keep installed-state checks, update transactions and recovery. Remove the two unused constructors; production uses `NewInstalledWithUpdateRuntime`. |
| Host file inspection | Remove unused `boundFileMatchesGroup`; its live underlying inspection remains. |
| V4 operator producer | Retire the 25-scenario scripts, injected faults, rehearsal and capture machinery, and their dedicated tests. Preserve still-used packaged menu and SSH tests in `.github/scripts/`. |
| Current collector | Keep only the five-journey path plus its existing submission, failure and cleanup handling. Remove the old outside-driver protocols and their source-copy inventories. |
| Historical qualification records | Keep the Go validators and GitHub acceptance reader. Existing release records still depend on their historical interpretation. Old producer source is available in Git at `0859e96`. |
| Native CI | Remove seven redundant package-test invocations. Full normal and race suites still run once each, followed by vet; native package/menu checks remain. |

## Concrete reductions

- The release scripts area shrank from **141 files / 25,823 lines** to
  **17 files / 3,356 lines** at the cleanup snapshot, including tests and its new
  README. Most removed lines belonged to the former V4 operator.
- The current collector shrank from **702 to 168 lines**.
- Three unused product functions were removed: `Adapter.boundFileMatchesGroup`,
  `softwarelifecycle.NewInstalled`, and
  `softwarelifecycle.NewInstalledWithUpdateAdmission`. Linux/amd64 reachability
  analysis and caller searches identified them as unused even with tests.
- The old Python-to-Go V4 assembler test was removed with its producer. Pure
  historical record-validation cases remain. The current MVP assembler still
  runs through the actual Go qualification command in its integration test.
- One obsolete test that only asserted two long-deleted filenames were absent
  was removed. It exercised no current behavior.

The dispatcher reports that new historical live attempts are retired before
contacting GitHub. The collector also reports this before SSH. This replaces a
removed capability; it does not change whether a historical record is valid.

## Navigation and file organization

Start with [the code map](../agents/code-map.md). Documentation has a
[single entry index](../README.md), with separate indexes for
[current and historical acceptance](../acceptance/README.md) and
[research](README.md).

- Proxy Installation's ownership decoding and details rendering live in
  `ownership.go` and `details.go`; the coupled review/execute state machine stays
  in `proxyinstallation.go`. All 141 declarations in that existing extraction
  were checked for AST equivalence.
- The 2,742-line release qualification file is split into dispatch, candidate,
  boundary, legacy live, publication, and failure files. All 156 declarations
  were preserved exactly. The [release command map](../../cmd/sbxr-release/README.md)
  describes the stages.
- Root release tests are grouped by CI, candidate, stable, collector, packaged
  driver, and transport responsibility. They stay in the root package because
  they exercise repository-relative paths.
- Current script tests live beside their scripts under `.github/scripts/`, with a
  [tooling map](../../.github/scripts/README.md). Historical source links point
  to the retained Git revision instead of deleted local files.
- `.gitignore` excludes local run history, Python caches and macOS metadata.
  The 4.3 GB `.scratch/` directory is preserved but no longer appears in normal
  `rg` searches as competing source trees.

## Remaining scope

This cleanup does not remove credential rotation, renewal, authentication,
ownership, exclusion locks, or recovery merely because their forced live
variants were retired. Their callers establish current use. The known
historical scenario 03 refusal remains a separate unresolved investigation;
neither deletion of its driver nor a local passing suite proves it fixed.

Installed product behavior is unchanged apart from removing uncalled functions.
The current workflow still contains older first-V3 and Installer-Updater paths;
the MVP manifest enters the current collector branch and exits before those
legacy live runners. Shared packaged helpers also support failure cleanup.
Deleting those remaining paths would require a separate release-mode decision,
not an inference from the five-journey test reduction.

## Validation and review

Passed with the pinned Go 1.26.6 toolchain and a user/group-owned temporary
directory:

- `go test ./... -count=1`, including the full release-tool suite, product
  packages, current MVP assembly and historical record validation.
- The focused root suites again after connecting the relocated shared menu
  tests to CI's normal Go test entry point.
- `go vet ./...` and a Linux/amd64 build of `cmd/sbxr`.
- Python helper discovery: 34 tests run, with 14 Linux-specific skips on macOS.
  Those skipped process-group/subreaper checks remain in native Linux CI.
- Shell syntax, exact declaration preservation for the two source splits,
  current shell/Python/Go checklist agreement, and whitespace checks.

## Standards review

The final code review found no code defect. Three navigation findings were
corrected: an old MVP test filename in the code map, historical commands without
an explicit historical checkout context, and the deleted assembler test still
listed in the catalog. A repository-wide audit checked 1,303 local Markdown links
without a broken target before the cleanup-report link was added.

One judgment-level duplication observation remains: checklist strings appear in
shell, Python and Go. Their current agreement was checked, and the existing MVP
assembler integration exercises the Python/Go boundary. No extra shared policy
file or release prerequisite was added for that maintenance observation.

Standards result: **0 unresolved defects; 3 navigation findings corrected;
1 maintenance observation**, concerning the repeated checklist definitions.

## Spec review

The Spec review found no final requirement defect after verifying the workflow
control flow: the MVP branch exits before the older forced-case runner. A
remaining call to the deleted V4 assembler test was caught during integration
and removed with that producer test before the passing full run.

Spec result: **0 unresolved findings**. Product behavior and historical readers
remain, while the retired live producer is removed and current source is mapped.

Automated tests and cross-builds do not establish live VPS, public-CA, or Karing
acceptance. No new release or live acceptance run is part of this cleanup.
