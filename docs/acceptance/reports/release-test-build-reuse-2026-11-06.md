# Release-tool test build reuse — 2026-11-06

This separately authorized offline investigation follows the cumulative Go race
suite timeout in [Verify 42217521869](https://github.com/albertloky/SBXR/actions/runs/42217521869)
at `335769cc1b27694d10065fa88eccc09cdeeccd80`. It does not access the VPS,
dispatch qualification, sign a candidate or publish a release.

## Observed failure and comparison

| Release-tool package | Previous c60efd0 normal / race | Failed 335769c normal / race |
|---|---:|---:|
| Linux amd64 | 376.368s / 589.816s | 393.306s / 600.106s timeout |
| Linux arm64 | 302.003s / 509.589s | 299.895s / 500.395s |

The previous [Verify 42208919789](https://github.com/albertloky/SBXR/actions/runs/42208919789)
passed all four jobs. Its amd64 race package had only 10.184 seconds of margin
under Go's default ten-minute package timeout. The failed run reports
`TestQualificationCommandBuildsOneCleanV3Candidate (0s)`, waiting in its initial
`go build`. The package's cumulative budget expired just as this test started;
the evidence does not show this individual test hanging for ten minutes.
Current arm64 passed the complete test step, then packaging was cancelled by the
amd64 matrix failure. Root Go tests, including the cleanup regressions, passed.

No Go source/tests, dependencies or Verify workflow changed between these two
revisions. Existing release-package assembly tests invoke ordinary recorder
commands, including the strict loader now opening regular files nonblockingly;
they do not invoke the new cleanup deadline or menu mode. CI did not emit
individual test timings, so the exact earlier test cost and runner contention
cannot be reconstructed from these logs.

## Redundant setup and intended repair

Static caller inspection found 23 identical CLI build sites across ten test files,
expanding to 51 builds per full package run. All compile the same `sbxr-release`
source with the same arguments and environment. No existing caller mutates that
executable or changes process environment/directory; real command invocations and
independent output trees must remain intact. The installer payload already caches
its two architecture builds and is outside this repair. Six distinct released-reader
compatibility checks also remain unchanged.

Six local pinned Go 1.26.6 builds took 2.223 seconds initially, then
0.767, 0.780, 0.776, 0.798 and 0.828 seconds (warm mean 0.790 seconds).
This confirms measurable redundant work locally; it does not predict Linux race
savings or identify all time consumed by the failed CI package.

The bounded design builds once per test process, retains synchronized immutable
executable bytes, and writes a fresh executable into each test's owned temporary
directory. It preserves real subprocess commands, fixture independence, error
reporting and cleanup. No test assertion, package timeout, race flag, workflow,
production source, dependency or release rule changes.

## Verification checkpoint

The regression first failed with three real builds where one was required. After
the repair, both new tests passed normally (2.284s) and under race detection
(4.425s). They execute the real compiler/CLI and verify independent paths/inodes,
copy mutation/removal, owner-directory cleanup, later-copy lifetime, and compiler
failure diagnostics with no temporary leftovers. The isolated success regression
intentionally performs one additional build in its own process; the failure
regression intentionally invokes the compiler with a rejected flag. The reduction
from 51 to one applies to the existing routine fixture builds, not every compiler
invocation including these new regressions.

The identical command-focused race selection passed all 469 tests/subtests
(16 top-level tests, zero skips) before and after, taking 79.548s versus 63.024s:
20.8% shorter on this Mac with Go 1.26.6. This is a single local comparison,
not a controlled Linux benchmark or live timing result. The unsplit full local
race package subsequently hit its unchanged 600-second alarm at 600.359s. Before
the alarm, 108 top-level tests (1,130 tests/subtests) passed and the existing
controlling-terminal test was skipped on macOS. The active clean-install repair
test had run for two seconds; no individual assertion failure or race warning
preceded the package alarm. This is a failed package run, not a full-suite pass.
The remaining 18 top-level tests passed in a separate bounded race batch in
45.658s (371 tests/subtests, zero skips). Across the two invocations, all 127
listed top-level tests are accounted for: 126 passed, one existing macOS skip;
1,483 distinct tests/subtests passed. This completes local case coverage, not an
unsplit local-package pass. Native CI still runs the full normal and race suites
without batching or timeout changes and remains required at this checkpoint.

The alarm left one disposable executable in its owned test directory. Fresh
process inspection found no remaining test child; only that verified file and
its empty parent directories were removed. The remainder batch cleaned its own
temporary files normally. Original logs were preserved.
Repository Go vet, changed-Go formatting, local Markdown link targets and
whitespace checks passed. Independent final source review found no blocking
issue. Concurrent first-use and recovery after a compiler failure were reviewed,
not directly exercised by the new regressions.

Raw failure evidence is under `.scratch/acceptance/c4g/`; comparison logs are in
`.scratch/acceptance/c5e/`, and baseline build timing is in
`.scratch/acceptance/c5p/build-timings.json`. Red/green evidence is in
`.scratch/acceptance/bct/`; focused before/after JSON is in `c5b/`, the unsplit alarm and remainder
selection/results in `c5r/`, and vet output in `c5v/`. All are local evidence in the Rust checkout, not current host-readiness
or live-qualification records. Preserve the original failure independently of
subsequent outcomes.

The existing Spec Kit project review tracks this bounded continuation. Its live
90-second details/five-journey criterion remains open. Offline test efficiency
cannot establish safe live cleanup duration or qualify any candidate.
