# Offline validation

Use the actual Rust checkout on main. Read AGENTS.md and triggered guides first.
No live host is needed. Keep test outputs under .scratch/acceptance/project-review/.
Use a short real TMPDIR within the workspace for socket fixtures, not a symlink.
This checkout uses the existing .scratch/toolchain/cargo and .scratch/toolchain/rustup
through CARGO_HOME/RUSTUP_HOME; call $CARGO_HOME/bin/cargo when absent from PATH.

1. Add adjacent Owner details regression tests, run `cargo test --offline --lib
   proxyinstallation::owner::tests`, and record the expected pre-fix failure.
2. Apply the bounded output-only change and rerun that exact suite.
3. Run `cargo test --offline --test menu`, relevant admission/disclosure tests,
   `cargo fmt --all -- --check`, and `cargo clippy --offline --all-targets -- -D warnings`.
4. Review diff and evidence links, run applicable full checks/CI for changed code.
5. Report exact results and live limitations. Do not dispatch candidate/live workflows.

Expected: output selection avoids unused adapter/status aggregation, old prepared
authority refuses, fallback and failed-output behavior remain correct, existing
menu/admission/disclosure regressions pass. Live 90-second success remains unverified.


## Approved reservation validation

Use Go 1.26.6, umask 022 and a short real workspace TMPDIR as in the code map.
Run the new exact build-212 regression before the policy change (expected failure),
then focused candidate-reservation/sequence checks after it. Run
`go test ./cmd/sbxr-release -count=1`, root integration checks and `go vet ./...`.
Existing complete CI verifies native architectures and retained release seams.
Read-only full reservation observation replay must accept exactly ten matching
records and twenty absent refs. Inspect refusal and single-field collision tests;
no test may dispatch a candidate or mutate remote assets. Record all limits.

## Build 213 reservation validation — current continuation

Use the same retained-tooling validation setup above, with new logs under
.scratch/acceptance/q13t/ or the scoped reservation run directory. The build-212
paragraph records its earlier ten-member result. For FR-012/SC-008, first run the
new q213 exact-record and omission/relabel regressions against the ten-record
policy and retain the expected failures. After the bounded change, rerun them
and the focused reservation/sequence/refusal checks, then the full release-tool
and root integration suites, vet and final-source CI. Confirm the previous ten
record bytes and historical replay remain unchanged. Current full observation
replay must accept eleven exact drafts and twenty-two explicitly absent refs.
No candidate/live dispatch, signing or remote mutation belongs to these checks.

## Bounded failure-cleanup validation

Use scoped private logs and real disposable process/filesystem fixtures. First
prove the new clock/driver/caller regressions fail before implementation, then
rerun focused .github/scripts/test_mvp_observe.py and test_v3_menu_session.py checks
plus the affected root caller tests. Include refusal before launch, shared cutoff
and reserve exhaustion, unchanged original/pending evidence, and process cleanup.
Run relevant broad checks and final-source CI after review. A menu success alone
must not satisfy client/secret/transport or live qualification checks.

## Release-tool build-reuse validation

Retain pinned-toolchain before/after evidence under scoped .scratch/acceptance/
run directories. Demonstrate repeated setup and executable-copy isolation
at real process/filesystem boundaries, then rerun unchanged CLI/reader tests.
Run focused normal acceptance, the same focused race comparison and full local
release-tool race checks plus vet; reuse valid unchanged integration evidence.
If the local unsplit run reaches its cumulative alarm, retain the failure and
account for unfinished tests in a separate bounded race batch; combined coverage
is not an unsplit pass. Final-source native CI retains its full unsplit normal/race
suites. Preserve the existing timeout and race settings. Compare timing only within its recorded
environment; require final-source CI before closing T050 or prior T044.

## Operator-budget continuation — 2026-11-06

Use scoped workspace artifacts for the adjacent test_mvp_operator_run.py suite
and existing root recorder/evidence, packaged-menu and release-safety wrappers.
Check default exec, bounded refusal, shared-cutoff exhaustion, clock faults,
cancellation, child/descendant stopping and exact signal results. Review the
current cleanup profile's row sums, distinct reserve meanings and handoff
thresholds. Retain the six-case inert clock/runtime/runner rehearsal separately
from maintained tests. No fixture result proves remote quiescence, Karing cleanup
or live readiness. Final-source native CI is T056; T018 remains independent.

## Build 214 retention — 2026-11-08

Use the existing pinned-toolchain validation setup and .scratch/acceptance/q214res/.
Prove q214 regressions fail against the eleven-record policy, then check the exact
unknown-signing/absent-manifest binding, twelve-record set, preserved prior records,
refusals, historical replay and next-sequence admission. Replay twelve matching
drafts and twenty-four explicit absent refs after fresh read-only checks; run
applicable retained-tooling checks and final-source CI. Earlier q212/q213 validation
counts remain historical. Do not dispatch, sign, mutate remote releases or infer
unsigned/live proof from cancellation.
