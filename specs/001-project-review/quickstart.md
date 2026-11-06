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
