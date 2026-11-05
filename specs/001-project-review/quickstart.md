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
