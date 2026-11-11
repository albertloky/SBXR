# Validate the cleanup

From the repository root, use the existing local tools; no installation is needed.

1. Confirm `git branch --show-current` is `main` and inspect `git diff --stat` plus
   `git status --short`. Only navigation, feature 002, src/subscription_artifact.rs and
   src/server_configuration.rs belong to this pass.
2. Run Spec Kit prerequisites with the existing qualification selector preserved:

   ```sh
   SPECIFY_FEATURE_DIRECTORY=specs/002-project-cleanup SPECIFY_FEATURE_NO_PERSIST=1 \
     bash .specify/scripts/bash/check-prerequisites.sh --json --require-tasks --include-tasks
   ```

3. Follow every local link in `docs/README.md`, `specs/README.md`, and feature 002.
   Every target must exist. Historical private scratch references are not public links.
4. Run `git diff --check`. Check new Markdown for trailing whitespace too, since
   ordinary Git diff omits untracked files.
5. Verify `.specify/feature.json` still selects `specs/001-project-review`.

Optional unchanged-source baseline checks: use the workspace-local Cargo environment
in `docs/rust-rewrite.md` for `cargo fmt --all --check` and the same command with
`--manifest-path tooling/rust-package/Cargo.toml`. Parse tracked Python files without
bytecode writes and shell files using `bash -n`. These checks are syntax/formatting,
not behavior or live qualification.

## Source simplification checks

Use a fresh short workspace-local run directory and TMPDIR as required by the
agent guide, and select the installed workspace-local Cargo/Rustup environment
from `docs/rust-rewrite.md`. All commands use cached dependencies.

```sh
cargo test --locked --offline --lib subscription_artifact::tests
cargo test --locked --offline --test subscription_artifact --test server_configuration
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path tooling/rust-package/Cargo.toml
cargo fmt --all --check
```

The focused run must pass the RFC vectors, Go-generated artifact/configuration
fixtures, tunnel-resource digest fixture, independent configuration digest
comparison, and invalid-input/redaction checks. The full run must preserve existing
platform skips and ignored helper/manual tests; it does not establish native Linux
or live qualification. The one-time wrong-padding mutation was restored and need
not be repeated for an unchanged diff.
