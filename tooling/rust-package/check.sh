#!/bin/bash
set -euo pipefail

package=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$package/../.." && pwd)
run=${SBXR_PACKAGE_RUN_DIR:-"$repository/.scratch/acceptance/rust-package"}
case "$run" in /*) ;; *) echo 'rust-package/run-directory refused' >&2; exit 1 ;; esac
mkdir -p "$run"
export TMPDIR="$run/t"
mkdir "$TMPDIR" # Refuse to reuse fixtures left by an earlier interrupted run.
cleanup() {
  # macOS compiler discovery leaves this cache in TMPDIR; retain it with the logs.
  if [ -f "$TMPDIR/xcrun_db" ] && [ ! -L "$TMPDIR/xcrun_db" ]; then
    compiler_cache=$(mktemp "$run/xcrun-cache.XXXXXX")
    mv "$TMPDIR/xcrun_db" "$compiler_cache"
  fi
  rmdir "$TMPDIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export CARGO_TARGET_DIR="$run/target"
if [ -x "$repository/.scratch/toolchain/cargo/bin/cargo" ]; then
  export CARGO_HOME="$repository/.scratch/toolchain/cargo"
  export RUSTUP_HOME="$repository/.scratch/toolchain/rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
manifest="$package/Cargo.toml"
cargo fmt --check --manifest-path "$manifest" 2>&1 | tee "$run/fmt.log"
cargo clippy --locked --offline --all-targets --manifest-path "$manifest" -- -D warnings 2>&1 | tee "$run/clippy.log"
cargo test --locked --offline --manifest-path "$manifest" 2>&1 | tee "$run/test.log"
cargo build --locked --offline --manifest-path "$manifest" 2>&1 | tee "$run/build.log"
