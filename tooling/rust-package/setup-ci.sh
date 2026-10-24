#!/usr/bin/env bash
# Workflow provisioning definition only. Local validation must never run this.
set -euo pipefail
case "${1:-}" in tools|native) ;; *) exit 2 ;; esac
test "$(uname -s)" = Linux
rustup toolchain install 1.90.0 --profile minimal --component clippy --component rustfmt
rustup default 1.90.0
if test "$1" = native; then
  case "$(uname -m)" in
    x86_64) target=x86_64-unknown-linux-musl ;;
    aarch64) target=aarch64-unknown-linux-musl ;;
    *) exit 2 ;;
  esac
  sudo apt-get update
  sudo apt-get install --yes --no-install-recommends musl-tools cmake make perl
  rustup target add --toolchain 1.90.0 "$target"
fi
cargo fetch --locked
cargo fetch --locked --manifest-path tooling/rust-package/Cargo.toml
