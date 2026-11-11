#!/usr/bin/env bash
# Workflow provisioning only; local tests replace every provisioning command with inert stubs.
set -euo pipefail
case "${1:-}" in tools|native) ;; *) exit 2 ;; esac
test "$(uname -s)" = Linux
rustup toolchain install 1.90.0 --profile minimal --component clippy --component rustfmt
rustup default 1.90.0
if test "$1" = native; then
  apt_get=(sudo apt-get)
  case "$(uname -m)" in
    x86_64)
      test "$(lsb_release -is):$(lsb_release -rs)" = Ubuntu:24.04
      target=x86_64-unknown-linux-musl
      # Bypass the runner's failing Azure mirror list for these two commands only.
      apt_sources="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ubuntu-amd64.sources"
      apt_get+=(-o "Dir::Etc::sourcelist=$apt_sources" -o Dir::Etc::sourceparts=-)
      ;;
    aarch64) target=aarch64-unknown-linux-musl ;;
    *) exit 2 ;;
  esac
  "${apt_get[@]}" update --error-on=any
  "${apt_get[@]}" install --yes --no-install-recommends musl-tools cmake make perl
  rustup target add --toolchain 1.90.0 "$target"
fi
cargo fetch --locked
cargo fetch --locked --manifest-path tooling/rust-package/Cargo.toml
