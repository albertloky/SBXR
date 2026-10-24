# Offline Rust package tooling

This standalone crate prepares and structurally checks local Rust package
bytes. It calls the product's `sbxr::release_identity` API directly for the
trailer, index, build metadata and static ELF checks. It does not run supplied
executables or installers, contact servers, build/sign/publish releases, or
establish deployment qualification.

Tests exercise the public CLI and library with inert synthetic ELF64 fixtures
for **amd64 and arm64**, real local subprocesses/files and an independent
Python standard-library archive/index decoder. Synthetic ELF fixtures never run.

## Asset contract

A complete directory has exactly four regular, non-symlink files:

```text
install.sh
release-index.json
sbxr-linux-amd64.tar.gz
sbxr-linux-arm64.tar.gz
```

Creation accepts one supplied, unstamped ELF per architecture. It must already
contain the exact retained `.sbxr.rust` metadata and pinned rustc `.comment`
required by `src/release_identity.rs`. The shared inspector requires ELF64,
the selected machine and musl target, executable entry/text mapping, static
linkage, and the matching trailer commit. Historical Go inspection stays in
the product module; this Rust tool accepts Rust artifacts only.

Each archive has one regular ustar member `sbxr`, mode `0755`, UID/GID/mtime
zero, empty owner/group/link names, zero padding and two terminal zero blocks.
Gzip has no filename or timestamp. `/usr/bin/gzip -n -c` supplies compression;
decompression is bounded and never extracts to disk. Repeated packaging with
the same gzip implementation and input produces identical bytes. Different
gzip versions are not claimed to produce identical compressed bytes. Checking
deliberately rejects noncanonical tar encodings, extensions and extra blocks.

The index is compact Go-field-order schema 2 with no trailing newline and
`subscription-clean-install-only`, `sources: []`, `sbxr-subscription-update-v1`.
It binds the installer and both archives. Index creation starts with exactly
three indexed assets and checks both executables and installer constant bindings.
Package checking requires all four assets, validates every indexed digest and
inspects the selected architecture, matching the Go command's selection.

Inputs have bounded sizes and stable descriptor/path identity checks. Fixed
asset names open relative to an existing directory descriptor with `NOFOLLOW`;
FIFOs, directories, symlinks and observed late changes are refused. Outputs are
exclusively created with mode `0600`; existing files and symlink targets are
never replaced. Failed partial writes remain for inspection.

## Commands

From the repository root, use a separate package target directory:

```sh
export CARGO_TARGET_DIR="$PWD/.scratch/acceptance/rust-package/target"
cargo build --locked --offline --manifest-path tooling/rust-package/Cargo.toml
tool="$CARGO_TARGET_DIR/debug/sbxr-rust-package"
```

Select the workspace-local Rust installation as documented in
`docs/rust-rewrite.md` when needed. The binary accepts `--flag value` or the
Go command's `-flag value`, refuses unknown/duplicate/missing flags, and emits
fixed diagnostics without input values. Success outcomes explicitly say local.

```sh
# Inspect the canonical bytes shared with the product build script.
"$tool" metadata --commit "$commit" --architecture amd64 --output "$metadata"

# Supply an already-built Rust ELF. Output basename must match architecture.
"$tool" package --tag "$tag" --commit "$commit" --sequence "$sequence" \
  --architecture amd64 --executable "$amd64_elf" \
  --output "$assets/sbxr-linux-amd64.tar.gz"
# Repeat for arm64, supplying its own ELF and archive name.

# Supply the existing reviewed bootstrap; this tool never generates one.
"$tool" index --tag "$tag" --commit "$commit" --sequence "$sequence" \
  --directory "$assets" --output "$assets/release-index.json"
"$tool" verify-package --directory "$assets" --architecture amd64
"$tool" verify-package --directory "$assets" --architecture arm64
```

`package` reports the **stamped executable** SHA-256 needed by the existing
bootstrap generator's `amd64-executable-sha256` / `arm64-executable-sha256`
bindings. Do not substitute the unstamped payload digest.

## Local checks and integration gaps

Run `bash tooling/rust-package/check.sh`. It uses cached dependencies, a separate
target directory, fresh temporary fixtures and retained logs under
`.scratch/acceptance/rust-package/`. Set `SBXR_PACKAGE_RUN_DIR` to another
absolute run path if needed. Dependencies already exist in the product;
no additional Rust package or system tool installation is needed. Tests also
require `/usr/bin/python3` and `/usr/bin/mkfifo`.

Remaining work outside this directory's ownership:

- Build the production executable for native Linux musl amd64 and arm64 with
  the pinned compiler, retained `.sbxr.rust` section and `.comment`. The product
  `build.rs` now embeds the section for an explicitly selected release build;
  `metadata` emits the identical statement for inspection. Neither attests to a
  build. Clean-source/provenance checks must independently bind the source claim.
- Retain the existing bootstrap generator's authenticated download,
  attestation/Acceptance Record, host/path and exact-removal-finisher safeguards.
  Constant agreement here does not validate shell semantics or authentication.
  No replacement bootstrap or download-and-run path is introduced.
- Integrate into reviewed build/workflow code, then perform native packaging,
  independent authentication and current live qualification. `consistent-local`
  grants no install, signing, release or publication authority.

At implementation time this macOS arm64 environment had Rust 1.90.0 for the
host and x86_64 Linux GNU standard libraries, with no installed musl target or
amd64/arm64 musl cross-linker. No native Linux build or deployment was attempted.

## Retained product build identity

In a clean, reviewed source checkout on an equipped Linux build host, use the
pinned Rust 1.90.0 toolchain. The controlled input is a lowercase full Git commit:

```sh
SBXR_BUILD_COMMIT="$(git rev-parse HEAD)" cargo build --locked --offline \
  --release --target x86_64-unknown-linux-musl
# Repeat on the equipped arm64 builder with aarch64-unknown-linux-musl.
```

This is a build command, not install or execution approval. `build.rs` refuses a
stamped debug profile, non-musl/unsupported target, invalid commit or different
compiler version/commit. It generates a linker script with explicit section bytes
and a matching loaded statement; no unsafe Rust attribute, assembler dependency
or post-link source-claim injection is used. Normal development builds retain no
released identity. The inherited internal retained-commit key is always overridden.
Packaging still requires static ELF, correct architecture/entry/text, exact
canonical metadata, pinned compiler comment and matching executable trailer.
Authentication, signer/provenance and Acceptance Record checks remain separate.
Native public **and private** dispatch stay closed pending qualification.

The optional offline mechanics check uses only already installed tools:

```sh
python3 tooling/rust-package/tests/build_identity.py \
  --root "$PWD" --run "$PWD/.scratch/acceptance/<fresh-run>" \
  --rustc /absolute/path/to/rustc --linker /absolute/path/to/rust-lld \
  --clang /absolute/path/to/clang --package "$tool"
```

It compiles the actual build script, tests refusal/normal development/controlled
release output, links a tiny no-stdlib AMD64 Rust object and an ARM64 assembly
fixture with `--gc-sections`, then invokes the existing structural package checks.
It never runs a generated ELF. The GNU-core/assembly inputs carry **synthetic musl
statements** to test linker mechanics only; they are not production SBXR musl
builds or authenticated artifacts. Changed statement commits must fail packaging
for `executable`, with no archive written. Disposable compiler/linker fixtures are
removed on success and failure; command/outcome logs remain in the selected run.
