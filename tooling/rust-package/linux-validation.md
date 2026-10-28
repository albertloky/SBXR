# Prepared Linux build and validation

This is a command handoff, not a claim that Linux or musl validation ran on the
Mac. Run checks as an ordinary user in a separately prepared native Linux
builder. No VPS, product installation, firewall/service/credential changes,
signing, remote workflow dispatch or publication is part of these commands.

## Minimum prepared inputs

For each artifact use a matching native machine:

| Artifact | Native machine | Rust target |
|---|---|---|
| amd64 | Linux x86_64 (workflow: Ubuntu 24.04) | x86_64-unknown-linux-musl |
| arm64 | Linux aarch64 (workflow: Ubuntu 24.04 ARM) | aarch64-unknown-linux-musl |

Use **Rust/Cargo 1.90.0**, with the selected target's standard library already
installed; native **musl-gcc** and musl headers/static libc; **cmake, make, perl**
for the locked AWS-LC/ring native builds; **Git, Python 3, Bash, gzip and coreutils**.
The two Cargo lockfiles' dependencies must already be available for `--offline`.
The product build adds no OpenSSL/system crypto dependency. Existing Go **1.26.6**
is additionally needed for the retained repository qualification/reference checks,
not for the shipped executable. These tools were not installed during local work.

The checked-in `.cargo/config.toml` selects native `musl-gcc`, static CRT, and a
common repository `target/`. It supplies no implicit cross-compiler or sysroot.
A Mac lld/no-stdlib fixture is not a production Rust musl build.

## Source archive validation

Use the exact archive identity and manifest digest supplied separately by the
coordinator. Verify its SHA-256 before extracting into a new directory. The
archive contains only committed files plus `SOURCE-MANIFEST.json`; it has no Git
metadata, scratch/cache outputs or live credentials. Public and synthetic test
fixtures are deliberately retained, including the 32.3 MB pinned DEB.

The coordinator supplies the externally pinned full commit and manifest digest.
From the newly extracted source root, verify every file before building:

```sh
python3 -B tooling/rust-package/source_snapshot.py --root "$PWD" \
  --commit "$source_commit" --verify-manifest-sha256 "$manifest_sha256"
```

This refuses missing, changed, extra or symlinked source files. It describes source
integrity, not a release signature or production authorization.

From that verified source root:

```sh
export CARGO_BUILD_JOBS=2
export TMPDIR="$PWD/.scratch/acceptance/linux-validation/t"
mkdir -p -m 0700 "$TMPDIR"
cargo fmt --all -- --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
cargo test --locked --offline --manifest-path tooling/rust-package/Cargo.toml
python3 -B -m unittest discover -s tooling/rust-package/tests -p 'test_*.py'
```

A source archive has no `.git`, so the CI helper's clean-Git check does not apply
to it. After the externally pinned archive/manifest has been checked, build with
its exact commit explicitly; do not invent a replacement Git commit:

```sh
source_commit="$(python3 -c 'import json;print(json.load(open("SOURCE-MANIFEST.json"))["commit"])')"
case "$(uname -m)" in
  x86_64) rust_target=x86_64-unknown-linux-musl ;;
  aarch64) rust_target=aarch64-unknown-linux-musl ;;
  *) exit 1 ;;
esac
SBXR_BUILD_COMMIT="$source_commit" cargo build --locked --offline --release --target "$rust_target"
cargo build --locked --offline --release --manifest-path tooling/rust-package/Cargo.toml
```

Build refuses other compiler versions/profiles/targets. The loaded statement and
retained `.sbxr.rust` section must match the source commit; Rust's pinned `.comment`
must remain. This build command never executes the resulting product.

For a real clean Git checkout, `build_native.py` performs the source/tool checks
and packaging together:

```sh
mkdir -p -m 0700 .scratch/acceptance/native-build
python3 tooling/rust-package/build_native.py --tag "$tag" \
  --commit "$(git rev-parse HEAD)" --sequence "$sequence" \
  --architecture "$architecture" \
  --output ".scratch/acceptance/native-build/sbxr-linux-$architecture.tar.gz"
```

Supply the two unchanged native archives to the existing assembly tool:

```sh
python3 tooling/rust-package/assemble.py --tool "$PWD/target/release/sbxr-rust-package" \
  --tag "$tag" --commit "$source_commit" --sequence "$sequence" \
  --amd64 "$amd64_archive" --arm64 "$arm64_archive" --output "$new_asset_directory"
```

The output must be exactly install.sh, release-index.json and the two native
archives. The Rust verifier requires static ELF64, target/entry/text mapping,
canonical metadata, pinned compiler comment, identity trailer, exact bootstrap
and all index/digest bindings. Structural consistency never substitutes for
Sigstore signatures, source/provenance, Acceptance Record or live qualification.

## Admission and remaining validation

Public dispatch requires authenticated delivery/current-process admission; private
dispatch requires offline exact-pair/role/start-lock admission. Proxy setup is currently
admitted only on Ubuntu 24.04 amd64; producing an arm64 artifact is not an arm64
proxy deployment claim. `closed_dispatch.sh` checks only non-root refusal and
private result codes, without installation or host-root effects.

Current acquisition has distinct authenticated stable and candidate routes. The
candidate route binds the signed manifest, protected gateway and installed/current
bytes; it grants no qualified stable authority. See the
[current native acceptance requirements](../../docs/rust-acceptance.md#conditional-native-setup-base-594add9).
The five exact-candidate live journeys still require their approved preparation
and actual evidence. Do not bypass admission with a test verifier,
URL override or environment switch. Native systemd/proc/cgroup, retained locks,
crash durability and exact-finisher execution also require current-source Linux
validation. The optional VMess profile needs separately bound two-node evidence.
Repository qualification/collector compatibility with the Rust product must be
checked before a live attempt; the Go policy engine and historical wire fields
have been retained, not reclassified as a new live pass.

The existing stable workflow still requires a manually selected successful
signed qualification, unchanged assets, complete cleanup and publication approval.
Local tests/builds do not make that gate eligible. HTTPS creation/ACME, incoming
updates and automatic migration remain outside this clean-install HTTP scope.
