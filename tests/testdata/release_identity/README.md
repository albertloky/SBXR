# Offline release identity fixtures

These are synthetic documents and inert ELF byte arrays. They are not native
Linux builds, actual release assets, deployment, runtime or qualification proof.
No fixture executable is run. The inert text is deliberately visible in every
ELF. The Go reference implementation remains unchanged.

`generate.go` calls the preserved Go implementations of
`StampReleaseExecutable`, `BuildLatestReleaseIndex`,
`BuildSubscriptionReleaseIndex` and `VerifyLinuxExecutable`. It emits:

- `go-stamped.bin`: canonical V1 trailer around synthetic text.
- `go-index-v1.json`, `go-index-v2.json`: exact compact Go index bytes (no newline).
- `go-{amd64,arm64}-{valid,wrong-toolchain,duplicate-setting,orphan-replacement}.bin`: synthetic
  ELF64/trailer pairs. The generator requires the original Go verifier to accept
  each `valid` proof and reject each wrong toolchain, duplicate build setting or orphan module replacement.
  It uses Go's own `runtime/debug.BuildInfo.String` for the module text.

The goldens bind `v3.2.1`, commit `b` repeated forty times and sequence 193.
Indexed assets have size 1 and digest `a` repeated sixty-four times; they are
claims for format testing, not authenticated assets.

Regenerate from the repository root, with a fresh workspace-local TMPDIR under
`.scratch/acceptance/<run>/`, using the existing Go 1.26.6 toolchain. For example:

```sh
GOTOOLCHAIN=go1.26.6 GOPROXY=off GOSUMDB=off GOCACHE="$PWD/.scratch/acceptance/<run>/go-cache" \
  go run tests/testdata/release_identity/generate.go
```

The generator overwrites only the named files in this fixture directory.

## Rust API and inspection boundary

`src/release_identity.rs` reuses existing SHA-256 and Installed Record primitives
and adds no dependency. The module is now exported through `src/lib.rs`, and integration tests use that
public crate interface. Native read-only installed-pair checks also consume these
strict trailer and ELF checks; their result remains structural, not authenticated.

`ReleaseIndex::build/decode`, `verify_release_index`, and `verify_asset_proofs`
retain index schema 1, schema 2, all four historical support scopes, the exact
source identity spelling/order, three ordered indexed assets and four exact
asset proofs. Digests cover the original supplied JSON bytes, including
whitespace. `canonical_bytes()` produces the compact Go writer representation
without changing the original digest subject. Unknown/duplicate/missing fields,
null or positional authorities, wrong types, unsupported scopes, duplicate
sources, extra assets and conflicting bytes refuse. Sources are limited to 32.
Stable version components have Go's no-leading-zero grammar, including major
zero, and the positive sequence is a u64 rather than a version-derived order.
The module's release identity type is separate from the ownership codec's
historically more restrictive resource-admission identity constructor.

`stamp_executable` and `read_executable_identity` retain the V1 layout:

```text
payload | compact identity JSON | SHA256(identity JSON)[32]
        | uint64_le(identity JSON length) | SBXR-IDENTITY-V1
```

The trailer binds repository, tag, commit, sequence, architecture and payload
SHA-256. Identity JSON is bounded to 4 KiB, the full executable to 256 MiB, and
the index/installer to 1 MiB. Existing canonical Go trailer bytes are identical.
Parsing also accepts Go's whitespace/order variations while checking their exact
raw document digest. Nested trailers, missing/unknown/duplicate identity fields,
conflicting payloads, impossible lengths and appended garbage refuse. Stamping
alone is a byte binding operation and does not establish executable validity.

`verify_installed_pair` compares Installed Record identity/sequence/architecture
and the entire executable digest with the trailer, matching Go's installed-pair
contract. This cannot authenticate the record's index digest or inspect a native
artifact. `inspect_release_executable` separately binds the index's
repository/tag/commit/sequence/architecture to an inspected executable.

`inspect_linux_artifact` requires the checked trailer and a bounded little-endian
ELF64 ET_EXEC or static ET_DYN for the selected amd64/arm64 machine, nonempty
`.text`/`.rodata`, an entry in the executable load mapping and matching text
section file/virtual addresses. Duplicate sections, PT_INTERP, malformed tables,
load-range overflows and dynamic dependency/audit/filter tags refuse. Static PIE
with no external dependencies retains the same language-specific requirements.

- Historical Go requires `.gopclntab` and aligned `.go.buildinfo`, the actual
  inline build-info format, Go `go1.26.6`, `GOOS=linux`, matching `GOARCH`, and
  `CGO_ENABLED=0`. Duplicate settings, including Go-quoted aliases, refuse.
  This supports the historical pinned toolchain's format, not older pointer
  build-info formats. It never accepts a binary just because Go checks vanished.
- Rust requires one PROGBITS `.sbxr.rust` section containing one strict JSON object with exactly the values
  from `rust_artifact_metadata(commit, architecture)`, with no trailing NUL:
  schema `sbxr-rust-artifact-v1`, repository `albertloky/SBXR`, package `sbxr`,
  compiler `rustc 1.90.0`, profile `release`, exact source commit and the matching
  `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl` target. A retained
  PROGBITS `.comment` must contain exactly one rustc compiler entry, pinned to
  `rustc version 1.90.0 (1159e78c4 2025-09-14)`. Conflicting Go/Rust markers or
  compiler statements refuse. Future offline packaging must embed this explicit
  statement and retain the compiler comment; this module does not modify any
  build or release workflow.

The Rust build statement is unauthenticated metadata, just as Go build info is
not a signature. These APIs return structural consistency only. **External
attestation verification is unimplemented in this module.** Signer/trusted-root,
transparency/timestamp, native release-proof selection, Acceptance Record,
qualification, immutable release selection and publication checks remain required
elsewhere. Archive decoding and checking that the inspected executable came from
the authenticated archive bytes also remain outside this module. No trusted
release or deployable candidate result is exposed here.

`tests/release_identity.rs` covers canonical Go parity, raw digest relationships,
all identity fields, support history, exact asset sets, bounds, ambiguity and
failure paths; explicit Rust metadata; independent original-Go-verifier vectors;
ELF machine/header/entry/section/dependency refusals; and static PIE. All checks
run locally and offline. This work does not claim a native Linux build, actual
packaging, runtime behavior, crash recovery, live VPS, Karing or deployment
qualification. The current Rust executable is not automatically admitted by
these new inspection requirements.
