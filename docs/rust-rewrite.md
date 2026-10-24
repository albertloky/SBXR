# Rust rewrite: first local setup slice

This isolated workspace contains the start of the Owner-requested full Rust
rewrite. It is an implementation increment, not a release or a deployable
replacement. The zero-argument Rust executable runs an explicitly labeled,
in-memory simulation. It cannot install software, write installation state,
change services/firewall, use credentials, or access the network.

## Provenance and preserved reference

- Workspace: `/Users/Albert/Documents/Codex/SBXR-rust-abbe4d7`.
- Original checkout: `/Users/Albert/Documents/Codex/SBXR`.
- Committed source: `abbe4d7dbe9ca7de93afa6475975fc4cb35ef74a`
  (`feat: guide proxy setup with a numbered wizard`).
- Created by a local clone with independent Git files (`--no-hardlinks`), then
  checked out at the exact commit on this copy's `main`.
- Original uncommitted edits and untracked files were not copied, moved,
  overwritten, committed, or reset. The original checkout remains the authority
  for those changes. All committed Go source remains here as reference.
- No `.agents/skills` directory exists in this committed snapshot or the
  original checkout at inspection time. Project `AGENTS.md` and triggered
  `docs/agents` guides were read.

The Owner's Rust decision replaces the language choice in ADR-0001 for this
rewrite. It does not waive the product, recovery, qualification, or publication
contracts. No in-place Go-to-Rust migration is introduced. Existing installations
must retain their exact-release removal/recovery route.

## Implemented behavior

The Standard setup path runs end to end through the numbered menu: choose
Standard by pressing Enter, inspect the plan, go Back, cancel, or explicitly
approve with exact `y`. Empty input, `n`, `c`, EOF and an unterminated `y` do not
approve. Help and bounded 256-byte line handling retain the current wizard's
behavior. Unsupported Cloudflare choices are not offered.

Proxy Installation Review is read-only. Prepared Action is opaque, bound to one
installation and its reviewed facts/revision, non-cloneable and consumed by
Execute. Rust ownership prevents reuse; a compile-fail test checks that boundary.
Execute revalidates the reviewed facts and action before any simulated effect.
Exact machine result codes for implemented outcomes match the Go source.

The simulator checks explicit fixture facts for root authority, Ubuntu 24.04,
amd64, absent/known footprint, idle mutation state, port 443 and destination
compatibility. These are **not inspections of the current machine**. Its phases
model setup only: Absent, Preparing, Activation committed, Running. Interrupted
precommit preparation permits Finish cleanup only; committed activation permits
Finish setup only. The journal is in memory and disappears when the process exits.
Status and result output always identify simulation. Traffic remains
`cannot be verified`; no simulated success claims local runtime, outside-client
or Karing verification.

## Module boundaries

| Path | Responsibility |
|---|---|
| `src/main.rs` | Zero-argument dispatch, process exit and terminal error reporting |
| `src/domain.rs` | Setup Action, Status, Confirmation, Availability, Phase and exact outcome codes |
| `src/configuration.rs` | Fixed Standard host contract copied from Go: paths, port, sing-box 1.14.3 identity and REALITY destination |
| `src/proxyinstallation.rs` | Read-only Review, opaque Prepared Action, fresh Execute admission and setup/recovery direction |
| `src/proxyinstallation/simulation.rs` | Explicit in-memory fixture facts, phases and interruption injection; no operating-system adapter |
| `src/terminal.rs` | Numbered menu, Standard setup wizard, bounded input and result presentation |
| `src/records.rs`, `src/records/` | Strict validated Standard schema-1 and Installed Record codecs, canonical wire bytes and legal setup checkpoints |
| `src/durable.rs` | Protected fixed-name record publication, directory locking, exact source/target comparison, fsync and recovery inspection |
| `src/*_tests.rs` | Adjacent domain/orchestration and terminal boundary tests |
| `tests/menu.rs` | Real Rust executable subprocess tests |

The first slice used only Rust's standard library. The durable foundation adds
pinned Serde/serde_json for strict typed records, SHA-256 for the existing digest
contract, and rustix for safe descriptor-relative Unix filesystem operations.
No Go subprocess bridge, protocol plugin mechanism or migration framework is
part of the Rust product.
The Cargo manifest disables publication. Rust 1.90.0 is pinned for reproducible
local development; it is not a release-toolchain qualification claim.

Independent parity checks now live in `tests/parity.rs` and
`tests/testdata/parity/`. Preserve their assertions and fixtures. They exposed
and now guard expiration of earlier Prepared Actions after every later Review,
including Status and View details. Configuration/secret encoding,
Subscription Serving, Software Lifecycle and a real Ubuntu Host Adapter are
unimplemented scopes that can be assigned separately after their contracts are
read. The integration owner should coordinate new `src/lib.rs` exports.

## Local commands and evidence

An isolated Rust toolchain was installed under `.scratch/toolchain/`, following
[rustup's documented custom install locations](https://rust-lang.github.io/rustup/installation/index.html#choosing-where-to-install).
No shell profile or global toolchain was changed. With a normal Rust 1.90.0
installation, use `cargo` directly. For this workspace-local installation:

```sh
export CARGO_HOME="$PWD/.scratch/toolchain/cargo"
export RUSTUP_HOME="$PWD/.scratch/toolchain/rustup"
export CARGO_TARGET_DIR="$PWD/.scratch/acceptance/rust-r1/target"
export PATH="$CARGO_HOME/bin:$PATH"
run="$PWD/.scratch/acceptance/rust-r1"
mkdir -p "$run"
export TMPDIR="$run/t"
mkdir "$TMPDIR" # Refuse to reuse temporary fixtures.
cargo fmt --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
cargo build --locked --offline
rmdir "$TMPDIR"
```

Run `cargo run --locked --offline` with no arguments for the local demonstration.
No `sudo` or live resource is needed. The current binary is always the simulator;
there is no hidden flag or environment switch to install on a host.

Initial missing-implementation failures, focused tests, final test/lint/build
results and a subprocess transcript are retained under
`.scratch/acceptance/rust-bootstrap/`. These are macOS arm64 local observations,
not native Ubuntu, packaged deployment, release qualification or Karing evidence.

## Parity gaps that remain required

- Real root-only Ubuntu admission, whole-host/package locks, fresh observations,
  timeouts/cancellation, ownership publication/fsync and protected file handling.
- Full schema-2/subscription/tunnel/removal records and production integration of
  the new Standard schema-1 filesystem foundation. Physical crash/power-loss and
  native Linux durability qualification remain untested.
- Real sing-box config validation, cryptographic key/Client Identity generation,
  confirmed client disclosure, identity revocation and sequential cutover.
- HTTP Subscription Serving and independent link rotation; optional VMess with
  dedicated Owner-installed cloudflared and honest pending/verified checks.
- Complete removal and interrupted removal preserving foreign/shared resources;
  Software Lifecycle Check/Recover and exact historical transaction readers.
- Other statuses/actions, full details and display-incomplete behavior for secret
  disclosures. Only setup outcomes are currently implemented in Rust.
- Native Linux amd64/arm64 build and packaging proof, bootstrap installer,
  signature/attestation verification and Rust-aware executable provenance.
  The existing verifier's Go metadata/`.gopclntab` requirement needs an explicit
  Rust proof while retaining historical Go compatibility; do not weaken it.
- All five current live acceptance journeys and publication approval. No live
  VPS, Karing, credentials, security setting, signing or publication action was
  attempted for this increment.

The reference docs' dated stable-release claim was not refreshed here. The parent
reports verified stable `v3.1.118` / `192`, with `v3.1.119` and `v3.1.120` failed
prereleases; this increment does not independently verify or use those releases.


## Durable foundation increment

`records::OwnershipRecord` supports the exact Standard setup schema-1 subset:
required fields, ordered permitted resources, the optional exact lock-provisioning
authority and all fourteen setup phases. Legacy schema-1 without that optional
authority remains readable and is not converted on read. Unknown/duplicate keys,
escaped duplicate keys, nulls, wrong types, nested arrays where objects are
required, trailing documents, invalid digest/identity/resource facts and
contradictory phase/direction/checkpoints refuse. Schema 2, tunnel and removal
records refuse; they are not silently reduced to schema 1.

`OwnershipRecord::decode(&[u8])` returns a validated record. `encode()` returns
Go's field order and trailing newline. Its full Standard output is checked
against `src/records/testdata/standard-schema1-go.json`, generated offline by the
preserved Go encoder using Go 1.26.6 and a temporary test overlay. Every byte of
committed Go source remains unchanged. `InstalledRecord::decode/encode` retain
schema-1 fields, immutable stable tag syntax, positive sequence, supported
architecture and the 4 KiB bound. That codec **does not authenticate** an
executable, release, signature or attestation.

Public record types have private validated data and no public Serde implementation
that could bypass validation. Ownership Record Debug and all errors omit raw
input. Only fixed secret-free fields can be encoded; no UUID, private key,
bearer credential or client artifact is represented.

`durable::OwnershipStore::open(path, owner_uid)` opens an existing absolute
0700 fixture directory. It walks each path component with no-follow descriptors,
requires trusted owners and non-writable ancestors, pins the directory inode,
and takes a nonblocking exclusive advisory lock on that directory descriptor.
It creates no directory or lock file. This is a **record-store lock**, not the
production Whole-Host Mutation Lock or a substitute for package/host exclusion.
A future Ubuntu adapter must use root authority and the real whole-host lock.

The store reads/writes only `proxy-ownership.json` and
`.proxy-ownership.json.next`. Files must be regular, one-link, expected-owner,
0600, bounded and bound to the checked inode. `load()` preserves original bytes
and never rewrites or promotes staged data. Writes require canonical exact
source bytes and either the identical record or one legal setup/cleanup
checkpoint; they cannot change installation identity, configuration digest,
resource authority or reverse a committed direction.

`publish(expected_bytes, &next)` exclusively creates or verifies the exact staged
target, writes/fsyncs it, rechecks the source and stage, renames, then fsyncs the
directory. Initial publication uses an atomic no-replace rename. An existing
incompatible or partial stage is preserved and refused. A failure before rename
reports `Publication::Unchanged`; a rename or later failure reports
`Publication::Uncertain`. Callers must reinspect; `synchronize(expected_bytes)`
reestablishes file and directory durability before relying on an observed target.
No error causes rollback, replacement of unknown residue or recursive cleanup.

`Snapshot::recovery()` reports Absent, Cleanup, FinishSetup, Running (record phase
only) or Refused. Staged-only initial authority and a staged activation boundary
refuse automatic recovery. A committed authoritative record never selects
cleanup. Known precommit staging can be replayed only by an explicit exact
publication retry. These APIs do not authorize resource effects, confirm Owner
intent or prove runtime health; future orchestration must supply those checks.

`next_setup_checkpoint()` advances exactly one setup phase;
`next_cleanup_checkpoint()` advances one of eight cleanup checkpoints only before
activation. The store intentionally has no delete API: authority removal still
needs a real host proof that cleanup completed. No setup operation or new
credential generation is connected to this filesystem adapter yet.

Offline tests reopen real fixture files after injected empty/partial writes,
stage fsync, pre/post rename, and pre/post directory fsync interruptions. They
also cover lock contention, stale bytes, skipped checkpoints, conflicting stage,
changed directory inode, unsafe ownership/mode, symlinks/hardlinks and preserving
foreign entries. Test-only fault injection is not a CLI flag or runtime switch.
Logs and the initial three stale-review parity failures are under
`.scratch/acceptance/rust-durable/`; local tests are separate from deployment
qualification and do not simulate an actual power failure.
