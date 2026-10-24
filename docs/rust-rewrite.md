# Rust rewrite: local implementation increments

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
| `src/proxyinstallation.rs` | Two-operation Interface, shared Review/Prepared Action types, explicit mode and simulation admission |
| `src/proxyinstallation/fixture.rs` | Durable Standard setup, activation, forward completion and eight-step cleanup through the fixture adapter |
| `src/proxyinstallation/simulation.rs` | Explicit in-memory fixture facts, phases and interruption injection; no operating-system adapter |
| `src/terminal.rs` | Numbered menu and wizard through Review/Execute; explicit simulation/fixture labels |
| `src/host.rs`, `src/host/` | Fixed command templates, marked fixture roots, read-only file evidence and bound filesystem effects; no process runner |
| `src/subscription_artifact.rs` | Pure VLESS/VMess client encoding, HTTP link/token syntax and redacted secret-bearing types |
| `src/records.rs`, `src/records/` | Strict schema-1/schema-2 historical authority, Installed Record codecs, exact ownership proofs and current HTTP/setup transitions |
| `src/server_configuration.rs` | Pure supplied-identity sing-box configuration, pinned package metadata and exact dedicated tunnel unit |
| `src/subscription_serving.rs` | Bounded HTTP runtime, constant-time credential verification, per-peer limits and complete cancellation |
| `src/durable.rs` | Protected fixed-name record publication, directory locking, exact source/target comparison, fsync and recovery inspection |
| `src/*_tests.rs` | Adjacent domain/orchestration and terminal boundary tests |
| `tests/menu.rs` | Real Rust executable subprocess tests |

The first slice used only Rust's standard library. The durable foundation adds
pinned Serde/serde_json for strict typed records, SHA-256 for the existing digest
contract, and rustix for safe descriptor-relative Unix filesystem operations.
Pinned httparse supplies the bounded HTTP syntax parser; subtle supplies the
constant-time digest comparison. Cargo.lock preserves exact registry checksums.
No Go subprocess bridge, protocol plugin mechanism or migration framework is
part of the Rust product.
The Cargo manifest disables publication. Rust 1.90.0 is pinned for reproducible
local development; it is not a release-toolchain qualification claim.

Independent parity checks now live in `tests/parity.rs` and
`tests/testdata/parity/`. Preserve their assertions and fixtures. They exposed
and now guard expiration of earlier Prepared Actions after every later Review,
including Status and View details. Pure server configuration and HTTP Subscription Serving are now implemented
through public library APIs. Cryptographic generation, product orchestration,
Software Lifecycle and a real Ubuntu Host Adapter remain separate integration
scopes; the CLI still constructs only the Standard simulator.

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
- Production integration of the strict records and Standard filesystem foundation.
  Historical schema-2, tunnel, HTTPS and removal records decode without migration;
  only current HTTP and setup transitions have writers. Physical crash/power-loss
  and native Linux durability qualification remain untested.
- Real sing-box config validation, cryptographic key/Client Identity generation,
  confirmed client disclosure, identity revocation and sequential cutover.
- Product-level HTTP serving/rotation orchestration and protected service/firewall
  installation; optional VMess/cloudflared prerequisite inspection and integration.
  Pure rendering, bounded HTTP runtime and durable HTTP transitions are available.
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

`records::OwnershipRecord` supports Standard setup schema-1 and the current and
historical schema-2 authority structures: exact required fields, ordered permitted
resources, creating/finishing releases, lock/tunnel, HTTP/HTTPS subscription,
certificate/identity operations, retained HTTPS and removal authority. It retains
all fourteen setup phases and the removal phase. Legacy schema-1 without that optional
authority remains readable and is not converted on read. Unknown/duplicate keys,
escaped duplicate keys, nulls, wrong types, nested arrays where objects are
required, trailing documents, invalid digest/identity/resource facts and
contradictory phase/direction/checkpoints refuse. Historical decoding preserves
authority; it never silently reduces records or enables in-place migration.
Canonical null completed-effect slices for Go link rotation/repair remain valid;
object authorities cannot be null or positional arrays.

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
input. Only fixed secret-free fields can be encoded; no Client Access UUID, private key,
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
source bytes and either the identical record, one legal setup/cleanup checkpoint,
or a supported current HTTP transition; they cannot change installation identity, configuration digest,
resource authority or reverse a committed direction.

`publish(expected_bytes, &next)` exclusively creates or verifies the exact staged
target, writes/fsyncs it, rechecks the source and stage, renames, then fsyncs the
directory. Initial publication uses an atomic no-replace rename. An existing
incompatible or partial stage is preserved and refused. A failure before rename
reports `Publication::Unchanged`; a rename or later failure reports
`Publication::Uncertain`. Callers must reinspect; `synchronize(expected_bytes)`
reestablishes file and directory durability before relying on an observed target.
No error causes rollback, replacement of unknown residue or recursive cleanup.

`Snapshot::recovery()` distinguishes Absent, setup Cleanup/FinishSetup, Running
(record phase only), subscription cleanup/forward, identity cleanup/forward,
historical certificate/migration, Removal and Refused. Staged-only initial
authority, operation admission and commit barriers refuse automatic recovery. A committed authoritative record never selects
cleanup. Known precommit staging can be replayed only by an explicit exact
publication retry. These APIs do not authorize resource effects, confirm Owner
intent or prove runtime health; future orchestration must supply those checks.

`next_setup_checkpoint()` advances exactly one setup phase;
`next_cleanup_checkpoint()` advances one of eight cleanup checkpoints only before
activation. The store now has a crate-private completed-cleanup removal primitive. It refuses
any authority before cleanup checkpoint eight or with incompatible staging. The
fixture journey calls it only after a fresh exact empty-footprint observation;
production removal still needs real host exclusion/proof. New credential
generation and real setup operations remain unavailable.

Offline tests reopen real fixture files after injected empty/partial writes,
stage fsync, pre/post rename, and pre/post directory fsync interruptions. They
also cover lock contention, stale bytes, skipped checkpoints, conflicting stage,
changed directory inode, unsafe ownership/mode, symlinks/hardlinks and preserving
foreign entries. Test-only fault injection is not a CLI flag or runtime switch.
Logs and the initial three stale-review parity failures are under
`.scratch/acceptance/rust-durable/`; local tests are separate from deployment
qualification and do not simulate an actual power failure.


## Fixture host and integrated codec increment

`host::FixtureHost::create(root, release)` requires an existing empty 0700
non-symlink temporary directory. It writes an explicit fixture marker and a
synthetic installed-software pair beneath that root. The bytes are visibly fake:
the executable is inert text, the signing key/package are fixture sentinels and
the configuration is `{"sbxr_fixture_only":true}`. They are not Ubuntu, upstream
package, cryptographic identity or release-verification proofs. `open(root)`
requires that exact marker. There is no fallback from a real host to this adapter.

All fixture paths are relative to a pinned root descriptor. Each parent is
opened without following symlinks and checked for safe ownership/permissions.
Reads verify file type, owner, mode, one-link metadata, inode identity, bounded
bytes and exact expected contents. Writes exclusively create missing targets or
accept identical owned targets; removals verify exact bound contents and never
recursively erase a directory. Known shared fixture parent directories are kept.
An unknown child can block cleanup while remaining untouched. Installed software
and unrelated entries are preserved by proxy cleanup.

`FixtureHost::inspect(&release)` is read-only. Its immutable observations include
file identity and digests, and refuse unknown or contradictory fixture facts.
Package, account, service, validation and listener-like effects use explicitly
named `.fixture-state/` sentinels. The mapped APT/configuration/unit paths model
file ownership below the root. No systemd, APT, firewall, account, download or
network operation executes. The adapter checks caller-owned fixture metadata;
it does not claim the production root:sing-box ownership model is qualified.

`planned_commands(Operation)` and `planned_observation_commands()` expose fixed
argv templates copied from Go, including the pinned package download directory
and packaged configuration check. They are **not an executable command plan**:
conditional/dynamic UID/GID, process/package exclusion, repository/download trust,
deadlines and real host observations still need porting before a live runner can
exist. `require_live_adapter()` explicitly refuses real deployment. No process
runner or live adapter is implemented.

`proxyinstallation::FixtureInstallation::new(host, release)` connects the
fixture adapter to the strict records and protected Ownership Store. It shares
the exact `Interface::review/execute` boundary and opaque non-cloneable Prepared
Action with the simulation. Prepared authority is bound to the concrete adapter,
instance, reviewed source/staged bytes and file evidence. Every later Review
expires it. Wrong release, unsupported authority, changed facts and unknown
resources grant no mutation; View details remains read-only and available.

The journey follows the Go order: nine pre-activation effects with durable
checkpoints, fresh stopped/owned checks before Activation committed, then service
enablement/start and a fresh fixture Running check. Precommit effect failure
enters the eight-step cleanup sequence. Committed activation permits only forward
completion. Cleanup resumes its recorded checkpoint, proves the entire fixture
proxy footprint absent, then removes only the completed record. A visible target
after uncertain publication is accepted only after an exact reread and successful
file/directory synchronization. Unknown staging is retained and refused.

The numbered terminal now consumes that same two-operation Interface. Its banner,
status suffixes and completion messages explicitly distinguish in-memory
simulation from filesystem fixtures. Tests run the ordinary Standard wizard
against the durable fixture journey, close/reopen the model after interruptions,
resume cleanup and forward completion, and preserve foreign files. The installed
executable still constructs only the simulation; there is no fixture CLI flag,
hidden environment switch, real installer or deployment path.

The completed subscription worker's `subscription_artifact` module is exported
through `lib.rs`. It adds no dependency and runs no network/host operation.
`ConnectionFacts` validates supplied Client Access Values and encodes the exact
VLESS node plus optional VMess v2 node, and official outside-client JSON.
`SubscriptionCredential` validates canonical supplied tokens and hashes their
encoded text. `HttpSubscriptionLink` validates only the fixed HTTP link shape
and retains the HTTP exposure warning. It does not generate or install a
credential, serve requests, rotate access or approve disclosure.

All secret-bearing codec fields are private. Debug/Display are redacted and no
public Serde implementation serializes them; explicit byte/string accessors
remain subject to future product disclosure/serving authority. The independent
fixtures contain only fixed synthetic values: 76 Go-generated acceptance/output
cases and six golden files preserve exact order, escaping, padding, node types
and newlines. Tests also check the 4 KiB subscription bound, canonical tokens,
HTTP rejection cases and ordinary diagnostic redaction. See
`tests/testdata/subscription_artifact/README.md` for the API and provenance.

Current local evidence is retained under `.scratch/acceptance/rust-host/`, with a
task-specific Cargo target directory. These are macOS filesystem/codec tests,
not Ubuntu/systemd/package verification, traffic, Karing, native Linux durability,
physical power-loss or packaged deployment qualification. No original Go checkout
or live resource is changed by this increment.


## Schema-2 authority and real HTTP/configuration increment

Current HTTP writers are small pure transitions on validated `OwnershipRecord`:
`begin/advance/commit/cleanup_http_enablement`,
`begin/advance/complete/cleanup_http_link_rotation`,
`begin/advance/complete/cleanup_http_runtime_repair`, and
`mark_subscription_compromised`. They serialize only supplied credential hashes.
Enablement follows Go checkpoints 0,1,2,3,8..15,22,23; every unfinished checkpoint
still requires cleanup until explicit final commitment. Link rotation keeps source
selection before commitment and target selection afterward. Compromise remains
sticky through cleanup and clears only with completed rotation. Runtime repair
commits forward before recording/restarting its unchanged generation; only accepted
completion removes its marker. Callers must prove each real effect before advancing.

Every transition preserves configuration, installation identity, exact resource
ordering and the creating release for each retained resource. `permits_successor`
compares only exact supported targets. It rejects skipped/reversed checkpoints,
creator rewrites and late tunnel attachment. `new_tunnel_setup` binds a dedicated
owner-provided tunnel before initial setup only. These pure APIs do not validate
prerequisite files, generate credentials, confirm Owner intent or authorize effects.

Historical HTTPS enablement/renewal/rotation/repair, certificate activation,
Client Identity cutover/revocation, transport retirement/migration and removal
records remain readable. Unsupported writers are unavailable. In particular no
migration flag can be cleared through current HTTP APIs, and a recorded source
revocation cannot be reversed. The Standard fixture journey explicitly refuses
schema-2 and tunnel records until matching host effects/orchestration exist.

Real protected-file publication tests reopen each HTTP checkpoint and inject
pre/post rename and synchronization failures around enablement/rotation/repair
commit boundaries. Staging cannot admit an operation or grant forward effects.
Uncertain publication requires rereading and synchronizing the selected target;
a committed rotation never returns to its source. This remains macOS fixture
filesystem evidence, not physical crash or native Linux durability qualification.

The adjacent record fixtures contain 67 valid Go-generated canonical records and
144 adversarial mutations independently rejected by Go and Rust. They cover
nested unknown/duplicate/escaped keys, missing/positional/null authority, resource
and creator tampering, contradictory targets/completed effects, revocation
barriers and retirement/removal bounds. See
`src/records/testdata/authority/README.md` for regeneration and provenance.

`server_configuration` renders actual sing-box Standard/optional VMess bytes,
UUID-only replacements, pinned package metadata and the dedicated tunnel unit.
Its 64 Go vectors and six goldens check byte parity, including JSON escaping and
redacted diagnostics. No random generation, X25519 public derivation, arbitrary
existing-config decoding or execution of sing-box/systemd is included.

`subscription_serving` serves real authenticated artifacts through a supplied
IPv4-matching TCP listener. It has eight workers, an 8192-byte header bound,
five-second absolute connection deadlines, bounded peer rate accounting and
joined cancellation. It uses constant-time SHA-256 digest comparison over canonical
encoded tokens. All refusals conceal raw input; secrets appear only in explicit
artifact accessors and authenticated responses. Runtime inspection distinguishes
prepared state from a running service. The eventual production role must bind
protected records/profile/process identity to the fixed recorded IPv4 and TCP8443.
No private role/CLI, host service/firewall integration or legacy TLS runtime exists.

The serving corpus has 65 Go request expectations: 63 match; Rust deliberately
refuses two malformed forms accepted by Go (a spaced field name and obsolete
folding). Review accepted the stricter parser boundary because these forms are
outside the ordinary client contract and introduce parsing ambiguity. RFC9112
[section 5](https://www.rfc-editor.org/rfc/rfc9112.html#section-5) defines field
syntax and deprecates folding. SBXR retains its concealed 404 for these refusals;
this does not claim the RFC's specified 400 response behavior. Tests and fixture
metadata preserve both Go and Rust statuses explicitly.

The integrated runtime tests use only synthetic credentials and loopback ephemeral
ports, including valid VLESS/VMess responses, header limits, slow input, overload,
actual-peer limits, cancellation and secret-free subprocess output. Two pinned
registry dependencies (`httparse` 1.10.1, `subtle` 2.6.1) were resolved offline from
the local Cargo cache. Evidence is under `.scratch/acceptance/rust-authority/`;
worker provenance remains under `rust-server/` and `rust-serving/`. No production
system, VPS, Karing, release signing or publication was exercised.
