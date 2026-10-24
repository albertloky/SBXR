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
| `src/proxyinstallation/fixture.rs` | Shared `StandardInstallation<H>` setup/recovery; the original `FixtureInstallation` alias retains its explicit adapter |
| `src/proxyinstallation/simulation.rs` | Explicit in-memory fixture facts, phases and interruption injection; no operating-system adapter |
| `src/terminal.rs` | Numbered menu and wizard through Review/Execute; explicit simulation/fixture labels |
| `src/host.rs`, `src/host/` | `SetupHost` contract, protected descriptor-relative files, original fixtures and Linux observation/injected effects |
| `src/host/process.rs` | Fixed queries, bounded subprocess output, cancellation, deadlines and owned process-group cleanup |
| `src/host/linux.rs`, `src/host/linux/` | Fail-closed native observers, pinned material, Standard file effects and injected-root integration |
| `src/host/locks.rs` | Retained whole-host flock and POSIX package guards, including descriptor-safe verification |
| `src/host/network.rs` | Direct verified TLS 1.3 public-IP/destination checks and exact IPv4 TCP443 bind admission |
| `src/host/system.rs` | Fixed managed command adapter with retained lock, pinned DEB and exclusive identity checks |
| `src/artifact_trust.rs` | Real offline Sigstore verification against pinned roots/policies, exact authenticated claims and bounded acquisition interface |
| `tooling/rust-package/` | Separate offline deterministic package/index CLI using the product release inspector |
| `src/identity_generation.rs` | Ephemeral X25519/UUID/credential generation, injected entropy and Go-compatible validation |
| `src/release_acquisition.rs`, `src/release_acquisition/` | Exact-tag metadata/Acceptance Record/signature/index/archive/current-byte binding; injected network boundary |
| `src/release_https.rs` | Bounded certificate-verified public HTTPS, manual authorized redirects, asynchronous DNS and whole-request interruption |
| `src/runtime_handoff.rs` | One-use authenticated descriptor lending, retained runtime starts, HTTP serving/watch composition and proxy cutover model |
| `src/release_archive.rs` | Bounded in-memory single gzip/ustar member inspection, with no extraction or execution |
| `src/private_roles.rs`, `src/host/runtime.rs` | Fixed silent private dispatch and protected injected lock/start checks; native dispatcher refuses |
| `src/removal.rs`, `src/host/linux/removal.rs`, `src/proxyinstallation/removal.rs` | Forward removal model, concrete Standard host/finalizer and shared Interface bridge |
| `src/release_identity.rs` | Strict index/trailer bindings and explicit Rust/historical Go ELF inspection; no external authentication |
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
through public library APIs. Cryptographic generation and structural release inspection are now integrated.
Fixed Ubuntu system effects and offline signature verification are integrated library
modules. Production acquisition/orchestration and Software Lifecycle remain separate
integration scopes; the CLI still constructs only the Standard simulator.

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

- A complete authenticated native entry: actual bounded HTTP acquisition,
  current-executable/release/index/archive authority, native prerequisites and
  qualification bindings. Fixed system effects, UID/GID publication, retained
  locks and direct network/bind admission now exist, tested through temporary
  roots, fake command transports and nonprivileged loopback. Native execution
  remains explicitly unavailable until these complete inputs are connected.
- Production integration of the strict records and Standard filesystem foundation.
  Historical schema-2, tunnel, HTTPS and removal records decode without migration;
  only current HTTP and setup transitions have writers. Physical crash/power-loss
  and native Linux durability qualification remain untested.
- Packaged sing-box validation and product integration of the ephemeral identity
  generators, confirmed client disclosure, revocation and sequential cutover.
- Product-level HTTP serving/rotation orchestration and protected service/firewall
  installation; optional VMess/cloudflared prerequisite inspection and integration.
  Pure rendering, bounded HTTP runtime and durable HTTP transitions are available.
- Complete removal and interrupted removal preserving foreign/shared resources;
  Software Lifecycle Check/Recover and exact historical transaction readers.
- Other statuses/actions, full details and display-incomplete behavior for secret
  disclosures. Only setup outcomes are currently implemented in Rust.
- Native Linux amd64/arm64 musl builds, retained Rust build-section embedding,
  bootstrap/workflow integration and authenticated extraction. Explicit Rust ELF
  and historical Go proofs, real offline attestation verification and local package
  tooling exist. They do not establish a clean-source build, complete positive
  SBXR release authentication or deployment qualification.
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

`planned_commands(Operation)` and `planned_observation_commands()` retain fixed
argv templates copied from Go, including the pinned package download directory
and packaged configuration check. They are **not an executable command plan**:
conditional/dynamic UID/GID, process/package exclusion, repository/download trust,
deadlines and real host observations still need porting before a live runner can
exist. `require_live_adapter()` explicitly refuses real deployment. A separate bounded fixed-argv read-only native runner now exists; no native
mutation runner or live adapter is implemented.

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

The numbered terminal consumes that same two-operation Interface. Its banner,
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


## Linux observation and injected Standard orchestration increment

`host::linux::NativeObserver::open()` refuses every platform except root Linux
Ubuntu 24.04 amd64, before running a probe. Native observation uses a protected
root descriptor, no-follow parents, root-owned non-writable executable paths and
fixed read-only queries for package/hold/account/process/systemd/listener/clock
facts. `/etc/os-release` permits only the fixed Ubuntu `../usr/lib/os-release`
symlink to a protected regular file. Unexpected statuses/exit codes, incomplete
observations, changed executable evidence and contradictory facts refuse.

`NativeObserver::{read_ownership,read_installed,read_configuration}` provide actual
bounded filesystem observations. Ownership remains strict validated authority;
configuration requires root ownership, 0640, the freshly observed package GID and
its exact expected digest. Installed pairs require protected files plus matching
record/trailer identity, sequence and whole-executable digest, and explicit Linux
ELF/build proof from `release_identity`. These are structural coherence checks,
not signer/index/attestation authentication. `production_admitted` remains false.
The next increment supplies network/bind and retained locks without enabling the
native frontend.

`host::process` exposes fixed typed `Query` values, not shell strings. Native
commands have five-second deadlines, a combined 1 MiB output cap, null stdin,
cleared environment, fixed PATH/locale and `/` working directory. Output reads
are nonblocking and check cancellation/deadline on every iteration. Child processes
run in a dedicated process group; wait-without-reaping retains the owned leader
until group termination and reaping, including descendant-held pipes and errors.
Raw stdout/stderr are never formatted by errors or Debug. This read-only runner
still refuses configuration validation and mutation. The system adapter described
below adds separate managed-command budgets; injected runners retain an explicit
cooperative-cancellation contract.

`StandardInstallation<H: SetupHost>` reuses the existing Review/Execute state
machine and opaque Prepared Action for both the original fixture and a Linux
adapter with injected effects. Every later Review expires authority, Execute
rechecks exact record/stage bytes and file/command fingerprints, and each durable
checkpoint still selects cleanup before Activation committed and only forward
completion afterward. An already enabled, quiescent service can be retried after
an interrupted enable checkpoint; active/foreign processes do not pass the
pre-activation stopped check. Traffic remains `cannot be verified`.

`LinuxHost::injected` requires an explicit protected 0700 root different from `/`
and a runner declaring injected effects. NativeReadOnly cannot become that
capability. `InjectedAdmission` values are test inputs, never real privilege,
network or lock proofs. This adapter publishes production-format APT/config/unit
files below that root and verifies fresh package/service/account facts through
the supplied runner. Native root writes are separately refused by protected
filesystem primitives. Current injected UID/GID mappings are caller-owned test
files. The next increment adds native chown, package/account exclusivity and fixed
systemd command implementations. There is no native-to-fixture fallback.

`SetupMaterial::verified` requires the pinned upstream signing-key digest and
DEB size/digest, a bounded fixed Standard configuration, and no implicit download.
Tests use private cfg(test) construction with visibly synthetic key/package bytes;
this never weakens the public pinned constructor or qualifies upstream trust.
The installed test executable uses inert Go-verified ELF bytes with a synthetic
trailer/record; it is never executed.

The executable retains its explicitly labeled simulator. Injected-host menus have
a separate banner and qualifier. `require_live_adapter()` distinguishes unsupported
native hosts from unavailable production effects and never returns a simulator.
No new public flag, hidden environment switch or native installation path exists.

Adjacent host tests run real protected files and controlled child processes with
fake package/systemd/account commands. They cover every reopened setup checkpoint,
pre/post-effect failure, forward enable/start retry, partial cleanup, stale Review,
foreign children, unsafe parents, hardlinks, changed roots, configuration/pair
bindings, output limits, cancellation and descendant pipe deadlines. A failure
injection exposed and corrected the overly strict enable retry without weakening
its assertion. Native mutation capability and parent no-follow guard mutation
checks demonstrate regression detection. Logs are under
`.scratch/acceptance/rust-linux/`.

The official Linux amd64 GNU standard-library target was installed only in the
workspace-local Rust 1.90 toolchain. `cargo check --target x86_64-unknown-linux-gnu`
is a cross-compilation/type check, not linking, a musl build, running Ubuntu,
embedding release metadata, package validation, service isolation, physical crash,
VPS/Karing or deployment qualification.

`identity_generation` integrates pinned dalek X25519, getrandom, base64 and zeroize
with no handwritten cryptography. Its ten tests retain five Go/RFC derivation
vectors, 29 Go validation cases, independent entropy allocation, fail-closed
partial entropy, redaction and ephemeral OS randomness. Its adapters feed the
existing server/client codecs; no generated credential is installed or disclosed
by a product action. Explicit accessors remain subject to future Owner authority.

`release_identity` integrates sixteen offline tests for strict raw-byte index and
trailer bindings, installed-pair coherence, explicit pinned Rust metadata/static
ELF and historical Go build proof. It introduces no dependency and removes no Go
proof requirement. The next increment adds external attestation verification and
local packaging; authenticated archive extraction, native Rust build proof and
existing Go-only workflow integration remain gaps. Structural inspection alone
never authorizes a trusted release, deployment or publication. See each fixture
subtree README.


## Retained host guards, system effects and authenticated evidence increment

`HostLock::acquire` retains the exact `run/lock/sbxr.lock` inode with an exclusive
flock. Review and declining approval create no coordination file. Approved Execute
acquires the guard, then rechecks record/stage bytes and observed fingerprints
before publishing or changing anything. Trusted descriptor-relative parents,
root/lock identity, owner, mode and one-link checks refuse unsafe replacements.
The root-owned sticky coordination parent is admitted only for this fixed lock.
The lock file stays after release, matching volatile coordination semantics.

`HostLock::acquire_packages` retains nonblocking POSIX locks on existing fixed
APT/dpkg lock inodes. Verification uses metadata without reopening or closing a
package inode, because closing another descriptor could release a process's POSIX
locks. A guard lease prevents duplicate acquisition through the same host guard.
Package guards are released before APT/dpkg commands acquire their own locks;
whole-host exclusion remains retained. Child-process tests prove package locks
stay busy across verification and become available after release.

`SystemRunner<T: Transport>` implements fixed systemd/APT/dpkg/account commands;
its narrow `CommandSpec` exposes read-only inspection, with private construction.
`NativeTransport` checks supported native environment and retained change lock,
protected executable bytes before/after execution, fixed argv/cwd, cleared
environment and bounded output/process-group cleanup. Managed commands and
sing-box validation receive Go's separate five-minute completion budget;
ordinary observations retain five seconds and the combined 1 MiB output cap.
A started managed command can complete after UI cancellation, under that bound.

Installation accepts only a supplied size/digest-pinned DEB; it does not download
one implicitly. Configuration publication uses the observed package GID, and the
state directory uses the observed UID/GID through descriptor chown. Unit reloads
follow durable unit/link effects. Cleanup validates the pinned package and exact
resources, refuses foreign UID/GID files or processes, compares the complete group
record after user deletion, and supports retry after partial user deletion or dpkg
states. Existing configuration/state and configuration staging require the current
package-account proof; missing accounts do not authorize a directory by its own
metadata. Two new refusal cases failed before these corrections and pass afterward. No recursive product deletion is introduced. The durable checkpoint
still selects cleanup before activation and forward-only completion afterward.

`NetworkAdmission::native` directly resolves fixed endpoints, reads the protected
Ubuntu CA bundle and uses rustls with an explicit provider and certificate/name
verification. Public IPv4 discovery is TLS 1.3 HTTPS to `api.ipify.org`, bounded to
64 body bytes and ten seconds. The destination is `google.com:443`, requiring
TLS 1.3 and h2, with a separate ten-second deadline. Pre-activation admission also
proves the exact IPv4 TCP443 bind and immediately closes it. Reads have absolute
deadlines and cooperative cancellation; a blocking TCP connect is bounded by its
remaining deadline. Ambient proxy settings are not used. The IP HTTP parser
refuses redirects, ambiguous framing and malformed lengths; these are stricter
failure cases than Go's default HTTP redirect behavior. Loopback tests use a
public fixed test key and isolated test CA, with no OS trust-store change.

The actual Standard state machine now drives this system adapter through a fake
command transport and real protected temporary files, including setup, partial
cleanup, foreign identity preservation and competing-host exclusion. Native
constructors refuse this Mac before commands or external network requests.
`LinuxHost::native_unreleased` has a distinct `NativeUnavailable` mode and cannot
grant a Prepared Action. Its effects capability remains false pending the complete
authenticated entry chain. The zero-argument frontend still selects the simulator.
These local tests do not run APT, systemd, chown to a foreign identity, or privileged
port binding on the host, and do not establish Ubuntu operation or live acceptance.

`artifact_trust` now authenticates real DSSE bundles with pinned
`sigstore-verify` 0.15.1 and its AWS-LC backend. Native GitHub release proofs require
verified RFC3161 timestamps and the exact release-service identity under the
preserved root; candidate proofs require the exact workflow/OIDC issuer, Rekor and
authenticated observer time. No current-time fallback or ambient roots are used.
Private result constructors separate authenticated payload/claims from structural
inspection. Signed SHA256 asset subjects and the SHA1 commit are checked in the
same authenticated native payload. Snappy decompression and injected acquisition
are bounded by size, deadlines and cancellation. The later HTTPS increment below
adds the actual bounded transport.

Twenty-four trust tests include two preserved genuine bundles, signature/payload/
timestamp/log tampering and forged claim rejection. The foreign repository's
genuine native proof authenticates cryptographically but refuses SBXR admission.
The backend intentionally refuses invalid extra timestamps and noncanonical wire
aliases more strictly than Go. The later public-release increment supplies genuine SBXR native proofs and
positive acquisition. The candidate fixture's raw manifest remains absent.
Authentication does not grant qualification.
See `tests/testdata/artifact_trust/README.md` for policy and fixture provenance.

The separate [offline package tool](../tooling/rust-package/README.md) reuses
`release_identity` to generate metadata, package supplied static Rust ELF files,
bind an index and check all four assets. Its canonical single-member archives,
exact installer constants and digest bindings are tested with inert ELF inputs for
both architectures and an independent decoder. It never executes supplied
artifacts, signs or publishes. Actual retained-section embedding, native musl
builds/linkers and bootstrap/workflow integration remain required. AWS-LC and ring
add native C/assembly build dependencies; a successful Mac build does not prove
Linux cross-build availability. Local integrated and package logs are retained in
`.scratch/acceptance/rust-native/`.


Final validation for this increment passed 198 product tests, format, strict
Clippy and a macOS arm64 build. Both retained-POSIX-lock and foreign-identity
mutation checks failed under their intentionally removed guard, then source was
restored before the final suite. The standalone package checks pass eight tests
plus format, strict Clippy and build. These counts include real local child,
filesystem and nonprivileged loopback boundaries, not native operating effects.

The updated Linux GNU cross-check failed in the native cryptographic dependencies
because `x86_64-linux-gnu-gcc` is absent. No compiler or privileged package was
installed to bypass that result. The earlier pre-crypto cross-check does not
validate this updated dependency graph. Linux/musl builds and deployment
qualification remain unestablished; the native frontend remains unavailable.


## Authenticated installed bytes, private dispatch and Standard removal increment

`AuthenticatedInstalled::acquire` binds an existing strict Installed Record and
supplied current/installed bytes before any request. It reads only the exact-tag
GitHub API route, requires stable immutable metadata and exactly four uploaded
canonical asset API URLs, validates the current clean-install-only HTTP Acceptance
Record, authenticates every native DSSE proof, then binds the exact index and
selected archive to those authenticated digests. The unpacked executable must
match the supplied installed bytes and pass retained Rust/historical Go ELF proof.
An injected `AcquisitionTransport` must enforce its deadline, cancellation,
HTTPS and redirect constraints. The current shared selection budget is 30 seconds;
the later increment supplies native HTTP transport. Parity with Go's longer
archive-request window remains integration work. This earlier increment fetched
no live release.

The current Acceptance Record reader intentionally covers the current
`subscription-clean-install-only` policy, including five HTTP journeys and its
exact disclosures/support/assets. Historical qualification, exceptions and
candidate delivery refuse here rather than being converted. The preserved Go
reader independently agrees with all 85 synthetic acceptance cases. The template
under `src/release_acquisition/testdata/` describes a fictional run; it is not
live evidence. Existing records require Go's toolchain line; a Rust-aware release
qualification declaration/workflow still needs an explicit reviewed contract.

`release_archive::unpack` uses pinned `flate2` 1.1.10 with its pure Rust backend.
Its [single-member decoder](https://docs.rs/flate2/1.1.10/flate2/bufread/struct.GzDecoder.html)
checks bounded output, complete compressed consumption and CRC, fixed regular
`sbxr` member metadata, padding and terminal blocks. No archive path is extracted.
The reader accepts the independently generated Go ustar/gzip fixture; noncanonical
extensions and extra terminal blocks refuse more strictly than Go's generic tar
reader. These encodings are outside the current fixed package producer contract.

`NativeObserver::authenticate_current` implements the Linux bridge from
`/proc/self/exe` and the protected installed pair to that acquisition chain. It
checks the fixed process path, regular/root-owned/one-link/executable metadata
and stable inode/content metadata, excluding read-updated atime. It is platform
gated and was not executed on this Mac. `LinuxHost::injected_authenticated` checks
newly observed installed files against the opaque authenticated result.
`native_authenticated_unreleased` performs the corresponding construction but
keeps native effects unavailable. `SetupMaterial::generated_standard` validates
key/DEB pins before injectable entropy; `recovered_standard` decodes the bound
existing configuration without new credentials. The Standard decoder rejects
unknown/duplicate fields, preserves raw hash bytes and derives public X25519 facts.
Actual pinned upstream key/DEB acquisition remains absent.

The real acquisition entry refuses the preserved genuine foreign native bundle
before downloading any index/archive. Positive index/archive/Standard integration
unit tests cross the signature boundary through a private `cfg(test)` constructor
only. That constructor is absent from product builds. The later public-release
proofs and example exercise genuine positive authentication independently of this
unit helper. The candidate fixture's raw manifest remains missing.

The zero-argument frontend remains the labeled simulator. It now recognizes only
the six exact Go private arguments before menu dispatch: lock provision, proxy
start, subscription serving and the three certbot roles. Product dispatch refuses
silently, with the recorder's exact exit 125, until native prerequisites exist.
`InjectedRuntime` performs real protected temporary-root lock provisioning and
ordinary proxy-start checks using authenticated installed bytes, exact startup
unit/configuration and unchanged running authority. Provisioning creates only the
fixed coordination inode under existing parents. Ordinary startup requires an
existing inode. The later handoff module supplies descriptor lending and bounded
serving/watch composition. Native protected sandbox/process/service adapters and
legacy renewal roles remain unavailable.

`StandardRemovalHost` provides actual Standard file/command effects behind the
worker's 29-test removal state machine. It requires an authenticated installed
context, retains whole-host/package guards through commitment, releases package
guards before commands, separates exact package unhold from pinned purge, and
rechecks foreign files/accounts/processes. Removal observations use ownership
facts without requiring clock, destination, public-IP or bind availability. A bare
package hold now refuses an absent footprint; failed unhold cannot reach purge.
The adapter handles product-only, running Standard and interrupted masked setup.
Subscription, tunnel, renewal, startup and other auxiliary authority explicitly
refuse until their concrete effects exist. Historical journals still decode.

The central store admits only exact removal commitment and checkpoint successors.
Staged checkpoints cannot skip progress or grant commitment. The finalizer moves
the exact final record without replacement to `var/lib/.sbxr-removal.json`, syncs
both parents, removes only the empty owned state directory, then unlinks and
syncs the finalizer. Tests retry interruptions after the move and directory removal;
post-unlink uncertainty maps to Problem detected and never removal success.
First-commit conflicting/partial staging remains a refusal requiring correction.
No recursive product cleanup is introduced. Unknown children remain untouched.

`RemovalInstallation<H>` implements the shared Interface and terminal actions,
including distinct Removal incomplete/Not installed states, exact result codes,
every-Review token expiry and literal `REMOVE SBXR` confirmation for Complete
removal. Finish removal follows Go's menu-selection approval without another
prompt. `StandardInstallation::into_host` releases its directory-writer guard
before `StandardRemovalHost::new` takes over. The tests drive setup then actual
injected Standard removal through the shared menu. Exact authenticated restoration
of missing installed members after process death is still unavailable; same-process
finalizer retry tests do not claim that capability or physical crash durability.

The Linux build inventory found QEMU 11.1.2 executables for amd64 and arm64, but no
configured Docker/Podman/Colima/Lima runtime or workspace Linux guest image. No VM
or container was started. The local Rust 1.90 toolchain has Darwin arm64 and Linux
GNU amd64 standard libraries; no musl targets or cross-compilers were installed.
The known GNU check needs `x86_64-linux-gnu-gcc` for AWS-LC/ring; that missing
prerequisite was not bypassed or installed. A prepared Linux amd64 environment
with Rust 1.90 and an existing C compiler can run `CARGO_BUILD_JOBS=2 cargo test
--locked` and `cargo build --locked`. Musl releases additionally need the matching
musl standard library/compiler, retained build-section embedding and packaging/
bootstrap/workflow review. Available QEMU alone is not a ready build environment.

Current evidence, the Go oracle and safety mutation logs are retained in
`.scratch/acceptance/rust-acquire/`. Native installation, live qualification,
VPS/Karing, signing, push and publication remain unperformed.


Final validation passed 247 product tests (including the 29 removal cases), eight
standalone packaging tests, format, strict all-target Clippy and both macOS builds.
The independent Go oracle agrees with 85 Acceptance Record cases. Signature-bypass
and weakened-phrase mutations each failed the corresponding integration test;
exact source was restored before the final checks. Evidence includes the fixed
bare-hold regression and the final product-only authority correction.

For a prepared Linux environment, use the workspace-local run/TMPDIR recipe above;
for example, create `.scratch/acceptance/linux/t` as a fresh owned directory, then
run `TMPDIR="$PWD/.scratch/acceptance/linux/t" CARGO_BUILD_JOBS=2 cargo test --locked`
and `cargo build --locked`. This requires Rust 1.90 and an existing C compiler.
These commands were not run in a Linux guest during this increment.


## Bounded HTTPS and genuine public-release increment

`HttpsTransport` now implements the acquisition boundary with pinned reqwest
0.13.5, Tokio 1.54.1 and webpki-roots 1.0.11. Reqwest disables default features;
Hickory supplies asynchronous DNS so cancellation does not leave an OS resolver
thread behind. The single-thread runtime uses the existing explicit ring TLS
provider and pinned Mozilla trust. It verifies TLS 1.2/1.3 certificates/hostnames,
limits headers and raw streaming bytes, rejects automatic content decoding, and
checks authorization before each of at most four redirects. It sends no cookies,
authorization or referer; ambient proxy settings are deliberately disabled.
Embedded roots and direct acquisition are stricter choices than Go's system-root
and ambient-proxy transport. They need Linux compatibility validation, not a
silent fallback. No production signature-verification callback is introduced.

Every request, including DNS/connect/TLS/header/body phases, is covered by the
selection deadline and cancellation. Tests exercise real TLS loopback, raw headers,
allowed/refused redirects, oversized declared/chunked bodies, encoded bodies,
untrusted certificates, nested runtimes, stalled reads and unresolved DNS.
The return-time budget check fixes a timeout/cancellation classification race.
The shared selection budget is still 30 seconds and is stricter than Go's longer
archive window. Native deployment remains closed while that policy is reconciled.
Exact release metadata now rejects Link headers before any proof or asset fetch;
this fixes a gap exposed by the new boundary tests, preserving Go's completeness
contract. Native proof pages retain their existing Link refusal.

Public read-only v3.1.118/192 metadata, all three native Snappy proof blobs and the
exact signed index are preserved under `tests/testdata/public_release/` with
provenance. Temporary blob URL credentials are excluded. Both offline replay and
actual `HttpsTransport` requests passed the complete `AuthenticatedInstalled`
chain using the real 14,975,576-byte amd64 archive: every signature and timestamp,
metadata/Acceptance Record, index/assets, archive, historical Go ELF proof and
exact current/installed-byte binding. The archive was held in ignored evidence and
parsed only in memory. No supplied code was executed or installed. This closes the
genuine SBXR positive-acquisition gap; it does not requalify that historical release
or qualify a Rust build. The repository-only evidence example documents replay.

The completed `runtime_handoff` module is integrated with rustix's `net` feature.
It implements single-use SCM_RIGHTS lending, exact process/peer identity binding,
retained Owner exclusion, startup interruption, HTTP listener/watch shutdown and
one-use configuration-bound proxy gates. Core `HostLock::runtime_start_lock`
returns a duplicate whose Rust lifetime retains the original guard. The concrete
injected-root ordinary proxy adapter now calls this shared authorization model
and rechecks protected installed/unit/configuration/authority bytes. Temporary-root
socket names stay relative to the same fixture directory to respect macOS's Unix
socket length limit without changing process CWD or adding external symlinks.

The private native dispatcher still refuses. Connecting `ServingHost` and borrowed
proxy starts requires actual protected Linux process/sandbox/NSS/public-IP facts,
service handoff wiring and atomic gate effects. These are explicit missing inputs;
the fixture loopback route is never selected for production. Linux-only peer tests
have not run on this Mac. Exact authenticated restoration of missing installed
members, auxiliary removal, upstream pinned key/DEB acquisition and Rust build
section/bootstrap/workflow integration remain concrete incomplete paths. No
restoration is guessed from a newer release or ordinary structural inspection.

The committed source-transfer archive is prepared under
`.scratch/archives/rust-source/` with an external SHA-256/commit manifest. It contains
only selected committed Rust source, tests, documentation, package tooling and
required preserved proof fixtures; it excludes history, scratch evidence, caches,
build outputs and the real downloaded archive. Parent can copy this local artifact
using available `scp`, `sftp` or `rsync` after choosing a reviewed destination; no
upload, SSH connection, VM or container has been started. An existing Linux amd64
Rust 1.90 environment with a C compiler can run the documented tests/build. The
Mac has QEMU and GNU target std but no prepared guest/container or
`x86_64-linux-gnu-gcc`; no prerequisite was installed.

Evidence for this increment is in `.scratch/acceptance/rust-https/`. All checks are
local regression/authentication checks, not native deployment qualification.

The integrated suite passed 284 product tests, including 25 portable handoff
cases; the packaging crate passed eight tests. Strict all-target Clippy, format
and both Mac builds passed. The complete public acquisition example passed again
after the completeness fix. Removing that fix in a scoped mutation failed the
regression before proof/asset acquisition; exact source was restored and the
regression passed. All 126 added lockfile nodes are new HTTPS/DNS dependencies;
no previously locked package version was replaced. Temporary fixture roots were
cleaned. Linux-only execution, native installation and deployment qualification
remain unperformed.
