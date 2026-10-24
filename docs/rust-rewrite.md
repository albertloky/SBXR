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
| `src/proxyinstallation/{subscription,identity}.rs` | Shared Owner Review/Execute bridges for HTTP and sequential Client Identity changes |
| `src/host/{subscription,identity}.rs` | Exact protected HTTP/identity publication and recovery, retained guards and explicitly injected runtime effects |
| `src/client_identity.rs` | Durable sequential UUID rotation, nine independent shutdown proofs and irreversible target-only recovery |
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
| `src/release_acquisition.rs`, `src/release_acquisition/` | Exact-tag authenticated archive acquisition, Installed Record derivation and separate current-byte binding |
| `src/host/restoration.rs`, `src/host/filesystem/restoration.rs` | Exact committed-finisher recovery, retained exclusion, prefix staging and record-first file publication; injected roots only |
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

## Current finite parity checklist

The dated increments below retain their original evidence. This table is the
current work index; implemented library code is distinct from wired product
journeys and native/deployment validation. Historical decoders preserve evidence
without enabling in-place Go-to-Rust migration.

| Path | Implemented now | Concrete remaining completion |
|---|---|---|
| Native public entry and Standard setup/recovery | Shared Review/Execute and composed Owner routing; typed native HTTP/identity backends, protected system adapters and authenticated Standard input factory using pinned acquisition/recovery; fixture end-to-end checks | Connect the qualified public entry and remaining owners. Digest-only early cleanup and exact authenticated package-default replacement/cleanup are implemented in fixtures. Native effects and new Linux branches remain unvalidated; public entry stays simulated. |
| Private runtime and service control | Native private-role composition for lock provisioning, proxy authorization and Standard HTTP serving; sandbox facts without proc; fixed bounded systemctl actions, lending, cutover and quiescence observations | Retain/verify released Rust build metadata and loaded commit; validate new Linux branches and real systemd sandbox/shutdown. Connect the controller to each Owner journey. Development binaries refuse before native effects. |
| HTTP enablement, link rotation and repair | Shared Interface/menu/default-No, strict durable authority, concrete protected publication/cleanup, actual local serving through retained-lock service control, full effect interruption/reopen matrix | Native runtime observations/effects and composed Owner routing are implemented and fixture-tested. Connect the qualified public entry and validate actual Linux systemd/firewall/cgroup behavior. Exact known canonical/staged two-link publication is supported; conflicting records remain refused. |
| Client Identity and client disclosure | Sequential durable rotation/recovery; concrete native identity runtime and composed Interface; protected publication/cutover, HTTP artifact refresh, strict VMess decoder; disclosure/link/compromise orchestration module | The protected disclosure Host, streaming output and terminal routing are implemented and fixture-tested. Qualify native runtime and complete public entry/details composition. Exact staged Client Identity publication retry and trusted historical certificate selection/state CAS are implemented. Historical TLS serving and its activation/repair/renewal Owner flows remain unavailable. |
| Optional VMess/tunnel | Rendering, client artifacts, identity generation, setup/recovery/check orchestration, guarded native connector/probe adapters, authenticated probe bytes and shared Owner frontend | Validate actual Linux connector/process/cgroup paths, local/public WS and VMess-only egress; qualify the optional profile. Fixture composition is not real tunnel qualification. |
| Removal and Software Lifecycle | Standard/current HTTP/Client Identity artifact and dedicated tunnel removal with interrupted retries; exact finalization, signed acquisition, protected missing-member restoration and fixed descriptor execution preparation | Active/retired HTTPS lineage and renewal cleanup now have concrete protected effects and interrupted-reopen tests. Unfinished transport migration remains unavailable. Actual native restored-finisher exec and Linux qualification remain; Owner Check/Recover composition. Reconcile historical qualification-policy acquisition and transport timeout/root differences. Old journal decoding alone grants no migration. |
| Packaging and Linux builds | Explicit Rust/historical Go artifact inspection, genuine public signature replay and offline packaging CLI | Retained Rust build section/loaded commit wiring, native amd64/arm64 musl builds, bootstrap/workflow integration and exact clean-source validation. Current Mac lacks a Linux cross-compiler/ready guest. |
| Deployment qualification | Local tests and parent Linux evidence for its named earlier snapshot | All five current live journeys for the exact packaged Rust candidate, followed by any separately authorized signing/publication. No local test result is deployment qualification. |

Pinned key/DEB acquisition is integrated through opaque `VerifiedPackage` into
`SetupMaterial`. The genuine inert DEB remains an explicit 32.3 MB fixture so
production-pin positive and mutation cases stay reproducible offline. It is not
part of the product binary. No new archive or upload is created by that decision.


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
injected Standard removal through the shared menu. The later exact-restoration increment implements missing-member recovery through
a fresh injected adapter after interruption. Native installer dispatch remains
unavailable; these tests do not claim physical crash durability.

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


## Exact committed-finisher restoration increment

`AuthenticatedArchive::acquire` authenticates an exact tag/commit/index against
real native signatures, derives the canonical Installed Record from the signed
index and inspected archive, and retains the executable bytes. It does not
require an existing Installed Record or executable. It grants no filesystem or
process permission. `AuthenticatedInstalled` remains a separate proof of supplied
current/installed bytes; native callers must still authenticate the actual kernel
process. No public signature-verification callback or unsigned success constructor
was added. Unit fixture helpers remain private to `cfg(test)`.

`RestorationHost::injected` reads committed current or finalizer authority under
the retained whole-host lock, selects only its Finishing Release Identity, and
retains the record-directory writer guard when that directory exists. Conflicting,
staged, uncommitted or early finalizer authority refuses. The adapter rejects `/`
and cannot run native commands. It never selects Latest, changes proxy resources,
rewrites the journal or chooses a different recovery direction.

Restoration requires protected existing parents, exact canonical bytes/modes and
one-link files. Executable-only residue refuses even when its bytes match. Unknown
state children and foreign targets remain untouched. Missing state directories
may be recreated only under proved finalizer authority. Hash-named
`.sbxr-restore-<executable-sha256>` stages admit only exact target prefixes in mode
0600, or a complete executable in mode 0755. Unknown bytes, links, metadata and
other staging identities refuse before publication. Each prefix resumes without
truncating unknown data. Publication uses no-replace rename and fsync: the exact
Installed Record and its parents are synchronized before the executable becomes
visible, then both final files and parents are synchronized again.

The returned `RestoredPair` proves restored files and exposes the exact Installed
Record. It does not claim to be the current OS process. Native recovery must
launch and independently authenticate that finisher; the temporary-root removal
test supplies explicit simulated current observations. Recovery returns the exact
Go success code `SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED` only after final checks.
Interrupted work retains the original journal and its legal forward direction.

Eleven focused restoration tests cover all five publication interruptions, empty/
partial/complete prefixes, fresh adapter reopen, existing-pair retry, both retained
locks, canonical record bytes, foreign resources, unsafe parents, cancellation and
capability markers. The ten preserved Go removal journal shapes are exercised with
test-bound finishers; the original fixture files remain unchanged. A recovered
product-only finisher also completes actual injected removal/finalization without
command mutations. These are local restart/failure tests, not physical power-loss
or Linux deployment qualification.

The repository-only public evidence example now runs the real authentication
backend against the preserved v3.1.118/192 signatures/index/archive, then exercises
restoration in a disposable protected root. It never executes fetched code and
cleans that root. The genuine replay passes without a test-only signature boundary.
No new dependencies, source uploads or live system effects are required by this
implementation slice.

Native restoration dispatch, auxiliary resource effects, concrete serving/process/
sandbox/cutover adapters and pinned upstream key/DEB acquisition remain incomplete.
The current metadata/Acceptance Record reader still authenticates only the current
clean-install policy: reading historical journals does not imply acquisition of
all historical qualification policies. Auxiliary publication cleanup also needs
Go's exact canonical/staged two-link identity proof; ordinary unrelated hardlinks
must continue to refuse. The native CLI remains closed while these paths and Linux
qualification are incomplete. This increment does not enable Go-to-Rust migration.

Local evidence is under `.scratch/acceptance/rust-restoration/`. The earlier
committed snapshot and its validations remain separate from these newer changes.

Validation passed 297 product tests, eight packaging tests, strict all-target
Clippy, format and the Mac build. The genuine offline archive-to-restored-pair
example passed through the real signature backend. Removing executable-only
residue refusal made its adversarial test fail; exact source was restored and
the test passed. No Linux, real-root or deployment qualification was performed.


## Linux regressions and concrete proxy cutover increment

The parent independently validated snapshot `0940fc9` on Linux under `umask 077`.
It reproduced a retained-descriptor writer-lock failure and fixture-mode failures;
after its three-file patch, 287 product tests, eight packaging tests, format,
strict Clippy and both GNU builds passed. Those results cover that snapshot and
patch only. Current native code has not been executed or cross-built on Linux.
The Mac still lacks a Linux C cross-compiler or prepared container/guest; no
prerequisite was installed and no privileged environment was started.

The retained-descriptor failure is confirmed: flock exclusion belongs to the
open file description and survives closing one descriptor while a duplicate
remains. A concurrent fork retaining a CLOEXEC descriptor until exec is the
inferred cause of the intermittent original failure. `OwnershipStore` now
explicitly unlocks on Drop because its private directory description is never
intentionally lent. A deterministic regression retains a duplicate, drops the
store, opens its successor and confirms closing the old duplicate cannot unlock
the successor. This is distinct from `HostLock` and runtime-start lending, whose
duplicates intentionally retain Owner exclusion. A separate regression proves
store release does not revoke that borrowed Host lock authority.

The adapted fixture corrections explicitly set package directory/unit modes to
0755/0644 and restoration fixture parents to their existing contract modes.
They remove ambient-umask assumptions without relaxing production ownership,
mode, parent, inode or hardlink checks. The genuine restoration evidence example
uses the same explicit fixture-parent modes.

`ProxyRuntimeHost` implements fresh authenticated installed-pair, ownership,
pending/finalizer absence, startup drop-in, effective ExecCondition and canonical
configuration checks. Native observations use `LinuxPeers` and fixed bounded
`systemctl show --property=ExecCondition --value sing-box.service`; injected
roots require explicit process/command observations. Cancellation and deadlines
propagate to the command runner, with the watcher joined on all return paths.
The native factory checks the actual Linux/Ubuntu/root/architecture environment;
unsupported hosts cannot select a simulator implicitly.

`host/runtime_io.rs` supplies nonblocking, close-on-exec Unix connections with
bounded polling and startup cancellation. Linux uses the fixed abstract address,
never filesystem-socket adoption or deletion. Fixture routes require an owned
protected root and direct-child socket, refuse parent escapes/symlinks and
recheck socket identity. Darwin uses only the explicit fixture route.

`ProxyRuntimeHost::prepare_cutover` rechecks Owner exclusion, actual observed
current image, release identity, canonical configuration and recorded recovery
direction before publishing the exact 65-byte volatile start gate. `CutoverGate`
retains the Owner through the scoped start and provides checked `finish` cleanup.
It removes only exact owned material, preserves foreign changes and reports an
explicit uncertain cleanup without silently retrying it in Drop. Its native
start helper binds the fixed channel and wraps a trusted bounded fixed systemd
start effect; complete native controller dispatch remains unavailable.

`Handoff::service` handles the PID assigned by systemd after startup begins.
It pins authenticated executable bytes, Owner UID and the fixed role cgroup,
then binds and rechecks the observed PID, start time and identity before lending.
The exact-identity `Handoff::new` constructor and wire protocol remain intact.
Native peer facts come from the kernel/proc observer. Portable tests inject those
facts while exercising actual sockets, SCM_RIGHTS, retained locks, file modes,
no-replace publication, exact one-use consumption and parent synchronization.
No caller-provided PID or environment value grants native authority.

The consumer requires a verified same-root borrowed StartLock, exact recorded
configuration token, one-link protected file and stable metadata. It unlinks and
syncs that gate only after capability/context rechecks. Ordinary starts remain
available only before the recorded cutover boundary; forward recovery selects
the target and cleanup selects the permitted source. A revoked source cannot
become executable through a stale or foreign token.

Current Mac validation under `umask 077` passed 311 product tests, eight packaging
tests, format, strict all-target Clippy and the build. Temporarily removing the
service executable binding made the adversarial handoff test fail; exact source
was restored and that test passed. Genuine preserved v3.1.118 authentication and
exact temporary-root restoration also passed offline. Temporary fixtures were
cleaned. Evidence is `.scratch/acceptance/rust-runtime/`. Rustix's already pinned
version only gains its `event` feature; no lockfile dependency version changed.

Concrete `ServingHost` and its sandbox/current-process proof bootstrap remain
the next incomplete path. The serving sandbox hides /proc, so proof cannot be
invented or replaced with fixture observations. Native serving material/watch/
bind and full service-controller dispatch remain closed. Auxiliary cleanup still
needs exact canonical/staged two-link proof, and pinned upstream key/DEB
acquisition, historical qualification-policy acquisition, transport timeout
parity, retained Rust build sections and bootstrap/workflow integration remain
unfinished. Exact missing-member restoration remains injected-root only. No
native root effect, new source upload, signing, push or publication occurred.
These tests do not qualify a Rust deployment or enable Go-to-Rust migration.


## Concrete serving and private-service composition increment

`ServingRuntimeHost` now supplies the complete current Standard HTTP runtime
boundary: freshly protected installed/ownership/configuration/group/unit files,
known state children and startup overrides, exact enablement link, pending/final
absence, a real listener, periodic public-IP checking and joined shutdown. It
never opens the sandbox-hidden bearer token or treats the auxiliary state file
as authority. The native observer independently checks the actual singleton
fixed cgroup, effective UID, all capability sets, NoNewPrivileges and EACCES for
the token, staging, proc and host system-control paths. Missing paths do not
count as inaccessible. No mount, capability, cgroup or security setting is changed.

The sandbox-visible `SandboxProcess` carries actual PID, UID, fixed cgroup and
kernel AT_EXECFN, with no invented executable digest or process start ticks.
Rustix's `runtime` plus `use-libc-auxv` features select direct libc getauxval for
static musl. The weak/dlsym variant would not resolve in a static executable;
the default raw auxv fallback can attempt hidden proc on older kernels. The
selected safe API avoids both routes without adding unsafe product code.

Systemd v255's [fixed execution path](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/exec-invoke.c)
uses fexecve/execveat; [Linux v6.8's exec implementation](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/exec.c)
can therefore report `/dev/fd/N` as kernel execfn. The receiver recognizes only
the fixed pathname or canonical nonnegative descriptor form and never opens,
follows or selects executable authority from that name. Unit/cgroup/loaded-build
and independent Owner-side image checks remain required. A regression covers
both supported forms and malformed, overflow, traversal and alternate paths.
`acquire_serving_start` rechecks these observations, matches actual SO_PEERCRED
UID, receives exactly one close-on-exec descriptor and revalidates its protected
inode/exclusion. Owner-side `Handoff::service` still independently authenticates
the full child executable and stable kernel process identity before lending.
Ordinary starts never create a missing lock; borrowed descriptions never unlock
the retained Owner or serialize new durable authority.

The current Go early-boot unit permits only AF_UNIX. Therefore private startup
performs local protected installed-pair status checks, as Go does, rather than
requiring impossible online acquisition inside that unit. Proxy/provision roles
also compare the actual proc-observed running image. The proc-hidden serving
role instead combines fixed unit/cgroup/sandbox, kernel execfn, loaded Rust build
commit and protected Rust installed-pair proof. These local checks do not create
`AuthenticatedArchive` or `AuthenticatedInstalled` acquisition proofs. Installation
continues to require the real signed acquisition boundary; no signature callback,
structural-only artifact trust or test verifier was added to production.

`NativePrivateRuntime` is wired into main's exact private argument dispatcher.
It maps only stopped serving/successful authorization or provisioning to exit 0;
renewal roles retain their refusal codes. A development binary has no released
`SBXR_BUILD_COMMIT`, retained Rust release artifact or musl release build and
refuses before network, signal registration, lock creation or service effects.
This does not open the public native setup frontend. Release-build metadata and
Linux systemd validation remain explicit prerequisites.

`ServiceController` composes retained Owner authority, exact installed/current
proof, fixed unit/authority checks, bounded systemctl commands and joined lending.
Its native command adapter accepts only a closed action enum, uses the verified
fixed executable/cwd, enforces the startup deadline/cancellation, bounds output
and rechecks both process-file and Owner identity. Starts recheck unchanged
Ownership Record bytes. Proxy cutover consumes the existing gate lease. Stop
completion is distinct from quiescence: a separate native observation checks
bounded cgroup-v2 population and an actual wildcard TCP8443 bind. No absence of
a listener alone proves accepted work has stopped.

Public-IP checks use the existing verified HTTPS transport with asynchronous DNS,
fixed api.ipify.org, bounded canonical public IPv4 bytes, no redirects/content
encoding and cancellation. The watcher uses the Go one-minute interval and joins
before return. SIGINT/SIGTERM cancellation uses the existing pinned Tokio with
its signal feature; only signal-hook-registry 1.4.8 was added to the lockfiles.
The old HostLock lending and Linux store-unlock fixes remain separate and intact.

The completed `package_acquisition` module is exported normally. It verifies
complete pinned armored-key/DEB bytes and exact control version/architecture,
authorizes each bounded HTTPS redirect before sending it and retains independent
dpkg/APT hold observations. `SetupMaterial::from_acquired_package` and
`recover_acquired_package` consume its opaque verified material through existing
pin checks. The recovered configuration is retained rather than regenerated.
The complete vendor DEB fixture is kept deliberately: the real production-pin
positive/mutation checks require those bytes for offline reproducibility. No
package is extracted, installed or executed by these tests.

Concrete portable checks exercise actual protected files, Unix descriptor
passing, retained locks, loopback HTTP response bytes, cancellation/joining,
periodic public-IP failure, foreign/pending material and child-image refusals.
The new fixed HTTPS probe also exercises actual TLS loopback and stalled-body
cancellation. A disposable nonprivileged sleep process exercises cancellation,
termination and reaping. Native systemctl, capability/proc-hidden sandbox,
SIGINT/SIGTERM registration and fixed public listener branches have not been
executed on this Mac. They require Linux validation, not a simulation fallback.
Local integration evidence is `.scratch/acceptance/rust-runtime/`.

Validation completed 339 product tests in the full combined offline suite under
umask 077, followed by the additional descriptor-execfn regression and all 25
affected handoff integration tests (340 distinct product cases). The current
focused runtime tests, strict all-target Clippy, format, Mac build and eight
packaging tests/checks/build also pass. A scoped removal of the receiver's
process-stability recheck made its changed-identity regression fail; exact source
was restored and that test passed. Temporary fixture roots were cleaned.
Current Linux branches, native signals/systemd/sandbox effects and deployment
qualification remain unexecuted. No new upload, push or publication occurred.


## HTTP Owner and Client Identity integration increment

`HttpInstallation<H: SubscriptionHost>` now exposes enable, rotate, runtime repair
and Finish subscription change through the shared two-operation Interface and
numbered terminal. New changes require default-No confirmation; selecting Finish
uses the Go recovery confirmation behavior. Every later Review expires earlier
prepared authority, and Execute compares durable bytes and fresh host facts under
retained Owner exclusion. Review reuses its observed subscription facts rather
than spending an additional HTTP probe on its details string. Proxy and
subscription capability statuses remain separate. HTTP exposure is shown in the
plan, and only a durably committed, locally verified link is disclosed once after
approval. A failed readback reports the existing display-incomplete code.

`ProtectedHttpHost` applies exact fixed firewall/unit/link, credential, state and
staging effects. It preserves SSH/unrelated firewall rules, REALITY configuration,
foreign paths and independent credentials. Ordinary protected reads still refuse
hardlinks. The publication helper admits only the exact canonical/staged pair
with two total links, identical inode/metadata/content and no third alias. Both
Go-supported fixed absolute and relative service links are recognized. Rotation
stops and drains the source before forward commitment; recovery never generates
another credential or resurrects a revoked source. Runtime repair retains the
same credential and server configuration.

The completed `client_identity` module is exported normally and its structural
successor relation is admitted by the durable CAS store. `ClientIdentityInstallation`
binds the worker's opaque prepared values to the shared Review expiration and
terminal confirmation. `ProtectedIdentityHost` retains whole-host, package and
managed-writer guards; performs real protected target/artifact/startup publication
and group-correct configuration replacement; and uses the existing cutover lease
and service-controller descriptor lending. Its injected runtime contract requires
explicit admission, loaded-route, shutdown, startup and running observations.
There is no default successful reload. All nine shutdown facts must hold before
revocation. Forward recovery republishes only the recorded target. The private
proxy/serving preparers now share strict Standard+dedicated-VMess decoding and
retain original input bytes as the configuration hash subject.

Tests exercise enable -> link rotate -> runtime repair, and HTTP enable -> Client
Identity rotate -> refreshed real loopback response. They use protected disposable
roots, real fsync/publication/locks/Unix descriptor handoff/one-use gate consumption
and bounded HTTP threads. Proxy, process, package, loaded-systemd and firewall
observations/effects remain explicitly injected; no sing-box binary, systemctl,
APT, iptables or real credential is executed/deployed. The identity effect matrix
interrupts before and after eight effects, reopens with failing entropy and checks
cleanup versus target-only completion. Remaining descendants, stale Review,
default-No, unknown material, foreign staging, mismatched/duplicate VMess JSON and
foreign links are refused. Two renderer goldens retain exact Go bytes.

The first concrete identity tests caught a startup directory made 0700 by umask
077 where its contract requires 0755. Publication now creates that directory with
an explicit mode, and the affected success/interruption/refusal tests pass. The
existing store-unlock regression remains separate from intentionally lent
HostLock authority; neither lifetime was weakened.

Both new Owner hosts intentionally reject root `/`; public zero-argument startup
still constructs the labeled simulator. They do not constitute a qualified native
Owner backend. Native process/service/firewall composition, client disclosure and
compromise flows, optional tunnel setup/check, auxiliary removal, native exact
restoration, explicit staged-record retry, release build/bootstrap and Linux/live
qualification remain finite follow-ups in the checklist above. The current Mac
still lacks a ready Linux guest/container or Linux C cross-linker; no tool was
installed and no new snapshot was uploaded. Local evidence remains under
`.scratch/acceptance/rust-runtime/`.

The final ownership review also guards the Go forward-only configuration-candidate
contract: a valid candidate appearing before revocation is preserved and refused.
Its new regression fails when that guard is removed. Validation passed the full
378-test offline product suite, then all 14 affected identity tests after this
last guard and added regression (379 distinct product cases total), eight offline
packaging tests, format, strict all-target Clippy and the Mac build under umask
077. Three mutations were caught: skipped descendant proof, expired Review
authority and a pre-revocation configuration candidate. Sources were restored
exactly and affected tests passed. Evidence is
`.scratch/acceptance/rust-runtime/http-owner-outcome.json`; committed Go source
remains byte-identical to the provenance commit. No new Linux or live pass is
claimed.


## Native Owner runtime and composed frontend increment

`OwnerRuntime<I: OwnerIo>` implements the HTTP and Client Identity runtime
contracts with one closed native command vocabulary. `NativeIo` runs only fixed
systemd/package/listener/process queries and fixed service actions, with verified
executable identity, sanitized environment, bounded output/deadlines, cancellation
and process-group cleanup. Firewall executable proof supports only the protected
Ubuntu nft/legacy alternatives chain. No arbitrary shell command or caller argv
is accepted. Native constructors require the supported Linux/root environment
and authenticated installed/executing bytes; injected constructors remain
separate and cannot select `/`.

The runtime checks the pinned package/hold, exact package unit, loaded fragments,
drop-ins/ExecStart, separately resolved service UID/GID, actual process image and
cgroup, MainPID and PID-bound listener. Readiness uses bounded real HTTP, exact
headers/artifact bytes and stable process identity after the response. Shutdown
checks inactive/zero PID, process/listener absence and fresh cgroup population;
stop completion alone never proves quiescence. Service actions compose the
existing controller, retained Owner descriptor lending and exact one-use cutover
gate. Independent serving health failure does not disable Client Identity review;
its known start route is proved before cutover and the selected artifact is
proved afterward.

Ordinary file readers retain one-link, exact mode and size stability checks.
Fixed cgroup virtual files have a separate bounded reader because their reported
size can be zero while reads return data; it retains protected parents,
owner/group/type/link/inode checks. The private serving/sandbox and shutdown
observers now use that reader. Native protected writes are scoped to the retained
Owner; identity effects clear the filesystem write lease even on error, so a
later review cannot retain abandoned exclusion.

`OwnerInstallation<S: OwnerSources>` composes the existing concrete Interfaces.
A later Review discards the previous selected module before opening another
writer. Only the selected module and its opaque prepared action survive until
Execute; source modules still perform their own fresh admission/CAS checks.
`NativeOwnerSources` opens typed native HTTP/identity adapters and prepares
Standard inputs from pinned package acquisition and exact saved configuration.
It caches only the public key/DEB bytes and revalidates their compiled pins when
forming material. Early setup recovery without saved exact configuration refuses.
Native removal remains unavailable: removing an installation must not acquire a
package or probe external destinations just to build its adapter. Public
zero-argument dispatch remains the explicitly labeled simulator until the missing
owners, build identity and qualification are complete.

The disclosure and tunnel modules are exported normally. Their 20 and 19 tests
pass in the shared suite. They remain orchestration implementations, not native
Owner flows: disclosure still needs its independently proved protected Host and
terminal output sink; tunnel still needs connector effects and a real probe
session that proves trusted public WS and authenticated VMess-only egress, stable
probe process and cleanup. A service-running observation never substitutes for
connection verification.

The native/composed fixture uses real protected files, locks, descriptor lending,
cutover consumption, the actual HTTP module and its default production rate
limiter; only command/process/public-IP observations and effects are injected.
Its test-only state constructor changes the loopback bind address while retaining
production artifact bytes, and is absent from production builds. Enable -> Client
Identity rotation -> link rotation works across writer lifetimes. An independent
serving fault is recovered without changing the link. UID/image/cgroup and kill
mode refusals preserve source authority. The process UID is a separate synthetic
service identity, so these fixture tests also support a root test runner without
pretending the proxy runs as root.

Validation passed the full 428-test offline suite, then all 14 affected native
tests after two provenance cases were added (430 distinct product cases). A
skipped service-UID check was caught by the new regression; exact source was
restored and affected tests passed. The actual-module composed journey passed
three repeated runs. Native systemd/firewall/cgroup execution and the latest
Linux build remain unvalidated. Evidence is under
`.scratch/acceptance/rust-owner/`; there were no live effects, transfers or
publication actions.

The property-query behavior is checked against the
[systemd v255 show implementation](https://raw.githubusercontent.com/systemd/systemd/v255/src/systemctl/systemctl-show.c):
property mode is distinct from status/help handling for an inactive missing unit.
This source check does not substitute for executing the native adapter on Linux.


## Concrete protected disclosure and output increment

`ProtectedDisclosureHost` now implements the disclosure module's retained
whole-host/package/writer guard, authenticated exact snapshot/inspection, bounded
no-follow material reads and exact durable compromise CAS. Native construction
requires supported root:root plus authenticated installed/executing bytes. An
explicit fixture root uses its actual independently pinned namespace owner; the
model's default remains root:root. File ownership is never inferred from the
supplied file itself. The sing-box configuration GID is independently resolved
and compared with the actual descriptor's proof.

The runtime independently inspects Ubuntu/architecture, public address,
transaction absence, pinned APT key/source, package/hold, account/state ownership,
protected configuration/hash/shape, package unit/loaded process/listener,
provisioning unit/link and enabled/active service. Unknown health remains false,
not a successful placeholder. Configuration validation requires retained Owner
authority and an already bounded, hash-bound supported configuration before the
fixed sing-box check command can run. On this Mac tests supply a parser/command
fixture; no package executable or native command is run.

Status uses a metadata-only regular-file reader for subscription token/state.
It preserves no-follow, protected ancestry, type/owner/mode/link/size and inode
checks without reading credential bytes. Missing bounded owned subscription
material can leave the independently confirmed client fallback available;
foreign type/permissions/ancestry refuse. View details reads only the canonical
credential and exact saved serving state and refuses disagreement. It neither
reads candidates nor completes an operation. Historical HTTPS redisclosure keeps
its scheme and grants no certificate mutation or in-place migration.

`DisclosureInstallation` and the composed Owner forward an explicit streaming
output sink. Show client configuration remains default-No; it writes a framed
client artifact only after confirmation and fresh revalidation. Output/flush
failure propagates as a terminal I/O error, matching Go, instead of reporting a
successful display or inventing a new result code. After success the terminal
retains the scrollback pause. View details has a separate validated link writer
with credential/transport warnings, keeping bearer URLs out of generic Review
strings. Confirmed compromise marking writes only the existing authority flag;
credentials/configuration remain unchanged, and uncertainty is reported without
retry. A later Review/status/details read expires old disclosure authority.

Concrete tests use actual protected files, inode/mode checks, independently
resolved fixture service identity, retained guards and durable publication.
They cover default-No, streaming confirmation, failed output, stale authority,
compromise persistence, canonical redisclosure, malformed-token fallback and
wrong GID. A real file-access-time check proves status reads metadata without
reading the token. Injecting a credential read into that helper makes the new
regression fail; restoring the exact source passes. Existing worker tests retain
root:root defaults and all assertions. This supplies no native Linux, packaged
or outside-client qualification.

Validation passed the 434-test integrated offline suite under umask 077, followed
by all four affected disclosure tests after the final status projection change.
Strict Clippy/format passed during integration; final build/package evidence is
under `.scratch/acceptance/rust-owner/`. Public zero-argument native dispatch is
still closed; the next incomplete functional path is the guarded tunnel
connector/probe/frontend adapter, followed by native recovery/removal and release
build/qualification work. No live effects, credential deployment, upload,
signing, push or publication occurred.

## Offline recovery and current auxiliary removal increment

`SetupMaterial::for_cleanup` binds precommit cleanup to the existing strict
Ownership Record and compiled upstream package/key pins. It carries no saved
configuration, package bytes or credentials. The concrete host checks any
remaining canonical/staged file against the recorded digest before removing it.
It cannot install or activate resources, and after cleanup it cannot advertise a
new setup using these incomplete inputs. The ten precommit setup checkpoints
reopen through the actual command adapter without saved secrets or available
network, listener-bind or clock facts. Activation commitment still refuses this
cleanup constructor. Native Owner construction selects this branch before
package acquisition; it refuses a removal finalizer in the setup factory.

`SetupMaterial::for_removal` and the native offline host builder likewise need no
package download, entropy, external destination or public-IP probe. Native Owner
sources now construct `RemovalInstallation` through that builder. The production
effect/public-entry gates remain closed. These constructors are implementation
boundaries, not evidence of a qualified native installation or removal.

`StandardRemovalHost<R, B>` accepts a narrow local `AuxiliaryRuntime`. The default
runtime refuses auxiliary authority. Its current HTTP implementation checks the
recorded serving generations, credential hashes, canonical/staged publication
bytes, exact service/firewall units and links, and known staging children before
commitment or effects. It stops the owned serving runtime and proves quiescence
before unlinking secret material, removes only its recorded firewall unit/rule,
and finishes existing removal commitment forward. Recorded source and target
publications may coexist; cleanup deletes them without selecting or resurrecting
a source. The exact Client Identity startup drop-in is removed only after proxy
shutdown; an SBXR-created empty parent is removed, while a shared parent is
preserved. Unknown files, credential changes and foreign startup routes refuse.
Historical HTTPS/renewal, dedicated tunnel and Client Identity subscription
artifact removal still refuse; their codecs remain readable.

`OwnerRuntime` supplies local systemd/process/cgroup/listener/firewall observation
and fixed disable commands for this adapter. It does not call public-IP discovery
or execute sing-box during removal. A concrete test starts the real loopback HTTP
module, commits removal, then disables/joins serving and the firewall using the
same runtime logic with injected system effects. Its network/configuration probe
methods deliberately panic if called. Temporary-root removal tests also cover
failed stop/retry, prepared enablement, source/target publication cleanup and
shared versus created startup directories.

`RestorationHost::native_unreleased` now supplies the same protected missing-member
filesystem implementation for a supported native root, using authenticated exact
archive bytes and retained whole-host/store exclusion. No native restoration was
executed during development. `prepare_finisher` consumes the sealed restored pair
and rechecks the exact release, authority, installed record, bytes, mode, GID and
inode into `RestoredFinisher`. Its fixed zero-argument Linux takeover uses the
retained executable descriptor, a cleared environment and the interactive
terminal. It explicitly releases the private store before exec, preserving the
separate close-only lifetime of intentionally lent HostLock descriptors. The
existing complete-adapter gate prevents takeover until production integration and
qualification are complete. Descriptor preparation/stale-authority/lock tests are
local evidence; the actual Linux exec path remains unexecuted and unvalidated.

The native tunnel worker's four-file export patch has been reviewed and integrated:
`host::tunnel_native`, the exact systemd argv parser, and the recorded cloudflared
binary digest getter. Its injected tests execute only their synthetic test
executable with explicit helper names, temporary roots and loopback TLS/HTTP
fixtures. The concrete connector/probe implementation is exported, but
`StandardHost` still needs the shared protected Standard bridge and an
authenticated pinned probe-image digest. Initial setup must also gain only the
exact valid retained proxy-start checkpoint; the current Running-only controller
continues to refuse it. No plain-start fallback or weakened authorization was
introduced. Tunnel frontend composition is a subsequent bounded integration.

Remaining feature/release checklist after this increment:

1. Compose the native public Owner entry after remaining inputs/owners are
   complete; the existing simulator and unavailable native gates remain explicit.
   Early no-config cleanup and offline removal construction are implemented.
2. Qualify protected disclosure/output/compromise on the supported Linux host;
   the composed fixture journeys already exist.
3. Implement the tunnel `StandardHost` bridge, authenticated probe-image binding,
   exact setup-start admission and Owner frontend composition. Connector/probe
   code exists; Linux/kernel/systemd/actual VMess validation is still absent.
4. Finish auxiliary Client Identity subscription-artifact, tunnel and historical
   HTTPS/renewal removal. Current HTTP/startup and non-subscription identity-target
   cleanup are implemented. Native restoration/takeover remains gated and needs
   Linux exec and complete product recovery qualification.
5. Complete the generic interrupted-publication retry and historical HTTPS
   mutation/certificate-selection paths where current retained authority needs
   them; unsupported paths continue to refuse.
6. Validate the current complete source on Linux, including native command,
   process/cgroup, lock and durability behavior. Earlier independent Linux results
   apply only to the older `0940fc9` snapshot plus its recorded patch.
7. Finish retained Rust ELF build identity, dual-architecture musl packages and
   reviewed bootstrap/workflow integration. Offline package tests are narrower
   evidence and do not qualify a release.
8. Qualify the exact packaged candidate's five supported live journeys and
   outside-client/Karing behavior, then obtain the required exact publication
   approval. This increment performs no live, credential/security, signing,
   upload, push or publication action.

Final validation for this increment passed **461 product tests and 8 offline
packaging tests** under umask 077, plus format, strict all-target Clippy and a
Mac debug build. The credential-digest removal mutation failed at the intended
foreign-token assertion and exact source restoration passed. Evidence is under
`.scratch/acceptance/rust-recovery/`, including the reviewed test scope and final
logs. The parent-reported worker broad-test denial had not executed; after
reviewing changed target side effects, one explicit retry with that evidence was
admitted and passed. No denied operation was silently rerouted. These results do
not qualify Linux native effects, descriptor exec, actual VMess traffic, an
installed package, a VPS or a release candidate.

## Native tunnel composition increment

`host::linux::TunnelStandard<R, B>` now implements the tunnel adapter's
`StandardHost` using the existing protected Standard observations and effects.
It uses the original retained Owner guard, updates the command runner's exact
configuration hash only from the current journal, and admits only schema-1 setup
writers. Idle schema-2 tunnel profiles remain readable for connection checks;
this adds no migration or historical writer. Cleanup uses digest-only material
and does not require or recreate the Owner token or cloudflared binary.

`VerifiedPackage::probe_image` derives an opaque executable proof by streaming
`./usr/bin/sing-box` from the fully key/DEB-pinned package's gzip/tar payload.
It bounds decompression/member count, checks the executable's exact type/mode,
root UID/GID and unique name, honors cancellation, and checks gzip completion.
It never extracts or executes a package member. The preserved genuine DEB's
91,990,368-byte executable has SHA-256
`33de1654134de582a3d23786fdba32e5461bfe3eefe3e11ddeef2a9635a9e91c`.
The bridge checks protected installed bytes against this proof before config
validation/start or probe launch. Neither a version string nor a hash sampled
from the current filesystem creates a production proof.

`ServiceController::start_setup_proxy` authorizes only the schema-1 dedicated
setup's exact `Service enabled`/`Finish setup` checkpoint, matching installed
Release Identity, private configuration and pinned package unit, with no
unrecorded startup drop-in. It retains the original Owner and a CLOEXEC duplicate
through the fixed start, rechecking unchanged journal authority afterward.
The pinned package unit contains no SBXR ExecCondition, so this initial start is
a direct Owner-scoped authorization; it does not wait for an absent private-role
child. Ordinary private proxy-start authorization remains Running-only, and
restart does not become an initial-setup route. Independent runtime observation
binds TCP10000 specifically to 127.0.0.1, the same exact proxy PID/image/cgroup as
TCP443, with no extra cgroup processes or control PID.

`TunnelOwnerInstallation` connects the existing durable tunnel orchestration to
the shared Interface. `NativeOwnerSources` composes this adapter, the authenticated
probe proof and concrete runtime/connector. The Owner wizard offers optional
Standard + Cloudflare where supported, retains Back/Cancel/default-No, validates
hostname-only input before retaining or echoing a draft, and shows the selected
tunnel ID before Apply. Later status/details expire prepared authority. Setup
results and explicit repeatable VMess connection checks use the Go result codes;
local Running and a fresh public check remain separate. HTTP serving accepts
strict supported VMess configurations, and normal Owner routing retains HTTP,
identity and disclosure journeys after tunnel setup.

Connector native write authority is now released after every successful or
failed scoped effect; it cannot keep an abandoned whole-host lock across later
reviews. The existing native-effect and public-entry gates remain closed. No
native systemd, APT, firewall, real probe, credential, VPS or release operation
was executed during development.

A separate existing Standard installation blocker is now reproduced with actual
pinned package data: the DEB supplies `/etc/sing-box/config.json` as a public
635-byte root-owned 0644 default. After `Package installed`, the existing Standard
observer expects the final journal-bound root:sing-box 0640 private file and
refuses before activation. The regression preserves those default bytes and
keeps cleanup direction. An exact package-owned default replacement/cleanup
repair is needed before native setup can be qualified. This increment does not
silently adopt that file or weaken private configuration checks. The genuine
public default fixture and digest are documented beside the tunnel fixtures.

Remaining release boundaries include this package-default repair, native Linux
systemd/proc/cgroup/exec and durability validation, remaining auxiliary removal
and historical publication/certificate paths, retained Rust ELF/build metadata,
dual-architecture musl/bootstrap/workflows, and exact packaged live/Karing
qualification. No in-place Go-to-Rust migration or publication is enabled.

Final validation of this composition passed **470 product tests**, **8 offline
packaging tests**, format, strict all-target Clippy and a Mac debug build under
umask 077. Five mutation checks were caught: omitted same-length probe digest
verification, an extra admitted setup checkpoint, omitted fresh reviewed
prerequisite verification, reversed recovery selection, and cleanup incorrectly
requiring missing Owner prerequisites. Every mutated source was restored byte
for byte and the final integrated suite passed afterward. Evidence is under
`.scratch/acceptance/rust-tunnel-compose/`. The default-package configuration
regression is an expected refusal, not successful native installation. Native
Linux, systemd/cgroup/process, actual probe/traffic, installed-package and exact
release qualification remain unperformed.


## Pinned package-default configuration repair

The genuine pinned amd64 DEB carries a public 635-byte root:root 0644 conffile.
The old Standard observer refused it immediately after package installation,
before it could publish the journal-bound private configuration. A regression
using those exact bytes failed with `Refused` before this repair and now reaches
`SetupComplete` with the exact intended root:sing-box 0640 file. The tunnel fixture
also reaches local Running while correctly reporting public VMess connection
pending; its loopback fixture supplies no working public route.

`package_acquisition/default-config.json` contains only that public package data,
SHA-256 `4da8152e6cc1b50b1eaa4ff5606510aeb6d3f6a6a5c91614d4b2c0ea9a2b1bde`.
The existing full pinned-DEB streaming check now also proves the unique member's
exact bytes, root UID/GID, regular type and 0644 mode. Recognition requires the
protected current schema-1 journal with the exact package identity, configuration
hash, public IP and lock provision; only Service masked through State directory
created is eligible. A currently installed package must independently claim the
fixed conffile path through dpkg-query and retain the existing package/account/unit
proofs. An absent package is allowed only at the already-authorized purge/config
cleanup interval, including purge success before checkpoint synchronization.
No default is adopted before an authorized package attempt or after private
configuration publication/activation, including an already-staged private
publication checkpoint. Incomplete staged bytes remain unproven and are
preserved/refused; digest-only offline recovery cannot authenticate a partial
secret file.

Replacement uses a fixed descriptor-relative helper: prove the default and its
one-link inode/group, create or prove the exact private staged bytes/group/mode,
sync the stage, recheck both identities, rename over that exact known default,
and sync the file and parent. A visible target before journal synchronization is
synced on retry. Cleanup recognizes only this exact default or the recorded
private target/stage and never recreates the public source. Foreign, changed,
symlinked, hardlinked, wrong-mode/group, unclaimed or stale-journal files remain
untouched. Ordinary protected reads and private configuration requirements were
not relaxed. This repair does not add default adoption to Complete removal;
pre-configuration residue uses Finish cleanup. Completed private installations
retain their existing Complete removal behavior.

Fixture tests cover before/after-rename interruption, exact-stage retry,
digest-only offline cleanup, before/after-purge interruption, missing checkpoint,
stale authority and foreign-file preservation. Test package runners explicitly
select absent-conffile or genuine-default profiles; no real package or service is
executed. Native public/effect gates remain closed. Native Ubuntu/systemd/proc/
cgroup/durability checks, remaining auxiliary/historical paths, retained Rust
build metadata, dual-architecture packaging/bootstrap/workflows and exact live
release/Karing qualification remain separate work.

Final repair checks passed **481 product tests**, **8 offline packaging tests**,
format, strict all-target Clippy and the Mac debug build under umask 077. Five
mutation checks caught omitted exact bytes, phase restriction, package ownership,
current journal and staged-publication checks; mutated source was restored
byte-for-byte before final integrated validation. Evidence is under
`.scratch/acceptance/rust-package-default/`. Go reference source remains unchanged.
These results do not establish native Linux, real package/systemd, actual VMess
traffic, power-loss durability or exact candidate release qualification.


## Current auxiliary removal and exact-finisher preparation

`StandardRemovalHost` now handles the pending HTTP Client Identity subscription
artifact, serving-state candidate and fixed serving startup-upgrade publication.
Each canonical/staged or exact two-link publication must match the recorded
artifact digest or exact state/unit bytes, root ownership, mode, group and safe
parents. The ordinary private readers still reject hardlinks. Unknown artifacts
without rotation authority are refused. Cleanup can reopen after each completed
file step, never publishes a source/target configuration, and preserves committed
removal direction when later serving shutdown fails. Historical HTTPS remains
unavailable; no certificate/CA/account operation was added.

`with_tunnel` composes the existing `Connector` with the current HTTP auxiliary
runtime. Native Owner construction now supplies that composition. Dedicated
removal authenticates the recorded process digest and loaded unit properties,
retains the original Owner lock and cancellation, and needs no Owner token,
cloudflared file or external connection. It stops only `sbxr-tunnel.service`,
unlinks only the recorded exact unit/stage/link, and reloads. It preserves the
Owner token/binary, unrelated connector configuration/services and other target
links. A missing unit with a still-cached loaded route is admitted only for
removal when stopped and all loaded properties exactly match; this supports an
interrupted final reload. Ordinary inspection/start remains strict. Foreign
units, stages, links, drop-ins, processes and ambiguous routes remain refused.

`RestoredFinisher` now uses one tested fixed command builder for its retained
exact executable descriptor, zero arguments, cleared minimal environment,
interactive stdio and root working directory. It revalidates journal and inode
before preparation. The native path retains the descriptor through exec path
resolution and explicitly releases the private store and host exclusion before
takeover. Tests prepare commands for all ten preserved Go recovery fixtures and
current tunnel authority without executing their artifacts. This strengthens
execution preparation; actual Linux exec remains unvalidated and gated.

The production public/effect gates remain closed. This increment does not add
historical HTTPS/renewal removal, arbitrary partial-file deletion, a Go-to-Rust
migration, publication/certificate recovery writers or packaging workflows.
Native systemd/cgroup/process behavior, physical crash durability and exact
packaged live qualification remain separate work.

Final validation passed **492 product tests**, **8 offline packaging tests**,
format, strict all-target Clippy and the Mac debug build under umask 077. Six
mutations were caught: missing artifact/process digest checks, widening the
stopped cached-unit exception to ordinary inspection, omitting finisher authority
recheck/environment clearing, and broad connector disablement. Source was
restored byte-for-byte before final integrated checks. Evidence is under
`.scratch/acceptance/rust-aux-remove/`; temporary fixture roots were cleaned.
Go reference source is unchanged. These checks do not qualify native cleanup,
Linux exec, outside traffic or a stable release.


## Retained HTTPS cleanup and interrupted publication

The new `host::historical` adapter reads the existing validated schema-2
HTTPS/renewal/retirement authority; it writes no new enablement, migration,
certificate issuance or renewal attempt. Standard removal now composes its exact
asset plan with the existing retained Owner/package guards, protected effects
and durable removal checkpoints. It removes owned active renewal entrypoints,
reloads, proves the official Certbot renewal route, then removes matching evidence
and coordination locks. Retirement removes only recorded quarantined bytes and
the owned lineage after firewall cleanup. Shared CA accounts, official timer,
Certbot/snapd, unrelated lineages, hooks, units and data remain unchanged.
Expired retained certificate bytes remain removable by ownership/hash proof;
expiry does not resurrect a subscription or prevent cleanup.

The proof includes strict bounded receipt decoding (duplicate/unknown-key
refusal), independent recorder identity, completed-hook order/outcome, unfinished
attempt process/boot/start-time checks, fixed snap publisher/version/route and
calendar observations, hook/configuration safety, exact legacy 80/8443 firewall
commands, and fresh quiescence. Current and known historical serving-unit bytes
are recognized only by removal; ordinary serving startup still requires the
current unit. Changed bytes, unsafe metadata/parents, extra archive generations,
unknown staging and foreign resource names refuse without erasure. Cleanup can
reopen after individual file/directory steps and never reverses removal direction.

Historical exclusion retains the three Certbot POSIX locks and, where recorded,
renewal admission/writer flocks. It checks both the current pathname/parent and
the held descriptor. Error release removes only its own newly created empty,
unchanged lock in the original proved namespace; pre-existing locks and changed
or renamed resources survive. Intentionally lent `HostLock` authority is unchanged.

`HistoricalHttps::select_published` selects all four matching canonical live
links, enforces generation direction and recorded hashes, verifies fullchain
composition, key correspondence, IP identity, trust and time, and returns a
redacted sealed proof. Native selection uses bundled public trust/current time;
fixture roots/time cannot authorize native publication. Existing inert PEM
fixtures are reused, with no certificate generated or issued. The certificate
state publisher requires an already recorded activation/repair source and target,
unchanged canonical ownership and exact staging. It retries before/after rename
with both directories synchronized, preserves independent credentials, and
leaves the operation checkpoint pending. It does not start TLS or clear an
unverified activation. Filesystem publication tests explicitly separate this CAS
boundary from cryptographic selection; a genuine native public-IP positive TLS
publication fixture remains absent.

Client Identity Finish now accepts only a canonical staged exact successor of
an already canonical operation. Review/read never promotes it. Crossing staged
revocation requires fresh startup routes and every shutdown proof; clearing a
staged completion requires fresh selected-subscription and running-configuration
proofs. Foreign/changed stages, a staged first authorization with no canonical
operation, stale reviews and source restoration after revocation remain refused.
The protected Host and shared Owner bridge use the same reviewed retry path.

Historical TLS preparation/serving/restart and the activation, repair, credential
rotation and renewal recorder/hook Owner flows are still absent. Unfinished
transport migration also refuses explicitly; current clean-install policy adds
no automatic migration. Those are feature gaps, not native validation passes.
The new certificate state publisher alone does not complete such a journey.
Production public/effect gates remain closed.

Validation evidence for this increment is retained under
`.scratch/acceptance/rust-historical/`. Final validation passed **515 product unit/integration tests**, **one compile-fail
doctest**, **8 offline packaging tests**, format, strict all-target Clippy and both
Mac debug builds. Nine targeted mutations were caught and exact source restored.
The created-lock mode, renamed-parent and empty-directory group regressions each
failed before their corrections and passed afterward. Temporary fixture roots
were cleaned. Mac fixture/process/loopback results do not establish
Linux systemd/proc/cgroup/exec, physical crash durability, a packaged installation,
outside traffic, Karing or release qualification.
