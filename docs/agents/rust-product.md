# Rust product and Owner journeys

This checkout builds the candidate executable from [Rust main](../../src/main.rs).
The public entry composes the [native Owner](../../src/host/owner.rs), [Proxy Installation](../../src/proxyinstallation/owner.rs) and [terminal](../../src/terminal.rs).
For a menu symptom, trace the selected journey through its host adapter and the consumer that observes its result.

| Journey | Product boundary | Where to check the handoff |
|---|---|---|
| M1 · Install and set up | [Bootstrap](../../tooling/rust-package/templates/install.sh.tmpl) writes the installed pair. [StandardInstallation](../../src/proxyinstallation/fixture.rs) owns the production setup checkpoints despite its filename. [Lifecycle](../../src/software_lifecycle.rs) reports installed status and checks qualified releases. | [Menu transcripts](../../tests/menu.rs), [Standard host tests](../../src/proxyinstallation/fixture_tests.rs), [optional tunnel](../../src/tunnel_setup.rs). Outside traffic requires separate observation. |
| M2 · Enable and import a subscription | [HTTP review and execution](../../src/proxyinstallation/subscription.rs) publish the protected artifact that the [private server](../../src/subscription_serving.rs) serves. | [Composed HTTP tests](../../src/proxyinstallation/subscription_tests.rs), [service tests](../../tests/subscription_serving.rs), [Karing readbacks](../../.github/scripts/native-receipts.py). |
| M3 · Rotate credentials | [Client Identity](../../src/client_identity.rs) and the [Subscription Link Credential](../../src/proxyinstallation/subscription.rs) have independent transitions. [Disclosure](../../src/proxyinstallation/disclosure.rs) uses its own output sink. | [Identity tests](../../tests/client_identity.rs), [disclosure tests](../../tests/disclosure.rs), [durable transitions](../../src/records/transitions.rs). |
| M4 · Restart serving | [Private roles](../../src/private_roles.rs) select the [runtime handoff](../../src/runtime_handoff.rs). [Service control](../../src/host/runtime/control.rs) and the [serving environment](../../src/host/runtime/serving_environment.rs) establish local state. | [Handoff tests](../../tests/runtime_handoff.rs), [serving checks](../../src/host/runtime/serving_tests.rs). Outside HTTP and proxy traffic require separate observations. |
| M5 · Remove or finish removal | [Removal](../../src/removal.rs) selects the legal direction. The [host adapter](../../src/host/linux/removal.rs) removes owned resources. A missing executable can require [bootstrap restoration](../../tooling/rust-package/templates/install.sh.tmpl) before a new menu can start. | [Removal tests](../../tests/removal.rs), [exact-finisher checks](../../src/host/restoration_tests.rs), [cleanup before terminal failure submission](../acceptance/http-subscription-live.md#terminal-failure-ends-candidate-authentication). |

The [acceptance procedure](../acceptance/http-subscription-live.md) defines outside and client evidence. The [release map](release-tooling.md) locates the operator and collector that consume it.

## Standard setup and build identity

Standard setup and recovery in this checkout use `src/proxyinstallation/fixture.rs` (`StandardInstallation<H>`);
`src/host/setup.rs` defines its narrow host contract. Native observations and
injected-root effects are in `src/host/linux.rs` and its small submodules; bounded
process transport is `src/host/process.rs`. Retained locks, direct TLS/bind
admission and fixed native command effects are `src/host/{locks,network,system}.rs`;
the public frontend requires the controlled native build and authenticated process admission, with no simulator fallback. `build.rs` retains the canonical structural `.sbxr.rust` statement through a
linker script for explicitly selected pinned Linux musl release builds;
`src/build_identity.rs` checks the loaded statement independently of authentication.
Identity generation, structural
release inspection and offline Sigstore authentication have separate modules and
adjacent/integration tests. `tooling/rust-package/` owns the Rust repository packaging/public-proof CLI,
byte-preserved standalone bootstrap, native musl builder, four-asset assembly and
local source snapshot/manifest verification. Its `linux-validation.md` lists
prepared-builder commands. The workflow definitions build native archives once
per architecture, reuse them for independent assembly checks and retain signed
qualification/manual publication gates. No workflow/provisioning follows from
local fixture success.

## Release and process admission

Exact installed-byte acquisition is `src/release_acquisition.rs`; its
`candidate.rs` submodule authenticates the signed empty-source HTTP candidate
manifest and keeps candidate archive/installed authority distinct from stable
proof. It shares bounded asset/archive/ELF verification with the stable route;
`host::admission` binds real delivery proofs to the protected/current executable
and loaded Rust statement, and guards selected Owner journeys. The sealed
`InstalledEvidence` interface retains candidate/stable roles throughout concrete
runtime effects and handoff. `host::admission_private` owns the separate offline
private exact-pair/role/start-lock proof; it never performs release acquisition.
Public entry requires genuine delivery/current-process admission; private startup keeps its exact offline pair/role/lock checks. The private-root, fixed-route
`release_https::CandidateGatewayTransport` composes the retained qualification
gateway without changing public/system TLS trust or artifact authentication.
Archive decoding is `src/release_archive.rs`; bounded HTTPS is `src/release_https.rs`. Genuine
public proofs and the repository evidence example cover actual acquisition.

## Private runtime and package inputs

Runtime-start descriptor lending and serving composition are `src/runtime_handoff.rs`.
Concrete proxy-start checks, protected material and scoped cutover publication are
`src/host/runtime/{proxy,material,gate}.rs`; `src/host/runtime_io.rs` provides bounded
Unix transport. The one-use consume effect is `src/host/filesystem/runtime.rs`.
Concrete serving/sandbox observations and fixed service control are
`src/host/runtime/{serving,serving_environment,control}.rs`. Private native
composition is `src/host/runtime/native_dispatch.rs`, with joined signals in
`shutdown.rs`; the public Owner shares that stop across acquisition, transaction,
probe and bounded child contexts, and `src/host/input.rs` provides cancellable
terminal I/O without changing terminal or descriptor settings. `src/private_roles.rs` owns exact argument dispatch. Development
builds fail closed before native effects. Tests use explicit injected roots,
process/command observations and real local sockets; packaged and outside observations are recorded per candidate in the
[acceptance reports](../acceptance/reports/README.md). Pinned key/DEB acquisition is `src/package_acquisition.rs`, consumed
by `src/host/linux/material.rs`.

## Subscription, identity and disclosure

HTTP Owner enable/rotate/repair/recovery is `src/proxyinstallation/subscription.rs`
with exact protected effects in `src/host/subscription{,/material,/effects}.rs`.
Client Identity orchestration is `src/client_identity.rs`, shared Owner bridge
`src/proxyinstallation/identity.rs`, and protected injected host
`src/host/identity{,/effects}.rs`. Publication recovery is
`src/host/filesystem/subscription.rs`; ordinary protected reads still reject all
hardlinks. The Owner tests in `src/proxyinstallation/subscription_tests.rs` compose
real local HTTP, locks and cutover consumption with injected system effects.
The injected constructors reject `/`; typed native constructors now use
`src/host/owner_runtime.rs` and its command/observation/probe/effect submodules.

## Menu and lifecycle composition

The composed Interface is `src/proxyinstallation/owner.rs`; native authenticated
sources are `src/host/owner.rs`. Only one selected journey retains its writer and
prepared authority. `src/host/owner.rs` composes zero-argument native Owner/lifecycle dispatch behind
the controlled native build and genuine delivery/current-process admission. `src/host/entry_input.rs` reads only the
retained fixed protected qualification handoff; full absence selects stable and
partial/stale input refuses. It binds real staged/delivered candidate proofs and
retains input freshness through the process guard; no environment/CLI switch is
supported. `src/software_lifecycle.rs` and
`src/host/lifecycle.rs` own Status/Check, clean-install Update refusal and reviewed
exact-finisher recovery; `src/host/filesystem/lifecycle.rs` is its read-only lock
probe. `terminal::run_with_lifecycle` supplies the two-module menu. Native public
Owner effects require the concrete retained admission and exact ownership. Fixed cgroup
virtual reads use `src/host/filesystem/runtime.rs` without changing ordinary
record/file validation. `src/disclosure.rs` and `src/tunnel_setup.rs` hold the
completed orchestration modules. Disclosure now uses the protected Host in
`src/host/disclosure.rs`, independent runtime proofs in
`src/host/owner_runtime/disclosure.rs`, and streaming Interface bridge in
`src/proxyinstallation/disclosure.rs`. The terminal uses an explicit output sink;
client secrets never enter Review details.

## Optional tunnel and package defaults

Native tunnel composition is
`src/host/linux/tunnel.rs`, with independent observations in
`src/host/owner_runtime/tunnel.rs` and the shared frontend in
`src/proxyinstallation/tunnel.rs`. `src/package_acquisition/probe.rs` derives the
probe executable proof from the full pinned DEB without extraction/execution.
The fixed initial setup start in `ServiceController` is separate from ordinary
private startup. The exact pinned public conffile is recognized only at
pre-configuration setup checkpoints by `src/host/linux/package_default.rs`; its protected atomic private
replacement is `src/host/filesystem/package_default.rs`. Native gates remain
conditional on genuine admission; Linux and packaged installation qualification remain separate.

## Removal and historical authority

Concrete Standard removal/finalization is `src/host/linux/removal.rs`, with the
model in `src/removal.rs` and shared Interface bridge in
`src/proxyinstallation/removal.rs`. Exact missing-member restoration is `src/host/restoration.rs`, using
`AuthenticatedArchive` and the protected prefix-staging helper in
`src/host/filesystem/restoration.rs`. It now includes a native unreleased constructor and sealed exact-inode finisher
takeover under its exact-finisher admission checks. Current HTTP/startup and
Client Identity artifact removal is
`src/host/linux/removal/{auxiliary,client_subscription}.rs`; dedicated connector
removal composes the same runtime in `src/host/linux/removal/tunnel.rs`, with
local native runtime
observations in `src/host/owner_runtime/removal.rs`. Digest-only cleanup/removal
material is in `src/host/linux/material.rs`; it never downloads or regenerates
secrets. Retained HTTPS/renewal cleanup and certificate selection/state publication are
in `src/host/historical/`; descriptor-relative lineage/lock handling is
`src/host/filesystem/historical.rs`, composed into removal by
`src/host/linux/removal/historical.rs`. Native retained renewal route observations
are `src/host/owner_runtime/historical.rs`. Legacy unit recognition is removal-only;
ordinary startup stays strict. Historical TLS serving/activation/renewal Owner
flows and unfinished transport migration remain explicitly unavailable. Exact restored-finisher command preparation reuses the retained authenticated descriptor; actual native
exec remains unqualified. Use the [Rust acceptance matrix](../rust-acceptance.md) for scope and the
[revision history](../rust-rewrite.md) for the evidence behind earlier increments.
