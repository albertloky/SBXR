# Rust clean-install acceptance matrix

Authority: ADR-0028, ADR-0026 in its historical scope, CONTEXT.md and the current
Software Lifecycle/Proxy Installation module contracts. This matrix supersedes
older Rust handoff checklists that treated every historical Go feature as a new
Rust release requirement. Local implementation/checks are distinct from native
and exact-candidate deployment qualification.

## Scope reconciliation

Current supported creation is clean install, Standard VLESS/REALITY, optional
Owner-provided dedicated VMess tunnel, HTTP subscriptions, independent client/link
rotation, disclosure/compromise marking and reviewed removal. New software Update,
in-place Go-to-Rust upgrade, automatic transport conversion, new HTTPS enablement,
certificate issuance, ACME calls and new renewal integration are intentionally
excluded. Do not implement them merely for line-by-line historical parity.

Retained authority must remain strictly readable, secret-safe and preserved.
Applicable unfinished setup, HTTP/client-identity changes and removal keep their
proved directions. Historical HTTPS/retirement resources require exact owned
cleanup; the existing exact-release removal-finisher restoration path is retained.
Legacy running TLS and its renewal/activation mutation are not offered by the new
clean-install Rust Owner. The original exact release handles installations the
new release cannot safely own; refusing them must preserve every byte and must
not claim completion or silently convert authority.

Historical Software Lifecycle rollback/forward completion remains required in
its original exact Go release; that implementation is preserved unchanged. The
Rust release declares no incoming sources, starts no Update Record, and offers no
Go-to-Rust takeover of those transactions. It detects their residue and refuses
normal proxy actions and mutation, preserving all bytes for the original exact
release. This is an explicit unsupported Rust route, not completed transaction
recovery. Supporting those transactions in a future Rust compatibility claim
would require additional implementation and tests; it is not a reason to add CA
issuance or a new upgrade writer to this clean-install release.

## Finite matrix

| Path | Intended supported result | Explicit refusal / exclusion | Qualification still needed |
|---|---|---|---|
| Clean install / Standard | Verified installed pair; Review/default-No; cleanup before commitment, forward setup afterward | Remaining foreign installation, wrong platform/root/package/configuration, unqualified native effects | Ubuntu package/systemd/firewall and exact packaged installation |
| HTTP subscriptions | Enable, rotate, repair, ordinary restart and interrupted recovery; independent bearer and Client Identity | New HTTPS/ACME/renewal integration; stale/foreign authority and unsafe publication | Actual native HTTP/firewall/cgroup and outside/Karing behavior |
| Client Identity / disclosure | Sequential VLESS+VMess rotation; source never restored after revocation; confirmed disclosure | Unknown keys/identity, stale review, unproved shutdown, foreign target | Native revocation, sessions and disclosure qualification |
| Tunnel | Protected Owner token/binary, dedicated connector, ordered WS/TLS/authenticated VMess probe; pending distinct from verified | Shared connector adoption, account/DNS mutation, direct-traffic fallback | Actual Linux connector/cgroup/WS and VMess-only outside egress |
| Removal / retained authority | Exact ownership, forward-only retry, current artifacts, active/retired HTTPS cleanup and exact finisher restoration | Foreign resources; new conversion writer; unsupported historical states must remain explicit | Native removal, actual restored-finisher exec and crash durability |
| Lifecycle Status / Check | Protected local pair/lock/transaction inspection; authenticated qualified Latest; same-release current; newer clean-install refusal | No Update action; unverified release, concurrent change and incomplete pair | Current Linux observation and public acquisition qualification |
| Lifecycle Recover | No-op when Ready; review/default-No and exact committed-removal finisher restoration, preserving proxy journal | Unknown/unproved direction, legacy Go update transaction (requires its original exact release), stale review or conflicting pair | Native exact-inode takeover; legacy transaction mutation is not offered by this Rust release |
| Public entry / release | Zero arguments compose the existing Owner and lifecycle; private-role argument contract stays fixed | Unsupported/unqualified native entry never falls back to simulation | Native current-source verification of cancellation and retained ELF identity, actual builds for both musl architectures, execution of the integrated bootstrap/CI definitions and five exact-candidate live journeys |

The implementation and validation status of this increment is recorded in the
Rust handoff and `.scratch/acceptance/rust-entry/`. Production dispatch remains
closed. No source fixture, simulated result or Mac build is a deployment pass.

## Increment evidence

The native/lifecycle composition increment passed 531 product unit/integration
tests, one compile-fail doctest, 8 offline packaging tests, format, strict Clippy
and Mac builds. Nine targeted mutations were caught. The real-executable
simulation-fallback regression failed before correction and passed afterward.
All temporary roots were cleaned. Evidence: `.scratch/acceptance/rust-entry/`.
These checks cover implemented paths and explicit refusals; none qualifies
native Linux effects, actual finisher exec, outside traffic, Karing or a release.

## Cancellation/build-identity increment (base 795006b)

Native Owner/private entry now shares scoped cancellation with acquisition,
transaction, probe and bounded child adapters. Fixture interruption/recovery and
late-approval/disclosure refusal are tested; retained lock lifetime is preserved.
The controlled pinned Linux-musl release build now emits canonical retained and
loaded Rust metadata, and structural package verification checks the unchanged
compiler/trailer/ELF bindings. Signature/provenance authentication is independent.
Both public and private qualification gates remain closed.

543 product tests, one compile-fail doctest, 8 packaging tests, 17 installed-tool
compiler/linker/package checks and 7 mutations passed, followed by the final
scoped checks/Clippy/build after source restoration. The linker inputs are inert
no-stdlib/assembly fixtures with synthetic metadata, not production SBXR builds.
Current-source GNU cross-check stopped in ring because `x86_64-linux-gnu-gcc` is
absent. Musl targets/cross-compilers are also absent. Linux signal/systemd/cgroup,
full native static builds, bootstrap/workflows and exact-candidate live journeys
remain unqualified. Evidence and the finite remaining checklist are in the latest
Rust handoff increment and `.scratch/acceptance/rust-cancel-build/`.

## Local release integration (base 7bf9437)

Rust now generates the byte-preserved standalone bootstrap and constructs the
clean-install-only four-asset set. New construction requires two strictly proved
Rust executables and the complete exact bootstrap; read-only historical Go
verification retains its pinned proof and original digest binding contract.
Public/tagged release verification uses real existing Sigstore authentication,
never a structural/test shortcut. Both workflow matrices select matching native
musl builders, then reuse the archives for independent asset checks. Signed
qualification, cleanup, failure handling and manual stable publication remain.

These are local code/configuration results. Current native gates are still
closed. Actual musl builds, Linux runtime/systemd/cgroup behavior, candidate-gateway
authentication/qualification activation, Rust live-driver compatibility and the
five exact-candidate HTTP journeys are not established by fixture tests or YAML
syntax checks. Source-only archive creation and manifest verification are local;
transfer/upload remains separately authorized. See the latest handoff increment.


## Native driver framing inspection (base 98e0dc43)

The parent reports all 556 distinct automated GNU cases for `98e0dc43` passing on
an unprivileged disposable Ubuntu 24.04 runner (303 library, 252 integration and
one compile-fail doctest). The approved CI run also reported both native musl
builds/static ELF/package checks. Its later closeout verification was blocked by
the platform and was not retried here. These named-source results are automated
validation, not an authenticated root installation or an exact-candidate live pass.

A concrete retained-driver mismatch was reproduced locally: native Rust frames
and lifecycle labels could not be consumed, and interrupted setup confirmation
prompts differed. Native presentation now repeats the retained frame, preserves
plain status fields, emits lifecycle result codes, uses Check/Recover labels and
the details continuation, and matches the two setup recovery prompts. Explicit
fixture/unavailable labels and all production/private gates remain unchanged.
The finite parser checks do not run the driver's process controller or native
host effects. See the latest Rust handoff for exact local checks.

The first authentic packaged Rust journey is still blocked by missing source
composition, not by a need to repeat the already reported unit suite:

- `release_acquisition::Metadata::decode_exact` rejects `sbxr_qualification`.
  Existing candidate-manifest Sigstore verification does not validate its
  approval/decision/release/support semantics or issue authenticated candidate
  installation authority. Candidate delivery must remain distinct from a stable
  Acceptance Record. Do not synthesize a live pass to satisfy the public route.
- `release_https::HttpsTransport::new` uses embedded public roots. The retained
  qualification gateway installs a temporary system CA and host routes, so that
  transport is not currently compatible with Rust acquisition. A reviewed,
  protected candidate transport/trust composition is missing; replacing strict
  TLS or artifact checks with a fixture verifier/URL override is not a solution.
- `require_live_adapter` unconditionally refuses; both public Owner entry and
  private startup reach it. Implemented adapters cannot execute through the
  packaged public/private entry until the real authentication and native startup
  prerequisites are composed and qualified. Removing that refusal alone is unsafe.
- The Standard failed-review branch still returns directly after its safety
  message. It lacks the retained driver's refusal code plus Retry/Back/Cancel
  protocol. The repaired read-only frames and declined recovery checks do not
  establish that unimplemented branch or an actual applied setup/recovery pass.

After those source paths are complete, prepare one reviewed exact clean-install
candidate with all four asset digests, authentic workflow/signature/native proofs,
a signed empty-source HTTP attempt, a fresh disposable amd64 host inventory and a
working exact-release recovery/cleanup route. Concrete permission must name the
host/candidate and root package/service/firewall/prerequisite changes, disposable
client credentials and revocation/disclosure, outside-client checks and complete
cleanup. Optional tunnel/Karing/account or existing working-proxy changes are not
implied. No such live action, source transfer, signing or publication occurred in
this inspection.
