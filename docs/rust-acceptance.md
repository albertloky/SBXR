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

## Signed-candidate semantics and failed setup Review (base 01f1bd4)

Candidate delivery now has a separate authenticated acquisition result. Its only
constructor verifies the exact raw manifest through the existing pinned-root,
issuer/workflow, DSSE subject, Rekor and observer-time verifier. It then validates
approval, ordered decision hashes, selected release/commit, all four asset proofs,
native evidence paths, the current empty-source HTTP attempt and byte-identical
candidate index. Downloads still pass bounded digest, archive, ELF, retained
metadata and installed/current-byte checks. New candidate construction requires
Rust. Neither a structural inspector nor a candidate result can become stable
installation authority; stable acquisition continues to require the qualified
Acceptance Record and native release-service proofs.

Failed Standard setup Review now emits the retained refusal code and offers
Retry/Back/Cancel. Retry performs a fresh Review; Back returns to connection
selection; Cancel/EOF cannot approve effects. Repeated refusal, stale authority
and interrupted input/response are covered by offline regressions. All public
and private production gates and the public TLS root store remain unchanged.

## Protected candidate gateway TLS (base 275c0c6)

`release_https::CandidateGatewayTransport::from_retained_gateway` now takes an
independently reviewed CA-file SHA-256 and reads only
`/root/sbxr-qualification-v3/ca.crt` on Linux/root. The snapshot requires safe
nonsymlink parents, a 0700 root-owned staging directory and one bounded regular
single-link 0600/0644 CA file, with inode/metadata/namespace and digest checks.
Its private client uses that one explicit anchor, normal certificate/hostname/
signature/time verification and the exact retained `127.0.0.2:443` route with
`api.github.com` as URL/SNI identity. It permits only the fixed SBXR Latest path
and asset IDs 1–4, rejects every redirect and unrelated probe, and cannot outlive
the original selection deadline. Existing HTTP bounds, cancellation and all
artifact authentication stay mandatory. Public roots, system trust stores and
public/private activation gates are unchanged. Tests use in-memory TLS and
protected temporary files; no listener or real gateway/NAT route is exercised.

## Evidence-bound native admission (base c084520)

Native admission now has two real acquisition constructors. Stable delivery keeps
qualified Acceptance Record/native signature checks; candidate delivery keeps the
explicit reviewed CA pin, manifest signature/approval and four-asset bindings.
Both produce `NativeAdmission` only after binding the protected Installed Record
raw bytes/inode, exact protected executable, the same kernel current executable
inode/bytes, and the canonical loaded Rust statement. The statement remains a
structural check in addition to cryptography. Record, namespace, metadata, bytes,
transaction absence and cancellation are rechecked through retained descriptors.
A copied executable with identical bytes cannot substitute for the current inode.

The sealed `InstalledEvidence` boundary preserves `DeliveryRole` and permits the
existing concrete effect adapters to carry either genuine delivery role or the
bound process proof. It cannot be implemented by an external structural record.
`NativeOwnerSources` requires the concrete native proof; every selected journey
retains a fresh process guard before Review, Execute and disclosure. Runtime file
checks and both creation/acceptance of one-use service handoff recheck the bound
proof. Existing owner/borrower lock lifetime and recovery direction remain intact.

Private startup uses a distinct `OfflinePrivateAdmission`, never delivery trust.
It rechecks the protected exact pair/inodes, loaded Rust metadata, supported role,
cancellation and existing startup lock. Serving derives its actual fixed cgroup,
kernel execfn and complete sandbox observations without /proc or online release
acquisition. Proxy/provision roles additionally retain their current executable
snapshot. Startup binds the proof to the exact role/root/lock; an Owner-held lock
without its lender cannot silently become ordinary-start authority. This local
private proof cannot be used as authenticated acquisition evidence.

Both `require_live_adapter` and private released-build activation still refuse.
The explicit repository entry composition
`run_public_delivery_unreleased(..., PublicDelivery::Candidate { reviewed_ca_sha256 })`
uses real candidate admission behind the same gate. Normal zero-argument entry
still selects stable delivery; no ambient/environment candidate selector was
introduced. Binding the independently reviewed candidate input to the actual
zero-argument qualification invocation remains a precise coordinator/driver
integration prerequisite. A different wrapper executable cannot stand in for
qualification of the exact packaged SBXR executable.

Before any activation, obtain a complete genuine signed current Rust candidate
manifest/artifact positive set and validate the current source on Linux. The
protected candidate invocation, actual gateway HTTP/NAT, public/private systemd
startup, cgroup/handoff and recovery behavior need exact-candidate qualification.
These prerequisites cannot be replaced by fixture positives, a build marker,
removing a refusal or converting candidate delivery into stable qualification.

The existing genuine candidate bundle verifies, but its matching raw manifest
(digest `0add26026bed41b9bebd770353e6d4249cf30bbf3090c618e59f619b0c30d476`)
is absent from the preserved fixtures. Semantic positives use clearly untrusted
synthetic JSON; the public acquisition refusal uses the genuine signature and
wrong raw bytes and proves no asset GET. A complete positive signed candidate
acquisition remains unverified until exact matching signed manifest/artifact
bytes are available. No test-only signature constructor was added. This is an
evidence prerequisite, not permission to sign a new candidate. The allowed public
release-asset inventory found the signature's source at failed v2.0.12/v2.0.13;
all 189 advertised releases contained no qualification-manifest asset. Those
public notes point to old Actions artifacts, which were not fetched. Searches of
tracked fixtures and the relevant local acquisition evidence found no matching
raw manifest. These findings establish absence from the checked sources, not
absence everywhere. The old signature alone cannot authorize a current Rust
clean-install manifest or turn those failed releases into qualified releases.

After those source paths are complete, prepare one reviewed exact clean-install
candidate with all four asset digests, authentic workflow/signature/native proofs,
a signed empty-source HTTP attempt, a fresh disposable amd64 host inventory and a
working exact-release recovery/cleanup route. Concrete permission must name the
host/candidate and root package/service/firewall/prerequisite changes, disposable
client credentials and revocation/disclosure, outside-client checks and complete
cleanup. Optional tunnel/Karing/account or existing working-proxy changes are not
implied. No such live action, source transfer, signing or publication occurred in
this inspection.
