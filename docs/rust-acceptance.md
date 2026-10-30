# Rust clean-install acceptance matrix

Authority: ADR-0028, ADR-0026 in its historical scope, CONTEXT.md and the current
Software Lifecycle/Proxy Installation module contracts. This matrix supersedes
older Rust handoff checklists that treated every historical Go feature as a new
Rust release requirement. Local implementation/checks are distinct from native
and exact-candidate deployment qualification.

Current native source composition is described in
[conditional native setup](#conditional-native-setup-base-594add9). The earlier
closed-gate increment notes describe their named revisions, not an additional
current blanket refusal. Conditional code availability does not authorize or
establish a live installation or stable release.

## Latest dated qualification closeout

[q205 administrative cleanup, 2026-10-30](acceptance/reports/q205-administrative-cleanup-2026-10-30.md) records completed approved cleanup of the failed build205 installation, exact candidate/source/CI bindings, preservation limits and remaining qualification work. It supersedes older missing-evidence/residue statements only where the dated observations resolve them; it does not qualify build205 or change the finite scope below.

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
| Clean install / Standard | Verified installed pair; Review/default-No; cleanup before commitment, forward setup afterward | Remaining foreign installation, wrong platform/root/package/configuration, unauthenticated or stale native effects | Ubuntu package/systemd/firewall and exact packaged installation |
| HTTP subscriptions | Enable, rotate, repair, ordinary restart and interrupted recovery; independent bearer and Client Identity | New HTTPS/ACME/renewal integration; stale/foreign authority and unsafe publication | Actual native HTTP/firewall/cgroup and outside/Karing behavior |
| Client Identity / disclosure | Sequential VLESS+VMess rotation; source never restored after revocation; confirmed disclosure | Unknown keys/identity, stale review, unproved shutdown, foreign target | Native revocation, sessions and disclosure qualification |
| Tunnel | Protected Owner token/binary, dedicated connector, ordered WS/TLS/authenticated VMess probe; pending distinct from verified | Shared connector adoption, account/DNS mutation, direct-traffic fallback | Actual Linux connector/cgroup/WS and VMess-only outside egress |
| Removal / retained authority | Exact ownership, forward-only retry, current artifacts, active/retired HTTPS cleanup and exact finisher restoration | Foreign resources; new conversion writer; unsupported historical states must remain explicit | Native removal, actual restored-finisher exec and crash durability |
| Lifecycle Status / Check | Protected local pair/lock/transaction inspection; authenticated qualified Latest; same-release current; newer clean-install refusal | No Update action; unverified release, concurrent change and incomplete pair | Current Linux observation and public acquisition qualification |
| Lifecycle Recover | No-op when Ready; review/default-No and exact committed-removal finisher restoration, preserving proxy journal | Unknown/unproved direction, legacy Go update transaction (requires its original exact release), stale review or conflicting pair | Native exact-inode takeover; legacy transaction mutation is not offered by this Rust release |
| Public entry / release | Zero arguments compose the existing Owner and lifecycle; private-role argument contract stays fixed | Unsupported host/build or unproved/stale pair never falls back to simulation | Native current-source verification of cancellation and retained ELF identity, actual builds for both musl architectures, execution of the integrated bootstrap/CI definitions and five exact-candidate live journeys |

The implementation and validation status of this increment is recorded in the
Rust handoff and its named run directories. Production dispatch requires the
controlled native build and the applicable authenticated/local startup proof.
No source fixture, simulated result or Mac build is a deployment pass.

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
The initial explicit repository composition was not sufficient for the actual
zero-argument executable. The protected handoff composition below closes that
source wiring gap without changing those activation gates. A different wrapper
executable cannot stand in for qualification of the exact packaged SBXR executable.

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

## Protected zero-argument selection (base f767df3)

The actual `main` → `run_public_unreleased` path now reads the existing fixed
`/root/sbxr-qualification-v3` handoff. No new command, argument, environment switch,
CA path or selector file was introduced. Genuinely absent staging selects ordinary
stable delivery; any existing incomplete, expired or unsafe staging refuses rather
than falling back to stable. Development/native activation still refuses first.

The seven required inputs are `qualification-manifest.json`,
`qualification.bundle`, `ca.crt`, `staging-owned`, `transport-owned`, `deadline`
and `runtime-deadline`. The manifest must describe the approved current
clean-install HTTP scope, one candidate identity/sequence and all four assets;
its workflow run/attempt must match the staging marker. The transport marker is
empty. Canonical epoch deadlines must keep the original six-hour bound and
60-second early runtime cutoff. Absolute and monotonic checks prevent renewal of
the loaded deadline. Root ownership, safe nonsymlink parents, 0700 staging,
single-link regular files, exact contract permissions, bounded bytes and retained
inodes are mandatory. Only CA and staging marker allow 0644 as well as 0600,
matching the retained producer; all other selected inputs require 0600.

Selection is untrusted structural data. Before candidate networking, the real
pinned Sigstore verifier authenticates the exact staged raw manifest and bundle.
The protected Installed Record must name that same full identity and sequence.
The fixed gateway then authenticates its own delivered manifest and all assets;
its raw signed manifest digest must equal the staged digest. The private TLS
client pins the selected CA bytes and keeps full hostname/certificate checks and
fixed destinations. The native process snapshot retains the selected handoff and
rechecks expiry/files/identity before existing guarded Owner effects. No unsigned
fixture or structural inspector can create installed/candidate authority, convert
candidate to stable or open a production gate. Software Lifecycle keeps its
existing qualified-stable discovery contract; candidate selection is not a stable
qualification or incoming-update authorization.

Offline fixtures cover absent/stale/partial/duplicate/unapproved/foreign input,
wrong identity/sequence/raw digest, cancellation, absolute and monotonic expiry,
unsafe links/permissions/parents, replaced identical-byte inodes, changed markers,
stale prepared actions and refusal of ambient/argument bypass. Synthetic semantic
positives select a source only; the unchanged genuine bundle rejects those
unsigned bytes. The missing genuine *current Rust* positive set and current-source
Linux/packaged qualification remain explicit prerequisites. No root handoff,
trust store, gateway, credential or service was changed by these checks.

### Frozen candidate preparation request, not authorization

1. Propose the exact frozen reviewed commit to
   `https://github.com/albertloky/SBXR.git`, `refs/heads/main`, only after a fresh
   ancestry/main-divergence review permits a normal fast-forward. Do not push to
   this isolated checkout's `origin`, which is the local retained Go checkout.
   A main push triggers `.github/workflows/verify.yml` native verification. Neither
   that push nor a workflow dispatch is authorized by local test approval.
2. The existing manual candidate workflow is `.github/workflows/candidate.yml`
   (`Construct qualified drafts`) on main, with fresh reviewed `b_tag`,
   `b_sequence` and canonical schema-v3 `v3_attempt`: empty incoming sources,
   clean-install HTTP support, all five required journeys and no exception or
   correction. Its exact four assets are `install.sh`, `release-index.json`,
   `sbxr-linux-amd64.tar.gz` and `sbxr-linux-arm64.tar.gz`. Bind native musl/static
   ELF checks, loaded build identity, index/installer/archive sizes and hashes,
   signed workflow/raw manifest and authentic native proofs to the same commit.
3. **This workflow has no preparation-only mode.** It creates tags/draft releases
   and assets; `sign` contacts the Acceptance VPS as root *before* keyless signing
   and attestation. `acceptance-vps` creates the protected handoff/ephemeral gateway
   keys and runs the retained root transport, including service, hosts/NAT and
   system-CA effects. Candidate failures now retain proposals and stop before burn
   signing, failed prerelease publication or unsigned draft/tag deletion; each needs a separate
   explicit action-time Owner decision under ADR-0032. Cancelling after signing is not
   an artifact-only boundary. Before dispatch, either review a separate bounded
   preparation-only change or obtain explicit permission for those exact combined
   effects. Stable publication remains a separate approved `stable.yml` dispatch.
4. Before any VPS root action, require current-source Linux checks and both native
   musl/package/bootstrap results, exact asset identities/digests, a reviewed fresh
   tag/sequence/attempt and baseline, an identified disposable Ubuntu 24.04 amd64
   host with inventory/SSH preservation and a working exact-release recovery and
   cleanup route. Signing currently requires root readiness *before* it can yield
   the complete current signed set; do not claim that set exists beforehand.
   Before enabling installation, additionally require the genuine signed positive
   set to pass acquisition/admission, reviewed narrow activation policy, protected
   input/CA/deadline agreement and exact-candidate private startup/cgroup/handoff
   qualification. Approvals must name root packages/hold, user/group/services,
   firewall/ports, temporary routing/trust/cutoff, disposable credentials and their
   revocation/disclosure, outside-client checks, applicable Karing observations
   and complete owned cleanup. Existing proxies and account/tunnel resources are
   excluded unless separately named.

No push/upload, CI dispatch, tag/release mutation, signing/attestation/burn,
VPS access, system trust/security/credential change or publication is performed
or authorized by this local increment. Stop source expansion at the frozen entry
increment; prepare the concrete approved candidate boundary before live work.


## Retained native setup guard (base f824c1f)

Native Standard and offline cleanup/removal factory arguments now require the
concrete `NativeAdmission`, rather than authenticated archive bytes alone. They
retain the existing process snapshot, including exact root, installed/current
file descriptors, raw record/inodes, loaded Rust identity, candidate handoff
freshness and cancellation. Native setup inspection rechecks that retained guard;
a copied Installed Record cannot replace it. The snapshot still cannot issue
cryptographic delivery authority. Structural test fixtures never construct a
positive authenticated current Rust admission.

That bounded hardening alone did **not** enable native setup. At `594add9`, the
global `require_live_adapter` refusal, private startup gate and native
`LinuxHost::effects_available == false` were unchanged. Its required follow-up was
conditional public/private composition and native effect availability behind the
real existing admission, plus honest native Standard presentation. Unsupported
platform/build, unsigned/stale admission, read-only/injected-root restrictions,
foreign resources and excluded legacy Update/HTTPS/renewal routes must still
refuse. Do not dispatch a candidate from this incomplete source merely to advance
the workflow. The absence of a complete signed current Rust positive set limits
runtime verification; it does not justify a test signature bypass.

The parent reports that exact baseline `f824c1fac8e61708947984122895da4400ddd012`
passed 596 distinct isolated Linux cases (333 library, 259 integration, four
compile-fail doctests), zero failed/ignored/uncovered. That is baseline evidence,
not coverage of this later hardening or native root execution.


## Conditional native setup (base 594add9)

The Owner explicitly approved source changes allowing setup after signed-release
and ownership checks, with no installation or host/release effects authorized.
The former unconditional refusal is now a native platform/controlled-build
prerequisite, not delivery trust. Public zero-argument entry still authenticates
the exact candidate or qualified stable release and binds the installed/current
inode, bytes and loaded Rust statement before constructing `NativeOwnerSources`.
Stable remains the default; protected candidate input and its expiry/role checks
are unchanged. No new switch, untrusted verifier, trust root or dependency exists.

Native Standard effects additionally require a native runner and the retained
concrete `NativeAdmission` snapshot, with exact root/record/process identity and
cancellation. An unauthenticated native constructor has no retained guard and
cannot gain effects. Admission is rechecked after host-lock acquisition, before
native writes are authorized; setup effects continue to recheck proof, journal,
configuration/package material and ownership. Existing before-commit cleanup,
after-commit forward completion, removal finalization and intentionally lent-lock
semantics remain intact. Native Review/result wording describes real host actions
and local checks, while leaving outside traffic `CannotBeVerified`.

Ordinary private startup remains offline: the controlled build prerequisite does
not replace exact pair/current-process, role, sandbox, start-lock and handoff
checks. Renewal/private legacy roles, new Update/HTTPS/migration, read-only
mutation adapters, missing material, unsafe parents/inodes and foreign/unknown
resources retain their refusals. Candidate delivery never becomes qualified stable
authority. Successful compilation is not cryptographic or deployment evidence.

Eligibility positives use explicit unsigned structural snapshots and a fake
runner solely to test the predicate; they never construct `NativeAdmission` or
execute native changes. Presentation tests forbid effect calls. Genuine preserved
public signature tests and the actual candidate/stable authentication refusals
remain independent. A genuine current Rust signed manifest/artifact set is still
required to test the complete native admission positive path; none was fabricated.

Remaining verification is finite: current-source Linux and both native musl
build/package checks; genuine exact candidate/installed-process positive admission;
then separately approved packaged root setup/recovery/startup, outside HTTP and
proxy traffic, client/Karing identity/link rotation, restart and complete cleanup.
The 596-case `f824c1f` result is baseline only. Source push, CI dispatch, signing,
VPS/security/trust/credential changes and publication remain separately approved
actions. Stable publication still requires its explicit post-qualification gate.
