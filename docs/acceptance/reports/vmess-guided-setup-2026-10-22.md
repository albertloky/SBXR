# Guided VMess tunnel implementation and automated verification — 2026-10-22

Implemented and regression-tested; **not a release or live qualification**.
Work remained uncommitted on `main`, based on
`1bc15c7bb10992b7c2680f2443df29d1ba4951ab`. The preexisting untracked `.codex/`
was preserved. No commit, push, publication, live VPS connection, Cloudflare
account/DNS/security change, or Karing change was performed.

The [setup guide](../../setup-vmess-tunnel.md) now walks a fresh user through
their own domain, unused hostname and dedicated remotely managed tunnel, a
loopback HTTP application route, official cloudflared installation and a hidden
token-file prompt. SBXR validates these local prerequisites and the selected
tunnel ID, then manages only `sbxr-tunnel.service`. Token and binary hashes bind
review to execution without persisting the token in SBXR state. The dynamic
service user receives its token through systemd credentials; removal preserves
the owner's token, package, domain, tunnel and DNS.

Setup previously could report success after only starting the local proxy.
It now reports public VMess verification separately: local WebSocket origin,
trusted public TLS/WebSocket upgrade, then authenticated VMess-only HTTPS traffic
with expected server IPv4 egress. The isolated sing-box client has no fallback;
its authenticated loopback listener must belong to its process. The check is
bounded, reaps its child and can be repeated without changing durable state.
Ordinary status views say that a public check has not been performed. A public
failure leaves local setup usable and gives stage-specific correction guidance.
An interrupted connector installation retains the existing Finish setup path.

The existing Proxy Installation module owns orchestration and authority; its
host adapter owns the dedicated unit and probe process. No dependency or new
domain module was added. Review covered setup, recovery, rotation, removal,
compatible update admission, bootstrap restoration and packaged cleanup callers.
Regression tests also preserve unrelated tunnel units during VLESS-only work.

Useful raw evidence is private under
[the macOS run](../../../.scratch/acceptance/t1/) and
[the disposable Linux runs](../../../.scratch/acceptance/tvm/RESULTS.md).
These links may be unavailable in a fresh clone. Commands below used Go 1.26.6
and run-local caches/TMPDIR; root/systemd checks ran only in newly created VMs.

| Status | Check and evidence |
|---|---|
| Passed | macOS `go test ./... -count=1`: all ten packages, including installer, upgrade/recovery and exact four-asset build/verification fixtures. [Final log](../../../.scratch/acceptance/t1/all-final.log). |
| Passed | Disposable Ubuntu 24.04 ARM64 `go test -json -timeout 30m ./... -count=1`: ten packages, 2,295 test/subtest passes, no failures; opt-in/platform skips were recorded separately. [Log](../../../.scratch/acceptance/tvm/corrected-full.log). |
| Passed | Same Linux snapshot, `go test -race -json -timeout 30m ./... -count=1`, 7m44s. The repository candidate workflow already uses the 30-minute bound. [Log](../../../.scratch/acceptance/tvm/corrected-race.log). |
| Passed | macOS race coverage: nine packages passed in the full run; all 96 release-package test names were partitioned into three disjoint groups, exit0 for all groups (95 passed, one native-Linux skip). No tests were omitted. [Group membership](../../../.scratch/acceptance/t1/race-groups.json), [results](../../../.scratch/acceptance/t1/release-race-results.json). |
| Passed | `go vet ./...` and `go mod verify` on macOS and Linux. [macOS vet](../../../.scratch/acceptance/t1/vet-last.log), [module verification](../../../.scratch/acceptance/t1/modules-last.log), [Linux vet](../../../.scratch/acceptance/tvm/corrected-vet.log), [modules](../../../.scratch/acceptance/tvm/corrected-modules.log). |
| Passed | Final focused VMess status/action/recovery tests, including race; strengthened canonical installer restoration, capability admission and preservation tests. [macOS](../../../.scratch/acceptance/t1/vmess-status-last.log), [installer/admission](../../../.scratch/acceptance/t1/final-admission.log), [Linux final-delta commands/results](../../../.scratch/acceptance/tvm/final-focused-root-progress.log). |
| Passed | Actual pinned sing-box 1.14.3 client/server traffic through local TLS/WebSocket and HTTPS fixtures: correct UUID succeeds, wrong UUID fails. No public route involved. [macOS](../../../.scratch/acceptance/t1/vmess-protocol-final.log), [Linux](../../../.scratch/acceptance/tvm/final-host.log). |
| Passed | Root host package, including actual systemd `LoadCredential`, `%d` expansion, merged `/usr`, exact unit lifecycle and foreign-owner refusal. [Linux host log](../../../.scratch/acceptance/tvm/final-host.log). The connector executable/token in this fixture are synthetic. |
| Passed | Official cloudflared 2026.10.3 accepts the exact unit flag arrangement in a network-isolated namespace and refuses the deliberately missing token file. [Offline flag check](../../../.scratch/acceptance/tvm/cloudflared-offline-flags.log). This does not prove an edge connection. |
| Passed | Native Ubuntu 24.04 amd64 controlling-terminal generated installer, nonroot refusal, and actual private stamped production menu with the VMess choice. Synthetic release identity only. [Results](../../../.scratch/acceptance/tvm/amd64/RESULTS.md). |
| Passed | Real SSH boundary fixture, including 31 boundary cases and locked-account checks, in the disposable Linux VM. Final root-fixture details are recorded in the [Linux results](../../../.scratch/acceptance/tvm/RESULTS.md). |
| Passed | Disposable Linux startup-cancellation and protected-menu process/cleanup fixtures, after establishing the wrapper's documented log-parent prerequisite. [Root-fixture results](../../../.scratch/acceptance/tvm/RESULTS.md). |
| Passed | All five opt-in module systemd fixtures in separate processes: certificate acceptance/recovery, mismatched-release maintenance/removal, ordinary starts, HTTP subscription and protected per-menu windows. [Individual outcomes](../../../.scratch/acceptance/tvm/systemd-individual-progress.log). |
| Passed in local follow-up | Pinned-DEB observer `TestMVPWindowObserverLinuxIntegration`, 157.48s, after the fixture-only hash-derivation repair described below. Real dpkg/hold/purge, loopback SSH, protected windows and refusal cases; no live host/account operation. [Named test log](../../../.scratch/acceptance/tobs/iteration2/observer-go.log). |
| Passed | Packaged cleanup/module contract checks; `git diff --check`. [Contract log](../../../.scratch/acceptance/t1/contracts-final.log). |
| Failed, coverage recovered | macOS monolithic race command exceeded Go's default ten-minute aggregate timeout in `cmd/sbxr-release`; no race report occurred. The unchanged tests all completed in the disjoint groups above and the full Linux race run passed. [Failure log](../../../.scratch/acceptance/t1/race-final.log). |
| Refused as designed | Official four-asset builder refused the Git-less/uncommitted source snapshot. No clean-Git guard was bypassed and no synthetic smoke executable is called a candidate. |
| Not run | Full amd64 suite duplication (native installer/menu checks ran), new live VPS deployment, real Cloudflare connector/route, outside-network clients, Karing acceptance, official candidate/native release qualification and publication. These results make no claim about those boundaries. |

Initial Linux execution exposed fixture prerequisites: missing/current-incompatible
`gh`, a root run of a test that correctly requires a nonroot caller, and a stale
SSH test expectation of 25 cases when its driver and Go contract have 31. The
disposable runner was corrected, the SSH expectation was updated to 31, and the
full checks above then passed. Initial logs were retained. Later root fixtures
also refused before effects on a proved quiescent test-created lock and the
minimal image's `/var/log` metadata; the Linux results record their repair and
rerun outcomes. A grouped root invocation also exposed test isolation between
fixtures with different generated CAs: Go cached the first process's system
roots. That failed invocation was retained and the fixtures were rerun in fresh
processes; all five passed. No assertion was weakened, test skipped to obtain a pass, or
timeout raised merely to turn a failure green.

Source provenance: the Linux broad suites used final4 archive SHA256
`b02fd909158443fd29f4f9d523c0a9993e061b834a3f361ee9e2e6917cf672d2`.
The final5 snapshot (SHA256
`52c9a5355a797dee97d527a9110bd32f939de22d1add96a57bb485b2cf7fdaf1`)
was byte-verified in the guest. Its Go deltas were `tunnel.go` and `vmess_test.go`
in Proxy Installation and `cmd/sbxr-release/installer_test.go`: final status/result
metadata and test-only strengthening. These were checked separately on Linux
and macOS; other deltas were documentation. The final working-source
[manifest](../../../.scratch/acceptance/t1/final-source.manifest) contains 373 files,
SHA256 `b4946820529d6b5c9505714511f731277240da38a90f387b75d0e3e07972f6fa`.
It excludes `.codex/`, `.scratch/`, this report and its navigation index to avoid
self-reference. Official archive checksums, source manifests, exact commands,
skips and disposable VM cleanup are retained in the Linux results.

Both newly created QEMU guests powered off and exited0; their loopback SSH ports
closed. Exact product, credential, certificate, wrapper and lock fixtures were
absent, services were inactive/not found, and original guest `/var/log` metadata
was restored before shutdown. Disposable disks, credential-bearing seeds and
private test keys were removed. Logs and public tool/source provenance remain.
The macOS run's [temporary-fixture cleanup](../../../.scratch/acceptance/t1/temp-cleanup.log)
also passed. No cleanup blocker remains.

Remaining release work requires a permitted clean revision and exact candidate
assets, native release verification, and separately authorized fresh live
qualification with the owner's dedicated domain/tunnel. That includes real
cloudflared edge operation, outside VLESS and VMess TLS traffic/egress, the five
HTTP subscription journeys and two-node Karing import/refresh, credential
rotations, serving/host restart, upgrade/recovery where supported, and removal.
The earlier RackNerd result at `.scratch/acceptance/rn1/RESULTS.md` remains
historical evidence for that deployment; it was neither changed nor reused as
proof of this source. RackNerd, BWH and existing Karing settings remain outside
this implementation task's authority.

## Local follow-up and proposed next live boundary

The follow-up request authorizes only remaining safe local checks and a proposal;
it retains the no-commit, no-push, no-publication and no-live restrictions.
Completed valid checks above were not repeated.

The ordinary production builder cannot build this implementation yet.
[`verifiedGitSource`](../../../cmd/sbxr-release/main.go#L458) requires the supplied
commit to equal `HEAD`, a zero result from `git diff --quiet HEAD --`, and then
builds exclusively from `git archive HEAD`. This checkout still contains the
reviewed uncommitted changes. A clean copy of the old HEAD would omit them;
creating a temporary commit or replacing the verifier would violate the scope.
The previous [source refusal](../../../.scratch/acceptance/tvm/package-smoke-build.log)
therefore remains valid and was not repeated. After a separately authorized
commit, local four-asset build and native verification can run without VPS,
publication or account credentials. The official candidate workflow additionally
creates GitHub drafts and attestations, uses GitHub authorization, and can
automatically trigger stable publication after successful qualification. It is
not an offline build command and must not be dispatched under this scope.

The pinned-DEB observer is a separate local test boundary, not a release or
real-account security operation. It can use a new disposable amd64 VM, the exact
public DEB, real dpkg/systemd/loopback SSH and ephemeral fixture keys. Guest-only
fixture permissions are restored; disks, keys and seed material are removed.
Its new run evidence is kept under `.scratch/acceptance/tobs/`.

Its first preflight proved a stale fixture value already present in HEAD:
the exact size/SHA-256-pinned DEB contains `/usr/bin/sing-box` SHA-256
`33de1654134de582a3d23786fdba32e5461bfe3eefe3e11ddeef2a9635a9e91c`,
but the fixture expected
`031042edfd30a215e4c69d83eb7d13c194e6ef50c782e2e1308d9d8fa128454a`.
No package was installed and the known-impossible test was not run. That first
guest was restored and removed. The minimal test-only repair makes the fixture
use the existing `prepare-mvp-window.py` helper to derive the installed-binary
hash from the receipt-verified DEB. The DEB pin, installed-binary equality check
and deliberately wrong-binary refusal case remain intact. No production code,
dependency, trust rule or credential was changed for this repair.

The corrected named observer then passed once in 157.48s, exit0. Its installed
package/binary checks and later zero-hash refusal executed under enabled Python
assertions. The Go wrapper discards successful child output; the named PASS,
source identities and independent postflight observations are retained. Existing
full suites and native menu checks were not repeated. The follow-up
[373-file source manifest](../../../.scratch/acceptance/tobs/followup-source.manifest)
has SHA256 `941c3de79ca5f46cd0f9fb2790cd6fa2d19430f6656f17e1e33ca1f2007fba6c`;
its sole source delta from the earlier verified manifest is
`.github/scripts/test_mvp_inspect_window_linux.py`. Product Go bytes are unchanged.
See the [follow-up evidence](../../../.scratch/acceptance/tobs/RESULTS.md) for both
iterations, the initial failure and cleanup receipts.
Independent postflight proved exact package/source inventories preserved and
package accounts, holds, units, fixture paths and temporary keys absent. Both
follow-up VMs are shut down; loopback SSH is closed, original guest metadata was
restored and owned disks/seed/private keys were removed. [Final cleanup receipt](../../../.scratch/acceptance/tobs/iteration2/disposable-cleanup.json).

### Plain setup flow and current limits

1. The user supplies their own active Cloudflare domain, unused hostname and
   dedicated remotely managed tunnel. In the dashboard they create/select that
   tunnel and add the hostname route to `http://127.0.0.1:10000`, with Path blank.
   SBXR does not perform those account/DNS actions or bypass Access/WAF policies.
2. On a fresh supported Ubuntu 24.04 amd64 host, the user installs official
   cloudflared and saves that tunnel's token through the guide's hidden prompt
   into root-owned mode-0600 `/etc/cloudflared/sbxr.token`. No token goes into chat,
   a shell argument, SBXR's hostname prompt or a client profile.
3. In `sudo sbxr`, choose Start setup with VMess WebSocket, enter the hostname,
   verify the displayed tunnel ID and approve the review. SBXR installs/starts
   its dedicated local unit alongside VLESS and runs the staged VMess check.
4. Correct any indicated local/route problem and repeat Check VMess connection.
   Then test an outside client. Enable the optional HTTP subscription only if
   wanted, accepting its bearer-link interception/tampering risk.

There is no domain provisioning, tunnel-creation API, cloudflared package
installer/updater, in-place VMess enablement, token/package replacement action,
new software Update operation, or automatic legacy HTTPS migration. Public
checks depend on trusted edge TLS and `api.ipify.org` returning the expected
server IPv4; outages or different egress produce pending rather than success.
The standalone Client Configuration still defaults to VLESS: explicitly select
the VMess outbound/node when testing it. Both share one Client Identity.
Removal preserves the owner-supplied package/token and account resources, which
must be retired separately. Outside-client, boot reliability and two-node Karing
behavior require live evidence.

### Smallest live proposal — not executed or currently approved

Use one **new disposable Ubuntu 24.04 amd64 VPS**, one unused hostname and one
new dedicated remotely managed tunnel. Do not use either protected BWH resource
or the existing RackNerd deployment. No eligible replacement host/IP, unused
FQDN or tunnel ID is supplied in the current scope: **exact target approval is
pending those bindings; none has been guessed or contacted**.

| Approval field | Exact boundary to bind before any live command |
|---|---|
| Server | Parent-supplied new IPv4, SSH user, pinned host-key fingerprint and existing authorized key reference; fresh OS and absence checked read-only first. Exclude `107.175.53.219` entirely. |
| Cloudflare | Parent-supplied unused FQDN/zone and dedicated tunnel ID; suggested tunnel label `sbxr-vmess-qa-20261022`. Owner performs the exact new route/tunnel/token provisioning. No existing DNS record, connector or account policy may be modified. |
| Build | Exact clean, separately authorized source commit and verified private four-asset package, with a clearly private identity and recorded hashes. No workflow dispatch, attestation/upload or public release. Current uncommitted source is not yet eligible. |
| Outside client | A separate short-lived command-line sing-box process on the controller, using the reviewed Client Configuration disclosure only for this test server, in memory/stdin, with trusted TLS and a VMess-only outbound. No system proxy, TUN, DNS, routing or existing client-profile changes. |

For that narrowly scoped live smoke: use the normal packaged setup/menu, verify
actual edge operation plus outside VMess HTTPS and expected egress, and verify
VLESS still works. Stop/start **only `sbxr-tunnel.service`** to prove pending then
recovery, and reboot **only the disposable VPS** once to prove boot activation.
These actions interrupt only the new test endpoints; reboot also briefly drops
that test SSH session. No forced transaction interruption or unrelated service
restart is proposed. Use no subscription endpoint for this first smoke, so it
needs no TCP8443 exposure, Certbot, trust-store, hosts-file or NAT changes. If
host/firewall/policy prerequisites require additional security changes, stop for
their specific approval instead of broadening this plan.

Keep SSH references and existing host trust unchanged. Transfer the tunnel token
only through a trusted hidden prompt or pinned-SSH stdin into its protected file;
never print/capture it or place it in arguments. Stop and reap outside clients
and remove their temporary material. After collecting secret-safe results, run
reviewed Complete removal, prove exact local absence and outside rejection, then
have the Owner retire only the newly created route/tunnel and test token; remove
the official cloudflared package only if separately approved and proved exclusive
to this disposable host. Destroying the VPS is a separate explicit irreversible
cleanup approval, not implied by this proposal. On an uncertain/disconnected
mutation, inspect state before retry; on failure retain the actual result and
use the supported finishing action, without modifying Ownership Records.

This smoke requires **no Karing changes** and is not official five-journey release
qualification. That later boundary requires the HTTP subscription, rotations,
serving restart/removal and actual two-node Karing import, latency and refresh.
Use a separate approved test Karing device/instance with temporary test profiles;
existing profiles/settings/selected connection remain protected. A temporary
profile is still a client write requiring explicit approval. If no isolated
Karing client is available, leave that qualification incomplete rather than
changing the user's current client. Do not invoke the official main-branch
qualification workflow without separate publication authorization: its successful
completion can start stable publication automatically.
