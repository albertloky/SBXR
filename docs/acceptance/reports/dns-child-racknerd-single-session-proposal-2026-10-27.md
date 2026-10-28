# Proposed RackNerd immediate-child diagnostic: one session

**Unapproved execution proposal, not a run result or adopted procedure.** Prepared
only from local committed sources/evidence; no new server reads or execution.
Source revision: `a257a6ecc3ea67518f1fedac485ae028af250252`.

**Preparation update:** the [frozen input/owner integration report](dns-child-runtime-input-preparation-2026-10-27.md) supersedes the unresolved watchdog, Python/input hash and universal perf-inventory prerequisites below. Use its current image hash and owner invocation. Its explicit passive-custody failure policy must be included in approval. The original scope below remains a proposal, not authorization.
Read the [reviewed runbook](../../../.github/scripts/dns-child-fixture-review.md),
[Linux report](dns-child-diagnostic-linux-2026-10-27.md) and
[official tracer assessment](../../research/bpftrace-0.23-no-mount.md).
This proposes a specifically approved mount-based alternative to the runbook's
no-mount prerequisite; it does not silently amend that prerequisite.

## Requested scope and hard stops

Authorize, only after the decisions below are resolved, one `immediate` observed
fixture session on the named RackNerd host. No baseline, pipe-wait, unrelated-child,
fault suite or retry is included. There is one selected child and no product run.
The observer attaches one exact fixture uprobe, five tracepoint types
(`sched_process_fork`, `sched_process_exit`, `sched_switch`, `sys_enter`, `sys_exit`),
plus the reviewed BEGIN/END/90-second interval machinery. Tracepoint attachment
is system-wide; predicates restrict recorded events, not attachment overhead.

Prohibit host-wide mount propagation, persistent mount configuration, services,
sysctl/network/firewall/security/credential changes, capability grants, user/PID/
network namespaces, product execution, DNS/socket fixture activity and release.
Use existing root permissions only; a denial stops the dependent stage.
No arbitrary commands, numeric-PID/group/name-based kill or automatic retry.

Budget from first preparation action: 10 minutes; compatibility probe: 20 seconds
including its cleanup; one session: **110 seconds total**; independent inventory
and mount cleanup: 60 seconds. Total ceiling 13m10s. Expiry means refusal and
bounded owned cleanup, never extension. A kernel uninterruptible task cannot be
guaranteed dead by a deadline: record residual ownership and stop; do not claim
the cap proves teardown. No automatic reboot, force/lazy unmount or broad cleanup.

## Exact inputs and identity

Official [v0.23.0 asset](https://github.com/bpftrace/bpftrace/releases/download/v0.23.0/bpftrace),
asset ID 240658814, 191439568 bytes, source commit
`01e806d24c61f996f1809e1e991646311499db4f`. Vendor provenance is established;
checksums pin bytes, not a reproducible-build attestation.

| Input | SHA-256 |
|---|---|
| Official outer AppImage | `3eefba1c9338a8f981af349b4904e03a82adb257c5eb8dd5fd484675333b1f1a` |
| Bundled `/AppRun` (54432 bytes) | `8bf49ff12fdce164d648513df789a7baaf8071fca625db8a80fd5841fcaa5ab5` |
| Inner bpftrace (4129224 bytes) | `72cfbbf403d9d1ba118892dc8ee94beb875be2ab5b68cdd79c8e665456cc7540` |
| Previously built diagnostic-only fixture | `4970f019bf6919d5dd7c74dba386c86df2cb4588b254bac674daf1265527f7bf` |
| Fixture source | `80811a959bffe20db2fcd92dece42a38cdfea7c7f0ff38cf4acec51c2265bee0` |
| Supervisor | `b0b49fa2d6c8f53b71f9ee25f622192c784130e10a0596afb5a0a33a0cfe05d9` |
| Wrapper | `6ebe18bf7728b03bc07b55881c38207729ba6075a198eb418b4443ac69a53e04` |
| Checker | `409871a2d5428087fb8cb97a8099028dabf926ab2c9fa48033414f26012a4adb` |
| Template | `f434c39c98de5152607380d0bd462339baf416ab6de4d096b5e2af26820717ce` |

Exact existing fixture symbol:
`_ZN16sbxr_dns_fixture12dns_observer23dns_child_observer_hook17h9e4679c7ef81f1e5E.llvm.11622216194542242137`.
Five call sites retain `(event, query, child)` in RDI/RSI/RDX. Rebuilding changes
the binary/symbol approval envelope: re-inspect and freeze it before proceeding.
Fixture loader/libc compatibility on the target is not yet established.

The manifest's `tracer` is **bundled AppRun**, with the AppRun hash above, not the
outer AppImage or inner ELF. The whole mounted official image and its inner ELF
are additional immutable dependency identities. This explicit launch identity
requires reviewer acceptance before execution; do not alter wrapper checks.
Resolve an exact compatible Python binary/hash and its trusted runtime libraries,
the new input-image hash, manifest hash, and outer-watchdog identity before stage A.
No placeholder hashes may reach a command.

## Mount and pathname construction

Use a fresh root-owned session directory (0700) on an existing local filesystem,
with separate `inputs`, `app`, `out` and evidence paths. Confirm free capacity and
existing loop/SquashFS support read-only; do not install modules/tools or change
kernel configuration to satisfy this proposal. Build a small SquashFS input image
from the pinned fixture, adjacent wrapper/checker/template, supervisor and a
resolved compatible Python executable. Reject symlinks for manifest files,
`__pycache__` and `.pyc`; exclude secrets. Preserve required executable modes.
Hash the image and six-file manifest. Limit new staging/evidence to 512 MiB;
if actual dependency size exceeds that, stop and revise the proposal.

An independently owned launcher first creates **only an outer mount namespace**,
then performs `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` there, before any
new mount. Compare its namespace inode with the host and inspect *all* mountinfo
propagation fields; refuse any shared/master/propagate_from relationship.
Never issue the propagation operation in the host namespace. No implicit shell
wrapper may continue after either check fails.

Inside that private namespace, allocate exactly two recorded read-only loop
devices: official image with byte offset **824016** and size limit **190615552**,
and the newly hashed input image. Mount each as read-only SquashFS, `nodev,nosuid`
(execution required, hence not `noexec`). No FUSE or AppImage self-extraction.
Loop allocation is host-global resource use despite private mount visibility;
explicit approval includes these two allocations and only their later detach.
Verify the mounted file hashes, read-only superblock, expected entrypoint symlink,
AppRun/mountroot directories and inner Nix closure before launch. Read-only bind
views of writable superblocks do not satisfy the supervisor.

Run **the official bundled AppRun directly from the mounted image**. Do not run
the outer ELF runtime, whose FUSE/helper/cleanup behavior has not been reviewed.
The static AppRun ELF has no PT_INTERP. Its supplied
[source](https://github.com/danobi/nix-appimage/blob/74e44691812b4f220e84fd89895931ff4f904a03/apprun.c)
at revision `74e44691812b4f220e84fd89895931ff4f904a03` does the following:

1. Resolves `/proc/self/exe` to its containing app directory; creates a mount
   namespace. For UID 0 it creates no user namespace and writes no UID/GID maps.
2. Mounts tmpfs over `<appdir>/mountroot`, then marks that mount unbindable.
   It does **not** first make inherited mounts recursively private. The outer
   namespace above is mandatory to prevent propagation before this operation.
3. Recursively bind-mounts each host root entry except `/nix` into that tmpfs;
   substitutes the image's `/nix`; chroots and restores the original cwd.
4. Reads `<appdir>/entrypoint` and execs the inner tracer. No fork or signal appears
   in this AppRun source. Some root-entry bind failures only warn: any warning
   invalidates compatibility; the reviewed wrapper refuses all tracer stderr.

The host `/proc`, `/sys`, `/dev`, input paths and writable output directory are
intended to remain visible; existing host `/nix` is hidden inside AppRun. No PID
namespace is created, so fixture PID identity should remain unchanged. Supervisor
`/proc/PID/fd/DIRFD/name` paths must still resolve to the same inode across this
chroot. This is **not a security sandbox**: most host paths remain writable with
existing root authority. Source-to-AppRun binary equivalence is not fully proven.
The trusted-platform/no privileged interference assumption remains essential.

## Stage A: fail-closed compatibility, no attachment

Only after specific approval: create the private mounts above, then run AppRun
once with `--version`, under the independent watchdog, with the same minimal
environment, cwd, proc-fd launch path and bounded pipes intended for the wrapper.
This probe executes tracer userspace but must not request BPF loading or fixture
execution. Require exact 0.23.0 output, empty stderr, zero exit, at most 8 KiB each
stream and 20 seconds including cleanup. Inspect host mountinfo before/after and
the private mount/proc path identities while available. Verify Python/library and
fixture ABI prerequisites without running the fixture. Missing evidence, warnings,
unexpected children/resources or inability to observe containment stops stage B.
`--version` success does not establish attachment or notification compatibility.

## Stage B: one immediate-child session

Keep the reviewed supervisor, wrapper and checker unchanged. Command shape,
resolved only after stage A and the approval manifest are accepted:

```text
<pinned-python> -I -S -B <immutable-supervisor>
  --manifest <frozen-six-input-manifest> --output <fresh-out/session>
  --case immediate --fault none --symbol <exact-symbol-above> --execute-approved
```

The fixture starts gated. Confirm executable inode, PID/starttime and parentage.
Only `GATED <pid>` plus the wrapper's exact post-attachment receipt may release
the single `G` byte. There is no sleep-based fallback or manual gate release.
The same-executable child exits and is reaped before Spawned, intentionally testing
EXIT-before-SPAWN. Require one correlated Begin/Fork/Exit/Spawn/Finish chain and
clean parser/result; Finish and DONE alone are not success or cleanup proof.
Attachment permission, notification transport through AppRun and real Linux
supervisor adapters remain unverified until this stage succeeds.

Keep reviewed limits: fixture streams 1 KiB each; wrapper streams 8 KiB each;
256-byte lines; observer capture 64 KiB/stderr 8 KiB, 32 queries, 128 wait rows,
4096 syscalls/child, 64 keys/map, eight perf pages per CPU. Record CPU count and
resource baseline; these limits do not independently bound total kernel memory.
No overhead comparison or historical DNS-root-cause claim from one session.

## Independent watchdog, inventories and cleanup ownership

The existing supervisor is independent of the wrapper, but **is not an external
watchdog for its own stalls**. A frozen, reviewed outer watchdog/launcher is still
a prerequisite. It must retain pidfds and validated starttime/ancestry for the
namespace keeper, supervisor and descendants, use subreaping, and keep discovery,
reaping and owned signaling independent of output draining. It must hold the outer
namespace lifetime until its mounts are normally unmounted. No generic `timeout`
or process-group kill substitutes for this ownership contract. No new watchdog
implementation is included or claimed tested by this proposal.

Session clock starts before supervisor launch. Begin supervisor-owned cleanup at
105s, escalate owned TERM to KILL after two seconds, and require the independent
watchdog to finish its owned actions by 110s. If supervisor stalls, watchdog sends
TERM to its pinned supervisor and registered descendants at 105s, KILL at 107s;
it continues adopting/reaping/discovery through 110s. Only retained pidfds, never
numeric/group/name signals. The wrapper's existing direct-child SIGKILL is also
explicitly in scope: its Popen child remains unreaped, preventing PID reuse before
the signal. On failure, close the fixture control pipe; do not feed more input.

An independent operator records bounded, read-only before/during/after inventories
of BPF program/map/link IDs, owned `/proc/PID/fdinfo` BPF/perf references, dynamic
uprobe/tracepoint attachment evidence and owned process/starttime identities.
Confirm available inventory tools and privileges before attaching; no bpffs or
tracefs mount is added. `bpftool ... show`/fdinfo alone may not expose every perf
attachment: the chosen inventory must establish coverage, or refuse the session.
Attribute deltas to owned FDs/programs; unrelated concurrent changes are not ours
to remove. No map/probe pinning is requested. Require no owned live processes,
open perf/BPF references, remaining owned links/programs/maps or dynamic probes.
Do not delete unexplained kernel objects to make a comparison pass.

After proving process/kernel cleanup, namespace owner normally unmounts the two
session mounts, closes namespace/file handles and detaches only the two recorded
loop allocations after verifying backing identity. AppRun tmpfs/binds disappear
only when its last namespace reference closes; exiting one process is not enough
if descendants or namespace FDs survive. Verify unchanged host mount table and
no owned loop allocations. If any unmount/detach fails or times out, preserve the
ownership ledger and evidence and report residuals; no forced/lazy unmount,
unrelated detach or deletion. Preserve small evidence; temporary image deletion
is a separate explicit decision, not automatic cleanup here.

## Decisions required before execution approval is actionable

- Accept direct bundled AppRun as tracer launch identity and approve private
  namespace/tmpfs/bind/chroot operations plus two read-only loop allocations.
- Freeze target paths, Python/runtime/image/manifest hashes and confirm target
  tools, filesystem support and ABI fit; no environment bootstrap is included.
- Supply and independently review the finite outer watchdog/namespace owner;
  approve process-local subreaping and precisely owned TERM/KILL, including the
  wrapper's direct-child SIGKILL. This is a concrete missing safety mechanism.
- Specify independent kernel/perf inventory coverage and its operator. If complete
  attribution is unavailable, approve stage A only and stop before attachment.
- Approve stage A separately from conditional stage B; a failed stage A never
  authorizes weakening the wrapper, changing security settings or another trial.

No execution, server access, mount, signal or upload occurred while preparing this
document. It is intentionally uncommitted pending review of these decisions.
