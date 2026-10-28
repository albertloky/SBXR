# Local runtime input preparation — locally ready for scoped approval

This supplements the [single-session proposal](dns-child-racknerd-single-session-proposal-2026-10-27.md).
No server reads, mounts, wrapper/fixture/tracer execution, signal operations,
uploads, commits or pushes were performed. All new source and this report remain
uncommitted. The existing reviewed supervisor is unchanged.

## Implemented and checked

- `.github/scripts/dns-child-session-watchdog.py` is a separate process deadline
  around only the fixed immediate-child supervisor command. It requires an
  already private mount namespace and immutable SquashFS bootstrap, retains
  verified input anchors, uses the existing reviewed pidfd ownership routines,
  and has no shell/group/numeric-PID signal fallback. It reports residual
  PID/starttime identities and sticky discovery uncertainty. Late observation
  after 107 seconds selects KILL immediately; even an already-late launch failure
  attempts owned cleanup once. An OS stall can exceed the time budget and is not
  falsely represented as a hard real-time guarantee.
- `.github/scripts/dns-child-resource-inventory.py` independently enumerates
  BPF program/map/link IDs using only GET_NEXT_ID commands (11/12/31 on x86-64
  syscall 321), and reads dynamic uprobe definitions. It creates/loads/attaches/
  pins/deletes nothing. It refuses denied/incomplete/unstable inventories and
  strictly validates snapshot shape. It deliberately does not certify complete
  perf-event FD cleanup.
- Adjacent tests exercise real decision/orchestration functions with all live
  adapters mocked. **64 inert tests pass:** 21 new watchdog, 5 new inventory,
  24 existing supervisor and 14 original observer tests. No mocked result proves
  real mount, pidfd, signal, BPF inventory or teardown behavior.
- A fresh internal read-only GPT-6 Astra medium reviewer found bootstrap file
  mount, late escalation, terminal observation/ledger and inventory-shape defects.
  Those were repaired with regressions. Final review found no remaining concrete
  defect in the changed patch; the subsequent ownership integration also passed static re-review. Review did
  not execute runtime adapters.

## Frozen ordinary file artifacts

All outputs are under the local ignored
[runtime-preparation directory](../../../.scratch/acceptance/runtime-preparation/).
The image was created as a regular file and re-extracted as data; no mounting or
execution of its contents occurred. All 595 extracted file sizes/digests match
`image-files-owner.json`. Scope: six diagnostic scripts/template, the exact fixture,
manifest, pinned Python executable and 586 standard-library source files. No
site-packages, bytecode/cache, downloaded tracer package, credentials, bulky logs,
or arbitrary workspace content is inside. Selected private-key/token/access-key
marker scanning passed; scope/provenance checks accompany that heuristic scan.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `runtime-inputs-owner.squashfs` | 15175680 | `19090e8ae99a2978dab3a02d9e3a0b68080ec2c15e98da1c4d7949dbea17aaa0` |
| `image-root/scripts/runtime-manifest.json` | 1012 | `a7b19198efb1beeae2f46d937cfe64cf78efbae4f58c58d328f4d8fa7097057e` |
| `image-files-owner.json` | 98028 | `f7f43303d23557b56a83155050c2fd74980c547e3e60533a50bb1bfb146f0590` |
| `squashfs-tools-4.6.1.tar.gz` | 286850 | `9c4974e07c61547dae14af4ed1f358b7d04618ae194e54d6be72ee126f0d2f53` |

Watchdog source SHA-256:
`09b2675e5f7c32d76c03700164c9b31f6dfd4aa39e335ea84449aa87f484226d`.
Inventory source SHA-256:
`9d89c04ca4250b10960428de4f2c75dd00b65cbc6a97c38aa794d17132afc3cd`.
Python executable SHA-256:
`fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7`.
Other exact artifact hashes and symbol remain in the proposal.

The image writer/reader were built locally from the
[official SquashFS 4.6.1 source archive](https://github.com/plougher/squashfs-tools/archive/refs/tags/4.6.1.tar.gz),
with gzip enabled and optional XZ/LZO/LZ4/ZSTD disabled; no installation or apt
operation. Image flags: no append, gzip, one processor, all root, no xattrs,
filesystem/file timestamps zero. Earlier candidate image and evidence are retained.

Manifest mount paths are frozen to `/tmp/sbxr-dns-a257a6e/inputs` and
`/tmp/sbxr-dns-a257a6e/app`; refuse an existing session directory. The manifest
must remain adjacent to the watchdog/supervisor on the same immutable image.
Changing mount paths changes the manifest and image hashes and requires review.

## Python and target ABI evidence

Python is the executor-provided CPython 3.12.14 executable, copied with only its
standard-library `.py` files. This is a pinned existing toolchain input, not a
new assertion of official CPython binary distribution provenance. Required native
modules `_ctypes`, `select`, `_hashlib`, `_posixsubprocess`, `fcntl`, `_struct` and
`_json` are built into that executable. Site packages and unused extension-module
DSOs were omitted. The copied interpreter/image was not executed to test relocation.

Static ELF inspection: Python needs GLIBC up to **2.17**, interpreter
`/lib64/ld-linux-x86-64.so.2`, and libc/libm/libpthread/libdl/libutil/librt SONAMEs.
Its RPATH is `$ORIGIN/../lib`; it has no libpython NEEDED dependency. The fixture
needs GLIBC up to **2.39** and libgcc_s ABI up to GCC_4.2.0. Ubuntu's official
[24.04 libc notice](https://ubuntu.com/security/notices/USN-6737-2) identifies its
2.39 libc baseline. Thus the requested symbol versions fit that distribution
baseline; this is not proof that the particular server has the expected files.

Future read-only target preflight must inspect release/architecture, actual loader
and SONAME resolution, libc/libgcc symbol definitions, existing loop/SquashFS and
tracefs support, free capacity, existing permissions and namespace propagation.
Do not run `ldd` on supplied artifacts; inspect ELF metadata. Confirm original host
mount namespace identity independently. The stage-A approved userspace probe must
also check Python relocation/imports using only the required standard modules,
without invoking any watchdog/fixture/wrapper main function. It must remain within
the same 20-second compatibility window; incompatibility stops attachment.

## Completed ownership handoff

The watchdog process is also the namespace custody owner. `supervise(custody=...)`
transfers the actual live ownership/process objects to `owner_finish`; it neither
closes their pidfds nor reconstructs ownership from a saved PID. Immutable-input
contexts and directory anchors enclose both phases. SIGINT/SIGTERM protection is
continuous across handoff; original handlers are restored only after observed
reaping. No new general launcher or separate FD-transfer service is required.

Before launching, the owner creates `out/watchdog-owner.jsonl` exclusively, writes
OWNER_ARMED with owner PID/starttime and namespace, and fsyncs the file and parent
directory. A failure here stops before launch. Later records distinguish custody,
failed-cleanup hold and actual owner release. Partial writes are handled; evidence
errors never become success. Retained handles, not that JSON ledger, remain the
live authority. The ledger is durable recovery evidence, not permission to signal
possibly reused numeric PIDs.

The 110-second session bound controls the attempt and signal policy: TERM at 105,
KILL at 107, no new launches/retries. The owner then has a 60-second observation/
reaping window; it sends no further signals. If processes are still alive or
observations remain uncertain, it records FAILED_CLEANUP_HOLD and keeps pidfds,
namespace and input anchors, observing once per 5 seconds. It must not unmount or
detach inputs. Once all direct/adopted processes are actually reaped it records
OWNER_RELEASED and exits, retaining any earlier failure classification.

**Approval must explicitly cover this pathological passive hold.** A finite hard
exit and continued custody of an unkillable process cannot both be guaranteed.
The hold performs no tracing launch, signal, mount or repair; it is a small
resource custodian, not a service installation. SIGKILL of the owner, host death,
privileged interference and filesystem/kernel stalls cannot be made safe by a
Python deadline. There is no automatic reboot, force-unmount or broader kill.
Do not terminate the custodian merely to make the nominal budget appear met.

## Perf evidence: narrow, achievable requirement

The fixture, wrapper and supervisor have no FD-transfer or pinning operations.
The fixed observer program requests no pinning/foreign FD handoff. Under the
already stated trusted-platform assumption (no external privileged actor stealing
FDs), complete direct/adopted process reaping closes their perf/BPF descriptors.
That owned lifetime evidence is the primary perf-resource cleanup argument; it
is not an assertion that all other host perf users disappeared.

The independent inventory corroborates this with stable before/after BPF program,
map and link IDs and dynamic-uprobe definitions. A differing global inventory
may reflect unrelated activity: report uncertainty and attribute it read-only;
never remove unrelated objects. `DONE`, map clearing or a successful parser alone
remain insufficient. No impossible universal enumeration of every host perf FD
is required, and the helper correctly continues to label its own coverage partial.

The exact target-only visibility check is: under the existing approved identity,
read the gated owned process's `/proc/PID/stat`, task children, fd symlinks and
fdinfo; confirm same lifetime/ownership, and ensure the inventory helper can read
its fixed tracefs path and enumerate BPF IDs without denial. The stage-A harmless
Python child may establish proc-read visibility; a live observer's BPF/perf fdinfo
can corroborate attachment while it exists. Short-lived descriptors may be gone
before sampling; absence of a sample is not itself a leak, whereas inaccessible
ownership/reaping observations make cleanup unproved. The hold policy handles
that failure. No additional mount or permission change may be used to make reads
work. This is the remaining target preflight, not unfinished local implementation.

## Exact proposed invocation and approval boundary

After the separately approved private namespace/mount construction and stage-A
compatibility checks, run the pinned image's Python (not an unspecified host
interpreter) with this fixed command shape:

```text
/tmp/sbxr-dns-a257a6e/inputs/python/bin/python3.12 -I -S -B
  /tmp/sbxr-dns-a257a6e/inputs/scripts/dns-child-session-watchdog.py
  --host-mount-namespace <independently-recorded-original-host-namespace>
  --manifest /tmp/sbxr-dns-a257a6e/inputs/scripts/runtime-manifest.json
  --output /tmp/sbxr-dns-a257a6e/out/session
  --execute-approved
```

`out` must already be fresh/local/root-owned 0700, and `session`/journal must not
exist. The owner verifies a different namespace and no propagation relationships;
it does not create mounts. The approved operator creates exactly the two private
read-only mounts and records their loop-device/backing identities as in the
proposal. Host namespace identity is a recorded preflight value, never guessed.

Request one bounded attempt: ten-minute preparation, 20-second userspace
compatibility probe, one 110-second immediate-child session and 60-second
cleanup/inventory window, plus the explicitly described passive failure hold.
The same request must name private mount/namespace/chroot, two read-only loops,
BPF/perf attachment, subreaping, precisely owned TERM/KILL and wrapper direct-child
SIGKILL. No host-wide propagation, persistent security/network/credential/service
changes, product execution, release, baseline/fault suite or automatic retry.

The source was frozen after final independent review; the image was regenerated
once afterward and all 595 files re-inspected as data. Earlier images remain as
historical evidence and must not be substituted for the exact current hash.
Local preparation is complete for this approval scope. No actual runtime result
or attachment permission has been established, and no action is authorized by
this report alone.
