# Subscription recorder refresh and removal boundaries

Research snapshot: 2026-08-31. Supports [Preserve Subscription Serving through Complete removal and updates](https://github.com/albertloky/SBXR/issues/338). This is primary-source research and engineering analysis, not an approved policy, implementation, or VPS acceptance record. It uses the vocabulary in `CONTEXT.md` and extends [the Certbot transition research](https://github.com/albertloky/SBXR/blob/36216d19ee7cc62b2c471171d6494f4c5016d791/docs/research/339-subscription-certbot-transition-hooks.md). The issue's resolution is the authority for decisions made after this research snapshot.

Sources inspected: Certbot `e75e7378cd024d74d18a22c66d5aea32abd474c7` (`v5.7.0`), snapd `b8d296798ecc2cec33c7edf495c71347defcfba9`, and systemd `91927a2a1281be60f931e90d78e851d8ffd0688f`. These upstream snapshots do not identify the installed VPS packages.

## Finding

An owned drop-in can gate the known official scheduled service without adding a renewal timer. The inspected code supports persistence when snapd rewrites that same unit file. **This does not prove prevention of unrecorded renewal across arbitrary future snap refreshes.** A new or renamed service can bypass the old name-specific drop-in before SBXR next inspects it. A watcher that notices changes afterward also cannot prove prevention. Strict prevention requires control before an unsupported route can execute, or a narrower supported-route contract.

## Verified source facts

### Official scheduled route

Certbot declares a `renew` oneshot app that runs `bin/python3 -s $SNAP/bin/certbot -q renew` on `00:00~24:00/2`. It also exposes the separate normal `certbot` app. [Certbot snap definition](https://github.com/certbot/certbot/blob/e75e7378cd024d74d18a22c66d5aea32abd474c7/snap/snapcraft.yaml#L42-L49)

Snapd generates a service's `ExecStart` from `LauncherCommand`. For a timer app, that command includes `snap run --timer=...` and the snap/app name. Service naming uses its security tag plus `.service`; service files are generated under `/etc/systemd/system`. For the ordinary `certbot` instance, this yields `snap.certbot.renew.service`. A wrapper must preserve the qualified official launcher semantics, including the timer argument, rather than assume plain `certbot renew` is identical. [Service template](https://github.com/snapcore/snapd/blob/b8d296798ecc2cec33c7edf495c71347defcfba9/wrappers/internal/service_unit_gen.go#L159-L189) [Launcher and service naming](https://github.com/snapcore/snapd/blob/b8d296798ecc2cec33c7edf495c71347defcfba9/snap/info.go#L1533-L1588) [Directory](https://github.com/snapcore/snapd/blob/b8d296798ecc2cec33c7edf495c71347defcfba9/dirs/dirs.go#L422-L427)

Snapd regenerates each current app's service file. Its inspected service-removal routine deletes enumerated service, socket, and timer files; that routine does not recursively delete service drop-in directories. This supports same-name persistence in these paths, not a general promise about every present or future refresh path. [Generation](https://github.com/snapcore/snapd/blob/b8d296798ecc2cec33c7edf495c71347defcfba9/wrappers/services.go#L595-L644) [Removal](https://github.com/snapcore/snapd/blob/b8d296798ecc2cec33c7edf495c71347defcfba9/wrappers/services.go#L1112-L1206)

Snap documents that refresh can stop and start services. Therefore a pre-refresh observation alone does not freeze the running route. [Snap refresh awareness](https://snapcraft.io/docs/explanation/how-snaps-work/refresh-awareness/)

### What a drop-in guarantees

Systemd applies drop-ins after the main unit. Different filenames are processed in lexical order; later configuration can change the result. Systemd explicitly warns that future vendor updates can be incompatible with local drop-ins. A drop-in attached to one unit name has no documented rule that follows a renamed app automatically. [Drop-in ordering](https://github.com/systemd/systemd/blob/91927a2a1281be60f931e90d78e851d8ffd0688f/man/systemd.unit.xml#L205-L249) [Vendor compatibility warning](https://github.com/systemd/systemd/blob/91927a2a1281be60f931e90d78e851d8ffd0688f/man/systemd.unit.xml#L2677-L2687)

An empty `ExecStart=` resets the command list. A failing non-ignored `ExecStartPre=` prevents `ExecStart=`. However, processes started by `ExecStartPre=` are killed before the next service process; it cannot leave a lock-holder process behind. A process-held exclusion spanning child execution must live in the actual wrapper or another explicitly designed lifecycle. Stopping a service can terminate its remaining processes, so service stop is not an idle-only removal gate. [Command reset and start ordering](https://github.com/systemd/systemd/blob/91927a2a1281be60f931e90d78e851d8ffd0688f/man/systemd.service.xml#L403-L459) [Stop behavior](https://github.com/systemd/systemd/blob/91927a2a1281be60f931e90d78e851d8ffd0688f/man/systemd.service.xml#L545-L562)

### Certbot exclusion

Certbot's Unix directory lock uses nonblocking `fcntl.lockf`, validates the file descriptor's device/inode against the current lock path, and removes the lock file before releasing it. A competing lock acquisition fails. A process list, a lock-file existence check, or an unrelated `flock` is not equivalent evidence. Any compatible gate must preserve these file-identity and lock semantics and cover the effective directories used by the supported Certbot route. [Certbot lock implementation](https://github.com/certbot/certbot/blob/e75e7378cd024d74d18a22c66d5aea32abd474c7/certbot/src/certbot/_internal/lock.py#L99-L181)

Certbot's directory locks do not establish that an independent SBXR receipt writer or hook is idle. The earlier research also establishes that a failing Certbot pre-hook does not prevent renewal. Neither mechanism alone supplies the complete removal gate. [Earlier verified hook and lock findings](https://github.com/albertloky/SBXR/blob/36216d19ee7cc62b2c471171d6494f4c5016d791/docs/research/339-subscription-certbot-transition-hooks.md)

## Design consequences, not new decisions

### Supported-route inspection

Before admitting an attempt through the owned recorder, verify the qualified snap/app identity, current metadata, generated service and timer route, effective merged commands and drop-ins, recorder bytes, receipt-store access, and hook configuration. Refuse before launching Certbot when those facts are unknown or unsupported. Validate the effective route, not merely the presence of the owned drop-in on disk. Keep missing or unfinished receipts visible as unknown outcomes.

This protects executions that actually enter the gate. It cannot protect a newly introduced route that never invokes it. SBXR inspection can detect observed drift and report `Problem detected`; it must not retroactively claim the interval was fully recorded. Likewise, SBXR update compatibility approval cannot control independent Certbot or snapd refreshes.

Do not execute arbitrary changed `ExecStart` text found on disk. A compatible official route must be recognized under a specified contract. Do not erase unrelated drop-ins to make inspection pass. A conflict is a refusal or an explicit repair decision.

### Removal must close admission before deleting

The approved policy is to refuse before Removal committed if Certbot or a recorder writer is active, without killing shared Certbot. A safe implementation needs exclusion, not a check followed by deletion:

1. Obtain the required SBXR mutation authority and an exclusive admission gate shared with every owned recorder/hook writer. If an active holder prevents acquisition, release what was acquired and refuse before commitment.
2. Establish compatible Certbot directory exclusion for the supported configuration. Contention or uncertain observation refuses removal. Hold the relevant gates while rechecking freshness and while admitting no new destructive overlap. Define one lock order and use nonblocking acquisition where needed to avoid parent/hook deadlock.
3. At Removal committed, retain a durable refusal state for owned entry points. Process locks vanish on death; they cannot alone protect an interrupted removal after reboot. Newly started owned hooks must not recreate removed state or act on stale authority.
4. Remove only proved owned lineage, hooks, recorder integration, serving resources, and evidence through the approved forward-completion path. Never delete or recreate a live shared lock inode as a shortcut.
5. Restore the preserved current official route only when its remaining configuration cannot call removed SBXR code. Re-observe that no owned entry point or writer remains before removing its durable evidence and finishing runtime.

These are required properties, not a proven command sequence. A direct Certbot invocation using other directories is outside the common lock domain. A root actor can bypass local gates. The specification must say which invocations are supported and what counts as drift. Concurrent snap refresh is another external writer; observing no snap operation once does not exclude one from starting later.

Refusal gates also affect unrelated lineages when they block the shared official `renew` invocation. That consequence must remain explicit, including after a crash: preventing an unsafe shared run can delay unrelated renewal until completion or repair.

### Restore current configuration; remove only owned files

Do not restore an old copied service file: snapd may have installed a newer valid official route. Remove the exact owned drop-in after verifying its ownership and content, keep unrelated drop-ins, reload systemd, and inspect the resulting current route. Delete an owned directory only if empty. Conflicting or unrecognized state requires refusal before commitment, or a stated forward-completion repair after commitment; it does not authorize overwriting unrelated state.

`systemctl revert` is unsuitable: it removes all matching drop-ins and can unmask a unit. A simple `systemctl mask` recipe is also not established here: masking may fail when a unit already exists in `/etc/systemd/system`, where snapd generates its services. Replacing that vendor-generated file to force a mask would add another ownership and restoration problem. [Revert behavior](https://github.com/systemd/systemd/blob/91927a2a1281be60f931e90d78e851d8ffd0688f/man/systemctl.xml#L1220-L1238) [Mask restrictions](https://github.com/systemd/systemd/blob/91927a2a1281be60f931e90d78e851d8ffd0688f/man/systemctl.xml#L1161-L1182)

## Policy still to settle

- **Refresh coverage:** accept a qualified known-route guarantee with drift detection, or require control over refresh admission before any changed route can run. Automatic adaptation to arbitrary future snap changes is not supported by this evidence. A separate after-the-fact watcher is not by itself the stronger guarantee.
- **Shared-host boundary:** specify supported direct Certbot entry points and handling of independent timers, custom directories, unrelated overrides, and simultaneous snap operations. Do not claim host-wide coverage from a single service drop-in.
- **Interrupted removal:** specify the durable gate's owner, its recovery after reboot, and how the official shared route is restored without calling deleted SBXR code or indefinitely hiding a blocked renewal.

The approved separation remains intact: the Ownership Record keeps the creating Release Identity; Removal committed separately binds the installed finishing release. Compatible SBXR updates preserve installation resources and credentials, gate unsupported compatibility, and provide precommit rollback. These decisions do not settle the external refresh boundary above.

## Acceptance still required

Run the exact packaged executable on a disposable VPS with the actual snapd/systemd/Certbot versions. Prove same-name snap refresh, changed-command refusal, a renamed/additional-route negative case, competing drop-ins, recorder start-write failure, child/writer/hook contention, direct supported Certbot contention, and crashes/reboots on both sides of Removal committed. Verify unrelated certificates and overrides survive, no shared Certbot is killed by removal, owned writers cannot return after deletion, and the current official route works after integration removal. Prove update rollback and interrupted removal using the exact bound release bytes.

No such packaged or VPS checks were performed for this note. Source inspection establishes mechanism limits; it does not satisfy these acceptance requirements.
