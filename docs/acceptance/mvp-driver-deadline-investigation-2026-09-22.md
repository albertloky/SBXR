# MVP driver deadline investigation — 2026-09-22

## Outcome

**The deadline failure is explained and the unchanged driver suite is verified
on an appropriately fast disposable Linux VM.** No product, driver, wrapper,
fixture assertion or timeout change was needed. The existing three-second
whole-process budget was expiring during launcher/wrapper startup in the
software-emulated amd64 environment, before the fixture created its process
journal. The assertion requiring three started fixture processes could therefore
not exercise its intended cleanup branch there.

This resolves the specific deadline investigation left open by the
[operator observer repair report](mvp-operator-observer-repair-2026-09-22.md).
It does **not** turn the failed emulated run into a pass or establish live
acceptance. An additional SSH regression replay later stopped at its separate
fixture-server readiness check. That issue was not investigated or repaired in
this bounded task, so full operator sign-off remains open.

Work stayed local on `main` at base
`477a0d7a32da683b0a0b00551696e363cfbc4e6c`. No commit, push, candidate dispatch,
VPS contact, public CA request, actual proxy installation or Karing action was
performed. The prior uncommitted observer repair is preserved.

## Source and feedback loop

The retained symptom was `AssertionError: ('deadline', [])` in
[the driver/wrapper fixture](../../.github/scripts/test_mvp_protected_menu.py).
The old log did not preserve the driver's refusal phase at that assertion.

Source inspection establishes that `drive` in
[`v3-menu-session.py`](../../.github/scripts/v3-menu-session.py) computes its
absolute monotonic deadline **before** creating `MenuSession`, which launches
the protected-menu executable. The timeout includes wrapper startup, menu work
and completion; it is not a fresh three-second timer started when the fixture
becomes ready. The fixture's deadline case expects all three process records,
an acquired kernel lock and the protected window before timeout cleanup.

Artifacts are retained under
[`.scratch/acceptance/d22/`](../../.scratch/acceptance/d22/). A clearly marked,
run-local timing probe loaded the unchanged fixture source and observed parent
subprocess elapsed time, atomic journal-file timestamps, driver output/refusal,
log mode and retained window files. It changed no subject-process code or
deadline. A subsequent diagnostic selected only the existing deadline case,
preserving its body, assertions and cleanup, to reproduce the exact reported
symptom after a full-suite attempt failed earlier on the same slow runner.

Both guests used the current checksum-verified Ubuntu 24.04 images, two virtual
CPUs, 2 GiB memory, restricted egress from first boot, and pinned-key loopback
SSH. No real SBXR, sing-box or Certbot was installed. The AMD guest used QEMU
TCG; the ARM guest used hardware acceleration (HVF) on the ARM Mac.

## Measurements and verification

| Run | Observed result |
|---|---|
| amd64 TCG, initial full-suite timing probe | The first normal fixture process appeared after **10.252922 s**. The normal case reached its expected product-code fixture output, but the driver expired its existing 15-second completion deadline. Total parent-observed time was 16.127936 s. Cleanup restored the original log identity. This was not the original symptom, so the next probe isolated the deadline case rather than mislabelling this result. |
| amd64 TCG, existing deadline case selected | Reproduced **exactly** `('deadline', [])`. Driver stderr was `SBXR_MENU_SESSION_REFUSED phase=output-deadline`; stdout was empty. Parent-observed duration was **3.689709 s** (including driver interpreter startup/cleanup). `/var/log` remained **0775**, no fixture process record or ready marker existed, and only the pre-window control/result FIFOs remained before fixture cleanup. No durable window state had been created. |
| ARM64 HVF, full-suite timing probe | Normal fixture process appeared after **0.221884 s**; normal completion took 0.432696 s. In the unchanged three-second deadline case, the three journal entries appeared after **0.213737, 0.229737 and 0.245737 s**. At timeout the ready marker existed, all three processes were gone, the kernel lock could be reacquired, retained state refused reuse, and explicit restoration succeeded. |
| ARM64 HVF, original command without the probe | Entire `python3 .github/scripts/test_mvp_protected_menu.py` passed unchanged: missing/unsafe directory and argument refusals; normal and nonzero completion; protocol, deadline and cancellation cleanup; live-group recovery refusal; explicit restoration; changed-link-count refusal and cleanup. |
| Adjacent same-process driver regressions | All **14** tests in `test_v3_menu_session.py` passed on Linux, including escaped-descendant cancellation and early leader-exit cleanup. |
| Additional real-SSH regression replay | **Did not reach its cases.** `test_ssh_boundary.py` returned `SSH_BOUNDARY_REFUSED case=sshd-ready`. This is a separate fixture-startup failure, not a successful 21-case run and not a recurrence of the deadline symptom. |

The causal conclusion is deliberately narrow: the observed slow environment
exhausted the whole-process budget during startup, while the fast environment
reached the intended active-process cleanup branch with the **same** deadline.
The driver correctly enforced its deadline in both cases. These measurements
do not isolate the relative cost of emulated CPU, guest startup/cache activity
and disk synchronization, or promise timing on a future live host.

No test was skipped or weakened to make the deadline suite pass. The emulated
failures remain in `amd64/profiled.log` and `amd64/deadline-only.log`; the measured
comparison is `timing-comparison.json`. The full uninstrumented pass is
`arm64/driver-final.log`, and the adjacent test result is `arm64/driver-unit.log`.
No implementation changed, so the previous observer's real dpkg/SSH results and
native Go test/vet results remain reusable evidence for their unchanged paths;
they are not represented as newly executed checks here.

## Separate SSH readiness limit

The additional SSH suite could not establish readiness of its own temporary
sshd. Its failure log does not establish the underlying authentication/startup
reason. Read-only inspection found the fresh cloud-image root account locked;
the existing fixture's temporary sshd uses `UsePAM no`. That is a plausible
preparation lead, **not a verified diagnosis**. No account, SSH configuration,
assertion or readiness timeout was changed. Investigation stopped at this
separate problem rather than starting another repair cycle.

The previously successful SSH run remains historical evidence for its named
source and environment. The new replay cannot be reported as passed. Any next
work should first examine the isolated SSH fixture's preparation/readiness,
without touching the VPS or dispatching a candidate.

## Integrity and cleanup

All five subject files stayed byte-identical throughout:

```text
44682b19fd7d3dcfd5041f4c97c94fd1cb15770c31c69761432cfc0093191def  test_mvp_protected_menu.py
abf49f90e3380863c7f6f3d4bf3240f23b1e0c258ac77bc7afc03f34d025c66b  v3-menu-session.py
0d5721dee62f86b6f8141b4935b8e941e4012af03a41a9d12c63f5d47e4c0895  mvp-protected-menu.sh
4358cb1ec189bd33518a081702355405e9110892cf2be7e8235671005e2959eb  with-protected-log-parent.sh
9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc  protected_command_supervisor.py
```

Independent before/after audits matched original log-parent/child identities,
fixture-path absence and unrelated package inventory in each guest. No operator
or SSH-fixture process remained, and SSH/rsyslog were active before shutdown.
At `2026-09-22T04:01:20Z`, both VM processes and loopback listeners were absent.
Both configured guest disks, seeds and ephemeral keys were removed. The unused
AMD base image was removed; the unmodified public ARM base image is retained
read-only, with its official checksum, to avoid another unnecessary download
for reproducible local work. It contains no configured guest state or Owner
credentials. Exact cleanup receipts are in `cleanup.json`.

Temporary probes exist only in the explicitly marked run-local `debug/`
directory, alongside diagnostic inputs and logs. No debug instrumentation was
added to repository source. This task changes only this report and the current
operator plan's explanation of the timing-sensitive fixture.
