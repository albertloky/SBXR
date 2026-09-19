# Temporary log-parent windows for MVP — 2026-09-19

This is the bounded operator plan for the existing `/var/log` protected-parent
prerequisite. It adds no journey to [MVP live acceptance](mvp-live-acceptance.md)
and changes no product trust rule, package, service unit, timer or tmpfiles rule.
The September 19 maintenance restored the original root:syslog 0775 mode. Its
retained VPS observations are historical; this document does not establish a
current clean host, CA capacity, candidate approval or live acceptance.

The Owner approved local preparation and validation. No live CA or host recheck
may begin before `2026-09-21T03:38:39Z`. The one-time v3.1.75 snapshot-recovery
plan is complete and must not be replayed on the removed installation.

## Chosen boundary

Use the unchanged qualified permission wrapper for **one complete packaged
menu process at a time**, including initial review, confirmation, synchronous
mutation, local verification and output. Restore the original mode after each
process. Keep outside HTTPS/proxy checks and Karing observations between these
windows, with `/var/log` at its original 0775 mode.

The [temporary launcher](../../.github/scripts/mvp-protected-menu.sh) accepts
zero arguments and invokes only `/usr/local/bin/sbxr`. It does not replace that
installed executable. Stage it with the qualified wrapper and supervisor in
`/root/sbxr-mvp-log-parent`, outside the workflow's qualification directories.
The exact process chain is:

```text
v3-menu-session.py --executable /root/sbxr-mvp-log-parent/mvp-protected-menu.sh
  -> launcher execs qualified wrapper
    -> private supervisor process group
      -> /usr/local/bin/sbxr and its synchronous Certbot descendants
```

The menu driver starts its executable in a new session. Therefore putting the
wrapper around the Python driver would not establish this boundary. Use its
existing `--executable` argument to select the launcher instead. No driver,
wrapper or supervisor change is required.

Installation and the entire **Start setup** session run through the ordinary
packaged path at 0775, using the unchanged menu driver with
`--executable /usr/local/bin/sbxr`. Setup installs the pinned sing-box package;
it does not require the Certbot log-parent window. Its final Running menu can
show subscription actions unavailable without invalidating the setup result.
An interrupted setup's status/details, Finish setup and Finish cleanup also use
the ordinary route at 0775; those operations can install/remove that package.

Once setup reaches Running, all subsequent packaged menu invocations use the
launcher: status/details, Check, configuration/link disclosure, enablement,
identity and link rotation,
replacement, legal finishing actions, and Complete removal. Do not split a
reviewed action and its confirmation into different processes. Do not invoke
Certbot directly, background a mutation, or hold 0755 using an idle sentinel
while another SSH session performs product operations.

Exporting `SBXR_EXECUTABLE` alone does not rewrite hard-coded inspections in
`v3-packaged-live.sh`. The current MVP collector does not perform the product
journeys. Review the new operator commands explicitly; do not execute retained
historical journey scripts unchanged or claim their direct menu calls are
wrapped. Read-only direct inspections may display unavailable subscription
actions at 0775; use the launcher for the actual menu observations.

## Fresh prerequisites before dispatch and each window

The original candidate-readiness gates still apply: exact-source main/CI,
clean-host and package facts, two-operation CA budget, outside path, Karing,
and concrete signing/live reviews. Review this plan and the exact launcher,
wrapper, supervisor and menu-driver identities before dispatch. Transfer the
temporary operator files only after the concrete live gate permits host work.

The short-window plan additionally requires fresh observations of this existing
host shape:

- `/var/log` is the original real root:syslog 0775 directory, without extended
  attributes. Record its device, inode, owner/group, link count and mode, plus
  the names and identities of its immediate child directories.
- `/var/log/letsencrypt` already exists as a real root-owned directory, without
  group/other write permission, symlink substitution or extended attributes.
  Inspect the three existing Certbot directories and lock state normally.
- `snapd` and the declared official Certbot package are already present and
  stable. After setup, the installed sing-box package must also match the
  declared pinned 1.13.19 amd64 receipt. Freshly compare all three receipts
  immediately before each Running-phase invocation;
  the launcher itself enforces the log-directory prerequisite, not the package
  receipts. No package/snap installation, refresh or other host maintenance is
  part of a permission window. Their installation scripts are not covered by
  this plan.
- SSH and logging are healthy. Retain the existing rsyslog tmpfiles-rule hash,
  `rsyslogd -N1` and `logrotate --debug /etc/logrotate.conf` results. Debug
  validation must not be replaced by a real log rotation.
- The staged operator directory and files have the reviewed identities and
  protected metadata. `window.state`, `window.state.control` and
  `window.state.result` are absent, including broken symlinks. No earlier
  driver, wrapper or Certbot process is left running.
- Product renewal evidence and Certbot activity are idle. The ordinary timer
  remains unchanged; its next firing must not cross the bounded mutation
  window. Respect the current collector deadline and driver timeout. Do not
  stop the shared timer or lengthen an acceptance deadline to manufacture a
  pass.

The wrapper pins `/var/log`'s link count. If initial issuance creates a missing
`/var/log/letsencrypt`, or another process creates/removes an immediate log
subdirectory, restoration correctly refuses the changed directory identity.
The launcher therefore refuses a missing/unsafe shared log directory before
opening the window. Do not create that directory or install dependencies as
unreviewed preparation. Stop and report a different fresh host shape.

Record the directory identity and child-directory inventory immediately before
each window and compare afterward. The wrapper does not freeze unrelated host
activity; any drift is an unexpected result, even if the menu action succeeded.

Complete removal includes the product's owned sing-box purge. This is the
specific existing removal case already exercised inside the unchanged wrapper
by the September 19 original-menu qualification, with the same pinned sing-box
1.13.19 amd64 package (`fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf`).
Reverify the declared/installed package identity. That retained result does not
authorize installation or removal of other packages inside a window, nor does
it prove the future candidate's complete removal journey.

## Staging and invocation

After the preceding live gate is accepted, create a new root:root 0700
`/root/sbxr-mvp-log-parent` directory, refusing any existing path. Transfer only
these reviewed source files, with no credentials in the staged scripts:

| File | Source | Mode |
|---|---|---|
| `mvp-protected-menu.sh` | `.github/scripts/mvp-protected-menu.sh` | 0700 |
| `with-protected-log-parent.sh` | `.github/scripts/sbxr-snapshot-recovery/with-protected-log-parent.sh` | 0700 |
| `protected_command_supervisor.py` | `.github/scripts/sbxr-snapshot-recovery/protected_command_supervisor.py` | 0600 |
| `v3-menu-session.py` | `.github/scripts/v3-menu-session.py` | 0600 |

Require root:root, regular one-link files without symlinks/xattrs. Compare their
on-host SHA-256 values against the exact reviewed source manifest. The wrapper
and supervisor remain:

```text
4358cb1ec189bd33518a081702355405e9110892cf2be7e8235671005e2959eb  with-protected-log-parent.sh
9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc  protected_command_supervisor.py
```

The launcher itself pins the wrapper hash; the wrapper pins its supervisor.
Neither establishes the installed candidate identity. Complete the normal
packaged candidate/attestation checks independently before any menu action.

For example, the reviewed replacement remains one menu-driver call:

```sh
export SBXR_QUALIFICATION_REQUEST=/root/sbxr-qualification-evidence/request.json
python3 /root/sbxr-mvp-log-parent/v3-menu-session.py \
  action 'Replace subscription certificate' \
  PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED \
  --confirmation yes \
  --executable /root/sbxr-mvp-log-parent/mvp-protected-menu.sh
```

This is an execution example, not a capacity probe or instruction to run it
before the renewal journey. Use the current request's scenario, actual timing
and the existing expected result for each action. Preserve private output in
the private run directory; never commit live links, tokens, UUIDs or raw client
configuration. A read-only initial menu may be obtained with
`printf '0\n' | /root/sbxr-mvp-log-parent/mvp-protected-menu.sh`.

After every normal command, require the exact original `/var/log` identity and
0775 mode, unchanged immediate-directory inventory, and absent state/FIFOs.
The wrapper restores before its launcher returns. A successful product code
without successful wrapper restoration is a failed acceptance observation.

Ordinary service restart may occur at 0775. Confirm real listener readiness and
trusted outside TLS after it: `Type=simple` systemd start completion alone is
not application readiness. Do not claim natural timer execution or Karing
acceptance from these checks.

## Refusal, interruption and cleanup

Any unexpected result ends test mutations and preserves the original outcome.
There is no automatic retry of certificate enablement/replacement or a failed
candidate. The existing collector records failure and burn; cleanup cannot
change that result.

On a driver timeout, protocol error or cancellation, its current cleanup uses
SIGKILL on the launcher group and reaps adopted descendants. This can kill the
wrapper before restoration. A retained valid state with `/var/log` at 0755 is
the qualified recovery condition, not a successful completed window.

First preserve the driver result, state and private process observations.
Require the driver to have finished descendant cleanup, the recorded controller
and its process group to be quiescent, unchanged boot/directory identity, no
open control channels, idle Certbot/managed writer state, and released locks.
A `process-cleanup` or `descendant-cleanup` failure is a stop requiring review.
Do not signal guessed/reused PIDs, delete state, force chmod, or start a second
window. After exact quiescence is established, the existing explicit recovery
command is:

```sh
bash /root/sbxr-mvp-log-parent/with-protected-log-parent.sh \
  restore /root/sbxr-mvp-log-parent/window.state
```

The command rechecks its authority and refuses a live group or changed state.
Require the normal restored-directory and absent-state results afterward. A
link-count or other identity mismatch is not permission to remove an unrelated
log directory or alter the saved record; retain evidence and stop for review.

The manifest-v3 workflow cleans its qualification transport on failure; it does
not perform uncertain product removal. Review the remaining installation.
Unfinished setup before any subscription attempt uses the ordinary setup cleanup
route at 0775 described above. For a reviewed Running/subscription state, perform
only the legal public finishing/removal action through the launcher. If the
exact installed executable is absent or its Installed/Ownership state differs
from the reviewed shape, retain evidence and stop. A late interrupted removal
can require supported exact-finisher restoration; that needs its own concrete
review before the launcher is usable. Do not replay the historical recovery or
infer product absence from a missing executable alone.

This separate cleanup must not read a failed/STOP collector request as
authorization: clear `SBXR_QUALIFICATION_REQUEST` for the cleanup command and
retain its actual result separately. Do not submit cleanup as a passing journey.

After normal Complete removal or reviewed failure cleanup, prove owned-resource
absence and unrelated preservation using the current procedure. Recheck the
original log-directory identity/mode, rsyslog tmpfiles-rule digest, active SSH
and logging, `rsyslogd -N1`, logrotate debug, and a unique syslog marker. Retain
secret-safe observations before deleting only the exact staged operator files
and their now-empty directory. If state, FIFOs, live processes or unrecognized
files remain, retain the directory and report the blocker.

## Local validation and limits

The focused [Linux/systemd test](../../internal/proxyinstallation/protected_log_parent_linux_test.go)
uses the production host trust checks, kernel locks, systemd serving role and
TLS listener. Its installed records and locally trusted certificates are
synthetic. The proxy workload is a TCP fixture; it is not live sing-box traffic.
The test proves unwrapped 0775 exclusion refusal, successful 0755 exclusion,
real contention refusal, wrapper restoration, serving at restored 0775,
correct/wrong-token HTTPS, ordinary restart and preserved files/lock inodes.

The [driver integration test](../../.github/scripts/test_mvp_protected_menu.py)
uses the actual menu driver, launcher, qualified wrapper and supervisor with a
numbered-menu protocol fixture. It tests process/session handling, nested
Certbot-like and escaped-session children, real file-lock release, normal and
nonzero exit, protocol/deadline/cancellation failure, live-group restore refusal,
refusal to reuse retained state, explicit recovery and the directory-link-count
constraint. It does not simulate actual product acceptance results.

Both tests run only in an explicitly marked disposable root Linux VM. The
existing wrapper's unchanged full signal/refusal qualification remains valid;
these tests exercise its new caller boundary. Final results and exact source
identities are retained under `.scratch/acceptance/p21/`. Local proof does not
establish packaged amd64 VPS behavior, real CA issuance, outside traffic,
natural renewal, Karing observations or the five live acceptance journeys.

The disposable Ubuntu 24.04 ARM64/HVF run passed the focused systemd test in
1.34 seconds and the final driver suite, including explicit restoration after
all three driver failure modes. The original unwrapped trust check refused at
0775; the same real exclusion succeeded only inside the 0755 window. The full
local `GOTOOLCHAIN=go1.26.6 go test ./... -count=1` and `go vet ./...` also passed.
An earlier driver run is retained separately: review found its unsafe-directory
fixture was affected by umask, so the final run explicitly sets/asserts 0775 and
requires the exact prerequisite refusal. No product check was weakened.

To repeat the focused proof, use a fresh disposable Ubuntu/systemd VM with
the explicit root-owned 0600 `/run/sbxr-isolated-test-host` marker containing
`disposable SBXR test VM\n`. Keep its egress restricted and install no real
Certbot, sing-box or SBXR. Stage the repository scripts together, preserving
their relative paths, and run `python3 .github/scripts/test_mvp_protected_menu.py`
as root. It refuses existing product, launcher-directory and shared-log fixture
paths and cleans its own files even on assertion failure.

For the separate systemd test, cross-build `go test -c
./internal/proxyinstallation` using Go 1.26.6 for the VM architecture. Stage the
unchanged wrapper (0700) and supervisor (0600) under a root:root 0700 directory,
then invoke the test executable as root with `SBXR_ISOLATED_SYSTEMD=1`,
`SBXR_LOG_PARENT_WRAPPER_DIR` set to that absolute directory, and
`-test.run=^TestProtectedLogParentPerMenuWindowIntegration$ -test.v`.
Use a private run-local `TMPDIR`. Its fixtures clean the synthetic installation,
services, certificates, group, address and log-parent mode. Neither executable
test is permitted on the real VPS.
