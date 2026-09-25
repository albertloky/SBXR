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

Use the currently reviewed permission wrapper for **one complete packaged
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
v3-menu-session.py --executable /root/sbxr-mvp-log-parent/mvp-protected-menu.sh --protected-wrapper
  -> launcher execs qualified wrapper
    -> private supervisor process group
      -> child shell sets umask 022 and execs /usr/local/bin/sbxr
        -> synchronous product descendants
```

The menu driver starts its executable in a new session. Therefore putting the
wrapper around the Python driver would not establish this boundary. Use its
existing `--executable` argument and `--protected-wrapper` opt-in to select
the launcher instead. The supervisor is unchanged; the wrapper includes the
separately approved startup cleanup repair. The September 25 launcher repair sets `022`
only inside their product child: the unchanged v3.1.81 updater needs that mask
to create `0755` executable files. Wrapper state/control files retain `077`,
and explicitly requested `0600` product files remain private. No existing file
mode is changed by setting the child mask. See the
[repair and rehearsal report](reports/ordinary-recurring-umask-repair-2026-09-25.md).
That expanded rehearsal exposed a separate startup-cancellation cleanup gap.
The [bounded cleanup repair](reports/ordinary-recurring-cleanup-repair-2026-09-25.md)
records its isolated validation and updated invocation. Native CI and the
current recurring procedure's fresh host, target, CA and attendance gates still
apply; historical qualification alone does not establish live readiness.

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

## Read-only state checks (corrected September 22)

Use the source-owned [window observer](../../.github/scripts/mvp-inspect-window.py)
instead of a copied run-local `inspect-window.py` or handwritten package
comparison. It is streamed, not a fifth staged operator file. A failed check
stops the command sequence; it never opens a permission window or runs SBXR.
Do not reuse historical observations as current expectations.

Prepare a local, private `expectation_file` from the **reviewed current**
candidate declaration, fresh host observations, and exact source checkout:

| JSON field | Expected value / authority |
|---|---|
| `proxy_package` | The unchanged `v3_attempt.proxy_package` from the verified qualification manifest (or reviewed declaration before signing). |
| `installed_binary_sha256` | SHA-256 of `./usr/bin/sing-box` extracted locally from that receipt's size/SHA-256-verified DEB. This is **not** the DEB digest. |
| `snap_packages` | Fresh reviewed `certbot`, `core24`, `snapd` entries, each containing only `version`, `revision`, `snap_sha256`, `snap_size`. Compare Certbot and snapd version/size/digest to the declared packages; preserve the reviewed core24 receipt. |
| `operator_sha256` | Map of the four staged basenames below to hashes of their reviewed source files. |
| `log_parent`, `log_children` | Fresh reviewed `metadata` and immediate directory/symlink inventory in the observer's JSON shape (`device`, `inode`, `uid`, `gid`, `mode` as an octal string, `links`, `directory`, `symlink`, `xattrs`). Use the original 0775 identity; do not adopt drift as a new baseline. |

The archive and Installed Record are separate authorities. Running requires
`dpkg-query` to report the declared version and architecture with **`hold ok
installed`** (abbreviated `hi `), even when the downloaded DEB is absent.
Successful setup intentionally removes `/var/lib/sbxr/sing-box_1.13.19_amd64.deb`;
its presence, including a broken symlink, is a refusal in these steady states.
The Ownership Record's `proxy_package_identity` is the space-joined string
`repository name version architecture size sha256`, **not** the declaration
object and not its signing-key field. The observer performs that comparison.
Renewal-attempt completion is checked independently of the temporary DEB.

Snap images may have multiple hard links because snapd uses a content cache.
The observer still requires regular root:root files, no group/other write bits
or extended attributes, and the exact reviewed version, revision, size and
SHA-256. It does not require a cache entry or a fixed link count and does not
modify either link. Operator files, installed records, executables and lock
files retain their one-link requirement; this exception changes no product
trust check.

Use `phase=not-installed` before installation; `not-set-up` after successful
installation/streamed candidate verification but before Start setup; `running`
after successful setup and before/after each subsequent menu process; and
`removed` after successful Complete removal, before deleting operator files.
The first, second and last phases require package absence; only `not-set-up`
expects the SBXR executable and Installed Record to remain. A transition or
incomplete state is **not** Running; stop and review it instead of relabelling
it to make this check pass. Reviewed failure cleanup still needs the separate
legal-action assessment described below.

Set `window_seconds=900`, or the smaller reviewed driver/collector bound, and
set `observation_file` to a fresh local run artifact. Use the same authenticated
connection options as the installed-candidate check. Neither `-n` nor
`StdinNull=yes` is permitted. From the source checkout:

<!-- mvp-window-observer-ssh -->
```sh
case "$phase" in not-installed|not-set-up|running|removed) ;; *) exit 1 ;; esac
case "$window_seconds" in ''|*[!0-9]*) exit 1 ;; esac
expectation_b64=$(python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1], "rb").read()).decode())' "$expectation_file")
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
  "${ssh_options[@]}" "$acceptance_host" \
  "python3 - '$phase' '$expectation_b64' --window-seconds '$window_seconds'" \
  < .github/scripts/mvp-inspect-window.py > "$observation_file"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["phase"] == sys.argv[2] and d["operator_files_verified"] and d["locks_unheld"] and d["writers_idle"]' "$observation_file" "$phase"
```

Run under `set -euo pipefail` (as in the candidate handoff) and require exit 0
before continuing. Base64 only transports non-secret receipt JSON safely through
the SSH command; it provides no authenticity. The local JSON check also refuses
an empty/missing streamed program instead of accepting Python's empty-input exit.
Never replace the resulting structured package observation with an `ii` string
assertion or infer package absence from a missing download. The observer checks
all declared snap receipts, original log identities, four staged files, retained
state absence, timer margin, writer processes, kernel locks and package/renewal
state. It emits no private Ownership Record contents or process command lines.

This supplements, rather than replaces, installed-candidate verification,
product menu Review, full protected-footprint absence after removal, logging
health, CA budget and outside/Karing observations. It is a point-in-time check,
not a lock against subsequent unrelated host activity or an acceptance pass.

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
on-host SHA-256 values against the exact reviewed source manifest. The current
wrapper includes the September 25 startup-cancellation repair; the supervisor
is unchanged. These bytes supersede the earlier wrapper for current MVP work,
not the historical v3.1.75 maintenance receipt:

```text
56fab3f89dbed0dbb668f296a33ac8b512e8676edb5962a796a45bbc649123de  with-protected-log-parent.sh
9861f9a16af051c9dcb7d21324ddb97a60690f3cf3fca7987f6c642d972a56cc  protected_command_supervisor.py
```

The launcher itself pins the wrapper hash; the wrapper pins its supervisor.
Neither establishes the installed candidate identity. Complete the normal
packaged candidate/attestation checks independently before any menu action.
Use the [current streamed SSH identity check](mvp-live-acceptance.md#checking-the-installed-candidate-over-ssh)
after installation; it needs no additional staged file or permission window.

For example, the reviewed replacement remains one menu-driver call:

```sh
export SBXR_QUALIFICATION_REQUEST=/root/sbxr-qualification-evidence/request.json
python3 /root/sbxr-mvp-log-parent/v3-menu-session.py \
  action 'Replace subscription certificate' \
  PROXY-INSTALLATION-SUBSCRIPTION-CERTIFICATE-REPLACED \
  --confirmation yes \
  --executable /root/sbxr-mvp-log-parent/mvp-protected-menu.sh --protected-wrapper
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

Use `--protected-wrapper` for every menu-driver invocation of this launcher.
The controlled-update caller selects the same behavior with its existing
`--protected-log-parent` option. Direct product execution and historical
interruption helpers retain their original immediate termination behavior;
they must not be substituted for this protected-window invocation.

On a driver timeout, protocol error or cancellation, the opted-in driver sends
USR1 only to its unreaped wrapper leader and gives startup cleanup at most twenty
seconds before the existing SIGKILL/group/adopted-descendant cleanup. This is
safety cleanup after failure, not additional journey or observation time.
Before product admission, the wrapper can remove only its own newly created,
identity-checked channels and restore its valid state. After admission might
have happened, it retains state without automatic permission restoration: the
driver must first finish terminating/reaping every descendant. A retained valid
state with the exact original directory identity and mode 0755 or 0775 is a
recovery condition, not a successful window. No operational orphan-channel
deletion route is added. Forced death or an unproved cleanup remains a stop.

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

The following paragraphs record the original September 19/21 qualification.
For the September 25 startup repair and revised wrapper, use its
[separate report](reports/ordinary-recurring-cleanup-repair-2026-09-25.md);
do not transfer an earlier pinned-byte claim to the new revision.

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

The driver's three-second deadline fixture counts launcher/wrapper startup in
its budget. The [September 22 timing investigation](reports/mvp-driver-deadline-investigation-2026-09-22.md)
reproduced expiration before fixture startup in a slow software-emulated guest,
then verified the full unchanged suite on an ARM64/HVF guest. Use an adequately
fast disposable Linux environment for this active-process cleanup test; retain
any earlier expiration as a failure, rather than lengthening the timeout,
skipping the case or counting an empty process journal as cleanup proof.

For the separate systemd test, cross-build `go test -c
./internal/proxyinstallation` using Go 1.26.6 for the VM architecture. Stage the
unchanged wrapper (0700) and supervisor (0600) under a root:root 0700 directory,
then invoke the test executable as root with `SBXR_ISOLATED_SYSTEMD=1`,
`SBXR_LOG_PARENT_WRAPPER_DIR` set to that absolute directory, and
`-test.run=^TestProtectedLogParentPerMenuWindowIntegration$ -test.v`.
Use a private run-local `TMPDIR`. Its fixtures clean the synthetic installation,
services, certificates, group, address and log-parent mode. Neither executable
test is permitted on the real VPS.

## Observer regression rehearsal

The source-owned observer has portable contract tests and a separate disposable
amd64 Ubuntu VM rehearsal. This second fixture is different from the synthetic
systemd/TLS test above: it installs, holds, removes and purges the actual pinned
sing-box DEB, without starting sing-box. The SBXR records/menu and snap CLI/images
are synthetic. Real OpenSSH executes the documented streamed observer against
real dpkg, filesystem metadata, a real systemd timer and kernel locks. Successful
menu and purge windows use the unchanged launcher/driver/wrapper. No public CA,
VPS, outside traffic or Karing action belongs in this regression.

Only in a freshly marked disposable **amd64** VM, with restricted egress and no
preexisting fixture resources, stage this checkout and the independently verified
pinned DEB. Keep the source tree layout intact. Use a new temporary directory
under that checkout's `.scratch/acceptance/<run>/` and run:

```sh
python3 .github/scripts/test_mvp_inspect_window_linux.py /absolute/path/to/verified-sing-box.deb
```

The marker and exact DEB checks are mandatory, and the fixture refuses existing
product, shared Certbot, operator, lock and timer paths. Its `finally`/cleanup
stack purges the package and removes its own fixtures even on an assertion
failure. Set `MVP_OBSERVER_INJECT_FAILURE=1` only for the separate expected-failure
cleanup check; require its named assertion, then independently audit fixture
absence and restored original log identity. Never run this fixture on the VPS.
Retained wrapper state is not blindly deleted if restoration fails. The ordinary
Go wrapper is opt-in via `SBXR_MVP_OBSERVER_DEB`; portable contracts always run.

The [September 22 observer repair report](reports/mvp-operator-observer-repair-2026-09-22.md)
retains the successful focused lifecycle rehearsal and original emulated-driver
failure. The [deadline investigation](reports/mvp-driver-deadline-investigation-2026-09-22.md)
explains that timing failure and verifies the unchanged driver suite, while
recording a separate incomplete SSH-fixture replay. The subsequent
[SSH readiness repair](reports/mvp-ssh-fixture-readiness-repair-2026-09-22.md) closes that
replay gap: the fixture now isolates its account record rather than inheriting
the host root lock, and all 21 real-SSH cases plus locked-account success/failure
regressions pass locally. Host accounts and the four staged operator files stay
unchanged. These are complementary local regression results, not live
qualification or authorization to dispatch a candidate.
