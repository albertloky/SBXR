# V4 operator harness

This directory prepares the 25 live scenarios in ADR-0022. It does not produce
passes from fixture results. The installed candidate is exercised through its
zero-argument public menu and its official service routes. The collector remains
the authority for scenario order, deadlines and cumulative evidence acceptance.

## Rehearsal before candidate preparation

From the repository root, run `bash .github/scripts/v3-operator/rehearse.sh`.
This checks split entry points in a fresh environment, rejects missing and
mismatched candidate inputs, and runs the Python helper tests. It substitutes
host actions at bounded entry seams and is not a product integration test.

The kernel controls currently require root x86-64 Linux with cgroup v2, systemd, fanotify,
ptrace, BPF cgroup egress support, Python 3, iproute2, iptables, util-linux and the
installed snap interpreter. Use a separately authorized host. Build the harmless
fixture with the project's pinned Go toolchain:

```sh
GOOS=linux GOARCH=amd64 GOTOOLCHAIN=go1.26.6 go build \
  -o /absolute/private/fixture .github/scripts/v3-operator/fixtures/file-boundary.go
```

Copy the operator directory, sibling `v3-packaged-live.sh` and
`v3-candidate-dispatch.sh`, `v3-recurring-evidence.sh`, and
`docs/acceptance/v4-operator-procedures.md` and
`docs/acceptance/evidence-assembly.md` into a
unique temporary repository-shaped tree on the Linux host. Preserve their
repository-relative paths. Copy the fixture separately into that temporary
tree. Do not copy private candidate data. Run there:

```sh
python3 /absolute/private/v3-operator/rehearse-linux.py \
  --fixture /absolute/private/fixture \
  --interpreter /snap/certbot/REVISION/usr/bin/python3.12 \
  --output /absolute/private/linux-rehearsal.json
```

When transferring from macOS, use a metadata-free archive (for example Python
`tarfile`) and exclude `__pycache__`, `.DS_Store` and AppleDouble `._*` files.
The exact-source gate rejects transfer metadata that changes the inventory.

Resolve the interpreter from the installed snap metadata; `REVISION` is not a
literal argument. The two snap cases execute only `--version` in uniquely named,
egress-blocked fixture units. The firewall case runs in a new network namespace.
The fixtures never start the official renewal service, install SBXR or request a
certificate. The controller tests cover sequencing and refusal using a modeled
OS; the kernel tests exercise the actual Linux mechanisms separately.

Retrieve the mode-0600 report and every sibling fixture log, retain them
privately with their original names and mode 0600, and remove the exact temporary
fixture directory after checking that its units, processes and cgroups are gone.
Before candidate check/dispatch, set:

```sh
export SBXR_OPERATOR_REHEARSAL_REPORT=/absolute/private/linux-rehearsal.json
python3 .github/scripts/v3-operator/check-readiness.py
```

Readiness requires all Linux fixture cases, including the entry suite, an age
of at most 24 hours, exact hashes for every helper/test source, the README,
procedure document, packaged-live module, collector and dispatch wrapper, and intact
protected fixture logs matching their recorded hashes. It validates the reported
Linux/root/x86-64 and snap interpreter provenance, then reruns the local entry
suite. The report is operator-controlled evidence, not independent attestation
of the remote host or interpreter bytes.
Any changed helper requires a fresh report. The runner retains private per-case
logs alongside its report, including failed-case diagnostics. The Go child
fixture repeats all four boundaries six times to exercise concurrent thread exits. Missing, failed, stale or mismatched
reports refuse V4 preparation. Passing this gate neither authorizes a candidate
nor proves its future live results. The ordered-syscall fixture also proves
successive holds remain on one Go process and refuses an early release or an
extra continuation. The startup-unit fixture uses a separate temporary service
and target to prove that denied ordinary starts leave a later authorized start
possible; it never starts SBXR.

The `interrupt-menu` fixture runs the real packaged `interrupt_at` function with
a temporary executable. It covers a delayed progress boundary, timeout, early
menu exit, descendants holding locks, and a descendant that creates another
session. It verifies that the controller reaps its descendants while preserving
an unrelated process. No fixture installs or invokes the SBXR product.

## Operator bundle and inputs

For an authorized future attempt, retain an exact copy and digest inventory of
this directory, `v3-packaged-live.sh`, and the procedure document with the
workflow's operator bundle. Distribute that exact copy to the original SSH
control sessions. Supply these environment variables explicitly to every fresh
shell; never rely on a prior shell's local variables:

| Variable | Meaning |
| --- | --- |
| `SBXR_V3_PACKAGED_LIVE_MODULE` | Absolute path to the attested packaged-live library |
| `SBXR_QUALIFICATION_MANIFEST` | Protected signed manifest for this attempt |
| `SBXR_QUALIFICATION_REQUEST` | Protected current collector request |
| `SBXR_INSTALLED_RECORD` | `/var/lib/sbxr/installed.json` |
| `SBXR_EXECUTABLE` | `/usr/local/bin/sbxr` |
| `SBXR_OPERATOR_STATE_DIR` | Private root-owned operator state directory |
| `SBXR_OPERATOR_EVIDENCE_DIR` | Private root-owned evidence directory |
| `SBXR_TRANSPORT_ROOT` | This attempt's private transport directory |
| `SBXR_TRANSPORT_UNIT` | This attempt's actual transport service |
| `STARTED_AT`, `SCENARIO_START` | Original collector scenario start, never reset |

Manifest/request paths and directory choices must match the actual collector
configuration. Keep files mode 0600 and private directories mode 0700. Do not set
`SBXR_OPERATOR_REHEARSAL` or `SBXR_OPERATOR_REHEARSAL_HOOK` in a live bundle.
Candidate identity and package phase checks belong to `operator-support.sh` and
`managed-hold.py`; callers must not recreate them with guessed exports.

## Extra observations in the original SSH session

After sourcing `operator-support.sh`, use `operator_observe` for extra read-only
status probes. A bare nonzero probe in that strict shell closes the original
session and invalidates continuity, even after a scenario script has succeeded.
For example, inspect the public menu without making its status command own the
SSH session's exit status:

```sh
operator_observe 'printf "0\n" | "$SBXR_EXECUTABLE" | grep -F "Proxy status:"'
```

The helper executes the one literal command string in a fresh strict Bash child
with stdin connected to `/dev/null`. Export any required values beforehand;
shell-local variables, exported functions, and Bash startup hooks do not carry
over. Use only read-only commands with secret-safe output. This is shell
isolation, not a filesystem sandbox.

`OPERATOR_OBSERVATION_EXIT=<status>` and `OPERATOR_OBSERVATION_STATUS` preserve
the child exit status. The helper itself returns success solely to keep the
original session alive, including on nonzero exit, unset input, or pipeline
failure. Inspect that status before another observation overwrites it. An
unexpected result still ends the attempt through the existing failure and
cleanup procedure; it must never be counted as passed evidence or retried into
a pass. Do not wrap a scenario script, required assertion, candidate check,
mutation, or evidence submission, and do not use the wrapper's `$?` as proof.
Those required operations retain their existing strict failure behavior.

Baseline setup interruption waits use an explicit 900-second monotonic timeout,
capped by the collector's original scenario deadline. This allows the existing
five-minute package commands to reach the requested progress boundary. The menu
runs in an isolated session; a dedicated Linux subreaper kills the owned process
group and reaps any adopted descendants on interruption, timeout, or early exit.
The helper reports a secret-safe reason and whether descendant cleanup finished.
A timeout still fails the signed attempt; it never becomes an observed boundary.

The helper tests use a persistent Bash process on a local PTY, reproduce the
bare-probe session loss, and verify same-process continuity and exact nonzero
statuses through this wrapper. They also verify strict child pipelines and
required assertion failures. These are local regressions, not live SSH evidence.

## Scenario map

| Scenarios | Entry or procedure |
| --- | --- |
| 01 baseline clean | `01-baseline-clean-start.sh`, `01-outside-request.sh`, `01-baseline-clean-finish.sh` |
| 02 baseline refusal | `02-baseline-refusal.sh` |
| 03 baseline precommit | `03-baseline-precommit.sh` |
| 04 baseline postcommit | `04-baseline-postcommit-start.sh`, `04-outside-request.sh`, `04-baseline-postcommit-finish.sh` |
| 05 baseline drift | `05-baseline-drift.sh` |
| 06 baseline removal | `06-baseline-removal.sh` |
| 07 identity absent | `07-identity-absent-start.sh`, `07-identity-absent-rotate.sh`, `07-identity-absent-finish.sh` |
| 08 enable schema 1 | `08-enable-schema1-setup.sh`, `08-enable-schema1-finish.sh enable`, then `verify` with protected outside observations |
| 09–10 link boundaries | `09-10-link-start.sh <scenario>`, `transition-operator.py`, `09-10-link-finish.sh <scenario>`, then `assemble-evidence.py <scenario>` |
| 11–15 managed renewal/recorder/package route | Shared start, `scenario-subscription-input.sh <scenario> before`, collector ready, captured helpers/action, `final`, collector result, shared finish, then assembly per `evidence-managed.md` |
| 16–18 identity boundaries/outage | Shared start/finish wrappers, public `identity-entry.py`, `transition-operator.py`, the collector-owned outside runner, then assembly per `evidence-identity.md` |
| 19 lifecycle menu | Shared start wrapper, `19-lifecycle-menu.sh` through `capture-source.py`, shared finish, then assembly |
| 20–22 removal exclusions | Shared wrappers plus canonical capture IDs `managed-hold`, `recorder-boundary`, `removal-refusal`, or `admission-race-operator` as specified |
| 23 directory locks | Shared wrappers plus canonical capture IDs `directory-locks` and `removal-refusal` |
| 24 secret containment | Shared wrappers plus captured `24-secret-containment.sh` and its exact retained receipts |
| 25 Karing final | Shared start, protected Owner-reviewed manual UI input, captured `karing-evidence.py`, and the Not installed finish |

The full sequence, family-check order, exact public actions, outside observations
and cleanup requirements are in
[`v4-operator-procedures.md`](../../../docs/acceptance/v4-operator-procedures.md).
For scenario 08, the existing outside runner must be connected before enablement;
`connection-probe.py` keeps one real TLS connection open through its local proxy.
Use `subscription-observation-input.sh` only in a private pipe to
`check-subscription.py --bound`; the input helper adds the current manifest,
request, original deadline and not-before binding, while the checker records the
actual successful TLS interval. Its input contains credentials. Never display
that pipe, put it in argv, or retain it in terminal/workflow captures. Store only
the checker's secret-safe bound JSON output as the scenario 08 subscription
observation.

The OS controllers own their kernel boundaries and cleanup. `managed-hold.py`
binds the actual snap child to the official recorder and its receipt;
`recorder-boundary.py` binds outcome/admission stops to the recorder's actual
locks; `transition-operator.py` binds public recovery to durable ownership
checkpoints. The egress guard stays attached until the controlled service stops.
A stop failure retains the guard and requires operator cleanup; it is a failed
scenario, not an invitation to continue.

## Startup observations and evidence assembly

`transition-operator.py rotate identity-absent` is the scenario-07 rotation
entry's coordinator. The same ordered startup observations run before the
identity precommit/postcommit interruptions and during `rotate
identity-unavailable`. The protected receipts record publication, reload,
effective route, unchanged source before cutover, and ordinary start/restart
denial after quiescence on the same actual UI process. A pre-gate `start` on the
already active source is a no-op; it does not prove that an external request was
admitted while the whole-host mutation lock was held.

For every nonbaseline scenario, `effective-route.py` observes the supported
Certbot timer-to-service route before timer stops or injected route faults.
Scenarios 07 and 08 invoke it automatically after supported setup; the 09/10
start entry invokes it before rotation. Later
procedures invoke it explicitly and retain the current request-bound receipt.
It observes renewal integration; the identity coordinator separately observes
proxy startup protection.

Scenarios 11–25 use one common entry clock. Run
`11-25-scenario-start.sh <scenario>` once after the collector creates the current
request. Immediately before the public action, hold, package refresh, route
injection, or Karing UI journey, run `scenario-entry.py action-start <scenario>`.
Run `scenario-entry.py action-complete <scenario>` immediately after that action
has completed, refused, or reached its required durable result, before final
outside and preservation checks. After those checks, run
`11-25-scenario-finish.sh <scenario>`. Each phase creates a new protected
`scenario-<scenario>-<phase>.json`; never edit, replace, or reuse one. Assembly
uses the `finish` file as `--state` and the start wrapper's
`scenario-<scenario>-effective-route.json` as `--effective-route`.

The start wrapper requires `initial` packages for scenarios 11–14 and
`after-snap-refresh` for scenarios 15–25. The finish wrapper requires `initial`
for 11–13, `after-snap-refresh` for 14–24, and proves `Not installed` for 25.
This asymmetry is intentional: scenario 14 performs the supported snap refresh.

`capture-source.py` is the only generic source wrapper. Its `--helper` value is
an allowlisted bundle identity, and `--output` must be a new file inside the
scenario's mode-0700 source directory. Arguments after `--` go only to that
helper. Interactive helpers keep stdin attached and stream their actual JSON
events to the operator while retaining the request-bound wrapper. A successful
wrapper exit is source transport; each family adapter still validates exact
records and event order.

For scenarios 11–15, `scenario-subscription-input.sh` stores the confirmed
public disclosure privately. `before` publishes the collector trigger; wait for
`NN-outside-ready.json` before `action-start`. After `action-complete`, run
`final` and wait for `NN-outside-result.json`. Those two files are raw
collector-owned receipts. Copy them unchanged into the scenario source
directory; do not pass them through `capture-source.py`. Scenario 18 permits
only `identity-unavailable final` and waits for
`identity-unavailable-repair-outside.json` before the repair capture.

`19-lifecycle-menu.sh` and `24-secret-containment.sh` each emit one whole-helper
capture. Their internal state files are diagnostic. The corresponding shared
`scenario-<scenario>-finish.json` remains the assembler's canonical state.

`evidence-timing.py` binds typed evidence timestamps to exact retained source
artifacts and event-specific lower/upper bounds. `assemble-evidence.py` uses that
seam for scenarios 07–25, requires fresh manifest/boundary/validator verification
and accepted-prefix receipts, validates the actual entry/controller/outside
artifacts, and invokes a pinned local qualification validator before writing
facts. Its protected operator-observation input must refer to the actual
capture bytes. Artifact digests detect substitution; the operator remains
responsible for verifying source provenance and attestation. This helper never
dispatches a candidate or submits evidence.

The exact CLI inputs, receipt schemas, and retained scenario-07 paths are in
[`evidence-assembly.md`](../../../docs/acceptance/evidence-assembly.md).

Keep fractional source timestamps unchanged. A later whole-second wire
observation cannot be rounded down before its source event. Scenario 07's old
session can terminate during rotation, before the action completes; its fresh
old-credential refusal must occur after completion. The assembler retains those
distinct ordering requirements and refuses all observations dated at scenario
start. Scenario 08 retains a safe completion receipt after its final assertions.
For 09/10, `link-outside.py` synchronizes a pending request with the controller's
prepared-target hold, checks closure before the five-second server deadline,
then checks the selected link after public recovery. `link-runtime.py` observes
the source process, cgroup descendants and sockets, staged target, and unchanged
proxy process/configuration. Scenario 10 holds the committed process before its
first serving-token read for target publication; the next Ownership Record write
would be too late because activation already occurred. A separate
`connection-probe.py` trace must span the whole action and recovery.

`09-10-link-start.sh` and `09-10-link-finish.sh` retain secret disclosures only
in protected files, coordinate the existing outside collector, and preserve the
original scenario clock. See the procedure for the required independent proxy
connection and operator capture observations. For 11–25, use the family source
guides in [`evidence-managed.md`](../../../docs/acceptance/evidence-managed.md),
[`evidence-identity.md`](../../../docs/acceptance/evidence-identity.md), and
[`evidence-final.md`](../../../docs/acceptance/evidence-final.md), then the common
CLI in [`evidence-assembly.md`](../../../docs/acceptance/evidence-assembly.md).
Local helper tests and rehearsal validate mechanics and refusal behavior. Only
fresh captured VPS, outside-client, and manual Karing sources within the signed
request can establish live observations.

`admission-race-operator.py` owns scenario 22's single prepared removal menu and
the existing recorder-admission controller. It waits for the transient menu's
active service and actual PID within the original deadline before binding its
process identity. It confirms that same reviewed
action only after the real recorder holds admission, requires refusal and an
unchanged owned inventory, then releases the recorder and restores its timer.
The detailed procedure specifies its inputs, evidence files and cleanup.
