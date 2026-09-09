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
`docs/acceptance/v4-operator-procedures.md` into a
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
nor proves its future live results.

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
| 09–10 link boundaries | `transition-operator.py` and the procedure document |
| 11–13 managed renewal/recorder | `managed-hold.py`, `hold-flock.py` and the procedure document |
| 14–18 route/identity/outage | `route-control.py`, `transition-operator.py`, `firewall-control.py` and the procedure document |
| 19 lifecycle menu | `19-lifecycle-menu.sh` |
| 20–22 removal exclusions | `managed-hold.py`, `recorder-boundary.py` and the procedure document |
| 23 directory locks | `directory-locks.py` and the procedure document |
| 24 secret containment | `24-secret-containment.sh`, `sandbox-token-probe.py` and the procedure document |
| 25 Karing final | Ordered UI procedure; actual fresh latency and due refresh observations remain mandatory |

The full sequence, family-check order, exact public actions, outside observations
and cleanup requirements are in
[`v4-operator-procedures.md`](../../../docs/acceptance/v4-operator-procedures.md).
For scenario 08, the existing outside runner must be connected before enablement;
`connection-probe.py` keeps one real TLS connection open through its local proxy.
Use `subscription-observation-input.sh` only in a private pipe to
`check-subscription.py`; its input contains credentials. Never display that pipe,
put it in argv, or retain it in terminal/workflow captures.

The OS controllers own their kernel boundaries and cleanup. `managed-hold.py`
binds the actual snap child to the official recorder and its receipt;
`recorder-boundary.py` binds outcome/admission stops to the recorder's actual
locks; `transition-operator.py` binds public recovery to durable ownership
checkpoints. The egress guard stays attached until the controlled service stops.
A stop failure retains the guard and requires operator cleanup; it is a failed
scenario, not an invitation to continue.
