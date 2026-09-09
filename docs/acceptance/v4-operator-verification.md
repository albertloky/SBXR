# V4 operator-harness verification

The operator harness for the 25 ADR-0022 live scenarios is implemented and its
preparation readiness check passed on 2026-09-09. This record covers helper and
fixture verification. No new candidate, product live scenario, certificate
request, Karing change, commit, push or recurring automation was started.

## Scope and structure

The scenario map and setup contract are in
[the harness README](../../.github/scripts/v3-operator/README.md). The concrete
09–25 commands, ordered observations and cleanup are in
[the operator procedures](v4-operator-procedures.md); 01–08 use the checked-in
split entries.

Candidate/request binding stays in the existing packaged-live seam and operator
support. Kernel execution, network and syscall controls own their stop/release
and cleanup rules. The managed recorder and public-transition coordinators bind
those controls to real process identities, locks, receipts and durable records.
Secret and outside-connection observations have separate bounded checkers.

V4 candidate check/dispatch now requires a protected Linux rehearsal report less
than 24 hours old, exact helper/test source hashes, all fixture groups passing,
and a fresh local entry-point rehearsal. Missing or changed reports fail before
GitHub dispatch. Fixture reports are never accepted as live scenario evidence.

## Verified results

| Verification | Result |
| --- | --- |
| Fresh-shell split-entry rehearsal | Passed; 17 bounded entries, 7 protected-input refusals, 21 shell syntax checks |
| Helper tests on macOS | 60 tests, 57 passed and 3 Linux/root-only skips |
| Helper tests on RackNerd Linux | 60 passed, no skips |
| Actual Linux fixture groups | All 15 passed |
| Go child boundary stress | 24/24 passed in the final consolidated run; 2 cases exercised a confirmed vanished thread |
| Earlier targeted Go child regression | 24/24 passed; 6 cases exercised the previously failing vanished-thread branch |
| Release declaration/dispatch tests | Passed with pinned Go 1.26.6, including V4 refusal before GitHub when rehearsal is absent |
| Release qualification CLI tests | Passed with pinned Go 1.26.6 |
| Final readiness | `ready: true`, `live_evidence: false` |

The Linux groups cover executable deny/release, controller death/EOF/timeout,
unrelated-process continuity, escaped-child refusal, persistent cgroup egress
denial, actual systemd cgroup reuse, harmless installed snap `--version` launch
chains, Python and multithreaded Go syscall boundaries, BSD flock coordination,
route restoration, isolated-network-namespace firewall restoration, and the
serving mount/capability sandbox probe.

The final Linux run completed at **2026-09-09 14:33:24 UTC** on
`Linux 6.8.0-138-generic x86_64`, glibc 2.39. Its 59 helper/test source hashes
matched the local tree. The retained private report is
`.scratch/operator-kernel-fixture/linux-rehearsal.json`, with SHA-256:

```text
6a7e2c6e7b7246ef4b9cee61c5d6f4e3dbc7f6d1289e9f396710af4b5bc36bf5
```

Per-case logs and the earlier failing fixture diagnostics are retained beside
that report. Future helper changes or report expiry require a new rehearsal.

## Defects caught during rehearsal

The first consolidated Linux run failed rather than producing readiness. A Go
thread had disappeared, but the tracer kept it in the set of threads whose stop
it awaited. Diagnostics confirmed `/proc/TID` was absent while the actual child
had exited successfully and the requested durable boundary had matched. The
corrected drain removes only confirmed absent identities, handles concurrent
clone events, stops every remaining live tracee, and rechecks the checkpoint.
The real repeated fixture exercised this exact branch successfully. The behavior
is consistent with the documented distinction between `ESRCH` and a final wait
notification in the [Linux ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Other corrections preserve unrelated interpreter executions, close the global
inode watch once the selected image is trapped, keep subscription credentials
out of argv/environment, reject failed controllers, detect capture/report
replacement, and retain network denial if stopping the managed unit fails.

## Host restoration and remaining live proof

After the Linux run, the official Certbot service was inactive with its original
snap command, its timer remained active, and SBXR executable/state remained
absent. No fixture units, cgroups, control paths or owned fixture processes
remained. The exact temporary RackNerd fixture directory was removed after the
private report and logs were retrieved.

The real candidate's recorder ancestry/receipt, provider behavior, outside
sessions, original SSH continuity, reviewed removal and recovery, and Karing's
fresh latency/due automatic refresh still require the separately authorized live
attempt. The transition coordinator's local tests use modeled OS processes;
actual Linux kernel mechanics are established by the separate fixture groups.
The report records interpreter and fixture digests as provenance; it is not a
signed third-party attestation or a substitute for the signed live manifest.
