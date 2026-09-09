# V4 operator-harness verification

The corrected operator harness passed its full readiness check on 2026-09-09
after the pre-dispatch audit found gaps in the initial check. This record covers
helper and fixture verification, not live scenario passes. The initial results
remain below with their limitations; the corrected results are authoritative
for the current operator source inventory.

The audit found that the entry rehearsal counted filenames instead of executed
entries, skipped the scenario 08 finish and scenario 24 scripts, and reported a
constant refusal count. Scenario 07 also lacked a concrete outside-session
producer and accepted four ordered timestamps as its outside evidence. The
historical results below therefore do not establish full procedure readiness.

## Corrected pre-dispatch verification

The scenario 07 driver now collects real outside-session observations through
the existing acceptance runner. A fresh challenge requires successful traffic
on the same old connection immediately before public rotation. The full receipt
requires actual connection closure, exactly one fresh old-credential refusal,
independent target health, confirmed manual replacement configuration, successful
replacement traffic, process/listener identity and cleanup. Timeouts alone are
refused. The collector validates the result before acknowledging it for reviewed
removal; its failures retain the existing canonical stop-and-burn vocabulary.

Phase publication uses Linux `renameat2(RENAME_NOREPLACE)`, avoiding partial-file
and transient hard-link windows. The entry rehearsal counts actual executions
and refusals and exercises the formerly missing scenario 08 finish and scenario
24 entry points. Readiness checks exact procedure/module/collector sources and
every retained fixture-log digest, in addition to report age and runtime
provenance. The report remains operator-controlled evidence, not independent
remote-host attestation.

| Final verification | Result |
| --- | --- |
| Fresh-shell entry rehearsal | 17 executed entries, 7 observed protected-input refusals, 21 shell syntax checks |
| macOS helper suite | 85 tests: 81 passed, 4 Linux/root-only skips |
| Linux helper suite | 85 passed, no skips, including actual atomic-publication checks |
| Linux fixture groups | All 16 passed, including the fresh-shell entry rehearsal |
| Exact source inventory | All 67 sources matched, including README, procedure, packaged module, collector and dispatch wrapper |
| Retained fixture logs | All 16 protected sibling logs present and hash-verified; no hidden command or test failures |
| Root repository tests | Fresh `GOTOOLCHAIN=go1.26.6 go test -count=1 .` passed |
| Corrected readiness | `ready: true`, `live_evidence: false` |

The final Linux report completed at **2026-09-09 15:26:18 UTC**. Its private path
is `.scratch/operator-audit-fix/linux-rehearsal-complete.json`, with SHA-256:

```text
4110b133a5dc159bdde85d72decd8a39bf40be4406fffb5cf31d501a28c277a6
```

Earlier correction runs exposed macOS AppleDouble transfer metadata, a missing
`rg` command hidden by a shell conditional, and a test reading process arguments
during child startup. The final transfer uses a metadata-free archive; the
binding scan checks the exit status of portable `grep`; and the test waits for
an explicit child-ready signal. The process observer now returns `unknown` if
arguments are unavailable. Failed and superseded reports/logs are retained
privately and must not be used for dispatch.

After final log retrieval, the exact temporary Linux fixture tree was removed.
No owned fixture processes, units or cgroups remained; SBXR executable/state
remained absent, the official Certbot service remained inactive, and its timer
remained active. No candidate, certificate request or Karing change was made by
these rehearsals.

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
| Initial fresh-shell split-entry rehearsal | Passed its implemented checks; reported 17 entries and 7 refusals, but those counts were not execution-derived and two entries were skipped; 21 shell syntax checks ran |
| Helper tests on macOS | 60 tests, 57 passed and 3 Linux/root-only skips |
| Helper tests on RackNerd Linux | 60 passed, no skips |
| Actual Linux fixture groups | All 15 passed |
| Go child boundary stress | 24/24 passed in the final consolidated run; 2 cases exercised a confirmed vanished thread |
| Earlier targeted Go child regression | 24/24 passed; 6 cases exercised the previously failing vanished-thread branch |
| Release declaration/dispatch tests | Passed with pinned Go 1.26.6, including V4 refusal before GitHub when rehearsal is absent |
| Release qualification CLI tests | Passed with pinned Go 1.26.6 |
| Initial readiness | Reported `ready: true`, `live_evidence: false`; superseded by the pre-dispatch audit hold above |

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
