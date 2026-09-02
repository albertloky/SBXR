# Issuance-bounded repair: failed live attempts

## Sequence 84: Mac SSH idle timeout

Attempt `run-33592907845-attempt-1` used `repair-issuance-bounded-v1`,
candidate `v3.1.1`, Release Sequence `84`, commit
`dd6fc91c9b860487bb5ae4da6ea81ccac78b00ba`, and Release Index SHA-256
`002723f3e2153ee7c5e4d5db18a7bd730e56f16e01cfb8986ebb3fea8cdf5342`.
Both candidate-native architecture jobs passed their full normal/race suites,
vet, module verification, and package checks. The signed manifest was created
at `2026-09-02T05:15:52Z` after the Owner-approved environment gate.

The first `baseline-clean` request began at `2026-09-02T05:17:38Z`.
Fresh VPS preflight passed at `2026-09-02T05:18:19Z`; the unchanged candidate's
public installer and `Not set up` state passed at `2026-09-02T05:18:39Z`.
The operator invoked reviewed Start setup through the packaged menu. The original
SSH continuity connection and setup command connection then closed unexpectedly.
No baseline pass or later scenario was submitted.

The fault was in the Mac control invocation, not established as a product defect:
`ProxyCommand=/usr/bin/nc -b en0 -w 10 %h %p`. macOS `nc(1)` explicitly applies
`-w` to idle established connections. The command therefore severed quiet SSH
connections after ten seconds, including the separate continuity session.
Read-only reconnection at `2026-09-02T05:19:04Z` found `Proxy status: Running`
and `PROXY-INSTALLATION-SETUP-COMPLETE`. That observation did not repair the
failed continuity requirement or justify further test mutations.

Canonical `v3-scenario-failure` facts were accepted with `unexpected-failure`,
`boundary: observed`, `host_state: Running`, `stop_test_mutations: true`, and
`burn_required: true`. The existing supported failure-cleanup path performed
reviewed Complete removal. At `2026-09-02T05:20:28Z`, fresh inspection proved
product and transport absence, including no listeners on 80/443/8443/9443.
Separate canonical cleanup facts were accepted as `completed` / `Not installed`;
the outcome remained `failed`. Exact attempt-owned temporary files were removed.
No subscription enablement, production CA order, or Karing profile change occurred.

[Candidate workflow 33592907845](https://github.com/albertloky/SBXR/actions/runs/33592907845)
finished with failed acceptance and successful failure finalization. `v3.1.1`
is a failed prerelease, and `refs/tags/release-burned/v3.1.1` records the burn.
Public stable `v3.1.0` is unchanged. No live scenario from this attempt is reusable.

The corrected invocation omits `nc -w`, uses SSH `ConnectTimeout=12`, and retains
SSH server-alive checks. The same physical-interface-bound connection answered at
`2026-09-02T05:20:11Z` and again at `2026-09-02T05:20:56Z`, proving survival of
a 45-second command-idle interval without changing Mac routing or Karing settings.
The qualification procedure now requires this check before signing.
A fresh Release Identity and the complete retained live matrix remain required.
Natural timer firing and naturally due renewal remain excluded and Not observed.

## Sequence 85: acceptance helper selected lifecycle status

Fresh attempt `run-33594398326-attempt-1` used `v3.1.2`, Release Sequence `85`,
commit `f6a527edab2203dbacb5bcf42a5bc9f1c5c72b6e`, and Release Index SHA-256
`e0b6df7603d850948481ac936d1c911164db0c056a415552f49532217650008a`.
Both candidate-native jobs and the separate Verify workflow passed. The signed
manifest was created at `2026-09-02T05:36:44Z`.

`baseline-clean` preflight passed at `2026-09-02T05:39:38Z`; clean installation
and comparison of the installed executable against the signed archive passed at
`2026-09-02T05:40:03Z`. Reviewed Start setup completed, but `run_action` returned
failure. The original direct SSH session remained connected. Read-only inspection
at `2026-09-02T05:40:32Z` found `Running` and
`PROXY-INSTALLATION-SETUP-COMPLETE`.

The existing helper selected the last `Code:` line from terminal output. The
terminal now prints Software Lifecycle status after the Proxy Installation
result in each menu frame, so that line was `SOFTWARE-LIFECYCLE-STATUS-READY`.
The helper therefore rejected successful setup before the additional state check
could run. No baseline result was submitted and no outside-client probe ran.

The exact shared helper regression failed before the fix and passed afterward.
The parser now skips the initial menu and later Software Lifecycle sections;
it still rejects a real refusal, an absent action result, and failed removal.
Complete removal's result without another menu remains accepted. The earlier
source-text test that required the broken last-line expression was replaced by
these executable checks. Cleanup test output now includes the initial menu, as
the real terminal does. No packaged product behavior changed.

With `GOTOOLCHAIN=go1.26.6`, every package passed normal and race checks. The two
full commands had compiled the obsolete source-text assertion before its removal
and therefore exited failed for that root-package assertion; the final root
package was rerun separately in both modes and passed. All other package results
in those full runs passed. Focused regression/cleanup tests, `go vet ./...`,
`go mod verify`, Bash syntax, and diff checks passed. Independent code-quality
review found no blockers. Fresh candidate-native verification remains mandatory.

Canonical failure facts were accepted and the workflow finalized `v3.1.2` as a
failed prerelease with its burn record. Supported Complete removal succeeded;
product and transport absence were rechecked at `2026-09-02T05:44:00Z`.
Separate canonical safety-cleanup facts remained `outcome: failed` with
`completed` / `Not installed`. Exact attempt-owned temporary files were removed.
No production CA order or Karing profile change occurred. A fresh identity and
the complete retained live matrix are still required.

Evidence: [candidate run 33594398326](https://github.com/albertloky/SBXR/actions/runs/33594398326)
and [Verify run 33594389070](https://github.com/albertloky/SBXR/actions/runs/33594389070).

## Unsigned sequence 86 preparation: Linux test-fixture pipe race

[Verify run 33596559548](https://github.com/albertloky/SBXR/actions/runs/33596559548)
found a Linux-only race in the new shell test: its fake command returned without
reading the input pipe. The resulting producer `SIGPIPE` made a successful
parser case fail before result selection. A native Linux reproduction observed
361 failures in 1,000 iterations; consuming input before returning the fixture
output passed all 1,000 iterations. The fixture now consumes its input, matching
the existing cleanup fixture. The acceptance helper itself is unchanged.

[Candidate run 33596570533](https://github.com/albertloky/SBXR/actions/runs/33596570533)
was cancelled before draft construction/signing. No `v3.1.3` release, signed
attempt, live scenario, or production CA request was created by that run.
Release Sequence `86` was not burned; it may be constructed from the corrected
commit after fresh native verification.
