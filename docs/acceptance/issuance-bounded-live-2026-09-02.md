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

## Signed sequence 86: setup failure with concurrent unattended upgrades

[Candidate run 33597082963](https://github.com/albertloky/SBXR/actions/runs/33597082963)
used `v3.1.3`, Release Sequence `86`, commit
`26ace973e5fb1d8b2ec83f6eb751a50fd080b845`, and Release Index SHA-256
`175b91c5610edbe9b0166fe0b3577db977806bb70dba9dc4cfd39fd9ee30879f`.
Both candidate-native builds and [Verify run 33597074011](https://github.com/albertloky/SBXR/actions/runs/33597074011)
passed. Manifest `eebd8debbd5344f4f2e951f021d46811169f23e1ecfc7b6e73e385602f7943e4`
was signed at `2026-09-02T06:15:40Z`; its attestation was verified before the
second environment approval.

The first request began at `2026-09-02T06:18:02Z`. Fresh preflight started at
`06:18:52Z` and passed at `06:18:53Z`, including package locks/process absence.
Clean installation, `Not set up`, and installed-executable/archive comparison
passed at `06:19:15Z`. Reviewed Start setup then returned failure. The shell
exited before retaining its scanned action output, so its exact failed operation
is unknown. Read-only inspection at `06:20:35Z` found `Not set up`, no Ownership
Record, and inactive `sing-box`. The original direct SSH session remained alive.

Independent system records prove that `apt-daily-upgrade.service` started at
`06:19:35Z`, after the clear preflight. Unattended upgrades began at `06:19:44Z`,
performed package work from `06:20:08Z`, and finished at `06:20:37Z`. This is a
confirmed concurrent package operation, consistent with setup's safety cleanup,
but not proof of its exact failure cause without the lost action output.

Canonical failure facts were accepted with `boundary: unknown` and
`host_state: Not set up`. No outside probe or baseline pass was submitted.
Supported Complete removal passed at `06:21:41Z`; fresh product absence was
checked at `06:22:01Z`. Separate cleanup facts were accepted as completed / Not
installed, with the outcome still failed. No production CA request or Karing
profile change occurred. This signed attempt requires a burn and a complete
rerun under a fresh Release Identity, unlike the earlier unsigned cancellation.
The workflow finished failed with successful failure finalization;
`refs/tags/release-burned/v3.1.3` was verified. Product/transport absence and removal
of the exact attempt-owned temporary files were proved at `06:23:52Z`.

At `06:22:40Z`, both previously active/enabled APT timers were temporarily stopped
after their services and package locks were idle. Their enabled state and
schedules were preserved. Restore both timers after qualification. The procedure
now requires that bounded exclusion and retention of scanned failure output at
the operator call site. No product behavior changed.

## Sequence 87: outside runner did not follow signing-key redirect

[Candidate run 33598688058](https://github.com/albertloky/SBXR/actions/runs/33598688058)
used `v3.1.4`, Release Sequence `87`, commit
`2461db5822bf99ac3580773a1a336eb092bfa237`, and Release Index SHA-256
`8b9a34ee84820b25634c5811a741b745aec75baf1dabf9d1bbd18c77b8c020d5`.
Both candidate-native builds and [Verify run 33598667749](https://github.com/albertloky/SBXR/actions/runs/33598667749)
passed. Manifest `079ab5a789ef5130e6be99216b552ef6ce83cc90e4e6fbadb66eeea99cbbf92c`
was signed at `2026-09-02T06:37:36Z`; attestation verification preceded the live gate.

The baseline request began at `06:39:12Z`. Mac/VPS preflight started at `06:40:04Z`
and passed at `06:40:09Z`, including inactive APT timers/services, clear locks,
exact package checks, and clean product state. Installation and executable/archive
comparison passed at `06:40:33Z`. Reviewed setup and local activation passed at
`06:41:03Z`; View details and capture checks passed at `06:41:36Z`. The original
direct SSH session remained alive. The required GitHub outside probe was then
requested, not replaced by a Mac probe.

The collector stopped at `06:41:47Z`. Its retained diagnostic is exactly
`Runner stage: download-client-signing-key`. The helper used
`curl -fsS https://sing-box.app/gpg.key`: the endpoint returns HTTP 301, and without
`-L`, curl saved the 167-byte redirect HTML. Reproduction produced SHA-256
`446a6087825fa73eadb045e5a2e9e2adf7df241b571228187728191d961dda1f`, not the pinned
key. Following the same redirect returned the unchanged required key SHA-256
`803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1`.
The shared helper now follows redirects, retaining the exact hash check. This
fix applies to both historical qualification and the outside-probe path.

A regression runs the actual download/check block with curl against a local
HTTP 301 server. The pinned body failed before the fix and passed afterward;
a changed body still fails. Ten focused repetitions and independent quality
review passed. This is automated evidence, not a live outside-traffic pass.
With pinned Go `1.26.6`, both complete repository-wide normal and race commands
passed with exit status zero, as did vet, module verification, shell syntax, and
diff checks. Twenty additional race-mode redirect regression repetitions passed.

The collector's original failure facts remain unchanged (`evidence-refused`,
unknown boundary/state). Supported Complete removal passed at `06:44:03Z`.
Separate safety-cleanup facts were accepted as completed / Not installed, with
the outcome still failed. Product/transport absence and exact temporary-file
cleanup passed at `06:46:11Z`; `refs/tags/release-burned/v3.1.4` was verified.
No outside-proxy-traffic result or baseline scenario passed. No production CA
request or Karing profile change occurred. APT timers remain temporarily stopped.
Before another signed attempt, the unchanged planned snaps were held until
`14:46:12Z`; this did not extend any qualification clock. Restore timers and
release package holds after qualification.
