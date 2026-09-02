# Issuance-bounded repair: failed live attempts

## Unsigned sequence 90: public release access unavailable

[Candidate run 33611200606](https://github.com/albertloky/SBXR/actions/runs/33611200606)
used commit `81a43da56bfcaccf461323eefe16698e3f040ed6`, `v3.1.7`, Sequence `90`,
and the approved v2 declaration. Preflight failed at public Latest verification,
before candidate builds, draft construction, signing, or live setup. The same
production verifier locally returned `refused`; a temporary diagnostic isolated
the failure to the initial public metadata request, before acceptance-record or
signature checks. Anonymous repository, Latest API, and release-page requests
returned HTTP `404`, while authenticated GitHub inspection reported
`visibility: PRIVATE`, `isPrivate: true`. Anonymous quota remained available;
this was not a rate-limit refusal. The diagnostic was removed after inspection.

No visibility change, authenticated-verifier bypass, signed attempt, or production
CA request was made. Making the repository public exposes source and history and
requires an explicit Owner visibility decision; general fix approval is not that
decision. Public install/verification cannot qualify while anonymous access is
unavailable. Existing stable `v3.1.0` remains the authenticated Latest record;
that is not proof it is publicly available. No `v3.1.7` or burned tag was created.

At `2026-09-02T08:59:53Z`, Certbot `5.8.0` revision `5893` was restored, the
general certbot/snapd/core24 holds were removed, and both original APT timers
were active/enabled. Product, transport, and evidence directories were absent.
No Karing app replacement, profile change, or connection change occurred.

## Approved lifecycle evidence correction

Albert approved [ADR-0020](../adr/0020-clean-install-lifecycle-evidence.md) on
2026-09-02: only `lifecycle-menu/explicit-confirmation` and
`lifecycle-menu/clean-install-target-refused` move to mandatory native automated
evidence under new signed policy `repair-issuance-bounded-v2`. The 25 live
scenarios, 29 automated-only scenarios, remaining live lifecycle checks, and
complete Karing journey are unchanged. Historical v1 results below are unchanged;
this decision is not a live pass or a published stable release. A fresh signed
attempt must rerun every retained live scenario.

Before the new attempt, official Karing metadata showed that asset `540868464`
replaced the same-version `karing_1.2.24.2709_macos_universal.dmg` at
`2026-09-02T08:32:22Z`. The replacement is `103105344` bytes, SHA-256
`7ee8f97d0291218beb83f910bd445a4081c67ea830e4dd5b73d2c4128563a8da`.
The download matched both values and passed strict deep signature verification
and notarized Developer ID assessment for `TNPM9PFX3W`. A recursive comparison
proved that every installed app file's SHA-256, symbolic-link target, and mode
matches the new image; only timestamps differed. No app replacement, profile
change, or connection change was needed. Earlier attempt package
identities remain unchanged historical facts, not the new declaration.

## Unsigned sequence 90: lifecycle live-contract blocker

[Candidate run 33606125022](https://github.com/albertloky/SBXR/actions/runs/33606125022)
targeted `v3.1.7`, Release Sequence `90`, commit
`c7af2723ab61dbe6abd43eb598da4e179858f91c`. Both native candidate builds and
[Verify run 33606090043](https://github.com/albertloky/SBXR/actions/runs/33606090043)
passed. Before signing, source inspection and independent specification review
confirmed that the unchanged single-candidate clean-install contract cannot
produce two required `lifecycle-menu` observations:

- `explicit-confirmation`: `terminal/lifecycle.go` returns before the Update
  prompt unless Check reports an available supported update, and before Recover
  confirmation unless an actual lifecycle recovery direction exists. Neither
  exists in the admitted same-candidate/no-update/no-recovery state.
- `clean-install-target-refused`: `softwarelifecycle/status.go` reports Already
  current for the same identity/sequence before testing update support. The
  specific clean-install-only refusal requires a different higher-sequence
  target. The signed one-candidate attempt has no such target; lower-sequence
  stable `v3.1.0` produces a different generic refusal.

The allowed live path can prove menu reachability, Already current, no recovery,
and an unchanged installation. A setup confirmation, generic older-release
refusal, or automated fixture is not either missing live observation. No fixture
gateway, invented target, protected-state edit, new exclusion, or relabelled pass
was used. ADR-0019 still requires the complete retained per-scenario evidence;
changing that contract was then an unresolved Owner decision, since resolved by
ADR-0020 above for new v2 attempts only.

The run was cancelled during draft construction, before signing or live setup.
Unsigned cleanup succeeded, and the `v3.1.7` release endpoint returned HTTP 404.
No signed attempt or production CA request was created; Sequence `90` was not
burned by this cancellation. Public stable `v3.1.0` remains unchanged.

At `2026-09-02T08:08:56Z`, the VPS's original Certbot `5.8.0` revision `5893` was
restored, general refresh holds for certbot/snapd/core24 were removed, and both
originally active/enabled APT timers were active/enabled again. Product and
qualification transport/evidence were absent. Mac qualification listeners were
absent at `08:09:06Z`; the temporary accessibility attribute was restored.
No Owner Karing profile or connection was changed.

## Sequence 89: Mac traffic probe preceded client readiness

[Candidate run 33602993845](https://github.com/albertloky/SBXR/actions/runs/33602993845)
used `v3.1.6`, Release Sequence `89`, commit
`fca10b069f6a4caab5b035e2c4deb443c15c5565`, and Release Index SHA-256
`c0a5518ce2e2917f76c30c06d1af260f7186997829c45e4bf2214c1856a46c17`.
Both candidate-native jobs and [Verify run 33602995332](https://github.com/albertloky/SBXR/actions/runs/33602995332)
passed. Manifest `d14f85d923ebe42e7b7c29e37bcf62b90d1d021e3567062fa76e30f74dc4e8cc`
was signed at `07:32:14Z`; its attestation and exact 25/29 lists were verified
before approving the live gate. All times below are on `2026-09-02`.

The collector accepted the six baseline prefixes in order. Clean setup/removal
finished at `07:37:50Z`; its real GitHub outside probe passed at `07:36:47Z`.
Footprint refusal/restoration finished at `07:39:46Z`. Precommit setup had durable
cleanup authority at `07:41:32Z` and finished cleanup at `07:41:45Z`. Its interrupt
capture was scanned against the current secrets; after cleanup, additional UUID
and 43-character REALITY-key shape checks proved that cleanup output and the
available journal could contain neither secret, although those provisional
values were no longer present in the configuration. Postcommit setup had durable
forward authority at `07:43:42Z`, finished at `07:43:51Z`, and passed its second
real GitHub outside probe at `07:44:01Z`. Metadata-drift refusal/restoration passed
at `07:45:56Z`. Removal commitment was observed at `07:47:24Z`; reviewed finishing
proved complete absence at `07:47:39Z`. Original SSH continuity checks passed for
each case. These accepted prefixes prove the collector now advances, but cannot
be reused after the later failure.

The `enable-schema1` request began at `07:48:53Z`. Fresh supported candidate
installation/setup, schema-1 origin, exact executable, and the effective official
renewal route passed at `07:49:46Z`. Before enabling subscription, the operator
launched a Mac client pipeline which first obtains public Show client
configuration over SSH. The traffic probe ran before that pipeline's final client
opened `127.0.0.1:2080`: at `07:50:17Z` it returned `ConnectionRefusedError` with
zero completed requests. Read-only inspection at `07:50:26Z` found the listener
present and its stderr capture empty. No traffic result or enablement pass was
submitted. No Enable subscription action or production CA request occurred.

Canonical failure facts retained the original `07:50:17Z` event, `operation-7`,
`enable-schema1`, and known `Running` state. The collector accepted the failure;
its downloaded failure artifact was byte-identical to the submitted facts.
The exact Mac client was stopped, its listener absent, and its capture empty at
`07:51:56Z`. Supported Complete removal passed at `07:52:22Z`. Product/transport
absence and removal of exact attempt-owned temporary files passed at `07:53:27Z`.
Separate cleanup facts remained failed, with completed / Not installed cleanup.
No Karing profile or Owner connection was changed. APT timers remain temporarily
stopped, with enabled state preserved; snap holds remain bounded by `14:46:12Z`.

The procedure now requires a bounded native Mac readiness check against the exact
client PID, executable, and loopback listener before any traffic probe. A local
reproduction delayed input to the real unchanged official client, with no
credentials or outside traffic: the immediate assertion failed, the readiness
check passed, and wrong-executable/exited-client cases refused. A live process
without a listener was refused at the unchanged 30-second readiness deadline.
The scenario
clock is unchanged; traffic failures cannot be retried. This is an operator
readiness correction, not a packaged-product change or a live acceptance pass.
A fresh Release Identity and all 25 retained live scenarios remain required.
Failure finalization passed; `refs/tags/release-burned/v3.1.6` was verified.
Public stable `v3.1.0` remains unchanged. Independent review found no blocker.

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

## Sequence 88: SSH consumed the collector's scenario input

[Candidate run 33600700277](https://github.com/albertloky/SBXR/actions/runs/33600700277)
used `v3.1.5`, Release Sequence `88`, commit
`b532def910d1d9afc9b50bd6eed5beaca7ef12b2`, and Release Index SHA-256
`248fe3ffdf454b5bff29ea40808d4c49d815dfb9e3db802cb679d31ecaf31174`.
Both native candidate builds and [Verify run 33600700209](https://github.com/albertloky/SBXR/actions/runs/33600700209)
passed. Manifest `4e18636047e15bc8d7865ec04c0bb4c6bc5fc444a8c668a9e96585be8b6c7c9b`
was signed at `2026-09-02T07:04:01Z`; its attestation was verified before live approval.

The first request began at `07:05:32Z`. Fresh Mac/VPS preflight started at
`07:06:26Z` and passed at `07:06:30Z`. Clean installation and unchanged executable
comparison passed at `07:06:52Z`; reviewed setup/local activation at `07:07:22Z`;
View details and capture checks at `07:08:11Z`. The actual GitHub Ubuntu outside
probe ran from `07:08:12Z` to `07:08:22Z` and returned all three true observations:
different direct/outside routes, proxied egress matching the VPS, and complete
runner-client cleanup. No substitute Mac probe supplied these observations.

Supported Complete removal and final capture scans passed at `07:09:35Z`;
the original SSH session answered at `07:09:39Z`, and the unchanged Mac package
was checked at `07:09:40Z`. The resulting baseline evidence was locally accepted
at `07:10:15Z` and atomically submitted. The collector accepted that first prefix,
removed its result file, then incorrectly entered final cleanup instead of
requesting `baseline-refusal`. At `07:10:37Z` its job log reported the absent
`outside-reply-baseline-postcommit.json`; that later probe had never been requested.

The scenario loop supplied its list on standard input. Its SSH children consumed
the remaining IDs, so the next read reached EOF. EOF also cleared `scenario`,
making the automatic failure facts invalid; no detailed failure artifact was
uploaded. The collector now reads the list from dedicated descriptor 3 and assigns
the current scenario only after a successful read. Normal SSH input remains
available for the explicit request/result transfers. The outside-probe child can
reuse its own descriptor 3 without changing the parent's descriptor.

The regression uses the actual loop boundaries and a real stdin-consuming child.
Before the fix it ran only the first scenario and lost the last ID; a second
case without stdin consumption separately proved the EOF identity loss. Both
cases passed twenty repetitions after the fix, and independent review found no
blockers. The test is not live acceptance evidence.
Both complete repository-wide normal and race test commands passed with pinned
Go `1.26.6`, as did vet, module verification, Bash syntax, and diff checks.

The workflow failed and burned `refs/tags/release-burned/v3.1.5`. The one accepted
baseline scenario belongs to this failed attempt and cannot be reused. No later
live scenario, production CA request, or Karing profile change occurred. Fresh
product/transport absence and exact remaining temporary-file cleanup passed at
`07:14:46Z`; no second product removal was needed. Separately constructed local
failure/cleanup facts were accepted as failed / completed / Not installed. They
do not replace the missing workflow failure artifact or change the failed result.

## Sequence 94: refresh hold refused as unsupported Certbot

[Candidate run 33633684913](https://github.com/albertloky/SBXR/actions/runs/33633684913)
used `v3.1.11`, Release Sequence `94`, commit
`39240c90f7246ce002a17aae80ba4b3adc421330`, and Release Index SHA-256
`49005fcb093bcf0ecfd70e00c4bd6d146f525adcf212ab2f79c804a95702c4bb`.
Both native jobs passed. Signed manifest
`32b4a6b462d369fe1a92d8cd027e97a6f56a05ce689e50124a5e320c2f0f81e1`
was independently validated and its attestation verified before live approval.
All six baseline scenarios were accepted, including both actual GitHub outside
probes, recovery directions, refusals, original SSH continuity, and removal.

`enable-schema1` began at `13:39:36Z`. Supported setup produced Running schema-1
authority at `13:39:55Z`. The exact Mac auxiliary client became ready at
`13:40:20Z`, and actual outside traffic used one uninterrupted connection.
The normal menu did not offer Enable subscription: View details reported
`Subscription enablement check: Subscription dependencies`. The official
Certbot `5.7.0` revision `5781` reported Notes `classic,held` because qualification
temporarily held refreshes. Both dependency admission and renewal-route inspection
required Notes to equal `classic`, incorrectly rejecting that unchanged package.
No Enable subscription execution, production CA request, or Karing profile change
occurred. The operator helper also retained a stale prior action on menu lookup
failure; that capture is not evidence of an enablement action result.

Failure facts recorded at `13:41:47Z` identify `enable-schema1`, refusal, and
Running. The collector retained those exact bytes and burned
`refs/tags/release-burned/v3.1.11`. Supported Complete removal and absence checks
passed at `13:44:05Z`; separate cleanup facts remain failed / completed /
Not installed. Certbot `5.8.0` revision `5893`, refresh eligibility, and the
original active/enabled APT timers were restored at `13:45:06Z`. Temporary
transport/files were absent and SSH still required public keys at `13:47:11Z`.

The correction accepts only `classic` and `classic,held` in both existing
inspection paths. Publisher, version, active-change, route, and other safety
checks remain unchanged. Each held-package regression failed before its fix and
passed afterward; focused tests also prove unsupported modes still refuse.
These are automated results, not subscription or Karing live acceptance. A fresh
candidate must repeat the full retained matrix; no baseline pass is reusable.
Multi-day natural renewal remains Not observed.

The first final-tree local normal suite reached its unchanged ten-minute package
limit in `TestBuildAndVerifyExactFourAssetRelease`, while its Linux release build
was still compiling. Every other package passed. The affected packaging test and
complete normal/race suites are being rerun without changing test timeouts; no
full-suite pass is claimed by this entry. Native verification must also pass
before signing a new attempt. During unsigned preparation, desktop control could
not operate Karing and then reported `Sky Computer Use native pipe startup failed`.
No new signed attempt, production issuance, or Karing profile/settings change was
made while that required client control remained unavailable.
