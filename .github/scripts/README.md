# Release and qualification scripts

This directory contains the current release-support tooling. Fresh HTTP
subscriptions use `mvp-http-live-v1` with `subscription-clean-install-only` and
empty incoming sources, described in
[HTTP subscription acceptance](../../docs/acceptance/http-subscription-live.md).
The producer retains `mvp-http-recurring-live-v1` and the historical HTTPS
`mvp-live-v1` and `mvp-recurring-live-v1` policies, described in
[ordinary recurring acceptance](https://github.com/albertloky/SBXR/blob/c298af182cdd159a6258c0d17fb37b9b663cf4ee/docs/acceptance/ordinary-recurring-live.md)
and [MVP live acceptance](https://github.com/albertloky/SBXR/blob/c298af182cdd159a6258c0d17fb37b9b663cf4ee/docs/acceptance/mvp-live-acceptance.md); it records
explicit human observations and does not run the historical V4 protocol.

The approved [live89 recording correction](../../docs/adr/0029-live89-operator-recording-correction.md)
is a separate one-target path for fresh v3.1.90/168. Its source review works from
committed Git inputs, requires exact preservation of `cmd/sbxr`, `internal`,
`go.mod`, `go.sum` and the bootstrap template, and binds the policy diff and
approved archive into `live89_correction_review`. Fresh native builds must match
both archived unstamped executable payloads. Candidate preparation and the
correction-result job reproduce the review; the latter retains the exact archive
with explicit provenance rather than driving a new live session. Original failed
live89 history and its burn remain intact. This path has no `owner_exception` and
retains ordinary native, signing, attestation, failure and publication gates.

The current Rust candidate producer refuses `live89_correction_review` during
preflight, before builds or drafts. That one-off Go payload evidence cannot
qualify a Rust rewrite. The pinned review script and candidate/stable readback
checks remain for historical evidence verification; this exclusion does not
relax their source, payload, signature or publication requirements.

| Area | Entry points |
|---|---|
| Candidate declaration and dispatch | `v3-candidate-dispatch.sh` |
| One-target r24 evidence applicability | `late-confirmation-review.py`, `test_late_confirmation_review.py`; [ADR-0024](../../docs/adr/0024-r24-late-confirmation-supplement.md) |
| One-target live89 recording correction | `live89-correction-review.py`, `test_live89_correction_review.py`; exact committed-source review and fresh archive payload verification under [ADR-0029](../../docs/adr/0029-live89-operator-recording-correction.md) |
| MVP observation assembly and submission | `v3-mvp-evidence.py`, `v3-recurring-evidence.sh` |
| Native Karing receipt readbacks | `native-receipts.py`, `capture-native.py`, adjacent tests; shared comparisons and prepared capture/verification callers with actual native-store provenance and strict node comparison |
| Local operator command logs | `mvp-operator-run.py`, `test_mvp_operator_run.py`; disjoint outer logs and pre-launch capture refusal |
| Window expectation proxy pin | `prepare-mvp-window.py`, `test_prepare_mvp_window.py`; derive `/usr/bin/sing-box` SHA-256 from the receipt-verified local DEB without changing host facts |
| Incremental explicit operator observations | `mvp-observe.py`, `test_mvp_observe.py`; explicit observations and signed opt-in attended response windows, no product driving or automatic pass |
| Packaged public-menu helpers | `v3-packaged-live.sh`, `v3-menu-session.py` |
| Temporary MVP log-parent window | [launcher](mvp-protected-menu.sh), [driver integration test](test_mvp_protected_menu.py), [startup cancellation regression](test_mvp_startup_cleanup.py), [operator plan](../../docs/acceptance/mvp-protected-log-parent-2026-09-19.md); use the driver's `--protected-wrapper` opt-in |
| Candidate transport | `v3-qualification-transport.sh` |
| Release history and publication support | `release-history.sh`, `prepare-burn-tag.sh`, `recheck-qualified-release.sh`; `release-main-review.py` binds committed candidate/main divergence to the security/evidence assessment retained by [ADR-0032](../../docs/adr/0032-qualified-publication-retry.md) |
| Qualified publication retry | `publication-recovery.py`, `test_publication_recovery.py`; authenticate an existing prepublication burn and its certified workflow invocation, preserving the full failed record before metadata-only recovery under [ADR-0032](../../docs/adr/0032-qualified-publication-retry.md) |
| Authenticated release asset reads | `download-release-asset.py` |
| Release metadata observations | `observe-github-resource.py`; only an explicit HTTP404 proves absence; authentication, server and transport failures stop cleanup |

`v3-packaged-live.sh` inventories the complete protected candidate footprint and
proves its absence after public cleanup, including the owned mutation-lock boot
unit and optional dedicated tunnel unit, their staged publication paths, and
their enablement symlinks. Owner-provisioned tunnel tokens and cloudflared are
preserved outside that cleanup authority. Absence checks
treat broken symlinks as present. Keep that inventory aligned with
`internal/proxyinstallation` whenever an owned host resource is added or moved;
`release_packaged_driver_test.go` owns the script-level regression checks.
The former `v3-clean` runner and forced-interruption procedure are retired;
their source remains in Git history. The shared menu, identity and cleanup
helpers remain available for current callers.

The candidate transport persists an absolute cutoff in its existing `deadline`
file, with a `runtime-deadline` sixty seconds earlier for process shutdown and
rollback. `up [UTC_UNIX_EPOCH]` accepts an earlier approved cutoff; it cannot
extend the signed `attended_finish_by` plus thirty minutes or the existing
six-hour ceiling. Without attendance the legacy six-hour bound remains. The
workflow derives the bound from the signed attendance value; the operator must
choose that value within the approved security window before dispatch. An
explicit cutoff bounds execution; it does not grant permission to start a run.
For an approval at A with journeys ending by A+2h30 and cleanup by A+3h, use
that attendance value and an absolute cutoff no later than A+3h. Preparation
counts inside the window. Restart reads the stored runtime deadline unchanged.

At cutoff the existing service terminates its gateway and descendants, escalates
to KILL after five seconds, and runs bounded rollback of only its exact NAT
rule, hosts line and matching CA source. Startup and shutdown are bounded too.
The hook takes a lock on the existing `transport-owned` marker and rejects a
replaced marker after waiting. It retains staging, keys and unit files because
an operator may still be reading them; it neither drives product removal nor
restores Mac/Karing state. Automatic routing rollback is not proof of complete
run cleanup. Failures leave the unit failed and emit
`SBXR-TRANSPORT-ROLLBACK-FAILED` in its journal; successful route restoration emits
`SBXR-TRANSPORT-ROUTES-RESTORED`. Failure never extends the approved window.

Normal `down` runs after the coordinator's readers have finished. It waits for
the owned service to stop before taking the same lock, then restores routes,
unlinks only the exact owned enablement link/unit, and validates the entire
known staging tree before deleting its leaves. Unknown files, links, hardlinks
or directories writable by group/others refuse deletion. The manifest and ownership marker are
retained until other removals finish so a partial cleanup can be retried. Keep
the existing protected-menu process supervision, product cleanup and client
restoration inside the approved window; this transport cutoff adds no release
qualification requirement.

For local operator helpers that use `LABEL.private`, `LABEL.stderr` and
`LABEL.receipt.json` for their inner captures, launch the outer command through
`mvp-operator-run.py` with the same label. The September 29 attempt failed when
an outer shell redirection created the inner helper's `s1-finish.stderr` first.
Use an existing fresh directory under `.scratch/acceptance/`; for example,
after the actual journey and its checks have been observed:

```sh
python3 .github/scripts/mvp-operator-run.py \
  --run-directory "$run" --label s1-finish -- \
  python3 "$run/finish-journey.py" s1 source-v3.1.81-precommit source-v3.1.81-upgrade
```

The outer logs are `s1-finish.operator.stdout` and `s1-finish.operator.stderr`,
created exclusively with mode `0600`. Existing outer logs or inner captures,
including broken symlinks, refuse before execution. The command inherits stdin
and the working directory, replaces the launcher process, and retains its own
exit and cancellation behavior. Inspect any newly reserved log after a failed
reservation; it is retained. Do not redirect outer logs onto inner capture
paths. This local wrapper does not perform observations, submit evidence, retry
an attempt, or authorize live work. Its nested-subprocess regression runs in the
ordinary Go suite. The run-local helper in this example remains attempt-specific.

Fresh native operator preparation copies `native-receipts.py` from this source
alongside its capture/recording helpers before freezing their bytes. The current
VLESS URI omits packet encoding; the reader requires Karing's explicit `xudp`,
matching sing-box's omitted-field default. Explicit empty encoding disables that
behavior and is refused. Historical run copies and failed records remain frozen;
this local correction supplies no live qualification or publication authority.

`subscription_nodes(profile, wire, attempt=...)` is a pure offline comparison.
Pass `v3_attempt` from the already authenticated signed manifest and the verified
candidate's emitted wire bytes, never a receipt-selected profile. Omission keeps
the strict one-node VLESS contract; `vless-vmess` requires exactly one VLESS and
one VMess node, the shared identity and exact TLS/WebSocket fields. The strict
VMess field set follows the saved Karing 1.2.25/2802 baseline representation,
including omitted zero `alter_id`; the wire still requires `aid: "0"`.
The Go/Python regression also uses the actual product encoder and full file
readbacks with public fixtures.
The two-node profile requires VLESS Vision on TCP 443 with Chrome uTLS, even if
incorrect wire and native values agree. Default one-node comparisons are unchanged.

`readbacks(..., attempt=...)` uses the same actual primary-store provenance checks
as the existing one-node procedure: owned protected stable source, exact
hash/size/mtime, unique complete profile and distinct private URL/profile captures
matching the emitted bytes. A separate client process/store is not a qualification
requirement. Do not take a target, profile policy or attempt from receipt claims.
Keep existing app/helper identity binding, selected connection, complete settings
and original-profile preservation checks in the reviewed capture/recording callers.
Freeze the helper and every affected caller before a new signed attempt.
Existing baseline serialization and latency observations prove no new candidate
URI import, refresh, traffic, latency or qualification outcome.

Fresh preparations copy `capture-native.py` to their existing prepared directory,
beside `native-inputs.json`, and `native-receipts.py` under `operator-source/`.
Use the existing reviewed input records and normal caller-byte bindings; no new
freeze format is needed. `capture-native.py capture` writes the existing private
capture envelope; `verify` consumes it and re-reads actual current sources.
Both resolve the attempt from the authenticated manifest and check the current
scenario request. Use phases `m2`, `m3-identity`, `m3-link` and `m5`; the two
`baseline-check` phases remain readiness only. Supply actual home-screen connected
and TUN observations using `--connected true|false --tun-enabled true|false`.
All captures are exclusive mode-0600 files, with complete audit/inventory retained
on refusal. Verification must pass immediately before recording native checks.
Neither command operates Karing or records import, refresh or latency as observed.

For new, explicitly pre-bound preparations, the same module owns the
[fixed native settings v2 comparison](../../docs/acceptance/http-subscription-live.md#future-native-settings-comparison).
`settings_binding()` reads the supported actual app identity and helper digest;
freeze that returned contract before dispatch. `settings_readback(binding)`
produces the full private baseline snapshot. `compare_settings(before, after,
binding)` validates both snapshots and derives the three permitted differences.
`capture_settings(baseline_source_record, fresh_current_path, binding)` writes
the actual current snapshot exclusively and returns the settings facts.
M2/M3/M5 capture and recording callers must all use
`preserved_v2(facts, binding, baseline_source_record)` with both trusted inputs
from the frozen preparation. Never select either input from the receipt.
`preserved(facts)` remains the strict v1 API.
The producer and consumer share the comparison and current-source provenance
checks. The timing-only handoff and receipt envelope are unchanged. Full-store
profile preservation and exact native URL/node checks remain separate required
caller checks. `test_native_settings.py` exercises the producer/consumer file
boundary and refusal cases using public fixtures, including Python 3.9.

The separate [future original-profile v3 policy](../../docs/acceptance/http-subscription-live.md#future-original-profile-comparison)
uses `original_profiles_audit_v3(before_profiles, after_profiles, timezone=...,
tzif_record=..., window_start=..., window_end=...)`. It returns the complete
private path/value diff and `passed`; callers retain the audit before requiring
that result. Only the fixed timestamp and latency-cache changes can pass, and
the built-in `custom` profile stays exact.
The frozen baseline determines the original-profile count and order; any nonempty
list of unique IDs containing `custom` is supported. Existing saved test profiles
can remain protected originals. Missing, extra, reordered or changed originals
still refuse; the fixed cache exceptions are unchanged.
`native_timezone_binding()` reads the native zone identity; fresh preparation
must also retain and freeze its exact TZif bytes. The comparator reads those
retained bytes, never process `TZ` or
current native state. Producers record their own baseline/current UTC read times,
not UI-selected windows. M2/M3/same-link/M5 consumers recompute the immutable audit
and separately verify current actual readbacks. Keep policy, baseline, timezone,
observation and caller provenance in the normal frozen input closure; generic
failure cleanup uses static retained authority. `test_native_profiles.py` covers
the fixed exceptions, strict fields, UTC windows and ambiguous/nonexistent local
times. No effective subscription timer model is a prerequisite of this policy.

For historical lifecycle transcripts, the shared menu driver requires Update's `CHECK-UPDATE-AVAILABLE` or Recover's
`STATUS-RECOVERY-REQUIRED` lifecycle review code exactly once before its exact
confirmation prompt. The ordinary action path uses the same rule. Missing, unexpected or duplicate review codes never authorize
confirmation; final action results and original deadlines remain separate.
`test_v3_menu_session.py` exercises success/refusal/deadline cases with actual
subprocess input, while current menus expose Check and Recover.
The shared session checks the original deadline before launch and every input,
and when consuming output, including buffered lines and transcript writes.
Failure cleanup retains its separate bounded quiescence budget; it does not
extend the journey or permit late confirmation.

`Start setup` now enters the numbered setup wizard. The qualification driver
requires its exact default connection prompt, selects **Standard**, then requires
**Apply setup? [y/N]** before sending `y`. It refuses a missing/changed wizard
prompt or a prerequisite refusal without approving anything. The Go terminal
tests also run this Python driver against the real terminal adapter over pipes;
the adjacent Python tests retain deadline, refusal and descendant-cleanup checks.
When explicitly observing an expected setup refusal without confirmation, the
driver requires that exact refusal and Retry/Back/Cancel prompt, sends only `c`,
then verifies cancellation and exits the returned menu within the original
deadline. Unexpected review codes or confirmation prompts still refuse.

The menu driver and packaged helpers share descendant cleanup.
They prefer Linux's optional task `children` list and fall back to parent IDs in
`/proc/PID/stat` when that interface is absent. Each signal uses a process handle
and a kernel child-ownership check, so stale IDs and unrelated siblings cannot
authorize a kill. The existing kill/reap proofs and cleanup deadlines remain.
The adjacent subprocess regressions cover the absent interface and an emulated
kernel child list, including an unowned list entry; signals, escaped processes,
locks and reaping remain real. No extra runtime file is needed in staged bundles.

For the current MVP's installed-candidate check, use the
[documented SSH handoff](../../docs/acceptance/http-subscription-live.md#checking-the-installed-candidate-over-ssh).
It streams this module and calls only `exact_candidate`; the current transport
does not stage `/run/sbxr-qualification/v3-packaged-live.sh`. The existing four-file
temporary-menu staging is unchanged. `release_candidate_handoff_test.go` covers
fresh-shell and streamed-source identity checks; `test_ssh_boundary.py` executes
the documented command over real SSH with the old helper path absent, and proves
refusal stops continuation without changing the synthetic installation.
The fixture supplies a read-only, synthetic password-disabled root shadow
record inside its private mount namespace, so key-only SSH does not inherit a
cloud image's locked-root/PAM policy. It never unlocks the host account.
`test_ssh_boundary_account.py` runs the same 25 real-SSH cases beneath a
deliberately locked caller account and exercises post-readiness failure cleanup;
both paths preserve the caller and host shadow records. The root Go integration
test includes both scripts. These Linux/root namespace tests are local regression
checks, not live acceptance.

The log-parent wrapper qualification is destructive and runs only as root on a
prepared disposable Ubuntu/systemd VM. With the wrapper, supervisor, and test
script staged in `/root/recovery/log-parent-qualification`, invoke it exactly as
`bash /root/recovery/log-parent-qualification/with-protected-log-parent-test.sh`.

`test_mvp_protected_menu.py` separately tests the real menu driver through the
temporary launcher and reviewed wrapper. It also requires a marked disposable
root Linux VM and refuses existing product/staging/Certbot-log fixture paths.
Use the operator plan for its scope and the adjacent Go Linux test for real
systemd/TLS behavior. Neither test contacts a public CA or qualifies a release.
Run fixed-path root-Linux fixtures sequentially within one disposable VM.
Concurrent menu-driver tests correctly trip the observer's active-writer
refusal; use separate disposable VMs if parallel execution is needed.

The repaired launcher sets `umask 022` only in the child that execs the unchanged
product; the pinned wrapper and supervisor retain private `077` state files.
The read-only `mvp-inspect-window.py` replaces run-local package/window probes.
Use its [documented SSH call and receipt inputs](../../docs/acceptance/mvp-protected-log-parent-2026-09-19.md#read-only-state-checks-corrected-september-22).
It queries the installed held package independently of the deliberately removed
DEB and compares the Ownership Record string, not the declaration object.
Snap images may have snapd cache hard links; root ownership, regular-file type,
non-writable group/other permissions, no xattrs, and exact receipts are still
required. Other protected files retain the one-link rule; ordinary `running`
refuses update transaction residue.
`test_mvp_inspect_window.py` covers portable contracts and, when run as root on
Linux, real snap/cache hard links and metadata/content refusals;
`test_mvp_inspect_window_linux.py VERIFIED_DEB` exercises the exact documented
call through loopback SSH, real dpkg install/hold/purge of the pinned official
amd64 package, the existing driver/launcher/wrapper, timer/lock refusals and
fixture cleanup. It refuses anything other than an explicitly marked disposable
root amd64 Linux VM with absent fixture resources. SBXR records/menu and snap
CLI/images are synthetic, with real snap/cache hard links; no CA or product
acceptance is claimed. Keep egress
restricted. The opt-in root Go wrapper uses `SBXR_MVP_OBSERVER_DEB`.

The asset reader uses `gh api` and makes at most one fresh GET after a TCP read
reset, the failure observed in the unsigned `v3.1.73` draft download. It discards
the incomplete body, obtains a new redirect from the API, and exposes a completed
file atomically. Other errors and a second reset fail. Callers retain their
existing identity, size, and SHA-256 verification; release mutations are not
retried. Error logs retain the read failure and discarded byte count with URLs
redacted. `python3 .github/scripts/test_download_release_asset.py -v` exercises
the real `gh` client against a local server, including resets and HTTP refusals;
the root `release_asset_download_test.go` includes it in ordinary Go checks.

Focused helper tests live beside the scripts they exercise, including
`test_mvp_evidence.py` and `test_ssh_boundary.py`. The former
outside-probe mode is retired. Repository-root Go tests are split by concern:
`release_workflow_test.go` covers native CI; `release_candidate_workflow_test.go`
covers candidate preparation; `release_stable_workflow_test.go` covers
publication/failure; and `release_collector_test.go`,
`release_packaged_driver_test.go`, and `release_transport_test.go` cover their
matching script boundaries. The former V4 operator producer is retired; retrieve
it only to interpret historical records at
[commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator).
