# Bounded operator cleanup preparation

This is an operator budget for a future, separately approved single Rust HTTP
qualification. It changes no signed qualification policy and authorizes no live
operation, system change, signing or publication. It follows the
[current HTTP guide](http-subscription-live.md#bounded-supported-cleanup-after-a-stopped-journey).
The reviewed code baseline is `9e625648e05ae8018f5d2cd9b051ff7a01a00c97`;
freeze the final reviewed source and every actual caller before use. Historical
q212/q213 callers, request identities and archives must not be reused as current
authority.

These are selected upper allocations for stopping work, not measured completion
guarantees. A refusal, missing reply, unknown ownership, lost connection or expired
authentication can still leave cleanup incomplete. Preserve evidence and report
that outcome; do not extend clocks or invent success.

## One absolute deadline

For the actual current request, obtain the verified `cleanup-deadline` from
[mvp-observe.py](../../.github/scripts/mvp-observe.py). Its conservative bound
credits only completed recorded waits. Pending responses add zero time; sealed,
missing, changed, malformed or expired inputs refuse.

Let `E` be the earliest of that bound, the existing protected candidate runtime
deadline and the approved absolute cleanup cutoff. Preserve the same original
cutoffs throughout the sequence. Fresh checks may tighten `E`, never extend it.
Do not reconstruct a later deadline from the time an operator becomes ready.
The per-command monotonic timer bounds that running command only. The shared
sequence does not automatically detect wall-clock rollback; stop on an observed
clock inconsistency rather than repairing timestamps or assuming extra time.

For a proposed 5½-hour attended window starting at `S`, the intended signed
finish is `S + 5h` and security/cleanup cutoff is `S + 5½h`, subject to the
actual signed and runtime limits. The transport normally stops serving one
minute before its cutoff; read its existing protected runtime file rather than
assuming this value. The signed finish must also satisfy its existing six-hour
attempt-start constraint. Build/sign/queue time consumes the original window.

Because the cleanup clock is capped by signed finish and scenario time, the
final thirty minutes do not extend product-operation authority. Terminal failure
and collector expiry may remove authentication earlier still.

## Selected complete cleanup envelopes

Use the 900-second envelope only for M1 when no candidate Karing profile has been
imported. Use 1200 seconds once HTTP/Karing state may exist, including M2–M5.
A planned manual M5 cleanup handoff requires the 1230-second variant below.
Do not select the smaller envelope merely because an import result is uncertain.

The ordered rows below are complete wall allocations. Each automated row is one
reviewed supervised batch. If implementation splits it into more supervised
batches, account for every additional stop allowance and recompute admission.
A row's remaining reserve contains all later rows plus the final 50-second guard.

| Ordered work | Action cap and supervision | Row total | Runner downstream reserve, M1 / HTTP |
|---|---|---:|---:|
| Read current request/clock, candidate and transport identity | 80s + 10s local stop | 90s | 810s / 1110s |
| Read fresh ownership, uncertain-action/process state; select exactly one legal action | 80s + 10s local stop | 90s | 720s / 1020s |
| One Complete removal or Finish removal | 360s menu + 30s remote clock/stop/connection allowance + 10s local stop | 400s | 320s / 620s |
| Verify host absence, package/account/service/firewall preservation and SSH | 80s + 10s local stop | 90s | 230s / 530s |
| Stop only owned outside clients; verify outside rejection | 50s + 10s local stop | 60s | 170s / 470s |
| Remove only candidate test profiles; restore original settings, selected profile, connection and TUN state, when applicable | 300s attended/UI allocation | 0s / 300s | Not an argv timeout |
| Verify original client readbacks; remove/redact inventoried disposable secrets and captures | 80s + 10s local stop | 90s | 80s / 80s |
| Retain truthful result; assemble/submit success only when all required proofs exist, otherwise original failure when appropriate | 20s + 10s local stop | 30s | 50s / 50s |
| Scheduling, boundary and reporting guard | Reserved, not another operation | 50s | — |
| **Total** | | **900s / 1200s** | |

The Karing row is an attended/UI stop allocation, not a claim that a command-line
watchdog controls a native application. A reviewed direct script could use
290s + 10s supervision within that row; a manual simple-action timeout remains
the full policy five minutes, not 290 seconds. Native capture/comparison belongs
in the following local-verification row. Freeze the exact applicable route and
prove that cleanup does not depend on an unanswered client reply before effects.

The [operator runner](../../.github/scripts/mvp-operator-run.py) bounded interface
uses all three arguments together: `--cutoff-unix E --timeout A --reserve R`.
Here `R` excludes its own fixed ten-second stop allowance. Admission requires
strictly `now + A + 10 + R < E`, not equality. This interface and its actual
composed caller require their own verification before live use; this table
asserts no simulation result.

For the removal row, use outer `A=390` and `R=320` for M1 or `R=620` for
HTTP/Karing. The [menu driver](../../.github/scripts/v3-menu-session.py) gets
`--timeout 360` and `--cleanup-reserve 360` or `660`, respectively.
That menu reserve includes remote clock/stop/connection allowance 30s, outer supervision 10s,
downstream work 270s/570s and guard 50s. Thus both layers protect the same
720s/1020s remaining envelope without double-counting supervision.

For a planned manual M5 cleanup handoff, reserve its separate 30 seconds of
readiness/response recording from initial admission: total **1230 seconds**.
Add 30 to each upstream downstream-reserve value until that recording work is
actually completed. In particular, the first two reserves are 1140/1050 seconds,
removal uses outer `R=650` and menu `--cleanup-reserve 690`, and the host/outside
rows use `R=560`/`500`. Both removal layers then protect 1050 seconds:
`390 + 10 + 650 = 360 + 690`. The 300-second Karing slot remains single.
Account for the real recording invocations and their supervision within the
extra 30 seconds; if their prepared command caps need more, increase the
variant and all upstream reserves before admission. Never silently consume the
50-second final guard for that additional work.

Use the freshly reviewed Complete removal confirmation or Finish removal
contract from the [maintained caller](../../.github/scripts/v3-packaged-live.sh).
Do not loop, finish setup first, retry uncertain removal, unset recorder bindings,
or substitute administrative deletion. An absent executable requires independent
absence or exact-finisher assessment. No such assessment may silently reinstall
or recreate transport.

## Scenario work caps and early stops

Let `B` be the original request deadline and `W` the sum of actual completed
recorded response waits. Technical age is elapsed time from the real request
start minus `W`. The table assumes `E = B + W`; an earlier signed/runtime/
approved cutoff tightens every value. All comparisons require positive margin.

These are per-operation caps selected for planning, not promises that all can be
consumed in one scenario. Before every effect, its full cap, applicable remote
and local stop allowances, and the complete remaining cleanup envelope must fit.
Do not start an operation merely because its own timeout fits. Recording,
preparation and coordination also consume time.

| Scenario | Selected qualification-action caps | Latest stop of other qualification work with the full cleanup envelope intact |
|---|---|---|
| M1 install, 30m | Packaged installer 60s; setup 240s; complete details/menu criterion **90s unchanged**; separate ordinary lifecycle menu actions 90s each; outside probe 50s; read-only SSH batch 80s | Before technical age 15m, reserving 900s |
| M2 subscription, 120m | HTTP enablement 180s; each bounded outside HTTP/artifact check 50s; grouped prepared import/latency/manual-refresh response timeout 600s | Before technical age 100m, reserving 1200s; handoff has the earlier limit below |
| M3 credentials, 30m | Client Identity rotation 90s; Subscription Link rotation 90s, ordered after identity proof; each outside-session/probe batch 50s; prepared Karing replacement-latency response timeout 300s | Before technical age 10m, reserving 1200s; manual handoff is substantially tighter |
| M4 serving, 30m | Owned ordinary serving restart 30s; each unchanged-link/artifact/outside probe batch 50s; read-only SSH batch 80s | Before technical age 10m, reserving 1200s |
| M5 removal, 30m | Ordinary restart/access menu action 90s and outside probe 50s; then the cleanup sequence above, including its one 360s removal and one 300s Karing slot | Before technical age 10m with the direct 1200s route, or 9m30s with the manual 1230s route; subtract only proved completed rows, never repeat removal |

A supervised product-menu action additionally budgets 30 seconds for remote
clock/stop/connection handling and 10 seconds of local stopping. Fresh Rust uses
the unwrapped menu driver; this allowance does not require a protected wrapper.
Other supervised batches budget their ten-second local stop. Refuse a full action
whose reviewed allocation no longer fits; do not silently shorten its plan.

M5 uses the cleanup sequence itself. After actual removal and independent absence
are proved, subtract only those completed rows and any applicable completed
prechecks from the remaining reserve. Do not replay removal or reserve a second
copy of its work. Its actual profile cleanup occupies the existing 300-second
Karing row once; it is not a five-minute wait followed by a second five-minute
cleanup allowance. If missing cooperation would prevent independently reachable
cleanup within the selected row, do not open that handoff.

## Handoff admission and the M3 limitation

Before a qualification handoff with response allowance `H`, require
`now + H + 30 + C < E`, where `C` is the complete remaining cleanup envelope.
The extra 30 seconds reserves readiness/response recording; it is not credited
as human waiting or silently taken from the final guard. Also require actual
notification + 3600 seconds <= signed attended finish. Keep the declaration's
existing 3600-second opt-in; do not change it to 300/600.

Consequences with no earlier global bound:

- M2's grouped 600-second handoff must start before technical age **89m30s**:
  7200 - 600 - 30 - 1200 = 5370 seconds.
- M3's prepared simple 300-second handoff must start before technical age
  **4m30s**: 1800 - 300 - 30 - 1200 = 270 seconds.
- A grouped ten-minute M3 handoff cannot fit alongside this cleanup envelope,
  even at request start. It is not part of this selected plan.
- A completed wait can extend the technical clock only by its actually recorded
  duration. Each subsequent handoff needs a new calculation. A pending wait never
  supplies that extension.
- M5's cleanup handoff uses the already allocated Karing row, rather than adding
  the same 300 seconds twice. Reserve its separate 30-second recording overhead
  before opening it and recompute the remaining envelope. If that manual handoff
  is planned from M5 entry, its base 1200-second cleanup budget becomes 1230
  seconds including this extra recording allowance; it does not become 1530.
  It still requires the one-hour signed-finish admission guard and independently
  reachable cleanup.

For M3, two 90-second mutations plus their 30+10-second supervision allowances
already consume 260 seconds. That leaves **less than ten seconds** before the
270-second notification threshold for all preceding outside-session setup,
identity/session-revocation/replacement proofs, link checks and coordination.
Those checks cannot be omitted, parallelized across dependent states or reported
early. The worst-case selected manual route therefore has no demonstrated fit.
Do not describe it as ready merely because a five-minute client timeout is allowed.

Direct authorized operation and observation of Karing creates no artificial
handoff or paused wait. It may avoid the manual response allowance, but its real
action/capture time still consumes the ten-minute technical-work allowance.
Review the actual direct route and its action budget before choosing it; tool
availability alone is insufficient. The manual route's lack of a guaranteed
worst-case fit is an explicit early-stop risk, not a new blanket prohibition on
an otherwise authorized bounded attempt. Refuse the actual next mutation or
handoff when its full cap plus downstream reserve cannot fit; do not omit checks
or continue into the cleanup allocation. Any unavailable required client route
remains a specific readiness gap. Do not reduce the cleanup reserve solely to
make the qualification plan fit.

For a signed finish at S+5h, every required manual notification must occur by
S+4h, even if a short response is expected. This independent restriction can
dominate the scenario limits. Prepare subsequent inputs before submitting the
previous result because the collector starts the next request immediately.
Do not shift the original attended start to absorb build, queue or coordination
delays.

## Final transport and preservation reserve

Select thirty minutes for post-result transport teardown and final verification,
within the original absolute security cutoff. It is separate from every scenario
envelope and cannot rescue expired product authentication.

The existing candidate-workflow EXIT cleanup trap can make twelve attempts,
using 90s SSH, up to 5s local reap and 5s sleep per iteration: approximately
`12 * (90 + 5 + 5) = 1200s` before other overhead. This is the unchanged workflow
trap, not a new operator observation/retry plan. The new operator runner does
not mechanically bound that loop. No additional operator retry is authorized.

Only 600 seconds of a selected thirty-minute reserve would then remain for
additional overhead and independent final ownership, trust/routing, SSH, client,
secret and evidence-preservation checks. Account for every supervised batch in
those independent checks and require its remaining work to fit the shared
cutoff. Thirty minutes is not a guarantee: the absolute cutoff can expire before
the workflow trap or verification completes, leaving cleanup unknown/incomplete.
Do not extend it or infer host cleanup solely from a workflow conclusion.

Use only exact-owned transport/trust/routing/recorder resources and fresh identity
checks. Preserve original Karing stores/settings, historical drafts/assets/
signatures, q212/q213 archives, unrelated resources and failed observations.
Keep unredacted retained captures private when ownership or redaction is uncertain.
No broad deletion, transport reconstruction, authentication bypass, automatic
extra attempt, burn, reservation action or administrative fallback is included.

[bounded-ssh.py](../../.github/scripts/bounded-ssh.py) caps an inspection at
120 seconds and only supervises the local SSH process. It cannot wrap a
360-second removal as a 120-second call. The action instead needs its reviewed
remote supervision and appropriately bounded outer runner. A timeout or lost
connection leaves remote outcome unknown until fresh independent inspection;
it does not prove remote quiescence or authorize replay.

## Evidence and readiness verdict

Build 212's actual supported removal took 151.571 seconds. Failure return to
removal start was 130.441 seconds; first post-removal safety/baseline verification
finished about 35.752 seconds after removal. Full scoped cleanup verification
finished about 610.157 seconds after failure, including transport work and
coordination. The 180-second prechecks and 360-second removal allocations exceed
those individual observations; none is a statistical bound.

That attempt had no enabled HTTP subscription or imported candidate Karing profile.
Build 213's later separately approved administrative recovery supplies no
supported-removal duration. HTTP/Karing cleanup, interrupted identity/publication/
removal states, connection-loss recovery and the new full caller remain unmeasured
live. See the [q212 report](reports/q212-details-timeout-2026-11-05.md),
[q213 report](reports/q213-interrupted-details-cleanup-2026-11-06.md) and
[bounded caller report](reports/bounded-safety-cleanup-2026-11-06.md).

M1 request-to-details-failure on q212 was about 6m37s. On q213, request-to-details
start was about 6m26s, followed by 79.98 seconds of retained interrupted capture:
about 7m46s total. The proposed fifteen-minute work allowance would leave about
8m23s / 7m14s after those respective traces for the still-unproved remaining M1
checks. q213 has no terminal details result; these figures neither prove a
90-second pass nor demonstrate a complete M1 fit.

Before live admission, freeze the exact candidate/source/host/request-bound
callers, map every real command and UI step into these rows, and verify their
composed timeout/refusal/uncertain-outcome behavior offline. Fresh host/client/
outside-route availability, ownership, authentication and original-state baselines
remain required under the approved scope. A missing capability or infeasible
remaining budget stops admission. Unknown live duration alone is not converted
into either a guarantee or permission for a new test. No successful simulation,
current host readiness or live qualification is asserted by this document.

## Offline no-reply containment rehearsal

The stop-only coordinator, `mvp-retained-containment.py`, now has concrete
process, host, native readback and transport-comparison adapters beside it in
`.github/scripts/mvp-containment-*.py`. The binding factory freezes all nine
phase callers and their source dependencies without executing them. Its output
is explicitly **not ready for live use**: an actual signed run, immutable failure,
request/clock, authenticated ownership review, host scope, outside process IDs,
original baselines and fresh CUA observations still have to be bound. A file
claiming confirmation does not itself grant permission.

The sequence preserves original cutoffs and failure identity, records exclusive
intents and refuses replay. The host payload checks actual machine/boot/run and
manifest anchors, exact authority and executable bytes, fragment/drop-in pins,
process/cgroup ownership, activation dependencies and absence of stop hooks.
Its only service effects are `systemctl disable --now` for the proved present
`sbxr-subscription.service` and `sing-box.service`. An absent unit must also have
no unloaded fragment or drop-in. Changed or unknown ownership refuses.

The process adapter runs checked source bytes through the existing bounded
operator supervisor and forwards interruption signals. The native entry uses the
prepared SSH transport's independent remote watchdog and the earlier of the
original request, runtime and signed deadlines. An uncertain stop is never
replayed or recorded as success. Losing SSH does not prove a systemd job stopped.
Subsequent checks require inactive/disabled services, empty candidate cgroups,
closed ports, preserved SSH, unchanged unrelated state and unchanged retained
files. Karing restoration is a direct CUA work item, followed by canonical file
readbacks; no CLI app-state mutation or profile deletion is offered.

The 900/1200-second cleanup allocations are retained: the 400-second product row
becomes stop-only containment; the 90-second disposal row becomes retained-data
and original-client verification. Proposed pre-review 180 seconds, response wait
60 seconds and coordination 30 seconds give 1170/1470 seconds in total. These
are enforced stop allocations, **not measured native completion times**. M3's
separate 300-second manual handoff plus 30 seconds recording still lacks a strict
fit; direct CUA must be ready and every next operation must fit its whole cap.

The existing failure finalizer records failure with **incomplete cleanup** and
submits only once. This may trigger the existing workflow's automatic transport
teardown; it therefore requires the real live-job action-time confirmation before
that job starts. The separate read-only transport observation uses 1350 seconds
(including supervision/SSH overhead) plus a 450-second reserve within the original
final cutoff. It verifies original trust/hosts/routing restoration and unchanged
retained installation; it does not itself execute teardown. Keeping temporary
trust or routing active is not a retention option.

Offline tests exercise real local processes, timeout/interruption, public fixture
files, actual host payload logic and native readback code. They do not exercise
Linux systemd, SSH loss, the live failure-finalization boundary or CUA restoration.
No fixture proves those timings. Success of this fallback means **contained with
retained data**, never completed cleanup or qualification. Packages, account,
configuration, disposable credentials, profiles and captures remain protected and
must be reported for later specifically approved removal. Do not admit a run
without closure of the actual callers, current readiness and full remaining budget.


The canonical `mvp-host-baseline.py` reader uses the bounded SSH producer's exact
`live/host-baseline.operator.stdout` location. It preserves source/host, byte,
required-path and successful-inspection checks. Do not move original evidence to
satisfy an outdated consumer path. The transport comparison accepts the original
regular-file metadata format, whose digest establishes its type, and the explicit
`kind: regular` field produced by newer snapshots. Other recorded fields remain
exact; only the existing hosts-file inode exception applies. Changed file type,
permissions, digest, size or CA-bundle inode still refuses.
