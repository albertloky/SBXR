# Bounded operator budget preparation — 2026-11-06

Baseline: main `9e625648e05ae8018f5d2cd9b051ff7a01a00c97`. This continuation
addresses the surrounding caller gap left after the supported safety-cleanup
clock/menu repair. It is offline preparation, not a new live attempt or proof
that cleanup fits a live window. Existing failed candidates and evidence remain
unchanged.

## Change and scope

The existing `mvp-operator-run.py` previously isolated logs and replaced itself
with the command. It had no optional action-cap/reserve interface. Its default
same-process exec contract remains unchanged. The explicit three-option mode now
requires the full command cap, ten seconds for local stopping, and the downstream
reserve to fit strictly before a fixed absolute cutoff. It supervises one local
foreground process group, preserves exclusive private logs, forwards cancellation,
and never selects operations, retries, records observations or claims cleanup.

Each admitted command also retains a monotonic cap and checks the wall-clock
cutoff. Separate invocations do not share a persistent monotonic sequence clock;
the wrapper cannot establish remote quiescence, contain detached sessions or
control Karing UI. Clock inconsistency, transport loss and unknown outcomes must
be handled explicitly by the prepared operator procedure.

The [current budget profile](../bounded-operator-cleanup.md) defines ordered
900-second M1 and 1200-second HTTP/Karing cleanup allocations (1230 seconds
when M5 needs a manual cleanup handoff), per-scenario action caps, downstream
verification reserves, manual handoff thresholds and a separate final transport
allowance. These are selected stopping allocations. Build 212's
observed removal and cleanup times are evidence for that earlier state, not
upper bounds for HTTP/Karing or an interrupted transaction.

Existing signed clocks, gates, project rules, product code and workflow cleanup
remain unchanged. The existing Spec Kit feature was continued; no new feature
branch, initialization or constitution ratification was introduced.

## Verification

- The new bounded invocation first failed against the old wrapper because the
  arguments were unsupported (exit 2, rather than the fixture command's 23).
- Final focused Python suite: **17 passed in 13.703 seconds**. It exercises real
  child/group termination, TERM/INT/HUP cancellation, exited-leader descendants,
  signal exit status, private captures, invalid budgets, sequential cutoff
  exhaustion and clock failures/jumps. The unchanged same-PID default tests pass.
- Review caught an attempt to reset SIGKILL's disposition when preserving a child
  signal result. The implementation now handles that uncatchable signal correctly;
  the real-child SIGKILL regression passes.
- Focused root integration passed in **43.518 seconds**: MVP recorder/evidence and
  operator wrapper, shared packaged menu drivers, and release safety adapters.
  Final fixture-only tightening was then covered by the 17-test Python run.
- A separate six-case public-fixture rehearsal composed the actual hash-bound
  cleanup clock loader, protected runtime reader and bounded command. Pending and
  completed-plus-pending histories admitted an inert local command; expired,
  sealed, missing and malformed histories refused it. Original fixture bytes
  remained unchanged. Budget arithmetic was also checked, without treating
  selected caps as measured durations.

Evidence: `.scratch/acceptance/ob1/` (red/final green and diagnostics),
`.scratch/acceptance/b6r/` (rehearsal and integration). No VPS, outside client,
Karing, signing, dispatch, cleanup execution or publication was used for these
checks. No Go/Rust implementation changed; broad local native/race checks were
not repeated solely for this Python/documentation continuation. The exact-source
GitHub Verify result is recorded below.

## Remaining limits and next admission

The manual M3 credentials route must notify its prepared five-minute Karing
handoff before technical age **4m30s** under this profile. Two maximum-budget
mutations consume 260 of those 270 seconds before all other required checks.
The worst-case manual route therefore has no demonstrated fit. A grouped
ten-minute handoff cannot fit a thirty-minute request with the full reserve.
A directly operated, actually observed client route needs its own reviewed cap
and working capability; tool availability is insufficient. Do not discard checks
or reduce cleanup reserves merely to call the plan ready.

The full HTTP/Karing cleanup duration, interrupted states and final transport
restoration remain unmeasured. The unchanged workflow cleanup loop can consume
about twenty minutes before additional overhead and independent checks; the
chosen final thirty minutes is not a guarantee. Exact prepared callers, current
candidate allocation, host/client readiness and a new approved attended window
remain necessary before live work. T018's full 90-second details result and all
five exact-candidate journeys remain unproved. No current live-readiness claim is
made by this report.


## Exact-source CI closeout — 2026-11-06

Commit `ab8f0601125a85d86f975608e3c8e8a0e2c9ae14` reached GitHub main.
[Verify 42240439778](https://github.com/albertloky/SBXR/actions/runs/42240439778),
attempt 1, completed successfully at 15:40:34 UTC with all four native and
assembly jobs passing. Fresh GitHub reads after the Mac reconnected confirmed
that source/run association and every job's successful result.

| Architecture | Release-tool normal / race | Root integration normal / race |
|---|---|---|
| amd64 | 314.212s / 531.685s | 110.042s / 110.232s |
| arm64 | 267.340s / 477.139s | 90.914s / 90.460s |

Decoded logs confirm the full unchanged normal/race Go commands, Rust checks,
formatting, Clippy, vet, native archive inspection, four-asset assembly and closed
dispatch checks passed. Cargo suites totaled 710 passed and two ignored per
architecture across product and packaging tests. The two ignored entries are a
child fixture invoked by timeout-controlled parent tests and a manual timing
measurement. The operator-runner suite is executed through the passing root
integration wrapper; successful individual Python output is suppressed there.
The local 17-test result above remains separately identified.

This closes T056 for the implemented source and its native CI. Receipt and job
identities are retained in `.scratch/acceptance/b6r/ci-completed.json`. The closeout
changes documentation only and claims no test run for a later commit. T018 and all
stated live timing/readiness limitations remain unchanged; no VPS/client access,
new candidate, signing, live test or publication occurred.
