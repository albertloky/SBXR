# Research and decisions

## Whole-project scope

Decision: use the eight rows of docs/rust-acceptance.md as review coverage.
Rationale: current accepted scope already distinguishes new clean-install behavior
from retained historical readers and exact-release recovery. Contract research
reviewed AGENTS, documentation routing, current ADRs and implementation entry points.
Alternative rejected: implementing all historical Go behavior as new Rust requirements.

## Details timeout

Decision: test eliminating full action aggregation only from write_details.
Evidence: build 212 native authentication took 1.858 seconds; initial ReviewStatus
36.276 seconds; driver input occurred 47.083 seconds into the 90-second budget.
write_details then entered another aggregate ReviewDetails which did not finish.
63 completed snapshot checks consumed 16.972 seconds, 71 installed-pair checks
15.933 seconds, 234 subprocess spans 16.601 seconds. These are inclusive categories
and MUST NOT be added together. Repeated work is confirmed; exact future live
latency remains unknown. Source owner.rs performs aggregate review then primary
reopen while output uses only details, followed by separately guarded disclosure.
Alternative rejected: raise timeout, reuse stale authority, skip native guards,
or change action aggregation used to expose independent removal.

## Evidence summaries

Decision: add q212 dated report and update the latest closeout pointer.
Rationale: current pointer still names q205; q212 provides newer bounded observations.
Alternative rejected: overwrite historical reports or mark unreached journeys passed.

## Unresolved operational decisions

A new live run, failure disposition and publication remain outside this plan.
Root cause is bounded to measured repeated work, not a claim that all latency is
explained. No external technology or dependency choice is needed; existing pinned
implementations are retained. No technical clarification prevents offline work.

## Remaining frame duplication at 6e87493

Confirmed from build 212: after aggregate ReviewStatus ended at native elapsed
39.164s, a new journeys (0.649s), open-http (1.906s) and HTTP inspection continued
to about 46.804s: approximately 7.64s of additional subscription-status presentation.
The first fix removed unused action aggregation from details, but did not change
this separate per-frame lookup. HttpInstallation already calculates status_for
from state() during review, then subscription_status calls state() again.

Decision: expose an in-call combined review/status result. Existing adapters get
a compatibility default; HTTP derives both values from the same state; Owner
obtains the selected status journey's value during existing action aggregation;
BoundJourney retains its admission guard. Terminal calls once per frame. No stored
cache, relaxed admission, changed action set, or deadline increase.

Validation uses existing ComposedSources with real protected-file/OwnerRuntime
observations, adjacent Owner regressions, native guard regressions and terminal
input-boundary assertions. The old clean-absent benchmark does not represent the
running HTTP path and is not used to predict VPS speed. A smaller duplicate pair
read in native journeys is deferred to avoid combining independent trust changes.


## Approved build 212 preservation

Decision: extend the existing fixed reservation set by exactly build 212 after
its explicit Owner approval. Current nine-record policy refuses the outstanding
draft, and draft metadata alone does not advance the published/burned/reserved
sequence. Fresh GETs and downloads at 09:18:54 UTC matched its original metadata
and all four asset sizes/digests; release/burn refs were absent. Retained manifest
signature verification binds the exact repository/workflow/main/source/hosted runner.

Alternative rejected: delete/finalize/burn the failed draft, broaden an allow-list,
reuse its sequence, or interpret old live approval as a new attempt. The approved
preservation mechanism requires none of those actions. A new final-source commit
and CI remain necessary before a separately approved candidate can be prepared.


## Build 213: interrupted details and premature terminal failure

Candidate v3.1.139/213 used f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3,
run 42023983739. Current and frozen menu-driver bytes match. The initial Owner
review took about 37.738 seconds and details writing 19.547 seconds. Details and
continuation input were observed at about 60.092 seconds, followed by a fresh
return-menu review. Capture ends at about 79.98 seconds with about 10.02 seconds
of the unchanged 90-second budget remaining. The local result file is absent.
There is no captured timeout/refusal, complete return frame or process result;
neither a pass nor a reproduced timeout can be inferred. Keep fresh-frame and
cancellation behavior; no timing increase or cached authority is justified.

The terminal failure submission returned success at 13:19:59 UTC on November 5.
The collector accepts that failure and exits; its EXIT path writes STOP, then
the candidate workflow's EXIT trap removes the transport and protected handoff.
Removal started at 13:20:20 and exited before selection with empty stdout. Later
read-only status diagnosis ended in authentication, and inventory proved the
handoff/trust/transport absent. With full handoff absence, public entry selects
stable authentication, which cannot authenticate this unqualified draft candidate.
No removal effect or defective removal transaction was observed.

Decision: clarify the terminal boundary in current guidance and the submit helper,
with a fixed message before publication. Do not gate failure on safety_cleanup:
not-started, incomplete and Unknown are necessary truthful states when ownership,
SSH, authentication or cleanup cannot be established; completed is a supplied
observation, not proof of current absence. Do not preserve/reconstruct temporary
trust after failure, bypass authentication or introduce a collector handshake.

The private operator caller wrote final completion only on the Mac; disconnect
left partial output and no result. That limits evidence. It does not justify
replaying the action or treating missing records as a timeout. Future preparation
must verify capture and cleanup access with offline interruption checks before
asking for another live attempt; this continuation adds no detached execution.

## Approved build 213 preservation — 2026-11-06

Decision: append the exact approved q213 signed-unqualified identity to the fixed
reservation set, preserving all ten earlier members and the original failed
candidate. The ten-record policy cannot admit the unresolved q213 draft, and
that draft alone does not advance published/burned/reserved sequence authority.
The new exact-record and next-candidate regressions failed against that policy
(.scratch/acceptance/q13t/red-pinned.log); implementation and final verification
are separate tasks.

The 09:58:41 UTC read-only review in .scratch/acceptance/q213disp/ matched all four
newly downloaded asset streams to recorded metadata and the signed manifest.
Current repository attestation verification bound the exact source, workflow,
main ref, hosted runner and run/attempt. All five signed-artifact files matched
the original retained bytes; release and burn refs were explicitly absent.
A later 10:59:21 UTC metadata refresh (.scratch/acceptance/q213refresh/summary.json)
matched all eleven drafts and twenty-two absent refs. That refresh did not
independently redownload assets, reverify signatures or inspect global history.
These are point-in-time observations, not a remote lock or current host readiness.

The original proposal's unadopted status describes its creation; the subsequent
explicit Owner approval authorizes only the bounded reservation implementation.
Alternatives excluded by that decision: deletion, burn signing, finalizer replay,
reusing q213, weakening the allow-list or treating retention as qualification.
The pre-live Pending failure-state file remains historical signed input; later
failure facts and administrative cleanup remain separate. Current draft body
matches construction text, but unchanged body since creation is not independently
proved. No technical ambiguity requires a new requirement or policy decision.

## Failure-cleanup caller and pending response — 2026-11-06

Current guidance already requires cleanup access independent of a missing client
reply, while original failure submission ends candidate authentication. Current
`operation-deadline` refuses pending responses, so the same normal action route
cannot implement that cleanup contract during an unfinished handoff. This is a
caller/timing distinction, not evidence of defective product removal or a reason
to recreate trust after terminal submission.

Agreed decision: use a read-only cleanup-only calculation over unchanged private
request/draft authority, then restrict the existing supervised driver to the two
removal actions. Count only completed response waits; cap by the original timing,
protected runtime deadline and explicit cutoff with a verification reserve.
Preserve the pending response, failure bytes/timestamps and normal refusal rules.
The earlier generic packaged helper's setup/detail/loop behavior is not authority
for the new explicit mode. A thin caller exposes one reviewed action, not a new
runner or automatic state-repair sequence.

Rejected alternatives: synthetic response/abandonment events, reusing the normal
operation route by dropping clock inputs, advancing setup or credentials during
failure cleanup, renewed per-command clocks, a fresh transport, or claiming all
cleanup from the product result code. Exact live duration and all surrounding
client/secret/transport checks remain unproved; the implementation and bounded
local checks are recorded in review.md. No new product-policy decision is required
for this bounded design.

## Release-tool CI package timeout — 2026-11-06

Observed: Verify 42217521869 at 335769cc1b27694d10065fa88eccc09cdeeccd80
exhausted the amd64 cmd/sbxr-release race package at 600.106 seconds. The active
TestQualificationCommandBuildsOneCleanV3Candidate reported 0s and was in its initial
go build. This establishes cumulative budget exhaustion, not an individual
600-second build hang or the sole cause of total runtime. Parent c60efd0306 used
589.816 seconds in that race package, only 10.184 seconds below the same limit.
Normal amd64 time changed 376.368 -> 393.306 seconds. Arm64 race passed at 500.395
seconds versus 509.589 previously (normal 299.895 versus 302.003); its later archive
was cancelled and assembly skipped after the matrix failure. Evidence remains in
.scratch/acceptance/c4g/ci-completed.json and amd64-job.log, plus c5e/ comparisons.

The static audit identified 51 identical CLI builds at 23 sites across ten test
files, without changed source/build environment/cwd or parallel callers. Six local
Go 1.26.6 builds took 2.223 seconds initially, then 0.767, 0.780, 0.776, 0.798 and
0.828 seconds (mean 0.790). Fifty such warm calls represent about 39.5 seconds of
local setup cost, not measured whole-suite savings or a Linux CI prediction.
See .scratch/acceptance/c5p/build-timings.json. The unchanged-source focused
`-race -run '^TestQualificationCommand'` baseline passed 16 top-level tests in
79.548 seconds (.scratch/acceptance/c5b/before-race.jsonl). The identical repaired
selection passed the same 16 top-level / 469 total tests without skips in 63.024
seconds (c5b/after-race.jsonl), 20.8% shorter in this single local comparison.
This does not predict Linux CI savings. The later unsplit local race package
failed at its unchanged 600-second alarm (600.359s). All intended local tests
were accounted for across that run and the bounded remainder; review.md records
counts and limits. An unsplit local pass and successful final-source native CI
have not been established.

Decision: reuse immutable built bytes only within this equivalent package-test
context and give each fixture a fresh executable. Reject shared mutable paths,
skipped subprocess/reader checks, a generic cross-context cache, increased alarms
or reduced race coverage. No product-policy clarification is needed; test-tooling
implementation choices remain bounded by the existing regression requirements.

## Operator-budget continuation — 2026-11-06

Decision: extend the existing private-log operator wrapper with an explicit bounded
mode rather than add an autonomous cleanup runner. The default exec path remains.
Use a shared absolute cutoff, per-command monotonic cap and separate downstream
reserve; keep selected wall allocations distinct from measured live durations.
The existing menu reserve includes its stopping allowance, whereas the outer
runner's R excludes its own ten seconds. The current procedure is the single
source for the 900/1200/1230s arithmetic and manual-handoff constraints.

Rejected alternatives: resetting deadlines per command, crediting a pending reply,
automatic recovery/retry, treating SSH termination as remote quiescence, or using
inert client fixtures as Karing evidence. The manual M3 route lacks demonstrated
worst-case fit, and real HTTP/Karing/interrupted-state cleanup remains unmeasured.
Those are explicit readiness limits, not reasons to weaken existing checks or
create a new blanket operational prohibition. No new Owner policy decision was
needed for this bounded offline implementation.
