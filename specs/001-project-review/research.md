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
