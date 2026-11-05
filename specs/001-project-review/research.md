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
