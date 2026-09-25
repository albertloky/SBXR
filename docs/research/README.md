# Research notes

This directory contains source reviews, design investigations, and codebase
catalogs. These notes inform implementation and documentation work, but they do
not change product behavior, acceptance policy, or a release result.

Use the [code map](../agents/code-map.md) for current implementation, and
[ADR-0023](../adr/0023-mvp-live-acceptance.md) plus the
[MVP procedure](../acceptance/mvp-live-acceptance.md) for current live scope.
Read the notes below only for the relevant background question.

## Dated codebase snapshots

| Question | Snapshot |
|---|---|
| Why was the live scope reduced? | [MVP qualification review — 2026-09-12](snapshots/2026-09-12-mvp-qualification-review.md) |
| What functions and modules existed then? | [Module/function catalog — 2026-09-12](snapshots/2026-09-12-module-function-catalog.md) |
| What did the earlier cleanup remove and retain? | [Codebase cleanup — 2026-09-12](snapshots/2026-09-12-codebase-cleanup.md) |

Catalog counts, line numbers, working-tree observations and references to local
instructions belong to their review date. They are not a maintained code map.

## Historical upstream research

| Question | Source review |
|---|---|
| First V3 journey and sing-box constraints | [294 — sing-box](historical/294-official-sing-box-constraints-first-v3-journey.md) |
| Karing parsing and the one-node artifact | [333 — subscription artifact](historical/333-karing-subscription-artifact-primary-sources.md) |
| Renewal timing and evidence limits | [335 — renewal qualification](historical/335-subscription-renewal-qualification-timing.md) |
| Recorder behavior across refresh and removal | [338 — refresh/removal](historical/338-subscription-recorder-refresh-removal.md) |
| Certbot hooks and transition ordering | [339 — Certbot transitions](historical/339-subscription-certbot-transition-hooks.md) |

These notes preserve original questions, source versions and proposals. Tracking
a previously local research note does not adopt its proposals or refresh its
upstream findings. Recheck primary sources when using them for a new decision.
