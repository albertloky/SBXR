# Acceptance documentation

## Recorded release state

[v3.1.81 / 159 stable publication — 2026-09-25](reports/v3.1.81-stable-publication-2026-09-25.md)
records successful immutable Latest publication. Read it with
[qualification — 2026-09-24](reports/v3.1.81-exception-qualification-2026-09-24.md)
and [ADR-0024](../adr/0024-r24-late-confirmation-supplement.md): prior live evidence
was reused under the exact one-target exception, not replaced by a fresh live run.
Refresh remote state before acting; this index is not a readiness receipt.

## Current procedure

[Ordinary recurring live acceptance](ordinary-recurring-live.md) is the approved
`mvp-recurring-live-v1` procedure: five normal journeys plus three actual packaged
source upgrade/recovery checks. The first route is v3.1.81 to the next release.
Read [ADR-0025](../adr/0025-ordinary-recurring-live-acceptance.md) and the procedure's
pre-dispatch gates; approval of scope is not a live pass or host authorization.

[MVP live acceptance](mvp-live-acceptance.md) retains the clean-install
procedure for `mvp-live-v1`. It defines the five normal journeys and the explicit
operator observation handoff. Use it with [ADR-0023](../adr/0023-mvp-live-acceptance.md).

[Temporary MVP log-parent windows](mvp-protected-log-parent-2026-09-19.md)
records the bounded operator plan for the existing protected-parent prerequisite
on the retained Ubuntu host shape. It requires fresh host evidence and review,
adds no MVP journey, and does not establish current readiness or acceptance.

## Reports and bounded maintenance

Use the [report index](reports/README.md) for release attempts, preflights,
repair results and investigations. Reports keep their original dates, scope
and limitations; a preparation report is not authorization to rerun its plan.

[GitHub CI review — 2026-09-24](reports/github-ci-review-2026-09-24.md) distinguishes
automated test results from live-qualification failures.
[Approved late-confirmation exception](late-confirmation-exception-2026-09-24.md)
records the bounded Owner decision, archival validator and exact v3.1.81/159
release exception. The ordinary live-result gate
is unchanged.

[Certificate-state and startup repairs — 2026-09-19](reports/certificate-start-coordination-repair-2026-09-19.md)
records local regression and isolated systemd validation, plus the
[maintenance handoff](v3.1.75-snapshot-recovery-runbook.md) for the retained
generation mismatch. The report distinguishes exact original-executable
rehearsals, source-level coverage and live observations. Its current status and
remaining gates are recorded there; the handoff adds no MVP journey.

## Historical and fixed-path material

The [historical index](historical/README.md) routes to the retired V4 procedures,
evidence guides and Installer-Updater release-pair procedure. Do not run them as
the current MVP checklist. Historical readers remain in Go; the producer source
is retained at [commit `0859e96`](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator).

The following paths deliberately remain here rather than being moved for tidiness:

| File | Why the path remains |
|---|---|
| [installer-updater-vps.md](installer-updater-vps.md) | Historical checklist whose bytes/path are consumed by release workflows |
| [v3-packaged-live.md](v3-packaged-live.md) | Versioned historical contracts and workflow checklist digest input |
| [Source-upgrade investigation](344-packaged-source-upgrade-investigation.md) | Linked by the unchanged packaged checklist; historical negative evidence |
| [Snapshot recovery runbook](v3.1.75-snapshot-recovery-runbook.md) | Exact one-time maintenance procedure exercised by a regression test |
| [MVP procedure](mvp-live-acceptance.md), [log-parent plan](mvp-protected-log-parent-2026-09-19.md) | Current procedure and executable handoffs consumed by tests |
| [Late-confirmation decision](late-confirmation-exception-2026-09-24.md) | Exact exception context linked by ADR-0024 |
