# GitHub automated-test and qualification review — 2026-09-24

## Scope and result

Read-only audit of the latest 40 GitHub workflow runs, from September 11 through
September 24, 2026 (UTC), including every run's jobs/steps and failed-job logs.
The list counts each run once at its latest attempt, not every retry. The first
attempt of run 35965345632 was additionally inspected separately.

| Workflow | Sample | Result |
|---|---:|---|
| Verify | 21 runs | 21 succeeded |
| Construct qualified drafts | 19 runs | 18 failed; 1 cancelled |

The 18 failed candidate runs stopped in: 15 `acceptance-vps` jobs, one preflight,
one draft-construction job, and one native ARM64 build/test job. Candidate build
jobs in this sample have 34 successes, one failure and one cancellation. An
`acceptance-vps` failure is not automatically an automated unit-test failure.

## Current source is being tested

[Verify run 35817086239](https://github.com/albertloky/SBXR/actions/runs/35817086239)
passed on exact current source `1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52`.
Both native Ubuntu amd64 and arm64 jobs passed full `go test ./... -count=1`,
race tests and vet, package construction/verification, actual packaged menu
checks and package-surface secret scans. The latest candidate's native builds
also succeeded; its failure occurred later in live qualification.

The `v2.0.0`/sequence-17 values in `verify.yml` are synthetic packaging-test
identities. The workflow checks out the triggering commit and builds that source;
it is not downloading an old v2 product to test instead. Some job names still
say Installer-Updater or A-to-B, although current MVP is clean-install. Those
labels are confusing, but are not proof that the assertions are obsolete.

## Established failure examples

- [Run 34650089869](https://github.com/albertloky/SBXR/actions/runs/34650089869)
  did have a real automated-test failure: the historical interruption fixture
  expected `deadline-before-boundary`, but observed `deadline-expired-before-start`.
  Commit `e360503` subsequently added fixture startup margin. The historical
  operator producer was later retired; its removal is not proof that every
  historical case passes today. This is not a currently repeating failure in
  the inspected Verify runs.
- [Run 35067639476](https://github.com/albertloky/SBXR/actions/runs/35067639476)
  failed draft construction after an HTTPS download connection reset, not a
  test assertion.
- [Run 35296858687](https://github.com/albertloky/SBXR/actions/runs/35296858687)
  exited preflight without enough diagnostics to establish its original upstream
  cause. Do not label it a stale test. The subsequent diagnostic improvement is
  retained in `cf2e89a`.
- [v3.1.75](v3.1.75-mvp-live-2026-09-18.md) encountered a real live restart and
  cleanup problem; it is not appropriate to categorize every qualification
  failure as harmless workflow friction.
- [v3.1.76](v3.1.76-mvp-live-2026-09-21.md) used a stale operator helper path;
  [v3.1.77](v3.1.77-mvp-live-2026-09-22.md) used an incorrect operator package
  observation; [v3.1.78](v3.1.78-mvp-live-2026-09-22.md) rejected legitimate snap
  cache hard links. These show real operator/checker problems and coverage gaps,
  not a reason to remove current product assertions. Source changes `477a0d7`,
  `d69bf8f`, and `1878d6f` addressed those respective boundaries.
- Run 35965345632 attempt 1 stopped while collecting release history after an
  asset-download/JSON error; public-latest verification had accepted. Attempt 2
  passed preflight, native builds, draft construction and signing, then failed
  on the final live evidence handoff. Its failure did not come from the automated
  product-test suite.

## Conclusion and limits

**Automated Verify is not constantly failing in this sample. Candidate/live
qualification is repeatedly failing.** There is evidence of historically brittle
fixtures and operator assumptions, but not evidence that the current automated
suite generally tests an obsolete SBXR implementation.

Prioritize the approved human-confirmation exception and reliable operator
evidence handling; distinguish automated verification from live qualification in
status summaries. Preserve genuine regression checks. Do not loosen assertions
just to turn red workflows green.

This is a hosted-run audit, not a new test execution or an exhaustive coverage
review. Older live failures were not all independently reproduced; detailed
examples above distinguish hosted logs from retained local incident reports.
Successful CI is not proof of complete real-host or Karing coverage. No workflow
was rerun, no candidate dispatched and no certificate requested for this audit.

[Local run metadata, job summaries and private logs](../../.scratch/acceptance/ci-review-20260924/).
[Approved exception and remaining implementation](late-confirmation-exception-2026-09-24.md).
