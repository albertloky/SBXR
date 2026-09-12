## Source navigation

For code changes, start with [the code map](docs/agents/code-map.md): it maps
tasks to entry points, owning modules, and focused checks.

Work in `main` unless the Owner requests another branch. Use the
[current MVP acceptance procedure](docs/acceptance/mvp-live-acceptance.md) for
live qualification. Historical reports and retired test procedures describe
their named revisions; they do not add requirements to the current MVP.
Local `.scratch/` contains run artifacts and copied source, not the source of
truth for a code change.

## Agent skills

### Issue tracker

Issues are tracked with GitHub Issues. See `docs/agents/issue-tracker.md`.

### Triage labels

The default five-label triage vocabulary is used. See `docs/agents/triage-labels.md`.

### Domain docs

This repository uses a single-context layout. See `docs/agents/domain.md`.

## Implementation and regression prevention

For every feature implementation and bug fix, take responsibility for preserving
existing behavior and preventing regressions. Apply these requirements
proportionately to the change's risk and complexity.

1. **Establish the intended behavior before editing.** For a bug, establish the
   failure from evidence or a reproducible case and separate confirmed causes
   from hypotheses. For a feature, identify its acceptance criteria and the
   existing behavior that must remain intact. Briefly explain why the proposed
   change addresses the problem and what it could affect.
2. **Inspect affected callers and execution paths.** When changing a shared
   helper or interface, inspect every affected caller, including its arguments,
   environment, paths, stdin/stdout, and error handling. Account for those callers
   in the fix and validation rather than checking only the helper in isolation.
3. **Make the smallest coherent change.** Cover the affected paths together.
   Avoid unrelated refactoring, new abstractions, policy gates, or evidence
   machinery. Preserve unrelated files and work.
4. **Prove the changed behavior.** For a bug fix, add a regression test that
   fails for the original defect and passes with the fix. For a feature, test
   its acceptance criteria and relevant existing behavior. Exercise the actual
   boundary being changed: use real SSH, subprocess, filesystem, menu, timing,
   and cleanup mechanisms where relevant and practical. Do not substitute a
   mock that bypasses the behavior the test is supposed to prove. If a failure
   cannot be reproduced or a boundary cannot be exercised, report that limit.
5. **Validate failure paths and test cleanup.** Exercise relevant refusal,
   interruption, and failure paths as well as success. Test fixtures must clean
   up even when assertions fail. Do not weaken assertions, suppress errors, or
   increase timeouts merely to obtain a pass; justify any such change with
   evidence about the intended behavior.
6. **Review and validate the final change.** Review the final diff specifically
   for regressions and missed callers. Run focused regression tests and the
   applicable integration checks, reusing valid results for unchanged
   components. Repeat checks when changes or failures invalidate their results.
   Do not use a new release candidate as the first test of a changed integration
   boundary.

If validation exposes a problem introduced by the change, correct it within the
same bounded repair phase and rerun the affected checks. If it reveals a separate
problem requiring another investigation, report it and stop rather than silently
expanding the task or starting another repair cycle.

When reporting completion, state what failed before, what passed afterward, what
remains untested, and any unresolved uncertainty. Keep **implemented**,
**regression-tested**, and **live-validated** distinct. Do not claim that a change
is bug-free; state the supporting evidence and its limits.
