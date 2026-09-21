# SBXR agent map

## Always applicable

- Work in `main` unless the Owner requests another branch.
- Historical reports and retired test procedures describe their named revisions;
  they do not add requirements to the current MVP.
- Local `.scratch/` contains run artifacts and copied source, not the source of
  truth for a code change.

## Task-specific guides

Read and follow the guides whose triggers match the task before doing that work.
They are required project instructions, not optional background. Do not read
every guide by default.

| Title | File path | When to read |
|---|---|---|
| Code map | [docs/agents/code-map.md](docs/agents/code-map.md) | First, before any code change, to find entry points, owning modules, and focused checks. |
| Implementation and regression prevention | [docs/agents/implementation.md](docs/agents/implementation.md) | Before implementation changes, including features, fixes, refactors, and build/test tooling; follow through validation and completion reporting. |
| Test files and local artifacts | [docs/agents/files-and-artifacts.md](docs/agents/files-and-artifacts.md) | Before creating or moving tests, fixtures, logs, captures, downloads, handoffs, reports, or backups, or running validation that uses temporary files. |
| Issue tracker: GitHub | [docs/agents/issue-tracker.md](docs/agents/issue-tracker.md) | Before reading, creating, updating, or closing issues or PRDs. |
| Triage labels | [docs/agents/triage-labels.md](docs/agents/triage-labels.md) | Before triaging issues or changing labels; use the default five-label vocabulary. |
| Domain documentation | [docs/agents/domain.md](docs/agents/domain.md) | Before changing module behavior, describing domain decisions, or editing domain documentation; this repository uses a single-context layout. |
| Current MVP live acceptance | [docs/acceptance/mvp-live-acceptance.md](docs/acceptance/mvp-live-acceptance.md) | Before planning, running, or assessing current MVP live qualification. |
