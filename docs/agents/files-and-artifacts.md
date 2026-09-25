# Test files and local artifacts

Keep SBXR-owned files inside this repository's workspace, not in `~/.codex`.

| Files | Location |
|---|---|
| Test source and reusable fixtures | Beside the code they exercise; script tests beside their scripts in `.github/scripts/`, Go tests beside their package, fixtures in adjacent `testdata/` |
| Repository-wide integration tests | Repository root, where their cross-module and repository-relative callers live |
| Local test-run outputs, logs, captures, downloads and handoffs | `.scratch/acceptance/<run>/` |
| Readable acceptance reports | `docs/acceptance/reports/`, indexed in its README, with links to the local run directory when needed |
| Current and fixed-path acceptance procedures | `docs/acceptance/`; check workflow and test callers before moving them |
| Historical procedures, research and plans | `docs/acceptance/historical/`, `docs/research/`, and `docs/history/plans/`; keep their named scope explicit |
| Project backups and Git bundles | `.scratch/archives/` |
| Unadopted local drafts retained during cleanup | `.scratch/archives/<cleanup>/local-drafts/`; preserve originals, do not promote them to policy |

For local SBXR validation, set `TMPDIR` to a temporary subdirectory of the
local run directory; use the [validation recipe](code-map.md#choosing-validation).
Remove disposable fixtures when the run finishes; retain useful observations and
handoffs there. `.scratch/` stays ignored by Git. Keep
credentials and raw private evidence out of committed reports. Update callers
and navigation links whenever test or artifact paths move.
