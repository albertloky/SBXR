# SBXR documentation

## Choose the task, then the source

| Need | Start here | What it establishes |
|---|---|---|
| Use SBXR | [Product README](../README.md) | Supported host, installation and menu journey |
| Set up optional VMess Tunnel | [VMess setup guide](setup-vmess-tunnel.md) | Your own domain/tunnel, protected token, dedicated connector and honest connection checks |
| Continue isolated Rust rewrite | [Rust increment and handoff](rust-rewrite.md), [current acceptance matrix](rust-acceptance.md) | Implemented slices, intentional exclusions and separate qualification |
| Change implementation | [Agent code map](agents/code-map.md) | Entry points, owning modules and focused checks |
| Understand domain language | [CONTEXT.md](../CONTEXT.md) | One shared glossary, not a second specification |
| Find an architectural or policy decision | [ADR index](adr/README.md) | Decisions grouped by scope and product era |
| Plan current live qualification | [Acceptance guide](acceptance/README.md) | Current MVP procedure and bounded prerequisites |
| Inspect a release or repair result | [Report index](acceptance/reports/README.md) | Dated observations, not present host readiness |
| Operate release tooling | [Release stage map](../cmd/sbxr-release/README.md), [script map](../.github/scripts/README.md) | Qualification code and workflow/helper ownership |
| Investigate upstream behavior | [Research index](research/README.md) | Current dependency compatibility, not adopted policy |

The latest publication recorded here is
[v3.1.81 / 159 on 2026-09-25](acceptance/reports/v3.1.81-stable-publication-2026-09-25.md).
Its [bounded Owner exception](adr/0024-r24-late-confirmation-supplement.md)
reuses prior live evidence; it is not a fresh live pass or a general waiver.
Refresh remote release state before a future release operation.

Current releases are [clean installation only](adr/0028-clean-install-only.md),
with no incoming sources and the five [HTTP live journeys](acceptance/http-subscription-live.md).
Historical HTTPS and recurring policies retain their meanings; they do not add
source update/recovery journeys to the current scope. Local implementation and
regressions do not assert a packaged live pass.

[Qualified publication and retry](adr/0032-qualified-publication-retry.md) makes
successful exact-candidate tests and cleanup prerequisites for stable publication.
Successful qualification and cleanup make the exact candidate eligible for publication.
The Owner must approve publication before explicit `stable.yml` dispatch with the
successful `qualification_run_id`. Publication revalidates authentication and unchanged
bytes, pauses for exact main-divergence review when needed, and preserves failures
for transparent retry.

## Repository layout

```text
cmd/sbxr/                       executable startup and private-role dispatch
cmd/sbxr-release/               repository-only packaging and qualification
internal/proxyinstallation/    proxy journey, private serving module, adapters
internal/softwarelifecycle/    installed software and release/update lifecycle
.github/scripts/               release/operator helpers and adjacent tests
.github/workflows/             native verification, candidate, stable publication
docs/agents/                   task-triggered working instructions
docs/adr/                      scoped decisions (see its index first)
docs/acceptance/                current and fixed-path procedures/decisions
docs/acceptance/reports/        dated release, repair and investigation reports
.scratch/                      ignored private evidence, drafts and backups
```

Go tests stay beside their code. Repository-root Go tests intentionally exercise
cross-module, script and workflow contracts; do not move them just to shorten
the root listing. See [artifact locations](agents/files-and-artifacts.md).

For low-noise implementation searches, begin in `cmd/`, `internal/`, or
`.github/` using the code map. Use `git grep` for committed material, or ordinary
`rg` for the working tree; avoid unrestricted searches through `.scratch/`.
Search reports and historical material explicitly when that is the task.

The current V3 checklist remains at the acceptance root because release
workflows bind its path and bytes. Stable replay reads a historical checklist
from the exact candidate Git revision. Retired procedures and plans remain in Git
history. A file's location or an old `accepted` header
does not broaden its scope. Follow current task guidance and the applicable
ADR; a historical report cannot add requirements or certify current state.
