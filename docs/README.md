# SBXR documentation

## Choose the task, then the source

| Need | Start here | What it establishes |
|---|---|---|
| Use SBXR | [Product README](../README.md) | Supported host, installation and menu journey |
| Set up optional VMess Tunnel | [VMess setup guide](setup-vmess-tunnel.md) | Your own domain/tunnel, protected token, dedicated connector and honest connection checks |
| Trace a Rust candidate journey | [Rust product map](agents/rust-product.md), [acceptance matrix](rust-acceptance.md), [revision handoff](rust-rewrite.md) | Current source in this checkout, boundaries, tests and dated evidence |
| Compare the Go product or trace a Go dependency | [Retained Go map](agents/go-reference.md) | Historical product behavior and packages still used by release tooling |
| Change implementation | [Agent code map](agents/code-map.md) | Entry points, owning modules and focused checks |
| Find specified project work | [Work specifications](../specs/README.md) | Scope, plans, task progress and recorded checks; not conversation transcripts |
| Understand domain language | [CONTEXT.md](../CONTEXT.md) | One shared glossary, not a second specification |
| Find an architectural or policy decision | [ADR index](adr/README.md) | Decisions grouped by scope and product era |
| Diagnose native disclosure without qualifying | [Disclosure diagnostic](acceptance/disclosure-diagnostic.md) | Signed diagnostic-only scope, preserved client/evidence and bounded restoration |
| Plan current live qualification | [Acceptance guide](acceptance/README.md) | Current MVP procedure and bounded prerequisites |
| Inspect a release or repair result | [Report index](acceptance/reports/README.md) | Dated observations, not present host readiness |
| Build/validate Rust release inputs locally | [Rust packaging/CI tooling](../tooling/rust-package/README.md), [prepared Linux commands](../tooling/rust-package/linux-validation.md) | Native musl inputs, strict artifact/bootstrap verification and source-only snapshot; no dispatch/publication |
| Trace a release, failure, or retry | [Release tooling map](agents/release-tooling.md) | Rust assets, Go decisions, operator observations and publication |
| Investigate upstream behavior | [Research index](research/README.md) | Current dependency compatibility, not adopted policy |

## Reading release evidence

| Question | Local evidence |
|---|---|
| What does this checkout implement? | [Rust product map](agents/rust-product.md) and [acceptance matrix](rust-acceptance.md). The public bootstrap selects the published Latest. |
| What did a particular live run establish? | [Dated reports](acceptance/reports/README.md). For later signed drafts, consult the [reservation decisions](adr/0032-qualified-publication-retry.md) for the outcome and cleanup actually recorded. |
| Was a particular historical version public? | The [v3.1.81 / 159 publication report](acceptance/reports/v3.1.81-stable-publication-2026-09-25.md) records its [bounded exception](adr/0024-r24-late-confirmation-supplement.md). The [public v3.1.118 / 192 fixture](../tests/testdata/public_release/README.md) preserves newer release metadata and signatures captured in October. Verify current remote state when a release operation requires it. |

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
src/                           Rust product, native host adapters and adjacent unit tests
tests/                         Rust integration tests and reusable fixtures
examples/                      Rust evidence/acquisition example
tooling/rust-package/           separate Rust package/bootstrap crate and local checks
cmd/sbxr/                       retained Go product startup and private-role dispatch
cmd/sbxr-release/               active Go qualification decisions, gateway and retained packaging
internal/proxyinstallation/    Go proxy reference, private serving module and adapters
internal/softwarelifecycle/    Go installed-software and lifecycle reference
.github/scripts/               release/operator helpers and adjacent tests
.github/workflows/             native verification, candidate, stable publication
docs/agents/                   task-triggered working instructions
docs/adr/                      scoped decisions (see its index first)
docs/acceptance/                current and fixed-path procedures/decisions
docs/acceptance/reports/        dated release, repair and investigation reports
specs/                         tracked work specifications, plans, tasks and assessments
.specify/, .agents/skills/      checkout-local Spec Kit configuration and retained skills, when present
.cargo/, target/               native build configuration and ignored compiler output
.scratch/                      ignored private evidence, drafts and backups
```

Go tests stay beside their code. Repository-root Go tests intentionally exercise
cross-module, script and workflow contracts; do not move them just to shorten
the root listing. See [artifact locations](agents/files-and-artifacts.md).

For low-noise implementation searches, begin in `src/` and `tests/` for Rust,
`tooling/rust-package/` for Rust packaging, or `cmd/`, `internal/`, and `.github/`
for retained Go/reference and release tooling, using the code map. Use `git grep`
for committed material, or ordinary `rg` for the working tree; avoid unrestricted searches through `.scratch/`.
Search reports and historical material explicitly when that is the task.

The current V3 checklist remains at the acceptance root because release
workflows bind its path and bytes. Stable replay reads a historical checklist
from the exact candidate Git revision. Retired procedures and plans remain in Git
history. A file's location or an old `accepted` header
does not broaden its scope. Follow current task guidance and the applicable
ADR; a historical report cannot add requirements or certify current state.
