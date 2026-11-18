# Code map

| If you are tracing… | Start here | Follow the handoff |
|---|---|---|
| <a id="isolated-rust-rewrite"></a>Installed candidate, menu status, setup, HTTP, identity rotation, restart or removal | [Rust product and the five Owner journeys](rust-product.md) | [Native Owner selection](../../src/host/owner.rs) → [composed Owner](../../src/proxyinstallation/owner.rs) → [terminal](../../src/terminal.rs) |
| <a id="release-tooling-and-qualification-harness"></a>Build inputs, private delivery, qualification, cleanup, publication or retry | [Release stages and focused checks](release-tooling.md) | [Rust package builder](../../tooling/rust-package/README.md) → [Go decisions](../../cmd/sbxr-release/README.md) → [workflow and operator helpers](../../.github/scripts/README.md) |
| <a id="product-execution"></a>Go behavior in an older release, parity vectors or a Go release-tool dependency | [Retained Go product map](go-reference.md) | [Go Proxy Installation](../../internal/proxyinstallation/README.md) and [Software Lifecycle](../../internal/softwarelifecycle/README.md) |
| What was specified, implemented, observed or released | [Documentation and evidence index](../README.md) | [Specifications](../../specs/README.md), [Rust acceptance matrix](../rust-acceptance.md), [dated reports](../acceptance/reports/README.md) |

The product glossary is [CONTEXT.md](../../CONTEXT.md). The [ADR index](../adr/README.md) identifies the applicable decision and its scope.

## Choosing validation

For a Rust change, use the focused tests in the [journey map](rust-product.md) and the
[packaging and native checks](../../tooling/rust-package/linux-validation.md) for the boundary being changed.
For Go, release and operator changes, use the focused checks in the [Go](go-reference.md) or [release](release-tooling.md) map.

Use the Go toolchain declared in [go.mod](../../go.mod). From the repository root,
choose a short local run name (replace `r1` as needed):

```sh
(
  set -eu
  umask 022
  name=r1
  run="$PWD/.scratch/acceptance/$name"
  mkdir -p "$run"
  fixtures="$run/t"
  mkdir "$fixtures" # Refuse to reuse an existing temporary directory.
  export TMPDIR="$fixtures"
  if [ "$(uname -s)" = Darwin ]; then
    short="$PWD/.scratch/$name"
    [ ! -e "$short" ] && [ ! -L "$short" ] || exit 1
    ln -s "$fixtures" "$short"
    export TMPDIR="$short"
  fi
  finish() {
    if [ "$TMPDIR" != "$fixtures" ]; then unlink "$TMPDIR"; fi
    rmdir "$fixtures" || exit 1
  }
  trap finish EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  GOTOOLCHAIN=go1.26.6 go test -timeout 30m ./...
  GOTOOLCHAIN=go1.26.6 go vet ./...
)
```

The subshell keeps these settings local and removes its newly created temporary
directory after the tools clean their fixtures. If a failure or interruption
leaves files behind, cleanup fails rather than deleting them; inspect and clean
only that run's disposable fixtures. Retain logs and useful evidence outside `t/`.

Host-adapter fixtures expect newly created files to have the current user's group.
Use a workspace-local directory owned by that user and group, not macOS
`/private/tmp`, which can give fixtures the `wheel` group.

On macOS, runtime-start tests append a 40-byte socket filename to `TMPDIR`.
The full pathname must fit in 103 bytes. The short alias above keeps the actual
fixtures in the run directory. For a longer checkout path, choose a shorter
alias whose full socket pathname fits. The 30-minute Go timeout applies to each
test package as a whole. The release-tool package runs many installer and
qualification fixtures in sequence.

The tables identify narrower package tests during development. Root Go tests
cover architecture, dependencies, script integration, and workflow contracts;
they are intentionally rooted here because they read repository-relative files.

For current MVP qualification changes, start with the focused Go/Python tests
and [HTTP procedure](../acceptance/http-subscription-live.md). Do not run the retired
V4 rehearsal or `check-readiness.py` for an MVP candidate. Historical V4 records remain readable; retired producer source is available in Git history.
Local fixtures and tests do not establish live qualification or Karing acceptance.

## Documentation and historical material

- [docs README](../README.md): documentation entry point and current/historical routing.
- [README.md](../../README.md): product overview and navigation.
- [CONTEXT.md](../../CONTEXT.md): the single domain glossary.
- [HTTP acceptance](../acceptance/http-subscription-live.md) and [ADR-0028](../adr/0028-clean-install-only.md): the current five HTTP journeys with no incoming sources. [ADR-0025](../adr/0025-ordinary-recurring-live-acceptance.md) and [ordinary recurring acceptance](https://github.com/albertloky/SBXR/blob/c298af182cdd159a6258c0d17fb37b9b663cf4ee/docs/acceptance/ordinary-recurring-live.md) retain their exact-source update/recovery meaning; [ADR-0023](../adr/0023-mvp-live-acceptance.md) retains the earlier five-journey HTTPS policy.
- [acceptance README](../acceptance/README.md): current procedure and historical acceptance routing.
- [research README](../research/README.md): investigation notes and their authority limits.
- [ADR index](../adr/README.md): decisions grouped by applicable scope and era.
- [Acceptance reports](../acceptance/reports/README.md): dated results, separate
  from current procedures. A report describes its named run, not current host state.

Local scratch and research files may contain unfinished user work. Inspect their
Git status before reorganizing them; use tracked source and current procedures
to determine implemented behavior.

Follow [the test-file and artifact locations guide](files-and-artifacts.md).
Tests live beside their code, run artifacts under `.scratch/acceptance/`, and
readable reports under `docs/acceptance/reports/`. `.scratch/` is excluded from Git and
normal source searches.
