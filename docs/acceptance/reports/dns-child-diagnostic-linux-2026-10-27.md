# DNS child diagnostic: isolated Linux preparation, 2026-10-27

Status: local build/static inspection and inert tests only. No fixture, observer,
product, tracing, signal fixture, VPS or SSH execution occurred in this task.
The historical DNS delay remains unexplained. These results grant no release,
deployment or runtime authority.

## Source and evidence

The supplied eleven-file diagnostic patch was applied in an isolated checkout at
`e7cb40d59ac9f8975852f807f7b887599744b969`. Preparation used a deliberately uncommitted source tree; those recorded artifacts
must not be stamped as the unchanged base revision.

| Input | SHA-256 |
|---|---|
| `observer.patch`, 50,737 bytes | `8f042ed266be751a74f15f8034d19ab9be457806303a7e4930c4e4c43b52a502` |
| `LINUX-OFFLINE-HANDOFF.md`, 5,165 bytes | `32e9376c45c4a41e8ffd733741bf630a434f31ec323bae9a86e0a0a7e2d3219f` |

Both original Library files retain their identities. No additional Library upload
is requested or performed. Reports belong here as Markdown; code/tests belong in
source paths. Raw evidence, binaries, tool downloads and local archives stay in
ignored `.scratch/acceptance/` and are not commit inputs.

Local evidence directories in this validation checkout:

- [Library/build/test evidence](../../../.scratch/acceptance/validation/).
- [Original fixture and provenance evidence](../../../.scratch/acceptance/fixture/).
- [Frozen supervisor review input](../../../.scratch/acceptance/supervisor-review/).

These private links may not exist in another checkout. The original frozen review
archive remains unchanged, SHA-256
`52b4459244d0074f092f857dbab8bb761885792ace03a5d9493fe7572cd64221`.
It is historical review input, not the source of truth after review corrections.

## Completed validation

The builder is Debian 13 x86-64. Rust/Cargo 1.90.0, CMake 4.4.4 and locked Cargo
dependencies were prepared in workspace-local directories before offline checks.
GCC is 14.2 and GNU binutils 2.44. Python tests used Python 3.12.14.

| Check | Result |
|---|---|
| Patch applicability and byte identity | Passed |
| Observer/checker Python tests | 14 passed |
| Query diagnostic relay Python tests | 3 passed |
| Rust `dns_observer` tests | 2 passed |
| Rust `query_diagnostic_` tests | 9 passed |
| `cargo build --locked --offline --release --lib` | Passed, identity variables unset |
| Unstamped `--release --bin sbxr` build | Passed; executable never run |
| Original supervisor inert suite | 16 passed; runtime interfaces guarded against calls |

The optimized library retained one hook definition and seven call/tail-call
relocations with event/query/child in RDI/RSI/RDX. Library SHA-256:
`38a86bc97a4212824986111a995df357ea5962b6aa5af5baf939fd4d86bf96f8`.

The ordinary unstamped GNU executable did **not** retain the hook. Its SHA-256 is
`63b3c3bed76d73d23e1c68f93f97a361efa812a9e2b6958e67201bc57f90a0c0`.
Library evidence therefore does not transfer to the linked product. No admission
or metadata was changed to force hook retention.

The separate harmless fixture imports the actual reviewed hook source. Its
original optimized executable retained one definition and five direct calls,
including error/unwind paths, with the same three-register ABI. Original fixture
SHA-256: `cd633e5ef9e12185ce3678ed8aafee1ee2feafadd9f8426e0f00a8e1433a8600`.
It requires x86-64 GNU/Linux and GLIBC symbols through 2.39; target compatibility
and all runtime behavior remain unverified. Relocated/rebuilt fixture bytes must
be independently pinned; do not reuse this digest for a new build.

## Repository source and review

- [Supervisor](../../../.github/scripts/dns-child-fixture-supervisor.py).
- [Inert supervisor tests](../../../.github/scripts/test_dns_child_fixture_supervisor.py).
- [Fixture source](../../../.github/scripts/testdata/dns-child-fixture/main.rs).
- [Review/run instructions](../../../.github/scripts/dns-child-fixture-review.md).
- [Data-only AppImage inspector](../../../.github/scripts/inspect-bpftrace-appimage.py).
- [Tracer provenance and no-mount build assessment](../../research/bpftrace-0.23-no-mount.md).

A fresh internal read-only reviewer used GPT-6 Astra, medium reasoning, and
reviewed the frozen source plus targeted corrections. The reviewer made no edits
and executed no tests or runtime operations. Initial and follow-up findings were:

| Finding | Repair and evidence |
|---|---|
| High: discovery errors skipped known-child cleanup | Signaling of established pidfds is independent of discovery; mocked spawn-failure and running-failure regressions pass. |
| High: path hashes did not bind subsequent execution | Retained supervisor-anchored descriptors on verified read-only local superblocks; final file and directory checked; existing bytecode caches refused; isolated Python flags. This adds an explicit immutable-backing-storage prerequisite. |
| Medium: gate writes could occur after deadline | Fresh monotonic checks before every gate write and fault injection; late-readiness event-loop regression passes. |
| Medium: stale receipt timestamps shortened the hold | Timestamps sampled when each receipt is processed. |
| Medium: helper tests missed orchestration failures | Added fully mocked event-loop regressions without real processes or signals. |
| High follow-up: zombie prefixes starved oversized inventories | Poll/reap before discovery and after signaling; a 40-child inert model advances through both batches. |
| Medium follow-up: first signal error starved later handles | Attempt every known pidfd before aggregating errors; two-handle refusal regression passes. |

The final static review found no remaining concrete blocker from those findings,
under the documented trusted-platform and immutable-storage assumptions. The
updated repository-source suite passed **24 inert tests**. Actual Linux adapters,
watchdog timing and process/kernel teardown remain unverified; this is not a
runtime pass. Tests/logs are in [project-review](../../../.scratch/acceptance/project-review/).

The relocated fixture now self-spawns through literal `/proc/self/exe` instead of
resolving a mutable pathname. It was rebuilt and statically inspected, never run.
Its five hook calls still use RDI/RSI/RDX. New executable SHA-256:
`4970f019bf6919d5dd7c74dba386c86df2cb4588b254bac674daf1265527f7bf`.
Source SHA-256: `80811a959bffe20db2fcd92dece42a38cdfea7c7f0ff38cf4acec51c2265bee0`.
The old fixture, old manifests and frozen archive were preserved unchanged.

## Boundaries and remaining work

The local executor lacks bpftrace, accessible tracepoint metadata and effective
capabilities; it has `NoNewPrivs=1` and seccomp filtering. No kernel capability or
attachment experiments were attempted. Separately reported server preflight facts
are not evidence of successful attachment and were not independently exercised here.

The official tracer AppImage was inspected as data. The inner binary has the
reviewed notification ordering, but its launcher mounts and chroots and its inner
ELF uses absolute Nix dependencies. A conventional no-mount build lacks mandatory
development dependencies here; see the linked build assessment. Missing optional
signatures are not being treated as a new mandatory attestation gate.

Before any runtime session: resolve the exact compatible no-mount tracer launch
artifact, approved immutable input storage and manifest, and obtain explicit
approval for fixture/observer execution, attachment and owned-process cleanup.
Start with one immediate-child session, not the full multi-case plan. Kernel
resource cleanup needs independent before/after evidence on every run.


## Final repository checks before commit

Checks were repeated on the final repository source before the diagnostic
preparation commit. The original patch checks remain distinct from supervisor
repair coverage:

- Original observer/checker Python suite: 14 passed; query relay: 3 passed.
- Supervisor repairs: 24 inert tests passed, including mocked event-loop and
  bounded descendant-discovery/reaping regressions; no real signal/process fixture.
- Packaging-tool Python suite: 4 passed using disposable local Git fixtures.
- Rust formatting and all-target Clippy compilation/lint passed. The filtered
  Rust suites passed 2 observer and 9 query-diagnostic tests. The ordinary release
  library build passed. [Final local logs](../../../.scratch/acceptance/final-main/)
  retain the separate outcomes.

Full Rust/Go execution suites were not run locally because they include excluded
process/signal fixtures. Compiling test targets is not executing them. No native
musl packaging, product execution, observer attachment or release workflow dispatch
was performed here. The existing ordinary Verify CI workflow is observed separately
for the exact committed revision; local filtered passes are not a full CI pass.

The source README and observer documentation now link this report/runbook; the
upstream notification citation is pinned to the inspected source revision. Raw
historical evidence and archives remain ignored and unchanged.
