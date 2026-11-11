# Project cleanup assessment — 2026-11-11

Baseline: `84af948` on `main`, 878 tracked files. Initial untracked entries were
`.agents/` and `.specify/`; both predate this task. No tracked edits existed.
This is a repository-wide maintenance inventory, navigation cleanup and two pure-output simplifications,
not an exhaustive source audit or a new qualification result.

## Area inventory and disposition

| Area | Observed role / evidence | Disposition |
|---|---|---|
| `src/` (251 files), `build.rs`, `examples/` | Rust implementation and adjacent fixtures; code-map ownership inspected; product formatting passes | Preserve structure; add omitted navigation |
| `tests/` (109 files) | Rust integration tests and reusable fixtures | Preserve structure; add omitted navigation |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/` | Pinned Rust toolchain/dependencies and target configuration | Preserve; no dependency or runtime change justified |
| `tooling/` (19 files) | Separate packaging crate, bootstrap, native build and snapshot tooling | Preserve; add omitted navigation; crate formatting passes |
| `cmd/` (69 files), `internal/` (150 files) | Retained Go product reference and active release/qualification helpers | Preserve; label their distinct roles accurately |
| `go.mod`, `go.sum`, root Go tests | Retained toolchain/dependencies and repository-relative integration contracts | Preserve; instructions explicitly prohibit moving merely to shorten the root listing |
| `.github/` (106 files) | Scripts, adjacent tests and three workflows | Preserve; included in syntax inventory, no workflow or release-policy change |
| `docs/` (124 files), `README.md`, `CONTEXT.md`, `AGENTS.md` | Guidance, domain glossary, scoped decisions and dated reports | Fix docs index map; preserve policy and recorded historical outcomes |
| `specs/` (11 existing files) | Feature 001 review, follow-up repairs and still-open live task | Preserve existing feature; add index and separate cleanup feature |
| `.gitignore`, `.gitattributes` | Scratch, Rust target and Python bytecode exclusions; repository text settings | Preserve; no tracked log, bytecode, OS metadata or backup detected |
| Local `.agents/`, `.specify/` | Existing Spec Kit 1.3.0 skills/templates and unratified constitution | Preserve; use installed workflow without installing or adopting new policy |
| Ignored `.scratch/` | Private evidence, toolchain, copied source and run output | Preserve existing content; create only this pass's `acceptance/cl11/` run |

## Delivered changes

- C001: `docs/README.md` described a Go-only directory layout and search route in
  this mixed checkout. Added Rust source, tests, examples, packaging, and work
  specifications, and qualified the retained Go roles.
- C002: tracked Spec Kit records had no index reachable from the documentation
  entry point. Added `specs/README.md` and the documentation-index route. The index
  describes scoped work records accurately and does not promise a thread transcript.

## Preserved and deferred work

- Missing local Markdown targets in the baseline scan all resolve into historical
  private `.scratch/` paths. Their absence here does not justify deleting evidence
  references or fabricating logs. No maintained non-scratch target was missing.
- There is no demonstrated runtime defect from this maintenance scan. Source inspection
  identified two equivalent pure transformations to simplify (C003/C004 below).
  Dependency upgrades and removal of retained Go code have no demonstrated need.
- `docs/rust-rewrite.md` is long (2,290 lines) but explicitly records successive
  implementation revisions. Splitting it requires anchor/caller and ownership review;
  it is preserved while the qualification thread retains its work.
- The initial active-thread inventory request did not return and was cancelled.
  Agnes subsequently confirmed the qualification thread's latest turn is completed
  and not actively editing. This resolved the source-edit ownership concern.
  Qualification code, feature 001 records, release state and the shared selector
  remain untouched; no direct task messages were sent.
- A scan for repeated 12-line blocks in non-test Rust source identified superficially
  similar transport, redaction, lock, record, admission and observation code.
  These checks retain distinct compatibility/authority contexts. Generalizing them
  is not justified by mechanical duplication and is intentionally deferred.

## Initial navigation verification

Before editing: 878 tracked files inventoried; no tracked generated-looking logs,
bytecode, backups or OS metadata. Baseline maintained local Markdown targets exist.
Both Rust crates pass formatting. All 86 tracked Python files parse; all 14 tracked
shell scripts pass `bash -n`. Syntax/formatting is not behavioral verification.

Final checks passed: all 33 local links across the ten changed/new Markdown files
resolve; no trailing whitespace; `git diff --check` passes. The only modified
previously tracked file is `docs/README.md`; new files are the work index and this
feature. The Git index is unchanged, main remains selected, and the existing
feature selector still names `specs/001-project-review`. All eight cleanup tasks
are complete. Results are also recorded in `.scratch/acceptance/cl11/validation.txt`.
No product behavior was changed in that initial phase, so its product tests were
not rerun. The continuation below supplies source verification. No live operations
or release qualification are claimed by either phase.

## Source continuation

- C003: replaced the handwritten standard Base64 encoder in
  `src/subscription_artifact.rs` with the already pinned engine's direct append.
  This removes custom encoding logic and its intermediate String; exact padded
  bytes, JSON ordering, newline, size checks and input/refusal semantics remain.
  Existing RFC vectors now also check preservation of the `vmess://` prefix.
- C004: replaced `src/server_configuration.rs`'s duplicate SHA-256 formatter with
  `records::sha256_hex` at configuration and tunnel-resource callers. The existing
  helper computes exactly the same lowercase digest. No public API changes.

The two source files remove 21 net lines. No dependency, lockfile, fixture,
credential-generation, parsing, redaction, admission, or durable state change.

Baseline and refactored focused checks both pass: one RFC-vector test, ten
server-configuration tests and eight subscription-artifact tests. These include
Go-generated exact output/refusal vectors, tunnel-unit/resource fixtures and an
independent configuration digest comparison. A deliberate temporary unpadded-engine
mutation failed both the Go-vector and exact-subscription integration tests;
the exact intended source was restored before final validation. This is a refactor,
not a claim that the original encoder was defective.

Final source checks pass in one clean full invocation: 690 product tests including
five compile-fail doctests, zero failures, two existing ignored entries; downstream
packaging has 12 passing tests and zero failures. Strict product all-target Clippy
with `-D warnings`, formatting, final link checks and diff whitespace checks pass.
The ignored entries are `blocked_output_child` (invoked by timeout-controlled parent
tests) and `measure_same_image_verification` (manual timing, not acceptance).
These are macOS-host offline checks; native Linux, outside-client/Karing, live
qualification and remote CI were not run. Unchanged Go tests were not rerun.
Logs and the mutation restoration copy are private under `.scratch/acceptance/cl12/`.

Final review covers exact output equivalence, empty inputs/padding, all three
production caller sites, preserved bounds/error paths, shared-helper ownership,
and allocation behavior. No blocking issue found. No new abstraction or dependency.

## Spec Kit provenance

Used installed Specify, Plan, Tasks, read-only Analyze and Implement instructions
and resolved templates.
`setup-plan`, `setup-tasks` and implementation prerequisites ran successfully. The
16-item specification checklist passes. No extension hooks were configured.
The feature selector remains `specs/001-project-review`; per-command overrides
select feature 002 without persisting. Git remained on `main` despite setup-plan's
feature-derived BRANCH field. No new branch, installation or push was made. Commit disposition is recorded in
the source closeout below.

Analyze rechecked eight requirements, six success criteria and 14 tasks with full
coverage and no blocking inconsistency. The specification checklist remains 16/16.
The source continuation extends the same cleanup feature rather than overwriting
the qualification-owned feature or treating initial documentation work as completion.

## Source closeout

Source cleanup is saved locally on main as
`799e23634c73ef3c8207bbdedac3802b2b09dbf8`. All 14 cleanup tasks are complete.
Documentation and Spec Kit records form a separate local commit. No push, live
operation, release mutation, installation or credential change was performed.
The qualification-owned feature and original untracked `.agents/` / `.specify/`
remain unchanged. No current authorization blocker remains for this completed
maintenance scope; optional historical-document splitting and security-boundary
refactors are intentionally not part of these behavior-preserving changes.
