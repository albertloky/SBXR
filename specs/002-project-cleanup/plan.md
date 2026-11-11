# Implementation Plan: Project cleanup

**Branch**: `main` | **Date**: 2026-11-11 | **Spec**: [spec.md](spec.md)

## Summary

Assess the entire tracked tree, then repair confirmed navigation omissions in
`docs/README.md` and add `specs/README.md`. Preserve runtime behavior, release tooling,
qualification records, private artifacts, and the untracked Spec Kit installation.

## Technical Context

Documentation and pure-output simplifications in a mixed Rust 1.90.0 / retained Go project. Existing Python
and Bash support read-only inventory and syntax checks; no new dependency.
Target: maintainers navigating the repository. Scale: 878 tracked files initially.
Validation: local target resolution, specification/task traceability, whitespace,
Rust formatting, focused before/after output tests, full offline Rust tests, strict
all-target Clippy, and syntax-only checks of existing Python and shell scripts.
No new performance target or product behavior; native/live tests are outside this pass.

## Constitution Check

Pre-design and post-design: PASS. Current scope, ownership, module responsibilities,
regression evidence and exact-candidate qualification remain unchanged. Existing
AGENTS/current ADRs remain authoritative; local constitution ratification is pending.
No new policy or authority is introduced. No hooks are configured.

## Project Structure

- `specs/002-project-cleanup/`: specification, plan, research, data model, validation,
  tasks, requirements checklist, and assessment.
- `specs/README.md`: discoverable work index.
- `docs/README.md`: accurate mixed-language directory map and work-record route.
- `.scratch/acceptance/cl11/`: initial navigation validation.
- `.scratch/acceptance/cl12/`: source before/after tests, mutation evidence and offline checks.

## Implementation strategy

1. Inventory all tracked areas and inspect existing navigation, ignore rules,
   current instructions, and prior Spec Kit review ownership.
2. Record preservation decisions and confirmed navigation omissions.
3. Update navigation and this feature; validate links, scope and whitespace.
4. Replace the handwritten standard Base64 encoder in `src/subscription_artifact.rs`
   with existing base64 0.22.1 STANDARD.encode_string, appending directly to the
   artifact buffer. Preserve all canonical URL/key validation and size bounds.
5. Replace local `digest` in `src/server_configuration.rs` with the established
   `records::sha256_hex` helper at its two callers; leave digest validation intact.
6. Run independent before/after tests, then broad offline tests and strict Clippy.
7. Report deferred operational or structural work without claiming live validation.

The existing `.specify/feature.json` points to the qualification-owned feature.
Use `SPECIFY_FEATURE_DIRECTORY=specs/002-project-cleanup` with
`SPECIFY_FEATURE_NO_PERSIST=1` for all Spec Kit scripts. This is an intentional
concurrency-preservation adaptation of Specify's normal selector persistence.
Setup script JSON reports a feature-derived BRANCH; `git branch --show-current`
is the source of truth and remains `main`.

## Source-change scope and callers

The Base64 helper has one production caller (`ConnectionFacts::subscription_artifact`)
and one existing RFC-vector test. Use the dependency directly at both sites, retaining
the vector assertions and Go-generated integration fixtures. The digest helper has
two callers: `ServerConfiguration::sha256_hex` and `TunnelBinding::resources`; both
produce existing representations. Shared records helper already computes the same
`format!("{:x}", Sha256::digest(bytes))`. No API, durable format, host effect, authority,
redaction, token parser, dependency or error path changes. Existing independent
server-configuration fixtures and digest assertions cover the public output boundary.

No security-boundary deduplication is included. Repeated admission, descriptor,
transport and recovery checks stay local because their authority/context differs.
