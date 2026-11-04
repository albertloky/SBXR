# Build 211 retained reservation — 2026-11-04

Build 211 / v3.1.137 remains signed-unqualified. The Owner-authorized continuation resolves its candidate-disposition gap by retaining the exact draft through the existing reservation mechanism. It does not retry qualification, finalize a burn, delete a draft or publish a release.

## Evidence and diagnosis

[Run 41312490744](https://github.com/albertloky/SBXR/actions/runs/41312490744) signed source `a0abe154f4380b2c2f5d28a979c9417d4059e90d` but failed acceptance. Its `cleanup-unqualified` job deliberately exited 1 at “Stop for an explicit candidate failure decision” and successfully uploaded retained finalization evidence. That is an intentional disposition boundary, not proof of a broken deletion/cleanup mechanism. Its failed status remains unchanged. The independently recorded supported VPS removal is historical evidence with its stated preservation limits, not current host readiness.

Read-only inspection matched draft 430636507, its source, draft flags, pending body, all four asset identities and independently downloaded sizes/SHA-256 hashes. Both release and burn refs were explicitly absent. The retained genuine manifest attestation was reverified for the exact repository, candidate workflow, main ref, source digest and hosted-runner requirement. Manifest SHA-256 is `81107d0cbeed9c0b3f2c759938065d08259966411acb68c1f1d01e282280989e`; release-index SHA-256 is `5bf9794eef667e8459eda7e24c6d0e4d9aed687bed7cae8e6297273c46185d68`.

Evidence is local in the original Go workspace at `.scratch/acceptance/q211-reservation/`; source tests are in the Rust checkout at `.scratch/acceptance/q211res/`. The existing GET-only inventory helper was imported with the exact build 211 identity; no candidate workflow dispatch or new inventory workflow was needed. Reads are not an atomic snapshot. Asset contents were never executed.

## Change and validation

The ninth reservation binds the draft, tag, sequence, source, signing state, manifest and four assets. The shell collector still requires the exact fixed policy; fresh candidate fixtures advance to build 212. Regressions cover missing/changed authority, publication flags, asset mutation, unknown/present refs, omitted or relabeled reservation, and independent tag/sequence/release-ID reuse. Historical replay and successful fresh qualification/publication decision fixtures remain part of the existing suite; fixtures do not perform publication.

The new exact-reservation regression failed before the policy change. The focused reservation suite passed (36.949s), followed by the complete release-tool package (452.299s), repository-root integration tests and all other Go packages. The initial broad run failed unchanged host-adapter socket tests because the Rust checkout temporary path exceeded macOS limits; that package passed with the documented shorter repository-local path. `go vet ./...` and whitespace checks passed. The fresh full GitHub observation set matched all nine reservations and all 18 absent refs. The first local observation serialization was correctly refused for noncanonical Unicode escaping; UTF-8 canonical replay of the same observations passed without weakening the validator. Logs retain both refusals and successful results. No product Rust behavior, deadline, signature rule, VPS operation or workflow activation policy changed.

## Remaining prerequisites

This resolves retention of build 211 rather than falsely completing its failed run. Next candidate identity/source must be freshly selected from current full history, reservation and ref observations, and final-source CI must pass. Live approval must separately bind the named VPS, profile, actual host/client readiness, explicit system trust/routing/firewall and disposable-secret effects, attendance/security cutoffs and scoped cleanup. Build 211 earns no journey credit. The details timeout and live benefit of the immutable-image optimizations remain unproved. Stable publication still requires separate approval after successful exact-candidate qualification and cleanup.
