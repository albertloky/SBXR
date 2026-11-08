# Build 214 cancellation and retained reservation — 2026-11-08

The Owner approved cancelling only run 42370644704 and preserving its exact
unqualified draft through the existing fixed reservation policy. Cancellation
has completed; the exact reservation is implemented and focused checks/fresh
observation replay passed. Broader verification and CI remain pending. Build 214 cannot be reused or promoted. No new live attempt or
publication is included.

## Terminal outcome and signing evidence

[Run 42370644704](https://github.com/albertloky/SBXR/actions/runs/42370644704),
attempt 1, used source `3c3735dcd3ebca409ccdaba277a0d50deb0b9432`. The ordinary
cancellation request was accepted at 2026-11-08 03:58:06 UTC without retry.
Subsequent GitHub verification found the run completed/cancelled. Sign job
128408019970 was cancelled with no recorded steps. Cleanup-unqualified job
128621544278 failed with no recorded steps; the cause is unproved. Do not label
that empty result an intentional finalizer stop or proof that a proposal ran.

No signed qualification manifest or formal completed-job unsigned proof is
established. The reservation therefore uses `signing_state: unknown` and omits
`qualification_manifest_sha256`. Waiting at the signing gate, lack of approval
and cancellation are not substitutes for the finalizer's unsigned-proof rules.
No signing or finalizer retry is performed to obtain a cleaner status. The live
qualification did not start; builds, packaging and draft creation are not a pass.

## Exact preserved identity

Candidate v3.1.140/214 is draft 437573394, with body `Qualification pending.`,
prerelease false and immutable false at the recorded check. Its index SHA-256 is
`acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69`.
The [retention contract](../../../specs/001-project-review/contracts/retained-candidate.md#build-214-retention--2026-11-08)
records the four exact asset IDs, sizes and hashes.

The four assets were downloaded and hash/size verified on 7 November at
16:02:18–21 UTC without execution. Preserved bytes were reverified before the
cancellation at 03:58:05 UTC on 8 November; the exact draft/source/body/flags
matched and both release/burn refs were explicitly absent then. These are
point-in-time observations, not a remote lock or complete post-cancellation
inventory replay. Preserve all local workflow-artifact copies and original
evidence; artifact expiry does not extend any qualification deadline.

Evidence is retained under .scratch/acceptance/q214-disposition-20261107/
(asset-preservation.json and the original proposal) and .scratch/acceptance/q214res/
(pre-cancel.json, cancel-result.json and terminal-status.json, observed at
03:58:33 UTC). The original
proposal remains a dated pre-approval/pre-cancellation record.

## Bounded policy change and verification checkpoint

The approved implementation appends only q214 to the eleven existing records,
requiring twelve exact drafts and twenty-four absent refs. Preserve unknown
signing for q203 and q214, all earlier signed-unqualified pins and historical
replay. Current-candidate fixtures may use prospective v3.1.141/215, subject to
independent global admission; cancellation does not release sequence 214.
No product schema, workflow permission, gate or authentication change is needed.

The two new q214 regressions failed against the eleven-record policy at
04:00:49 UTC: the exact twelfth record was missing and fresh-candidate preflight
refused. The expected failure is retained in q214res/red.log and red-result.json.
The focused `Reservation|ReservedDraft` suite passed 487 test/subtest results
without skips (q214res/focused-result.json). Fresh GET-only replay at 04:03:46 UTC
accepted all twelve exact drafts and twenty-four explicitly absent refs. The
previous eleven canonical records and q214 draft were unchanged; zero approvals
and seven artifacts were observed, with no signed manifest. Fresh asset metadata
matched preserved copies independently hashed before cancellation; assets were
not redownloaded by this replay. See q214res/current-observations/result.json.

Independent code review found no blocker. The full release-tool suite passed
1,529 test/subtest results in 455.123s with one existing macOS controlling-terminal
skip; root integration passed 289 with three existing Linux/real-SSH skips.
`go vet ./...`, formatting, Markdown links and whitespace checks passed. Receipts
are q214res/{release-full,root-integration,vet}-result.json. Go 1.26.6, umask 022
and scoped temporary files were used without increasing its default timeout.
No local race or unchanged Rust rerun is claimed; native CI covers those checks.
T057–T061 are complete; T062 awaits exact-source push/CI.
The read-only installed Analyze/Converge assessment found no new implementation
or authority gap; existing full-validation and live gaps remain explicitly open.
The earlier T056 completion is unchanged. T018's exact-candidate 90-second
details/five-journey live criterion remains unproved.

No draft/body/asset/tag mutation, burn, deletion, new signing, live/VPS/client/
security change, cleanup execution or publication belongs to this retention.
The cancelled run and failed cleanup-unqualified result keep their original
conclusions. This records neither host/client readiness nor cleanup completion.
