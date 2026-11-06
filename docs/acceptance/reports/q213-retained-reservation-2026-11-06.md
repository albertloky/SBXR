# Build 213 retained reservation — 2026-11-06

The Owner approved preserving failed v3.1.139/213 as signed-unqualified through
SBXR's existing fixed reservation mechanism. The draft, four assets, signature,
failed outcome and previous ten reservations remain preserved. No live attempt
or remote release mutation is part of this change.

## Exact identity and read-only verification

[Run 42023983739](https://github.com/albertloky/SBXR/actions/runs/42023983739),
attempt 1, signed source `f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3`,
draft 435196915. The signed manifest has 6530 bytes and SHA-256
`e0ce70ea6c28537a3f8e33b1f29a6af75f0037ff87b572eb5e0cd201ffa3bc4c`;
release-index SHA-256 is
`be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf`.
The exact four asset IDs, sizes and hashes are independently pinned in
[the reservation](../../../cmd/sbxr-release/candidate_reservations.go).

After approval, fresh canonical GET observations completed at 10:59:21 UTC:
all eleven q203–q213 drafts matched their exact source records, body, flags and
asset identities; all twenty-two release/burn refs were explicitly absent.
A fresh download/hash and cryptographic signature check completed at 11:00:23 UTC.
All four q213 assets matched the original IDs, sizes and signed hashes. The genuine
attestation verified the exact repository, candidate workflow, main ref, source/
signer commit and GitHub-hosted run/attempt; its bundle matched the original.
No downloaded installer or executable was run.

The earlier preservation review also downloaded the signed-manifest artifact:
all five extracted files were byte-identical to the originals. Its signed
candidate-failure-state is the pre-live Pending state, not the later failure;
original M1 failure evidence and later administrative cleanup remain separate.
Current draft body `Qualification pending.` matches the original construction
instruction. Original release observations omit body, so unchanged since creation
is not independently proved. Current before/after observations match. GitHub
artifact expiry is 2027-02-03T12:03:54Z; local original evidence remains retained.
These reads are not atomic; future supported operations recheck live bindings.

The [failed live and cleanup report](q213-interrupted-details-cleanup-2026-11-06.md)
retains its dated meaning. Installation/setup completed, details capture was
interrupted, later journeys were not completed, and separately approved
administrative cleanup was verified. Neither a full 90-second details pass nor
a timeout is established. Administrative cleanup is not a passing supported
removal journey and does not establish present host readiness. Signing succeeded;
acceptance failed. The release-disposition job stopped at “Stop for an explicit
candidate failure decision”; adoption neither reruns it nor changes that outcome.

## Bounded implementation

The eleventh fixed record adds only q213. The Go validator and shell collector
require exactly eleven records. Current-candidate fixtures use prospective
v3.1.140/214; independent tag, sequence and release-ID collisions still refuse.
All ten previous record blocks and their identity values remain unchanged,
including q203's unknown signing state. Historical replay keeps its meaning.

No product Rust behavior, deadline, schema, dependency, credential, host/security
setting, workflow permission, signing authority or approval gate changed. The
existing read-only observation route is sufficient; no inventory dispatch is
needed. This reservation preserves unresolved authority and blocks its reuse or
promotion through supported paths. It is not a burn or qualification.

## Validation checkpoint

The two new q213 regressions failed against the ten-record policy and passed
after adding the exact record. The focused reservation suite passed 23 top-level
tests without skips in 56.688 seconds using the installed Go 1.26.6 toolchain.
It exercises the real shell/jq/Python/Go adapter, q213 missing/changed metadata,
unavailable/present refs, forbidden current-candidate allowance, omitted or
relabelled reservations, independent identity collisions, sequence progression,
historical replay and qualification/publication decision fixtures. The fixtures
perform no remote publication. Formatting, shell syntax and whitespace passed.

The complete release-tool package passed in 482.500 seconds using Go 1.26.6
for the test process and child builds; its native Linux menu execution test was
skipped on this Mac. Repository-root integration tests passed in 94.162 seconds,
with three explicitly opt-in/root-Linux fixture skips. Go vet and module integrity
verification passed. The fresh full-inventory replay at 11:07:27 UTC accepted all
eleven exact records and twenty-two explicitly absent refs across 208 releases.
Independent code and Spec Kit consistency review found no implementation or
authority blocker; two stale task summaries were corrected. Local documentation
links and whitespace checks passed, and temporary fixture roots were removed empty.
Product Rust was unchanged, so existing valid local results were reused.

Final-source GitHub CI remains a separate post-push check at this commit checkpoint,
not a result inferred from local tests. Exact commit/push/CI receipts are retained
under `.scratch/acceptance/q213res/`; T038 is complete only when those checks pass.

The prior operational warning change bf72f300 passed all four jobs in
[Verify 42189134454](https://github.com/albertloky/SBXR/actions/runs/42189134454).
That closes its earlier pending-CI checkpoint; it does not validate this new
reservation commit or establish live success.

Private evidence: `.scratch/acceptance/q213disp/` (original review),
`q213refresh/` (fresh eleven-draft/22-ref observations), `q213res/` (implementation
and fresh assets/signature), `q13t/` (red/green focused tests), `q13p/` and `q13i/`
(pinned full release-tool and root integration checks). Original run evidence
remains under `.scratch/acceptance/q213-full-20261105/`.

## Remaining prerequisites

Final-source CI and fresh global release/burn/reservation history and collision
checks precede any next candidate. v3.1.140/214 is prospective, not allocated.
A new live qualification needs specific approval of its exact source, host/profile,
actual host/client readiness, temporary changes, attended window and scoped cleanup.
The details criterion and five HTTP journeys remain unverified. Stable publication
requires successful exact-candidate qualification/cleanup and separate approval.
