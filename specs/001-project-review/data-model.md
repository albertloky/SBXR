# Review data model

No durable product schema changes.

Capability: name, governing requirement, source boundary, tests, evidence gap.
Finding: ID, capability, evidence, classification, action, verification status.
Classification is exactly confirmed defect, documentation mismatch, unverified
behavior or decision required. A finding cannot become live-validated from local tests.
Verification: command/check, source revision, result and boundary limitations.
Candidate: tag/sequence/source/run plus unchanged asset identity and failed outcome.

Existing Prepared Action transitions remain review -> one-use execution or
invalidation by a later review/details request. Details retain no prepared action.


Retained Candidate Reservation: reuse the existing fixed record containing tag,
sequence, source, run ID, release ID, index digest, signing state, manifest digest
and each asset's ID/name/size/digest. Append only the approved build 212 member;
no wire-schema change. Unknown-signing and signed-unqualified remain distinct.
Observation state must explicitly establish absent release/burn refs and matching
unchanged drafts. The ten-record set is exact, not a caller-extensible allow-list.

Build 213 continuation (2026-11-06): append one signed-unqualified member using
those same fields, with the exact values in contracts/retained-candidate.md.
The current set becomes exactly eleven, q203–213; the preceding ten are unchanged.
This does not change the wire schema or transition any failed candidate to
qualified, unsigned, burned or published. Attempt 1 is verified provenance;
the existing reservation schema continues to bind its run ID and manifest digest.

Failure-cleanup continuation: reuse the existing private request and unsealed,
request-bound observation draft without changing either schema or bytes. Completed
handoffs contribute only their recorded waits; a pending handoff remains pending.
The caller also uses an explicit absolute cutoff, post-action verification reserve
and protected candidate runtime deadline. These bound one supervised removal
action; they do not create response, success, cleanup-completion or release authority.

Release-tool test-build continuation: one process-local cache holds only successful
immutable executable bytes and their mode for the audited unchanged build context.
A build failure remains visible and leaves the cache empty; no error is cached.
Each fixture owns a distinct temporary executable copy and lifetime.
No product, qualification-wire or persistent schema changes; separate test processes
and distinct build inputs do not inherit cached authority.

## Operator-budget continuation — 2026-11-06

An optional local invocation carries an absolute cutoff, positive command cap and
nonnegative downstream reserve, supplied together and finite. Its fixed ten-second
local stopping allowance is separate from that reserve. The original request,
draft, signed/runtime cutoffs and failed observations retain their existing bytes
and authority. Selected procedure rows describe allocations and remaining work;
they are neither observations nor new qualification records. No product or signed
wire schema changes, persistent sequence clock or automatic cleanup state machine.

## Build 214 retention — 2026-11-08

Append q214 through the unchanged reservation fields: exact source/run/release,
index and four asset identities, signing_state `unknown`, absent manifest digest.
The approved exact set becomes twelve, q203–214; eleven prior records stay intact.
Cancellation and unknown signing are separate facts. No unsigned, signed, burned
or qualified transition is inferred, and no wire schema changes. Earlier dated
ten/eleven-record paragraphs retain their historical meaning.
