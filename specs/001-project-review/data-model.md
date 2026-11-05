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
