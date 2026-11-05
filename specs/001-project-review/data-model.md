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
