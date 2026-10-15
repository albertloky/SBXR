---
status: accepted
---

# Select equivalent native release proofs

GitHub's native release-attestation endpoint is scoped to a source commit.
Separate immutable releases can return multiple signed statements for one
commit. Requiring one API record therefore blocks legitimate releases without
establishing a unique Release Identity. Repeated equivalent proofs also do not
change the identity or bytes being authenticated.

The GitHub Adapter accepts a complete, unpaginated set of 1–99 native GitHub
release attestations. It cryptographically verifies and strictly parses every
record for the repository and source commit under one 30-second selection
budget. At least one statement must name the requested canonical tag. Every
statement for that tag must bind its exact four asset names and SHA-256 digests.
Equivalent statements may coexist, as may valid statements for other tags.
Equivalence compares release claims; signatures, timestamps, JSON formatting,
asset order and existing nonempty opaque predicate IDs need not be identical.

Missing target proof, conflicting target bytes, invalid records, non-GitHub
initiators, pagination links and a saturated first page are refused. A hidden
later page could contain a conflicting claim; silently selecting the first
matching statement would miss it. An invalid signature or statement cannot
establish that its apparent other tag is trustworthy. The bounded reader
therefore refuses those histories instead of skipping unverifiable evidence.
The synchronous cryptographic verifier cannot be interrupted mid-call; deadline
checks before and after verification and before acceptance prevent late proof
from being accepted.

Existing signer, trusted-root, timestamp, digest, strict JSON, asset, Release
Identity, Acceptance Record, Release Sequence and qualification requirements
remain in force. Native release proofs retain GitHub's
`https://dotcom.releases.github.com` certificate identity. Candidate-manifest
proofs separately retain their existing Actions workflow identity. No trust
root, dependency or persistent access setting changes.

The API count in publication facts remains the total returned record count.
Publication still requires the production verifier's accepted exact Release
Identity and sequence. The repository tool may verify one exact immutable public
stable tag through the same Adapter for publication failure cleanup, including
a tag that is no longer Latest. Refused and unavailable JSON results do not
authorize cleanup to call a release publicly verified. All four public asset
downloads must still match the expected bytes.

This refines ADR-0008's verification and ADR-0014's repository-tool boundary;
installed-software discovery continues to select canonical Latest only. Tagged
verification refuses qualification transport. No product command, alternate
installer selection or update authority is added.

The Owner approved activation on 2026-10-15. This decision grants no live-run
or publication waiver, and does not qualify a failed candidate. Failed release
identities, burns and historical evidence retain their existing meanings.
