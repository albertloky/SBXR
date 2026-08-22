---
status: accepted
---

# Public release verification dependencies

Only the public GitHub release Adapter may use `github.com/sigstore/sigstore-go v1.3.0` to verify GitHub's signed release attestations and `github.com/klauspost/compress` to decode bounded Snappy attestation bundles.

In normal use, the Adapter verifies GitHub's canonical immutable qualified Latest release, its exact four assets, Release Identity, Acceptance Record, signed subjects, sizes, digests, redirects, and downloaded bytes. During an approved Acceptance VPS run, the same Adapter may select only the two draft identities bound by one keyless-signed, root-only qualification manifest from the trusted workflow. That channel changes release selection only and adds no public command, unsigned switch, or second transaction path. No other Module or Adapter may import these dependencies. A version change or use outside this boundary requires a new decision.

This avoids local certificate, transparency-log, timestamp, and Snappy implementations while keeping external release-verification complexity behind one Adapter.
