# Public release verification dependencies

Software Lifecycle may use `github.com/sigstore/sigstore-go v1.3.0` to verify GitHub's signed release attestations and `github.com/klauspost/compress/snappy` to decode GitHub's bounded Snappy attestation bundles. These are the only additions to ADR-0001's pre-approved dependency categories. Their use remains inside the public GitHub release Adapter, under the fixed trusted-root fingerprint and exact release checks required by [Build the exact six-asset Release Identity and public verifier](https://github.com/albertloky/SBXR/issues/155).

This avoids implementing certificate, transparency-log, timestamp, and Snappy verification locally. Any version change or use outside this boundary requires a new review and recorded decision.
