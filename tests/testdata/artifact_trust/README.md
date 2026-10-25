`native-statement.json` is a synthetic in-toto release/v0.2 statement with the
same field and four-asset contract as the preserved Go parser. Its commit,
digests, IDs and tag are literal offline test values. It has no signature and
does not establish any release's authenticity or qualification.

The two genuine bundles remain unchanged under the preserved Go adapter's
`internal/softwarelifecycle/adapter/github/testdata/` directory:

| Fixture | SHA-256 | Meaning |
| --- | --- | --- |
| `github-attestation.bundle` | `874a216db183b363265190077f1fccacc32c2ae5a150c312fbff5908e554bea2` | Real candidate workflow signature binding manifest digest `0add26026bed41b9bebd770353e6d4249cf30bbf3090c618e59f619b0c30d476` |
| `github_release_bundle.json` | `a1c39f89db9cd170a7cd3cabc18fa062223e65f2f078c63d8d9a7bb5f2d91f02` | Real GitHub release/TSA signature for commit `c5e17a62e06a1d201570249c61fae531e9244e1b` in another repository |

Both authenticate in Rust under the same pinned roots and signer policies used
by Go's `sigstore_test.go` and `public_release_test.go`. The foreign native
statement then refuses SBXR claim admission. Negative tests mutate genuine
payloads, certificates, signatures, TSA tokens, Rekor inclusion material and
integrated times in memory. Snappy tests compress the genuine native bundle
offline; no fixture signing or live acquisition is performed.

The selected backend is `sigstore-verify = "=0.15.1"`, with default features
disabled and `aws-lc-rs` enabled; raw compression uses `snap = "=1.1.2"`.
Verifier source is the maintained Sigstore project's published crate, Git
revision `fc308a2f0bcef92f10c199c6d75fa72441b329f7`:
[verification API](https://github.com/sigstore/sigstore-rust/blob/fc308a2f0bcef92f10c199c6d75fa72441b329f7/crates/sigstore-verify/src/verify.rs),
[authenticated timestamp collection](https://github.com/sigstore/sigstore-rust/blob/fc308a2f0bcef92f10c199c6d75fa72441b329f7/crates/sigstore-verify/src/verify_impl/helpers.rs).

Native proofs require at least one RFC 3161 token; the backend authenticates its
signature binding, exact TSA authority/window, signing chain and certificate
validity at verified time. Its no-public-log policy applies only to the native
GitHub root and exact release-service URI. Candidate proofs retain required
Rekor verification, at least one authenticated observer time, the exact Actions
workflow URI and exact OIDC issuer. Neither policy adds an SCT requirement,
matching the current Go options. No current-time fallback, ambient roots or
external verification command is used.

Strict wire-field checks preserve Go's unknown-field refusals around the Rust
backend's otherwise permissive Serde decoding. Canonical Sigstore JSON field
names are required; noncanonical protobuf field-name aliases refuse.

The backend has no SHA-1 artifact API. For native statements it verifies the
whole DSSE payload while binding one signed SHA-256 asset subject; the wrapper
also requires the exact SHA-1 commit in that same authenticated payload. Every
valid SBXR native statement must contain all four SHA-256 asset subjects, so
this imposes no missing algorithm requirement on SBXR's release format.

The backend rejects any supplied invalid timestamp even if another valid
source would meet the threshold. This is stricter refusal than Go's timestamp
threshold collector. Genuine SBXR native proofs and the complete positive acquisition example now
live in `tests/testdata/public_release/`. The exact raw manifest bytes for the
candidate fixture remain absent. Neither fixture set claims a fresh positive
qualification or deployment result.


`src/release_acquisition/candidate_tests.rs` exercises current manifest approval,
workflow, decision-chain, full release/asset, support and exact index semantics
with synthetic JSON that cannot issue authenticated proof. The genuine candidate
bundle above rejects these different manifest bytes through the actual public
acquisition API before any asset request. Metadata-read cancellation likewise
cannot grant late authority. The role-separation compile-fail check prevents a
candidate installed result from substituting for a stable installed result.
A complete positive signed-candidate acquisition is not claimed without the
missing matching raw manifest and its exact artifacts.
