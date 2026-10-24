# Genuine public SBXR release evidence

Captured from public read-only GitHub endpoints on 2026-10-24 for v3.1.118,
sequence 192, commit `abb3975c4f1c3fb376ed4a61020d935f8669863b`.
This is historical release authentication evidence, not Rust deployment or fresh
live qualification. No fetched executable or installer was executed.

Sources:

- `https://api.github.com/repos/albertloky/SBXR/releases/tags/v3.1.118`
- `https://api.github.com/repos/albertloky/SBXR/attestations/sha1:abb3975c4f1c3fb376ed4a61020d935f8669863b?predicate_type=release&per_page=100`
- Exact release asset API IDs 663220323 (index) and 663220325 (amd64 archive).
- The three public Azure blob paths and compressed SHA-256 values in
  `provenance.json`. Their Snappy bytes are unchanged. Every proof authenticates
  against the preserved native release root, RFC3161 timestamp and exact signer.
  This complete set includes valid other tags at the same commit.

`release.json` preserves the required public metadata fields, exact release body
and all four asset bindings. `attestations.json` preserves entry order, public
blob hosts/paths and current API shape; temporary SAS query credentials were
replaced with the inert query `fixture=offline`. The real bundle bytes were not
modified. The index is byte-preserved, SHA-256
`64c8ecd65ad0813f1e8ae0a6cbda9402eb08fafbe83165ce49d2cf86b368ad6f`.
The 14,975,576-byte amd64 archive stays in ignored local evidence, SHA-256
`a65da1977be25a2a90c52f8ee80afb2a93648944bc5fee26249e7c2b32eb9307`.
Do not add downloaded production executables or bearer query values to fixtures.

The pinned `X-GitHub-Api-Version: 2026-03-10` matches the preserved Go Source.
That version returns blob references without inline bundles. The default older
API also adds a deprecation Link header; all exact metadata/proof reads must
retain the existing complete-response refusal rather than ignore that header.
The version is documented by GitHub at
https://docs.github.com/en/rest/about-the-rest-api/api-versions.

`tests/public_release.rs` verifies every genuine signature, the equivalent signed
claims and exact index. Its mutation changes an asset name while retaining valid
JSON and policy-matching digest subjects, and must fail signature verification.
No test-only signature constructor is involved.

`examples/verify_public_release.rs` also verifies the complete archive, ELF/trailer
and installed-byte binding using the real acquisition API. It also exercises
exact restoration into a disposable protected temporary root. Supply the ignored evidence directory containing the
fixed archive basename. Archive decoding stays in memory; recovery writes only
its two fixed fixture paths and never executes them:

```sh
cargo run --locked --offline --example verify_public_release -- <evidence-directory>
cargo run --locked --offline --example verify_public_release -- <evidence-directory> --public
```

The first command replays these preserved public proof/metadata/index bytes and
the local archive. The second uses actual bounded HTTPS for every exact-release
request and checks against the same inert local bytes. The fixture root is cleaned
on success or refusal. The example is a repository evidence tool, not a public installation action or production authority bypass.
