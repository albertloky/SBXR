# Ephemeral cryptographic identity generation

All identities here are fixed, public test inputs. Tests using OS entropy keep
their generated values in memory, install nothing and transmit nothing. These
checks establish local generation/codec parity, not deployment qualification.

## Central integration

Core has integrated the module export, focused tests and the following pinned
registry dependencies in the central manifest/lockfile:

```toml
x25519-dalek = { version = "=2.0.1", features = ["static_secrets"] }
getrandom = "=0.3.4"
base64 = "=0.22.1"
zeroize = "=1.8.2"
```

The existing `subtle` dependency supplies the constant-time public-key comparison.
The existing `SubscriptionCredential` supplies canonical token validation and
SHA-256 of the encoded token text. There is no handwritten cryptography and no
Go subprocess in the Rust implementation.

API:

- `Identity::generate()` obtains a v4 UUID (16 bytes), four-byte short ID and
  raw 32-byte X25519 private key from separate secure entropy draws. Dalek
  derives the public key. Newly generated encodings are lowercase UUID/hex and
  unpadded URL-safe base64; the raw private bytes are retained, not pre-clamped.
- `Identity::from_private_key(uuid, private_key, short_id)` derives a canonical
  public key for supplied Go-format input. `from_parts` additionally verifies
  the supplied public key in constant time, preserving accepted input spelling.
  Both match Go's lowercase v4 UUID and four-byte hex rules. Go's CR/LF and
  nonzero unused base64 bits, and uppercase short-ID hex, remain accepted.
  Padding, spaces, tabs, standard-base64 symbols, wrong decoded lengths and
  mismatched public keys refuse. Every 32-byte private input is legal for
  X25519, including fixed zero test inputs; dalek performs the required clamping.
- `uuid()`, `private_key()`, `public_key()` and `short_id()` are explicit accessors.
  `server_identity()` adapts to the existing pure server renderer. Rendering and
  these accessors do not approve disclosure, installation or rotation effects.
- `ClientUuid::generate()` supports UUID-only VLESS/VMess replacement. Pass the
  value to `ServerConfiguration::with_client_uuid`; ending old sessions and
  sequential revocation still belong to product orchestration.
- `SubscriptionGeneration::generate()` uses independent 32-byte credential and
  16-byte Link ID draws. `credential()` returns the existing redacted
  `SubscriptionCredential`; `link_id()` returns its nonsecret generation ID.
  An additional `GenerationId::generate()` draws 16 more independent bytes for
  a recorder or rotation operation. No identifier is derived from a credential
  or a Client Identity. `GenerationId::parse` accepts exactly 32 lowercase hex
  characters.
- Each generator has `generate_with_entropy(&mut dyn Entropy)`. `OsEntropy`
  delegates to `getrandom::fill`; deterministic sources are only for tests.
  An entropy implementation must fill the whole requested buffer or fail.
  Any error, including a partial-fill failure, returns `EntropyUnavailable`
  without retry, fallback or partial identity. Error sources are not retained.

All module value types redact Debug and Display, and errors contain no input.
There are no public Serde implementations or persistence APIs. Temporary entropy
and decoded-key buffers, identity-owned UUID/private-key strings and dalek static
secrets are zeroized on drop. This does not promise erasure of compiler/caller
copies or the existing server/client/credential artifacts returned to callers.

Library API references:
[dalek X25519](https://docs.rs/x25519-dalek/2.0.1/x25519_dalek/),
[getrandom failure contract](https://docs.rs/getrandom/0.3.4/getrandom/fn.fill.html),
[base64](https://docs.rs/base64/0.22.1/base64/),
[zeroize guarantees and limits](https://docs.rs/zeroize/1.8.2/zeroize/).

## Independent Go fixtures and local checks

`generate.go` calls Go 1.26.6's `crypto/ecdh` and the preserved production
`singbox.Adapter.ValidIdentity` with fixed test input. Its five derivation
vectors include RFC 7748 Alice/Bob keys, zero, all-FF and a sequential private
key. Twenty-nine validation cases record Go's exact acceptance/refusal behavior.
The generator never calls random generation or edits production Go source.

Regenerate from the repository root, using the workspace-local temporary path
required by `docs/agents/files-and-artifacts.md`:

```sh
GOTOOLCHAIN=go1.26.6 go run tests/testdata/identity_generation/generate.go
```

After central integration, use a unique target/run directory as described in
`docs/rust-rewrite.md`, then run:

```sh
cargo test --locked --offline --test identity_generation
cargo clippy --locked --offline --all-targets -- -D warnings
rustfmt --edition 2024 --check src/identity_generation.rs tests/identity_generation.rs
```

During worker development an ignored isolated manifest under
`.scratch/acceptance/rust-identity/check/` includes the real module and existing
codec source directly, with the same integration test file. It permits focused
validation without modifying the parent-owned Cargo manifest, lockfile or exports.
Before/after logs, the isolated lockfile, lint output and public-key mismatch
mutation evidence live under `.scratch/acceptance/rust-identity/`.

Tests exercise deterministic entropy allocation, UUID bit rules, Go/RFC key
derivation, legacy validation, every entropy-failure boundary, token-text digest,
redaction, actual OS entropy and the existing server/client codecs including
UUID-only VLESS/VMess replacement. No VPS, Karing, service, credential installation,
release signing, publication or live acceptance journey is exercised.
