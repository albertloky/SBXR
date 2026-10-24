# Pure server configuration fixtures

These files use only fixed synthetic credentials. No real credential is generated,
read or configured. No rendered command is executed. The fixtures establish local
codec parity, not sing-box/systemd execution or deployment qualification.

## API and integration

`src/server_configuration.rs` uses the existing serde_json/sha2 dependencies and
`configuration::STANDARD` / `subscription_artifact::valid_vmess_hostname` helpers.
The module is exported by `src/lib.rs`; integration tests use that public crate
interface. The canonical tunnel unit asset is shared with record ownership hashing.

- `ServerIdentity::from_private_key(uuid, private_key, short_id)` validates supplied
  lowercase v4 client UUID, Go raw-URL-base64 32-byte private-key syntax and four-byte
  hexadecimal short ID. The private fields cannot be constructed or deserialized
  without validation. There is no key generation, X25519 public-key derivation or
  caller-supplied public key to trust; those belong to the cryptographic adapter.
  Go accepts CR/LF and noncanonical unused base64 bits here, and uppercase short-ID
  hex. The differential vectors retain that exact acceptance.
- `ServerConfiguration::standard(&identity)` renders the fixed Standard endpoint.
  `new(&identity, destination_address, server_name)` matches Go's lower-level host/port
  and nonempty-SNI encoder, including its permissive host syntax. It grants no
  network-compatibility admission. `with_vmess_websocket(&self, hostname)` adds the
  sole fixed loopback VMess origin with the same UUID, and refuses a second one.
- `with_client_uuid(&self, uuid)` renders a supplied replacement in every inbound,
  preserving REALITY material and all other fields. It generates no credential and
  performs no session termination, revocation or transaction. Arbitrary existing
  configuration decoding/inspection is deliberately outside this rendering API.
- `as_bytes()` explicitly exposes secret-bearing bytes; `sha256_hex()` binds their
  exact bytes. Identity/configuration Debug and Display are redacted. The single
  error contains no source input and types have no public Serde implementation.
- `PINNED_SING_BOX` retains the exact official repository, signing key, package
  version/size/digest, architecture, artifact and package-owned service-unit path.
  SBXR does not render a replacement for sing-box's packaged service unit.
- `tunnel_unit()` returns only Go's dedicated `sbxr-tunnel.service` bytes.
  `TunnelBinding::from_parts(tunnel_id, token_sha256, binary_sha256)` validates
  nonsecret fingerprint syntax; its accessors return those same nonsecret fields.
  `resources()` lists only the unit, synchronized stage and exact enablement link.
  `valid_cloudflared_version(output)` retains Go's 2025.4.0 minimum and output shape.

A future host adapter must independently verify token contents, protected parents,
root ownership, 0600 token / 0755 binary, one-link regular files, exact bound file
bytes, successful observed version execution, exclusive unused dedicated service
names, and fresh systemd state. Rendering or constructing `TunnelBinding` does not
establish any of those facts or grant authority. Owner-provided token/binary and
Cloudflare account/domain/tunnel/DNS remain outside owned cleanup resources.
No cryptographic dependency, filesystem adapter, process runner or real service
integration is added by this slice.

## Go provenance

`generate.go` runs the preserved production Go sing-box adapter using Go 1.26.6.
Its 64 differential vectors record acceptance and exact successful bytes, including
UUID/key/short-ID refusals, host/port boundaries and IPv6, Go HTML/Unicode JSON
escaping, SNI acceptance and canonical VMess hostname validation. The all-zero
private key and its fixed derived public key are synthetic test values. A
noncanonical final base64 digit decodes to that same private key.

`standard.json` and `vless-vmess.json` preserve exact lexical map-key order,
field types, disabled logging and final newline. The generator parses the current
Go AST to extract the exact unexported tunnel unit and setup pins without editing
Go source. `tunnel-resources.json` comes from Go `TunnelAuthority.Resources()`.
The three owned resources bind the SHA-256 of the exact unit bytes, preserving the
`LoadCredential`/`--token-file`, dynamic user, loopback metrics, disabled auto-update
and null journal contracts. The token itself never enters rendered unit bytes.

Regenerate from the repository root with the cached Go 1.26.6 toolchain:

```sh
GOTOOLCHAIN=go1.26.6 go run tests/testdata/server_configuration/generate.go
```

Use the workspace-local Rust toolchain and a unique target/run directory as in
`docs/rust-rewrite.md`, then run:

```sh
cargo test --locked --offline --test server_configuration
cargo clippy --locked --offline --test server_configuration -- -D warnings
rustfmt --edition 2024 --check src/server_configuration.rs tests/server_configuration.rs
```

Initial missing-module failure, passing checks, mutation-test failure and fixture
regeneration evidence belong under `.scratch/acceptance/rust-server/`. These are
macOS arm64 local observations. Native Ubuntu, upstream configuration validation,
physical crash durability, traffic, outside-client/Karing and all five packaged
live journeys remain untested by this slice.
