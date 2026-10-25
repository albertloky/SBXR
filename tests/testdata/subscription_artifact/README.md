# Synthetic subscription/client codec fixtures

Generated offline from the preserved Go codecs at `0ef2afe` (Go source from
`abbe4d7`) using Go 1.26.6. The UUID, zero-filled private-key input, short ID,
token and documentation addresses are fixed synthetic values. No randomness,
host access, DNS, connector, certificate, credential installation or live resource
is used. The generator derives the public key through Go's existing X25519
implementation; the Rust artifact module never receives a private key.

From the repository root, regenerate with the pinned Go toolchain:

```sh
GOTOOLCHAIN=go1.26.6 GOPROXY=off GOSUMDB=off \
  go run tests/testdata/subscription_artifact/generate.go
```

The optional final argument selects a separate existing output directory for
comparison. `generate.go` is excluded from ordinary Go builds. It imports and
calls the original codecs rather than reproducing their serialization logic.
Set `TMPDIR` and `GOCACHE` inside a fresh `.scratch/acceptance/<run>/` directory
when running validation, as required by the project artifact guide.

- `vless.txt`, `vless-vmess.txt`: exact subscription bytes, including ordered
  query fields, percent escaping, standard padded base64 and final LF.
- `client-vless.json`, `client-vless-vmess.json`: complete outside-client JSON,
  including Go's top-level struct order, nested sorted map keys and final LF.
- `vmess-v2.json`: the decoded v2 node for human inspection; JSON values such
  as `port` and `v` are strings, and both nodes share one UUID.
- `go-vectors.json`: 76 input/output cases for IPv4, v4 UUID, server name,
  public-key encoding, short ID, VMess DNS labels and the 4 KiB artifact bound.
  Go diagnostic redaction is bypassed only in this synthetic fixture generator.

Go's strict base64 decoder ignores CR/LF in public keys; the URI escapes those
bytes and retains the artifact limit. The vectors prove 4,095 and 4,096 bytes
are accepted and 4,097 bytes is refused. HTTP tokens instead require exactly 43
canonical raw-base64url characters representing 32 bytes. SHA-256 is over that
encoded token text, not the decoded bytes.

`src/subscription_artifact.rs` uses existing Serde/serde_json and SHA-256
dependencies. Its small base64 helper only encodes VMess JSON; RFC 4648 vectors
and the Go byte fixtures check its alphabet/padding. It implements no
cryptography. Public keys and tokens are validated by alphabet, exact decoded
length and zero unused bits, without deriving keys or authenticating requests.

The module is exported from `src/lib.rs`; integration tests consume that public
API. No additional Cargo dependency is needed. Public API:

```text
ConnectionFacts::new(ipv4, uuid, server_name, public_key, short_id, Option<vmess_hostname>)
    -> Result<ConnectionFacts, ArtifactError>
ConnectionFacts::subscription_artifact() -> Result<ClientArtifact, ArtifactError>
ConnectionFacts::client_configuration() -> Result<ClientArtifact, ArtifactError>
ClientArtifact::as_bytes() -> &[u8]
SubscriptionCredential::parse(&str) -> Result<SubscriptionCredential, ArtifactError>
SubscriptionCredential::as_str() -> &str
SubscriptionCredential::sha256() -> [u8; 32]
HttpSubscriptionLink::new(ipv4, &SubscriptionCredential) -> Result<HttpSubscriptionLink, ArtifactError>
HttpSubscriptionLink::parse(&str) -> Result<HttpSubscriptionLink, ArtifactError>
HttpSubscriptionLink::as_str() -> &str
HttpSubscriptionLink::transport_warning() -> &'static str
valid_vmess_hostname(&str) -> bool
MAX_SUBSCRIPTION_BYTES, VMESS_WEBSOCKET_PATH, HTTP_TRANSPORT_WARNING
```

All fields are private; secret-bearing types have redacted Debug/Display and no
Serde implementation. Byte/string accessors explicitly expose credentials and
must be called only within the product's existing disclosure/serving authority.
The helpers validate syntax and build bytes. They do not check Ownership Records,
server configuration, host/public-IP policy, request authentication, availability
or Karing import, and do not approve disclosure or establish deployment qualification.
