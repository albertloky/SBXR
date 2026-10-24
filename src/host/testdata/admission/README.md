# Offline TLS admission fixtures

`generate.go` uses only the Go standard library and fixed public Ed25519 seeds
0 and 1. It generates `ca.pem`, `server.pem` and `server-key.pem` with validity
2000-01-01 through 2100-01-01. The leaf covers `localhost` and `127.0.0.1`.
The private key is intentionally public test data, not an operational credential.

The Rust tests use only ephemeral, nonprivileged loopback listeners and an
in-memory isolated root store. They never import the CA into the operating system,
contact the fixed production endpoints, or bind privileged TCP443. Successful
TLS 1.3/h2, certificate/name/ALPN refusals, bounded HTTP framing, cancellation and
busy bind tests do not qualify a destination or live host.

Regenerate offline with the repository's Go 1.26.6 from the repository root:

```sh
GOTOOLCHAIN=go1.26.6 go run src/host/testdata/admission/generate.go
```

The generator writes only these three fixture files. Preserve their deterministic
bytes and fixed public identities when reviewing changes.
