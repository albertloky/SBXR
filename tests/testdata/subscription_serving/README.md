# Synthetic HTTP serving contract

`requests.json` contains 65 manually specified HTTP request cases based on the
current Go Module in `internal/proxyinstallation/subscriptionserving/serving.go`
and its adjacent tests, also checked against the preserved original checkout.
`@TOKEN@` is replaced with the canonical all-zero 32-byte token encoded as 43
raw-base64url characters. Every UUID, public key, token and address used here is
fixed synthetic data. No generator, random credential, TLS certificate, live
client, DNS lookup, network configuration, VPS or installed service is used.

`404.txt`, `429.txt` and `503.txt` are exact Go-format generic responses, including
CRLF headers, no-store, nosniff, Connection: close, exact Content-Length, final
body LF and Retry-After: 10 for 429/503. The Rust runtime must not include any
presented path, token, artifact, address or raw network error in these responses.
Only authenticated 200 responses contain the current Subscription Artifact.
The narrow `.gitattributes` entry prevents text normalization of these wire bytes
and recognizes intentional header CRLF while retaining ordinary whitespace checks.

The fixtures cover canonical and noncanonical paths/tokens, unescaped targets,
GET/HTTP/1.1, Host presence and duplicates, queries/fragments, transfer encoding,
declared bodies, contradictory Content-Length, malformed headers and retained
LF-delimiter compatibility. Parser tests reuse the same cases as the real
loopback runtime tests. Additional tests exercise 8,192/8,193-byte boundaries,
2,600 small headers, all 43 token positions, encoded-text hashing, six-source
bursts, fractional refill, 1,024-entry capacity and ten-minute idle expiry.

Runtime tests bind only `127.0.0.1:0` and use real TCP streams. They verify both
VLESS and optional VMess artifacts, no body draining/100-continue, one response
per connection despite keepalive/pipelining, actual-peer rate keys despite
forwarding headers, eight stalled workers plus a synchronous 503 responder,
five-second absolute header deadlines, cancellation and complete socket/worker
shutdown, listener ownership/refusal, and secret-free subprocess output.
The worker-bound test advances only the injected accounting clock so all eight
same-loopback-source sockets can remain active; connection deadlines always use
the real monotonic clock. Rate-table capacity/expiry use deterministic pure tests.

## Public API and core integration

The serving implementation is in `src/subscription_serving.rs`. Its fields are
private; Generation, State, Module and Cancellation have redacted Debug/Display
and no Serde implementation. Result codes and inspection facts contain only
bounded codes, the non-secret Link ID and runtime knowledge.

```text
Generation::new(link_id: &str, credential_sha256: [u8; 32]) -> Result<Generation, Code>
State::prepare_http(&ConnectionFacts, Generation) -> Result<State, Code>
Module::new() -> Module
Module::with_clock(Fn() -> Instant + Send + Sync + 'static) -> Module
Module::inspect(&Arc<State>) -> Facts { code, link_id, runtime }
Module::serve(Arc<State>, TcpListener, &Cancellation) -> Code
Cancellation::new(), clone(), cancel(), is_cancelled()
Code::as_str(), Runtime::as_str()
```

Core has integrated the pinned manifest/lockfile, module export and validated
IPv4 accessor. The original worker handoff required these changes:

1. Add pinned dependencies `httparse = "=1.10.1"` and `subtle = "=2.6.1"`, and
   update Cargo.lock using the existing workspace-local Cargo installation.
2. Export `pub mod subscription_serving;` in `src/lib.rs`.
3. Add this read-only accessor inside the existing `impl ConnectionFacts` in
   `src/subscription_artifact.rs`:

   ```rust
   pub fn public_ipv4(&self) -> Ipv4Addr {
       self.public_ipv4
   }
   ```

The accessor binds serving to the profile's already validated address without
duplicating/parsing codec output or accepting a second contradictory IPv4.
These shared files were deliberately not changed by the serving worker.
The new dependencies were downloaded into the workspace-local Cargo cache;
the shared manifest/lockfile remain untouched by this worker.
Library API references: [httparse Request](https://docs.rs/httparse/1.10.1/httparse/struct.Request.html),
[subtle ConstantTimeEq](https://docs.rs/subtle/2.6.1/subtle/trait.ConstantTimeEq.html).

Focused evidence lives in `.scratch/acceptance/rust-serving/`. Its standalone
harness compiles the actual serving source and integration tests, and a copy of
the current artifact codec with only the proposed IPv4 accessor added. The
harness pins the two proposed dependencies and leaves core's source, manifest
and exports untouched. Its result is a focused slice check pending core
integration, not a passing full-repository build.

## Deliberate limits

This is HTTP only. It does not implement legacy TLS preparation, trust/key/SAN
validation, certificate expiry shutdown, or HTTPS compatibility. That retained
contract remains an explicit later gap; HTTP never loads a retired certificate.

The Module consumes an already bound listener and verifies its IPv4 matches the
prepared profile. Like Go's private runtime it permits an ephemeral port for
tests; the eventual protected production role must prove the recorded IPv4 and
fixed TCP 8443, complete Ownership Record/configuration, process isolation,
periodic public-address validity and all host authority before invoking it.
No CLI/private-role, installation/service/firewall, schema-2 records, rotation,
removal, credentials generation or product orchestration is added here.

Cancellation is a single-session handle. Serve closes the listener, shuts down
registered sockets and joins every worker before reporting Stopped/Failed.
An already transmitted artifact or client cache cannot be revoked by shutdown.
The standard-library accept loop uses nonblocking accept and a cancellable
10 ms idle wait; it creates no extra accept/shutdown thread or request queue.
The kernel's listener backlog is outside the executing-worker count.

Go's `http.ReadRequest` accepts spaces in header names and obsolete folded
headers. The standards parser used here refuses those two malformed syntaxes
with the same concealed 404. They are explicit compatibility differences, not
claimed Go byte-for-byte request acceptance parity. The other 63 fixture cases
match Go. Host values otherwise retain Go's one-nonempty-Host rule; they never
select the artifact, authenticated identity, redirect or rate-limit source.
`check_go.go` checks all 65 expectations using Go's standard parser and the exact
Go handler conditions, with explicit `go_status` fields for the two differences:

```sh
GOTOOLCHAIN=go1.26.6 GOPROXY=off GOSUMDB=off \
  go run tests/testdata/subscription_serving/check_go.go \
  tests/testdata/subscription_serving/requests.json
```

Set `TMPDIR`, `GOCACHE` and `GOPATH` inside a new `.scratch/acceptance/<run>/`
for this optional local check. It reads synthetic bytes only; it starts no socket
and performs no product, filesystem-authority or host operation.

macOS loopback checks do not qualify native Ubuntu/systemd behavior, hostile
physical networks, real socket-buffer write stalls, TLS, power loss, packaged
deployment, outside traffic, Karing or a release. No live action, release signing,
publication or original Go checkout mutation is performed.
