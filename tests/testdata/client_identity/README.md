# Client Identity rotation fixtures

`checkpoints.tsv` transcribes the secret-free checkpoint/direction contract from the preserved Go `clientIdentityCheckpointPolicies` in `internal/proxyinstallation/proxyinstallation.go`.

Tests generate only synthetic UUID/key/token material inside disposable local fixture roots. Record writes use real fsync/rename and retained flock; shutdown coverage includes a local child process and an accepted loopback socket. These tests do not prove native systemd, cgroup or deployment behavior. Conflicting or incomplete staged records are preserved and refused. A renamed record is re-read and synchronized before recovery; an acknowledged revocation never selects source restoration.

The completed core integration exports the module normally, admits its structural
successor relation in the durable store, maps the shared Owner Interface/terminal,
and provides `host::identity::ProtectedIdentityHost` for explicit injected roots.
Concrete Owner tests use actual protected publication, service-controller descriptor
lending, one-use cutover consumption and HTTP artifact refresh. Runtime startup now
shares the strict Standard+VMess decoder. These additions do not establish a native
Owner backend or Linux systemd qualification.

The original handoff requirements below record worker boundaries; the first four
are now integrated with the preceding limits. The last two remain gaps:

- Export `client_identity` from `src/lib.rs`, and map its Review/Execute results into the shared Interface without weakening review expiration or disclosure confirmation.
- Admit `client_identity::permits_successor` in the durable store as structural CAS validation; the injected host still supplies Owner confirmation, retained whole-host/package/managed-writer exclusion, exact installed-release authentication and all host proofs.
- Implement the narrow `Host` contract using protected files and bounded service control. Proxy stop and fresh proxy/serving quiescence must cover main PID, descendants, accepted requests and listeners. `StartTarget` must use the existing exact one-use cutover gate and borrowed Owner lock.
- Share a strict VLESS+VMess configuration decoder with private proxy/serving startup. The current base's runtime preparer accepts Standard VLESS only.
- Supply selected legacy HTTPS renewal/certificate authority updates centrally if those historical recovery paths are enabled. This slice preserves the recorded certificate, independent credential and fault/renewal evidence; it does not issue certificates or silently adopt a changed generation.
- Supply an explicit exact-stage publication retry/inspection path for conflicting staged authority. `Snapshot` deliberately does not promote or discard it.

The first local build exposed missing concurrent core modules; focused verification therefore uses a scratch copy of base commit `72b92c5` with only this module's export added. No preserved Go checkout, live resource, credential, security setting, Karing state, signing or publication is touched.
