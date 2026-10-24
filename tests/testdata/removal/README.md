# Removal recovery fixtures

These ten secret-free synthetic journals are byte-for-byte copies of the
preserved Go reference in `internal/proxyinstallation/testdata/removal-recovery/`
at `abbe4d7dbe9ca7de93afa6475975fc4cb35ef74a`. They bind historical `v3.0.0`
finishing authority at removal checkpoint 10, including pending enablement,
link rotation, certificate activation, client identity rotation and compromise.
The Rust tests require strict decode and unchanged canonical re-encoding before
running only temporary filesystem fixtures and injected effects.

No fixture contains an operational credential. No test invokes systemd, APT,
firewall commands, Cloudflare, certificate issuance, a VPS or a real installer.
The tests demonstrate orchestration, not Linux durability, release authentication,
exact executable restoration, packaged acceptance or live qualification.

`tests/removal.rs` now imports the public library module. Core integration adds
`StandardRemovalHost`, exact durable transitions/finalization and the shared
Interface/terminal. The concrete adapter is Standard-only and injected; native
effects, auxiliary resources and authenticated restoration remain unavailable.
No existing Go installation is migrated.

Current integration boundaries:

- Library export, shared Complete/Finish actions, distinct states/machine codes,
  every-Review token invalidation and exact `REMOVE SBXR` confirmation are integrated.
- Implement `RemovalHost` using retained whole-host/package/writer guards,
  protected filesystem identities, exact per-rule firewall cleanup, dedicated
  tunnel-only cleanup, shared renewal-route restoration, bounded fixed commands
  and fresh complete absence checks. No native adapter exists in this slice.
- The central store now admits exact commitment/checkpoint successors. The Standard
  adapter implements protected synchronized finalization with interrupted retries;
  this is local filesystem evidence, not physical crash qualification.
- Connect `ExactRestoration` to authenticated same-release acquisition and
  protected missing-member restoration. The tests restore inert fixture markers;
  they do not authenticate or install real executables.

The fake lifecycle facts and admission fingerprints are explicit injected facts,
not a native host audit. Fixture file effects check bytes, mode, type, link count
and current UID before unlinking; their temporary roots are owned by each test.
Local fsync/finalizer interruption tests cannot establish physical crash or
power-loss durability. Pending historical transport migration refuses conversion,
matching the current reader-only boundary.

`FinalSynchronizationUnknown` must map to Problem detected and require fresh
inspection; do not promise that Finish removal remains available after an
uncertain finalizer unlink sync. `PackageHold` maps to the separate `host::Operation::RemovePackageHold`; it verifies
pinned package identity, applies unhold and checks absence before the separately
pinned purge effect.
