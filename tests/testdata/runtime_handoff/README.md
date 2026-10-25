# Runtime handoff fixtures

These are synthetic local fixtures, not host, systemd, public-address, deployment,
or client qualification. The unit is copied byte-for-byte from
`internal/proxyinstallation/adapter/host/serving.go`; its bytes are independently
compared in `tests/runtime_handoff.rs`. The referenced runtime-start, serving and
proxy-start Go files were checked against the preserved original checkout and
matched. No Go source is changed.

Portable socket names are relative to the same workspace-owned fixture root to
avoid Darwin SUN_LEN limits with a long TMPDIR; no working-directory change or
external temporary symlink is used.

Portable tests use real descriptor passing, retained flock descriptions, Unix
sockets and loopback HTTP with injected process/sandbox observations. The explicit
`serve_subscription_loopback_fixture` route requires an injected root and uses a
synthetic loopback artifact plus an ephemeral listener. It cannot bind a live
recorded endpoint. Credentials, UUIDs and keys in these tests are synthetic.

The receiver reserves the full Linux SCM_RIGHTS ceiling before rejecting extra
descriptors. See [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).
This avoids the demonstrated pinned-rustix Darwin truncated-control iterator
panic; accepted messages still require exactly one control message, one owned
close-on-exec descriptor, and the exact one-byte response. Refusal closes every
received descriptor. Borrowed locks expose no descriptor or AsFd implementation.

`native_linux_observation_binds_a_real_child_peer_and_parent_identity` is Linux
only. It uses a disposable child process and local socket; it does not change
cgroups or host security. It is not run on macOS. Native Linux peer observations
read /proc and therefore belong on the lender side. A service whose sandbox hides
/proc needs independently authenticated Host observations; unavailable proof must
remain a refusal.

## Core integration hooks

The delegated files intentionally do not edit Cargo, lib, root dispatch or other
workers' host modules. Core must:

1. Enable rustix's existing `net` feature and export `pub mod runtime_handoff`.
2. Retain the original Owner HostLock and provide a CLOEXEC duplicate to
   `StartLock::from_owner_duplicate`. It verifies both existing exclusion and the
   exact protected inode. Ordinary starts use `StartLock::existing` and never
   create a missing lock; borrowed guards close without unlocking the Owner.
   Ordinary guards explicitly unlock on Drop, so a fork-retained descriptor
   cannot extend their exclusion after refusal or completed startup. Owner
   duplicates and received borrowers remain close-only; lender/borrower role is
   separate from ownership of lock release. Descriptor-leak fixtures retain a
   raw close-only lock owner so an explicit ordinary unlock cannot mask leaks.
3. Bind/connect the fixed `runtime_start_address` abstract Linux socket. Use
   `Handoff::new` plus `with_runtime_start` around the bounded fixed service start.
   The expected peer identity must come from authenticated installed bytes and
   actual kernel/process observations, never arguments or environment. A busy
   start calls `acquire_runtime_start`; its connector must honor the context's
   deadline and return an independently trusted lender identity.
4. Implement `ServingHost` with complete protected resource, authenticated
   installed/current executable, unit, configuration-group, sandbox, pending/final
   absence and public-IP observations. The watcher must be cancellation-aware and
   periodic (Go uses one minute). `serve_subscription` validates and prepares,
   retains the lock through bind, releases it before serving, and joins both the
   actual serving module and watcher before returning. Map only `Code::Stopped`
   to exit 0; periodic public-IP failure maps to `Failed`/exit 1.
5. Implement `ProxyStartHost` with the same installed authority, fixed startup
   integration, actual held mutation observation and atomic exact-configuration
   start-gate consumption. Dispatch `authorize_proxy_start` success as exit 0 and
   refusal as exit 1. Ordinary starts are refused once the cutover gate is reached;
   a borrowed Owner scope must consume the one-use configuration-bound gate.

There is no success-by-default native adapter. Unsupported retained HTTPS and
VMess server profiles fail closed rather than being served as Standard HTTP.
The root dispatcher must remain unavailable until the above inputs are connected.

## Local validation environment

Core-owned Cargo/lib files were preserved. Validation uses an isolated manifest
and a private target directory at
`/Users/Albert/Documents/Codex/2026-10-24/task-10/runtime-handoff-validation`.
It uses the existing locked dependency versions plus rustix's `net` feature, the
unchanged product module snapshot, and the actual delegated source/tests. A
capability-check mutation was applied only to a temporary copy and its refusal
test failed as expected; the mutation was restored.

Automatic approval review refused creating a repository `.scratch` directory
outside the three assigned paths; that combined command did not execute. Build
and temporary fixture output therefore use the provided writable task workspace.
All synthetic fixture directories from the demonstrated abort were inspected and
removed. No new live resource, account, credential, security setting, service,
signing, publication, Git/index, or commit action was taken.

Full Linux cross-checking stopped in ring's build script because
`x86_64-linux-gnu-gcc` is unavailable. No compiler or service was installed. Linux
execution and deployment qualification remain outstanding.

## Core proxy/cutover integration

The later core increment supplies `ProxyRuntimeHost`, `CutoverGate` and bounded
Unix transport in `src/host/runtime/` and `src/host/runtime_io.rs`. Rustix's existing
`event` feature supports deadline-aware polling; no dependency version changed.
`ProxyStartHost::verify_startup` now receives `StartContext`, and gate consumption
receives both that context and the actual borrowed `StartLock` for independent
capability checks. Existing fixture assertions are preserved.

`Handoff::new` retains exact preselected identity matching. `Handoff::service`
pins the authenticated installed executable, Owner UID and fixed role cgroup,
then captures and rechecks the observed peer's PID, start time and complete
identity before sending a descriptor. This permits systemd to assign the child
PID during startup. The native path uses Linux kernel/proc observations;
portable integration tests explicitly inject those observations while exercising
real descriptor passing, locks, Unix transport and protected filesystem effects.
The protocol and its one-use/no-relending constraints are unchanged.

`ProxyRuntimeHost::prepare_cutover` publishes only the currently recorded gated
configuration under the retained Owner lock. `CutoverGate::start_native` binds
the fixed abstract address and wraps a trusted bounded fixed systemd-start
callback; `start_fixture` is an explicit injected route. Checked `finish` removes
only matching owned bytes and reports uncertainty once. Unwind cleanup also
preserves changed foreign material. Revoked source configurations never regain
authority. The authorization consumer requires the borrowed Owner description,
exact canonical token, safe metadata and one link before unlink and parent sync.

Native dispatch remains unavailable. Concrete `ServingHost`, protected sandbox/
current-process bootstrap and full service-controller orchestration are not
implemented by this increment. A service with hidden /proc cannot substitute
synthetic process facts. Portable tests are not Linux execution or deployment
qualification. The parent separately validated the earlier 0940fc9 snapshot plus
its Linux patch; that evidence does not cover these newer native branches.

## Sandbox-safe core receiver and native composition

The subsequent core increment adds a separate `SandboxProcess` (actual PID/UID,
fixed cgroup and kernel execfn), because hidden proc cannot supply start ticks or
an executable digest. No placeholder full ProcessIdentity is constructed.
`acquire_serving_start` applies Go's receiver-side peer-UID/held-descriptor checks
and stable sandbox-visible observations. The existing Owner-side Handoff still
checks complete child executable/process proof. Existing sandbox failure
assertions remain; the fixture process literal now states only available facts.

The core concrete serving tests use real protected files, HTTP/Unix sockets and
descriptor lending with explicit synthetic kernel/service observations. Native
private dispatch revalidates local installed status and does not attempt online
acquisition in the AF_UNIX-only boot unit. It never constructs an authenticated
acquisition result from those local status checks. Native serving/start/stop,
quiescence and signal code is implemented but requires Linux execution and a
valid released Rust build; ordinary development binaries still refuse.
