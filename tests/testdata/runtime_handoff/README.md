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
