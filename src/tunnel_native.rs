//! Native dedicated-tunnel adapter. Register this file as `host::tunnel_native`
//! so protected filesystem/process helpers retain their existing visibility.
//! Native constructors are unreleased; all injected roots reject `/`.
use super::{
    HostError, Operation,
    filesystem::{Kind, ProtectedFs, Resource},
    locks::HostLock,
    process::{self, Cancellation, CommandOutput},
};
use crate::{
    durable::OwnershipStore,
    records::{OwnershipRecord, ReleaseIdentity, sha256_hex},
    release_acquisition::AuthenticatedInstalled,
    runtime_handoff::{self, ProcessIdentity},
    server_configuration::{ServerConfiguration, tunnel_unit},
    tunnel_setup::{
        self as t, Budget, EgressReply, EgressRequest, FileFacts, ListenerProof, Prerequisites,
        ProbePlan, ProbeProblem, ProbeSession, WebSocketReply, WebSocketRequest,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::{
    fs::{Mode, OFlags},
    process::{Pid, Signal, WaitId, WaitIdOptions},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt,
    future::Future,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    os::{fd::AsFd, unix::process::CommandExt},
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const TOKEN: &str = "etc/cloudflared/sbxr.token";
const BINARY: &str = "usr/bin/cloudflared";
const UNIT: &str = "etc/systemd/system/sbxr-tunnel.service";
const LINK: &str = "etc/systemd/system/multi-user.target.wants/sbxr-tunnel.service";
const GROUP: &str = "/system.slice/sbxr-tunnel.service";
const EXEC: &str = "/usr/bin/cloudflared --config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file /run/credentials/sbxr-tunnel.service/tunnel-token";
const POLL: Duration = Duration::from_millis(20);
fn refused(_: impl fmt::Debug) -> t::Error {
    t::Error::Authority
}
fn host_error(e: HostError) -> t::Error {
    match e {
        HostError::Cancelled => t::Error::Interrupted,
        HostError::Timeout => t::Error::TimedOut,
        _ => t::Error::Authority,
    }
}
fn budget(b: &Budget<'_>) -> Result<Duration, ProbeProblem> {
    b.remaining().map_err(|e| {
        if e == t::Error::Interrupted {
            ProbeProblem::Cancelled
        } else {
            ProbeProblem::TimedOut
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorQuery {
    Version,
    Properties,
    Listener(u16),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorAction {
    Reload,
    Start,
    StopDisable,
}
impl ConnectorAction {
    pub fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Reload => &["daemon-reload"],
            Self::Start => &["start", "sbxr-tunnel.service"],
            Self::StopDisable => &["disable", "--now", "sbxr-tunnel.service"],
        }
    }
}
/// Injection is for synthetic systems. Native commands use only the closed
/// vocabulary above; a successful command never substitutes for ownership.
pub trait ConnectorIo {
    fn query(
        &self,
        q: ConnectorQuery,
        stop: &Cancellation,
        timeout: Duration,
    ) -> Result<CommandOutput, HostError>;
    fn command(
        &self,
        a: ConnectorAction,
        owner: &Arc<HostLock>,
        stop: &Cancellation,
    ) -> Result<(), HostError>;
    fn process(&self, pid: u32) -> Result<ProcessIdentity, HostError>;
    fn quiescent(&self, stop: &Cancellation) -> Result<bool, HostError>;
}
#[derive(Clone, Copy)]
pub struct NativeConnectorIo;
impl NativeConnectorIo {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stop: &Cancellation,
        timeout: Duration,
    ) -> Result<CommandOutput, HostError> {
        super::linux::require_native_environment()?;
        let fs = ProtectedFs::native()?;
        let path = program.strip_prefix('/').ok_or(HostError::Unsafe)?;
        let (_, before) = fs
            .raw(path, Mode::from_raw_mode(0o755), 128 << 20)?
            .ok_or(HostError::Foreign)?;
        if before.gid != 0 {
            return Err(HostError::Foreign);
        }
        let out = process::run_in(
            program,
            args,
            "/",
            timeout.min(Duration::from_secs(15)),
            64 << 10,
            stop,
        )?;
        let (_, after) = fs
            .raw(path, Mode::from_raw_mode(0o755), 128 << 20)?
            .ok_or(HostError::Foreign)?;
        if before != after {
            return Err(HostError::Unsafe);
        }
        Ok(out)
    }
}
const PROPERTIES: &str = "--property=LoadState,FragmentPath,DropInPaths,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStart,ExecStop,ExecStopPost,KillMode,DynamicUser,LoadCredential,ActiveState,MainPID,ControlPID,ControlGroup";
impl ConnectorIo for NativeConnectorIo {
    fn query(
        &self,
        q: ConnectorQuery,
        stop: &Cancellation,
        timeout: Duration,
    ) -> Result<CommandOutput, HostError> {
        match q {
            ConnectorQuery::Version => {
                self.run("/usr/bin/cloudflared", &["--version"], stop, timeout)
            }
            ConnectorQuery::Properties => self.run(
                "/usr/bin/systemctl",
                &["show", PROPERTIES, "sbxr-tunnel.service"],
                stop,
                timeout,
            ),
            ConnectorQuery::Listener(port) => {
                let p = format!(":{port}");
                self.run(
                    "/usr/bin/ss",
                    &["-H", "-ltnp", "sport", "=", &p],
                    stop,
                    timeout,
                )
            }
        }
    }
    fn command(
        &self,
        a: ConnectorAction,
        g: &Arc<HostLock>,
        stop: &Cancellation,
    ) -> Result<(), HostError> {
        if g.root() != Path::new("/") {
            return Err(HostError::Unsafe);
        }
        g.verify()?;
        let out = self.run(
            "/usr/bin/systemctl",
            a.arguments(),
            stop,
            Duration::from_secs(15),
        )?;
        g.verify()?;
        if out.code() != 0 {
            return Err(HostError::Io);
        }
        Ok(())
    }
    fn process(&self, pid: u32) -> Result<ProcessIdentity, HostError> {
        runtime_handoff::linux_process(pid).map_err(|_| HostError::Foreign)
    }
    fn quiescent(&self, stop: &Cancellation) -> Result<bool, HostError> {
        super::linux::require_native_environment()?;
        for _ in 0..2 {
            if stop.cancelled() {
                return Err(HostError::Cancelled);
            }
            let base = Path::new("/sys/fs/cgroup/system.slice");
            let parent = rustix::fs::open(
                base,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| HostError::Unsafe)?;
            let meta = rustix::fs::fstat(&parent).map_err(|_| HostError::Unsafe)?;
            if meta.st_uid != 0 || meta.st_mode & 0o022 != 0 {
                return Err(HostError::Unsafe);
            }
            let group = match rustix::fs::openat(
                &parent,
                "sbxr-tunnel.service",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(_) => return Err(HostError::Unsafe),
            };
            let meta = rustix::fs::fstat(&group).map_err(|_| HostError::Unsafe)?;
            if meta.st_uid != 0 || meta.st_mode & 0o022 != 0 {
                return Err(HostError::Unsafe);
            }
            let fd = rustix::fs::openat(
                &group,
                "cgroup.events",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| HostError::Unsafe)?;
            let mut bytes = Vec::new();
            std::fs::File::from(fd)
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| HostError::Io)?;
            if bytes.len() > 4096
                || !std::str::from_utf8(&bytes).is_ok_and(|s| {
                    s.lines()
                        .filter(|l| l.starts_with("populated "))
                        .eq(["populated 0"])
                })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorInspection {
    pub fingerprint: String,
    pub empty: bool,
    pub installed: bool,
    pub stopped: bool,
    pub running: bool,
}
pub struct Connector<I> {
    fs: ProtectedFs,
    io: I,
}
impl Connector<NativeConnectorIo> {
    pub fn native_unreleased() -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        Ok(Self {
            fs: ProtectedFs::native()?,
            io: NativeConnectorIo,
        })
    }
}
impl<I: ConnectorIo> Connector<I> {
    pub fn injected(root: &Path, io: I) -> Result<Self, HostError> {
        if root == Path::new("/") {
            return Err(HostError::LiveUnavailable);
        }
        Ok(Self {
            fs: ProtectedFs::open(root)?,
            io,
        })
    }
    pub fn prerequisites(&self, stop: &Cancellation) -> Result<Prerequisites, t::Error> {
        if stop.cancelled() {
            return Err(t::Error::Interrupted);
        }
        let (token, tp) = self
            .fs
            .raw(TOKEN, Mode::from_raw_mode(0o600), 16384)
            .map_err(|_| t::Error::TokenFile)?
            .ok_or(t::Error::TokenFile)?;
        let token = Zeroizing::new(token);
        let (binary, bp) = self
            .fs
            .raw(BINARY, Mode::from_raw_mode(0o755), 128 << 20)
            .map_err(|_| t::Error::BinaryFile)?
            .ok_or(t::Error::BinaryFile)?;
        if tp.gid != self.fs.gid || bp.gid != self.fs.gid {
            return Err(t::Error::Authority);
        }
        let out = self
            .io
            .query(ConnectorQuery::Version, stop, Duration::from_secs(5))
            .map_err(host_error)?;
        if out.code() != 0 {
            return Err(t::Error::BinaryVersion);
        }
        let facts = |mode| FileFacts {
            uid: 0,
            mode,
            links: 1,
            regular: true,
            stable: true,
            protected_parents: true,
        };
        // Injected roots use a virtual root owner. Native ProtectedFs requires uid 0.
        let result = Prerequisites::inspect(
            &token,
            facts(0o600),
            &binary,
            facts(0o755),
            out.text().map_err(|_| t::Error::BinaryVersion)?,
        )?;
        let after_token = self
            .fs
            .raw(TOKEN, Mode::from_raw_mode(0o600), 16384)
            .map_err(|_| t::Error::TokenFile)?
            .ok_or(t::Error::TokenFile)?;
        let after_token = (Zeroizing::new(after_token.0), after_token.1);
        let after_binary = self
            .fs
            .raw(BINARY, Mode::from_raw_mode(0o755), 128 << 20)
            .map_err(|_| t::Error::BinaryFile)?
            .ok_or(t::Error::BinaryFile)?;
        if tp != after_token.1
            || bp != after_binary.1
            || token.as_slice() != after_token.0.as_slice()
            || binary != after_binary.0
        {
            return Err(t::Error::PrerequisitesChanged);
        }
        if stop.cancelled() {
            return Err(t::Error::Interrupted);
        }
        Ok(result)
    }
    fn properties(&self, stop: &Cancellation) -> Result<BTreeMap<String, String>, t::Error> {
        let out = self
            .io
            .query(ConnectorQuery::Properties, stop, Duration::from_secs(5))
            .map_err(host_error)?;
        if out.code() != 0 {
            return Err(t::Error::Authority);
        }
        let mut p = BTreeMap::new();
        for line in out.text().map_err(refused)?.lines() {
            let (k, v) = line.split_once('=').ok_or(t::Error::Authority)?;
            if p.insert(k.into(), v.into()).is_some() {
                return Err(t::Error::Authority);
            }
        }
        Ok(p)
    }
    fn files(&self, owned: bool) -> Result<(bool, bool, bool, String), t::Error> {
        let mut proof = String::new();
        for dir in [
            "etc/systemd/system",
            "run/systemd/system",
            "usr/local/lib/systemd/system",
            "usr/lib/systemd/system",
            "lib/systemd/system",
            "etc/systemd/system.control",
            "run/systemd/system.control",
            "run/systemd/transient",
        ] {
            if dir.starts_with("lib/")
                && self
                    .fs
                    .metadata("lib")
                    .map_err(refused)?
                    .is_some_and(|m| m.kind == rustix::fs::FileType::Symlink)
            {
                // Ubuntu's merged-/usr alias is admitted only at this exact target.
                self.fs
                    .observe(Resource {
                        path: "lib",
                        kind: Kind::Link("usr/lib"),
                    })
                    .map_err(refused)?
                    .ok_or(t::Error::Authority)?;
                continue;
            }
            for suffix in [
                "sbxr-tunnel.service",
                "sbxr-tunnel.service.d",
                "multi-user.target.wants/sbxr-tunnel.service",
                "multi-user.target.requires/sbxr-tunnel.service",
            ] {
                let path = format!("{dir}/{suffix}");
                if owned && (path == UNIT || path == LINK) {
                    continue;
                }
                if self.fs.metadata(&path).map_err(refused)?.is_some() {
                    return Err(t::Error::Authority);
                }
            }
        }
        let mut unit = false;
        let mut staged = false;
        for (path, present) in [
            (UNIT, &mut unit),
            (
                "etc/systemd/system/sbxr-tunnel.service.sbxr-next",
                &mut staged,
            ),
        ] {
            if let Some((bytes, p)) = self
                .fs
                .raw(path, Mode::from_raw_mode(0o644), 8192)
                .map_err(refused)?
            {
                if !owned || bytes != tunnel_unit().as_bytes() || p.gid != self.fs.gid {
                    return Err(t::Error::Authority);
                }
                *present = true;
                proof.push_str(&format!("{p:?}"));
            }
        }
        let link = self
            .fs
            .observe(Resource {
                path: LINK,
                kind: Kind::Link("../sbxr-tunnel.service"),
            })
            .map_err(refused)?;
        if link.is_some() && !owned {
            return Err(t::Error::Authority);
        }
        proof.push_str(&format!("{link:?}"));
        Ok((unit, link.is_some(), staged, proof))
    }
    pub fn inspect(
        &self,
        owned: bool,
        stop: &Cancellation,
    ) -> Result<ConnectorInspection, t::Error> {
        self.inspect_with_digest(owned, None, stop)
    }
    fn inspect_with_digest(
        &self,
        owned: bool,
        expected_binary: Option<&str>,
        stop: &Cancellation,
    ) -> Result<ConnectorInspection, t::Error> {
        if stop.cancelled() {
            return Err(t::Error::Interrupted);
        }
        let (unit, link, staged, proof) = self.files(owned)?;
        let p = self.properties(stop)?;
        let get = |key: &str| p.get(key).map(String::as_str).ok_or(t::Error::Authority);
        let stopped = matches!(get("ActiveState")?, "inactive" | "failed")
            && get("MainPID")? == "0"
            && get("ControlPID")? == "0"
            && matches!(get("ControlGroup")?, "" | GROUP)
            && self.io.quiescent(stop).map_err(host_error)?;
        let load = get("LoadState")?;
        if load == "not-found" {
            for key in [
                "FragmentPath",
                "DropInPaths",
                "ExecStart",
                "ExecCondition",
                "ExecStartPre",
                "ExecStartPost",
                "ExecReload",
                "ExecStop",
                "ExecStopPost",
                "LoadCredential",
            ] {
                if p.get(key).is_some_and(|v| !v.is_empty()) {
                    return Err(t::Error::Authority);
                }
            }
            if !stopped {
                return Err(t::Error::Authority);
            }
        } else {
            if !unit
                || load != "loaded"
                || get("FragmentPath")? != "/etc/systemd/system/sbxr-tunnel.service"
                || get("KillMode")? != "control-group"
                || get("DynamicUser")? != "yes"
                || get("LoadCredential")? != "tunnel-token:/etc/cloudflared/sbxr.token"
            {
                return Err(t::Error::Authority);
            }
            for key in [
                "DropInPaths",
                "ExecCondition",
                "ExecStartPre",
                "ExecStartPost",
                "ExecReload",
                "ExecStop",
                "ExecStopPost",
            ] {
                if !get(key)?.is_empty() {
                    return Err(t::Error::Authority);
                }
            }
            if !super::owner_runtime::exact_connector_exec(
                get("ExecStart")?,
                "/usr/bin/cloudflared",
                EXEC,
            ) {
                return Err(t::Error::Authority);
            }
        }
        let installed = unit && link && !staged && load == "loaded";
        let mut running = false;
        if get("ActiveState")? == "active" {
            let pid = get("MainPID")?.parse::<u32>().map_err(refused)?;
            if !installed || pid < 2 || get("ControlPID")? != "0" || get("ControlGroup")? != GROUP {
                return Err(t::Error::Authority);
            }
            let process = self.io.process(pid).map_err(host_error)?;
            let expected = if let Some(digest) = expected_binary {
                digest.to_owned()
            } else {
                let binary = self
                    .fs
                    .raw(BINARY, Mode::from_raw_mode(0o755), 128 << 20)
                    .map_err(refused)?
                    .ok_or(t::Error::Authority)?;
                sha256_hex(&binary.0)
            };
            if process.pid != pid
                || process.uid == 0
                || process.cgroup != GROUP
                || process.executable_sha256 != expected
                || self.io.process(pid).map_err(host_error)? != process
            {
                return Err(t::Error::Authority);
            }
            running = true;
        } else if !stopped {
            return Err(t::Error::Authority);
        }
        let fingerprint = sha256_hex(format!("{proof}:{p:?}").as_bytes());
        Ok(ConnectorInspection {
            fingerprint,
            empty: !unit && !link && !staged && load == "not-found" && stopped,
            installed,
            stopped,
            running,
        })
    }
    fn install_scoped(&mut self, g: &Arc<HostLock>, stop: &Cancellation) -> Result<(), t::Error> {
        let before = self.inspect(true, stop)?;
        if !before.stopped && !before.running {
            return Err(t::Error::Authority);
        }
        self.fs
            .publish_bytes(UNIT, tunnel_unit().as_bytes(), Mode::from_raw_mode(0o644))
            .map_err(refused)?;
        self.fs
            .install(Resource {
                path: LINK,
                kind: Kind::Link("../sbxr-tunnel.service"),
            })
            .map_err(refused)?;
        self.io
            .command(ConnectorAction::Reload, g, stop)
            .map_err(host_error)?;
        if !self.inspect(true, stop)?.installed {
            return Err(t::Error::Authority);
        }
        g.verify().map_err(refused)
    }
    fn start_scoped(&mut self, g: &Arc<HostLock>, stop: &Cancellation) -> Result<(), t::Error> {
        if !self.inspect(true, stop)?.installed {
            return Err(t::Error::Authority);
        }
        self.io
            .command(ConnectorAction::Start, g, stop)
            .map_err(host_error)?;
        if !self.inspect(true, stop)?.running {
            return Err(t::Error::Authority);
        }
        g.verify().map_err(refused)
    }
    fn remove_scoped(
        &mut self,
        g: &Arc<HostLock>,
        authority: &crate::records::TunnelAuthority,
        stop: &Cancellation,
    ) -> Result<(), t::Error> {
        let state = self.inspect_with_digest(true, Some(authority.binary_sha256()), stop)?;
        if state.empty {
            return Ok(());
        }
        // No prerequisite read: missing Owner token/binary cannot prevent cleanup.
        // Running cleanup still proves process ownership in inspect above.
        self.io
            .command(ConnectorAction::StopDisable, g, stop)
            .map_err(host_error)?;
        if !self.inspect(true, stop)?.stopped {
            return Err(t::Error::Authority);
        }
        self.fs
            .remove(Resource {
                path: LINK,
                kind: Kind::Link("../sbxr-tunnel.service"),
            })
            .map_err(refused)?;
        for path in [UNIT, "etc/systemd/system/sbxr-tunnel.service.sbxr-next"] {
            self.fs
                .remove_bytes(path, tunnel_unit().as_bytes(), Mode::from_raw_mode(0o644))
                .map_err(refused)?;
        }
        self.io
            .command(ConnectorAction::Reload, g, stop)
            .map_err(host_error)?;
        if !self.inspect(true, stop)?.empty {
            return Err(t::Error::Authority);
        }
        g.verify().map_err(refused)
    }
    pub fn install(&mut self, g: &Arc<HostLock>, stop: &Cancellation) -> Result<(), t::Error> {
        self.with_owner(g, |this| this.install_scoped(g, stop))
    }
    pub fn start(&mut self, g: &Arc<HostLock>, stop: &Cancellation) -> Result<(), t::Error> {
        self.with_owner(g, |this| this.start_scoped(g, stop))
    }
    pub fn remove(
        &mut self,
        g: &Arc<HostLock>,
        authority: &crate::records::TunnelAuthority,
        stop: &Cancellation,
    ) -> Result<(), t::Error> {
        self.with_owner(g, |this| this.remove_scoped(g, authority, stop))
    }
    fn with_owner<T>(
        &mut self,
        g: &Arc<HostLock>,
        effect: impl FnOnce(&mut Self) -> Result<T, t::Error>,
    ) -> Result<T, t::Error> {
        self.authorize(g)?;
        let result = effect(self);
        self.fs.authorize_native_writes(None).map_err(refused)?;
        result
    }
    fn authorize(&mut self, g: &Arc<HostLock>) -> Result<(), t::Error> {
        if g.root() != self.fs.path() {
            return Err(t::Error::Authority);
        }
        g.verify().map_err(refused)?;
        if self.fs.path() == Path::new("/") {
            self.fs
                .authorize_native_writes(Some(g.clone()))
                .map_err(refused)?;
        }
        Ok(())
    }
}

/// Direct HTTP/1.1 transport. DNS/connect use bounded cancellable transports;
/// socket/TLS I/O shares one deadline and a fixed polling interval.
#[derive(Clone)]
pub struct ProbeNetwork {
    tls: Arc<rustls::ClientConfig>,
    fixture: Option<Arc<LoopbackNetwork>>,
}
#[derive(Clone)]
pub struct LoopbackNetwork {
    pub local_origin: SocketAddrV4,
    pub public_hostname: String,
    pub public_address: SocketAddrV4,
}
impl ProbeNetwork {
    pub fn native() -> Result<Self, ProbeProblem> {
        Self::configured(
            rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            None,
        )
    }
    pub fn injected(
        roots: rustls::RootCertStore,
        fixture: LoopbackNetwork,
    ) -> Result<Self, ProbeProblem> {
        if !fixture.local_origin.ip().is_loopback()
            || !fixture.public_address.ip().is_loopback()
            || fixture.local_origin.port() == 0
            || fixture.public_address.port() == 0
            || !crate::subscription_artifact::valid_vmess_hostname(&fixture.public_hostname)
        {
            return Err(ProbeProblem::Authority);
        }
        Self::configured(roots, Some(Arc::new(fixture)))
    }
    fn configured(
        roots: rustls::RootCertStore,
        fixture: Option<Arc<LoopbackNetwork>>,
    ) -> Result<Self, ProbeProblem> {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| ProbeProblem::TlsHandshake)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(tls),
            fixture,
        })
    }
    fn wait<T>(
        &self,
        b: &Budget<'_>,
        deadline: Instant,
        f: impl Future<Output = Result<T, ProbeProblem>>,
    ) -> Result<T, ProbeProblem> {
        budget(b)?;
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ProbeProblem::Network);
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProbeProblem::Network)?;
        let result=rt.block_on(async{tokio::select!{result=f=>result,_=async{loop{if b.cancellation().cancelled()||Instant::now()>=deadline{break}tokio::time::sleep(POLL).await;}}=>Err(if b.cancellation().cancelled(){ProbeProblem::Cancelled}else{ProbeProblem::TimedOut})}});
        budget(b)?;
        if Instant::now() >= deadline {
            return Err(ProbeProblem::TimedOut);
        }
        result
    }
    fn connect(
        &self,
        host: &str,
        port: u16,
        b: &Budget<'_>,
        deadline: Instant,
        override_address: Option<SocketAddrV4>,
    ) -> Result<BoundedTcp, ProbeProblem> {
        // getent runs in the shared bounded process transport. A libc DNS
        // worker in a dropped async runtime could otherwise outlive the budget.
        let addresses = if let Some(address) = override_address {
            vec![SocketAddr::V4(address)]
        } else {
            budget(b)?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(ProbeProblem::TimedOut)?;
            let out = NativeConnectorIo
                .run(
                    "/usr/bin/getent",
                    &["ahosts", host],
                    b.cancellation(),
                    remaining,
                )
                .map_err(|e| match e {
                    HostError::Cancelled => ProbeProblem::Cancelled,
                    HostError::Timeout => ProbeProblem::TimedOut,
                    _ => ProbeProblem::Dns,
                })?;
            if out.code() != 0 {
                return Err(ProbeProblem::Dns);
            }
            let mut addresses = std::collections::BTreeSet::new();
            for line in out.text().map_err(|_| ProbeProblem::Dns)?.lines() {
                let ip = line
                    .split_whitespace()
                    .next()
                    .ok_or(ProbeProblem::Dns)?
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| ProbeProblem::Dns)?;
                addresses.insert(SocketAddr::new(ip, port));
                if addresses.len() > 64 {
                    return Err(ProbeProblem::Dns);
                }
            }
            if addresses.is_empty() {
                return Err(ProbeProblem::Dns);
            }
            addresses.into_iter().collect()
        };
        let stream = self.wait(b, deadline, async {
            let mut result = None;
            for address in addresses {
                if let Ok(s) = tokio::net::TcpStream::connect(address).await {
                    result = Some(s);
                    break;
                }
            }
            let stream = result
                .ok_or(ProbeProblem::Network)?
                .into_std()
                .map_err(|_| ProbeProblem::Network)?;
            stream
                .set_nonblocking(false)
                .map_err(|_| ProbeProblem::Network)?;
            Ok(stream)
        })?;
        Ok(BoundedTcp {
            stream,
            stop: b.cancellation().clone(),
            deadline,
        })
    }
    fn tls(
        &self,
        socket: BoundedTcp,
        host: &str,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, BoundedTcp>, ProbeProblem> {
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| ProbeProblem::TlsHandshake)?;
        let conn = rustls::ClientConnection::new(self.tls.clone(), name)
            .map_err(|_| ProbeProblem::TlsHandshake)?;
        let mut tls = rustls::StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(tls_problem)?;
        }
        if tls.conn.alpn_protocol().is_some_and(|a| a != b"http/1.1") {
            return Err(ProbeProblem::TlsHandshake);
        }
        Ok(tls)
    }
    pub fn websocket(
        &self,
        r: &WebSocketRequest,
        b: &Budget<'_>,
    ) -> Result<WebSocketReply, ProbeProblem> {
        let deadline = Instant::now() + budget(b)?.min(r.timeout());
        let url = reqwest::Url::parse(&r.url()).map_err(|_| ProbeProblem::Authority)?;
        let host = url.host_str().ok_or(ProbeProblem::Authority)?;
        let (port, override_address) = if r.trusted_tls_required() {
            if let Some(f) = &self.fixture {
                if host != f.public_hostname {
                    return Err(ProbeProblem::Authority);
                }
                (443, Some(f.public_address))
            } else {
                (443, None)
            }
        } else {
            (
                10000,
                Some(
                    self.fixture
                        .as_ref()
                        .map_or(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10000), |f| {
                            f.local_origin
                        }),
                ),
            )
        };
        let socket = self.connect(host, port, b, deadline, override_address)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n",
            crate::subscription_artifact::VMESS_WEBSOCKET_PATH,
            if r.trusted_tls_required() {
                host
            } else {
                "127.0.0.1:10000"
            },
            r.key()
        );
        let response = if r.trusted_tls_required() {
            let mut tls = self.tls(socket, host)?;
            exchange_headers(&mut tls, request.as_bytes(), r.max_header_bytes())
        } else {
            let mut socket = socket;
            exchange_headers(&mut socket, request.as_bytes(), r.max_header_bytes())
        };
        budget(b)?;
        let (status, headers) = response?;
        Ok(WebSocketReply {
            status,
            headers,
            trusted_tls: r.trusted_tls_required(),
            redirected: (300..400).contains(&status),
        })
    }
    fn egress(&self, r: &EgressRequest<'_>, b: &Budget<'_>) -> Result<EgressReply, ProbeProblem> {
        let deadline = Instant::now() + budget(b)?.min(r.timeout());
        let mut socket = self.connect(
            "127.0.0.1",
            r.proxy_address().port(),
            b,
            deadline,
            Some(r.proxy_address()),
        )?;
        let credentials = Zeroizing::new(format!("{}:{}", r.username(), r.password()));
        let auth = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
        let request = Zeroizing::new(format!(
            "CONNECT api.ipify.org:443 HTTP/1.1\r\nHost: api.ipify.org:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
            auth.as_str()
        ));
        let (status, headers) = exchange_headers(&mut socket, request.as_bytes(), 16 << 10)?;
        if status != 200
            || headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("location"))
        {
            return Err(if (300..400).contains(&status) {
                ProbeProblem::Redirect
            } else {
                ProbeProblem::Traffic
            });
        }
        let mut tls = self.tls(socket, "api.ipify.org")?;
        let(status,headers)=exchange_headers(&mut tls,b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",16<<10)?;
        budget(b)?;
        if (300..400).contains(&status)
            || headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("location"))
        {
            return Err(ProbeProblem::Redirect);
        }
        if status != 200 {
            return Err(ProbeProblem::Http(status));
        }
        // A tiny fixed response needs no general transfer-decoding framework.
        let mut length = None;
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("transfer-encoding")
                || k.eq_ignore_ascii_case("content-encoding")
            {
                return Err(ProbeProblem::Headers);
            }
            if k.eq_ignore_ascii_case("content-length") {
                let n = v.parse::<usize>().map_err(|_| ProbeProblem::Headers)?;
                if length.replace(n).is_some() || n >= r.max_body_bytes() {
                    return Err(ProbeProblem::Egress);
                }
            }
        }
        let mut body = Vec::new();
        let mut byte = [0];
        while length.is_none_or(|n| body.len() < n) {
            budget(b)?;
            match tls.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if body.len() + 1 >= r.max_body_bytes() {
                        return Err(ProbeProblem::Egress);
                    }
                    body.push(byte[0]);
                }
                Err(e) => return Err(io_problem(e)),
            }
        }
        if length.is_some_and(|n| n != body.len()) {
            return Err(ProbeProblem::Egress);
        }
        budget(b)?;
        Ok(EgressReply {
            status,
            body,
            trusted_tls: true,
            authenticated_proxy: true,
            redirected: false,
        })
    }
}
fn tls_problem(e: io::Error) -> ProbeProblem {
    if let Some(error) = e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        return if matches!(error, rustls::Error::InvalidCertificate(_)) {
            ProbeProblem::TlsCertificate
        } else {
            ProbeProblem::TlsHandshake
        };
    }
    io_problem(e)
}
fn io_problem(e: io::Error) -> ProbeProblem {
    if e.get_ref().is_some_and(|e| e.is::<CancelledIo>()) {
        return ProbeProblem::Cancelled;
    }
    match e.kind() {
        io::ErrorKind::TimedOut => ProbeProblem::TimedOut,
        io::ErrorKind::Interrupted => ProbeProblem::Cancelled,
        _ => ProbeProblem::Network,
    }
}
#[derive(Debug)]
struct CancelledIo;
impl fmt::Display for CancelledIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cancelled")
    }
}
impl std::error::Error for CancelledIo {}
struct BoundedTcp {
    stream: TcpStream,
    stop: Cancellation,
    deadline: Instant,
}
impl BoundedTcp {
    fn remaining(&self) -> io::Result<Duration> {
        if self.stop.cancelled() {
            return Err(io::Error::other(CancelledIo));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .map(|d| d.min(POLL))
            .ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
}
impl Read for BoundedTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            match self.stream.read(buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}
impl Write for BoundedTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match self.stream.write(buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
fn exchange_headers(
    s: &mut (impl Read + Write),
    request: &[u8],
    limit: usize,
) -> Result<(u16, Vec<(String, String)>), ProbeProblem> {
    s.write_all(request).map_err(io_problem)?;
    s.flush().map_err(io_problem)?;
    let mut bytes = Vec::new();
    let mut byte = [0];
    // Read exactly through CRLFCRLF; TLS bytes after a proxy CONNECT stay unread.
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= limit {
            return Err(ProbeProblem::Headers);
        }
        if s.read(&mut byte).map_err(io_problem)? != 1 {
            return Err(ProbeProblem::Headers);
        }
        bytes.push(byte[0]);
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    if !matches!(parsed.parse(&bytes), Ok(httparse::Status::Complete(_)))
        || parsed.version != Some(1)
    {
        return Err(ProbeProblem::Headers);
    }
    let status = parsed.code.ok_or(ProbeProblem::Headers)?;
    let headers = parsed
        .headers
        .iter()
        .map(|h| {
            Ok((
                h.name.to_owned(),
                std::str::from_utf8(h.value)
                    .map_err(|_| ProbeProblem::Headers)?
                    .to_owned(),
            ))
        })
        .collect::<Result<_, _>>()?;
    Ok((status, headers))
}

pub trait ProbeObservations {
    fn process(&self, pid: u32) -> Result<ProcessIdentity, ProbeProblem>;
    fn listeners(&self, port: u16, b: &Budget<'_>) -> Result<String, ProbeProblem>;
}
#[derive(Clone, Copy)]
pub struct NativeProbeObservations;
impl ProbeObservations for NativeProbeObservations {
    fn process(&self, pid: u32) -> Result<ProcessIdentity, ProbeProblem> {
        runtime_handoff::linux_process(pid).map_err(|_| ProbeProblem::Listener)
    }
    fn listeners(&self, port: u16, b: &Budget<'_>) -> Result<String, ProbeProblem> {
        let out = NativeConnectorIo
            .query(
                ConnectorQuery::Listener(port),
                b.cancellation(),
                budget(b)?.min(Duration::from_secs(2)),
            )
            .map_err(|e| match e {
                HostError::Cancelled => ProbeProblem::Cancelled,
                HostError::Timeout => ProbeProblem::TimedOut,
                _ => ProbeProblem::Listener,
            })?;
        if out.code() != 0 {
            return Err(ProbeProblem::Listener);
        }
        Ok(out.text().map_err(|_| ProbeProblem::Listener)?.into())
    }
}
/// A waitable leader pins the process-group number until the group is killed.
/// No signal is ever sent to its group after the leader has been reaped.
struct ProbeChild {
    child: Child,
    group: Pid,
    reaped: bool,
    clean: bool,
}
impl ProbeChild {
    fn new(mut child: Child) -> Result<Self, ProbeProblem> {
        let group = Pid::from_raw(child.id() as i32).filter(|p| p.as_raw_nonzero().get() > 1);
        let Some(group) = group else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProbeProblem::Spawn);
        };
        if rustix::process::getpgid(Some(group)).ok() != Some(group) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProbeProblem::Spawn);
        }
        Ok(Self {
            child,
            group,
            reaped: false,
            clean: false,
        })
    }
    fn alive(&self) -> Result<bool, ProbeProblem> {
        if self.reaped {
            return Ok(false);
        }
        rustix::process::waitid(
            WaitId::Pid(self.group),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .map(|s| s.is_none())
        .map_err(|_| ProbeProblem::Exited)
    }
    fn send(&mut self, bytes: &[u8], b: &Budget<'_>) -> Result<(), ProbeProblem> {
        let mut stdin = self.child.stdin.take().ok_or(ProbeProblem::Spawn)?;
        let flags = rustix::fs::fcntl_getfl(stdin.as_fd()).map_err(|_| ProbeProblem::Spawn)?;
        rustix::fs::fcntl_setfl(stdin.as_fd(), flags | OFlags::NONBLOCK)
            .map_err(|_| ProbeProblem::Spawn)?;
        let mut sent = 0;
        while sent < bytes.len() {
            budget(b)?;
            if !self.alive()? {
                return Err(ProbeProblem::Exited);
            }
            match stdin.write(&bytes[sent..]) {
                Ok(0) => return Err(ProbeProblem::Spawn),
                Ok(n) => sent += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(POLL)
                }
                Err(_) => return Err(ProbeProblem::Spawn),
            }
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), ProbeProblem> {
        if self.reaped {
            return if self.clean {
                Ok(())
            } else {
                Err(ProbeProblem::Cleanup)
            };
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        match rustix::process::kill_process_group(self.group, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            // macOS can return EPERM for a group containing only a zombie.
            // Reap only an observed exited leader; still prove group absence.
            Err(rustix::io::Errno::PERM) if !self.alive().map_err(|_| ProbeProblem::Cleanup)? => {}
            Err(_) => return Err(ProbeProblem::Cleanup),
        }
        loop {
            if !self.alive().map_err(|_| ProbeProblem::Cleanup)? {
                break;
            }
            if Instant::now() >= deadline {
                return Err(ProbeProblem::Cleanup);
            }
            thread::sleep(POLL);
        }
        self.child.wait().map_err(|_| ProbeProblem::Cleanup)?;
        self.reaped = true;
        loop {
            match rustix::process::test_kill_process_group(self.group) {
                Err(rustix::io::Errno::SRCH) => {
                    self.clean = true;
                    return Ok(());
                }
                Err(_) => return Err(ProbeProblem::Cleanup),
                Ok(()) => {}
            }
            if Instant::now() >= deadline {
                return Err(ProbeProblem::Cleanup);
            }
            thread::sleep(POLL);
        }
    }
}
impl Drop for ProbeChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub struct NativeProbeSession<O = NativeProbeObservations> {
    child: ProbeChild,
    observations: O,
    network: ProbeNetwork,
    port: u16,
    password_sha256: String,
    executable_sha256: String,
    initial: Option<ProcessIdentity>,
}
impl NativeProbeSession<NativeProbeObservations> {
    fn spawn(
        plan: &ProbePlan,
        expected_sha256: &str,
        network: ProbeNetwork,
        b: &Budget<'_>,
    ) -> Result<Self, ProbeProblem> {
        super::linux::require_native_environment().map_err(|_| ProbeProblem::Authority)?;
        if network.fixture.is_some() {
            return Err(ProbeProblem::Authority);
        }
        let fs = ProtectedFs::native().map_err(|_| ProbeProblem::Authority)?;
        let (bytes, before) = fs
            .raw("usr/bin/sing-box", Mode::from_raw_mode(0o755), 256 << 20)
            .map_err(|_| ProbeProblem::Authority)?
            .ok_or(ProbeProblem::Authority)?;
        if sha256_hex(&bytes) != expected_sha256 || before.gid != 0 {
            return Err(ProbeProblem::Authority);
        }
        budget(b)?;
        let child = Command::new("/usr/bin/sing-box")
            .args(["run", "-c", "/dev/stdin"])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .map_err(|_| ProbeProblem::Spawn)?;
        let mut child = ProbeChild::new(child)?;
        child.send(plan.as_bytes(), b)?;
        let after = fs
            .raw("usr/bin/sing-box", Mode::from_raw_mode(0o755), 256 << 20)
            .map_err(|_| ProbeProblem::Authority)?
            .ok_or(ProbeProblem::Authority)?;
        if before != after.1 || bytes != after.0 {
            return Err(ProbeProblem::Authority);
        }
        Self::construct(
            child,
            plan,
            expected_sha256,
            NativeProbeObservations,
            network,
        )
    }
}
impl<O: ProbeObservations> NativeProbeSession<O> {
    /// Own an already spawned synthetic child in a caller-owned process group.
    /// This constructor executes nothing and cannot be used with the native root.
    pub fn injected(
        root: &Path,
        child: Child,
        plan: &ProbePlan,
        expected_sha256: &str,
        observations: O,
        network: ProbeNetwork,
        b: &Budget<'_>,
    ) -> Result<Self, ProbeProblem> {
        let mut child = ProbeChild::new(child)?;
        if root == Path::new("/") || network.fixture.is_none() {
            return Err(ProbeProblem::Authority);
        }
        ProtectedFs::open(root).map_err(|_| ProbeProblem::Authority)?;
        child.send(plan.as_bytes(), b)?;
        Self::construct(child, plan, expected_sha256, observations, network)
    }
    fn construct(
        child: ProbeChild,
        plan: &ProbePlan,
        expected: &str,
        observations: O,
        network: ProbeNetwork,
    ) -> Result<Self, ProbeProblem> {
        let value: serde_json::Value =
            serde_json::from_slice(plan.as_bytes()).map_err(|_| ProbeProblem::Authority)?;
        let password = value["inbounds"][0]["users"][0]["password"]
            .as_str()
            .ok_or(ProbeProblem::Authority)?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(ProbeProblem::Authority);
        }
        Ok(Self {
            child,
            observations,
            network,
            port: plan.port(),
            password_sha256: sha256_hex(password.as_bytes()),
            executable_sha256: expected.into(),
            initial: None,
        })
    }
    fn identity(&self) -> Result<ProcessIdentity, ProbeProblem> {
        if !self.child.alive()? {
            return Err(ProbeProblem::Exited);
        }
        let process = self.observations.process(self.child.child.id())?;
        if process.pid != self.child.child.id()
            || process.parent_pid != std::process::id()
            || process.uid != rustix::process::geteuid().as_raw()
            || process.executable_sha256 != self.executable_sha256
            || rustix::process::getpgid(Some(self.child.group)).ok() != Some(self.child.group)
            || self.initial.as_ref().is_some_and(|p| p != &process)
        {
            return Err(ProbeProblem::Listener);
        }
        ProcessIdentity::new(
            process.pid,
            process.parent_pid,
            process.start_ticks,
            process.uid,
            &process.executable_sha256,
            &process.cgroup,
        )
        .map_err(|_| ProbeProblem::Listener)?;
        Ok(process)
    }
}
fn exclusive_listener(text: &str, port: u16, pid: u32) -> bool {
    let lines = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return false;
    }
    let line = lines[0];
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 6
        || fields[0] != "LISTEN"
        || fields[3] != format!("127.0.0.1:{port}")
        || line.matches("pid=").count() != 1
    {
        return false;
    }
    let Some(value) = line
        .split_once("pid=")
        .and_then(|(_, v)| v.split_once(','))
        .map(|(p, _)| p)
    else {
        return false;
    };
    value == pid.to_string()
}
impl<O: ProbeObservations> ProbeSession for NativeProbeSession<O> {
    fn listener(&mut self, b: &Budget<'_>) -> Result<ListenerProof, ProbeProblem> {
        let deadline = Instant::now() + budget(b)?.min(Duration::from_secs(5));
        loop {
            budget(b)?;
            let process = self.identity()?;
            let listeners = self.observations.listeners(self.port, b)?;
            if !listeners.trim().is_empty() {
                if !exclusive_listener(&listeners, self.port, process.pid)
                    || self.identity()? != process
                {
                    return Err(ProbeProblem::Listener);
                }
                self.initial = Some(process.clone());
                return Ok(ListenerProof {
                    listener_pid: process.pid,
                    process,
                    address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port),
                    exclusive: true,
                    process_alive: true,
                });
            }
            if Instant::now() >= deadline {
                return Err(ProbeProblem::Listener);
            }
            thread::sleep(POLL);
        }
    }
    fn egress(
        &mut self,
        r: &EgressRequest<'_>,
        b: &Budget<'_>,
    ) -> Result<EgressReply, ProbeProblem> {
        use subtle::ConstantTimeEq;
        if r.proxy_address() != SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)
            || r.username() != "sbxr-probe"
            || !bool::from(
                self.password_sha256
                    .as_bytes()
                    .ct_eq(sha256_hex(r.password().as_bytes()).as_bytes()),
            )
        {
            return Err(ProbeProblem::Authority);
        }
        self.listener(b)?;
        let reply = self.network.egress(r, b)?;
        self.listener(b)?;
        Ok(reply)
    }
    fn stop_and_reap(&mut self) -> Result<(), ProbeProblem> {
        self.child.stop()
    }
}

/// The shared Standard host owns package/material effects. Core integration must
/// implement this bridge with its existing protected adapter, using this exact
/// retained Owner guard rather than acquiring another mutation lock.
/// `probe_sha256` must authenticate the pinned package binary, not trust a hash
/// obtained solely from the current filesystem or a version string.
pub trait StandardHost {
    fn effects_available(&self) -> bool {
        false
    }
    fn root(&self) -> &Path;
    fn verify_installed(&mut self, proof: &AuthenticatedInstalled) -> Result<(), HostError>;
    fn public_ipv4(&mut self, owner: &Arc<HostLock>) -> Result<String, HostError>;
    /// Bind root/package/configuration admission and exact proxy PID, command,
    /// executable, cgroup, TCP443 and loopback TCP10000 observations. Unknown or
    /// foreign listener/unit residue must refuse, including on an empty setup.
    fn inspect(
        &mut self,
        owner: &Arc<HostLock>,
        record: Option<&OwnershipRecord>,
        stop: &Cancellation,
    ) -> Result<t::Inspection, HostError>;
    fn effect(
        &mut self,
        owner: &Arc<HostLock>,
        op: Operation,
        record: &OwnershipRecord,
        config: Option<&ServerConfiguration>,
        stop: &Cancellation,
    ) -> Result<(), HostError>;
    /// Use the concrete shared ServiceController and independently checked
    /// effective unit, retaining this exact Owner guard in native and fixtures.
    fn start_proxy(
        &mut self,
        owner: &Arc<HostLock>,
        record: &OwnershipRecord,
        stop: &Cancellation,
    ) -> Result<(), HostError>;
    fn probe_sha256(
        &mut self,
        owner: &Arc<HostLock>,
        stop: &Cancellation,
    ) -> Result<String, HostError>;
}
pub struct TunnelGuard {
    owner: Arc<HostLock>,
    packages: RefCell<Option<super::locks::PackageLocks<'static>>>,
    store: RefCell<OwnershipStore>,
}
pub struct ProtectedTunnelHost<'a, S, I = NativeConnectorIo> {
    standard: S,
    connector: Connector<I>,
    proof: &'a AuthenticatedInstalled,
    network: ProbeNetwork,
}
impl<'a, S: StandardHost> ProtectedTunnelHost<'a, S, NativeConnectorIo> {
    pub fn native_unreleased(
        proof: &'a AuthenticatedInstalled,
        standard: S,
    ) -> Result<Self, HostError> {
        super::linux::require_native_environment()?;
        if standard.root() != Path::new("/") {
            return Err(HostError::Unsafe);
        }
        let mut host = Self {
            standard,
            connector: Connector::native_unreleased()?,
            proof,
            network: ProbeNetwork::native().map_err(|_| HostError::Unsafe)?,
        };
        host.standard.verify_installed(proof)?;
        Ok(host)
    }
}
impl<'a, S: StandardHost, I: ConnectorIo> ProtectedTunnelHost<'a, S, I> {
    pub fn injected(
        root: &Path,
        proof: &'a AuthenticatedInstalled,
        standard: S,
        io: I,
        network: ProbeNetwork,
    ) -> Result<Self, HostError> {
        if root == Path::new("/") || standard.root() != root || network.fixture.is_none() {
            return Err(HostError::LiveUnavailable);
        }
        let mut host = Self {
            standard,
            connector: Connector::injected(root, io)?,
            proof,
            network,
        };
        host.standard.verify_installed(proof)?;
        Ok(host)
    }
    pub fn standard(&self) -> &S {
        &self.standard
    }
    pub fn standard_mut(&mut self) -> &mut S {
        &mut self.standard
    }
}
impl<S: StandardHost, I: ConnectorIo> t::Host for ProtectedTunnelHost<'_, S, I> {
    type Guard = TunnelGuard;
    type Probe = NativeProbeSession;
    fn acquire(&mut self, stop: &Cancellation) -> Result<TunnelGuard, t::Error> {
        if stop.cancelled() {
            return Err(t::Error::Interrupted);
        }
        let fs = &self.connector.fs;
        let owner = Arc::new(HostLock::existing(fs.path(), fs.uid).map_err(host_error)?);
        let packages = owner.retain_packages().map_err(host_error)?;
        if fs.metadata("var/lib/sbxr").map_err(refused)?.is_none() {
            return Err(t::Error::Authority);
        }
        fs.observe(Resource {
            path: "var/lib/sbxr",
            kind: Kind::Directory(Mode::from_raw_mode(0o700)),
        })
        .map_err(refused)?
        .ok_or(t::Error::Authority)?;
        let store =
            OwnershipStore::open(&fs.path().join("var/lib/sbxr"), fs.uid).map_err(refused)?;
        let g = TunnelGuard {
            owner,
            packages: RefCell::new(Some(packages)),
            store: RefCell::new(store),
        };
        self.verify_guard(&g)?;
        Ok(g)
    }
    fn verify_guard(&mut self, g: &TunnelGuard) -> Result<(), t::Error> {
        if g.owner.root() != self.connector.fs.path()
            || self.standard.root() != self.connector.fs.path()
        {
            return Err(t::Error::Authority);
        }
        g.owner.verify().map_err(host_error)?;
        g.packages
            .borrow()
            .as_ref()
            .ok_or(t::Error::Authority)?
            .verify()
            .map_err(host_error)?;
        self.standard
            .verify_installed(self.proof)
            .map_err(host_error)
    }
    fn installed_release(&mut self, g: &TunnelGuard) -> Result<ReleaseIdentity, t::Error> {
        self.verify_guard(g)?;
        Ok(self.proof.record().release_identity())
    }
    fn public_ipv4(&mut self, g: &TunnelGuard) -> Result<String, t::Error> {
        self.verify_guard(g)?;
        let ip = self.standard.public_ipv4(&g.owner).map_err(host_error)?;
        if !crate::records::ownership_public_ipv4(&ip) {
            return Err(t::Error::Authority);
        }
        self.verify_guard(g)?;
        Ok(ip)
    }
    fn snapshot(&mut self, g: &TunnelGuard) -> Result<t::Snapshot, t::Error> {
        self.verify_guard(g)?;
        let s = g.store.borrow().load().map_err(refused)?;
        Ok(t::Snapshot {
            current: s.current.map(|r| r.bytes().to_vec()),
            staged: s.staged.map(|r| r.bytes().to_vec()),
        })
    }
    fn prerequisites(
        &mut self,
        g: &TunnelGuard,
        stop: &Cancellation,
    ) -> Result<Prerequisites, t::Error> {
        self.verify_guard(g)?;
        let p = self.connector.prerequisites(stop)?;
        self.verify_guard(g)?;
        Ok(p)
    }
    fn inspect(
        &mut self,
        g: &TunnelGuard,
        r: Option<&OwnershipRecord>,
        stop: &Cancellation,
    ) -> Result<t::Inspection, t::Error> {
        self.verify_guard(g)?;
        if r.is_some_and(|r| {
            r.tunnel_authority().is_none()
                || r.release_identity() != self.proof.record().release_identity()
        }) {
            return Err(t::Error::Authority);
        }
        let standard = self
            .standard
            .inspect(&g.owner, r, stop)
            .map_err(host_error)?;
        let authority = r.and_then(OwnershipRecord::tunnel_authority);
        let connector = self.connector.inspect_with_digest(
            r.is_some(),
            authority.as_ref().map(|a| a.binary_sha256()),
            stop,
        )?;
        // The Standard observer must independently prove its loopback 10000
        // listener shares the exact managed proxy PID and no foreign listeners.
        self.verify_guard(g)?;
        Ok(t::Inspection {
            fingerprint: sha256_hex(
                format!("{}:{}", standard.fingerprint, connector.fingerprint).as_bytes(),
            ),
            empty: standard.empty && connector.empty,
            ready: standard.ready && connector.installed,
            stopped: standard.stopped && connector.stopped,
            running: standard.running && connector.running,
        })
    }
    fn configuration(&mut self, g: &TunnelGuard, r: &OwnershipRecord) -> Result<Vec<u8>, t::Error> {
        self.verify_guard(g)?;
        let (bytes, _) = self
            .connector
            .fs
            .raw(
                "etc/sing-box/config.json",
                Mode::from_raw_mode(0o640),
                1 << 20,
            )
            .map_err(refused)?
            .ok_or(t::Error::Authority)?;
        if sha256_hex(&bytes) != r.configuration_sha256()
            || ServerConfiguration::decode_supported(&bytes).is_err()
        {
            return Err(t::Error::Authority);
        }
        self.verify_guard(g)?;
        Ok(bytes)
    }
    fn synchronize(&mut self, g: &TunnelGuard, expected: &[u8]) -> Result<(), t::Error> {
        self.verify_guard(g)?;
        g.store
            .borrow()
            .synchronize(expected)
            .map_err(|_| t::Error::Publication)
    }
    fn publish(
        &mut self,
        g: &TunnelGuard,
        expected: Option<&[u8]>,
        next: &OwnershipRecord,
    ) -> Result<(), t::Error> {
        self.verify_guard(g)?;
        if !self.standard.effects_available() {
            return Err(t::Error::Authority);
        }
        g.store
            .borrow_mut()
            .publish(expected, next)
            .map_err(|_| t::Error::Publication)?;
        self.verify_guard(g).map_err(|_| t::Error::Publication)
    }
    fn effect(
        &mut self,
        g: &TunnelGuard,
        e: t::Effect,
        r: &OwnershipRecord,
        c: Option<&ServerConfiguration>,
        stop: &Cancellation,
    ) -> Result<(), t::Error> {
        self.verify_guard(g)?;
        if !self.standard.effects_available() {
            return Err(t::Error::Authority);
        }
        if stop.cancelled() {
            return Err(t::Error::Interrupted);
        }
        let current = g.store.borrow().load().map_err(refused)?;
        if current.staged.is_some()
            || current
                .current
                .is_none_or(|s| s.bytes() != r.encode().unwrap_or_default())
        {
            return Err(t::Error::Authority);
        }
        let result = match e {
            t::Effect::InstallConnector | t::Effect::StartConnector => {
                if Some(self.connector.prerequisites(stop)?.authority().clone())
                    != r.tunnel_authority()
                {
                    return Err(t::Error::PrerequisitesChanged);
                }
                if e == t::Effect::InstallConnector {
                    self.connector.install(&g.owner, stop)
                } else {
                    self.connector.start(&g.owner, stop)
                }
            }
            t::Effect::RemoveConnector => self.connector.remove(
                &g.owner,
                &r.tunnel_authority().ok_or(t::Error::Authority)?,
                stop,
            ),
            t::Effect::Standard(Operation::StartService) => {
                self.standard
                    .probe_sha256(&g.owner, stop)
                    .map_err(host_error)?;
                self.standard
                    .start_proxy(&g.owner, r, stop)
                    .map_err(host_error)
            }
            t::Effect::Standard(op) => {
                // APT/dpkg acquire their own POSIX locks. Retain flock/writer;
                // the shared Standard adapter rechecks package locks itself.
                g.packages.borrow_mut().take();
                let result = self
                    .standard
                    .effect(&g.owner, op, r, c, stop)
                    .map_err(host_error);
                let packages = g.owner.retain_packages().map_err(host_error)?;
                *g.packages.borrow_mut() = Some(packages);
                result
            }
        };
        result.map_err(|err| {
            if matches!(
                err,
                t::Error::Interrupted | t::Error::TimedOut | t::Error::PrerequisitesChanged
            ) {
                err
            } else {
                t::Error::Effect(e)
            }
        })?;
        self.verify_guard(g)
    }
    fn remove_completed_cleanup(
        &mut self,
        g: &TunnelGuard,
        expected: &[u8],
    ) -> Result<(), t::Error> {
        self.verify_guard(g)?;
        if !self.standard.effects_available() {
            return Err(t::Error::Authority);
        }
        g.store
            .borrow_mut()
            .remove_completed_cleanup(expected)
            .map_err(|_| t::Error::Publication)?;
        self.verify_guard(g).map_err(|_| t::Error::Publication)
    }
    fn websocket(
        &mut self,
        g: &TunnelGuard,
        r: &WebSocketRequest,
        b: &Budget<'_>,
    ) -> Result<WebSocketReply, ProbeProblem> {
        self.verify_guard(g).map_err(|_| ProbeProblem::Authority)?;
        let reply = self.network.websocket(r, b)?;
        self.verify_guard(g).map_err(|_| ProbeProblem::Authority)?;
        Ok(reply)
    }
    fn probe_port(&mut self, g: &TunnelGuard, b: &Budget<'_>) -> Result<u16, ProbeProblem> {
        self.verify_guard(g).map_err(|_| ProbeProblem::Authority)?;
        budget(b)?;
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProbeProblem::Port)?;
        let port = listener
            .local_addr()
            .map_err(|_| ProbeProblem::Port)?
            .port();
        drop(listener);
        Ok(port)
    }
    fn spawn_probe(
        &mut self,
        g: &TunnelGuard,
        plan: &ProbePlan,
        b: &Budget<'_>,
    ) -> Result<Self::Probe, ProbeProblem> {
        self.verify_guard(g).map_err(|_| ProbeProblem::Authority)?;
        budget(b)?;
        if self.connector.fs.path() != Path::new("/") {
            return Err(ProbeProblem::Spawn);
        }
        let expected = self
            .standard
            .probe_sha256(&g.owner, b.cancellation())
            .map_err(|_| ProbeProblem::Authority)?;
        NativeProbeSession::spawn(plan, &expected, self.network.clone(), b)
    }
}

pub(in crate::host) fn retained_start(
    stop: &Cancellation,
    start: impl FnOnce(&runtime_handoff::StartContext) -> Result<(), runtime_handoff::Error>,
) -> Result<(), runtime_handoff::Error> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let done = AtomicBool::new(false);
    struct Finish<'a>(&'a AtomicBool);
    impl Drop for Finish<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let cancel = crate::subscription_serving::Cancellation::new();
    let context = runtime_handoff::StartContext::new(
        cancel.clone(),
        Instant::now() + runtime_handoff::START_TIMEOUT,
    );
    thread::scope(|scope| {
        let finish = Finish(&done);
        let relay = thread::Builder::new()
            .name("sbxr-tunnel-start-cancel".into())
            .spawn_scoped(scope, || {
                while !done.load(Ordering::Acquire) {
                    if stop.cancelled() {
                        cancel.cancel();
                        return;
                    }
                    thread::sleep(POLL);
                }
            })
            .map_err(|_| runtime_handoff::Error::Refused)?;
        context.check()?;
        let result = start(&context);
        drop(finish);
        relay.join().map_err(|_| runtime_handoff::Error::Refused)?;
        context.check()?;
        result
    })
}
