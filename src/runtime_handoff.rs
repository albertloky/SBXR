//! Authenticated one-use runtime starts and HTTP serving composition.
//!
//! This module never creates lock files, changes services, writes authority, or
//! selects an executable from arguments/environment. Native dispatch must supply
//! authenticated installed identity and complete fresh protected host observations.
//! A private CLI role alone is never permission. Legacy TLS remains refused.
mod sandbox;
use crate::{
    private_roles::Role,
    records::{
        OwnershipRecord, RecoveryDirection, ReleaseIdentity, ServingAuthority, SetupPhase,
        sha256_hex,
    },
    server_configuration::ServerConfiguration,
    subscription_serving::{Cancellation, Code, Generation, Module, State},
};
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat},
    io::{self as rio, Errno, IoSlice, IoSliceMut},
    net::{
        self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
    },
};
pub use sandbox::{SandboxProcess, acquire_serving_start};
use std::{
    fmt,
    io::{Read, Write},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, TcpListener},
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const SUBSCRIPTION_CGROUP: &str = "/system.slice/sbxr-subscription.service";
pub const PROXY_CGROUP: &str = "/system.slice/sing-box.service";
pub const START_TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(5);
#[cfg(target_os = "linux")]
const MAX_EXECUTABLE: usize = 256 << 20;
const MAX_CONFIGURATION: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Refused,
    Busy,
    Cancelled,
    Deadline,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("runtime start authority refused")
    }
}
impl std::error::Error for Error {}
fn refused(_: impl fmt::Debug) -> Error {
    Error::Refused
}
fn role_name(role: Role) -> Result<&'static str, Error> {
    match role {
        Role::SubscriptionServing => Ok("--subscription-serving\n"),
        Role::ProxyStartAuthorize => Ok("--proxy-start-authorize\n"),
        _ => Err(Error::Refused),
    }
}
fn cgroup(role: Role) -> Result<&'static str, Error> {
    match role {
        Role::SubscriptionServing => Ok(SUBSCRIPTION_CGROUP),
        Role::ProxyStartAuthorize => Ok(PROXY_CGROUP),
        _ => Err(Error::Refused),
    }
}

/// One absolute startup deadline, capped at Go's fifteen seconds. Cancellation
/// is also the serving stop handle; the startup deadline does not end serving.
pub struct StartContext {
    pub stop: Cancellation,
    deadline: Instant,
    parents: Vec<Cancellation>,
}
impl StartContext {
    pub fn new(stop: Cancellation, deadline: Instant) -> Self {
        Self {
            stop,
            deadline: deadline.min(Instant::now() + START_TIMEOUT),
            parents: Vec::new(),
        }
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn check(&self) -> Result<(), Error> {
        if self.stop.is_cancelled() || self.parents.iter().any(Cancellation::is_cancelled) {
            Err(Error::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    fn pause(&self, duration: Duration) -> Result<(), Error> {
        self.check()?;
        thread::sleep(duration.min(self.deadline.saturating_duration_since(Instant::now())));
        self.check()
    }
}

/// Kernel/process observations, never request fields. Start time defeats PID
/// reuse; parent PID, cgroup and exact authenticated executable bytes are bound.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub parent_pid: u32,
    pub start_ticks: u64,
    pub uid: u32,
    pub executable_sha256: String,
    pub cgroup: String,
}
impl ProcessIdentity {
    pub fn new(
        pid: u32,
        parent_pid: u32,
        start_ticks: u64,
        uid: u32,
        executable_sha256: &str,
        cgroup: &str,
    ) -> Result<Self, Error> {
        if pid == 0
            || parent_pid == 0
            || start_ticks == 0
            || executable_sha256.len() != 64
            || executable_sha256
                .bytes()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
            || executable_sha256.bytes().all(|b| b == b'0')
            || !cgroup.starts_with('/')
            || cgroup.len() > 4095
            || cgroup.bytes().any(|b| b.is_ascii_control())
            || cgroup.split('/').any(|p| matches!(p, "." | ".."))
        {
            return Err(Error::Refused);
        }
        Ok(Self {
            pid,
            parent_pid,
            start_ticks,
            uid,
            executable_sha256: executable_sha256.into(),
            cgroup: cgroup.into(),
        })
    }
    fn accepts(&self, role: Role, uid: u32) -> bool {
        self.uid == uid
            && cgroup(role).is_ok_and(|expected| self.cgroup == expected)
            && Self::new(
                self.pid,
                self.parent_pid,
                self.start_ticks,
                self.uid,
                &self.executable_sha256,
                &self.cgroup,
            )
            .is_ok()
    }
}
impl fmt::Debug for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Runtime process identity (redacted)")
    }
}

/// Trusted Host boundary. Portable tests inject synthetic observations; a native
/// implementation must derive peers from SO_PEERCRED, never argv/environment.
pub trait PeerObservations {
    fn current(&self) -> Result<ProcessIdentity, Error>;
    fn peer(&self, connection: &UnixStream) -> Result<ProcessIdentity, Error>;
}
/// Lender-side Linux proof. A service with /proc hidden must receive a trusted
/// Host observation implementation; it must not replace missing proof with argv.
pub struct LinuxPeers;
impl PeerObservations for LinuxPeers {
    fn current(&self) -> Result<ProcessIdentity, Error> {
        linux_process(std::process::id())
    }
    fn peer(&self, connection: &UnixStream) -> Result<ProcessIdentity, Error> {
        #[cfg(target_os = "linux")]
        {
            let credentials = net::sockopt::socket_peercred(connection).map_err(refused)?;
            let observed = linux_process(credentials.pid.as_raw_nonzero().get() as u32)?;
            if observed.uid != credentials.uid.as_raw() {
                return Err(Error::Refused);
            }
            Ok(observed)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = connection;
            Err(Error::Refused)
        }
    }
}
#[cfg(target_os = "linux")]
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(refused)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(refused)?;
    if bytes.is_empty() || bytes.len() > max {
        Err(Error::Refused)
    } else {
        Ok(bytes)
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn linux_process(pid: u32) -> Result<ProcessIdentity, Error> {
    let directory = PathBuf::from(format!("/proc/{pid}"));
    let before = read_bounded(&directory.join("stat"), 8192)?;
    let (parent, ticks) = parse_process_stat(&before, pid)?;
    let status = read_bounded(&directory.join("status"), 65536)?;
    let status = std::str::from_utf8(&status).map_err(refused)?;
    let ids: Vec<_> = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .ok_or(Error::Refused)?
        .split_whitespace()
        .collect();
    if ids.len() != 4 || ids.iter().any(|id| *id != ids[0]) {
        return Err(Error::Refused);
    }
    let uid = ids[0].parse().map_err(refused)?;
    let groups = read_bounded(&directory.join("cgroup"), 4096)?;
    let group = std::str::from_utf8(&groups)
        .map_err(refused)?
        .strip_prefix("0::")
        .and_then(|s| s.strip_suffix('\n'))
        .ok_or(Error::Refused)?;
    let executable = read_bounded(&directory.join("exe"), MAX_EXECUTABLE)?;
    let result = ProcessIdentity::new(pid, parent, ticks, uid, &sha256_hex(&executable), group)?;
    let after = read_bounded(&directory.join("stat"), 8192)?;
    if parse_process_stat(&after, pid)? != (parent, ticks)
        || read_bounded(&directory.join("cgroup"), 4096)? != groups
        || read_bounded(&directory.join("status"), 65536)?
            .split(|b| *b == b'\n')
            .find(|l| l.starts_with(b"Uid:"))
            != status
                .as_bytes()
                .split(|b| *b == b'\n')
                .find(|l| l.starts_with(b"Uid:"))
    {
        return Err(Error::Refused);
    }
    Ok(result)
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn linux_process(_: u32) -> Result<ProcessIdentity, Error> {
    Err(Error::Refused)
}

#[cfg(any(target_os = "linux", test))]
fn parse_process_stat(bytes: &[u8], expected_pid: u32) -> Result<(u32, u64), Error> {
    let text = std::str::from_utf8(bytes).map_err(refused)?;
    if !text.starts_with(&format!("{expected_pid} (")) {
        return Err(Error::Refused);
    }
    let (_, fields) = text.rsplit_once(") ").ok_or(Error::Refused)?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let parent = fields
        .get(1)
        .ok_or(Error::Refused)?
        .parse()
        .map_err(refused)?;
    let ticks = fields
        .get(19)
        .ok_or(Error::Refused)?
        .parse()
        .map_err(refused)?;
    if parent == 0 || ticks == 0 {
        return Err(Error::Refused);
    }
    Ok((parent, ticks))
}

struct LockPath {
    path: PathBuf,
    root: OwnedFd,
    uid: u32,
}
impl LockPath {
    fn open(path: &Path, uid: u32) -> Result<Self, Error> {
        let root = Self::open_root(path, uid)?;
        Ok(Self {
            path: path.into(),
            root,
            uid,
        })
    }
    fn open_root(path: &Path, uid: u32) -> Result<OwnedFd, Error> {
        if path == Path::new("/") {
            if uid != 0 {
                return Err(Error::Refused);
            }
            fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(refused)
        } else {
            crate::durable::open_directory(path, uid).map_err(refused)
        }
    }
    fn parent(&self) -> Result<OwnedFd, Error> {
        let current = Self::open_root(&self.path, self.uid)?;
        if !same(
            &fs::fstat(&current).map_err(refused)?,
            &fs::fstat(&self.root).map_err(refused)?,
        ) {
            return Err(Error::Refused);
        }
        let mut directory = current;
        for (part, sticky) in [("run", false), ("lock", true)] {
            directory = fs::openat(
                &directory,
                part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(refused)?;
            let stat = fs::fstat(&directory).map_err(refused)?;
            if stat.st_uid != self.uid
                || stat.st_mode & 0o022 != 0 && !(sticky && stat.st_mode & 0o1000 != 0)
            {
                return Err(Error::Refused);
            }
        }
        Ok(directory)
    }
    fn held(&self) -> Result<(), Error> {
        let parent = self.parent()?;
        let probe = fs::openat(
            &parent,
            "sbxr.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(refused)?;
        match self.verify(&probe) {
            Err(Error::Busy) => Ok(()),
            _ => Err(Error::Refused),
        }
    }
    fn verify(&self, file: impl AsFd) -> Result<(), Error> {
        let directory = self.parent()?;
        let opened = fs::fstat(&file).map_err(refused)?;
        let current =
            fs::statat(&directory, "sbxr.lock", AtFlags::SYMLINK_NOFOLLOW).map_err(refused)?;
        let safe = |s: &Stat| {
            FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
                && s.st_uid == self.uid
                && s.st_nlink == 1
                && s.st_mode & 0o7777 == 0o600
        };
        if !safe(&opened) || !safe(&current) || !same(&opened, &current) {
            return Err(Error::Refused);
        }
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(lock_error)
    }
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}
fn lock_error(error: Errno) -> Error {
    if matches!(error, Errno::AGAIN | Errno::ACCESS) {
        Error::Busy
    } else {
        Error::Refused
    }
}

/// Every descriptor is close-on-exec. Drop only closes: explicitly unlocking a
/// duplicate would release the Owner's shared open-file-description lock.
pub struct StartLock {
    file: OwnedFd,
    path: LockPath,
    borrowed: bool,
}
impl StartLock {
    pub fn existing(root: &Path, owner_uid: u32) -> Result<Self, Error> {
        let path = LockPath::open(root, owner_uid)?;
        let parent = path.parent()?;
        let file = fs::openat(
            &parent,
            "sbxr.lock",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(refused)?;
        let lock = Self {
            file,
            path,
            borrowed: false,
        };
        lock.verify()?;
        Ok(lock)
    }
    /// Core integration hook: consume a CLOEXEC duplicate of an already-held
    /// HostLock. The original Owner guard must outlive the handoff/start closure.
    pub fn from_owner_duplicate(root: &Path, owner_uid: u32, file: OwnedFd) -> Result<Self, Error> {
        let lock = Self {
            file,
            path: LockPath::open(root, owner_uid)?,
            borrowed: false,
        };
        rio::fcntl_setfd(&lock.file, rio::FdFlags::CLOEXEC).map_err(refused)?;
        lock.path.held()?;
        lock.verify()?;
        Ok(lock)
    }
    pub fn verify(&self) -> Result<(), Error> {
        self.path.verify(&self.file)
    }
    pub fn is_borrowed(&self) -> bool {
        self.borrowed
    }
    pub fn root(&self) -> &Path {
        &self.path.path
    }
    pub fn descriptor(&self) -> Result<OwnedFd, Error> {
        if self.borrowed {
            return Err(Error::Refused);
        }
        self.verify()?;
        rio::fcntl_dupfd_cloexec(&self.file, 3).map_err(refused)
    }
}
impl fmt::Debug for StartLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Runtime start lock (redacted)")
    }
}

/// Owns the listener and consumes exactly one connection, including refusal.
/// The caller binds a fresh abstract Linux address (no stale path to remove) or
/// supplies a fixture socket; this API never adopts/removes a filesystem socket.
enum ExpectedPeer {
    Exact(ProcessIdentity),
    Service { executable_sha256: String },
}
pub struct Handoff<'a> {
    listener: UnixListener,
    owner: &'a StartLock,
    role: Role,
    expected: ExpectedPeer,
    binding: Option<&'a dyn crate::release_acquisition::InstalledEvidence>,
}
impl<'a> Handoff<'a> {
    pub fn new(
        listener: UnixListener,
        owner: &'a StartLock,
        role: Role,
        expected: ProcessIdentity,
    ) -> Result<Self, Error> {
        role_name(role)?;
        if owner.borrowed || !expected.accepts(role, owner.path.uid) {
            return Err(Error::Refused);
        }
        owner.verify()?;
        listener.set_nonblocking(true).map_err(refused)?;
        Ok(Self {
            listener,
            owner,
            role,
            expected: ExpectedPeer::Exact(expected),
            binding: None,
        })
    }
    /// Systemd assigns the child PID after start. Pin its authenticated image,
    /// UID and fixed role cgroup, then bind/recheck the observed kernel PID and
    /// start time before lending. No request/environment PID is trusted.
    pub fn service(
        listener: UnixListener,
        owner: &'a StartLock,
        role: Role,
        authenticated: &'a dyn crate::release_acquisition::InstalledEvidence,
    ) -> Result<Self, Error> {
        role_name(role)?;
        authenticated.verify_binding().map_err(refused)?;
        if owner.borrowed {
            return Err(Error::Refused);
        }
        owner.verify()?;
        listener.set_nonblocking(true).map_err(refused)?;
        Ok(Self {
            listener,
            owner,
            role,
            expected: ExpectedPeer::Service {
                executable_sha256: authenticated.record().executable_sha256().into(),
            },
            binding: Some(authenticated),
        })
    }
    pub fn accept(
        self,
        observations: &impl PeerObservations,
        context: &StartContext,
    ) -> Result<(), Error> {
        let (mut connection, _) = loop {
            context.check()?;
            match self.listener.accept() {
                Ok(value) => break value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    context.pause(POLL)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::Refused),
            }
        };
        drop(self.listener);
        connection.set_nonblocking(true).map_err(refused)?;
        if let Some(proof) = self.binding {
            proof.verify_binding().map_err(refused)?;
        }
        let expected = observations.peer(&connection)?;
        let accepted = match &self.expected {
            ExpectedPeer::Exact(exact) => &expected == exact,
            ExpectedPeer::Service { executable_sha256 } => {
                expected.accepts(self.role, self.owner.path.uid)
                    && &expected.executable_sha256 == executable_sha256
            }
        };
        if !accepted {
            return Err(Error::Refused);
        }
        read_role(&mut connection, self.role, context)?;
        self.owner.verify()?;
        if observations.peer(&connection)? != expected {
            return Err(Error::Refused);
        }
        let duplicate = self.owner.descriptor()?;
        send_descriptor(&connection, &duplicate, context)
    }
}
/// Match Go's scoped start: one listener, one peer and one joined lender.
/// A failed/panicking start cancels only this handoff, preserving Owner authority.
/// The start callback must obey the supplied context's absolute deadline.
pub fn with_runtime_start(
    offer: Handoff<'_>,
    observations: &(impl PeerObservations + Sync),
    context: &StartContext,
    start: impl FnOnce(&StartContext) -> bool,
) -> bool {
    let mut parents = context.parents.clone();
    parents.push(context.stop.clone());
    let handoff_context = StartContext {
        stop: Cancellation::new(),
        deadline: context.deadline,
        parents,
    };
    thread::scope(|scope| {
        let _cancel_on_unwind = CancelOnDrop(handoff_context.stop.clone());
        let worker = thread::Builder::new()
            .name("sbxr-runtime-handoff".into())
            .spawn_scoped(scope, || offer.accept(observations, &handoff_context));
        let Ok(worker) = worker else {
            return false;
        };
        let started = start(context) && context.check().is_ok();
        if !started {
            handoff_context.stop.cancel();
        }
        worker.join().is_ok_and(|result| result.is_ok()) && started
    })
}

/// The fixed abstract Linux address has no filesystem entry to adopt or delete.
#[cfg(target_os = "linux")]
pub fn runtime_start_address(root: &Path) -> Result<std::os::unix::net::SocketAddr, Error> {
    use std::os::{linux::net::SocketAddrExt, unix::ffi::OsStrExt};
    let name = format!(
        "sbxr-runtime-start-{}",
        &sha256_hex(root.as_os_str().as_bytes())[..16]
    );
    std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).map_err(refused)
}

fn read_role(stream: &mut UnixStream, role: Role, context: &StartContext) -> Result<(), Error> {
    let expected = role_name(role)?.as_bytes();
    let mut bytes = [0; 64];
    let mut length = 0;
    while length < expected.len() {
        context.check()?;
        match stream.read(&mut bytes[length..expected.len() + 1]) {
            Ok(0) => return Err(Error::Refused),
            Ok(n) => length += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => context.pause(POLL)?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Refused),
        }
    }
    if &bytes[..length] == expected {
        Ok(())
    } else {
        Err(Error::Refused)
    }
}
fn write_role(stream: &mut UnixStream, role: Role, context: &StartContext) -> Result<(), Error> {
    let mut bytes = role_name(role)?.as_bytes();
    while !bytes.is_empty() {
        context.check()?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::Refused),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => context.pause(POLL)?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Refused),
        }
    }
    Ok(())
}
fn send_descriptor(
    stream: &UnixStream,
    descriptor: &OwnedFd,
    context: &StartContext,
) -> Result<(), Error> {
    #[cfg(target_vendor = "apple")]
    net::sockopt::set_socket_nosigpipe(stream, true).map_err(refused)?;
    let fds = [descriptor.as_fd()];
    loop {
        context.check()?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(Error::Refused);
        }
        let flags = SendFlags::DONTWAIT;
        #[cfg(target_os = "linux")]
        let flags = flags | SendFlags::NOSIGNAL;
        match net::sendmsg(stream, &[IoSlice::new(&[1])], &mut control, flags) {
            Ok(1) => return Ok(()),
            Err(Errno::AGAIN) => context.pause(POLL)?,
            Err(Errno::INTR) => continue,
            _ => return Err(Error::Refused),
        }
    }
}
fn receive_descriptor(stream: &UnixStream, context: &StartContext) -> Result<OwnedFd, Error> {
    loop {
        context.check()?;
        let mut bytes = [0; 2];
        // Receive the full SCM_RIGHTS descriptor ceiling before rejecting extras.
        // Pinned rustix cannot safely iterate truncated Darwin rights headers.
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let flags = RecvFlags::DONTWAIT;
        #[cfg(target_os = "linux")]
        let flags = flags | RecvFlags::CMSG_CLOEXEC;
        let result = match net::recvmsg(
            stream,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut control,
            flags,
        ) {
            Ok(result) => result,
            Err(Errno::AGAIN) => {
                context.pause(POLL)?;
                continue;
            }
            Err(Errno::INTR) => continue,
            Err(_) => return Err(Error::Refused),
        };
        let mut descriptors = Vec::new();
        let mut messages = 0;
        let mut unknown = false;
        // Draining owns/closes every received descriptor, including refusal.
        for message in control.drain() {
            messages += 1;
            match message {
                RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
                _ => unknown = true,
            }
        }
        if result.bytes != 1
            || bytes[0] != 1
            || result
                .flags
                .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
            || unknown
            || messages != 1
            || descriptors.len() != 1
        {
            return Err(Error::Refused);
        }
        let descriptor = descriptors.pop().ok_or(Error::Refused)?;
        rio::fcntl_setfd(&descriptor, rio::FdFlags::CLOEXEC).map_err(refused)?;
        return Ok(descriptor);
    }
}

/// Consumes its socket on every path. Both endpoints must have trusted process
/// expectations; the borrower rechecks its own identity and the lender after I/O.
pub fn borrow(
    mut connection: UnixStream,
    root: &Path,
    role: Role,
    expected_lender: &ProcessIdentity,
    observations: &impl PeerObservations,
    context: &StartContext,
) -> Result<StartLock, Error> {
    context.check()?;
    let uid = expected_lender.uid;
    let current = observations.current()?;
    if !current.accepts(role, uid) || observations.peer(&connection)? != *expected_lender {
        return Err(Error::Refused);
    }
    connection.set_nonblocking(true).map_err(refused)?;
    write_role(&mut connection, role, context)?;
    let file = receive_descriptor(&connection, context)?;
    if observations.current()? != current || observations.peer(&connection)? != *expected_lender {
        return Err(Error::Refused);
    }
    let lock = StartLock {
        file,
        path: LockPath::open(root, uid)?,
        borrowed: true,
    };
    lock.path.held()?;
    lock.verify()?;
    context.check()?;
    Ok(lock)
}

/// Busy is never admission. Retry both ordinary acquisition and the scoped
/// handoff, including one that appears after this wait started. Connect must be
/// nonblocking/deadline-bounded and return an independently trusted lender proof.
pub fn acquire_runtime_start(
    root: &Path,
    uid: u32,
    role: Role,
    observations: &impl PeerObservations,
    context: &StartContext,
    mut connect: impl FnMut() -> Result<(UnixStream, ProcessIdentity), Error>,
) -> Result<StartLock, Error> {
    let process = observations.current()?;
    if !process.accepts(role, uid) {
        return Err(Error::Refused);
    }
    loop {
        context.check()?;
        match StartLock::existing(root, uid) {
            Ok(lock) => {
                if observations.current()? != process {
                    return Err(Error::Refused);
                }
                context.check()?;
                return Ok(lock);
            }
            Err(Error::Busy) => (),
            Err(error) => return Err(error),
        }
        if let Ok((stream, expected)) = connect()
            && let Ok(lock) = borrow(stream, root, role, &expected, observations, context)
        {
            return Ok(lock);
        }
        context.pause(Duration::from_millis(25))?;
    }
}

/// The fixed unit, not a user-selected command. Byte parity is fixture-tested.
pub const SERVING_UNIT: &str = "[Unit]\nDescription=SBXR Subscription Serving\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/local/bin/sbxr --subscription-serving\nUser=root\nGroup=root\nRestart=no\nKillMode=control-group\nTimeoutStopSec=10s\nSendSIGKILL=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictNamespaces=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nInaccessiblePaths=/var/lib/sbxr/subscription-token /var/lib/sbxr/subscription-staging -/var/lib/sbxr/client-identity-target.json -/var/lib/sbxr/client-identity-target.json.sbxr-next /proc /run/dbus\nTemporaryFileSystem=/run/systemd:ro,mode=000\nStandardInput=null\nStandardOutput=null\nStandardError=null\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathAccess {
    PermissionDenied,
    Missing,
    Accessible,
    Unknown,
}
/// Each path must fail with EACCES, not merely be absent. In order: token,
/// staging, proc, systemd, dbus. The Host observes capabilities and NNP directly.
pub struct ServingSandbox {
    pub effective_uid: u32,
    pub process: SandboxProcess,
    pub capabilities: [u64; 4],
    pub no_new_privileges: bool,
    pub inaccessible: [PathAccess; 5],
    pub cgroup_procs: Vec<u8>,
}
impl ServingSandbox {
    pub fn validate(&self) -> Result<(), Error> {
        if self.effective_uid != 0
            || !self.process.accepts(0)
            || self.capabilities != [0; 4]
            || !self.no_new_privileges
            || self.inaccessible != [PathAccess::PermissionDenied; 5]
            || self.cgroup_procs.len() >= 4096
            || std::str::from_utf8(&self.cgroup_procs)
                .map_err(refused)?
                .trim()
                != self.process.pid.to_string()
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchOutcome {
    Cancelled,
    PublicIpv4Failed,
}
/// Protected observation boundary with no success defaults. The concrete Host
/// validates protected installed status under the lock; this never manufactures
/// signed acquisition trust or a proc-based current-image proof in the sandbox.
/// Historical committed-update runtime remains unsupported by the native adapter.
pub trait ServingHost: Sync {
    fn acquire_start(&self, context: &StartContext) -> Result<StartLock, Error>;
    fn installed_identity(
        &self,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<ReleaseIdentity, Error>;
    fn ownership(&self) -> Result<Vec<u8>, Error>;
    fn pending_and_final_absent(&self) -> Result<bool, Error>;
    /// Validate the complete selected resource footprint, protected unit/state
    /// bytes, group/config ownership and any renewal/retirement material.
    fn validate_material(
        &self,
        record: &OwnershipRecord,
        selected: &ServingAuthority,
    ) -> Result<(), Error>;
    fn unit(&self) -> Result<Vec<u8>, Error>;
    fn sandbox(&self) -> Result<ServingSandbox, Error>;
    fn public_ipv4(&self, context: &StartContext) -> Result<Ipv4Addr, Error>;
    fn configuration(&self) -> Result<Vec<u8>, Error>;
    fn bind_listener(&self, address: Ipv4Addr, port: u16) -> Result<TcpListener, Error>;
    /// Run a cancellation-aware periodic public-IP check; production checks at
    /// one minute. Must return when stop is cancelled; the caller always joins.
    fn watch_public_ipv4(&self, expected: Ipv4Addr, stop: &Cancellation) -> WatchOutcome;
}

struct Prepared {
    state: Arc<State>,
    lock: StartLock,
    recorded: Ipv4Addr,
    bind: Ipv4Addr,
    port: u16,
}
fn prepare(
    host: &impl ServingHost,
    context: &StartContext,
    fixture: bool,
) -> Result<Prepared, Error> {
    context.check()?;
    let lock = host.acquire_start(context)?;
    lock.verify()?;
    if fixture && lock.root() == Path::new("/") {
        return Err(Error::Refused);
    }
    let installed = host.installed_identity(&lock, context)?;
    let body = host.ownership()?;
    let record = OwnershipRecord::decode(&body).map_err(refused)?;
    if record.phase() != SetupPhase::Running
        || record.recovery_direction() != RecoveryDirection::None
        || record.release_identity() != installed
        || !host.pending_and_final_absent()?
    {
        return Err(Error::Refused);
    }
    let selected = select_http_authority(&record, lock.is_borrowed())?;
    host.validate_material(&record, &selected)?;
    if host.unit()? != SERVING_UNIT.as_bytes() {
        return Err(Error::Refused);
    }
    host.sandbox()?.validate()?;
    let recorded: Ipv4Addr = record.public_ipv4().parse().map_err(refused)?;
    if host.public_ipv4(context)? != recorded {
        return Err(Error::Refused);
    }
    let configuration = host.configuration()?;
    if configuration.is_empty()
        || configuration.len() > MAX_CONFIGURATION
        || sha256_hex(&configuration) != record.configuration_sha256()
    {
        return Err(Error::Refused);
    }
    let configuration = ServerConfiguration::decode_supported(&configuration).map_err(refused)?;
    // The loopback fixture is explicit and only admitted with an injected root;
    // its synthetic artifact names loopback. It can never select a live listener.
    let bind = if fixture {
        Ipv4Addr::LOCALHOST
    } else {
        recorded
    };
    let facts = configuration
        .connection_facts(&bind.to_string())
        .map_err(refused)?;
    let generation =
        Generation::new(selected.link_id(), selected.credential_digest()).map_err(refused)?;
    let state = State::prepare_http(&facts, generation).map_err(refused)?;
    if host.ownership()? != body {
        return Err(Error::Refused);
    }
    lock.verify()?;
    context.check()?;
    Ok(Prepared {
        state: Arc::new(state),
        lock,
        recorded,
        bind,
        port: if fixture { 0 } else { 8443 },
    })
}

/// Go's current runtime selection rules over a fully validated Ownership Record.
/// HTTPS and VMess profiles unsupported by the existing Rust preparer refuse.
pub fn select_http_authority(
    record: &OwnershipRecord,
    borrowed: bool,
) -> Result<ServingAuthority, Error> {
    if record.phase() != SetupPhase::Running
        || record.recovery_direction() != RecoveryDirection::None
    {
        return Err(Error::Refused);
    }
    let wire: serde_json::Value =
        serde_json::from_slice(&record.encode().map_err(refused)?).map_err(refused)?;
    if !borrowed
        && (wire["subscription_transport_migration"] == true
            || wire.get("subscription_rotation").is_some())
    {
        return Err(Error::Refused);
    }
    if let Some(rotation) = wire.get("client_identity_rotation") {
        let checkpoint = rotation["checkpoint"].as_str().ok_or(Error::Refused)?;
        let ordinary = matches!(
            checkpoint,
            "rotation authorized"
                | "target prepared"
                | "startup integration published"
                | "systemd reloaded"
                | "startup route verified"
        );
        let forward = matches!(
            checkpoint,
            "source revoked" | "target published" | "target started"
        );
        let selected = if forward {
            "target_configuration_sha256"
        } else {
            "source_configuration_sha256"
        };
        if !ordinary && !borrowed
            || rotation.get("subscription").is_none()
            || rotation[selected].as_str() != Some(record.configuration_sha256())
        {
            return Err(Error::Refused);
        }
    }
    if let Some(repair) = wire.get("subscription_repair")
        && repair["checkpoint"] != "prepared"
        && repair.get("target").is_none()
    {
        return Err(Error::Refused);
    }
    let mut selected = wire
        .get("serving")
        .or_else(|| {
            wire.get("subscription_enablement")
                .and_then(|e| e.get("serving"))
        })
        .ok_or(Error::Refused)?;
    if let Some(activation) = wire.get("certificate_activation") {
        selected = activation.get("target").ok_or(Error::Refused)?;
    }
    if let Some(target) = wire
        .get("subscription_repair")
        .and_then(|r| r.get("target"))
    {
        selected = target;
    }
    if selected["http"] != true {
        return Err(Error::Refused);
    }
    ServingAuthority::http_digest(
        selected["link_id"].as_str().ok_or(Error::Refused)?,
        selected["credential_sha256"]
            .as_str()
            .ok_or(Error::Refused)?,
    )
    .map_err(refused)
}

pub fn serve_subscription(
    host: &impl ServingHost,
    module: &Module,
    context: &StartContext,
) -> Code {
    serve(host, module, context, false)
}
/// Synthetic local integration only. Requires a protected injected root and
/// serves a synthetic loopback profile on an ephemeral port. No native fallback.
pub fn serve_subscription_loopback_fixture(
    host: &impl ServingHost,
    module: &Module,
    context: &StartContext,
) -> Code {
    serve(host, module, context, true)
}
fn serve(host: &impl ServingHost, module: &Module, context: &StartContext, fixture: bool) -> Code {
    let Ok(prepared) = prepare(host, context, fixture) else {
        return Code::Refused;
    };
    let Ok(listener) = host.bind_listener(prepared.bind, prepared.port) else {
        return Code::Refused;
    };
    if listener.local_addr().ok().is_none_or(|a| {
        a.ip() != IpAddr::V4(prepared.bind) || prepared.port != 0 && a.port() != prepared.port
    }) || prepared.lock.verify().is_err()
        || context.check().is_err()
    {
        return Code::Refused;
    }
    drop(prepared.lock);
    let public_failed = AtomicBool::new(false);
    let code = thread::scope(|scope| {
        let _cancel_on_unwind = CancelOnDrop(context.stop.clone());
        let watch = thread::Builder::new()
            .name("sbxr-public-ip-watch".into())
            .spawn_scoped(scope, || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    host.watch_public_ipv4(prepared.recorded, &context.stop)
                }));
                if !matches!(result, Ok(WatchOutcome::Cancelled)) || !context.stop.is_cancelled() {
                    public_failed.store(true, Ordering::SeqCst);
                    context.stop.cancel();
                }
            });
        let Ok(watch) = watch else {
            return Code::Failed;
        };
        let code = module.serve(prepared.state, listener, &context.stop);
        context.stop.cancel();
        if watch.join().is_err() {
            return Code::Failed;
        }
        code
    });
    if code == Code::Stopped && public_failed.load(Ordering::SeqCst) {
        Code::Failed
    } else {
        code
    }
}

struct CancelOnDrop(Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Private ExecCondition Host boundary. Authentication and fixed startup-unit
/// validation must be performed under the retained exact lock; no CLI fact is
/// an observation. No default native implementation grants partial authority.
pub trait ProxyStartHost {
    fn acquire_start(&self, context: &StartContext) -> Result<StartLock, Error>;
    fn installed_identity(
        &self,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<ReleaseIdentity, Error>;
    fn ownership(&self) -> Result<Vec<u8>, Error>;
    fn verify_startup(&self, record: &OwnershipRecord, context: &StartContext)
    -> Result<(), Error>;
    fn configuration(&self) -> Result<Vec<u8>, Error>;
    fn mutation_in_progress(&self) -> Result<bool, Error>;
    /// Atomically consume the exact configuration-bound one-use Owner gate.
    fn consume_authorization(
        &self,
        configuration_sha256: &str,
        lock: &StartLock,
        context: &StartContext,
    ) -> Result<(), Error>;
}
/// Ordinary starts may use the source before the cutover gate. At/after the
/// gate only a borrowed Owner lock plus one consumed exact authorization works.
/// This selects no recovery direction and never starts or publishes anything.
pub fn authorize_proxy_start(
    host: &impl ProxyStartHost,
    context: &StartContext,
) -> Result<(), Error> {
    context.check()?;
    let lock = host.acquire_start(context)?;
    lock.verify()?;
    let installed = host.installed_identity(&lock, context)?;
    let body = host.ownership()?;
    let record = OwnershipRecord::decode(&body).map_err(refused)?;
    let wire: serde_json::Value =
        serde_json::from_slice(&record.encode().map_err(refused)?).map_err(refused)?;
    if record.phase() != SetupPhase::Running
        || record.recovery_direction() != RecoveryDirection::None
        || record.release_identity() != installed
        || wire["subscription_transport_migration"] == true
        || wire.get("proxy_startup").is_none()
    {
        return Err(Error::Refused);
    }
    host.verify_startup(&record, context)?;
    let configuration = host.configuration()?;
    if configuration.is_empty()
        || configuration.len() > MAX_CONFIGURATION
        || sha256_hex(&configuration) != record.configuration_sha256()
    {
        return Err(Error::Refused);
    }
    ServerConfiguration::decode_supported(&configuration).map_err(refused)?;
    if host.ownership()? != body {
        return Err(Error::Refused);
    }
    lock.verify()?;
    context.check()?;
    if let Some(selected) = cutover_configuration(&record)? {
        if !lock.is_borrowed() || !host.mutation_in_progress()? {
            return Err(Error::Refused);
        }
        host.consume_authorization(&selected, &lock, context)?;
        context.check()?;
    }
    Ok(())
}

/// The Owner may start only this committed initial tunnel setup checkpoint.
/// This does not relax ordinary private startup, grant an automatic restart, or
/// select a cleanup direction. ServiceController retains the original Owner.
pub fn setup_start_configuration(record: &OwnershipRecord) -> Result<String, Error> {
    if record.schema() != 1
        || record.phase() != SetupPhase::ServiceEnabled
        || record.recovery_direction() != RecoveryDirection::FinishSetup
        || record.tunnel_authority().is_none()
        || record.pending_change().is_some()
        || record.lock_provisioning_sha256().is_none()
    {
        return Err(Error::Refused);
    }
    Ok(record.configuration_sha256().into())
}

/// Selects only the currently recorded configuration. This grants no permission:
/// gated starts still need the borrowed Owner lock and a consumed one-use token.
pub fn cutover_configuration(record: &OwnershipRecord) -> Result<Option<String>, Error> {
    if record.phase() != SetupPhase::Running
        || record.recovery_direction() != RecoveryDirection::None
    {
        return Err(Error::Refused);
    }
    let wire: serde_json::Value =
        serde_json::from_slice(&record.encode().map_err(refused)?).map_err(refused)?;
    if wire["subscription_transport_migration"] == true {
        return Err(Error::Refused);
    }
    let Some(rotation) = wire.get("client_identity_rotation") else {
        return Ok(None);
    };
    let checkpoint = rotation["checkpoint"].as_str().ok_or(Error::Refused)?;
    let ordinary = matches!(
        checkpoint,
        "rotation authorized"
            | "target prepared"
            | "startup integration published"
            | "systemd reloaded"
            | "startup route verified"
    );
    let selected = if ordinary || rotation["direction"] != "forward" {
        "source_configuration_sha256"
    } else {
        "target_configuration_sha256"
    };
    let selected = rotation[selected].as_str().ok_or(Error::Refused)?;
    if selected != record.configuration_sha256() {
        return Err(Error::Refused);
    }
    Ok(if ordinary {
        None
    } else {
        Some(selected.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn received_descriptor_is_close_on_exec() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let context =
            StartContext::new(Cancellation::new(), Instant::now() + Duration::from_secs(1));
        send_descriptor(&sender, &descriptor, &context).unwrap();
        let received = receive_descriptor(&receiver, &context).unwrap();
        assert!(
            rio::fcntl_getfd(&received)
                .unwrap()
                .contains(rio::FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn proc_identity_parser_handles_parentheses_and_refuses_bad_or_reused_identity() {
        let mut fields = vec!["S".to_owned(), "1".to_owned()];
        fields.extend((2..19).map(|_| "0".to_owned()));
        fields.push("1234".into());
        let stat = format!("42 (odd ) name) {}", fields.join(" "));
        assert_eq!(parse_process_stat(stat.as_bytes(), 42), Ok((1, 1234)));
        assert_eq!(parse_process_stat(stat.as_bytes(), 43), Err(Error::Refused));
        assert!(parse_process_stat(b"42 (missing fields) S 1", 42).is_err());
    }
}
