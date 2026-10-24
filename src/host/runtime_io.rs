//! Bounded nonblocking Unix connection for the fixed runtime-start channel.
//! This module never creates/adopts/removes a filesystem socket in production.
use crate::runtime_handoff::{Error, StartContext};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{self, SocketAddrUnix},
};
use std::{os::unix::net::UnixStream, path::Path, time::Duration};
fn refused(_: impl std::fmt::Debug) -> Error {
    Error::Refused
}
fn connect(address: &SocketAddrUnix, context: &StartContext) -> Result<UnixStream, Error> {
    context.check()?;
    #[cfg(target_os = "linux")]
    let fd = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(refused)?;
    #[cfg(not(target_os = "linux"))]
    let fd = {
        // Fixture portability only. Native Linux creates both flags atomically.
        let fd = net::socket(net::AddressFamily::UNIX, net::SocketType::STREAM, None)
            .map_err(refused)?;
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).map_err(refused)?;
        let flags = rustix::fs::fcntl_getfl(&fd).map_err(refused)?;
        rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(refused)?;
        fd
    };
    match net::connect(&fd, address) {
        Ok(()) => (),
        Err(Errno::INPROGRESS) => loop {
            context.check()?;
            let duration = Duration::from_millis(20).min(
                context
                    .deadline()
                    .saturating_duration_since(std::time::Instant::now()),
            );
            let timeout = Timespec::try_from(duration).map_err(refused)?;
            let mut ready = [PollFd::new(&fd, PollFlags::OUT)];
            match poll(&mut ready, Some(&timeout)) {
                Ok(0) => continue,
                Ok(_) => {
                    net::sockopt::socket_error(&fd)
                        .map_err(refused)?
                        .map_err(refused)?;
                    break;
                }
                Err(Errno::INTR) => continue,
                Err(error) => return Err(refused(error)),
            }
        },
        Err(error) => return Err(refused(error)),
    }
    context.check()?;
    Ok(UnixStream::from(fd))
}
pub fn connect_native(root: &Path, context: &StartContext) -> Result<UnixStream, Error> {
    super::linux::require_native_environment().map_err(refused)?;
    if root != Path::new("/") {
        return Err(Error::Refused);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        let address = crate::runtime_handoff::runtime_start_address(root)?;
        let name = address.as_abstract_name().ok_or(Error::Refused)?;
        connect(
            &SocketAddrUnix::new_abstract_name(name).map_err(refused)?,
            context,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = context;
        Err(Error::Refused)
    }
}
/// Only explicit injected roots may use a fixture pathname.
fn fixture_path(root: &Path, path: &Path) -> Result<std::path::PathBuf, Error> {
    if root == Path::new("/")
        || !path.is_absolute()
        || path.parent() != Some(root)
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(Error::Refused);
    }
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::symlink_metadata(root).map_err(refused)?.uid();
    let _root = crate::durable::open_directory(root, uid).map_err(refused)?;
    let cwd = std::env::current_dir().map_err(refused)?;
    Ok(path.strip_prefix(cwd).unwrap_or(path).to_owned())
}
pub fn connect_fixture(
    root: &Path,
    path: &Path,
    context: &StartContext,
) -> Result<UnixStream, Error> {
    context.check()?;
    let relative = fixture_path(root, path)?;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let before = std::fs::symlink_metadata(path).map_err(refused)?;
    if !before.file_type().is_socket()
        || before.uid() != std::fs::symlink_metadata(root).map_err(refused)?.uid()
        || before.nlink() != 1
    {
        return Err(Error::Refused);
    }
    let stream = connect(&SocketAddrUnix::new(&relative).map_err(refused)?, context)?;
    let after = std::fs::symlink_metadata(path).map_err(refused)?;
    if (
        before.dev(),
        before.ino(),
        before.uid(),
        before.gid(),
        before.mode(),
        before.nlink(),
    ) != (
        after.dev(),
        after.ino(),
        after.uid(),
        after.gid(),
        after.mode(),
        after.nlink(),
    ) {
        return Err(Error::Refused);
    }
    context.check()?;
    Ok(stream)
}
pub fn bind_fixture(root: &Path, path: &Path) -> Result<std::os::unix::net::UnixListener, Error> {
    let relative = fixture_path(root, path)?;
    std::os::unix::net::UnixListener::bind(relative).map_err(refused)
}
pub fn bind_native(root: &Path) -> Result<std::os::unix::net::UnixListener, Error> {
    super::linux::require_native_environment().map_err(refused)?;
    if root != Path::new("/") {
        return Err(Error::Refused);
    }
    #[cfg(target_os = "linux")]
    {
        std::os::unix::net::UnixListener::bind_addr(&crate::runtime_handoff::runtime_start_address(
            root,
        )?)
        .map_err(refused)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "runtime-io-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn actual_fixture_connection_is_nonblocking_cloexec_and_uses_same_owned_socket() {
        let root = Root::new();
        let path = root.0.join("io.sock");
        let cwd = std::env::current_dir().unwrap();
        let listener = UnixListener::bind(path.strip_prefix(cwd).unwrap()).unwrap();
        let context = StartContext::new(
            crate::subscription_serving::Cancellation::new(),
            Instant::now() + Duration::from_secs(1),
        );
        let mut stream = connect_fixture(&root.0, &path, &context).unwrap();
        assert!(
            rustix::io::fcntl_getfd(&stream)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::fs::fcntl_getfl(&stream)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
        let (mut peer, _) = listener.accept().unwrap();
        peer.write_all(b"ok").unwrap();
        let mut b = [0; 2];
        stream.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ok");
    }
    #[test]
    fn cancellation_deadline_and_untrusted_fixture_routes_never_connect() {
        let root = Root::new();
        let path = root.0.join("absent.sock");
        let stop = crate::subscription_serving::Cancellation::new();
        stop.cancel();
        let context = StartContext::new(stop, Instant::now() + Duration::from_secs(1));
        assert!(matches!(
            connect_fixture(&root.0, &path, &context),
            Err(Error::Cancelled)
        ));
        let context = StartContext::new(
            crate::subscription_serving::Cancellation::new(),
            Instant::now(),
        );
        assert!(matches!(
            connect_fixture(&root.0, &path, &context),
            Err(Error::Deadline)
        ));
        assert!(connect_fixture(Path::new("/"), &path, &context).is_err());
        assert!(connect_fixture(&root.0, Path::new("/tmp/outside.sock"), &context).is_err());
    }
    #[test]
    fn fixture_routes_refuse_parent_escape_symlinks_and_existing_listener_adoption() {
        let root = Root::new();
        let other = Root::new();
        let target = other.0.join("target.sock");
        let listener = bind_fixture(&other.0, &target).unwrap();
        let link = root.0.join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let context = StartContext::new(
            crate::subscription_serving::Cancellation::new(),
            Instant::now() + Duration::from_secs(1),
        );
        assert!(connect_fixture(&root.0, &link, &context).is_err());
        assert!(connect_fixture(&root.0, &root.0.join("../outside.sock"), &context).is_err());
        assert!(bind_fixture(&other.0, &target).is_err());
        assert!(listener.local_addr().is_ok());
    }
}
