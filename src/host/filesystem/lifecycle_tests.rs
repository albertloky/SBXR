use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "lp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        stdfs::create_dir(&path).unwrap();
        let root = Self(path);
        for (path, mode) in [("", 0o700), ("run", 0o755), ("run/lock", 0o1777)] {
            let path = root.0.join(path);
            if !path.exists() {
                stdfs::create_dir(&path).unwrap();
            }
            stdfs::set_permissions(path, stdfs::Permissions::from_mode(mode)).unwrap();
        }
        root
    }
    fn lock(&self, body: &[u8]) -> PathBuf {
        let path = self.0.join("run/lock/sbxr.lock");
        stdfs::write(&path, body).unwrap();
        stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        stdfs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn inode_replacement_before_and_after_flock_is_refused_without_changing_either_file() {
    for point in [0, 1] {
        let root = Root::new();
        let path = root.lock(b"retained inode");
        let retained = root.0.join("run/lock/retained");
        let before = stdfs::metadata(&path).unwrap();
        let protected = ProtectedFs::open(&root.0).unwrap();
        let mut replaced = false;
        let result = protected.lifecycle_lock_probe(|at| {
            if at == point {
                stdfs::rename(&path, &retained).unwrap();
                root.lock(b"replacement inode");
                replaced = true;
            }
        });
        assert!(replaced);
        assert_eq!(result, Err(HostError::Foreign));
        let after = stdfs::metadata(&retained).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert_ne!(stdfs::metadata(&path).unwrap().ino(), before.ino());
        assert_eq!(stdfs::read(&retained).unwrap(), b"retained inode");
        assert_eq!(stdfs::read(&path).unwrap(), b"replacement inode");
        for path in [&path, &retained] {
            let fd = fs::open(path, OFlags::RDONLY | OFlags::NOFOLLOW, Mode::empty()).unwrap();
            fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        }
    }
}
#[test]
fn sticky_exception_does_not_relax_other_paths_or_expected_ownership() {
    let root = Root::new();
    let path = root.lock(b"preserve foreign file");
    let mut protected = ProtectedFs::open(&root.0).unwrap();
    assert_eq!(protected.lifecycle_lock_held(), Ok(false));
    assert!(matches!(
        protected.parent("run/lock/sbxr.lock", false),
        Err(HostError::Unsafe)
    ));
    assert!(matches!(
        super::super::super::locks::lock_parent(
            &protected.root,
            protected.uid,
            "run/lock/other",
            false
        ),
        Err(HostError::Unsafe)
    ));
    assert!(matches!(
        super::super::super::locks::lock_parent(
            &protected.root,
            protected.uid.wrapping_add(1),
            super::super::super::locks::MUTATION_LOCK,
            false
        ),
        Err(HostError::Unsafe)
    ));
    // A different expected group must refuse even a safely owned regular inode.
    protected.gid = protected.gid.wrapping_add(1);
    assert_eq!(protected.lifecycle_lock_held(), Err(HostError::Foreign));
    assert_eq!(stdfs::read(&path).unwrap(), b"preserve foreign file");
}
