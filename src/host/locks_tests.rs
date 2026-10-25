use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "locks-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        stdfs::create_dir(&path).unwrap();
        stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o700)).unwrap();
        for p in PACKAGE_LOCKS {
            let file = path.join(p);
            stdfs::create_dir_all(file.parent().unwrap()).unwrap();
            stdfs::write(&file, b"").unwrap();
            stdfs::set_permissions(file, stdfs::Permissions::from_mode(0o640)).unwrap();
        }
        Self(path)
    }
    fn uid(&self) -> u32 {
        stdfs::metadata(&self.0).unwrap().uid()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        stdfs::remove_dir_all(&self.0).unwrap()
    }
}
fn child_busy(path: &Path) -> bool {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "host::locks::tests::child_probe", "--nocapture"])
        .env("SBXR_LOCK_FIXTURE", path)
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .contains("FIXTURE-LOCK-BUSY")
}
#[test]
fn child_probe() {
    let Some(path) = std::env::var_os("SBXR_LOCK_FIXTURE") else {
        return;
    };
    let fd = fs::open(
        PathBuf::from(path),
        OFlags::RDWR | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .unwrap();
    match fs::fcntl_lock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => println!("FIXTURE-LOCK-FREE"),
        Err(Errno::AGAIN) | Err(Errno::ACCESS) => println!("FIXTURE-LOCK-BUSY"),
        Err(e) => panic!("fixture error: {e:?}"),
    }
}
#[test]
fn host_is_retained_and_package_checks_do_not_release_posix_locks() {
    let root = Root::new();
    let host = HostLock::acquire(&root.0, root.uid()).unwrap();
    assert!(matches!(
        HostLock::acquire(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    let package = host.acquire_packages().unwrap();
    for _ in 0..3 {
        package.verify().unwrap();
        assert!(child_busy(&root.0.join(PACKAGE_LOCKS[0])))
    }
    assert!(matches!(host.acquire_packages(), Err(HostError::Busy)));
    drop(package);
    assert!(!child_busy(&root.0.join(PACKAGE_LOCKS[0])));
    drop(host);
    HostLock::acquire(&root.0, root.uid()).unwrap();
}
#[test]
fn replacement_and_newly_appearing_lock_inodes_refuse() {
    let root = Root::new();
    stdfs::remove_file(root.0.join(PACKAGE_LOCKS[3])).unwrap();
    let host = HostLock::acquire(&root.0, root.uid()).unwrap();
    let package = host.acquire_packages().unwrap();
    stdfs::write(root.0.join(PACKAGE_LOCKS[3]), b"").unwrap();
    assert!(package.verify().is_err());
    drop(package);
    let mutation = root.0.join(MUTATION_LOCK);
    stdfs::rename(&mutation, mutation.with_extension("old")).unwrap();
    stdfs::write(&mutation, b"").unwrap();
    assert!(host.verify().is_err());
}
#[test]
fn foreign_modes_and_symlinks_are_preserved() {
    for mode in [0o644, 0o666] {
        let root = Root::new();
        let path = root.0.join(MUTATION_LOCK);
        stdfs::create_dir_all(path.parent().unwrap()).unwrap();
        stdfs::write(&path, b"keep").unwrap();
        stdfs::set_permissions(&path, stdfs::Permissions::from_mode(mode)).unwrap();
        assert!(HostLock::acquire(&root.0, root.uid()).is_err());
        assert_eq!(stdfs::read(path).unwrap(), b"keep");
    }
    let root = Root::new();
    let p = root.0.join(PACKAGE_LOCKS[0]);
    stdfs::remove_file(&p).unwrap();
    symlink(root.0.join(PACKAGE_LOCKS[1]), &p).unwrap();
    let host = HostLock::acquire(&root.0, root.uid()).unwrap();
    assert!(host.acquire_packages().is_err());
    assert!(p.is_symlink());
}

#[test]
fn private_existing_locks_do_not_create_and_owned_package_guards_retain_exclusion() {
    let root = Root::new();
    assert!(HostLock::existing(&root.0, root.uid()).is_err());
    assert!(HostLock::provision(&root.0, root.uid()).is_err());
    assert!(!root.0.join("run").exists());
    stdfs::create_dir_all(root.0.join("run/lock")).unwrap();
    let host = std::sync::Arc::new(HostLock::provision(&root.0, root.uid()).unwrap());
    let retained = host.retain_packages().unwrap();
    for _ in 0..2 {
        retained.verify().unwrap();
        assert!(child_busy(&root.0.join(PACKAGE_LOCKS[0])));
    }
    assert!(matches!(host.acquire_packages(), Err(HostError::Busy)));
    drop(retained);
    assert!(!child_busy(&root.0.join(PACKAGE_LOCKS[0])));
}

#[test]
fn runtime_duplicate_retains_owner_exclusion_and_rechecks_inode() {
    let root = Root::new();
    let owner = HostLock::acquire(&root.0, root.uid()).unwrap();
    let duplicate = owner.runtime_start_lock().unwrap();
    duplicate.start_lock().verify().unwrap();
    assert!(matches!(
        HostLock::existing(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    drop(duplicate);
    assert!(matches!(
        HostLock::existing(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    let path = root.0.join(MUTATION_LOCK);
    stdfs::rename(&path, path.with_extension("retained")).unwrap();
    stdfs::write(&path, []).unwrap();
    stdfs::set_permissions(&path, stdfs::Permissions::from_mode(0o600)).unwrap();
    assert!(owner.runtime_start_lock().is_err());
}

#[test]
fn store_drop_does_not_unlock_the_distinct_intentionally_lent_host_lock() {
    let root = Root::new();
    let state = root.0.join("var/lib/sbxr");
    stdfs::create_dir_all(&state).unwrap();
    stdfs::set_permissions(&state, stdfs::Permissions::from_mode(0o700)).unwrap();
    let owner = HostLock::acquire(&root.0, root.uid()).unwrap();
    let duplicate = owner.runtime_start_lock().unwrap();
    let store = crate::durable::OwnershipStore::open(&state, root.uid()).unwrap();
    drop(store);
    let next = crate::durable::OwnershipStore::open(&state, root.uid()).unwrap();
    duplicate.start_lock().verify().unwrap();
    assert!(matches!(
        HostLock::existing(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    drop(duplicate);
    owner.verify().unwrap();
    drop(next);
    assert!(matches!(
        HostLock::existing(&root.0, root.uid()),
        Err(HostError::Busy)
    ));
    drop(owner);
    HostLock::existing(&root.0, root.uid()).unwrap();
}
