use super::*;
use std::{
    cell::{Cell, RefCell},
    fs,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

const TABLE: &str = "1 0 8:1 / / rw - ext4 none rw\n2 1 0:1 / /proc rw - proc proc rw\n3 1 0:2 / /sys rw - sysfs sysfs rw\n4 1 8:2 / /data rw - ext4 none rw\n5 2 8:3 / /proc/nested rw - ext4 none rw\n6 1 0:3 / /memory rw - tmpfs none rw\n7 1 8:1 /source /same rw - ext4 none rw\n8 1 0:4 / /opaque rw - unknownfs none rw\n9 1 8:4 / /var/lib/sing-box/nested rw - ext4 none rw\n";
struct Fixture {
    root: PathBuf,
    table: String,
    fault: &'static str,
    group_only: bool,
    reads: Cell<usize>,
    scans: RefCell<Vec<String>>,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "mount-scan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        for path in [
            "proc/nested",
            "sys",
            "data",
            "memory",
            "same",
            "opaque",
            "var/lib/sing-box/nested",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::create_dir_all(root.join("proc/77")).unwrap();
        fs::write(root.join("proc/77/status"), b"virtual process metadata").unwrap();
        fs::write(root.join("sys/virtual"), b"virtual metadata").unwrap();
        Self {
            root,
            table: TABLE.into(),
            fault: "",
            group_only: false,
            reads: Cell::new(0),
            scans: RefCell::new(vec![]),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl Transport for Fixture {
    fn run(&self, command: &CommandSpec, _: &Cancellation) -> Result<CommandOutput, HostError> {
        assert!(!command.mutation());
        let args = command.arguments();
        match command.program() {
            "/usr/bin/getent" => {
                let (code, text) = if args[0] == "passwd" {
                    if self.group_only {
                        (2, "")
                    } else {
                        (0, "sing-box:x:999:998::/var/lib/sing-box:/usr/sbin/nologin")
                    }
                } else {
                    (0, "sing-box:x:998:")
                };
                CommandOutput::completed(code, text.as_bytes().to_vec())
            }
            "/usr/bin/pgrep" => CommandOutput::completed(
                0,
                if self.fault == "foreign-process" && args[0] != "-x" {
                    b"77\n88\n".to_vec()
                } else {
                    b"77\n".to_vec()
                },
            ),
            "/usr/bin/cat" => {
                assert_eq!(
                    args,
                    &[self.root.join("proc/self/mountinfo").to_string_lossy()]
                );
                assert!(command.timeout.unwrap() <= Duration::from_secs(5));
                let n = self.reads.get();
                self.reads.set(n + 1);
                if self.fault == "read" || self.fault == "reread" && n > 0 {
                    return CommandOutput::completed(1, vec![]);
                }
                let table = if self.fault == "topology" && n > 0 {
                    self.table.replace("8:2", "8:99")
                } else {
                    self.table.clone()
                };
                CommandOutput::completed(0, table.into_bytes())
            }
            "/usr/bin/find" => {
                if self.fault == "timeout" {
                    return Err(HostError::Timeout);
                }
                if self.fault == "scan" {
                    return CommandOutput::completed(1, vec![]);
                }
                self.scans.borrow_mut().push(args[0].clone());
                // Real nonprivileged find walks the fixture tree. Only ownership
                // predicates are replaced: every regular fixture file represents
                // account-owned data, except uid-only/gid-only controls. Mount
                // boundaries come from synthetic TABLE.
                let mut translated = Vec::new();
                let mut i = 0;
                while i < args.len() {
                    if args[i] == "-uid" || args[i] == "-gid" {
                        let (id, excluded) = if args[i] == "-uid" {
                            ("999", "gid-only")
                        } else {
                            ("998", "uid-only")
                        };
                        assert_eq!(args[i + 1], id);
                        translated.extend(
                            ["(", "-type", "f", "!", "-name", excluded, ")"].map(str::to_string),
                        );
                        i += 2;
                    } else {
                        translated.push(args[i].clone());
                        i += 1;
                    }
                }
                let out = Command::new("/usr/bin/find")
                    .args(translated)
                    .output()
                    .unwrap();
                CommandOutput::completed(out.status.code().unwrap(), out.stdout)
            }
            other => panic!("unexpected command {other}"),
        }
    }
}
fn runner(f: Fixture) -> SystemRunner<Fixture> {
    SystemRunner::construct(&f.root.clone(), f, &"a".repeat(64)).unwrap()
}

#[test]
fn allowed_running_process_metadata_and_clean_multiple_mounts_are_admitted() {
    for group_only in [false, true] {
        let mut f = Fixture::new();
        f.group_only = group_only;
        let r = runner(f);
        assert!(r.exclusive_accounts(&Cancellation::new()).is_ok());
        assert_eq!(r.transport.reads.get(), 2);
        assert_eq!(r.transport.scans.borrow().len(), 7);
        assert!(r.transport.scans.borrow().contains(&r.path("/proc/nested")));
        assert!(!r.transport.scans.borrow().contains(&r.path("/proc")));
    }
}
#[test]
fn data_mounts_including_nested_real_bind_tmpfs_and_unknown_remain_in_scope() {
    for path in [
        "data/foreign",
        "proc/nested/foreign",
        "memory/foreign",
        "same/foreign",
        "opaque/foreign",
        "var/lib/sing-box/nested/foreign",
    ] {
        for group_only in [false, true] {
            let mut f = Fixture::new();
            f.group_only = group_only;
            fs::write(f.root.join(path), b"owned data").unwrap();
            assert!(
                matches!(
                    runner(f).exclusive_accounts(&Cancellation::new()),
                    Err(HostError::Foreign)
                ),
                "{path}"
            );
        }
    }
}
#[test]
fn state_and_configuration_exceptions_do_not_apply_to_leftover_group() {
    let f = Fixture::new();
    fs::create_dir_all(f.root.join("etc/sing-box")).unwrap();
    fs::write(
        f.root.join("etc/sing-box/config.json"),
        b"owned configuration",
    )
    .unwrap();
    fs::write(f.root.join("var/lib/sing-box/owned"), b"owned state").unwrap();
    let r = runner(f);
    assert!(r.exclusive_accounts(&Cancellation::new()).is_ok());
    assert!(matches!(
        r.group_exclusive(998, &Cancellation::new()),
        Err(HostError::Foreign)
    ));
}
#[test]
fn scan_read_topology_deadline_and_process_failures_never_authorize() {
    for fault in [
        "read",
        "reread",
        "topology",
        "scan",
        "timeout",
        "foreign-process",
    ] {
        for group_only in [false, true] {
            let mut f = Fixture::new();
            f.fault = fault;
            f.group_only = group_only;
            assert!(
                runner(f).exclusive_accounts(&Cancellation::new()).is_err(),
                "{fault}"
            );
        }
    }
    let r = runner(Fixture::new());
    let stop = Cancellation::new();
    stop.cancel();
    assert!(r.account_files(Some(999), 998, &stop).is_err());
    assert_eq!(r.transport.reads.get(), 0);
    assert!(
        r.scan_output("/usr/bin/cat", &[], &Cancellation::new(), Instant::now())
            .is_err()
    );
    assert_eq!(r.transport.reads.get(), 0);
}
#[test]
fn mount_parser_refuses_incomplete_ambiguous_and_unsafe_observations() {
    for bad in [
        "".into(),
        TABLE.trim_end().into(),
        TABLE.replace("8:1", "bad"),
        TABLE.replace("/data", "/../data"),
        TABLE.replace("/data", "/proc"),
        TABLE.replace("4 1", "3 1"),
        TABLE.replace("/data", "/bad\\999"),
        TABLE.replace("1 0", "x 0"),
        TABLE.replace("1 0", "1 4"),
        TABLE.replace("/ / rw - ext4", "/ / rw - proc"),
    ] {
        assert!(mounts(bad.as_bytes()).is_err(), "{bad}");
        let mut f = Fixture::new();
        f.table = bad;
        assert!(runner(f).exclusive_accounts(&Cancellation::new()).is_err());
    }
    assert!(mounts(TABLE.replace("1 0", "1 1").as_bytes()).is_ok());
    assert!(mounts(&[0xff, b'\n']).is_err());
    assert!(mounts(&vec![b'\n'; process::OUTPUT_LIMIT + 1]).is_err());
    assert!(
        mounts(
            TABLE
                .replace("rw - ext4", "rw future:tag - ext4")
                .as_bytes()
        )
        .is_ok()
    );
    assert_eq!(
        mount_path(r"/a\040b\011c\012d\134e").unwrap(),
        "/a b\tc\nd\\e"
    );
}
#[test]
fn escaped_mount_patterns_do_not_prune_other_data() {
    let mut f = Fixture::new();
    f.table
        .push_str("10 1 0:9 / /v[ab]\\040space rw - proc none rw\n");
    fs::create_dir(f.root.join("v[ab] space")).unwrap();
    fs::write(f.root.join("v[ab] space/metadata"), b"virtual").unwrap();
    let r = runner(f);
    assert!(r.exclusive_accounts(&Cancellation::new()).is_ok());
    fs::create_dir(r.root.join("va space")).unwrap();
    fs::write(r.root.join("va space/foreign"), b"owned").unwrap();
    assert!(matches!(
        r.exclusive_accounts(&Cancellation::new()),
        Err(HostError::Foreign)
    ));
}

#[test]
fn uid_only_and_gid_only_data_both_block_identity_but_group_checks_only_gid() {
    for name in ["uid-only", "gid-only"] {
        let f = Fixture::new();
        fs::write(f.root.join("proc/nested").join(name), b"owned data").unwrap();
        let r = runner(f);
        assert!(matches!(
            r.exclusive_accounts(&Cancellation::new()),
            Err(HostError::Foreign)
        ));
        assert_eq!(
            r.group_exclusive(998, &Cancellation::new()).is_ok(),
            name == "uid-only"
        );
    }
}

#[test]
fn hidden_virtual_mount_cannot_prune_visible_data_after_overmount() {
    let mut f = Fixture::new();
    // The proc mount belongs to the root mount, not covering data mount 4.
    // Its old pathname is hidden; the visible directory is ordinary data.
    f.table
        .push_str("10 1 0:9 / /data/hidden rw - proc none rw\n");
    fs::create_dir(f.root.join("data/hidden")).unwrap();
    fs::write(f.root.join("data/hidden/foreign"), b"owned data").unwrap();
    assert!(runner(f).exclusive_accounts(&Cancellation::new()).is_err());
}

// systemd's normal binfmt_misc automount has two mount IDs at one path.
const BINFMT_STACK: &str = "10 2 0:32 / /proc/sys/fs/binfmt_misc rw shared:13 - autofs systemd-1 rw\n11 10 0:35 / /proc/sys/fs/binfmt_misc rw shared:35 - binfmt_misc binfmt_misc rw\n";
#[test]
fn binfmt_automount_metadata_stack_preserves_nested_data_coverage() {
    let mut f = Fixture::new();
    f.table.push_str(BINFMT_STACK);
    f.table
        .push_str("12 11 8:9 / /proc/sys/fs/binfmt_misc/data rw - ext4 none rw\n");
    fs::create_dir_all(f.root.join("proc/sys/fs/binfmt_misc/data")).unwrap();
    let r = runner(f);
    assert!(r.exclusive_accounts(&Cancellation::new()).is_ok());
    fs::write(
        r.root.join("proc/sys/fs/binfmt_misc/data/foreign"),
        b"owned data",
    )
    .unwrap();
    assert!(matches!(
        r.exclusive_accounts(&Cancellation::new()),
        Err(HostError::Foreign)
    ));
}
#[test]
fn binfmt_stack_never_hides_data_or_ambiguous_parentage() {
    for stack in [
        BINFMT_STACK.replace("- autofs", "- ext4"),
        BINFMT_STACK.replace("- binfmt_misc", "- tmpfs"),
        BINFMT_STACK.replace("11 10", "11 2"),
        BINFMT_STACK.replace("10 2", "10 1"),
        BINFMT_STACK.replace("0:32 /", "0:32 /subtree"),
        format!("{BINFMT_STACK}12 10 8:9 / /proc/sys/fs/binfmt_misc/hidden rw - ext4 none rw\n"),
        format!(
            "{BINFMT_STACK}12 11 0:36 / /proc/sys/fs/binfmt_misc rw - binfmt_misc binfmt_misc rw\n"
        ),
    ] {
        assert!(
            mounts(format!("{TABLE}{stack}").as_bytes()).is_err(),
            "{stack}"
        );
    }
}
