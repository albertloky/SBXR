use super::*;
use crate::{
    domain::{Action, Confirmation, Outcome, Status},
    proxyinstallation::StandardInstallation,
    server_configuration::ServerIdentity,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn release() -> ReleaseIdentity {
    ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap()
}
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
            "linux-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        let root = Self(p);
        root.write(
            "etc/os-release",
            b"ID=ubuntu\nVERSION_ID=\"24.04\"\n",
            0o644,
        );
        let old = crate::release_identity::read_executable_identity(include_bytes!(
            "../../tests/testdata/release_identity/go-amd64-valid.bin"
        ))
        .unwrap();
        let executable = crate::release_identity::stamp_executable(
            old.payload(),
            "v3.1.118",
            &"a".repeat(40),
            192,
            crate::release_identity::Architecture::Amd64,
        )
        .unwrap();
        root.write("usr/local/bin/sbxr", &executable, 0o755);
        let record =
            InstalledRecord::new(release(), 192, "amd64", &sha256_hex(&executable)).unwrap();
        root.write(
            "var/lib/sbxr/installed.json",
            &record.encode().unwrap(),
            0o600,
        );
        fs::set_permissions(
            root.0.join("var/lib/sbxr"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        for path in ["var/lib", "usr/local/bin"] {
            fs::set_permissions(root.0.join(path), fs::Permissions::from_mode(0o755)).unwrap();
        }
        root
    }
    fn write(&self, path: &str, body: &[u8], mode: u32) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn host(&self) -> LinuxHost<Fake> {
        let key = b"synthetic key".to_vec();
        let package = b"synthetic package".to_vec();
        let configuration = ServerConfiguration::standard(
            &ServerIdentity::from_private_key(
                "12345678-1234-4234-8234-123456789abc",
                &"A".repeat(43),
                "01020304",
            )
            .unwrap(),
        )
        .unwrap();
        let material = SetupMaterial {
            key_sha256: sha256_hex(&key),
            package_sha256: sha256_hex(&package),
            key,
            package,
            configuration_digest: configuration.sha256_hex(),
            configuration: Some(configuration),
            offline: false,
        };
        LinuxHost::injected(&self.0, Fake::new(&self.0), material, admission()).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn admission() -> InjectedAdmission {
    InjectedAdmission {
        public_ipv4: "8.8.8.8".into(),
        root: true,
        architecture: "amd64".into(),
        destination_compatible: true,
        tcp443_available: true,
        host_lock_held: true,
        package_locks_held: true,
    }
}
#[derive(Clone)]
struct Fake {
    root: PathBuf,
    package: bool,
    held: bool,
    identity: bool,
    masked: bool,
    enabled: bool,
    active: bool,
    fail: Option<Operation>,
    fail_after: bool,
    cancel_after: Option<Operation>,
    queries_fail: bool,
    configuration_owner: bool,
    install_default: bool,
    effects: Vec<Operation>,
    native_capable: bool,
}
impl Fake {
    fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            package: false,
            held: false,
            identity: false,
            masked: false,
            enabled: false,
            active: false,
            fail: None,
            fail_after: false,
            cancel_after: None,
            queries_fail: false,
            configuration_owner: true,
            install_default: false,
            effects: vec![],
            native_capable: false,
        }
    }
}
impl CommandRunner for Fake {
    fn native_effects(&self) -> bool {
        self.native_capable
    }
    fn bind_configuration(&mut self, hash: &str) -> Result<(), HostError> {
        if hash.len() == 64 {
            Ok(())
        } else {
            Err(HostError::Foreign)
        }
    }
    fn query(&self, q: Query, stop: &Cancellation) -> Result<CommandOutput, HostError> {
        if self.queries_fail || stop.cancelled() {
            return Err(HostError::Unsafe);
        }
        let metadata = fs::metadata(&self.root).unwrap();
        let (code, text) = match q {
            Query::DestinationDns | Query::PublicIpDns => return Err(HostError::Unsafe),
            Query::Package => {
                if self.package {
                    (
                        0,
                        format!("1.14.3 amd64 {}", if self.held { "hi" } else { "ii" }),
                    )
                } else {
                    (1, String::new())
                }
            }
            Query::Hold => (0, if self.held { "sing-box" } else { "" }.into()),
            Query::User => {
                if self.identity {
                    (
                        0,
                        format!(
                            "sing-box:x:{}:{}::/nonexistent:/usr/sbin/nologin",
                            metadata.uid(),
                            metadata.gid()
                        ),
                    )
                } else {
                    (2, String::new())
                }
            }
            Query::Group => {
                if self.identity {
                    (0, format!("sing-box:x:{}:", metadata.gid()))
                } else {
                    (2, String::new())
                }
            }
            Query::Process => {
                if self.active {
                    (0, "123".into())
                } else {
                    (1, String::new())
                }
            }
            Query::Enabled => {
                if self.enabled {
                    (0, "enabled".into())
                } else if self.masked {
                    (1, "masked".into())
                } else if self.package {
                    (1, "disabled".into())
                } else {
                    (4, "not-found".into())
                }
            }
            Query::Active => {
                if self.active {
                    (0, "active".into())
                } else {
                    (3, "inactive".into())
                }
            }
            Query::LoadState => (
                0,
                if self.masked {
                    "masked"
                } else if self.package {
                    "loaded"
                } else {
                    "not-found"
                }
                .into(),
            ),
            Query::Listener => (
                0,
                if self.active {
                    "LISTEN 0 128 *:443 *:* users:((\"sing-box\",pid=123,fd=1))"
                } else {
                    ""
                }
                .into(),
            ),
            Query::ConfigurationOwner => {
                if self.package && self.configuration_owner {
                    (0, "sing-box: /etc/sing-box/config.json".into())
                } else {
                    (1, String::new())
                }
            }
            Query::UnitOwner => {
                if self.package {
                    (
                        0,
                        "sing-box: /usr/lib/systemd/system/sing-box.service".into(),
                    )
                } else {
                    (1, String::new())
                }
            }
            Query::ProxyStartCondition => return Err(HostError::LiveUnavailable),
            Query::Clock => (0, "yes".into()),
            Query::ValidateConfiguration => (0, String::new()),
        };
        CommandOutput::completed(code, text.into_bytes())
    }
    fn injected_effects(&self) -> bool {
        true
    }
    fn effect(&mut self, op: Operation, stop: &Cancellation) -> Result<(), HostError> {
        self.effects.push(op);
        if self.fail == Some(op) && !self.fail_after {
            return Err(HostError::Injected);
        }
        match op {
            Operation::MaskService => self.masked = true,
            Operation::InstallPackage => {
                self.package = true;
                self.identity = true;
                if self.install_default {
                    let default = crate::package_acquisition::DEFAULT_CONFIGURATION;
                    let config = self.root.join(CONFIG);
                    fs::create_dir_all(config.parent().unwrap()).unwrap();
                    fs::write(&config, default).unwrap();
                    fs::set_permissions(config, fs::Permissions::from_mode(0o644)).unwrap();
                }
                fs::create_dir_all(self.root.join("etc/sing-box")).unwrap();
                fs::set_permissions(
                    self.root.join("etc/sing-box"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                let unit = self.root.join("usr/lib/systemd/system/sing-box.service");
                fs::create_dir_all(unit.parent().unwrap()).unwrap();
                fs::write(&unit, b"synthetic package-owned unit\n").unwrap();
                fs::set_permissions(unit, fs::Permissions::from_mode(0o644)).unwrap();
            }
            Operation::HoldPackage => self.held = true,
            Operation::UnmaskService => self.masked = false,
            Operation::EnableService => self.enabled = true,
            Operation::StartService => self.active = true,
            Operation::StopDisableService => {
                self.active = false;
                self.enabled = false;
            }
            Operation::RemovePackage => {
                self.package = false;
                self.held = false;
                let unit = self.root.join("usr/lib/systemd/system/sing-box.service");
                if unit.exists() {
                    fs::remove_file(unit).unwrap();
                }
            }
            Operation::RemovePackageIdentity => self.identity = false,
            _ => (),
        };
        if self.cancel_after == Some(op) {
            stop.cancel();
            let uid = fs::metadata(&self.root).unwrap().uid();
            assert!(
                matches!(
                    crate::host::locks::HostLock::existing(&self.root, uid),
                    Err(HostError::Busy)
                ),
                "cancellation must not release retained Owner exclusion inside an effect"
            );
        }
        if self.fail == Some(op) && self.fail_after {
            return Err(HostError::Injected);
        }
        Ok(())
    }
}
fn execute<R: CommandRunner>(
    installation: &mut StandardInstallation<LinuxHost<R>>,
    action: Action,
) -> crate::domain::Result {
    let prepared = installation
        .review(action)
        .prepared
        .expect("legal injected action");
    installation.execute(prepared, Confirmation::Approved)
}
#[test]
fn injected_linux_setup_uses_actual_configuration_and_durable_core() {
    let root = Root::new();
    let mut host = root.host();
    host.runner.install_default = true;
    let expected = host.material.configuration_bytes().unwrap().to_vec();
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    assert_eq!(installation.review(Action::Status).status, Status::NotSetUp);
    let result = execute(&mut installation, Action::StartSetup);
    assert_eq!(result.outcome, Outcome::SetupComplete);
    assert!(result.message.contains("Injected"));
    assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), expected);
    assert!(
        installation
            .host()
            .runner()
            .effects
            .contains(&Operation::StartService)
    );
    drop(installation);
    let mut host = root.host();
    host.runner = Fake::new(&root.0);
    host.runner.package = true;
    host.runner.held = true;
    host.runner.identity = true;
    host.runner.enabled = true;
    host.runner.active = true;
    let installation = StandardInstallation::new(host, release()).unwrap();
    assert_eq!(installation.review(Action::Status).status, Status::Running);
}
#[test]
fn unsupported_host_and_unknown_commands_never_get_prepared_authority() {
    for field in 0..5 {
        let root = Root::new();
        let mut host = root.host();
        match field {
            0 => host.admission.root = false,
            1 => host.admission.architecture = "arm64".into(),
            2 => host.admission.destination_compatible = false,
            3 => host.admission.package_locks_held = false,
            _ => host.runner.queries_fail = true,
        };
        let installation = StandardInstallation::new(host, release()).unwrap();
        assert!(installation.review(Action::StartSetup).prepared.is_none());
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    }
}
#[test]
fn observation_change_after_review_refuses_before_effects() {
    let root = Root::new();
    let mut installation = StandardInstallation::new(root.host(), release()).unwrap();
    let token = installation.review(Action::StartSetup).prepared.unwrap();
    root.write("etc/os-release", b"ID=debian\nVERSION_ID=12\n", 0o644);
    assert_eq!(
        installation.execute(token, Confirmation::Approved).outcome,
        Outcome::Refused
    );
    assert!(installation.host().runner().effects.is_empty());
}
#[test]
fn protected_parents_and_foreign_files_are_preserved() {
    let root = Root::new();
    let outside = root.0.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::create_dir_all(root.0.join("etc/apt")).unwrap();
    symlink(&outside, root.0.join("etc/apt/keyrings")).unwrap();
    let installation = StandardInstallation::new(root.host(), release()).unwrap();
    assert!(installation.review(Action::StartSetup).prepared.is_none());
    assert!(fs::read_dir(outside).unwrap().next().is_none());
}
#[test]
fn native_is_explicitly_unsupported_on_mac_and_synthetic_packages_never_verify() {
    if !cfg!(target_os = "linux") {
        assert!(matches!(
            NativeObserver::open(),
            Err(HostError::UnsupportedHost)
        ))
    }
    let config = ServerConfiguration::standard(
        &ServerIdentity::from_private_key(
            "12345678-1234-4234-8234-123456789abc",
            &"A".repeat(43),
            "01020304",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        SetupMaterial::verified(
            b"synthetic key".to_vec(),
            b"synthetic package".to_vec(),
            config
        ),
        Err(HostError::Foreign)
    ));
}

#[test]
fn every_setup_checkpoint_reopens_with_its_exact_recovery_direction() {
    let phases = [
        SetupPhase::OwnershipRecorded,
        SetupPhase::AptKeyInstalled,
        SetupPhase::AptSourceInstalled,
        SetupPhase::ServiceMasked,
        SetupPhase::PackageInstalled,
        SetupPhase::PackageHeld,
        SetupPhase::StateDirectoryCreated,
        SetupPhase::ConfigurationInstalled,
        SetupPhase::ConfigurationValidated,
        SetupPhase::ServiceUnmasked,
        SetupPhase::ActivationCommitted,
        SetupPhase::ServiceEnabled,
        SetupPhase::ServiceStarted,
    ];
    for phase in phases {
        let root = Root::new();
        let mut host = root.host();
        host.interrupt_after(Some(phase));
        let mut installation = StandardInstallation::new(host, release()).unwrap();
        let result = execute(&mut installation, Action::StartSetup);
        let cleanup = phase.recovery_direction() == crate::records::RecoveryDirection::Cleanup;
        assert_eq!(
            result.outcome,
            if cleanup {
                Outcome::NeedsCleanup
            } else {
                Outcome::NeedsCompletion
            },
            "{phase:?}"
        );
        let runner = installation.host().runner().clone();
        drop(installation);
        let mut host = root.host();
        host.runner = runner;
        let mut installation = StandardInstallation::new(host, release()).unwrap();
        let action = if cleanup {
            Action::FinishCleanup
        } else {
            Action::FinishSetup
        };
        let opposite = if cleanup {
            Action::FinishSetup
        } else {
            Action::FinishCleanup
        };
        assert!(installation.review(opposite).prepared.is_none());
        let result = execute(&mut installation, action);
        assert_eq!(
            result.outcome,
            if cleanup {
                Outcome::CleanedUp
            } else {
                Outcome::SetupComplete
            },
            "{phase:?}"
        );
        assert_eq!(
            installation.review(Action::Status).status,
            if cleanup {
                Status::NotSetUp
            } else {
                Status::Running
            }
        );
    }
}
#[test]
fn precommit_failure_cleans_exact_files_and_postcommit_failure_only_finishes_forward() {
    for (operation, forward) in [
        (Operation::InstallPackage, false),
        (Operation::EnableService, true),
        (Operation::StartService, true),
    ] {
        let root = Root::new();
        let mut host = root.host();
        host.runner.fail = Some(operation);
        host.runner.fail_after = true;
        let mut installation = StandardInstallation::new(host, release()).unwrap();
        let result = execute(&mut installation, Action::StartSetup);
        if forward {
            assert_eq!(result.outcome, Outcome::NeedsCompletion);
            assert!(
                installation
                    .review(Action::FinishCleanup)
                    .prepared
                    .is_none()
            );
            installation.host_mut().runner_mut().fail = None;
            assert_eq!(
                execute(&mut installation, Action::FinishSetup).outcome,
                Outcome::SetupComplete
            );
        } else {
            assert_eq!(result.outcome, Outcome::CleanedUp);
            assert!(!root.0.join(CONFIG).exists());
            assert!(!root.0.join(ARTIFACT).exists());
        }
    }
}
#[test]
fn cleanup_preserves_unknown_child_and_remains_pending() {
    let root = Root::new();
    let mut host = root.host();
    host.interrupt_after(Some(SetupPhase::ConfigurationInstalled));
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    assert_eq!(
        execute(&mut installation, Action::StartSetup).outcome,
        Outcome::NeedsCleanup
    );
    root.write("etc/sing-box/foreign", b"keep", 0o600);
    assert_eq!(
        execute(&mut installation, Action::FinishCleanup).outcome,
        Outcome::NeedsCleanup
    );
    assert_eq!(
        fs::read(root.0.join("etc/sing-box/foreign")).unwrap(),
        b"keep"
    );
    assert!(root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}
#[test]
fn hardlinks_wrong_mode_and_changed_root_are_refused_without_effects() {
    for attack in 0..3 {
        let root = Root::new();
        let host = root.host();
        match attack {
            0 => {
                fs::hard_link(
                    root.0.join("var/lib/sbxr/installed.json"),
                    root.0.join("copy"),
                )
                .unwrap();
            }
            1 => {
                fs::set_permissions(root.0.join("etc"), fs::Permissions::from_mode(0o777)).unwrap()
            }
            _ => {
                let renamed = root.0.with_extension("old");
                fs::rename(&root.0, &renamed).unwrap();
                fs::create_dir(&root.0).unwrap();
                fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
                let refused = host.inspect_setup(&release()).is_err();
                fs::remove_dir(&root.0).unwrap();
                fs::rename(renamed, &root.0).unwrap();
                assert!(refused);
                continue;
            }
        }
        assert!(host.inspect_setup(&release()).is_err());
        assert!(host.runner.effects.is_empty());
    }
}

#[test]
fn protected_native_readers_bind_exact_records_configuration_and_pair() {
    let root = Root::new();
    let mut installation = StandardInstallation::new(root.host(), release()).unwrap();
    execute(&mut installation, Action::StartSetup);
    let host = installation.host();
    assert!(read_ownership(&host.fs).unwrap().is_some());
    assert!(read_installed(&host.fs).unwrap().is_some());
    let expected = host.configuration_sha256();
    let config =
        read_configuration(&host.fs, &host.runner, &expected, &Cancellation::new()).unwrap();
    assert_eq!(
        config.as_bytes(),
        host.material.configuration_bytes().unwrap()
    );
    assert_eq!(config.sha256_hex(), expected);
    assert!(!format!("{config:?}").contains("private_key"));
    assert!(
        read_configuration(
            &host.fs,
            &host.runner,
            &"0".repeat(64),
            &Cancellation::new()
        )
        .is_err()
    );
    fs::write(root.0.join("usr/local/bin/sbxr"), b"changed").unwrap();
    assert!(read_installed(&host.fs).is_err());
}

#[test]
fn native_runner_cannot_become_an_injected_effect_capability() {
    let root = Root::new();
    let material = root.host().material;
    assert!(matches!(
        LinuxHost::injected(&root.0, NativeReadOnly, material, admission()),
        Err(HostError::LiveUnavailable)
    ));
}

#[test]
fn activation_effects_refuse_incomplete_material_even_with_valid_record() {
    let root = Root::new();
    let mut host = root.host();
    let authority =
        OwnershipRecord::new_standard(release(), "8.8.8.8", &host.configuration_sha256()).unwrap();
    assert!(
        host.apply_setup(Operation::EnableService, &authority)
            .is_err()
    );
    assert!(
        host.apply_setup(Operation::StartService, &authority)
            .is_err()
    );
    assert!(host.runner.effects.is_empty());
}

#[test]
fn coherent_plain_text_pair_is_not_accepted_as_linux_release_structure() {
    let root = Root::new();
    let bytes = b"coherent text is not a native executable";
    root.write("usr/local/bin/sbxr", bytes, 0o755);
    let record = InstalledRecord::new(release(), 192, "amd64", &sha256_hex(bytes)).unwrap();
    root.write(
        "var/lib/sbxr/installed.json",
        &record.encode().unwrap(),
        0o600,
    );
    assert!(read_installed(&root.host().fs).is_err());
}

struct SystemFixtureTransport {
    backend: std::rc::Rc<std::cell::RefCell<Fake>>,
    commands: std::rc::Rc<std::cell::RefCell<Vec<super::super::system::CommandSpec>>>,
    user_deleted: std::cell::Cell<bool>,
    fail_groupdel: std::cell::Cell<bool>,
    fail_unhold: std::cell::Cell<bool>,
    fail_clock: std::cell::Cell<bool>,
    replace_group_after_userdel: std::cell::Cell<bool>,
    foreign_identity: std::rc::Rc<std::cell::Cell<bool>>,
}
impl super::super::system::Transport for SystemFixtureTransport {
    fn run(
        &self,
        spec: &super::super::system::CommandSpec,
        stop: &Cancellation,
    ) -> Result<CommandOutput, HostError> {
        self.commands.borrow_mut().push(spec.clone());
        let p = spec.program();
        let args = spec.arguments();
        for query in [
            Query::Package,
            Query::Hold,
            Query::User,
            Query::Group,
            Query::Process,
            Query::Enabled,
            Query::Active,
            Query::LoadState,
            Query::Listener,
            Query::UnitOwner,
            Query::ConfigurationOwner,
            Query::Clock,
            Query::ValidateConfiguration,
        ] {
            let (program, arguments) = query.argv();
            if p == program
                && args
                    .iter()
                    .map(String::as_str)
                    .eq(arguments.iter().copied())
            {
                if query == Query::Clock && self.fail_clock.get() {
                    return Err(HostError::Unsafe);
                }
                if query == Query::User && self.user_deleted.get() {
                    return CommandOutput::completed(2, vec![]);
                }
                let output = self.backend.borrow().query(query, stop)?;
                if query == Query::Group
                    && self.user_deleted.get()
                    && self.replace_group_after_userdel.get()
                    && output.code() == 0
                {
                    return CommandOutput::completed(
                        0,
                        format!("{}foreign-member", output.text()?).into_bytes(),
                    );
                }
                return Ok(output);
            }
        }
        let operation = match (
            p,
            args.iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        ) {
            ("/usr/bin/systemctl", ["mask", "sing-box.service"]) => Some(Operation::MaskService),
            ("/usr/bin/dpkg", ["--install", _]) => Some(Operation::InstallPackage),
            ("/usr/bin/apt-mark", ["hold", "sing-box"]) => Some(Operation::HoldPackage),
            ("/usr/bin/apt-mark", ["unhold", "sing-box"]) => {
                if self.fail_unhold.get() {
                    return CommandOutput::completed(1, vec![]);
                }
                self.backend.borrow_mut().held = false;
                None
            }
            ("/usr/bin/systemctl", ["unmask", "sing-box.service"]) => {
                Some(Operation::UnmaskService)
            }
            ("/usr/bin/systemctl", ["enable", "sing-box.service"]) => {
                Some(Operation::EnableService)
            }
            ("/usr/bin/systemctl", ["start", "sing-box.service"]) => Some(Operation::StartService),
            ("/usr/bin/systemctl", ["disable", "--now", "sing-box.service"]) => {
                Some(Operation::StopDisableService)
            }
            ("/usr/bin/systemctl", ["daemon-reload"]) => None,
            ("/usr/bin/systemctl", ["stop", "sbxr-mutation-lock.service"]) => None,
            ("/usr/bin/apt-get", ["update"]) => None,
            ("/usr/bin/apt-get", ["purge", "-y", "sing-box=1.14.3"]) => {
                Some(Operation::RemovePackage)
            }
            ("/usr/sbin/userdel", ["sing-box"]) => {
                self.user_deleted.set(true);
                None
            }
            ("/usr/sbin/groupdel", ["sing-box"]) => {
                if self.fail_groupdel.get() {
                    return CommandOutput::completed(1, vec![]);
                }
                Some(Operation::RemovePackageIdentity)
            }
            ("/usr/bin/find", _) => {
                return CommandOutput::completed(
                    0,
                    if self.foreign_identity.get() {
                        b"foreign owned path\n".to_vec()
                    } else {
                        vec![]
                    },
                );
            }
            ("/usr/bin/pgrep", ["-u" | "-G" | "-x", _]) => {
                return self.backend.borrow().query(Query::Process, stop);
            }
            _ => panic!("unexpected fixture command {spec:?}"),
        };
        if let Some(operation) = operation
            && self.backend.borrow_mut().effect(operation, stop).is_err()
        {
            return CommandOutput::completed(
                1,
                b"synthetic failure; no raw diagnostics escape".to_vec(),
            );
        }
        CommandOutput::completed(0, vec![])
    }
}
type SystemHost = LinuxHost<super::super::system::SystemRunner<SystemFixtureTransport>>;
type CommandLog = std::rc::Rc<std::cell::RefCell<Vec<super::super::system::CommandSpec>>>;
fn system_host(root: &Root) -> (SystemHost, CommandLog, std::rc::Rc<std::cell::Cell<bool>>) {
    let base = root.host();
    let commands = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let foreign = std::rc::Rc::new(std::cell::Cell::new(false));
    let transport = SystemFixtureTransport {
        backend: std::rc::Rc::new(std::cell::RefCell::new(base.runner)),
        commands: commands.clone(),
        user_deleted: std::cell::Cell::new(false),
        fail_groupdel: std::cell::Cell::new(false),
        fail_unhold: std::cell::Cell::new(false),
        fail_clock: std::cell::Cell::new(false),
        replace_group_after_userdel: std::cell::Cell::new(false),
        foreign_identity: foreign.clone(),
    };
    let runner = super::super::system::SystemRunner::injected(
        &root.0,
        transport,
        &base.material.configuration_sha256(),
    )
    .unwrap()
    .fixture_package(&base.material.package);
    (
        LinuxHost::injected(&root.0, runner, base.material, admission()).unwrap(),
        commands,
        foreign,
    )
}
#[test]
fn actual_system_adapter_drives_standard_setup_and_ownership_safe_cleanup() {
    for cleanup in [false, true] {
        let root = Root::new();
        let (mut host, commands, _) = system_host(&root);
        if cleanup {
            host.interrupt_after(Some(SetupPhase::ConfigurationValidated));
        }
        let mut installation = StandardInstallation::new(host, release()).unwrap();
        assert!(!root.0.join(super::super::locks::MUTATION_LOCK).exists());
        let prepared = installation.review(Action::StartSetup).prepared.unwrap();
        assert!(!root.0.join(super::super::locks::MUTATION_LOCK).exists());
        let result = installation.execute(prepared, Confirmation::Approved);
        assert_eq!(
            result.outcome,
            if cleanup {
                Outcome::NeedsCleanup
            } else {
                Outcome::SetupComplete
            }
        );
        if cleanup {
            let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
            assert_eq!(
                installation
                    .execute(prepared, Confirmation::Approved)
                    .outcome,
                Outcome::CleanedUp
            );
            assert!(
                commands
                    .borrow()
                    .iter()
                    .any(|c| c.program() == "/usr/sbin/userdel")
            );
            assert!(
                commands
                    .borrow()
                    .iter()
                    .any(|c| c.program() == "/usr/sbin/groupdel")
            );
            assert!(!root.0.join(CONFIG).exists());
        } else {
            assert_eq!(
                fs::metadata(root.0.join(CONFIG)).unwrap().gid(),
                fs::metadata(&root.0).unwrap().gid()
            );
            assert_eq!(installation.review(Action::Status).status, Status::Running);
        }
        assert!(
            commands
                .borrow()
                .iter()
                .any(|c| c.program() == "/usr/bin/dpkg")
        );
        assert!(
            commands
                .borrow()
                .iter()
                .any(|c| c.arguments() == ["daemon-reload"])
        );
        // Execute released exclusion; the persistent coordination inode is preserved.
        super::super::locks::HostLock::acquire(&root.0, fs::metadata(&root.0).unwrap().uid())
            .unwrap();
    }
}
#[test]
fn system_adapter_preserves_foreign_identity_resources_and_pending_direction() {
    let root = Root::new();
    let (mut host, commands, foreign) = system_host(&root);
    host.interrupt_after(Some(SetupPhase::ConfigurationValidated));
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    foreign.set(true);
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    assert!(
        !commands
            .borrow()
            .iter()
            .any(|c| c.program() == "/usr/sbin/userdel")
    );
    assert!(root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}
#[test]
fn competing_host_lock_refuses_prepared_action_without_system_mutation() {
    let root = Root::new();
    let (host, commands, _) = system_host(&root);
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    let competing =
        super::super::locks::HostLock::acquire(&root.0, fs::metadata(&root.0).unwrap().uid())
            .unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::Refused
    );
    assert!(!commands.borrow().iter().any(|c| c.mutation()));
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    drop(competing);
}

#[test]
fn partial_user_deletion_keeps_group_cleanup_recoverable() {
    let root = Root::new();
    let (mut host, _, _) = system_host(&root);
    host.interrupt_after(Some(SetupPhase::ConfigurationValidated));
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    installation
        .host()
        .runner()
        .transport()
        .fail_groupdel
        .set(true);
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    assert!(installation.host().runner().transport().user_deleted.get());
    installation
        .host()
        .runner()
        .transport()
        .fail_groupdel
        .set(false);
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::CleanedUp
    );
}

#[test]
fn missing_package_identity_proof_preserves_existing_state() {
    for staged_only in [false, true] {
        let root = Root::new();
        let (mut host, commands, _) = system_host(&root);
        host.interrupt_after(Some(SetupPhase::ConfigurationValidated));
        let mut installation = StandardInstallation::new(host, release()).unwrap();
        let prepared = installation.review(Action::StartSetup).prepared.unwrap();
        assert_eq!(
            installation
                .execute(prepared, Confirmation::Approved)
                .outcome,
            Outcome::NeedsCleanup
        );
        let configuration_path = if staged_only {
            let stage = root.0.join(format!("{CONFIG}.sbxr-next"));
            fs::rename(root.0.join(CONFIG), &stage).unwrap();
            fs::remove_dir(root.0.join("var/lib/sing-box")).unwrap();
            stage
        } else {
            root.0.join(CONFIG)
        };
        let configuration = fs::read(&configuration_path).unwrap();
        installation
            .host()
            .runner()
            .transport()
            .user_deleted
            .set(true);
        commands.borrow_mut().clear();
        assert!(
            installation
                .review(Action::FinishCleanup)
                .prepared
                .is_none()
        );
        assert_eq!(fs::read(&configuration_path).unwrap(), configuration);
        assert_eq!(root.0.join("var/lib/sing-box").exists(), !staged_only);
        assert!(!commands.borrow().iter().any(|c| c.mutation()));
        assert_eq!(
            OwnershipRecord::decode(
                &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap()
            )
            .unwrap()
            .recovery_direction(),
            crate::records::RecoveryDirection::Cleanup
        );
    }
}

#[test]
fn package_identity_proof_preserves_changed_group_after_user_deletion() {
    let root = Root::new();
    let (mut host, commands, _) = system_host(&root);
    host.interrupt_after(Some(SetupPhase::ConfigurationValidated));
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    installation
        .host()
        .runner()
        .transport()
        .replace_group_after_userdel
        .set(true);
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    assert!(installation.host().runner().transport().user_deleted.get());
    assert!(
        !commands
            .borrow()
            .iter()
            .any(|c| c.program() == "/usr/sbin/groupdel")
    );
    assert_eq!(
        OwnershipRecord::decode(
            &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap()
        )
        .unwrap()
        .recovery_direction(),
        crate::records::RecoveryDirection::Cleanup
    );
}

#[test]
fn authenticated_standard_factory_and_private_roles_recheck_protected_installed_bytes() {
    use crate::private_roles::{Role, Runtime};
    let root = Root::new();
    // This fixture crosses the signature boundary only in cfg(test); the real
    // acquisition test separately refuses a genuine foreign signer/claim set.
    let (authenticated, executable) = crate::release_acquisition::fixture_authenticated();
    root.write("usr/local/bin/sbxr", &executable, 0o755);
    root.write(
        "var/lib/sbxr/installed.json",
        &authenticated.record().encode().unwrap(),
        0o600,
    );
    fs::create_dir_all(root.0.join("run/lock")).unwrap();
    let mut runtime = crate::host::runtime::InjectedRuntime::open(&root.0, &authenticated).unwrap();
    assert_eq!(runtime.invoke(Role::ProvisionMutationLock), 0);
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    assert_eq!(runtime.invoke(Role::ProxyStartAuthorize), 1);
    assert_eq!(runtime.invoke(Role::SubscriptionServing), 1);
    let base = root.host();
    let host = LinuxHost::injected_authenticated(
        &root.0,
        base.runner,
        base.material,
        admission(),
        &authenticated,
    )
    .unwrap();
    let mut installation =
        StandardInstallation::new(host, authenticated.record().release_identity()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::SetupComplete
    );
    let mut wire: serde_json::Value = serde_json::from_slice(
        &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
    )
    .unwrap();
    let startup = b"[Service]\nExecCondition=+/usr/local/bin/sbxr --proxy-start-authorize\n";
    root.write(
        "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
        startup,
        0o644,
    );
    wire["schema"] = 2.into();
    wire["proxy_startup"] =
        serde_json::json!({"drop_in_sha256":sha256_hex(startup),"directory_created":true});
    let resources = wire["permitted_resources"].as_array_mut().unwrap();
    resources[0] = resources[0]
        .as_str()
        .unwrap()
        .replace("schema-1", "schema-2")
        .into();
    resources.push(format!("/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf root:root 0644 one-link sha256:{}",sha256_hex(startup)).into());
    resources.push("/etc/systemd/system/sing-box.service.d root:root 0755 SBXR-created empty-after-drop-in-removal".into());
    let count = resources.len();
    wire["resource_creating_releases"] =
        serde_json::Value::Array(vec![wire["release_identity"].clone(); count]);
    let record = OwnershipRecord::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &record.encode().unwrap(),
        0o600,
    );
    assert_eq!(runtime.invoke(Role::ProxyStartAuthorize), 0);
    for path in [
        "var/lib/.sbxr-removal.json".to_owned(),
        format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
    ] {
        root.write(&path, b"foreign pending authority", 0o600);
        assert_eq!(runtime.invoke(Role::ProxyStartAuthorize), 1);
        assert_eq!(
            fs::read(root.0.join(&path)).unwrap(),
            b"foreign pending authority"
        );
        fs::remove_file(root.0.join(path)).unwrap();
    }
    let owner =
        crate::host::locks::HostLock::existing(&root.0, fs::metadata(&root.0).unwrap().uid())
            .unwrap();
    assert_eq!(runtime.invoke(Role::ProxyStartAuthorize), 1);
    owner.verify().unwrap();
    drop(owner);
    assert_eq!(runtime.invoke(Role::ProxyStartAuthorize), 0);
    root.write(
        "etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf",
        b"foreign",
        0o644,
    );
    assert_eq!(runtime.invoke(Role::ProxyStartAuthorize), 1);
    root.write("usr/local/bin/sbxr", b"foreign", 0o755);
    assert_eq!(runtime.invoke(Role::ProvisionMutationLock), 1);
    let base = root.host();
    assert!(
        LinuxHost::injected_authenticated(
            &root.0,
            base.runner,
            base.material,
            admission(),
            &authenticated
        )
        .is_err()
    );
}
#[test]
fn existing_standard_decoding_preserves_raw_hash_and_derives_client_values() {
    let root = Root::new();
    let host = root.host();
    let bytes = host.material.configuration_bytes().unwrap();
    let decoded = ServerConfiguration::decode_standard(bytes).unwrap();
    assert_eq!(decoded.as_bytes(), bytes);
    let facts = decoded.connection_facts("8.8.8.8").unwrap();
    assert_eq!(facts.public_ipv4().to_string(), "8.8.8.8");
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(bytes).unwrap())
            .unwrap();
    assert_eq!(
        ServerConfiguration::decode_standard(&pretty)
            .unwrap()
            .as_bytes(),
        pretty
    );
    let mut bad: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    bad["unknown"] = true.into();
    assert!(ServerConfiguration::decode_standard(&serde_json::to_vec(&bad).unwrap()).is_err());
    let mut duplicate = bytes.to_vec();
    duplicate.splice(1..1, b"\"inbounds\":[],".iter().copied());
    assert!(ServerConfiguration::decode_standard(&duplicate).is_err());
    assert_eq!(format!("{decoded:?}"), "Server configuration (redacted)");
}

#[test]
fn package_hold_footprint_never_counts_as_absent() {
    let root = Root::new();
    let mut host = root.host();
    host.runner.held = true;
    let installation = StandardInstallation::new(host, release()).unwrap();
    assert!(installation.review(Action::StartSetup).prepared.is_none());
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
}
#[test]
fn failed_package_unhold_keeps_cleanup_pending_and_never_purges() {
    let root = Root::new();
    let (mut host, commands, _) = system_host(&root);
    host.interrupt_after(Some(SetupPhase::ConfigurationValidated));
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    installation
        .host()
        .runner()
        .transport()
        .fail_unhold
        .set(true);
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::NeedsCleanup
    );
    assert!(
        !commands
            .borrow()
            .iter()
            .any(|c| c.program() == "/usr/bin/apt-get"
                && c.arguments().first().is_some_and(|a| a == "purge"))
    );
    assert!(
        installation
            .host()
            .runner()
            .transport()
            .backend
            .borrow()
            .held
    );
    installation
        .host()
        .runner()
        .transport()
        .fail_unhold
        .set(false);
    let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::CleanedUp
    );
}

#[test]
fn invalid_pinned_material_never_generates_credentials() {
    struct NoEntropy;
    impl crate::identity_generation::Entropy for NoEntropy {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::identity_generation::IdentityError> {
            panic!("invalid material reached entropy")
        }
    }
    assert!(matches!(
        SetupMaterial::generated_standard(
            b"synthetic invalid key".to_vec(),
            vec![],
            &mut NoEntropy
        ),
        Err(HostError::Foreign)
    ));
}

fn running_removal_host(
    root: &Root,
) -> (
    StandardRemovalHost<super::super::system::SystemRunner<SystemFixtureTransport>>,
    CommandLog,
) {
    let (authenticated, executable) = crate::release_acquisition::fixture_authenticated();
    root.write("usr/local/bin/sbxr", &executable, 0o755);
    root.write(
        "var/lib/sbxr/installed.json",
        &authenticated.record().encode().unwrap(),
        0o600,
    );
    let (base, commands, _) = system_host(root);
    let host = LinuxHost::injected_authenticated(
        &root.0,
        base.runner,
        base.material,
        admission(),
        &authenticated,
    )
    .unwrap();
    let mut setup =
        StandardInstallation::new(host, authenticated.record().release_identity()).unwrap();
    let prepared = setup.review(Action::StartSetup).prepared.unwrap();
    assert_eq!(
        setup.execute(prepared, Confirmation::Approved).outcome,
        Outcome::SetupComplete
    );
    (
        StandardRemovalHost::new(setup.into_host()).unwrap(),
        commands,
    )
}
#[test]
fn actual_standard_removal_requires_typed_confirmation_and_deletes_exact_owned_pair() {
    for approved in [false, true] {
        let root = Root::new();
        let (host, commands) = running_removal_host(&root);
        let mut installation = crate::proxyinstallation::RemovalInstallation::new(host);
        let input = if approved {
            b"2\nREMOVE SBXR\n".as_slice()
        } else {
            b"2\ny\n0\n".as_slice()
        };
        let mut input = std::io::Cursor::new(input);
        let mut output = vec![];
        crate::terminal::run(&mut input, &mut output, &mut installation).unwrap();
        assert_eq!(root.0.join("usr/local/bin/sbxr").exists(), !approved);
        assert_eq!(root.0.join("var/lib/sbxr").exists(), !approved);
        assert!(!root.0.join("var/lib/.sbxr-removal.json").exists());
        if approved {
            assert!(
                String::from_utf8(output)
                    .unwrap()
                    .contains("SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED")
            );
            let log = commands.borrow();
            let unhold = log
                .iter()
                .position(|c| c.arguments() == ["unhold", "sing-box"])
                .unwrap();
            let purge = log
                .iter()
                .position(|c| c.arguments().first().is_some_and(|a| a == "purge"))
                .unwrap();
            assert!(unhold < purge);
        }
    }
}
#[test]
fn durable_standard_finalizer_resumes_after_move_and_directory_removal() {
    for point in [1, 2, 3] {
        let root = Root::new();
        let (mut host, _) = running_removal_host(&root);
        host.interrupt_finalization(point);
        let mut installation = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = installation
            .review(Action::CompleteRemoval)
            .prepared
            .unwrap();
        let result = installation.execute(prepared, Confirmation::Approved);
        assert_eq!(result.outcome, Outcome::RemovalNeedsCompletion);
        assert_eq!(
            result.status,
            if point == 3 {
                Status::ProblemDetected
            } else {
                Status::RemovalIncomplete
            }
        );
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
        assert_eq!(
            root.0.join("var/lib/.sbxr-removal.json").exists(),
            point != 3
        );
        let review = installation.review(Action::FinishRemoval);
        if point == 3 {
            assert!(review.prepared.is_none());
        } else {
            assert_eq!(
                installation
                    .execute(review.prepared.unwrap(), Confirmation::Approved)
                    .outcome,
                Outcome::RemovalComplete
            );
            assert!(!root.0.join("var/lib/sbxr").exists());
            assert!(!root.0.join("var/lib/.sbxr-removal.json").exists());
        }
    }
}
#[test]
fn removal_prepared_actions_expire_and_foreign_files_are_preserved() {
    let root = Root::new();
    let (host, _) = running_removal_host(&root);
    let mut installation = crate::proxyinstallation::RemovalInstallation::new(host);
    let prepared = installation
        .review(Action::CompleteRemoval)
        .prepared
        .unwrap();
    installation.review(Action::Status);
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::Refused
    );
    root.write("etc/sing-box/foreign", b"preserved", 0o644);
    assert!(
        installation
            .review(Action::CompleteRemoval)
            .prepared
            .is_none()
    );
    assert_eq!(
        fs::read(root.0.join("etc/sing-box/foreign")).unwrap(),
        b"preserved"
    );
    assert_eq!(
        OwnershipRecord::decode(
            &fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap()
        )
        .unwrap()
        .phase(),
        SetupPhase::Running
    );
}

#[test]
fn product_only_and_pre_activation_removal_remove_no_foreign_resources() {
    for setup in [false, true] {
        let root = Root::new();
        let (authenticated, executable) = crate::release_acquisition::fixture_authenticated();
        root.write("usr/local/bin/sbxr", &executable, 0o755);
        root.write(
            "var/lib/sbxr/installed.json",
            &authenticated.record().encode().unwrap(),
            0o600,
        );
        let (base, _, _) = system_host(&root);
        let mut host = LinuxHost::injected_authenticated(
            &root.0,
            base.runner,
            base.material,
            admission(),
            &authenticated,
        )
        .unwrap();
        if setup {
            host.interrupt_after(Some(SetupPhase::PackageHeld));
            let mut installation =
                StandardInstallation::new(host, authenticated.record().release_identity()).unwrap();
            let prepared = installation.review(Action::StartSetup).prepared.unwrap();
            assert_eq!(
                installation
                    .execute(prepared, Confirmation::Approved)
                    .outcome,
                Outcome::NeedsCleanup
            );
            host = installation.into_host();
        }
        let host = StandardRemovalHost::new(host).unwrap();
        let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalComplete
        );
        assert!(!root.0.join("var/lib/sbxr").exists());
        assert!(!root.0.join("etc/systemd/system/sing-box.service").exists());
    }
}

#[test]
fn durable_removal_staging_never_skips_or_grants_a_checkpoint() {
    let root = Root::new();
    let material = root.host();
    let mut store = crate::durable::OwnershipStore::open(
        &root.0.join("var/lib/sbxr"),
        fs::metadata(&root.0).unwrap().uid(),
    )
    .unwrap();
    let source =
        OwnershipRecord::new_standard(release(), "8.8.8.8", &material.configuration_sha256())
            .unwrap();
    store.publish(None, &source).unwrap();
    let committed = crate::removal::commit_removal(Some(&source), &release()).unwrap();
    store
        .publish(Some(&source.encode().unwrap()), &committed)
        .unwrap();
    let next = crate::removal::next_checkpoint(&committed).unwrap();
    root.write(
        &format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
        &next.encode().unwrap(),
        0o600,
    );
    let snapshot = store.load().unwrap();
    assert_eq!(snapshot.recovery(), crate::durable::Recovery::Removal);
    assert_eq!(
        crate::removal::checkpoint(&snapshot.current.unwrap().record).unwrap(),
        0
    );
    let skipped = crate::removal::next_checkpoint(&next).unwrap();
    assert!(
        store
            .publish(Some(&committed.encode().unwrap()), &skipped)
            .is_err()
    );
    store
        .publish(Some(&committed.encode().unwrap()), &next)
        .unwrap();
    assert_eq!(
        crate::removal::checkpoint(&store.load().unwrap().current.unwrap().record).unwrap(),
        1
    );
}
#[test]
fn standard_removal_requires_ownership_without_clock_or_network_availability() {
    let root = Root::new();
    let (mut host, _) = running_removal_host(&root);
    host.inner.runner.transport().fail_clock.set(true);
    host.inner.admission.destination_compatible = false;
    host.inner.admission.tcp443_available = false;
    let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
    let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
    assert_eq!(
        removal.execute(prepared, Confirmation::Approved).outcome,
        Outcome::RemovalComplete
    );
}

#[test]
fn restored_exact_finisher_reopens_and_completes_actual_product_only_removal() {
    let root = Root::new();
    let archive = crate::release_acquisition::fixture_archive();
    fs::remove_file(root.0.join("usr/local/bin/sbxr")).unwrap();
    fs::remove_file(root.0.join("var/lib/sbxr/installed.json")).unwrap();
    fs::remove_dir(root.0.join("var/lib/sbxr")).unwrap();
    fs::create_dir_all(root.0.join("run/lock")).unwrap();
    let mut record =
        crate::removal::commit_removal(None, &archive.record().release_identity()).unwrap();
    while crate::removal::checkpoint(&record).unwrap()
        < crate::removal::checkpoint_limit(&record).unwrap()
    {
        record = crate::removal::next_checkpoint(&record).unwrap();
    }
    let authority = record.encode().unwrap();
    root.write("var/lib/.sbxr-removal.json", &authority, 0o600);
    let restored = {
        let mut recovery = crate::host::restoration::RestorationHost::injected(&root.0).unwrap();
        recovery
            .restore(&archive, &crate::artifact_trust::SelectionBudget::new())
            .unwrap()
    };
    assert_eq!(
        fs::read(root.0.join("var/lib/.sbxr-removal.json")).unwrap(),
        authority
    );
    // This injected test supplies simulated current bytes. Native recovery must
    // launch and authenticate the exact finisher; restoration proves files only.
    assert!(restored.record() == archive.record());
    let bytes = fs::read(root.0.join("usr/local/bin/sbxr")).unwrap();
    let authenticated = archive
        .bind_current(
            &bytes,
            &bytes,
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let (base, commands, _) = system_host(&root);
    let host = LinuxHost::injected_authenticated(
        &root.0,
        base.runner,
        base.material,
        admission(),
        &authenticated,
    )
    .unwrap();
    let mut removal =
        crate::proxyinstallation::RemovalInstallation::new(StandardRemovalHost::new(host).unwrap());
    let prepared = removal.review(Action::FinishRemoval).prepared.unwrap();
    assert_eq!(
        removal.execute(prepared, Confirmation::Approved).outcome,
        Outcome::RemovalComplete
    );
    assert!(!root.0.join("var/lib/sbxr").exists());
    assert!(!root.0.join("usr/local/bin/sbxr").exists());
    assert!(!root.0.join("var/lib/.sbxr-removal.json").exists());
    assert!(!commands.borrow().iter().any(|c| c.mutation()));
}

#[test]
fn fake_package_material_has_explicit_contract_modes() {
    let root = Root::new();
    let mut runner = Fake::new(&root.0);
    runner
        .effect(Operation::InstallPackage, &Cancellation::new())
        .unwrap();
    for (path, mode) in [
        ("etc/sing-box", 0o755),
        ("usr/lib/systemd/system/sing-box.service", 0o644),
    ] {
        assert_eq!(
            fs::metadata(root.0.join(path)).unwrap().mode() & 0o7777,
            mode
        );
    }
}

#[test]
fn journal_only_cleanup_reopens_without_saved_secrets_or_network() {
    for phase in [
        SetupPhase::OwnershipRecorded,
        SetupPhase::AptKeyInstalled,
        SetupPhase::AptSourceInstalled,
        SetupPhase::ServiceMasked,
        SetupPhase::PackageInstalled,
        SetupPhase::PackageHeld,
        SetupPhase::StateDirectoryCreated,
        SetupPhase::ConfigurationInstalled,
        SetupPhase::ConfigurationValidated,
        SetupPhase::ServiceUnmasked,
    ] {
        let root = Root::new();
        let (mut host, commands, _) = system_host(&root);
        host.interrupt_after(Some(phase));
        let mut setup = StandardInstallation::new(host, release()).unwrap();
        assert_eq!(
            execute(&mut setup, Action::StartSetup).outcome,
            Outcome::NeedsCleanup
        );
        let mut host = setup.into_host();
        let record = read_ownership(&host.fs).unwrap().unwrap();
        let mut offline = SetupMaterial::for_cleanup(&record).unwrap();
        // Only these synthetic test hashes replace the production upstream pins.
        offline.key_sha256 = host.material.key_sha256.clone();
        offline.package_sha256 = host.material.package_sha256.clone();
        assert!(
            offline.configuration.is_none() && offline.key.is_empty() && offline.package.is_empty()
        );
        host.material = offline;
        host.interrupt_after(None);
        host.admission.destination_compatible = false;
        host.admission.tcp443_available = false;
        host.runner.transport().fail_clock.set(true);
        let count = commands.borrow().len();
        let mut reopened = StandardInstallation::new(host, release()).unwrap();
        let review = reopened.review(Action::FinishCleanup);
        assert!(
            review.prepared.is_some(),
            "{phase:?}: {:?}",
            reopened.host().inspect_setup(&release())
        );
        assert_eq!(
            reopened
                .execute(review.prepared.unwrap(), Confirmation::Approved)
                .outcome,
            Outcome::CleanedUp,
            "{phase:?}"
        );
        assert!(reopened.review(Action::StartSetup).prepared.is_none());
        assert_eq!(reopened.review(Action::Status).status, Status::NotSetUp);
        assert!(!root.0.join(CONFIG).exists());
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
        assert!(commands.borrow()[count..].iter().all(|c| {
            !matches!(c.program(), "/usr/bin/sing-box" | "/usr/bin/getent")
                || c.arguments()
                    .first()
                    .is_some_and(|a| matches!(a.as_str(), "passwd" | "group"))
        }));
    }
}
#[test]
fn journal_only_cleanup_preserves_unbound_configuration_and_cannot_reverse_commitment() {
    let root = Root::new();
    let mut host = root.host();
    host.interrupt_after(Some(SetupPhase::OwnershipRecorded));
    let mut setup = StandardInstallation::new(host, release()).unwrap();
    assert_eq!(
        execute(&mut setup, Action::StartSetup).outcome,
        Outcome::NeedsCleanup
    );
    let mut host = setup.into_host();
    let source = read_ownership(&host.fs).unwrap().unwrap();
    host.material = SetupMaterial::for_cleanup(&source).unwrap();
    root.write(CONFIG, b"unrecorded configuration", 0o640);
    let setup = StandardInstallation::new(host, release()).unwrap();
    assert!(setup.review(Action::FinishCleanup).prepared.is_none());
    assert_eq!(
        fs::read(root.0.join(CONFIG)).unwrap(),
        b"unrecorded configuration"
    );
    let mut record = source;
    while record.phase() != SetupPhase::ActivationCommitted {
        record = record.next_setup_checkpoint().unwrap();
    }
    assert!(SetupMaterial::for_cleanup(&record).is_err());
}

#[derive(Clone)]
struct RemovalAuxiliary {
    active: std::rc::Rc<std::cell::Cell<bool>>,
    firewall: std::rc::Rc<std::cell::Cell<bool>>,
    fail_stop: std::rc::Rc<std::cell::Cell<bool>>,
}
impl AuxiliaryRuntime for RemovalAuxiliary {
    fn observe(&self, _: &OwnershipRecord) -> Result<AuxiliaryFacts, HostError> {
        let rule = if self.firewall.get() {
            "-A INPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT\n"
        } else {
            ""
        };
        Ok(AuxiliaryFacts {
            fingerprint: format!("fixture:{}", self.active.get()),
            serving_running: self.active.get(),
            quiescent: !self.active.get(),
            firewall_rules: format!("*filter\n:INPUT ACCEPT [0:0]\n{rule}COMMIT\n"),
        })
    }
    fn disable(
        &mut self,
        firewall: bool,
        _: &OwnershipRecord,
        owner: &Arc<super::super::locks::HostLock>,
    ) -> Result<(), HostError> {
        owner.verify()?;
        if self.fail_stop.get() {
            return Err(HostError::Injected);
        }
        if firewall {
            self.firewall.set(false);
        } else {
            self.active.set(false);
        }
        Ok(())
    }
}
fn http_removal_host(
    root: &Root,
    pending: bool,
) -> (
    StandardRemovalHost<
        super::super::system::SystemRunner<SystemFixtureTransport>,
        RemovalAuxiliary,
    >,
    RemovalAuxiliary,
) {
    let (mut host, _) = running_removal_host(root);
    let record = read_ownership(&host.inner.fs).unwrap().unwrap();
    let credential =
        crate::subscription_artifact::SubscriptionCredential::parse(&"A".repeat(43)).unwrap();
    let firewall = crate::host::subscription::http_firewall_unit(record.public_ipv4()).unwrap();
    let mut record = record
        .begin_http_enablement(
            &"1".repeat(32),
            &credential,
            &"2".repeat(32),
            &sha256_hex(&firewall),
        )
        .unwrap();
    for _ in 1..crate::records::HTTP_ENABLEMENT_CHECKPOINTS.len() {
        record = record.advance_http_enablement().unwrap();
    }
    if !pending {
        record = record.commit_http_enablement().unwrap();
    }
    // Existing writers perform this transition; fixture setup leaves the exact
    // canonical resulting record, not a forged host-admission shortcut.
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &record.encode().unwrap(),
        0o600,
    );
    use crate::host::subscription as h;
    root.write(
        h::TOKEN,
        format!("{}\n", credential.as_str()).as_bytes(),
        0o600,
    );
    let serving = if pending {
        match record.http_operation().unwrap().unwrap() {
            crate::records::HttpOperation::Enablement { target, .. } => target,
            _ => unreachable!(),
        }
    } else {
        record.serving_authority().unwrap()
    };
    root.write(h::STATE, &serving.state_bytes().unwrap(), 0o600);
    root.write(
        h::UNIT,
        crate::runtime_handoff::SERVING_UNIT.as_bytes(),
        0o644,
    );
    root.write(h::FIREWALL, &firewall, 0o644);
    fs::create_dir_all(root.0.join(h::STAGING)).unwrap();
    fs::set_permissions(root.0.join(h::STAGING), fs::Permissions::from_mode(0o700)).unwrap();
    symlink("../sbxr-subscription.service", root.0.join(h::LINK)).unwrap();
    symlink(
        "../sbxr-subscription-firewall.service",
        root.0.join(h::FIREWALL_LINK),
    )
    .unwrap();
    let mut offline = SetupMaterial::for_removal(Some(&record)).unwrap();
    offline.key_sha256 = host.inner.material.key_sha256.clone();
    offline.package_sha256 = host.inner.material.package_sha256.clone();
    host.inner.material = offline;
    host.inner.runner.transport().fail_clock.set(true);
    let runtime = RemovalAuxiliary {
        active: std::rc::Rc::new(std::cell::Cell::new(true)),
        firewall: std::rc::Rc::new(std::cell::Cell::new(true)),
        fail_stop: std::rc::Rc::new(std::cell::Cell::new(false)),
    };
    (host.with_auxiliary(runtime.clone()), runtime)
}
#[test]
fn offline_http_removal_cleans_current_and_prepared_resources_with_forward_retry() {
    for pending in [false, true] {
        let root = Root::new();
        let (host, runtime) = http_removal_host(&root, pending);
        let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
        runtime.fail_stop.set(true);
        let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalNeedsCompletion
        );
        let committed = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
        assert_eq!(
            OwnershipRecord::decode(&committed)
                .unwrap()
                .recovery_direction(),
            crate::records::RecoveryDirection::Removal
        );
        assert!(root.0.join(crate::host::subscription::TOKEN).exists());
        runtime.fail_stop.set(false);
        let prepared = removal.review(Action::FinishRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalComplete
        );
        assert!(!runtime.active.get() && !runtime.firewall.get());
        assert!(!root.0.join("var/lib/sbxr").exists());
        assert!(!root.0.join(crate::host::subscription::UNIT).exists());
        assert!(!root.0.join(CONFIG).exists());
    }
}
#[test]
fn offline_http_removal_refuses_changed_token_foreign_staging_and_startup_without_commitment() {
    for changed in 0..3 {
        let root = Root::new();
        let (host, runtime) = http_removal_host(&root, false);
        let foreign_token = format!("{}A\n", "C".repeat(42));
        let (path, body, mode) = match changed {
            0 => (
                crate::host::subscription::TOKEN,
                foreign_token.as_bytes(),
                0o600,
            ),
            1 => (
                "var/lib/sbxr/subscription-staging/foreign",
                b"preserved".as_slice(),
                0o600,
            ),
            _ => (
                crate::host::identity::STARTUP,
                b"unowned route".as_slice(),
                0o644,
            ),
        };
        root.write(path, body, mode);
        let before = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
        let removal = crate::proxyinstallation::RemovalInstallation::new(host);
        assert!(removal.review(Action::CompleteRemoval).prepared.is_none());
        assert_eq!(fs::read(root.0.join(path)).unwrap(), body);
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            before
        );
        assert!(runtime.active.get() && runtime.firewall.get());
    }
}

#[test]
fn offline_http_rotation_removal_accepts_only_recorded_source_and_target_publications() {
    let root = Root::new();
    let (mut host, runtime) = http_removal_host(&root, false);
    let record = read_ownership(&host.inner.fs).unwrap().unwrap();
    let credential = crate::subscription_artifact::SubscriptionCredential::parse(&format!(
        "{}A",
        "B".repeat(42)
    ))
    .unwrap();
    let rotated = record
        .begin_http_link_rotation(&"3".repeat(32), &"4".repeat(32), &credential)
        .unwrap();
    let target = match rotated.http_operation().unwrap().unwrap() {
        crate::records::HttpOperation::Rotation { target, .. } => target,
        _ => unreachable!(),
    };
    root.write(
        "var/lib/sbxr/proxy-ownership.json",
        &rotated.encode().unwrap(),
        0o600,
    );
    use crate::host::subscription as h;
    root.write(
        h::CANDIDATE_TOKEN,
        format!("{}\n", credential.as_str()).as_bytes(),
        0o600,
    );
    root.write(h::CANDIDATE_STATE, &target.state_bytes().unwrap(), 0o600);
    root.write(
        &format!("{}.sbxr-next", h::STATE),
        &target.state_bytes().unwrap(),
        0o600,
    );
    host.inner.material.configuration_digest = rotated.configuration_sha256().into();
    let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
    let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
    assert_eq!(
        removal.execute(prepared, Confirmation::Approved).outcome,
        Outcome::RemovalComplete
    );
    assert!(!runtime.active.get() && !runtime.firewall.get());
    assert!(!root.0.join("var/lib/sbxr").exists());
}
#[test]
fn offline_removal_cleans_only_recorded_proxy_startup_and_preserves_shared_directory() {
    for created in [false, true] {
        let root = Root::new();
        let (host, _) = running_removal_host(&root);
        let source = read_ownership(&host.inner.fs).unwrap().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&source.encode().unwrap()).unwrap();
        value["schema"] = 2.into();
        value["permitted_resources"][0] =
            "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2".into();
        value["resource_creating_releases"] =
            vec![
                value["release_identity"].clone();
                value["permitted_resources"].as_array().unwrap().len()
            ]
            .into();
        let body = crate::client_identity::STARTUP_DROP_IN.as_bytes();
        value["proxy_startup"] =
            serde_json::json!({"drop_in_sha256":sha256_hex(body),"directory_created":created});
        let mut resources = vec![format!(
            "/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf root:root 0644 one-link sha256:{}",
            sha256_hex(body)
        )];
        if created {
            resources.push("/etc/systemd/system/sing-box.service.d root:root 0755 SBXR-created empty-after-drop-in-removal".into());
        }
        for resource in resources {
            value["permitted_resources"]
                .as_array_mut()
                .unwrap()
                .push(resource.into());
            let creator = value["release_identity"].clone();
            value["resource_creating_releases"]
                .as_array_mut()
                .unwrap()
                .push(creator);
        }
        let record = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        root.write(
            "var/lib/sbxr/proxy-ownership.json",
            &record.encode().unwrap(),
            0o600,
        );
        root.write(crate::host::identity::STARTUP, body, 0o644);
        fs::set_permissions(
            root.0.join(crate::host::identity::STARTUP_DIR),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalComplete
        );
        assert!(!root.0.join(crate::host::identity::STARTUP).exists());
        assert_eq!(
            root.0.join(crate::host::identity::STARTUP_DIR).exists(),
            !created
        );
    }
}

#[test]
fn offline_client_target_removal_uses_go_contract_without_restoring_revoked_source() {
    for fixture in [
        include_bytes!("../../tests/testdata/removal/client-cleanup.json").as_slice(),
        include_bytes!("../../tests/testdata/removal/client-forward.json").as_slice(),
    ] {
        let root = Root::new();
        let (mut host, commands) = running_removal_host(&root);
        let base = read_ownership(&host.inner.fs).unwrap().unwrap();
        let source = fs::read(root.0.join(CONFIG)).unwrap();
        let target = String::from_utf8(source.clone())
            .unwrap()
            .replace(
                "12345678-1234-4234-8234-123456789abc",
                "87654321-4321-4321-8321-cba987654321",
            )
            .into_bytes();
        assert_ne!(source, target);
        let mut template: serde_json::Value = serde_json::from_slice(fixture).unwrap();
        let old_source = template["client_identity_rotation"]["source_configuration_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let old_target = template["client_identity_rotation"]["target_configuration_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        template = serde_json::from_str(
            &serde_json::to_string(&template)
                .unwrap()
                .replace(&old_source, &sha256_hex(&source))
                .replace(&old_target, &sha256_hex(&target)),
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&base.encode().unwrap()).unwrap();
        value["schema"] = 2.into();
        value["permitted_resources"][0] =
            "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2".into();
        value["resource_creating_releases"] =
            vec![
                value["release_identity"].clone();
                value["permitted_resources"].as_array().unwrap().len()
            ]
            .into();
        value["proxy_startup"] = template["proxy_startup"].clone();
        value["client_identity_rotation"] = template["client_identity_rotation"].clone();
        let additions = template["permitted_resources"].as_array().unwrap();
        for resource in &additions[additions.len() - 6..] {
            value["permitted_resources"]
                .as_array_mut()
                .unwrap()
                .push(resource.clone());
            let creator = value["release_identity"].clone();
            value["resource_creating_releases"]
                .as_array_mut()
                .unwrap()
                .push(creator);
        }
        if template["client_identity_rotation"]["direction"] == "forward" {
            value["configuration_sha256"] = sha256_hex(&target).into();
            for resource in value["permitted_resources"].as_array_mut().unwrap() {
                if resource
                    .as_str()
                    .is_some_and(|r| r.starts_with("/etc/sing-box/config.json sha256:"))
                {
                    *resource =
                        format!("/etc/sing-box/config.json sha256:{}", sha256_hex(&target)).into();
                }
            }
            root.write(CONFIG, &target, 0o640);
        }
        let record = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        root.write(
            "var/lib/sbxr/proxy-ownership.json",
            &record.encode().unwrap(),
            0o600,
        );
        root.write(crate::host::identity::TARGET, &target, 0o600);
        root.write(crate::host::identity::CONFIG_STAGE, &target, 0o640);
        root.write(
            crate::host::identity::STARTUP,
            crate::client_identity::STARTUP_DROP_IN.as_bytes(),
            0o644,
        );
        fs::set_permissions(
            root.0.join(crate::host::identity::STARTUP_DIR),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut material = SetupMaterial::for_removal(Some(&record)).unwrap();
        material.key_sha256 = host.inner.material.key_sha256.clone();
        material.package_sha256 = host.inner.material.package_sha256.clone();
        host.inner.material = material;
        let count = commands.borrow().len();
        let mut removal = crate::proxyinstallation::RemovalInstallation::new(host);
        let prepared = removal.review(Action::CompleteRemoval).prepared.unwrap();
        assert_eq!(
            removal.execute(prepared, Confirmation::Approved).outcome,
            Outcome::RemovalComplete
        );
        for p in [
            CONFIG,
            crate::host::identity::TARGET,
            crate::host::identity::CONFIG_STAGE,
            crate::host::identity::STARTUP,
        ] {
            assert!(!root.0.join(p).exists());
        }
        assert!(!commands.borrow()[count..].iter().any(|c| {
            c.arguments()
                .first()
                .is_some_and(|a| a == "start" || a == "restart")
        }));
    }
}

#[path = "linux/tunnel_tests.rs"]
mod tunnel_composition;

#[path = "linux/package_default_tests.rs"]
mod package_defaults;

#[path = "linux/auxiliary_removal_tests.rs"]
mod auxiliary_removal;

#[path = "linux/historical_tests.rs"]
mod historical_removal;

#[test]
fn lifecycle_transaction_arriving_after_setup_review_refuses_without_effects() {
    let root = Root::new();
    let mut installation = StandardInstallation::new(root.host(), release()).unwrap();
    let prepared = installation.review(Action::StartSetup).prepared.unwrap();
    let path = "usr/local/bin/.sbxr-update-candidate";
    root.write(path, b"retained exact software transaction", 0o600);
    assert_eq!(
        installation
            .execute(prepared, Confirmation::Approved)
            .outcome,
        Outcome::Refused
    );
    assert!(installation.host().runner().effects.is_empty());
    assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    assert_eq!(
        fs::read(root.0.join(path)).unwrap(),
        b"retained exact software transaction"
    );
}

#[test]
fn owner_cancellation_preserves_durable_setup_direction_and_releases_locks() {
    for at in [Operation::HoldPackage, Operation::StartService] {
        let root = Root::new();
        let session = crate::subscription_serving::Cancellation::new();
        let mut host = root.host().with_cancellation(session.clone().into());
        host.runner.cancel_after = Some(at);
        let mut installation = StandardInstallation::new(host, release()).unwrap();
        let prepared = installation.review(Action::StartSetup).prepared.unwrap();
        let result = installation.execute(prepared, Confirmation::Approved);
        assert!(session.is_cancelled());
        assert_ne!(result.outcome, Outcome::SetupComplete);
        assert_eq!(installation.host().runner.effects.last(), Some(&at));
        let bytes = fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap();
        let record = OwnershipRecord::decode(&bytes).unwrap();
        let direction = if at == Operation::HoldPackage {
            crate::records::RecoveryDirection::Cleanup
        } else {
            crate::records::RecoveryDirection::FinishSetup
        };
        assert_eq!(record.recovery_direction(), direction);
        // Existing host authority is never explicitly unlocked while lent.
        // End-change releases this owned handle; reopening only its private
        // store also releases exclusion, as established by the Linux regression.
        let mut runner = installation.into_host().runner;
        runner.cancel_after = None;
        let host = LinuxHost::injected(&root.0, runner, root.host().material, admission()).unwrap();
        let mut resumed = StandardInstallation::new(host, release()).unwrap();
        let action = if direction == crate::records::RecoveryDirection::Cleanup {
            Action::FinishCleanup
        } else {
            Action::FinishSetup
        };
        let result = execute(&mut resumed, action);
        assert_eq!(
            result.outcome,
            if action == Action::FinishCleanup {
                Outcome::CleanedUp
            } else {
                Outcome::SetupComplete
            }
        );
        assert!(
            resumed.host().runner.effects[resumed
                .host()
                .runner
                .effects
                .iter()
                .position(|e| *e == at)
                .unwrap()
                + 1..]
                .iter()
                .all(|e| direction == crate::records::RecoveryDirection::Cleanup
                    || !matches!(e, Operation::RemovePackage | Operation::RemoveAptSource))
        );
    }
}

#[test]
fn native_eligibility_requires_runner_and_fresh_retained_guard() {
    let root = Root::new();
    let mut host = root.host();
    assert_eq!(host.native_authorized(), Err(HostError::Foreign));
    let source = crate::host::admission::tests::Fixture::new();
    // Eligibility predicate only: private fields carry an unsigned structural
    // guard and fake runner. No NativeAdmission or genuine signed positive proof
    // is constructed and no native begin_change/effect is ever invoked.
    let guard = Arc::new(source.capture().unwrap());
    host.authenticated = Some(guard.record().clone());
    host.native_guard = Some(guard);
    assert_eq!(
        host.native_authorized(),
        Err(HostError::Foreign),
        "foreign root"
    );
    host.fs = ProtectedFs::open(&source.0).unwrap();
    host.native_authorized().unwrap();
    let record = host.authenticated.take();
    assert_eq!(host.native_authorized(), Err(HostError::Foreign));
    host.authenticated = record;
    host.native_mode = true;
    assert!(!host.effects_available(), "injected runner is not native");
    host.runner.native_capable = true;
    assert!(host.effects_available(), "all eligibility conditions hold");
    let guard = host.native_guard.take();
    assert!(!host.effects_available(), "record alone is not admission");
    host.native_guard = guard;
    source.write("usr/local/bin/sbxr", b"foreign", 0o755);
    assert!(host.native_authorized().is_err());
    assert!(
        !host.effects_available(),
        "stale admission cannot enable effects"
    );
    assert!(host.runner.effects.is_empty());
}

#[test]
fn native_retained_guard_keeps_cancellation_and_record_namespace_checks() {
    let root = Root::new();
    let mut host = root.host();
    let source = crate::host::admission::tests::Fixture::new();
    let guard = Arc::new(source.capture().unwrap());
    host.authenticated = Some(guard.record().clone());
    host.native_guard = Some(guard);
    host.fs = ProtectedFs::open(&source.0).unwrap();
    host.native_authorized().unwrap();
    let original = fs::read(source.0.join("var/lib/sbxr/installed.json")).unwrap();
    source.write("replacement", &original, 0o600);
    fs::rename(
        source.0.join("replacement"),
        source.0.join("var/lib/sbxr/installed.json"),
    )
    .unwrap();
    assert!(
        host.native_authorized().is_err(),
        "same bytes in another inode are stale"
    );
    host.stop.cancel();
    assert_eq!(host.native_authorized(), Err(HostError::Cancelled));
    assert!(host.runner.effects.is_empty());
}

#[test]
fn cancelled_native_begin_refuses_before_lock_or_command_even_without_proof() {
    let root = Root::new();
    let mut host = root.host();
    host.native_mode = true;
    host.runner.native_capable = true;
    host.stop.cancel();
    assert_eq!(host.begin_change(), Err(HostError::Cancelled));
    assert!(host.lock.is_none());
    assert!(host.runner.effects.is_empty());
    assert!(!host.effects_available());
}
