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
            configuration,
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
    queries_fail: bool,
    effects: Vec<Operation>,
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
            queries_fail: false,
            effects: vec![],
        }
    }
}
impl CommandRunner for Fake {
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
            Query::Clock => (0, "yes".into()),
            Query::ValidateConfiguration => (0, String::new()),
        };
        CommandOutput::completed(code, text.into_bytes())
    }
    fn injected_effects(&self) -> bool {
        true
    }
    fn effect(&mut self, op: Operation, _: &Cancellation) -> Result<(), HostError> {
        self.effects.push(op);
        if self.fail == Some(op) && !self.fail_after {
            return Err(HostError::Injected);
        }
        match op {
            Operation::MaskService => self.masked = true,
            Operation::InstallPackage => {
                self.package = true;
                self.identity = true;
                fs::create_dir_all(self.root.join("etc/sing-box")).unwrap();
                let unit = self.root.join("usr/lib/systemd/system/sing-box.service");
                fs::create_dir_all(unit.parent().unwrap()).unwrap();
                fs::write(unit, b"synthetic package-owned unit\n").unwrap();
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
        if self.fail == Some(op) && self.fail_after {
            return Err(HostError::Injected);
        }
        Ok(())
    }
}
fn execute(
    installation: &mut StandardInstallation<LinuxHost<Fake>>,
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
    let host = root.host();
    let expected = host.material.configuration.as_bytes().to_vec();
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
    assert_eq!(config.as_bytes(), host.material.configuration.as_bytes());
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
        &base.material.configuration.sha256_hex(),
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
    let bytes = host.material.configuration.as_bytes();
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
