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
