use super::*;
const DEFAULT: &[u8] = crate::package_acquisition::DEFAULT_CONFIGURATION;
fn paused(phase: SetupPhase) -> (Root, StandardInstallation<LinuxHost<Fake>>) {
    let root = Root::new();
    let mut host = root.host();
    host.runner.install_default = true;
    host.interrupt_after(Some(phase));
    let mut installation = StandardInstallation::new(host, release()).unwrap();
    assert_eq!(
        execute(&mut installation, Action::StartSetup).outcome,
        Outcome::NeedsCleanup
    );
    (root, installation)
}
fn record(root: &Root) -> OwnershipRecord {
    OwnershipRecord::decode(&fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap())
        .unwrap()
}
#[test]
fn package_default_has_exact_bytes_mode_owner_and_package_membership() {
    let (root, installation) = paused(SetupPhase::PackageInstalled);
    assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
    assert_eq!(DEFAULT.len(), 635);
    let meta = fs::metadata(root.0.join(CONFIG)).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o644);
    assert_eq!(
        (meta.uid(), meta.gid()),
        (
            fs::metadata(&root.0).unwrap().uid(),
            fs::metadata(&root.0).unwrap().gid()
        )
    );
    assert!(
        installation
            .review(Action::FinishCleanup)
            .prepared
            .is_some()
    );
}
#[test]
fn package_default_cleanup_reopens_without_downloads_or_configuration_secrets() {
    for phase in [
        SetupPhase::PackageInstalled,
        SetupPhase::PackageHeld,
        SetupPhase::StateDirectoryCreated,
    ] {
        let (root, installation) = paused(phase);
        let record = record(&root);
        let mut host = installation.into_host();
        let mut offline = SetupMaterial::for_cleanup(&record).unwrap();
        // Only the old fixture key/package bytes are synthetic. Default is the genuine pin.
        offline.key_sha256 = host.material.key_sha256.clone();
        offline.package_sha256 = host.material.package_sha256.clone();
        host.material = offline;
        assert!(host.material.configuration.is_none() && host.material.package.is_empty());
        let mut reopened = StandardInstallation::new(host, release()).unwrap();
        assert_eq!(
            execute(&mut reopened, Action::FinishCleanup).outcome,
            Outcome::CleanedUp
        );
        assert!(!root.0.join(CONFIG).exists());
        assert!(!root.0.join("etc/sing-box").exists());
        assert!(!root.0.join("var/lib/sbxr/proxy-ownership.json").exists());
    }
}
#[test]
fn package_default_survives_interrupted_purge_then_cleans_with_committed_direction() {
    for fail_after in [false, true] {
        let (root, mut installation) = paused(SetupPhase::PackageInstalled);
        installation.host_mut().runner.fail = Some(Operation::RemovePackage);
        installation.host_mut().runner.fail_after = fail_after;
        assert_eq!(
            execute(&mut installation, Action::FinishCleanup).outcome,
            Outcome::NeedsCleanup
        );
        assert_eq!(record(&root).cleanup_checkpoint(), 3);
        assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
        let mut host = installation.into_host();
        host.runner.fail = None;
        let mut reopened = StandardInstallation::new(host, release()).unwrap();
        assert_eq!(
            execute(&mut reopened, Action::FinishCleanup).outcome,
            Outcome::CleanedUp
        );
        assert!(!root.0.join(CONFIG).exists());
    }
}
#[test]
fn package_default_replacement_interruptions_retry_or_cleanup_without_source_resurrection() {
    for point in [1, 2] {
        for cleanup in [false, true] {
            let (root, installation) = paused(SetupPhase::StateDirectoryCreated);
            let authority = record(&root);
            let mut host = installation.into_host();
            let target = host.material.configuration_bytes().unwrap().to_vec();
            host.begin_change().unwrap();
            host.fs
                .package_replacement_fault
                .store(point, Ordering::Relaxed);
            assert!(matches!(
                host.apply_setup(Operation::InstallConfiguration, &authority),
                Err(HostError::Injected)
            ));
            host.end_change();
            assert_eq!(
                fs::read(root.0.join(CONFIG)).unwrap(),
                if point == 1 { DEFAULT } else { &target }
            );
            assert_eq!(
                root.0.join(format!("{CONFIG}.sbxr-next")).exists(),
                point == 1
            );
            if cleanup {
                let mut offline = SetupMaterial::for_cleanup(&authority).unwrap();
                offline.key_sha256 = host.material.key_sha256.clone();
                offline.package_sha256 = host.material.package_sha256.clone();
                host.material = offline;
                let mut reopened = StandardInstallation::new(host, release()).unwrap();
                assert_eq!(
                    execute(&mut reopened, Action::FinishCleanup).outcome,
                    Outcome::CleanedUp
                );
                assert!(!root.0.join(CONFIG).exists());
            } else {
                // The same current checkpoint can retry an interrupted effect; stale records cannot.
                host.begin_change().unwrap();
                host.apply_setup(Operation::InstallConfiguration, &authority)
                    .unwrap();
                host.end_change();
                assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), target);
                assert_eq!(
                    fs::metadata(root.0.join(CONFIG)).unwrap().mode() & 0o7777,
                    0o640
                );
                assert!(!root.0.join(format!("{CONFIG}.sbxr-next")).exists());
            }
        }
    }
}
#[test]
fn package_default_refuses_foreign_content_modes_links_owners_and_stages() {
    for attack in 0..9 {
        let (root, mut installation) = paused(SetupPhase::PackageInstalled);
        let prepared = installation.review(Action::FinishCleanup).prepared.unwrap();
        let config = root.0.join(CONFIG);
        let stage = format!("{CONFIG}.sbxr-next");
        match attack {
            0 => root.write(CONFIG, b"foreign configuration", 0o644),
            1 => fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap(),
            2 => {
                fs::rename(&config, root.0.join("outside")).unwrap();
                symlink(root.0.join("outside"), &config).unwrap();
            }
            3 => fs::hard_link(&config, root.0.join("outside")).unwrap(),
            4 => installation.host_mut().runner.configuration_owner = false,
            5 => installation.host_mut().fs.gid = installation.host().fs.gid.wrapping_add(1),
            6 => root.write(&stage, b"foreign staged bytes", 0o640),
            7 => root.write(CONFIG, DEFAULT, 0o640),
            8 => {
                root.write("foreign-parent/config.json", DEFAULT, 0o644);
                fs::remove_dir_all(root.0.join("etc/sing-box")).unwrap();
                symlink(root.0.join("foreign-parent"), root.0.join("etc/sing-box")).unwrap();
            }
            _ => unreachable!(),
        }
        let before = fs::read(&config).unwrap();
        let count = installation.host().runner.effects.len();
        assert!(
            installation
                .review(Action::FinishCleanup)
                .prepared
                .is_none(),
            "attack {attack}"
        );
        assert_eq!(
            installation
                .execute(prepared, Confirmation::Approved)
                .outcome,
            Outcome::Refused,
            "attack {attack}"
        );
        assert_eq!(fs::read(&config).unwrap(), before);
        assert_eq!(installation.host().runner.effects.len(), count);
        if attack == 6 {
            assert_eq!(
                fs::read(root.0.join(&stage)).unwrap(),
                b"foreign staged bytes"
            );
        }
    }
}
#[test]
fn package_default_requires_preconfiguration_current_journal_and_package_proof() {
    for phase in [
        SetupPhase::ConfigurationInstalled,
        SetupPhase::ConfigurationValidated,
        SetupPhase::ServiceUnmasked,
    ] {
        let (root, installation) = paused(phase);
        root.write(CONFIG, DEFAULT, 0o644);
        assert!(
            installation
                .review(Action::FinishCleanup)
                .prepared
                .is_none()
        );
        assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
    }
    let root = Root::new();
    root.write(CONFIG, DEFAULT, 0o644);
    let installation = StandardInstallation::new(root.host(), release()).unwrap();
    assert!(installation.review(Action::StartSetup).prepared.is_none());
    let (root, mut installation) = paused(SetupPhase::PackageInstalled);
    installation.host_mut().runner.package = false;
    assert!(
        installation
            .review(Action::FinishCleanup)
            .prepared
            .is_none()
    );
    assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
}
#[test]
fn package_default_changed_after_observation_is_preserved_by_replacement() {
    let (root, installation) = paused(SetupPhase::StateDirectoryCreated);
    let authority = record(&root);
    let mut host = installation.into_host();
    assert!(host.inspect_setup(&release()).is_ok());
    root.write(CONFIG, b"changed after read", 0o644);
    host.begin_change().unwrap();
    assert!(
        host.apply_setup(Operation::InstallConfiguration, &authority)
            .is_err()
    );
    host.end_change();
    assert_eq!(
        fs::read(root.0.join(CONFIG)).unwrap(),
        b"changed after read"
    );
    assert!(!root.0.join(format!("{CONFIG}.sbxr-next")).exists());
}
#[test]
fn package_default_current_journal_excludes_stale_replacement_authority() {
    let (root, installation) = paused(SetupPhase::StateDirectoryCreated);
    let current = record(&root);
    let mut wire: serde_json::Value = serde_json::from_slice(&current.encode().unwrap()).unwrap();
    wire["phase"] = "Package installed".into();
    let old = OwnershipRecord::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
    let mut host = installation.into_host();
    assert!(
        host.package_default(Some(&old), &host.facts().unwrap(), &mut String::new())
            .is_err()
    );
    host.begin_change().unwrap();
    assert!(
        host.apply_setup(Operation::InstallConfiguration, &old)
            .is_err()
    );
    host.end_change();
    assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
    assert!(!root.0.join(format!("{CONFIG}.sbxr-next")).exists());
}
#[test]
fn package_default_handles_install_effect_before_its_checkpoint_without_earlier_adoption() {
    for phase in [SetupPhase::AptSourceInstalled, SetupPhase::ServiceMasked] {
        let (root, installation) = paused(SetupPhase::PackageInstalled);
        let mut wire: serde_json::Value =
            serde_json::from_slice(&record(&root).encode().unwrap()).unwrap();
        wire["phase"] = serde_json::to_value(phase).unwrap();
        let interrupted = OwnershipRecord::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
        root.write(
            "var/lib/sbxr/proxy-ownership.json",
            &interrupted.encode().unwrap(),
            0o600,
        );
        let mut reopened = StandardInstallation::new(installation.into_host(), release()).unwrap();
        if phase == SetupPhase::ServiceMasked {
            assert_eq!(
                execute(&mut reopened, Action::FinishCleanup).outcome,
                Outcome::CleanedUp
            );
        } else {
            assert!(reopened.review(Action::FinishCleanup).prepared.is_none());
            assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
        }
    }
}
#[test]
fn package_default_cleanup_preserves_changed_residue_after_purge() {
    let (root, mut installation) = paused(SetupPhase::PackageInstalled);
    installation.host_mut().runner.fail = Some(Operation::RemovePackage);
    installation.host_mut().runner.fail_after = true;
    assert_eq!(
        execute(&mut installation, Action::FinishCleanup).outcome,
        Outcome::NeedsCleanup
    );
    assert!(!installation.host().runner.package);
    root.write(CONFIG, b"changed after purge", 0o644);
    installation.host_mut().runner.fail = None;
    assert!(
        installation
            .review(Action::FinishCleanup)
            .prepared
            .is_none()
    );
    assert_eq!(
        fs::read(root.0.join(CONFIG)).unwrap(),
        b"changed after purge"
    );
    assert_eq!(record(&root).cleanup_checkpoint(), 3);
}
#[test]
fn package_default_staged_private_checkpoint_cannot_readopt_public_source() {
    for phase in [
        SetupPhase::PackageInstalled,
        SetupPhase::StateDirectoryCreated,
    ] {
        let (root, mut installation) = paused(phase);
        let current = record(&root);
        let staged = current.next_setup_checkpoint().unwrap();
        root.write(
            &format!("var/lib/sbxr/{}", crate::durable::STAGED_FILE),
            &staged.encode().unwrap(),
            0o600,
        );
        let host = installation.host();
        let observed =
            host.package_default(Some(&current), &host.facts().unwrap(), &mut String::new());
        if phase == SetupPhase::StateDirectoryCreated {
            assert!(observed.is_err());
            assert!(
                installation
                    .review(Action::FinishCleanup)
                    .prepared
                    .is_none()
            );
            assert_eq!(fs::read(root.0.join(CONFIG)).unwrap(), DEFAULT);
        } else {
            assert!(observed.unwrap());
            assert_eq!(
                execute(&mut installation, Action::FinishCleanup).outcome,
                Outcome::CleanedUp
            );
        }
    }
}
