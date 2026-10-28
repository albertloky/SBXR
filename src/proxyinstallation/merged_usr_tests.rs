//! Real temporary-root layout checks; no native paths or system effects.
use super::*;
use std::os::unix::fs::symlink;

fn system_unit_layout(root: &Root, merged: bool) {
    fs::create_dir_all(root.0.join("usr/lib/systemd/system")).unwrap();
    if merged {
        symlink("usr/lib", root.0.join("lib")).unwrap();
    } else {
        fs::create_dir_all(root.0.join("lib/systemd/system")).unwrap();
    }
}

#[test]
fn subscription_enable_accepts_merged_and_unmerged_system_unit_layouts() {
    for merged in [false, true] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        root.setup(&archive);
        system_unit_layout(&root, merged);
        root.write(
            "usr/lib/systemd/system/unrelated.service",
            b"preserve",
            0o644,
        );
        let proof = archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let mut m = module(&root, &proof, archive);
        let review = m.review(Action::EnableSubscription);
        assert!(
            review.prepared.is_some(),
            "merged={merged}: {:?}",
            review.refusal
        );
        assert_eq!(
            m.execute(review.prepared.unwrap(), Confirmation::Approved)
                .outcome,
            Outcome::SubscriptionEnabled,
            "merged={merged}"
        );
        assert_eq!(m.subscription_status(), "Available");
        assert_eq!(
            fs::read(root.0.join("usr/lib/systemd/system/unrelated.service")).unwrap(),
            b"preserve"
        );
        if merged {
            assert_eq!(
                fs::read_link(root.0.join("lib")).unwrap(),
                PathBuf::from("usr/lib")
            );
        } else {
            assert!(fs::symlink_metadata(root.0.join("lib")).unwrap().is_dir());
        }
    }
}

#[test]
fn subscription_layout_refuses_foreign_aliases_and_unsafe_canonical_paths() {
    for fault in [
        "foreign",
        "absolute",
        "parent",
        "dangling",
        "target-link",
        "nested-link",
        "writable-target",
        "linked-alias",
    ] {
        let root = Root::new();
        let archive = Arc::new(crate::release_acquisition::fixture_archive());
        let record = root.setup(&archive);
        root.write("foreign/sentinel", b"preserve", 0o644);
        fs::create_dir_all(root.0.join("usr/lib")).unwrap();
        let target = match fault {
            "foreign" => "foreign",
            "absolute" => "/usr/lib",
            "parent" => "../usr/lib",
            _ => "usr/lib",
        };
        symlink(target, root.0.join("lib")).unwrap();
        match fault {
            "dangling" => fs::remove_dir(root.0.join("usr/lib")).unwrap(),
            "target-link" => {
                fs::remove_dir(root.0.join("usr/lib")).unwrap();
                symlink("../foreign", root.0.join("usr/lib")).unwrap();
            }
            "nested-link" => symlink("../../foreign", root.0.join("usr/lib/systemd")).unwrap(),
            "writable-target" => {
                fs::set_permissions(root.0.join("usr/lib"), fs::Permissions::from_mode(0o777))
                    .unwrap()
            }
            "linked-alias" => {
                fs::hard_link(root.0.join("lib"), root.0.join("lib-copy")).unwrap();
                assert_eq!(fs::symlink_metadata(root.0.join("lib")).unwrap().nlink(), 2);
            }
            _ => {}
        }
        let proof = archive
            .bind_current(
                archive.executable(),
                archive.executable(),
                &crate::artifact_trust::SelectionBudget::new(),
            )
            .unwrap();
        let m = module(&root, &proof, archive);
        assert!(
            m.review(Action::EnableSubscription).prepared.is_none(),
            "{fault}"
        );
        assert!(m.host().backend().trace.is_empty());
        assert_eq!(
            fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
            record.encode().unwrap()
        );
        assert_eq!(
            fs::read(root.0.join("foreign/sentinel")).unwrap(),
            b"preserve"
        );
        assert_eq!(
            fs::read_link(root.0.join("lib")).unwrap(),
            PathBuf::from(target)
        );
        assert!(!root.0.join(TOKEN).exists());
    }
}

#[test]
fn subscription_layout_still_refuses_vendor_units_dropins_and_enablement_links() {
    for merged in [false, true] {
        let directories: &[&str] = if merged {
            &["usr/lib/systemd/system"]
        } else {
            &["usr/lib/systemd/system", "lib/systemd/system"]
        };
        for directory in directories {
            for unit in [
                "sbxr-subscription.service",
                "sbxr-subscription-firewall.service",
            ] {
                for suffix in [
                    unit.to_owned(),
                    format!("{unit}.d/override.conf"),
                    format!("multi-user.target.wants/{unit}"),
                    format!("multi-user.target.requires/{unit}"),
                ] {
                    let root = Root::new();
                    let archive = Arc::new(crate::release_acquisition::fixture_archive());
                    let record = root.setup(&archive);
                    system_unit_layout(&root, merged);
                    let foreign = format!("{directory}/{suffix}");
                    root.write(&foreign, b"preserve", 0o644);
                    let proof = archive
                        .bind_current(
                            archive.executable(),
                            archive.executable(),
                            &crate::artifact_trust::SelectionBudget::new(),
                        )
                        .unwrap();
                    let m = module(&root, &proof, archive);
                    assert!(
                        m.review(Action::EnableSubscription).prepared.is_none(),
                        "merged={merged}: {foreign}"
                    );
                    assert!(m.host().backend().trace.is_empty());
                    assert_eq!(fs::read(root.0.join(&foreign)).unwrap(), b"preserve");
                    assert_eq!(
                        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
                        record.encode().unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn changed_lib_alias_invalidates_prepared_subscription_before_effects() {
    let root = Root::new();
    let archive = Arc::new(crate::release_acquisition::fixture_archive());
    let record = root.setup(&archive);
    system_unit_layout(&root, true);
    let proof = archive
        .bind_current(
            archive.executable(),
            archive.executable(),
            &crate::artifact_trust::SelectionBudget::new(),
        )
        .unwrap();
    let mut m = module(&root, &proof, archive);
    let review = m.review(Action::EnableSubscription);
    assert!(review.prepared.is_some(), "{:?}", review.refusal);
    fs::remove_file(root.0.join("lib")).unwrap();
    symlink("foreign", root.0.join("lib")).unwrap();
    assert_eq!(
        m.execute(review.prepared.unwrap(), Confirmation::Approved)
            .outcome,
        Outcome::Refused
    );
    assert!(m.host().backend().trace.is_empty());
    assert_eq!(
        fs::read(root.0.join("var/lib/sbxr/proxy-ownership.json")).unwrap(),
        record.encode().unwrap()
    );
    assert!(!root.0.join(TOKEN).exists());
    assert_eq!(
        fs::read_link(root.0.join("lib")).unwrap(),
        PathBuf::from("foreign")
    );
}
