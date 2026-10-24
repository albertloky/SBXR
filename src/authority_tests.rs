use super::*;
use std::{fs, path::PathBuf};
fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/records/testdata/authority")
            .join(format!("{name}.json")),
    )
    .unwrap()
}
#[test]
fn preserved_go_authority_records_decode_and_reencode_without_byte_drift() {
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/records/testdata/authority");
    let mut count = 0;
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            let bytes = fs::read(&path).unwrap();
            let record = OwnershipRecord::decode(&bytes)
                .unwrap_or_else(|_| panic!("Go authority refused: {}", path.display()));
            assert_eq!(record.encode().unwrap(), bytes, "{}", path.display());
            count += 1;
        }
    }
    assert_eq!(count, 67);
}

fn record(name: &str) -> OwnershipRecord {
    OwnershipRecord::decode(&fixture(name)).unwrap()
}
fn token(letter: &str) -> crate::subscription_artifact::SubscriptionCredential {
    crate::subscription_artifact::SubscriptionCredential::parse(&(letter.repeat(42) + "A")).unwrap()
}
fn firewall() -> String {
    let value: serde_json::Value = serde_json::from_slice(&fixture("http-active")).unwrap();
    value["subscription_resources"]["firewall_sha256"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn http_enablement_steps_match_go_and_every_uncommitted_generation_cleans_up() {
    let base = record("schema1-running");
    let credential = token("A");
    let mut current = base
        .begin_http_enablement(&"1".repeat(32), &credential, &"3".repeat(32), &firewall())
        .unwrap();
    assert!(base.permits_successor(&current));
    assert_eq!(current.schema(), 2);
    for (index, checkpoint) in HTTP_ENABLEMENT_CHECKPOINTS.iter().enumerate() {
        assert_eq!(
            current.encode().unwrap(),
            fixture(&format!(
                "http-enable-{}",
                char::from(b'a' + *checkpoint as u8)
            ))
        );
        assert_eq!(
            current.pending_change(),
            Some(PendingChange::Enablement {
                checkpoint: *checkpoint
            })
        );
        let cleanup = current.cleanup_http_enablement().unwrap();
        assert!(current.permits_successor(&cleanup));
        assert_eq!(cleanup.encode().unwrap(), fixture("schema2-idle"));
        if *checkpoint != 23 {
            assert!(current.commit_http_enablement().is_err())
        }
        if index + 1 < HTTP_ENABLEMENT_CHECKPOINTS.len() {
            let next = current.advance_http_enablement().unwrap();
            assert!(current.permits_successor(&next));
            current = next;
        }
    }
    let committed = current.commit_http_enablement().unwrap();
    assert_eq!(committed.encode().unwrap(), fixture("http-active"));
    assert!(current.permits_successor(&committed));
    assert!(
        !String::from_utf8(committed.encode().unwrap())
            .unwrap()
            .contains(credential.as_str())
    );
}
#[test]
fn link_rotation_selects_only_the_target_after_commit() {
    let source = record("http-active");
    let mut current = source
        .begin_http_link_rotation(&"6".repeat(32), &"4".repeat(32), &token("B"))
        .unwrap();
    assert!(source.permits_successor(&current));
    for name in ["http-rotate-a", "http-rotate-b"] {
        assert_eq!(current.encode().unwrap(), fixture(name));
        assert_eq!(
            current.pending_change().unwrap().direction(),
            Some(ChangeDirection::Cleanup)
        );
        assert_eq!(
            current
                .cleanup_http_link_rotation()
                .unwrap()
                .encode()
                .unwrap(),
            source.encode().unwrap()
        );
        let next = current.advance_http_link_rotation().unwrap();
        assert!(current.permits_successor(&next));
        current = next;
    }
    assert_eq!(current.encode().unwrap(), fixture("http-rotate-c"));
    assert_eq!(
        current.pending_change().unwrap().direction(),
        Some(ChangeDirection::Forward)
    );
    assert!(current.cleanup_http_link_rotation().is_err());
    assert!(!current.permits_successor(&source));
    let target = current.complete_http_link_rotation().unwrap();
    assert!(current.permits_successor(&target));
    assert_eq!(
        target.serving_authority().unwrap().link_id(),
        "4".repeat(32)
    );
    assert_eq!(target.configuration_sha256(), source.configuration_sha256());
    let marked = source.mark_subscription_compromised().unwrap();
    let mut changed = marked
        .begin_http_link_rotation(&"6".repeat(32), &"4".repeat(32), &token("B"))
        .unwrap();
    assert!(
        String::from_utf8(
            changed
                .cleanup_http_link_rotation()
                .unwrap()
                .encode()
                .unwrap()
        )
        .unwrap()
        .contains("subscription_compromised")
    );
    changed = changed
        .advance_http_link_rotation()
        .unwrap()
        .advance_http_link_rotation()
        .unwrap();
    assert!(
        !String::from_utf8(
            changed
                .complete_http_link_rotation()
                .unwrap()
                .encode()
                .unwrap()
        )
        .unwrap()
        .contains("subscription_compromised")
    );
}
#[test]
fn http_runtime_repair_commits_before_target_publication_and_cannot_reverse() {
    let source = record("http-active");
    let mut current = source.begin_http_runtime_repair(&"7".repeat(32)).unwrap();
    assert!(source.permits_successor(&current));
    assert_eq!(current.encode().unwrap(), fixture("http-repair-a"));
    assert_eq!(
        current
            .cleanup_http_runtime_repair()
            .unwrap()
            .encode()
            .unwrap(),
        source.encode().unwrap()
    );
    for name in ["http-repair-b", "http-repair-target", "http-repair-c"] {
        let next = current.advance_http_runtime_repair().unwrap();
        assert!(current.permits_successor(&next));
        current = next;
        assert_eq!(current.encode().unwrap(), fixture(name));
        assert!(current.cleanup_http_runtime_repair().is_err());
        if name != "http-repair-c" {
            assert!(!current.permits_successor(&source));
        }
    }
    // Accepted repair preserves the generation; forward completion returns identical idle bytes.
    let completed = current.complete_http_runtime_repair().unwrap();
    assert!(current.permits_successor(&completed));
    assert_eq!(completed.encode().unwrap(), source.encode().unwrap());
}
#[test]
fn tunnel_metadata_is_created_only_before_initial_setup_and_does_not_own_owner_secrets() {
    let base = record("schema1-setup");
    let tunnel = TunnelAuthority::new(
        "12345678-1234-1234-1234-123456789abc",
        &"d".repeat(64),
        &"e".repeat(64),
    )
    .unwrap();
    let setup = OwnershipRecord::new_tunnel_setup(
        base.release_identity(),
        base.public_ipv4(),
        base.configuration_sha256(),
        tunnel.clone(),
    )
    .unwrap();
    assert_eq!(setup.encode().unwrap(), fixture("schema1-tunnel"));
    assert!(!base.permits_successor(&setup));
    for resource in tunnel.resources() {
        assert!(!resource.starts_with("/etc/cloudflared/sbxr.token"));
        assert!(!resource.starts_with("/usr/bin/cloudflared"));
    }
    assert!(TunnelAuthority::new("bad token", &"d".repeat(64), &"e".repeat(64)).is_err());
}
#[test]
fn historical_authority_never_enables_automatic_transport_or_identity_migration() {
    for name in [
        "https-active",
        "https-rotate-c",
        "https-certificate-repair-target",
        "http-migration-pending",
        "client-rotation-i",
        "profile-removal-c",
    ] {
        let current = record(name);
        assert!(
            current
                .begin_http_enablement(&"1".repeat(32), &token("A"), &"3".repeat(32), &firewall())
                .is_err()
        );
        assert!(current.advance_http_link_rotation().is_err());
        assert!(current.advance_http_runtime_repair().is_err());
    }
    let migration = record("http-migration-pending");
    assert_eq!(
        migration.pending_change(),
        Some(PendingChange::HistoricalTransportMigration)
    );
    assert!(!migration.permits_successor(&record("http-retired-https")));
    let revoked = record("client-rotation-i");
    assert_eq!(
        revoked.pending_change().unwrap().direction(),
        Some(ChangeDirection::Forward)
    );
    assert!(!revoked.permits_successor(&record("client-rotation-h")));
}

#[test]
fn authority_and_runtime_configuration_share_exact_nonsecret_bindings() {
    let current = record("http-tunnel");
    let authority = current.serving_authority().unwrap();
    let generation = crate::subscription_serving::Generation::new(
        authority.link_id(),
        authority.credential_digest(),
    )
    .unwrap();
    let facts = crate::subscription_artifact::ConnectionFacts::new(
        current.public_ipv4(),
        "12345678-1234-4234-8234-123456789abc",
        "google.com",
        "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q",
        "01020304",
        Some("tunnel.example.com"),
    )
    .unwrap();
    let state = std::sync::Arc::new(
        crate::subscription_serving::State::prepare_http(&facts, generation).unwrap(),
    );
    assert_eq!(
        crate::subscription_serving::Module::new()
            .inspect(&state)
            .runtime,
        crate::subscription_serving::Runtime::Unknown
    );
    let tunnel = current.tunnel_authority().unwrap();
    let binding = crate::server_configuration::TunnelBinding::from_parts(
        tunnel.tunnel_id(),
        &"d".repeat(64),
        &"e".repeat(64),
    )
    .unwrap();
    assert_eq!(binding.resources(), tunnel.resources());
    assert_eq!(
        tunnel_unit_sha256(),
        sha256_hex(crate::server_configuration::tunnel_unit().as_bytes())
    );
}
#[test]
fn successors_preserve_each_existing_resource_creator() {
    let mut value: serde_json::Value = serde_json::from_slice(&fixture("http-active")).unwrap();
    value["resource_creating_releases"][10]["Tag"] = "v3.1.117".into();
    let source = OwnershipRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
    let target = source
        .begin_http_link_rotation(&"6".repeat(32), &"4".repeat(32), &token("B"))
        .unwrap();
    assert_eq!(
        target.creating_releases()[10],
        source.creating_releases()[10]
    );
    let mut replaced: serde_json::Value =
        serde_json::from_slice(&target.encode().unwrap()).unwrap();
    replaced["resource_creating_releases"][10]["Tag"] = "v3.1.118".into();
    let replaced = OwnershipRecord::decode(&serde_json::to_vec(&replaced).unwrap()).unwrap();
    assert!(!source.permits_successor(&replaced));
    assert!(!format!("{source:?}").contains(&"c".repeat(64)));
}

#[test]
fn adversarial_authority_vectors_match_go_refusals() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "records/testdata/authority/adversarial.vectors"
    ))
    .unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 144);
    for case in cases.as_array().unwrap() {
        let original = fixture(case["fixture"].as_str().unwrap());
        let path = case["path"].as_str().unwrap();
        let operation = case["operation"].as_str().unwrap();
        let bytes = if operation.contains("duplicate") {
            let key = format!("\"{path}\":");
            let alias = if operation == "escaped_duplicate" {
                format!("\"\\u{:04x}{}\":", path.as_bytes()[0], &path[1..])
            } else {
                key.clone()
            };
            String::from_utf8(original)
                .unwrap()
                .replacen(&key, &format!("{alias}null,{key}"), 1)
                .into_bytes()
        } else {
            let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            let (parent, key) = path.rsplit_once('/').unwrap();
            let target = value.pointer_mut(parent).unwrap();
            if operation == "remove" {
                target.as_object_mut().unwrap().remove(key);
            } else if let Some(object) = target.as_object_mut() {
                object.insert(key.into(), case["value"].clone());
            } else {
                target.as_array_mut().unwrap()[key.parse::<usize>().unwrap()] =
                    case["value"].clone();
            }
            serde_json::to_vec(&value).unwrap()
        };
        assert!(
            OwnershipRecord::decode(&bytes).is_err(),
            "mutation accepted: {}",
            case["name"]
        );
    }
}
