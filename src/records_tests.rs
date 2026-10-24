use super::*;
use serde_json::{Value, json};

pub(super) fn standard() -> OwnershipRecord {
    OwnershipRecord::new_standard(
        ReleaseIdentity::new("v3.1.118", &"a".repeat(40), &"b".repeat(64)).unwrap(),
        "8.8.8.8",
        &"c".repeat(64),
    )
    .unwrap()
}
fn changed(name: &str, value: Value) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(&standard().encode().unwrap()).unwrap();
    record[name] = value;
    serde_json::to_vec(&record).unwrap()
}

#[test]
fn canonical_setup_encoding_preserves_go_order_and_newline() {
    let bytes = standard().encode().unwrap();
    assert_eq!(
        bytes,
        include_bytes!("records/testdata/standard-schema1-go.json")
    );
    assert!(bytes.starts_with(b"{\"schema\":1,\"phase\":\"Ownership recorded\",\"unfinished_direction\":\"cleanup required\",\"release_identity\":{\"Repository\":\"albertloky/SBXR\",\"Tag\":\"v3.1.118\",\"Commit\":"));
    assert!(bytes.ends_with(b"}}\n"));
    assert_eq!(
        OwnershipRecord::decode(&bytes).unwrap().encode().unwrap(),
        bytes
    );
    assert_eq!(standard().permitted_resources().len(), 18);
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn duplicate_unknown_null_array_and_trailing_fields_are_rejected() {
    let bytes = standard().encode().unwrap();
    let source = String::from_utf8(bytes.clone()).unwrap();
    let bad = [
        source.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1),
        source.replacen("\"schema\":1", "\"schema\":1,\"sch\\u0065ma\":1", 1),
        source.replacen(
            "\"Repository\":",
            "\"Repository\":\"albertloky/SBXR\",\"Repository\":",
            1,
        ),
        source.replacen(
            "\"unit_sha256\":",
            "\"unit_sha256\":\"x\",\"unit_sha256\":",
            1,
        ),
        source.replacen(
            "\"schema\":1",
            "\"schema\":1,\"credential\":\"do-not-leak\"",
            1,
        ),
        source.clone() + "{}",
        format!("\u{feff}{source}"),
    ];
    for source in bad {
        assert!(OwnershipRecord::decode(source.as_bytes()).is_err());
    }
    for (name, value) in [
        ("schema", json!(null)),
        ("schema", json!(1.0)),
        ("lock_provisioning", json!(null)),
        ("lock_provisioning", json!([])),
        (
            "release_identity",
            json!([
                "albertloky/SBXR",
                "v3.1.118",
                "a".repeat(40),
                "b".repeat(64)
            ]),
        ),
        ("phase", json!({"Ownership recorded":null})),
    ] {
        assert!(
            OwnershipRecord::decode(&changed(name, value)).is_err(),
            "accepted {name}"
        );
    }
    assert!(OwnershipRecord::decode(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    assert!(OwnershipRecord::decode(b"[]").is_err());
    assert_eq!(
        RecordError.to_string(),
        "Invalid or unsupported record authority"
    );
}

#[test]
fn all_required_fields_and_nested_identity_fields_are_required() {
    let canonical = standard().encode().unwrap();
    let value: Value = serde_json::from_slice(&canonical).unwrap();
    for name in value
        .as_object()
        .unwrap()
        .keys()
        .filter(|n| n.as_str() != "lock_provisioning")
    {
        let mut without = value.clone();
        without.as_object_mut().unwrap().remove(name);
        assert!(
            OwnershipRecord::decode(&serde_json::to_vec(&without).unwrap()).is_err(),
            "missing {name} accepted"
        );
    }
    for field in ["Repository", "Tag", "Commit", "IndexSHA256"] {
        let mut without = value.clone();
        without["release_identity"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(OwnershipRecord::decode(&serde_json::to_vec(&without).unwrap()).is_err());
    }
}

#[test]
fn unsupported_authority_and_changed_resources_cannot_be_promoted() {
    for (name, value) in [
        ("schema", json!(2)),
        ("tunnel", json!({})),
        ("subscription_compromised", json!(true)),
        ("client_identity_rotation", json!({})),
        ("unfinished_direction", json!("setup required")),
        ("configuration_sha256", json!("d".repeat(64))),
        ("permitted_resources", json!(["/etc/ssh/sshd_config"])),
    ] {
        assert!(OwnershipRecord::decode(&changed(name, value)).is_err());
    }
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.1.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.88.99.1",
        "192.168.1.1",
        "198.18.1.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
    ] {
        assert!(
            OwnershipRecord::decode(&changed("public_ipv4", json!(address))).is_err(),
            "accepted {address}"
        );
    }
}

#[test]
fn setup_checkpoint_order_preserves_the_commitment_boundary() {
    let mut record = standard();
    while record.phase() != SetupPhase::ActivationCommitted {
        assert_eq!(record.recovery_direction(), RecoveryDirection::Cleanup);
        record = record.next_setup_checkpoint().unwrap();
    }
    assert_eq!(record.recovery_direction(), RecoveryDirection::FinishSetup);
    assert!(record.next_cleanup_checkpoint().is_err());
    while record.phase() != SetupPhase::Running {
        record = record.next_setup_checkpoint().unwrap();
    }
    assert_eq!(record.recovery_direction(), RecoveryDirection::None);
    assert!(record.next_setup_checkpoint().is_err());
    let mut cleanup = standard().next_cleanup_checkpoint().unwrap();
    assert!(cleanup.next_setup_checkpoint().is_err());
    while cleanup.cleanup_checkpoint() != 8 {
        cleanup = cleanup.next_cleanup_checkpoint().unwrap();
    }
    assert!(cleanup.next_cleanup_checkpoint().is_err());
    assert!(!record.permits_successor(&standard()));
}

#[test]
fn read_does_not_convert_legacy_authority_or_rewrite_its_bytes() {
    let bytes = standard().encode().unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("lock_provisioning");
    value["permitted_resources"]
        .as_array_mut()
        .unwrap()
        .truncate(15);
    let legacy = OwnershipRecord::decode(&serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    assert_eq!(legacy.permitted_resources().len(), 15);
    assert!(
        !String::from_utf8(legacy.encode().unwrap())
            .unwrap()
            .contains("lock_provisioning")
    );
}

#[test]
fn installed_record_codec_is_strict_but_does_not_authenticate_an_executable() {
    let bytes = format!(
        "{{\"schema\":1,\"repository\":\"albertloky/SBXR\",\"tag\":\"v3.1.118\",\"commit\":\"{}\",\"release_index_sha256\":\"{}\",\"sequence\":192,\"architecture\":\"amd64\",\"executable_sha256\":\"{}\"}}\n",
        "a".repeat(40),
        "b".repeat(64),
        "c".repeat(64)
    );
    let record = InstalledRecord::decode(bytes.as_bytes()).unwrap();
    assert_eq!(record.sequence(), 192);
    assert_eq!(record.release_identity().tag(), "v3.1.118");
    let zero = bytes.replace("v3.1.118", "v0.0.1");
    assert_eq!(
        InstalledRecord::decode(zero.as_bytes())
            .unwrap()
            .release_identity()
            .tag(),
        "v0.0.1"
    );
    assert!(InstalledRecord::decode(&[bytes.as_bytes(), &vec![b' '; 4096]].concat()).is_err());
    assert_eq!(record.encode().unwrap(), bytes.as_bytes());
    for replacement in [
        "\"architecture\":\"x86\"",
        "\"sequence\":0",
        "\"sequence\":1,\"sequence\":2",
        "\"token\":\"do-not-leak\"",
        "\"sequence\":null",
    ] {
        let bad = bytes.replace("\"sequence\":192", replacement);
        assert!(InstalledRecord::decode(bad.as_bytes()).is_err());
    }
}
