#![forbid(unsafe_code)]

use sbxr::{configuration, server_configuration::*};
use serde_json::Value;

const UUID: &str = "12345678-1234-4234-8234-123456789abc";
const PRIVATE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn identity() -> ServerIdentity {
    ServerIdentity::from_private_key(UUID, PRIVATE, "01020304").unwrap()
}

#[test]
fn production_server_bytes_match_go_for_standard_and_optional_vmess() {
    let standard = ServerConfiguration::standard(&identity()).unwrap();
    assert_eq!(
        standard.as_bytes(),
        include_bytes!("testdata/server_configuration/standard.json")
    );
    let vmess = standard.with_vmess_websocket("tunnel.example.com").unwrap();
    assert_eq!(
        vmess.as_bytes(),
        include_bytes!("testdata/server_configuration/vless-vmess.json")
    );
    let v: Value = serde_json::from_slice(vmess.as_bytes()).unwrap();
    assert_eq!(v["log"], serde_json::json!({"disabled":true}));
    assert_eq!(v["inbounds"][0]["listen"], "::");
    assert_eq!(v["inbounds"][1]["listen"], "127.0.0.1");
    assert_eq!(v["inbounds"][1]["listen_port"], 10000);
    assert_eq!(v["inbounds"][1]["transport"]["path"], "/sbxr-vmess");
    assert!(v["inbounds"][1].get("tls").is_none());
    assert!(
        String::from_utf8_lossy(vmess.as_bytes())
            .find("cloudflared")
            .is_none()
    );
}

#[test]
fn validation_and_json_escaping_match_go_differential_vectors() {
    let vectors: Value = serde_json::from_slice(include_bytes!(
        "testdata/server_configuration/go-vectors.json"
    ))
    .unwrap();
    for vector in vectors.as_array().unwrap() {
        let text = |field: &str| vector[field].as_str().unwrap();
        let result =
            ServerIdentity::from_private_key(text("uuid"), text("private_key"), text("short_id"))
                .and_then(|id| {
                    ServerConfiguration::new(&id, text("destination"), text("server_name"))
                })
                .and_then(|c| {
                    if text("vmess_hostname").is_empty() {
                        Ok(c)
                    } else {
                        c.with_vmess_websocket(text("vmess_hostname"))
                    }
                });
        assert_eq!(
            result.is_ok(),
            vector["accepted"].as_bool().unwrap(),
            "vector {}",
            text("name")
        );
        if let Ok(config) = result {
            assert_eq!(
                config.as_bytes(),
                text("output").as_bytes(),
                "vector {}",
                text("name")
            );
        }
    }
    assert_eq!(vectors.as_array().unwrap().len(), 64);
}

#[test]
fn supplied_uuid_replacement_preserves_all_other_fields_in_both_inbounds() {
    let config = ServerConfiguration::standard(&identity())
        .unwrap()
        .with_vmess_websocket("tunnel.example.com")
        .unwrap();
    let mut before: Value = serde_json::from_slice(config.as_bytes()).unwrap();
    let replacement = "00000000-0000-4000-8000-000000000000";
    let after = config.with_client_uuid(replacement).unwrap();
    for inbound in before["inbounds"].as_array_mut().unwrap() {
        inbound["users"][0]["uuid"] = replacement.into();
    }
    assert_eq!(
        serde_json::from_slice::<Value>(after.as_bytes()).unwrap(),
        before
    );
    assert!(
        after
            .with_client_uuid("private-input-invalid-uuid")
            .is_err()
    );
    assert!(after.with_vmess_websocket("other.example.com").is_err());
}

#[test]
fn tunnel_unit_and_only_owned_resources_match_go() {
    assert_eq!(
        tunnel_unit().as_bytes(),
        include_bytes!("testdata/server_configuration/sbxr-tunnel.service")
    );
    let binding = TunnelBinding::from_parts(UUID, &"1".repeat(64), &"2".repeat(64)).unwrap();
    let expected: Vec<String> = serde_json::from_slice(include_bytes!(
        "testdata/server_configuration/tunnel-resources.json"
    ))
    .unwrap();
    assert_eq!(binding.resources(), expected);
    assert!(
        binding
            .resources()
            .iter()
            .all(|p| !p.starts_with(TUNNEL_TOKEN_PATH) && !p.starts_with(TUNNEL_BINARY_PATH))
    );
    assert!(
        tunnel_unit()
            .contains("DynamicUser=yes\nLoadCredential=tunnel-token:/etc/cloudflared/sbxr.token\n")
    );
    assert!(tunnel_unit().contains("--config /dev/null --no-autoupdate tunnel --metrics 127.0.0.1:0 run --token-file %d/tunnel-token\n"));
    assert!(tunnel_unit().contains("StandardOutput=null\nStandardError=null\n"));
    assert!(!tunnel_unit().contains("--token "));
    assert_eq!(TUNNEL_WANTS_TARGET, "../sbxr-tunnel.service");
}

#[test]
fn pinned_package_matches_current_go_host_contract() {
    let pins: Value = serde_json::from_slice(include_bytes!(
        "testdata/server_configuration/standard-pins.json"
    ))
    .unwrap();
    let p = PINNED_SING_BOX;
    for (field, value) in [
        ("APTKeyURL", p.signing_key_url),
        ("APTKeySHA256", p.signing_key_sha256),
        ("PackageName", p.name),
        ("PackageVersion", p.version),
        ("Architecture", p.architecture),
        ("PackageSHA256", p.sha256),
        ("PackageArtifactPath", p.artifact_path),
        ("ServiceUnitPath", p.service_unit_path),
    ] {
        assert_eq!(pins[field], value);
    }
    assert_eq!(pins["PackageSize"], p.size);
    assert_eq!(p.repository, "https://deb.sagernet.org/");
    assert_eq!(p.version, configuration::STANDARD.package_version);
    assert_eq!(p.sha256, configuration::STANDARD.package_sha256);
}

#[test]
fn diagnostics_never_disclose_supplied_credentials_or_configuration() {
    let id = identity();
    let config = ServerConfiguration::standard(&id).unwrap();
    let text = format!("{id:?} {id} {config:?} {config}");
    for secret in [UUID, PRIVATE, "01020304", "private_key"] {
        assert!(!text.contains(secret));
    }
    let error =
        ServerIdentity::from_private_key(UUID, "secret-invalid-key", "01020304").unwrap_err();
    assert_eq!(format!("{error}"), "server configuration refused");
    assert!(!format!("{error:?}").contains("secret-invalid-key"));
}

#[test]
fn binding_rejects_invalid_authority_shapes_and_exposes_only_fingerprints() {
    let binding = TunnelBinding::from_parts(UUID, &"1".repeat(64), &"2".repeat(64)).unwrap();
    assert_eq!(binding.tunnel_id(), UUID);
    assert_eq!(binding.token_sha256(), "1".repeat(64));
    assert_eq!(binding.binary_sha256(), "2".repeat(64));
    for (id, token, binary) in [
        (UUID.to_uppercase(), "1".repeat(64), "2".repeat(64)),
        (format!("{UUID}\n"), "1".repeat(64), "2".repeat(64)),
        (UUID.into(), "1".repeat(63), "2".repeat(64)),
        (UUID.into(), "F".repeat(64), "2".repeat(64)),
        (UUID.into(), "1".repeat(64), "g".repeat(64)),
    ] {
        assert!(TunnelBinding::from_parts(&id, &token, &binary).is_err());
    }
    // Tunnel IDs are not constrained to the generated client UUID v4 variant.
    assert!(
        TunnelBinding::from_parts(
            "00000000-0000-0000-0000-000000000000",
            &"0".repeat(64),
            &"0".repeat(64)
        )
        .is_ok()
    );
    let config = ServerConfiguration::standard(&identity()).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        config.sha256_hex(),
        format!("{:x}", Sha256::digest(config.as_bytes()))
    );
}

#[test]
fn cloudflared_version_gate_requires_token_file_support() {
    for version in [
        "cloudflared version 2025.4.0",
        "cloudflared version 2025.04.999",
        "cloudflared version 2026.1.0 (built synthetic)",
        "\ncloudflared version 2026.10.0\n",
    ] {
        assert!(valid_cloudflared_version(version), "{version}");
    }
    for version in [
        "",
        "2026.10.0",
        "cloudflared version 2025.3.99",
        "cloudflared version 2024.12.0",
        "cloudflared version 2026.0.0",
        "cloudflared version 2026.13.0",
        "cloudflared version 2026.001.0",
        "cloudflared version 2026.10",
        "cloudflared version 2026.10.0-dev",
        "cloudflared version 2026.10.0\ttext",
    ] {
        assert!(!valid_cloudflared_version(version), "{version}");
    }
    assert_eq!(TUNNEL_BINARY_PATH, "/usr/bin/cloudflared");
    assert_eq!(TUNNEL_TOKEN_PATH, "/etc/cloudflared/sbxr.token");
}

#[test]
fn runtime_decoder_accepts_exact_standard_and_vmess_without_changing_hash_subject() {
    let standard = include_bytes!("testdata/server_configuration/standard.json");
    let vmess = include_bytes!("testdata/server_configuration/vless-vmess.json");
    for bytes in [standard.as_slice(), vmess.as_slice()] {
        let original = [b" \n".as_slice(), bytes, b"\n".as_slice()].concat();
        let decoded = ServerConfiguration::decode_supported(&original).unwrap();
        assert_eq!(decoded.as_bytes(), original);
        let client = decoded
            .connection_facts("8.8.8.8")
            .unwrap()
            .subscription_artifact()
            .unwrap();
        assert!(!client.as_bytes().is_empty());
    }
    assert!(ServerConfiguration::decode_standard(vmess).is_err());
}
#[test]
fn runtime_vmess_decoder_refuses_duplicates_unknown_fields_and_identity_mismatch() {
    let source = include_bytes!("testdata/server_configuration/vless-vmess.json");
    for mutate in 0..5 {
        let mut v: Value = serde_json::from_slice(source).unwrap();
        match mutate {
            0 => {
                v["inbounds"][1]["users"][0]["uuid"] = "22345678-1234-4234-8234-123456789abc".into()
            }
            1 => v["inbounds"][1]["listen"] = "0.0.0.0".into(),
            2 => v["inbounds"][1]["transport"]["path"] = "/foreign".into(),
            3 => v["inbounds"][1]["foreign"] = true.into(),
            _ => v["outbounds"][0]["type"] = "block".into(),
        }
        assert!(
            ServerConfiguration::decode_supported(&serde_json::to_vec(&v).unwrap()).is_err(),
            "case {mutate}"
        );
    }
    let duplicated =
        String::from_utf8(source.to_vec())
            .unwrap()
            .replacen("{", "{\"inbounds\":[],", 1);
    assert!(ServerConfiguration::decode_supported(duplicated.as_bytes()).is_err());
}
