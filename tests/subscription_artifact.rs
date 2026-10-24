#![forbid(unsafe_code)]

use sbxr::subscription_artifact::{
    ArtifactError, ConnectionFacts, HTTP_TRANSPORT_WARNING, HttpSubscriptionLink,
    MAX_SUBSCRIPTION_BYTES, SubscriptionCredential, VMESS_WEBSOCKET_PATH, valid_vmess_hostname,
};

const UUID: &str = "12345678-1234-4234-8234-123456789abc";
const PUBLIC_KEY: &str = "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q";
const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn facts(hostname: Option<&str>) -> ConnectionFacts {
    ConnectionFacts::new(
        "198.51.100.42",
        UUID,
        "www.example.com",
        PUBLIC_KEY,
        "01020304",
        hostname,
    )
    .unwrap()
}

#[test]
fn subscription_bytes_match_both_preserved_go_formats() {
    for (hostname, expected) in [
        (
            None,
            include_bytes!("testdata/subscription_artifact/vless.txt").as_slice(),
        ),
        (
            Some("tunnel.example.com"),
            include_bytes!("testdata/subscription_artifact/vless-vmess.txt").as_slice(),
        ),
    ] {
        let artifact = facts(hostname).subscription_artifact().unwrap();
        assert_eq!(artifact.as_bytes(), expected);
        assert_eq!(artifact.as_bytes().last(), Some(&b'\n'));
        assert!(!artifact.as_bytes().contains(&b'\r'));
        assert!(artifact.as_bytes().len() <= MAX_SUBSCRIPTION_BYTES);
    }
}

#[test]
fn outside_client_json_matches_go_field_order_types_and_trailing_newline() {
    for (hostname, expected) in [
        (
            None,
            include_bytes!("testdata/subscription_artifact/client-vless.json").as_slice(),
        ),
        (
            Some("tunnel.example.com"),
            include_bytes!("testdata/subscription_artifact/client-vless-vmess.json").as_slice(),
        ),
    ] {
        let client = facts(hostname).client_configuration().unwrap();
        assert_eq!(client.as_bytes(), expected);
        let json: serde_json::Value = serde_json::from_slice(client.as_bytes()).unwrap();
        assert_eq!(json["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(json["inbounds"][0]["listen_port"], 2080);
        assert_eq!(json["outbounds"][0]["type"], "vless");
        assert_eq!(json["outbounds"][0]["uuid"], UUID);
        assert!(!String::from_utf8_lossy(client.as_bytes()).contains("private_key"));
        if hostname.is_some() {
            assert_eq!(json["outbounds"][1]["uuid"], UUID);
            assert_eq!(
                json["outbounds"][1]["transport"]["path"],
                VMESS_WEBSOCKET_PATH
            );
        }
    }
}

#[test]
fn go_generated_validation_vectors_match_exact_acceptance_and_output() {
    let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(
        "testdata/subscription_artifact/go-vectors.json"
    ))
    .unwrap();
    let mut count = 0;
    for vector in vectors.as_array().unwrap() {
        let f = &vector["facts"];
        let text = |name: &str| f[name].as_str().unwrap();
        let result = ConnectionFacts::new(
            text("PublicIPv4"),
            text("UUID"),
            text("ServerName"),
            text("PublicKey"),
            text("ShortID"),
            Some(text("VMessHostname")),
        )
        .and_then(|f| f.subscription_artifact());
        assert_eq!(
            result.is_ok(),
            vector["accepted"].as_bool().unwrap(),
            "vector {}",
            vector["name"]
        );
        if let Ok(artifact) = result {
            assert_eq!(
                artifact.as_bytes(),
                vector["artifact"].as_str().unwrap().as_bytes(),
                "vector {}",
                vector["name"]
            );
        }
        count += 1;
    }
    assert!(count >= 76, "validation vector set was truncated");
}

#[test]
fn vmess_hostname_rules_are_distinct_from_reality_server_names() {
    for hostname in ["tunnel.example.com", "a.b", "1.2", "127.000.0.1"] {
        assert!(valid_vmess_hostname(hostname));
    }
    for hostname in [
        "",
        "localhost",
        "127.0.0.1",
        "EXAMPLE.COM",
        "https://example.com",
        "a..b",
        "a.b.",
        "a-.b",
        "a_b.c",
        "a.b:443",
        "é.example",
    ] {
        assert!(!valid_vmess_hostname(hostname));
    }
    assert!(
        ConnectionFacts::new("198.51.100.42", UUID, "A..B", PUBLIC_KEY, "01020304", None).is_ok()
    );
    assert_eq!(
        facts(None).subscription_artifact().unwrap().as_bytes(),
        facts(Some("")).subscription_artifact().unwrap().as_bytes()
    );
}

#[test]
fn http_links_use_only_the_exact_recorded_ipv4_fixed_port_and_raw_token() {
    let token = SubscriptionCredential::parse(TOKEN).unwrap();
    let link = HttpSubscriptionLink::new("198.51.100.42", &token).unwrap();
    let expected = format!("http://198.51.100.42:8443/s/{TOKEN}");
    assert_eq!(link.as_str(), expected);
    assert_eq!(
        HttpSubscriptionLink::parse(&expected).unwrap().as_str(),
        expected
    );
    assert_eq!(token.as_str(), TOKEN);
    assert_eq!(
        token.sha256(),
        [
            15, 0, 115, 133, 182, 249, 212, 183, 238, 178, 116, 134, 5, 175, 225, 169, 132, 160,
            163, 191, 163, 240, 20, 208, 158, 42, 120, 76, 233, 229, 205, 26
        ]
    );
    for ip in [
        "::1",
        "::ffff:198.51.100.42",
        "198.051.100.42",
        "example.com",
        "198.51.100.42:8443",
        "198.51.100.42\n",
    ] {
        assert!(HttpSubscriptionLink::new(ip, &token).is_err());
    }
    for bad in [
        expected.replacen("http:", "https:", 1),
        expected.replacen("http:", "HTTP:", 1),
        expected.replace(":8443", ":80"),
        expected.replace(":8443", ""),
        expected.replace("/s/", "/S/"),
        expected.replace("/s/A", "/s/%41"),
        expected.replace("198.51.100.42", "user@198.51.100.42"),
        format!("{expected}?"),
        format!("{expected}?x=1"),
        format!("{expected}#x"),
        format!("{expected}/"),
        format!("{expected}\n"),
        format!(" {expected}"),
    ] {
        assert!(HttpSubscriptionLink::parse(&bad).is_err());
    }
}

#[test]
fn credentials_are_canonical_32_byte_raw_base64url() {
    for bad in [
        String::new(),
        "A".repeat(42),
        "A".repeat(44),
        format!("{TOKEN}="),
        format!("{TOKEN}\n"),
        format!("{}B", "A".repeat(42)),
        format!("{}C", "A".repeat(42)),
        format!("{}D", "A".repeat(42)),
        format!("+{}", "A".repeat(42)),
        format!("/{}", "A".repeat(42)),
        format!(" {}", "A".repeat(42)),
        format!("\r{}", "A".repeat(42)),
    ] {
        assert!(SubscriptionCredential::parse(&bad).is_err());
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (index, last) in alphabet.iter().enumerate() {
        let candidate = format!("{}{}", "_".repeat(42), *last as char);
        assert_eq!(
            SubscriptionCredential::parse(&candidate).is_ok(),
            index % 4 == 0
        );
    }
}

#[test]
fn http_exposure_warning_retains_the_review_disclosure() {
    assert_eq!(
        HTTP_TRANSPORT_WARNING,
        "HTTP exposes the Subscription Link credential and downloaded proxy credentials to network interception and permits response tampering. Token authentication does not protect the transport."
    );
    let link = HttpSubscriptionLink::new(
        "198.51.100.42",
        &SubscriptionCredential::parse(TOKEN).unwrap(),
    )
    .unwrap();
    assert_eq!(link.transport_warning(), HTTP_TRANSPORT_WARNING);
}

#[test]
fn ordinary_diagnostics_never_disclose_client_or_subscription_secrets() {
    let facts = facts(Some("tunnel.example.com"));
    let artifact = facts.subscription_artifact().unwrap();
    let client = facts.client_configuration().unwrap();
    let credential = SubscriptionCredential::parse(TOKEN).unwrap();
    let link = HttpSubscriptionLink::new("198.51.100.42", &credential).unwrap();
    let output = format!(
        "{facts:?} {facts:#?} {facts} {artifact:?} {artifact} {client:?} {client} {credential:?} {credential} {link:?} {link} {err:?} {err}",
        err = ArtifactError
    );
    for secret in [
        UUID, PUBLIC_KEY, "01020304", TOKEN, "vless://", "vmess://", "http://",
    ] {
        assert!(!output.contains(secret));
    }
    let error = ConnectionFacts::new(
        "198.51.100.42",
        "secret-invalid-uuid",
        "www.example.com",
        PUBLIC_KEY,
        "01020304",
        None,
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "subscription artifact refused");
    assert!(!format!("{error:?}").contains("secret-invalid-uuid"));
}
