use sbxr::identity_generation::{
    ClientUuid, Entropy, GenerationId, Identity, IdentityError, SubscriptionGeneration,
};
use sbxr::{server_configuration::ServerConfiguration, subscription_artifact::ConnectionFacts};
use serde::Deserialize;
use std::collections::VecDeque;

struct TestEntropy {
    bytes: VecDeque<u8>,
    requests: Vec<usize>,
    fail_at: Option<usize>,
}

impl TestEntropy {
    fn sequence(length: u8) -> Self {
        Self {
            bytes: (0..length).collect(),
            requests: Vec::new(),
            fail_at: None,
        }
    }
}

impl Entropy for TestEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), IdentityError> {
        self.requests.push(destination.len());
        if self.fail_at == Some(self.requests.len()) {
            destination.fill(0xee);
            return Err(IdentityError::EntropyUnavailable);
        }
        for byte in destination {
            *byte = self
                .bytes
                .pop_front()
                .ok_or(IdentityError::EntropyUnavailable)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct GoVectors {
    identities: Vec<IdentityVector>,
    validation: Vec<ValidationVector>,
}

#[derive(Deserialize)]
struct IdentityVector {
    name: String,
    uuid: String,
    private_key: String,
    public_key: String,
    short_id: String,
}

#[derive(Deserialize)]
struct ValidationVector {
    name: String,
    uuid: String,
    private_key: String,
    public_key: String,
    short_id: String,
    valid: bool,
}

fn vectors() -> GoVectors {
    serde_json::from_str(include_str!("testdata/identity_generation/go-vectors.json")).unwrap()
}

#[test]
fn generated_identity_uses_independent_entropy_and_matches_go_derivation() {
    let mut entropy = TestEntropy::sequence(52);
    let identity = Identity::generate_with_entropy(&mut entropy).unwrap();
    assert_eq!(entropy.requests, [16, 4, 32]);
    assert!(entropy.bytes.is_empty());
    assert_eq!(
        identity.uuid().as_str(),
        "00010203-0405-4607-8809-0a0b0c0d0e0f"
    );
    assert_eq!(identity.short_id(), "10111213");
    let fixture = vectors()
        .identities
        .into_iter()
        .find(|v| v.name == "sequential")
        .unwrap();
    assert_eq!(identity.private_key(), fixture.private_key);
    assert_eq!(identity.public_key(), fixture.public_key);
}

#[test]
fn x25519_vectors_match_go_and_rfc7748() {
    for vector in vectors().identities {
        let identity =
            Identity::from_private_key(&vector.uuid, &vector.private_key, &vector.short_id)
                .unwrap_or_else(|_| panic!("vector refused: {}", vector.name));
        assert_eq!(identity.public_key(), vector.public_key, "{}", vector.name);
        assert!(
            Identity::from_parts(
                &vector.uuid,
                &vector.private_key,
                &vector.public_key,
                &vector.short_id,
            )
            .is_ok(),
            "{}",
            vector.name
        );
    }
}

#[test]
fn validation_matches_go_including_legacy_encoding_tolerance() {
    for vector in vectors().validation {
        let identity = Identity::from_parts(
            &vector.uuid,
            &vector.private_key,
            &vector.public_key,
            &vector.short_id,
        );
        assert_eq!(identity.is_ok(), vector.valid, "{}", vector.name);
        if let Ok(identity) = identity {
            assert_eq!(identity.uuid().as_str(), vector.uuid);
            assert_eq!(identity.private_key(), vector.private_key);
            assert_eq!(identity.public_key(), vector.public_key);
            assert_eq!(identity.short_id(), vector.short_id);
        }
    }
}

#[test]
fn uuid_generation_sets_version_and_variant_without_changing_other_bits() {
    let mut entropy = TestEntropy {
        bytes: [0xff; 16].into(),
        requests: Vec::new(),
        fail_at: None,
    };
    let uuid = ClientUuid::generate_with_entropy(&mut entropy).unwrap();
    assert_eq!(uuid.as_str(), "ffffffff-ffff-4fff-bfff-ffffffffffff");
    assert_eq!(entropy.requests, [16]);
    for bad in [
        "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF",
        "ffffffff-ffff-3fff-bfff-ffffffffffff",
        "ffffffff-ffff-4fff-cfff-ffffffffffff",
        "ffffffff-ffff-4fff-bfff-ffffffffffff\n",
        "",
        "💣",
    ] {
        assert!(ClientUuid::parse(bad).is_err());
    }
}

#[test]
fn subscription_credential_and_generation_ids_use_separate_random_bytes() {
    let mut entropy = TestEntropy::sequence(64);
    let generation = SubscriptionGeneration::generate_with_entropy(&mut entropy).unwrap();
    let operation = GenerationId::generate_with_entropy(&mut entropy).unwrap();
    assert_eq!(entropy.requests, [32, 16, 16]);
    assert_eq!(
        generation.credential().as_str(),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    );
    assert_eq!(
        generation.link_id().as_str(),
        "202122232425262728292a2b2c2d2e2f"
    );
    assert_eq!(operation.as_str(), "303132333435363738393a3b3c3d3e3f");
    assert_eq!(
        generation.credential().sha256(),
        [
            0xea, 0x86, 0x6a, 0x75, 0x7e, 0x4c, 0x38, 0xba, 0xbf, 0xa8, 0x12, 0x7c, 0xbe, 0x9a,
            0x40, 0x9d, 0x3e, 0x1f, 0x93, 0xa0, 0x0f, 0xf1, 0x48, 0x8f, 0xf7, 0x35, 0xfc, 0xf9,
            0x17, 0xaf, 0xff, 0xd0,
        ]
    );
}

#[test]
fn generation_id_parser_accepts_only_lowercase_16_byte_hex() {
    assert!(GenerationId::parse("0123456789abcdef0123456789abcdef").is_ok());
    for bad in [
        "",
        "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef",
        "g123456789abcdef0123456789abcdef",
    ] {
        assert!(GenerationId::parse(bad).is_err());
    }
}

#[test]
fn every_entropy_failure_refuses_without_retry_or_partial_identity() {
    for fail_at in 1..=3 {
        let mut entropy = TestEntropy::sequence(52);
        entropy.fail_at = Some(fail_at);
        assert!(matches!(
            Identity::generate_with_entropy(&mut entropy),
            Err(IdentityError::EntropyUnavailable)
        ));
        assert_eq!(entropy.requests.len(), fail_at);
    }
    for fail_at in 1..=2 {
        let mut entropy = TestEntropy::sequence(48);
        entropy.fail_at = Some(fail_at);
        assert!(matches!(
            SubscriptionGeneration::generate_with_entropy(&mut entropy),
            Err(IdentityError::EntropyUnavailable)
        ));
        assert_eq!(entropy.requests.len(), fail_at);
    }
    let mut empty = TestEntropy::sequence(0);
    assert!(GenerationId::generate_with_entropy(&mut empty).is_err());
    assert!(ClientUuid::generate_with_entropy(&mut empty).is_err());
}

#[test]
fn secret_bearing_debug_display_and_errors_are_redacted() {
    let identity = Identity::generate_with_entropy(&mut TestEntropy::sequence(52)).unwrap();
    let subscription =
        SubscriptionGeneration::generate_with_entropy(&mut TestEntropy::sequence(48)).unwrap();
    let text = format!(
        "{identity:?} {identity} {:?} {} {subscription:?} {subscription} {:?} {}",
        identity.uuid(),
        identity.uuid(),
        subscription.link_id(),
        subscription.link_id(),
    );
    for secret in [
        identity.uuid().as_str(),
        identity.private_key(),
        identity.public_key(),
        identity.short_id(),
        subscription.credential().as_str(),
    ] {
        assert!(!text.contains(secret));
    }
    for error in [
        IdentityError::EntropyUnavailable,
        IdentityError::InvalidIdentity,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        assert!(!format!("{error:?} {error}").contains(identity.private_key()));
    }
}

#[test]
fn generated_values_feed_existing_server_and_client_codecs() {
    let identity = Identity::generate_with_entropy(&mut TestEntropy::sequence(52)).unwrap();
    let server = ServerConfiguration::standard(&identity.server_identity().unwrap()).unwrap();
    let config: serde_json::Value = serde_json::from_slice(server.as_bytes()).unwrap();
    assert_eq!(
        config["inbounds"][0]["users"][0]["uuid"],
        identity.uuid().as_str()
    );
    assert_eq!(
        config["inbounds"][0]["tls"]["reality"]["private_key"],
        identity.private_key()
    );
    let facts = ConnectionFacts::new(
        "192.0.2.1",
        identity.uuid().as_str(),
        "microsoft.com",
        identity.public_key(),
        identity.short_id(),
        Some("vmess.example.com"),
    )
    .unwrap();
    let artifact = facts.subscription_artifact().unwrap();
    assert!(!String::from_utf8_lossy(artifact.as_bytes()).contains(identity.private_key()));
    let mut entropy = TestEntropy {
        bytes: [0xff; 16].into(),
        requests: Vec::new(),
        fail_at: None,
    };
    let replacement = ClientUuid::generate_with_entropy(&mut entropy).unwrap();
    let rotated = server
        .with_vmess_websocket("vmess.example.com")
        .unwrap()
        .with_client_uuid(replacement.as_str())
        .unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(rotated.as_bytes()).unwrap();
    assert_eq!(
        rotated["inbounds"][0]["users"][0]["uuid"],
        rotated["inbounds"][1]["users"][0]["uuid"]
    );
    assert_ne!(
        rotated["inbounds"][0]["users"][0]["uuid"],
        config["inbounds"][0]["users"][0]["uuid"]
    );
    assert_eq!(
        rotated["inbounds"][0]["tls"]["reality"],
        config["inbounds"][0]["tls"]["reality"]
    );
}

#[test]
fn os_entropy_creates_ephemeral_valid_identities_without_external_effects() {
    let identity = Identity::generate().unwrap();
    assert!(
        Identity::from_parts(
            identity.uuid().as_str(),
            identity.private_key(),
            identity.public_key(),
            identity.short_id()
        )
        .is_ok()
    );
    let subscription = SubscriptionGeneration::generate().unwrap();
    assert_eq!(subscription.credential().as_str().len(), 43);
    assert!(GenerationId::parse(subscription.link_id().as_str()).is_ok());
    assert!(ClientUuid::parse(ClientUuid::generate().unwrap().as_str()).is_ok());
    assert!(GenerationId::parse(GenerationId::generate().unwrap().as_str()).is_ok());
}
