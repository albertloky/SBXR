use super::ReleaseIdentity;
use super::identity::WireReleaseIdentity;
use super::{RecordError, decode, encode, sha256_hex};
use super::{authority::*, operations::*, resources::resources, retirement::WireRetirement};
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, net::IpAddr};

pub const PACKAGE_IDENTITY: &str = "https://deb.sagernet.org/ sing-box 1.14.3 amd64 32297878 ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetupPhase {
    #[serde(rename = "Ownership recorded")]
    OwnershipRecorded,
    #[serde(rename = "APT key installed")]
    AptKeyInstalled,
    #[serde(rename = "APT source installed")]
    AptSourceInstalled,
    #[serde(rename = "Service masked")]
    ServiceMasked,
    #[serde(rename = "Package installed")]
    PackageInstalled,
    #[serde(rename = "Package held")]
    PackageHeld,
    #[serde(rename = "State directory created")]
    StateDirectoryCreated,
    #[serde(rename = "Configuration installed")]
    ConfigurationInstalled,
    #[serde(rename = "Configuration validated")]
    ConfigurationValidated,
    #[serde(rename = "Service unmasked")]
    ServiceUnmasked,
    #[serde(rename = "Activation committed")]
    ActivationCommitted,
    #[serde(rename = "Service enabled")]
    ServiceEnabled,
    #[serde(rename = "Service started")]
    ServiceStarted,
    #[serde(rename = "Running")]
    Running,
    #[serde(rename = "Removal committed")]
    RemovalCommitted,
}

const PHASES: [SetupPhase; 14] = [
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
    SetupPhase::Running,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryDirection {
    #[serde(rename = "cleanup required")]
    Cleanup,
    #[serde(rename = "setup required")]
    FinishSetup,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "removal required")]
    Removal,
}
impl SetupPhase {
    pub fn recovery_direction(self) -> RecoveryDirection {
        match self {
            Self::Running => RecoveryDirection::None,
            Self::RemovalCommitted => RecoveryDirection::Removal,
            Self::ActivationCommitted | Self::ServiceEnabled | Self::ServiceStarted => {
                RecoveryDirection::FinishSetup
            }
            _ => RecoveryDirection::Cleanup,
        }
    }
    fn next(self) -> Option<Self> {
        PHASES
            .iter()
            .position(|p| *p == self)
            .and_then(|i| PHASES.get(i + 1).copied())
    }
}

fn string_enum<'de, D: Deserializer<'de>, T: serde::de::DeserializeOwned>(
    decoder: D,
) -> Result<T, D::Error> {
    let value = String::deserialize(decoder)?;
    T::deserialize(serde::de::value::StringDeserializer::<D::Error>::new(value))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LockProvisioning {
    pub unit_sha256: String,
}
pub(super) fn lock_digest() -> String {
    sha256_hex(include_bytes!("lock-provision.service"))
}
fn nonnull_optional<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Option<LockProvisioning>, D::Error> {
    super::object(decoder).map(Some)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireOwnershipRecord {
    pub schema: u32,
    #[serde(deserialize_with = "string_enum")]
    pub phase: SetupPhase,
    #[serde(deserialize_with = "string_enum")]
    pub unfinished_direction: RecoveryDirection,
    #[serde(deserialize_with = "super::object")]
    pub release_identity: WireReleaseIdentity,
    pub proxy_package_identity: String,
    pub public_ipv4: String,
    pub destination_address: String,
    pub destination_server_name: String,
    pub configuration_sha256: String,
    pub permitted_resources: Vec<String>,
    pub cleanup_checkpoint: u32,
    pub removal_checkpoint: u32,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_objects"
    )]
    pub resource_creating_releases: Option<Vec<WireReleaseIdentity>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub finishing_release_identity: Option<WireReleaseIdentity>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub serving: Option<WireServing>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub renewal: Option<WireRenewal>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub certificate_activation: Option<WireActivation>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub subscription_enablement: Option<WireEnablement>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub subscription_rotation: Option<WireRotation>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub subscription_repair: Option<WireRepair>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub subscription_compromised: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub subscription_resources: Option<WireSubscriptionResources>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub proxy_startup: Option<WireStartup>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "nonnull_optional"
    )]
    pub lock_provisioning: Option<LockProvisioning>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub tunnel: Option<WireTunnel>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub client_identity_rotation: Option<WireClientRotation>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub https_retirement: Option<WireRetirement>,
    #[serde(
        default,
        skip_serializing_if = "is_false",
        deserialize_with = "super::true_only"
    )]
    pub subscription_transport_migration: bool,
}

/// Validated authority only; raw secrets and unsupported operation fields cannot
/// be represented. No Serde implementation bypasses this type's validation.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipRecord(pub(super) WireOwnershipRecord);
impl fmt::Debug for OwnershipRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnershipRecord")
            .field("phase", &self.phase())
            .field("direction", &self.recovery_direction())
            .finish_non_exhaustive()
    }
}
impl OwnershipRecord {
    pub fn new_standard(
        release: ReleaseIdentity,
        public_ipv4: &str,
        configuration_sha256: &str,
    ) -> Result<Self, RecordError> {
        let mut wire = WireOwnershipRecord {
            schema: 1,
            phase: SetupPhase::OwnershipRecorded,
            unfinished_direction: RecoveryDirection::Cleanup,
            release_identity: release.0,
            proxy_package_identity: PACKAGE_IDENTITY.into(),
            public_ipv4: public_ipv4.into(),
            destination_address: "google.com:443".into(),
            destination_server_name: "google.com".into(),
            configuration_sha256: configuration_sha256.into(),
            permitted_resources: vec![],
            cleanup_checkpoint: 0,
            removal_checkpoint: 0,
            resource_creating_releases: None,
            finishing_release_identity: None,
            serving: None,
            renewal: None,
            certificate_activation: None,
            subscription_enablement: None,
            subscription_rotation: None,
            subscription_repair: None,
            subscription_compromised: false,
            subscription_resources: None,
            proxy_startup: None,
            tunnel: None,
            client_identity_rotation: None,
            https_retirement: None,
            subscription_transport_migration: false,
            lock_provisioning: Some(LockProvisioning {
                unit_sha256: lock_digest(),
            }),
        };
        wire.permitted_resources = resources(&wire);
        Self::validated(wire)
    }
    pub(super) fn validated(wire: WireOwnershipRecord) -> Result<Self, RecordError> {
        if !super::validation::valid(&wire) {
            return Err(RecordError);
        }
        Ok(Self(wire))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let wire = decode(bytes)?;
        if !super::validation::valid_shapes(bytes) {
            return Err(RecordError);
        }
        Self::validated(wire)
    }
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(&self.0)
    }
    pub fn public_ipv4(&self) -> &str {
        &self.0.public_ipv4
    }
    pub fn destination_address(&self) -> &str {
        &self.0.destination_address
    }
    pub fn destination_server_name(&self) -> &str {
        &self.0.destination_server_name
    }
    /// Ordinary private starts never choose a pending transition or recovery path.
    pub fn ordinary_proxy_start_sha256(&self) -> Option<&str> {
        if self.phase() != SetupPhase::Running
            || self.recovery_direction() != RecoveryDirection::None
            || self.pending_change().is_some()
            || self.0.subscription_transport_migration
        {
            return None;
        }
        self.0
            .proxy_startup
            .as_ref()
            .map(|s| s.drop_in_sha256.as_str())
    }
    pub fn lock_provisioning_sha256(&self) -> Option<&str> {
        self.0
            .lock_provisioning
            .as_ref()
            .map(|lock| lock.unit_sha256.as_str())
    }
    pub fn phase(&self) -> SetupPhase {
        self.0.phase
    }
    pub fn recovery_direction(&self) -> RecoveryDirection {
        self.0.unfinished_direction
    }
    pub fn cleanup_checkpoint(&self) -> u32 {
        self.0.cleanup_checkpoint
    }
    pub fn permitted_resources(&self) -> &[String] {
        &self.0.permitted_resources
    }
    pub fn configuration_sha256(&self) -> &str {
        &self.0.configuration_sha256
    }
    pub fn release_identity(&self) -> ReleaseIdentity {
        ReleaseIdentity(self.0.release_identity.clone())
    }
    pub fn next_setup_checkpoint(&self) -> Result<Self, RecordError> {
        if self.0.cleanup_checkpoint != 0 {
            return Err(RecordError);
        }
        let mut wire = self.0.clone();
        wire.phase = wire.phase.next().ok_or(RecordError)?;
        wire.unfinished_direction = wire.phase.recovery_direction();
        Self::validated(wire)
    }
    pub fn next_cleanup_checkpoint(&self) -> Result<Self, RecordError> {
        if self.recovery_direction() != RecoveryDirection::Cleanup || self.0.cleanup_checkpoint >= 8
        {
            return Err(RecordError);
        }
        let mut wire = self.0.clone();
        wire.cleanup_checkpoint += 1;
        Self::validated(wire)
    }
    pub fn permits_successor(&self, next: &Self) -> bool {
        self == next
            || self.next_setup_checkpoint().as_ref() == Ok(next)
            || self.next_cleanup_checkpoint().as_ref() == Ok(next)
            || self.http_successor(next)
    }
}

pub(super) fn public_ipv4(value: &str) -> bool {
    let Ok(address) = value.parse::<IpAddr>() else {
        return false;
    };
    let address = match address {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(v) => v.to_ipv4_mapped(),
    };
    let Some(address) = address else { return false };
    let [a, b, c, _] = address.octets();
    !(matches!(a, 0 | 10 | 127 | 224..=255)
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && (b == 0 && (c == 0 || c == 2) || b == 88 && c == 99 || b == 168)
        || a == 198 && ((18..=19).contains(&b) || b == 51 && c == 100)
        || a == 203 && b == 0 && c == 113)
}

pub(super) fn base_resources(wire: &WireOwnershipRecord) -> Vec<String> {
    let mut resources: Vec<String> = vec![
        "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1".into(),
        "/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority".into(),
        "/var/lib/sbxr/.proxy-ownership.json.next root:root 0600 one-link transaction material".into(),
        "/var/lib/sbxr/sing-box_1.14.3_amd64.deb root-owned one-link verified package artifact".into(),
        "/etc/apt/keyrings/sagernet.asc sha256:803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1".into(),
        "/etc/apt/keyrings/sagernet.asc.sbxr-next root-owned transaction material".into(),
        "/etc/apt/sources.list.d/sagernet.sources https://deb.sagernet.org/ signed-by sagernet.asc".into(),
        "/etc/apt/sources.list.d/sagernet.sources.sbxr-next root-owned transaction material".into(),
        "sing-box package 1.14.3 amd64 deb-sha256:ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e".into(),
        "sing-box package hold".into(),
        format!("/etc/sing-box/config.json sha256:{}", wire.configuration_sha256),
        "/var/lib/sing-box package state".into(),
        "sing-box.service package provenance stopped-disabled-before-commit".into(),
        "sing-box package-created user and group".into(),
        "tcp/443 local listener".into(),
    ];
    if let Some(lock) = &wire.lock_provisioning {
        resources.extend([
            format!("/etc/systemd/system/sbxr-mutation-lock.service root:root 0644 one-link sha256:{}", lock.unit_sha256),
            "/etc/systemd/system/sbxr-mutation-lock.service.sbxr-next root-owned synchronized no-replace publication".into(),
            "/etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service root-owned symlink ../sbxr-mutation-lock.service".into(),
        ]);
    }
    resources
}
