//! Typed operation metadata shared by legacy decoding and current HTTP writers.
use super::{authority::*, lower_hex};
use serde::{Deserialize, Serialize};
pub(super) const ROTATION_EFFECTS: &[&str] = &[
    "prepare target",
    "stop source",
    "publish target",
    "activate target",
];
pub(super) const CLIENT_EFFECTS: &[&str] = &[
    "prepare target",
    "publish startup integration",
    "reload systemd",
    "verify startup route",
    "establish cutover gate",
    "stop source",
    "prove source quiescence",
    "revoke source",
    "publish target",
    "start target",
    "verify target",
    "clean staging",
];
pub(super) const CLIENT_CHECKPOINTS: &[&str] = &[
    "rotation authorized",
    "target prepared",
    "startup integration published",
    "systemd reloaded",
    "startup route verified",
    "cutover gated",
    "source stopped",
    "source quiescent",
    "source revoked",
    "target published",
    "target started",
];
pub(super) fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}
fn equal(completed: &Option<Vec<String>>, expected: &[&str]) -> bool {
    completed.as_deref().unwrap_or(&[]) == strings(expected)
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireEnablement {
    pub checkpoint: u32,
    pub link_id: String,
    pub credential_sha256: String,
    pub recorder_id: String,
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
    pub resources: Option<WireSubscriptionResources>,
}
impl WireEnablement {
    pub fn valid(&self) -> bool {
        if self.checkpoint > 23
            || !nonzero_hex(&self.link_id, 32)
            || !nonzero_hex(&self.credential_sha256, 64)
            || !nonzero_hex(&self.recorder_id, 32)
        {
            return false;
        }
        if let Some(resources) = &self.resources {
            if !resources.valid() {
                return false;
            }
            if resources.http {
                return self.renewal.is_none()
                    && match &self.serving {
                        None => self.checkpoint < 8,
                        Some(s) => {
                            s.http
                                && s.valid()
                                && s.link_id == self.link_id
                                && s.credential_sha256 == self.credential_sha256
                        }
                    };
            }
        }
        if self.serving.is_some() != self.renewal.is_some()
            || self.serving.is_some() && self.resources.is_none()
        {
            return false;
        }
        self.serving.as_ref().is_none_or(|s| {
            let r = self.renewal.as_ref().expect("paired");
            s.valid()
                && r.valid()
                && s.link_id == self.link_id
                && s.credential_sha256 == self.credential_sha256
                && r.recorder_id == self.recorder_id
                && self
                    .resources
                    .as_ref()
                    .is_some_and(|resources| resources.public_ipv4 == r.public_ipv4)
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRotation {
    pub operation_id: String,
    pub kind: String,
    pub direction: String,
    pub effects: Vec<String>,
    pub completed_effects: Option<Vec<String>>,
    #[serde(deserialize_with = "super::object")]
    pub source: WireServing,
    #[serde(deserialize_with = "super::object")]
    pub target: WireServing,
    pub checkpoint: String,
}
impl WireRotation {
    pub fn valid(&self) -> bool {
        let (completed, direction) = match self.checkpoint.as_str() {
            "target authorized" => (&[][..], "cleanup"),
            "stop authorized" => (&["target prepared"][..], "cleanup"),
            "committed" => (&["target prepared", "source stopped"][..], "forward"),
            _ => return false,
        };
        nonzero_hex(&self.operation_id, 32)
            && self.kind == "rotate subscription link"
            && self.direction == direction
            && self.effects == strings(ROTATION_EFFECTS)
            && equal(&self.completed_effects, completed)
            && self.source.valid()
            && self.target.valid()
            && self.source.link_id != self.target.link_id
            && self.source.credential_sha256 != self.target.credential_sha256
            && self.source.http == self.target.http
            && self.source.certificate_generation == self.target.certificate_generation
            && self.source.certificate_sha256 == self.target.certificate_sha256
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireActivation {
    #[serde(deserialize_with = "super::object")]
    pub source: WireServing,
    #[serde(deserialize_with = "super::object")]
    pub target: WireServing,
    pub checkpoint: String,
}
impl WireActivation {
    pub fn valid(&self) -> bool {
        matches!(
            self.checkpoint.as_str(),
            "target recorded" | "target accepted"
        ) && self.source.compatible_target(&self.target)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRepair {
    pub operation_id: String,
    pub kind: String,
    pub direction: String,
    pub correction: String,
    pub effects: Vec<String>,
    pub completed_effects: Option<Vec<String>>,
    pub checkpoint: String,
    #[serde(deserialize_with = "super::object")]
    pub source: WireServing,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub target: Option<WireServing>,
}
impl WireRepair {
    pub fn valid(&self) -> bool {
        if !nonzero_hex(&self.operation_id, 32)
            || self.kind != "repair subscription"
            || !self.source.valid()
            || !matches!(
                self.checkpoint.as_str(),
                "prepared" | "committed" | "accepted"
            )
        {
            return false;
        }
        let effects = match self.correction.as_str() {
            "restart owned serving runtime" => &["restart owned serving runtime"][..],
            "renew owned certificate" => &[
                "renew owned certificate",
                "activate published certificate",
                "resolve renewal evidence",
            ][..],
            _ => return false,
        };
        let completed = if self.checkpoint == "accepted" {
            effects
        } else if self.correction == "renew owned certificate" && self.target.is_some() {
            &["certificate published"][..]
        } else {
            &[][..]
        };
        self.effects == strings(effects)
            && equal(&self.completed_effects, completed)
            && self.direction
                == if self.checkpoint == "prepared" {
                    "cleanup"
                } else {
                    "forward"
                }
            && !(self.checkpoint == "prepared" && self.target.is_some()
                || self.checkpoint == "accepted" && self.target.is_none())
            && self.target.as_ref().is_none_or(|t| {
                self.source.compatible_target(t)
                    && (self.correction == "restart owned serving runtime" && t == &self.source
                        || self.correction == "renew owned certificate"
                            && t.certificate_generation > self.source.certificate_generation)
            })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireClientSubscription {
    #[serde(deserialize_with = "super::object")]
    pub source: WireServing,
    #[serde(deserialize_with = "super::object")]
    pub target: WireServing,
    pub source_artifact_sha256: String,
    pub target_artifact_sha256: String,
}
impl WireClientSubscription {
    pub fn valid(&self) -> bool {
        self.source.compatible_target(&self.target)
            && nonzero_hex(&self.source_artifact_sha256, 64)
            && nonzero_hex(&self.target_artifact_sha256, 64)
            && self.source_artifact_sha256 != self.target_artifact_sha256
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireClientRotation {
    pub operation_id: String,
    pub direction: String,
    pub effects: Vec<String>,
    pub completed_effects: Vec<String>,
    pub source_configuration_sha256: String,
    pub target_configuration_sha256: String,
    pub checkpoint: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::optional_object"
    )]
    pub subscription: Option<WireClientSubscription>,
}
impl WireClientRotation {
    pub fn index(&self) -> Option<usize> {
        CLIENT_CHECKPOINTS
            .iter()
            .position(|p| *p == self.checkpoint)
    }
    pub fn valid(&self, startup: Option<&WireStartup>, configuration: &str) -> bool {
        let Some(i) = self.index() else { return false };
        self.operation_id.len() == 32
            && self.operation_id.bytes().all(|b| b.is_ascii_hexdigit())
            && self.operation_id.bytes().any(|b| b != b'0')
            && lower_hex(&self.source_configuration_sha256, 64)
            && lower_hex(&self.target_configuration_sha256, 64)
            && self.source_configuration_sha256 != self.target_configuration_sha256
            && self.effects == strings(CLIENT_EFFECTS)
            && self.completed_effects == strings(&CLIENT_EFFECTS[..i])
            && self.direction == if i < 8 { "cleanup" } else { "forward" }
            && startup.is_some()
            && configuration
                == if i >= 9 {
                    &self.target_configuration_sha256
                } else {
                    &self.source_configuration_sha256
                }
    }
}
