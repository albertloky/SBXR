use super::authority::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireRetirement {
    #[serde(deserialize_with = "super::object")]
    pub serving: WireServing,
    #[serde(deserialize_with = "super::object")]
    pub renewal: WireRenewal,
    #[serde(deserialize_with = "super::object")]
    pub resources: WireSubscriptionResources,
    pub configuration_mode: u32,
    pub configuration_sha256: String,
    pub evidence_sha256: String,
}
impl WireRetirement {
    pub fn valid(&self) -> bool {
        self.serving.valid()
            && !self.serving.http
            && self.renewal.valid()
            && self.resources.valid()
            && !self.resources.http
            && self.resources.public_ipv4 == self.renewal.public_ipv4
            && self.configuration_mode & !0o777 == 0
            && self.configuration_mode & 0o133 == 0
            && self.configuration_mode & 0o400 != 0
            && nonzero_hex(&self.configuration_sha256, 64)
            && nonzero_hex(&self.evidence_sha256, 64)
    }
    pub fn resources(&self) -> Vec<String> {
        let mut out=vec!["/var/lib/sbxr/subscription-https-retired root:root 0700 retained-https-v1".into(),format!("/var/lib/sbxr/subscription-https-retired/renewal.conf root:root 0{:o} one-link sha256:{}",self.configuration_mode,self.configuration_sha256),"/var/lib/sbxr/subscription-https-retired/recorder.conf root:root 0644 one-link recorder-v1".into(),"/var/lib/sbxr/subscription-https-retired/deploy-hook root:root 0700 one-link deploy-writer-v1".into(),"/var/lib/sbxr/subscription-https-retired/post-hook root:root 0700 one-link post-writer-v1".into(),format!("/var/lib/sbxr/renewal-attempts.json root:root 0600 one-link retired-evidence-sha256:{}",self.evidence_sha256),"/var/lib/sbxr/renewal-admission.lock root:root 0600 one-link admission-v1".into(),"/var/lib/sbxr/renewal-writer.lock root:root 0600 one-link writer-v1".into()];
        out.extend(self.serving.resources().into_iter().skip(5));
        out.extend(self.resources.resources().into_iter().skip(3));
        out
    }
}
