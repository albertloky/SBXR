use super::{
    lower_hex,
    ownership::{
        PACKAGE_IDENTITY, RecoveryDirection, SetupPhase, WireOwnershipRecord, lock_digest,
        public_ipv4,
    },
    resources::resources,
};
pub(super) fn valid(r: &WireOwnershipRecord) -> bool {
    use RecoveryDirection::{None as Idle, Removal};
    use SetupPhase::{RemovalCommitted, Running};
    if !matches!(r.schema, 1 | 2) || !r.release_identity.valid() {
        return false;
    }
    if r.schema == 1 {
        if r.resource_creating_releases.is_some()
            || r.finishing_release_identity.is_some()
            || r.serving.is_some()
            || r.renewal.is_some()
            || r.certificate_activation.is_some()
            || r.subscription_enablement.is_some()
            || r.subscription_rotation.is_some()
            || r.subscription_repair.is_some()
            || r.subscription_resources.is_some()
            || r.proxy_startup.is_some()
            || r.client_identity_rotation.is_some()
            || r.https_retirement.is_some()
            || r.subscription_transport_migration
        {
            return false;
        }
    } else {
        if !r
            .resource_creating_releases
            .as_ref()
            .is_some_and(|v| v.len() == r.permitted_resources.len() && v.iter().all(|i| i.valid()))
        {
            return false;
        }
        if r.unfinished_direction == Removal {
            if !r
                .finishing_release_identity
                .as_ref()
                .is_some_and(|v| v.valid())
            {
                return false;
            }
        } else if r.phase != Running
            || r.unfinished_direction != Idle
            || r.finishing_release_identity.is_some()
        {
            return false;
        }
    }
    let context = r.phase == Running && r.unfinished_direction == Idle
        || r.phase == RemovalCommitted && r.unfinished_direction == Removal;
    if r.https_retirement.as_ref().is_some_and(|v| {
        r.schema != 2
            || !v.valid()
            || v.renewal.public_ipv4 != r.public_ipv4
            || !r.serving.as_ref().is_some_and(|s| s.http)
            || r.renewal.is_some()
    }) {
        return false;
    }
    if r.subscription_transport_migration
        && (!r.https_retirement.as_ref().is_some_and(|v| {
            r.serving.as_ref().is_some_and(|s| {
                s.link_id == v.serving.link_id && s.credential_sha256 == v.serving.credential_sha256
            })
        }) || r.phase != Running
            || r.unfinished_direction != Idle
            || r.subscription_enablement.is_some()
            || r.subscription_rotation.is_some()
            || r.subscription_repair.is_some()
            || r.client_identity_rotation.is_some()
            || r.certificate_activation.is_some())
    {
        return false;
    }
    if let Some(s) = &r.serving {
        if !s.valid()
            || r.proxy_package_identity.is_empty()
            || !matches!(r.phase, Running | RemovalCommitted)
        {
            return false;
        }
        if s.http
            && (r.renewal.is_some()
                || !r.subscription_resources.as_ref().is_some_and(|v| v.http)
                || r.certificate_activation.is_some()
                || r.subscription_repair
                    .as_ref()
                    .is_some_and(|v| v.correction != "restart owned serving runtime"))
        {
            return false;
        }
    }
    if r.renewal.as_ref().is_some_and(|v| {
        r.serving.as_ref().is_none_or(|s| s.http)
            || !v.valid()
            || v.public_ipv4 != r.public_ipv4
            || !matches!(r.phase, Running | RemovalCommitted)
    }) {
        return false;
    }
    if let Some(v) = &r.certificate_activation
        && (r.schema != 2
            || r.renewal.is_none()
            || !context
            || !v.valid()
            || !r.serving.as_ref().is_some_and(|s| {
                if v.checkpoint == "target recorded" {
                    s == &v.source
                } else {
                    s == &v.target
                }
            }))
    {
        return false;
    }
    if let Some(v) = &r.subscription_enablement
        && (r.schema != 2
            || r.serving.is_some()
            || r.renewal.is_some()
            || r.certificate_activation.is_some()
            || !context
            || !v.valid())
    {
        return false;
    }
    if let Some(v) = &r.subscription_rotation
        && (r.schema != 2
            || r.subscription_enablement.is_some()
            || r.certificate_activation.is_some()
            || !context
            || !v.valid()
            || !r.serving.as_ref().is_some_and(|s| {
                (s.http || r.renewal.is_some())
                    && if v.checkpoint == "committed" {
                        s == &v.target
                    } else {
                        s == &v.source
                    }
            }))
    {
        return false;
    }
    if let Some(v) = &r.subscription_repair
        && (r.schema != 2
            || r.subscription_enablement.is_some()
            || r.subscription_rotation.is_some()
            || r.certificate_activation.is_some()
            || !context
            || !v.valid()
            || !r.serving.as_ref().is_some_and(|s| {
                (s.http || r.renewal.is_some())
                    && if v.checkpoint == "accepted" {
                        v.target.as_ref() == Some(s)
                    } else {
                        s == &v.source
                    }
            }))
    {
        return false;
    }
    if r.subscription_compromised && (r.schema != 2 || r.serving.is_none()) {
        return false;
    }
    if r.subscription_resources.as_ref().is_some_and(|v| {
        r.schema != 2
            || !v.valid()
            || v.public_ipv4 != r.public_ipv4
            || !r
                .serving
                .as_ref()
                .is_some_and(|s| (s.http || r.renewal.is_some()) && s.http == v.http)
    }) {
        return false;
    }
    if r.proxy_startup.as_ref().is_some_and(|v| {
        r.schema != 2 || !v.valid() || !matches!(r.phase, Running | RemovalCommitted)
    }) {
        return false;
    }
    if r.lock_provisioning
        .as_ref()
        .is_some_and(|v| v.unit_sha256 != lock_digest() || r.proxy_package_identity.is_empty())
    {
        return false;
    }
    if r.tunnel.as_ref().is_some_and(|v| {
        !v.valid() || r.proxy_package_identity.is_empty() || r.lock_provisioning.is_none()
    }) {
        return false;
    }
    if let Some(v) = &r.client_identity_rotation {
        if r.schema != 2
            || r.subscription_enablement.is_some()
            || r.subscription_rotation.is_some()
            || r.subscription_repair.is_some()
            || r.certificate_activation.is_some()
            || !context
            || !v.valid(r.proxy_startup.as_ref(), &r.configuration_sha256)
            || (v.subscription.is_none()) != (r.serving.is_none())
        {
            return false;
        }
        if v.subscription.as_ref().is_some_and(|sub| {
            !sub.valid()
                || !sub.source.http && r.renewal.is_none()
                || !r
                    .serving
                    .as_ref()
                    .is_some_and(|s| s == &sub.source || s == &sub.target)
        }) {
            return false;
        }
    }
    if r.unfinished_direction == Removal {
        if r.phase != RemovalCommitted
            || r.cleanup_checkpoint != 0
            || r.removal_checkpoint
                > if r.proxy_package_identity.is_empty() {
                    3
                } else {
                    11
                }
        {
            return false;
        }
        if r.proxy_package_identity.is_empty() {
            return r.public_ipv4.is_empty()
                && r.destination_address.is_empty()
                && r.destination_server_name.is_empty()
                && r.configuration_sha256.is_empty()
                && r.permitted_resources == resources(r);
        }
    } else if r.phase == RemovalCommitted
        || r.unfinished_direction != r.phase.recovery_direction()
        || r.cleanup_checkpoint > 8
        || r.removal_checkpoint != 0
        || r.unfinished_direction != RecoveryDirection::Cleanup && r.cleanup_checkpoint != 0
    {
        return false;
    }
    r.proxy_package_identity == PACKAGE_IDENTITY
        && lower_hex(&r.configuration_sha256, 64)
        && public_ipv4(&r.public_ipv4)
        && r.destination_address == "google.com:443"
        && r.destination_server_name == "google.com"
        && r.permitted_resources == resources(r)
}
pub(super) fn valid_shapes(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    if let Some(serving) = value.get("serving")
        && serving.get("http").is_some_and(|v| v != true)
    {
        return false;
    }
    if let Some(resources) = value.get("subscription_resources") {
        for flag in ["http", "recorder_directory_created"] {
            if resources.get(flag).is_some_and(|v| v != true) {
                return false;
            }
        }
    }
    if let Some(retired) = value.get("https_retirement")
        && (retired["serving"].get("http").is_some()
            || retired["resources"].get("http").is_some()
            || retired["resources"]
                .get("recorder_directory_created")
                .is_some_and(|v| v != true))
    {
        return false;
    }
    if let Some(repair) = value.get("subscription_repair")
        && (repair.get("effects").is_none() || repair.get("completed_effects").is_none())
    {
        return false;
    }
    true
}
