use super::ownership::{WireOwnershipRecord, base_resources};
pub(super) fn resources(r: &WireOwnershipRecord) -> Vec<String> {
    let mut out = if r.proxy_package_identity.is_empty() {
        vec![
            "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1".into(),
            "/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority".into(),
            "/usr/local/bin/sbxr exact committed Release Identity".into(),
            "/var/lib/sbxr/installed.json exact committed Release Identity".into(),
        ]
    } else {
        base_resources(r)
    };
    if r.schema == 2 {
        out[0] = "/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-2".into()
    }
    if let Some(v) = &r.tunnel {
        out.extend(v.resources())
    }
    if let Some(v) = &r.serving {
        out.extend(v.resources())
    }
    if let Some(v) = &r.renewal {
        out.extend(v.resources())
    }
    if let Some(v) = &r.subscription_resources {
        out.extend(v.resources())
    }
    if let Some(v) = &r.https_retirement {
        out.extend(v.resources());
        if r.subscription_transport_migration {
            for path in [
                "/var/lib/sbxr/subscription-https-retired/renewal.conf",
                "/var/lib/sbxr/subscription-https-retired/recorder.conf",
                "/var/lib/sbxr/subscription-https-retired/deploy-hook",
                "/var/lib/sbxr/subscription-https-retired/post-hook",
                "/var/lib/sbxr/subscription-serving.json",
                "/etc/systemd/system/sbxr-subscription-firewall.service",
            ] {
                out.push(format!(
                    "{path}.sbxr-next root-owned retained-https migration publication"
                ))
            }
        }
    }
    if let Some(repair) = &r.subscription_repair {
        let serving = r.serving.as_ref().expect("validated repair serving");
        let replace_shared = repair.target.is_some() && *serving == repair.source;
        let additional = if *serving != repair.source {
            Some(&repair.source)
        } else {
            repair.target.as_ref()
        };
        if let Some(additional) = additional.filter(|v| *v != serving) {
            for resource in additional.resources() {
                let path = identity_path(&resource);
                if let Some(index) = out.iter().position(|old| identity_path(old) == path) {
                    if replace_shared {
                        out[index] = resource
                    }
                } else {
                    out.push(resource)
                }
            }
        }
    }
    if let Some(e) = &r.subscription_enablement {
        if let Some(v) = &e.serving {
            out.extend(v.resources())
        } else {
            out.extend(["/var/lib/sbxr/subscription-token root:root 0600 one-link provisional credential","/var/lib/sbxr/subscription-staging root:root 0700 provisional material","/etc/systemd/system/sbxr-subscription.service root:root 0644 one-link fixed-serving-v1","/etc/systemd/system/multi-user.target.wants/sbxr-subscription.service root-owned provisional enablement symlink","/etc/letsencrypt/archive/sbxr-subscription owned provisional lineage","/etc/letsencrypt/live/sbxr-subscription owned provisional lineage","/etc/letsencrypt/renewal/sbxr-subscription.conf owned provisional lineage","/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf root:root 0644 provisional recorder route","/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription root:root 0700 provisional hook","/etc/letsencrypt/renewal-hooks/post/sbxr-subscription root:root 0700 provisional hook","/var/lib/sbxr/renewal-attempts.json root:root 0600 provisional evidence"].into_iter().map(str::to_owned))
        }
        if let Some(v) = &e.renewal {
            out.extend(v.resources())
        }
        if let Some(v) = &e.resources {
            out.extend(v.resources())
        }
        if (8..=14).contains(&e.checkpoint) {
            out.push("/var/lib/sbxr/subscription-staging/credential root:root 0600 one-link provisional credential".into())
        }
        if (8..=15).contains(&e.checkpoint) {
            out.push("/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable provisional serving state".into())
        }
        for path in [
            "/var/lib/sbxr/subscription-staging/credential",
            "/var/lib/sbxr/subscription-staging/serving.json",
            "/var/lib/sbxr/subscription-token",
            "/var/lib/sbxr/subscription-serving.json",
            "/etc/systemd/system/sbxr-subscription.service",
            "/etc/systemd/system/sbxr-subscription-firewall.service",
            "/etc/systemd/system/snap.certbot.renew.service.d/50-sbxr-recorder.conf",
            "/etc/letsencrypt/renewal-hooks/deploy/sbxr-subscription",
            "/etc/letsencrypt/renewal-hooks/post/sbxr-subscription",
            "/var/lib/sbxr/renewal-admission.lock",
            "/var/lib/sbxr/renewal-writer.lock",
            "/var/lib/sbxr/renewal-attempts.json",
        ] {
            out.push(format!(
                "{path}.sbxr-next root-owned synchronized no-replace publication"
            ))
        }
    }
    if r.subscription_rotation.is_some() {
        out.extend(["/var/lib/sbxr/subscription-staging/credential root:root 0600 one-link replacement credential".into(),"/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable replacement serving state".into()]);
    }
    if let Some(v) = &r.proxy_startup {
        out.extend(v.resources())
    }
    if let Some(rotation) = &r.client_identity_rotation {
        out.extend([format!("/var/lib/sbxr/client-identity-target.json root:root 0600 one-link sha256:{}",rotation.target_configuration_sha256),"/var/lib/sbxr/client-identity-target.json.sbxr-next root-owned Client Identity target publication".into(),format!("/etc/sing-box/.config.json.sbxr-next root:sing-box 0640 one-link sha256:{}",rotation.target_configuration_sha256),"/etc/systemd/system/sing-box.service.d/sbxr-client-identity.conf.sbxr-next root-owned Client Identity startup publication".into()]);
        if let Some(sub) = &rotation.subscription {
            for serving in [&sub.source, &sub.target] {
                for resource in serving.resources() {
                    let path = identity_path(&resource);
                    if !out.iter().any(|old| identity_path(old) == path) {
                        out.push(resource)
                    }
                }
            }
            out.extend([format!("/var/lib/sbxr/subscription-staging/client-artifact root:root 0600 one-link sha256:{}",sub.target_artifact_sha256),"/var/lib/sbxr/subscription-staging/serving.json root:root 0600 immutable Client Identity serving state".into(),"/var/lib/sbxr/subscription-staging/client-artifact.sbxr-next root-owned Client Identity artifact publication".into(),"/var/lib/sbxr/subscription-staging/serving.json.sbxr-next root-owned Client Identity state publication".into(),"/etc/systemd/system/sbxr-subscription.service.sbxr-next root-owned Client Identity serving startup publication".into(),"/etc/systemd/system/sbxr-subscription.service.sbxr-next.sbxr-next root-owned Client Identity serving startup publication".into()]);
        }
    }
    if r.subscription_enablement
        .as_ref()
        .is_some_and(|e| e.resources.as_ref().is_some_and(|v| v.http))
    {
        out.retain(|v| {
            !v.contains("letsencrypt") && !v.contains("certbot") && !v.contains("renewal-")
        });
    }
    out
}
fn identity_path(value: &str) -> &str {
    value.split_once(' ').map_or(value, |(path, _)| path)
}
pub(super) fn creator_identity(value: &str) -> String {
    if value.starts_with("/var/lib/sbxr/renewal-attempts.json ") {
        return "/var/lib/sbxr/renewal-attempts.json".into();
    }
    if value.starts_with("/etc/sing-box/config.json ") {
        return "/etc/sing-box/config.json".into();
    }
    value
        .replace("schema-1", "schema")
        .replace("schema-2", "schema")
}
