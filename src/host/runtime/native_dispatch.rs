//! Native private dispatch over already protected installed state. This local
//! status check grants no artifact-acquisition/install trust. Early boot permits
//! AF_UNIX only and therefore must never depend on online release acquisition.
//! Development binaries lack released build identity and refuse before effects.
use super::*;
use crate::{
    runtime_handoff::{LinuxPeers, PeerObservations},
    subscription_serving::{Code, Module},
};
use std::time::Instant;
pub struct NativePrivateRuntime;
fn released_build() -> Result<&'static str, Error> {
    // Retained identity must not activate unqualified native roles.
    super::super::require_live_adapter().map_err(refused)?;
    crate::build_identity::compiled_commit().ok_or(Error::Refused)
}

impl NativePrivateRuntime {
    fn run(&self, role: Role) -> Result<(), Error> {
        if matches!(
            role,
            Role::RenewalRecord | Role::RenewalDeploy | Role::RenewalPost
        ) {
            return Err(Error::Refused);
        }
        let commit = released_build()?;
        let context = StartContext::new(
            Cancellation::new(),
            Instant::now() + runtime_handoff::START_TIMEOUT,
        );
        let _signals = super::shutdown::Signals::native(context.stop.clone())?;
        let admission =
            crate::host::admission_private::OfflinePrivateAdmission::native(role, &context)
                .map_err(refused)?;
        let installed = admission.record();
        if commit != installed.release_identity().commit() {
            return Err(Error::Refused);
        }
        match role {
            Role::SubscriptionServing => {
                // The sandbox cannot read /proc. Fixed cgroup, kernel execfn,
                // loaded build identity, protected installed pair and complete
                // sandbox checks form the ordinary local contract. The Owner
                // independently checks full child bytes when lending authority.
                let host = ServingRuntimeHost::native_unreleased(&admission).map_err(refused)?;
                if runtime_handoff::serve_subscription(&host, &Module::new(), &context)
                    == Code::Stopped
                {
                    Ok(())
                } else {
                    Err(Error::Refused)
                }
            }
            Role::ProxyStartAuthorize => runtime_handoff::authorize_proxy_start(
                &ProxyRuntimeHost::native_local_unreleased(&admission).map_err(refused)?,
                &context,
            ),
            Role::ProvisionMutationLock => {
                context.check()?;
                let current = LinuxPeers.current()?;
                if current.uid != 0 || current.executable_sha256 != installed.executable_sha256() {
                    return Err(Error::Refused);
                }
                let files =
                    super::material::RuntimeFiles::native_record(&admission).map_err(refused)?;
                let lock = HostLock::provision(Path::new("/"), 0).map_err(refused)?;
                files.installed()?;
                if LinuxPeers.current()? != current {
                    return Err(Error::Refused);
                }
                lock.verify().map_err(refused)?;
                context.check()
            }
            _ => Err(Error::Refused),
        }
    }
}
impl Runtime for NativePrivateRuntime {
    fn invoke(&mut self, role: Role) -> u8 {
        if self.run(role).is_ok() {
            0
        } else {
            role.refused_code()
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unreleased_private_dispatch_refuses_every_role_before_effects() {
        for role in [
            Role::ProvisionMutationLock,
            Role::ProxyStartAuthorize,
            Role::SubscriptionServing,
            Role::RenewalRecord,
            Role::RenewalDeploy,
            Role::RenewalPost,
        ] {
            assert_eq!(NativePrivateRuntime.invoke(role), role.refused_code());
        }
    }
}
