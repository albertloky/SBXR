//! Fixed same-executable private role dispatch. No public action or secret output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    ProvisionMutationLock,
    ProxyStartAuthorize,
    SubscriptionServing,
    RenewalRecord,
    RenewalDeploy,
    RenewalPost,
}
impl Role {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "--provision-mutation-lock" => Self::ProvisionMutationLock,
            "--proxy-start-authorize" => Self::ProxyStartAuthorize,
            "--subscription-serving" => Self::SubscriptionServing,
            "--certbot-recorder" => Self::RenewalRecord,
            "--certbot-deploy-hook" => Self::RenewalDeploy,
            "--certbot-post-hook" => Self::RenewalPost,
            _ => return None,
        })
    }
    pub fn refused_code(self) -> u8 {
        if self == Self::RenewalRecord { 125 } else { 1 }
    }
}
pub trait Runtime {
    fn invoke(&mut self, role: Role) -> u8;
}
/// Explicit unavailable adapter for callers without native released-build inputs.
/// Concrete native composition lives in host::runtime and remains prerequisite-gated.
pub struct NativeUnavailable;
impl Runtime for NativeUnavailable {
    fn invoke(&mut self, role: Role) -> u8 {
        role.refused_code()
    }
}
pub fn dispatch(arguments: &[std::ffi::OsString], runtime: &mut impl Runtime) -> Option<u8> {
    if arguments.len() != 1 {
        return None;
    }
    let role = Role::parse(arguments[0].to_str()?)?;
    Some(runtime.invoke(role))
}
