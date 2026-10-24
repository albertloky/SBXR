pub mod artifact_trust;
pub mod client_identity;
pub mod configuration;
pub mod domain;
pub mod durable;
pub mod host;
pub mod identity_generation;
pub mod package_acquisition;
pub mod private_roles;
pub mod proxyinstallation;
pub mod records;
pub mod release_acquisition;
pub mod release_archive;
pub mod release_https;
pub mod release_identity;
pub mod removal;
pub mod runtime_handoff;
pub mod server_configuration;
pub mod subscription_artifact;
pub mod subscription_serving;
pub mod terminal;

#[cfg(test)]
#[path = "proxyinstallation_tests.rs"]
mod proxyinstallation_tests;
