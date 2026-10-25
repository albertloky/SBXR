/// Fixed values copied from the committed Go host contract; never probed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardSetup {
    pub ownership_path: &'static str,
    pub configuration_path: &'static str,
    pub mutation_lock_path: &'static str,
    pub service: &'static str,
    pub package_version: &'static str,
    pub package_sha256: &'static str,
    pub listen_port: u16,
    pub handshake_address: &'static str,
    pub server_name: &'static str,
}

pub const STANDARD: StandardSetup = StandardSetup {
    ownership_path: "/var/lib/sbxr/proxy-ownership.json",
    configuration_path: "/etc/sing-box/config.json",
    mutation_lock_path: "/run/lock/sbxr.lock",
    service: "sing-box.service",
    package_version: "1.14.3",
    package_sha256: "ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e",
    listen_port: 443,
    handshake_address: "google.com:443",
    server_name: "google.com",
};
