# Synthetic native tunnel adapter inputs

`ca.pem`, `server.pem` and `server-key.pem` are disposable RSA test material,
created with OpenSSL solely for these loopback fixtures. The server certificate
has the DNS SANs `fixture.example.com` and `api.ipify.org`. The CA private key is
not retained. The server key is public test data, never a live credential.

The tests inject this CA and loopback addresses explicitly. Native construction
uses the bundled public WebPKI roots and fixed production targets; it cannot
select these fixture trust roots or address overrides. The test executable is
its own synthetic proxy subprocess: it authenticates CONNECT and terminates
fixture TLS without running sing-box, cloudflared, systemd or any downloaded
program. Tests deliberately fabricate `/proc` and socket-owner observations;
those tests prove adapter handling and cleanup, not Linux kernel observations
or actual VMess traffic. Public DNS, Linux systemd/cgroup behavior and an
outside client remain unvalidated.

`package-default.json` is the unchanged 635-byte public default configuration
from the pinned sing-box 1.14.3 amd64 DEB (full DEB SHA-256
`ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e`).
Its SHA-256 is `4da8152e6cc1b50b1eaa4ff5606510aeb6d3f6a6a5c91614d4b2c0ea9a2b1bde`.
It is public package data, not an operational configuration. The integration
regression now proves exact package-owned recognition and atomic replacement
with the intended private 0640 file. The source copy in
`src/package_acquisition/default-config.json` is independently checked against the
fully pinned DEB's unique root:root 0644 member by the streaming package test.
Changed, unclaimed or post-configuration defaults remain refused. These local
fixtures do not qualify a native package installation or public VMess traffic.
