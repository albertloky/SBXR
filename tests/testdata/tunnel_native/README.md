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
