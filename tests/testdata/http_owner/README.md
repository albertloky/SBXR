# HTTP Owner fixtures

`generate.go` copies the named private renderer functions and ServingAuthority
wire struct unchanged from preserved Go commit abbe4d7. It generates two
byte-comparison fixtures without network, service or credential deployment.
The public A-repeated test credential is synthetic. Regenerate with the existing
Go toolchain and a workspace-owned GOCACHE/GOTMPDIR, passing this directory.

Owner fixture tests use protected disposable roots, actual Unix descriptor
lending, bounded local HTTP serving and injected system/process observations.
The interruption matrix advances only the private rate-accounting clock to
isolate recovery from per-source burst depletion; all I/O deadlines use real
time. The ordinary end-to-end test uses the default clock and production
limiter. No host clock, systemd, firewall, mount or security setting changes.

Client Identity Owner tests additionally compose the strict durable rotation
module, real protected target/configuration/startup files, one-use proxy gate
consumption through ServiceController and real HTTP artifact refresh. The proxy
process and loaded systemd/firewall observations remain injected. No native
service, package, firewall or credentials are deployed.
