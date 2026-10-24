# Public loopback-only TLS material

These fixed Ed25519 keys are deliberately public synthetic test material. Their
only purpose is real certificate/hostname/HTTP boundary testing on nonprivileged
loopback listeners using private per-client trust stores and DNS overrides. They
are never installed in system trust, used as a production credential, or deployed.

`generate.go` regenerates the three PEM files with the pinned Go toolchain. The
fixed seeds are 4 (CA) and 5 (leaf); certificate validity is 2000–2100. The DNS names
match the fixed acquisition authorities so tests exercise normal hostname checks.
Real public requests instead use the pinned Mozilla roots. The generation program
is not part of the Rust executable or a runtime dependency.
