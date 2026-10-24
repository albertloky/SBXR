# Package acquisition fixtures

These are public, inert verification inputs. Tests never install or execute the
DEB, contact the vendor, modify APT/system trust, or use persistent credentials.

Fetched over HTTPS on 2026-10-24:

- `sagernet.asc`: `https://sing-box.app/gpg.key`, redirected to
  `https://deb.sagernet.org/gpg.key`; 3,129 bytes, SHA-256
  `803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1`.
- `Packages`: the single unchanged `sing-box` 1.14.3 amd64 stanza from
  `https://deb.sagernet.org/dists/*/*/binary-amd64/Packages`. It is a locator
  input, not authenticated release metadata or an authority to change the pins.
- `sing-box_1.14.3_amd64.deb`: complete vendor bytes from
  `https://deb.sagernet.org/files/ver_Gz0vP/sing-box_1.14.3_linux_amd64.deb`,
  redirected to the vendor's Gemfury S3 CDN; 32,297,878 bytes, SHA-256
  `ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e`.
  The full inert artifact is retained so a positive production-pin test exercises
  the actual SHA-256 verifier with no synthetic pin or success callback.
- `control.tar.gz`: the exact 972-byte ar member from that package, used to test
  structural metadata checks separately from the package digest check. No member
  is extracted by the Rust implementation.

Package source and license: [SagerNet/sing-box v1.14.3](https://github.com/SagerNet/sing-box/tree/v1.14.3)
(GPL-3.0-or-later, as identified in its control metadata). Vendor repository
configuration: [official package-manager documentation](https://sing-box.sagernet.org/installation/package-manager/).

The pins are copied from the preserved Go `hostSetupSpec`, not discovered from
the network. Go's signing-key fingerprint is SHA-256 of the complete armored key
bytes; neither Go nor this port substitutes arbitrary OpenPGP signatures for the
pinned DEB digest. Maintained `sha2` performs the cryptographic digest verification.
The `_gpgorigin` member is never executed, imported, or treated as a verification
callback. There is no caller-selectable trust policy or test-only verifier.

`generate.go` produces the three PEM fixtures in its current directory using the
same deliberately public Ed25519 test seeds as the existing release HTTPS tests.
The CA/leaf are valid 2000–2100 and name only the fixed package authorities plus
loopback. Run it only inside this fixture directory. They are not production
credentials and are never installed in the system trust store. Private client
roots and DNS overrides exist only inside the module's tests; public clients use
the pinned Mozilla roots with certificate and hostname verification enabled.

These local tests provide acquisition/regression evidence, not Ubuntu package
installation, deployment qualification, Karing acceptance, signing or publication.

Core integration retains the complete 32,297,878-byte inert DEB deliberately.
Its positive and same-length mutation tests must exercise the real compiled-in
production pin offline. A synthetic replacement or absent-file skip would lose
that coverage; deterministic retrieval would require network access on a fresh
checkout. The cost is about 32.3 MB in committed test inputs. It is not embedded
in the product binary, extracted, installed or executed. No updated source
archive or upload is part of this integration.

The public module export replaces the worker's temporary path inclusion.
`SetupMaterial::from_acquired_package` and `recover_acquired_package` consume the
opaque verified bytes, preserve existing pin checks and generate or retain the
configuration as appropriate. The combined integration test uses synthetic
entropy and never modifies a host.
