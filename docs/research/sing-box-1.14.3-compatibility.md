# sing-box 1.14.3 compatibility review — 2026-10-18

This source update pins fresh SBXR installations to official stable sing-box
1.14.3. It does not establish packaged live acceptance or change the current
clean-install-only support contract. Published v3.1.109 remains independent and
unchanged; its exact release still owns removal of its existing installations.

## Official package identity

[SagerNet v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3)
was published on 2026-10-09 as a non-draft, non-prerelease release.
SBXR uses the [official APT repository](https://deb.sagernet.org/Packages),
whose signed Release identifies the package index. Verification of Release.gpg
with the existing pinned public key succeeded: signer fingerprint
`2C317FBD5D886B4E89BAE8DA6D9152172A2B2F0C`; key-file SHA-256 remains
`803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1`.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| [APT amd64 DEB](https://deb.sagernet.org/files/ver_Gz0vP/sing-box_1.14.3_linux_amd64.deb) | 32297878 | `ed7feaa6c2083d58a7195866bf25a2693abc2beaf5c0d192c9370ffa39e0fd6e` |
| [GitHub amd64 DEB](https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box_1.14.3_linux_amd64.deb) | 32297762 | `eb8a5f1f2643baf1a060d0b5f0d1d015e28b72afa446be2d180f366a5dde18b1` |
| [GitHub macOS arm64 archive](https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-darwin-arm64.tar.gz) | 29163190 | `0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5` |

Downloaded bytes matched their respective published hashes. The two DEBs have
different archive hashes, but their `/usr/bin/sing-box` payloads are identical:
91990368 bytes, SHA-256
`33de1654134de582a3d23786fdba32e5461bfe3eefe3e11ddeef2a9635a9e91c`.
That hash identifies sing-box, not the separately packaged SBXR executable.
Control metadata, post-install script and the service unit also matched.
The APT hash is the setup, ownership, observer and new-qualification pin.

## Generated configuration

The [tagged migration guide](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/migration.md)
and [deprecation list](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/deprecated.md)
were reviewed against both generated configurations. Neither emits legacy DNS
servers, inline ACME, address-filter DNS rules, independent DNS cache, store_rdrc,
legacy inbound routing fields, ECH fields, or removed TUN options.

The server retains one VLESS inbound, REALITY handshake to google.com:443,
`xtls-rprx-vision`, and a direct outbound. The client retains its IPv4 server,
loopback mixed inbound, REALITY public key/short ID, and Chrome uTLS. These fields
remain supported by the tagged [TLS](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/shared/tls.md),
[VLESS inbound](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/inbound/vless.md),
and [VLESS outbound](https://github.com/SagerNet/sing-box/blob/v1.14.3/docs/configuration/outbound/vless.md)
contracts. Omitted packet encoding still defaults to XUDP in
[the outbound implementation](https://github.com/SagerNet/sing-box/blob/v1.14.3/protocol/vless/outbound.go#L77-L85).

No DNS section is needed for this configuration: the
[ordinary dialer](https://github.com/SagerNet/sing-box/blob/v1.14.3/common/dialer/dialer.go#L99-L127)
uses the default resolver when fewer than two DNS transports exist;
[box initialization](https://github.com/SagerNet/sing-box/blob/v1.14.3/box.go#L391-L398)
creates typed local DNS when none is configured. The
[REALITY handshake](https://github.com/SagerNet/sing-box/blob/v1.14.3/common/tls/reality_server.go#L116-L122)
uses this dialer. Both actual generated files passed `sing-box check` with the
verified official macOS arm64 1.14.3 binary, without warnings. This checks schema
and construction; it does not prove network traffic or Linux systemd behavior.

The DEB retains `/usr/bin/sing-box`, `/etc/sing-box/config.json`,
`/usr/lib/systemd/system/sing-box.service`, the sing-box system user and
`/var/lib/sing-box` state directory. Its post-install script creates the user and
reloads systemd without starting the service. Complete removal must still purge
the package, including its service template, D-Bus and polkit policy files.

## Qualification boundary

Fresh qualification requires the exact new APT identity, including byte count
and digest. The fixed historical Owner-exception and live89 archival paths retain their
original 1.13.19 identity and signed fixtures. Original live89 replay additionally
requires its exact original tag, sequence and source commit. Release discovery recognizes
both exact qualified package identities; it rejects other versions/digests and
mismatched outside-client identities. The installer also retains both complete
package/resource tuples when restoring the exact release committed to finish
removal; mixed tuples refuse. Fresh setup accepts only 1.14.3. Existing native,
attestation, all five live journeys and actual cleanup gates remain required
before stable publication.

Private downloads and local verification artifacts are retained under
`.scratch/acceptance/u143/`. No prior candidate's live results qualify the changed
binary.
