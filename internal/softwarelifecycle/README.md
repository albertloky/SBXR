# Software Lifecycle

Software Lifecycle owns SBXR release identity and delivery. One selected immutable tag either becomes one typed `VerifiedRelease` and one completely staged architecture payload, or `View` returns `SOFTWARE-LIFECYCLE-RELEASE-REFUSED` with no candidate or permitted mutation.

The genuine external Seam is `ReleaseSource`. The GitHub Adapter:

1. requires `/usr/bin/gh` version `2.97.0`, matches it to the installed `gh` Debian package, proves that package is unchanged, proves the configured APT origin is `https://cli.github.com/packages`, requires the reviewed current signing fingerprint `7F38BBB59D064DBCB3D84D725612B36462313325` in the configured keyring, and matches `/usr/bin/gh` to the exact immutable verified official `amd64` or `arm64` package bytes;
2. runs `gh release verify <tag> --repo albertloky/SBXR --format json`;
3. downloads each attested file from that same explicit tag through bounded standard output, stopping before more than 1 MiB for `release-index.json` or 256 MiB for either archive can enter memory or disk;
4. runs `gh release verify-asset <tag> <file>` for `release-index.json` and every downloaded payload; and
5. returns only the repository, tag, commit, asset digests, downloaded bytes, and verifier proof needed by `View`.

Raw verifier output and errors never cross the Adapter. `View` requires the attested, indexed, verified, and downloaded sets to agree exactly. The v1 index accepts only its ten named top-level fields and the four named fields for each of exactly two roles. Version and tag remain safe opaque strings; sequence, not version parsing, controls ordering. It rejects duplicate JSON keys, unknown fields, missing or duplicate roles/names, unsafe names, source ZIPs, malformed values, non-positive or oversized files, digest/size disagreement, extra or missing files, and archives that do not contain exactly one regular executable named `sbxr` with mode `0755` or contain a trailing gzip member.

`View` reports only installation status, installed identity when valid, verified and staged candidate proof, migration schema summary, eligibility, the two affected architecture components, and currently permitted review action. It does not publish or execute an archive, change the host, retain release history, expose Owner-managed values, accept ordinary HTTPS/checksums/earlier proof, or add an offline verifier. Durable candidate retention belongs to issue #128.

Issue #126 lets `View` authenticate one selected architecture before the Ubuntu staging Adapter opens it in a fresh private directory. The Adapter never executes the candidate. It checks archive size, digest, entry type, ownership and mode, Linux ELF architecture, static linkage, Go `1.26.5`, `GOOS=linux`, selected `GOARCH`, and `CGO_ENABLED=0`, then removes the temporary copy.

The executable embeds repository, immutable tag, commit SHA, and the SHA-256 of its unstamped ELF bytes as its independent payload identity. Software Lifecycle binds those facts to the already authenticated external index and asset proof; the index SHA-256 remains outside the executable to avoid a circular archive digest. `sbxr version` reports the embedded facts. A later installed-State slice may add the complete bound Release Identity without accepting a caller-authored index SHA.

The stamped payload also contains the complete generated JSON Schema for State schema `1`, its exact zero-edge migration path, the exact ten managed systemd units, and public no-authority qualification fixtures made by the real six-profile and seven-representation renderers. Schema `1` has no predecessor, so the payload rejects an invented bootstrap migration; the first real successor must add one complete deterministic no-network edge.

`go run ./cmd/sbxr-release -tag <tag> -commit <commit> -architecture <amd64|arm64> -output <archive>` is the production release-build entry point. It refuses a commit other than the checked-out `HEAD`, refuses tracked changes, exports the exact committed source rather than building untracked files, builds the pure-Go Linux executable, generates all embedded material, and runs the exact native validators before it can stamp or write the one-file archive. Native qualification uses Xray-core `v26.3.27`, sing-box `v1.13.16` with AnyTLS floor `v1.12.0`, cloudflared `2026.7.3`, Certbot `5.4` or newer from either the supported snap or a proved pip virtual environment, and Mihomo `v1.19.29`. Qualification fixture values are fixed public test material, never Owner credentials, provider authority, or Owner selections. The payload records the exact qualified artifact bytes, so any later semantic or representation change requires requalification.

Native tools are release-build inputs, not Clean VPS prerequisites. On the Clean VPS, staging authenticates the immutable release, checks the exact embedded schema, zero-edge migration path, units, paths, baselines, qualified artifact hashes, executable identity, architecture, and runtime facts, and never executes the candidate.

Programs are reserved for `/opt/sbxr/releases/<Release Identity>/`; Owner and generated State stays under `/var/lib/sbxr/`; service-consumable secret material stays under `/etc/sbxr/`; and the active immutable subscription set stays at `/var/lib/sbxr/subscriptions/current/`. The one-file archive cannot write to any of those paths during staging.

The fixed bounds are 1 MiB for `release-index.json` and 256 MiB for each architecture archive. Changing either limit requires a reviewed specification and new qualification evidence.
