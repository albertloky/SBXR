# Software Lifecycle

Software Lifecycle owns SBXR release identity and delivery. Issue #125 implements the first public `View` slice only: one selected immutable tag either becomes one typed `VerifiedRelease`, or `View` returns `SOFTWARE-LIFECYCLE-RELEASE-REFUSED` with no candidate or permitted mutation.

The genuine external Seam is `ReleaseSource`. The GitHub Adapter:

1. requires `/usr/bin/gh` version `2.97.0`, matches it to the installed `gh` Debian package, proves that package is unchanged, proves the configured APT origin is `https://cli.github.com/packages`, requires the reviewed current signing fingerprint `7F38BBB59D064DBCB3D84D725612B36462313325` in the configured keyring, and matches `/usr/bin/gh` to the exact immutable verified official `amd64` or `arm64` package bytes;
2. runs `gh release verify <tag> --repo albertloky/SBXR --format json`;
3. downloads each attested file from that same explicit tag through bounded standard output, stopping before more than 1 MiB for `release-index.json` or 256 MiB for either archive can enter memory or disk;
4. runs `gh release verify-asset <tag> <file>` for `release-index.json` and every downloaded payload; and
5. returns only the repository, tag, commit, asset digests, downloaded bytes, and verifier proof needed by `View`.

Raw verifier output and errors never cross the Adapter. `View` requires the attested, indexed, verified, and downloaded sets to agree exactly. The v1 index accepts only its ten named top-level fields and the four named fields for each of exactly two roles. Version and tag remain safe opaque strings; sequence, not version parsing, controls ordering. It rejects duplicate JSON keys, unknown fields, missing or duplicate roles/names, unsafe names, source ZIPs, malformed values, non-positive or oversized files, digest/size disagreement, extra or missing files, and archives that do not contain exactly one regular executable named `sbxr` with mode `0755` or contain a trailing gzip member.

`View` reports only installation status, installed identity when valid, verified candidate proof, migration schema summary, eligibility, the two affected architecture components, and currently permitted review action. It does not publish or execute an archive, change the host, retain release history, expose Owner-managed values, accept ordinary HTTPS/checksums/earlier proof, or add an offline verifier. Candidate staging and durable candidate retention belong to later issues #126 and #128.

The fixed bounds are 1 MiB for `release-index.json` and 256 MiB for each architecture archive. Changing either limit requires a reviewed specification and new qualification evidence.
