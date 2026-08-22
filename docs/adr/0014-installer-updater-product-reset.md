---
status: accepted
---

# Reset SBXR to the Installer-Updater

SBXR is one root-only Installer-Updater for Ubuntu Server 24.04 on `amd64` and `arm64`. Software Lifecycle is the sole deep Module. Its Interface is exactly `Status`, `Check`, `Update`, and `Recover`, all with one shared typed Result. The zero-argument numbered line menu is a standard-library Adapter to that Interface.

The product installs and updates only `/usr/local/bin/sbxr` and `/var/lib/sbxr/installed.json`. Install, Update, and Recover share one nonblocking kernel mutation lock. Update uses one strict schema-1 Update Record and exactly two durable checkpoints: before `Committed`, only restoration of the verified prior pair is legal; at and after `Committed`, only retention of the verified candidate and completion of cleanup is legal. Recovery refuses contradictory or incomplete authority.

Normal discovery admits only GitHub's canonical immutable qualified Latest release. One approved Acceptance VPS run may instead route the unchanged Pasteable Install Command and production GitHub Adapter to the exact two draft Release Identities bound by a keyless-signed, root-only trusted-workflow manifest. The locked channel changes release selection only; it adds no Owner command, argument, environment switch, menu action, transaction path, or unsigned test mode. Release Identity is repository, immutable tag, commit SHA, and `release-index.json` SHA-256. Release Sequence is the only update-order authority. Each public release has exactly `install.sh`, `release-index.json`, `sbxr-linux-amd64.tar.gz`, and `sbxr-linux-arm64.tar.gz`.

The Installer-Updater release line begins at `v2.0.0`, sequence `17`. Stable publication requires the packaged two-release procedure in `acceptance/RELEASE.md`. The installed executable accepts only `sudo sbxr`; any argument is refused. Repository-only `cmd/sbxr-release` is not an Owner command.

The final full proxy product is preserved by annotated tag `archive/full-product-v1.0.15` at exact commit `14fdf0a3decb6c653f9669438bf40221813b9d7d`. There is no archive branch. Twelve retired Modules, their commands, tests, workflows, dependencies, and runtime behavior are deleted atomically. Historical releases remain public and unsupported.

The only legacy behavior is a narrow install refusal: when safe inspection of `/usr/local/bin/sbxr` proves a valid historical `albertloky/SBXR` executable from immutable release `v1.0.0` through `v1.0.15`, installation returns `SOFTWARE-LIFECYCLE-INSTALL-LEGACY-REFUSED` and changes neither MVP path. SBXR does not scan other legacy paths, migrate, clean up, run side by side, or retain disabled compatibility behavior.

ADR-0001, ADR-0008, and this ADR are the complete current ADR authority. ADR-0002 through ADR-0007 and ADR-0009 through ADR-0013 are superseded by this decision.
