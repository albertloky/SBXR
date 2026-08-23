# SBXR

SBXR is a small, root-only Installer-Updater for Ubuntu Server 24.04. It installs one `sbxr` executable, finds only the qualified latest stable release, updates itself without losing the prior working executable, and recovers deterministically after interruption.

## Supported system

- Ubuntu Server 24.04 on `amd64` or `arm64`
- Root authority through `sudo`
- An interactive UTF-8 terminal
- `curl` for the first GitHub HTTPS download

SBXR owns only `/usr/local/bin/sbxr` and `/var/lib/sbxr/installed.json` after a successful installation. It does not migrate, clean up, or run the historical proxy product.

## Installation

Use the permanent Pasteable Install Command:

```sh
curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh | sudo bash
```

The command supports only the fixed host contract above. It authenticates and verifies the complete candidate before it changes either owned path. A current valid installation is a no-op. A higher-sequence local installation is not downgraded. A proved historical full-product executable from `v1.0.0` through `v1.0.15` is refused unchanged.

## Numbered menu

Run the installed product with no arguments:

```sh
sudo sbxr
```

The menu shows the installed version and one lifecycle state: `Ready`, `Update in progress`, or `Recovery required`.

- `1. Check for updates` reads GitHub's canonical qualified Latest release without changing local files.
- `2. Update SBXR` performs a fresh check, verifies the higher Release Sequence, and runs one crash-safe update.
- `1. Start recovery` is the only normal action shown when recovery is required.
- `0. Exit` returns to the shell.

Use Up, Down, a displayed number, and Enter. Pasted input, mouse input, unknown escape sequences, stale selections, and command arguments execute nothing.

## Update and recovery safety

Install, Update, and Recover share one nonblocking mutation lock. Update keeps exact prior and candidate bytes under a strict two-checkpoint transaction. Before `Committed`, recovery can only restore the verified prior release. At or after `Committed`, recovery can only retain the verified candidate and finish cleanup. Contradictory evidence fails closed.

## Releases and qualification

Each release has exactly four public assets:

```text
install.sh
release-index.json
sbxr-linux-amd64.tar.gz
sbxr-linux-arm64.tar.gz
```

Stable publication requires native automated proof on both architectures and one live packaged Ubuntu Server 24.04 `amd64` journey. The journey installs release A through the Pasteable Install Command, checks for release B through A's real numbered menu, updates through the production Software Lifecycle transaction, proves interruption and both recovery directions, preserves SSH, and verifies stable no-update behavior. Each Release Identity gets its own public Acceptance Record.

See [acceptance/RELEASE.md](acceptance/RELEASE.md) for the exact procedure.

## Historical full-product releases

Releases `v1.0.0` through `v1.0.15` remain public, immutable, unsupported history. Their final source is preserved by annotated tag `archive/full-product-v1.0.15` at commit `14fdf0a3decb6c653f9669438bf40221813b9d7d`. They are not installation, update, migration, recovery, compatibility, or qualification inputs for the Installer-Updater.
