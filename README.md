# SBXR

SBXR is a root-only V3 proxy product for one Ubuntu Server. Software Lifecycle installs and updates the `sbxr` executable. Proxy Installation owns the installed proxy journey through a review-first numbered menu.

## Supported system

- Ubuntu Server 24.04; the first V3 proxy journey accepts only `amd64`
- Root authority through `sudo`
- An interactive UTF-8 terminal
- `curl` for the first GitHub HTTPS download

Software Lifecycle owns `/usr/local/bin/sbxr` and `/var/lib/sbxr/installed.json`. V3 setup may add only the exact Proxy Installation resources recorded in `/var/lib/sbxr/proxy-ownership.json`. The current tracer bullet reviews and cancels setup without creating any of them.

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

Every screen shows the installed version, Proxy Installation Status, latest result, and stable result code. A clean installed host starts at `Not set up` with exactly:

- `1. Start setup` performs fresh read-only preflight and shows a secret-safe plan.
- `2. View details` shows current secret-safe local facts.
- `3. Complete removal` is visible but remains unavailable until its reviewed removal slice is implemented.
- `0. Exit` returns to the shell.

Enter or `n` declines the Start setup plan; `y` is the only approval value. Approved mutation is not part of this tracer bullet and is refused safely. Command arguments execute nothing.

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
