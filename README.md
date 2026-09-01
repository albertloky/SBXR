# SBXR

SBXR is a root-only V3 proxy product for one Ubuntu Server. Software Lifecycle installs and updates the `sbxr` executable. Proxy Installation owns the installed proxy journey through a review-first numbered menu.

> Authority: [ADR-0016](docs/adr/0016-v3-proxy-product-and-modules.md) extends the V3 contract for [#342](https://github.com/albertloky/SBXR/issues/342). This is an accepted implementation contract, not a claim that subscription or Client Identity rotation is shipped. The tracer-bullet menu description and Installer-Updater release-pair procedure below are historical snapshots; use ADR-0016 for current boundaries, recurring qualification requirements, and the approved first-subscription clean-install policy.

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

Every screen shows fresh proxy, subscription, and Software Lifecycle status.
The same menu lists legal Proxy Installation Actions plus `Check`, `Update`, and
`Recover`. Numbers follow the currently legal proxy Actions. `Update` shows the
exact target; `Recover` shows the proved direction. Only `y` approves effects.
Empty input or `n` cancels. Changed facts require a fresh review.

## Update and recovery safety

The first subscription release supports clean installation only. No incoming
update from `v3.0.21` or earlier is supported. Use the old release's reviewed
Complete removal, finish an interrupted removal through its exact-release route,
then install and set up fresh. Expect downtime, new proxy credentials, and new
client setup. Installation refuses remaining authority or resources.

Future recurring updates require explicit qualified source support. They preserve
Ownership Record bytes, creating provenance, proxy configuration, and both
credentials. Before `Committed`, recovery restores the exact prior release.
After `Committed`, it retains the candidate and finishes Subscription Serving
runtime verification before clearing the Update Record. It does not restart
sing-box. See [Software Lifecycle](internal/softwarelifecycle/README.md) for the
versioned support and transaction contracts.

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
