# SBXR

SBXR is a root-only V3 proxy product for one Ubuntu Server. Software Lifecycle installs and updates the `sbxr` executable. Proxy Installation owns the installed proxy journey through a review-first numbered menu.

The source implements setup and removal, subscription enablement and link
rotation, Client Identity rotation, managed renewal recording, and recovery.
Implementation and automated tests do not establish release acceptance. Use
[ADR-0016](docs/adr/0016-v3-proxy-product-and-modules.md) for the product contract
and the [current MVP live acceptance procedure](docs/acceptance/mvp-live-acceptance.md)
for live qualification.

For development, start with the [code map](docs/agents/code-map.md). It links
entry points, owning modules, tests, and the release harness. Domain terms are
defined in [CONTEXT.md](CONTEXT.md). The [documentation index](docs/README.md)
separates the current MVP procedure from historical acceptance material and
research notes.

## Supported system

- Ubuntu Server 24.04; the first V3 proxy journey accepts only `amd64`
- Root authority through `sudo`
- An interactive UTF-8 terminal
- `curl` for the first GitHub HTTPS download

Software Lifecycle owns `/usr/local/bin/sbxr` and `/var/lib/sbxr/installed.json`.
Confirmed V3 setup creates the Proxy Installation resources recorded in
`/var/lib/sbxr/proxy-ownership.json`; reviewed Complete removal uses that authority
to remove the installation. See the [Proxy Installation guide](internal/proxyinstallation/README.md)
for setup, subscription, identity, and removal responsibilities.

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

Stable publication requires native automated proof on both architectures and
the live packaged Ubuntu Server 24.04 `amd64` journeys for the candidate's
declared scope, including required outside-network and actual Karing evidence.
Each Release Identity gets its own public Acceptance Record.

The current clean-install MVP scope is
[`mvp-live-v1`](docs/adr/0023-mvp-live-acceptance.md):
[`mvp-install`](docs/acceptance/mvp-live-acceptance.md), `mvp-subscription`,
`mvp-credentials`, `mvp-renewal`, and `mvp-removal`. Use the [MVP live
acceptance procedure](docs/acceptance/mvp-live-acceptance.md). It retains normal
artifact trust, outside traffic, trusted HTTPS, and Karing import/refresh. It
does not establish incoming-upgrade behavior, natural timer firing, or naturally
due client auto-refresh.

The former [V4 operator producer](https://github.com/albertloky/SBXR/tree/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator),
its [25-scenario procedure](docs/acceptance/historical/v4-operator-procedures.md), and its
evidence guides are historical for their named attempts. The producer is retired
from the working tree; historical Go readers and validators remain so existing
records retain their meaning. Dated reports in [docs/acceptance](docs/acceptance)
describe individual attempts. The [Installer-Updater release-pair procedure](docs/acceptance/historical/installer-updater-release.md)
is also historical.

`v3.1.0` / Release Sequence `83` has an
[Owner-approved exception](docs/adr/0017-one-release-owner-exception.md) with
incomplete live VPS and Karing qualification. It applies only to that release.

`v3.1.81` / Release Sequence `159` was
[published stable on 2026-09-25](docs/acceptance/reports/v3.1.81-stable-publication-2026-09-25.md).
Its [separate bounded exception](docs/adr/0024-r24-late-confirmation-supplement.md)
reuses prior v3.1.80 live evidence and late Owner confirmation; no fresh live run
was performed. The failed v3.1.80 qualification remains burned.

## Historical full-product releases

Releases `v1.0.0` through `v1.0.15` remain public, immutable, unsupported history. Their final source is preserved by annotated tag `archive/full-product-v1.0.15` at commit `14fdf0a3decb6c653f9669438bf40221813b9d7d`. They are not installation, update, migration, recovery, compatibility, or qualification inputs for the Installer-Updater.
