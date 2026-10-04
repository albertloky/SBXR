# SBXR

SBXR is a root-only V3 proxy product for one Ubuntu Server. Software Lifecycle installs the `sbxr` executable and retains recovery for existing durable transactions. Proxy Installation owns the installed proxy journey through a review-first numbered menu.

The source implements setup and removal, subscription enablement and link
rotation, Client Identity rotation, and recovery. Newly enabled subscriptions use HTTP. The current release direction is clean installation only; existing installations use their exact release for reviewed removal and removal recovery.
Implementation and automated tests do not establish release acceptance. Use
[ADR-0016](docs/adr/0016-v3-proxy-product-and-modules.md) for the product contract
and the [current HTTP live acceptance procedure](docs/acceptance/http-subscription-live.md)
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

This command selects the published Latest, not unpublished checkout changes. The command supports only the fixed host contract above. It authenticates and verifies the complete candidate before it changes either owned path. A current valid installation is a no-op. A higher-sequence local installation is not downgraded. A proved historical full-product executable from `v1.0.0` through `v1.0.15` is refused unchanged.

## Numbered menu

Run the installed product with no arguments:

```sh
sudo sbxr
```

Every screen shows fresh proxy, subscription, and Software Lifecycle status.
The same menu lists legal Proxy Installation Actions plus `Check`, `Update`, and
`Recover`. Update is unsupported in this clean-install-only product and refuses
without replacement. Recover retains proved transaction recovery; it does not
start legacy transport migration. Only `y` approves a supported action's effects.
Empty input or `n` cancels. Changed facts require a fresh review.

## Subscription transport

New subscriptions use `http://<recorded IPv4>:8443/s/<token>`. They need provider
TCP 8443 access and create no Let's Encrypt certificate, Certbot dependency or
TCP 80 challenge rule. Token authentication and protected local files remain.
HTTP exposes the link and downloaded proxy credentials to interception and
permits tampering; the confirmation plan discloses this risk. The VLESS/REALITY
proxy on TCP 443 and software signature/attestation checks remain unchanged.

Automatic legacy HTTPS migration is disabled. Historical HTTPS repair and
cleanup authority remain available to their exact-release recovery paths; they
are not incoming-upgrade support. See [ADR-0028](docs/adr/0028-clean-install-only.md).

## Clean installation and recovery

Release support is `subscription-clean-install-only`, with an explicit empty
incoming source list. To replace an existing installation, use that release's
reviewed Complete removal, finish an interrupted removal through its exact-release
route, then install and set up fresh. This entails downtime, new proxy credentials
and new client setup. The installer refuses remaining authority or resources and
retains exact removal-finisher restoration. An already absent host needs no old
source installation or removal.

There is no background software updater. Explicit Update refuses in the current
product. Existing transaction rollback/forward completion, installation recovery,
proxy/subscription operation recovery and Complete removal keep their original
proved directions. Local regression tests do not establish a live release.

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

The current scope uses `mvp-http-live-v1`: `mvp-install`, `mvp-subscription`,
`mvp-credentials`, `mvp-serving`, and `mvp-removal`, in that order. See the
[HTTP live procedure](docs/acceptance/http-subscription-live.md). It requires no
source setup, source update/recovery journey or subscription certificate issuance.
Applicable recovery regressions remain ordinary tests. Historical repair and
HTTPS/recurring policies retain their original interpretation.

Before recommending Latest, prove refusal by the unchanged old updater and the
installer over existing state. Without that proof, keep the candidate non-Latest;
passing the five journeys alone cannot establish update compatibility.

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
