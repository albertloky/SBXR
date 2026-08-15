# SBXR

SBXR is a single-owner terminal application for installing and managing a six-profile proxy service on an Ubuntu VPS. It brings installation, Client Access, Cloudflare Tunnel, certificates, subscriptions, health checks, updates, recovery, and Complete removal into one Owner Console.

> [!IMPORTANT]
> The ordinary install command selects only the newest qualified stable release. Release `v1.0.6` is the current predecessor release. It cannot update to the root-runtime design in ADR-0010. A root-runtime release becomes stable only after its exact public bytes pass the package qualification policy.

## Supported system

- Ubuntu 24.04 on `amd64` or `arm64`
- `curl` available for the first GitHub HTTPS download
- An interactive SSH terminal
- At least `80×24`; `120×36` adds a details column
- Root access, either directly or through ordinary `sudo`

Run the Pasteable Install Command as root or as a sudo-authorized non-root account. Root starts the complete Owner Console directly. A non-root Owner Launch Identity authenticates before SBXR shows a Console screen. The complete Owner Console then runs as root.

## Pasteable Install Command

The ordinary command follows only GitHub's stable release selection:

```bash
bash <(curl -fsSL https://github.com/albertloky/SBXR/releases/latest/download/install.sh)
```

To select the current predecessor release exactly, use:

```bash
bash <(curl -fsSL https://github.com/albertloky/SBXR/releases/download/v1.0.6/install.sh) --tag v1.0.6
```

The first `install.sh` download is trusted through GitHub HTTPS. The release-specific script accepts only Ubuntu Server 24.04 on `amd64` or `arm64` in a real interactive terminal. It updates APT metadata and installs or repairs only `ca-certificates`, `curl`, `iproute2`, `nftables`, `iptables`, `sudo`, and their required Ubuntu foundation. It then either proves and re-enters the exact installed root-owned release or verifies the exact release index, selected archive, embedded executable identity, architecture, and digests in a fresh Owner-only temporary directory. Root starts the complete Owner Console directly. A non-root Owner Launch Identity authenticates before the same complete root Owner Console starts. Temporary material is removed after it exits. The script never receives Cloudflare authority, upgrades the host, performs unrelated package cleanup, or performs Destructive Reclamation. The root Owner Console admits a Clean VPS without destructive confirmation. For a Reclaimable VPS, it shows the complete exact effects and requires `RECLAIM THIS VPS` before it freshly rechecks the same Plan and starts one durable Change Set.

## Destructive reclamation and recovery

Before **Irreversible reclamation started**, Back and Cancel remain available and SBXR can roll back its reversible preparation. After that durable checkpoint, rollback and cancellation are unavailable. A command failure, lost SSH session, process death, or VPS reboot enters **Recovery Required** and continues the exact recorded operation forward from its last proven checkpoint when SBXR starts again.

Complete removal deletes only SBXR-owned resources and package holds. It does not restore software, identities, Docker, firewall policy, or Cloudflare resources that the Owner approved for permanent reclamation. Complete removal succeeds only after SBXR proves **Not installed** with no retained SBXR recovery material.

## User commands

The installed executable is `/usr/local/bin/sbxr` and is normally available as `sbxr`.

| Command | Purpose |
|---|---|
| `sbxr` | Open the Owner Console. On a clean VPS it starts installation review; on an installed VPS it opens the Managed dashboard or exact recovery view. |
| `sbxr version` | Print the embedded release identity in a short human-readable form. |
| `sbxr version --json` | Print the embedded repository, tag, commit, architecture, payload SHA-256, and State schema as JSON. |

There is no public `--help` command and no other public command mode. Unknown arguments do not create extra management authority.

If a forced termination, VPS power loss, or broken SSH client leaves the terminal display damaged, restore the terminal with:

```sh
reset
```

Closing the Owner Console does not stop the proxy services or cancel an active Change Set. Use the cancellation action shown by SBXR when cancellation is available.

## Owner Console areas

The Managed dashboard contains:

- Overview
- Access
- Connection Profiles
- Cloudflare Tunnel
- Certificates
- Subscription
- Network
- Services and diagnostics
- Updates
- Security
- Complete removal
- Exit SBXR

Access values appear only after the launch privacy choice and successful system authentication. Denying or cancelling authentication opens a limited read-only dashboard instead.

## TUI controls

The two footer lines inside SBXR always show the controls valid for the current screen. These are the complete controls used by the Owner Console.

### Global controls

| Key | Action |
|---|---|
| `Up` / `Down` | Move through navigation, profiles, values, or actions. |
| `Tab` / `Shift+Tab` | Move forward or backward between navigation, actions, and input fields. |
| `Left` / `Right` | Change the selected choice or profile action when a screen offers choices. |
| `Enter` / `Space` | Open, select, continue, copy, review, or apply the visibly selected action. |
| `Esc` | Go back. On a multi-section review, it first returns to the previous section. |
| `Ctrl+C` | Open the visible Exit SBXR confirmation. It does not immediately exit. |
| `Enter` / `Space` in exit confirmation | Exit SBXR. |
| `Esc` in exit confirmation | Stay in SBXR. |

`Q` is never an exit key. In an input field, `q` is ordinary input data.

### Input and paste

| Key or action | Result |
|---|---|
| Type normally | Add text to the focused field. |
| Paste | Add the pasted text as data; pasted control-like content is not executed as a TUI command. |
| `Backspace` | Delete the last character. |
| `Tab` / `Shift+Tab` | Leave the input field and return to actions or navigation. |
| `Esc` | Leave the current input or screen without approving a change. |

Input is limited to 1,024 characters. When the terminal becomes smaller than `80×24`, SBXR pauses drawing and activation while preserving the current input, selection, and review. Enlarge the terminal to continue.

### Context-specific controls

| Screen | Controls |
|---|---|
| Safe-editing field | `Enter` submits the field. `Space` adds data. `Tab` moves to **Review updated request**, **Help for this field**, and **Back** when typed Help is available. Help gives the purpose, instructions, accepted format, common mistakes, recovery, a marked synthetic example, official source, and sensitivity. `Esc` closes Help without changing the input. |
| Privacy choice or limited dashboard | `Up` / `Down` or `Tab` / `Shift+Tab` chooses; `Enter` / `Space` continues. |
| Plan or multi-section review | `Enter` / `Space` advances to the next section and eventually selects the visible Apply action; `Esc` returns one section or goes back. |
| Correction flow | `Up` / `Down` chooses the action, `Left` / `Right` chooses an offered value, `Tab` focuses input, and `R` runs **Check again**. |
| Active cancellable Change Set | `C` requests cancellation. SBXR waits for the next safe checkpoint; it does not kill an unsafe step halfway through. |
| Access values | `Up` / `Down` chooses a value; `Enter` / `Space` copies it; a left mouse click on the visible selected value performs the same explicit copy action; `Tab` returns to navigation. |
| Connection Profiles | `Up` / `Down` chooses a profile, `Left` / `Right` chooses its action, and `Enter` / `Space` selects it. |
| Subscription, certificates, diagnostics, updates, and recovery | `Up` / `Down` chooses an action; `Enter` / `Space` selects it; `Esc` returns to Overview. |
| Cloudflare token field | Type or paste the token, `Tab` returns to actions, and `Shift+Tab` returns from actions to the token field. The complete token is masked and must not be copied into evidence. |
| Live Profile Check | `Esc` stops the session-only check and returns to Subscription. |
| Complete removal | Type exactly `COMPLETE REMOVAL`, use `Tab` to return to actions, then separately select **Permanently remove SBXR**. Before the irreversible checkpoint, Back and Cancel remain available. After it, neither Back nor Cancel is available. |

## Internal system commands

The executable also contains these fixed `private` modes:

```text
sbxr private health-check
sbxr private update-check
sbxr private install-apply
sbxr private client-access
sbxr private recover
sbxr private subscription-serve
sbxr private certificate-renewal
```

These are not Owner commands. They are called only by SBXR's installed systemd units or its verified root execution paths. Do not run them manually to install, repair, force recovery, or bypass the Owner Console.

## Release-maintainer commands

These repository commands build and verify immutable release material. They are not VPS management commands.

Generate the release-specific `install.sh` before building the index:

```sh
go run ./cmd/sbxr-release bootstrap \
  -version <version> \
  -sequence <sequence> \
  -tag <tag> \
  -commit <commit> \
  -output <install.sh>
```

Build one application archive and its matching component archive from a clean exact commit using Go `1.26.5`:

```sh
go run ./cmd/sbxr-release \
  -tag <tag> \
  -commit <commit> \
  -architecture <amd64|arm64> \
  -output <application-archive> \
  -component-output <component-archive>
```

Build `release-index.json` from a directory containing exactly `install.sh` and the four fixed application and component archives:

```sh
go run ./cmd/sbxr-release index \
  -version <version> \
  -sequence <sequence> \
  -tag <tag> \
  -commit <commit> \
  -directory <asset-directory> \
  -output <release-index.json>
```

Verify and safely stage both architectures of an immutable GitHub candidate:

```sh
go run ./cmd/sbxr-release verify -tag <tag>
```

The production release workflow is [`.github/workflows/candidate.yml`](.github/workflows/candidate.yml). Release-maintainer commands fail closed; they do not provide a force or continue-anyway option.

## Development checks

```sh
go list ./... | grep -v '/internal/ownerconsole$' | xargs go test -count=1
go test ./internal/ownerconsole -count=1
go list ./... | grep -v '/internal/ownerconsole$' | xargs go test -race -p 1 -count=1
go vet ./...
```

The full acceptance procedures and current evidence boundaries are documented in [`acceptance/RELEASE.md`](acceptance/RELEASE.md).
