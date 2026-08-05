# SBXR v1 specification

## Status and authority

This is the implementation-ready source of truth for SBXR v1. It records the current result of the [Specify SBXR v1](https://github.com/albertloky/SBXR/issues/1) Wayfinder. Linked issues explain why decisions were made, but an implementation agent must be able to build SBXR from this document without reading those conversations.

`CONTEXT.md` defines the canonical domain language. The words **must**, **must not**, **required**, **may**, and **optional** are normative. When an older planning document or issue comment conflicts with this document, this document controls unless a later approved decision explicitly supersedes it.

## 1. Scope and fixed rules

### 1.1 Product boundary

SBXR manages exactly:

- one Owner;
- one Clean Ubuntu Server 24.04 VPS;
- one `sbxr` management executable;
- two proxy cores, Xray and sing-box, running concurrently;
- six named Connection Profiles;
- one named Cloudflare Tunnel;
- one IP-based HTTPS subscription service and one subscription token;
- one typed Desired State;
- one GitHub Release update path; and
- transaction rollback for unfinished Change Sets.

Initial installation targets a Clean VPS. Later updates, migrations, health checks, repairs, rotations, certificate renewal, and Complete removal operate only on the same SBXR-managed VPS when its Desired State lineage is proven.

SBXR v1 does not include multi-user accounts, roles, quotas, billing, invitations, groups, a web management panel, multiple VPS hosts, another operating system, import of unrelated proxy installations, extra Connection Profiles, durable backup, historical restore, restoration of old credentials, recovery onto another VPS, or recovery from missing or corrupt Desired State.

### 1.2 Implementation and release stack

- Use pinned Go and produce pure-Go (`CGO_ENABLED=0`) executables for `linux/amd64` and `linux/arm64`.
- Ship one immutable archive per architecture. Each archive contains one `sbxr` executable with its schemas, migrations, systemd templates, and Release Identity embedded.
- `sbxr` opens the Owner Console by default, contains private modes for services, timers, and recovery, and exposes `sbxr version` for diagnostics.
- Use the Go standard library by default. Pre-approved dependency categories are Bubble Tea v2, Lip Gloss v2, necessary Bubbles controls, one maintained YAML library, and one reviewed QR library.
- Do not add containers, a database, ORM, dynamic plugins, a multilingual framework, or general CLI, configuration, HTTP, logging, dependency-injection, or test frameworks unless a later approved ticket proves the existing choices insufficient.

The initial researched core baselines are Xray `v26.3.27`, sing-box `v1.13.16` with AnyTLS requiring at least `v1.12.0`, and cloudflared `2026.7.3`. A Release Qualification must pin and requalify the exact versions it ships rather than assuming these remain current.

### 1.3 Installed processes

Normal Managed operation contains:

```text
xray.service
sing-box.service
cloudflared.service
sbxr-subscription.service

sbxr-cert-renew.service
sbxr-cert-renew.timer
sbxr-update-check.service
sbxr-update-check.timer
sbxr-health-check.service
sbxr-health-check.timer
```

Timers are schedulers, not continuously running services. Private modes and timers call the same Module Interfaces as the Owner Console and never contain separate product behavior.

### 1.4 Installation and health states

The installation status is exactly:

- **Not installed** — no active installation and no retained SBXR recovery material.
- **Managed** — Desired State lineage is proven and no Change Set is unfinished. Individual Module health may still be imperfect.
- **Change in progress** — one approved Change Set holds the global mutation lock.
- **Recovery Required** — SBXR cannot prove current Desired State lineage or the safe resolution of an unfinished Change Set; ordinary mutations are blocked.

A Module Health Result is separately exactly **Healthy**, **Needs attention**, **Failed**, or **Unknown**.

### 1.5 Default network registry

| Purpose | Default |
|---|---|
| Detected SSH listener | detected port/TCP |
| ACME HTTP-01 validation | `80/TCP`, temporary only |
| VLESS REALITY Vision | `443/TCP` |
| Hysteria2 | `443/UDP` |
| TUIC | `8443/UDP` |
| AnyTLS | `9443/TCP` |
| Subscription HTTPS | `10443/TCP` |
| VLESS XHTTP origin | `127.0.0.1:11080/TCP`, never public |
| VLESS WebSocket origin | `127.0.0.1:11081/TCP`, never public |

TCP and UDP ownership are independent, so `443/TCP` and `443/UDP` may coexist. The SSH port and temporary `80/TCP` purpose never move. A configurable occupied default receives a reviewed random available alternative; a committed selection remains stable until another reviewed Change Set changes it.

## 2. System-wide safety rules

### 2.1 Privilege and process isolation

- Owner Console runs non-root. It requests the normal system sudo prompt only when an approved operation needs privilege.
- Denied, cancelled, or expired sudo authentication opens a limited read-only dashboard without Client Access Values or privileged actions.
- Privileged work is short-lived, revision-bound, and accepts typed validated requests only. There is no arbitrary command, path, file reader, or service-control Interface.
- Xray, sing-box, cloudflared, and Subscription Serving use separate non-root identities and may read only their prepared files.
- Xray and sing-box receive only `CAP_NET_BIND_SERVICE` when a selected port below 1024 requires it.
- Root-only directories and files use `0700` and `0600`. Root-owned service-readable directories and files use `0750` and `0640` with the owning service group.
- Symbolic links, wrong ownership, unsafe permissions, unexpected files, privilege widening, and bypass controls are rejected.

### 2.2 Secret boundary

Each owning Module defines, validates, rotates, and replaces its secrets. State stores typed values without interpreting their meaning.

The authenticated Owner Console may deliberately display Client Access Values. Infrastructure Secrets must not be displayed. Only the dedicated Cloudflare credential screen may show the first and last four characters of the management token or Tunnel run token.

Certificate private keys, REALITY private keys, ACME account material, complete Cloudflare credentials, authorization headers, generated configurations, recovery-journal contents, and Rollback Snapshot contents are never revealable or included in diagnostic output.

Secrets must not enter command arguments, environment variables, events, support bundles, raw external-tool output, telemetry, automatic uploads, proxy access logs, traffic history, crash reports, or core dumps. Cloudflared uses a root-owned token file.

### 2.3 Plan, Apply, and Change Set

Every consequential action uses review-first `Plan` then `Apply` behavior:

1. `Plan` returns an exact secret-safe preview bound to the current Desired State revision, relevant checksums, verified inputs, and Observed State.
2. The Owner may approve that exact one-use Plan or go Back. Approval does not authorize another target or a changed Plan.
3. `Apply` rejects a stale or reused Plan and reruns volatile and privileged facts before the first mutation.
4. One Change Set contains the candidate Desired State commit, prepared managed changes, health gates, and rollback instructions.
5. System Changes applies the Change Set under one global kernel file lock.

Read-only operations do not create a Plan, Change Set, or Rollback Snapshot.

### 2.4 Transaction journal and rollback

Before the first live step, System Changes creates and verifies one root-only transaction-scoped Rollback Snapshot. For installation it records the proven Not installed baseline and SBXR-owned additions. For Managed work it contains only the prior Desired State bytes, affected managed files and settings, required evidence, and the prior verified executable when software changes.

The recovery journal durably records:

1. `Prepared`;
2. `Step started` and `Step completed` for each live step;
3. `Pre-publication health passed`;
4. `Desired State publication started`;
5. `Desired State published` after atomic replacement and readback;
6. `Post-publication health passed`; and
7. `Complete`.

Rollback records `Rollback started`, paired rollback-step checkpoints, `Rollback verified`, and `Rolled back`. Cancellation after mutation records `Cancellation requested`, waits for a safe checkpoint, and performs complete rollback. It never kills a step in an unsafe middle state.

A successful revision exists only after post-publication gates and durable `Complete`. After `Complete`, the Rollback Snapshot and completed journal are deleted. Restart during that cleanup completes cleanup and does not roll back.

### 2.5 Restart and Recovery Required

A private recovery mode runs before affected public services and timers. It acquires the kernel file lock, validates Desired State, journal, Rollback Snapshot, and active-resource lineage, and automatically rolls back the unfinished Change Set already authorized by the original Plan.

The lock is the kernel lock, not a PID or timeout convention. SBXR never steals a held lock. If the process dies, the released lock plus an unfinished journal routes to recovery mode.

If rollback cannot be proved, or committed Desired State lineage is missing, corrupt, contradictory, or manually altered, SBXR enters Recovery Required. With valid unfinished transaction material it may offer `Retry automatic rollback`. Otherwise it offers safe evidence, read-only diagnostics, `Check again`, and separately confirmed Complete removal. It never adopts discovered files, bypasses the journal, force-unlocks, starts uncertain services, or pretends to restore an older revision.

### 2.6 Health gates and Correction Flows

Each check is **Required** or **Advisory**.

- Every Required check must be Healthy.
- Required Needs attention, Failed, or Unknown stops before mutation or triggers rollback after mutation.
- Advisory Needs attention may pass only when disclosed in the Plan.
- Advisory Failed or Unknown never passes.
- There is no `Continue anyway` control.

Every blockage opens a Correction Flow showing **Problem**, exact **Found**, exact **Required**, **Why SBXR stopped**, a separately reviewable SBXR correction Plan when safe, an exact Owner checklist otherwise, `Check again`, `Back`, and copyable redacted evidence. Recheck repeats the affected check and then the complete relevant preflight. No failure becomes a dead-end page.

### 2.7 Bounded waits

- Deterministic local failures stop immediately.
- Temporary DNS, HTTPS, GitHub, or Cloudflare API failures receive at most three attempts within `60 seconds`.
- Cloudflare zone activation uses a separate `10-minute` pre-install wait and may offer another explicit `10-minute` wait.
- Approved Cloudflare DNS, Tunnel, and route changes receive up to `5 minutes` for authoritative and connected health.
- Local service startup and listener checks receive up to `60 seconds`.
- ACME uses a bounded Certificate Lifecycle timeout.
- Certificate renewal follows its approved due and retry rules.

No background action retries forever. Reaching a Required post-mutation limit triggers rollback.

### 2.8 Fixed resource rules

A Clean VPS must provide Ubuntu Server `24.04.x`, `systemd`, `linux/amd64` or `linux/arm64`, at least one logical CPU, at least `512 MiB` physical RAM, and at least one usable public IPv4 or IPv6 address. `1 GiB` RAM is recommended; swap does not count as physical RAM. Virtualization brand is not a gate when required capabilities pass.

Before mutation, SBXR reserves preparation, temporary-copy, Rollback Snapshot, journal-growth, rollback, and filesystem-overhead space. After reservation, the larger of `1 GiB` or `10%` of the SBXR filesystem must remain free. This limit is not configurable. SBXR may remove only its own incomplete temporary files that are already safe to delete.

The VPS wall clock must be plausibly synchronized before installation or mutation. Durations use a monotonic clock. On a Clean VPS only, SBXR may offer a reviewed `systemd-timesyncd` correction when no competing time owner exists.

## 3. Architecture and repository

### 3.1 Deep Modules

SBXR has exactly eleven deep Modules:

| Module | Ownership | External Interface |
|---|---|---|
| Owner Console | TUI navigation, input, review, confirmation, and presentation | `Run` |
| Connection Profiles | Six profiles, credentials, ports, and Xray/sing-box configurations | `View`, `Plan`, `Apply` |
| Subscription Publication | Token semantics, client representations, exports, and atomic artifact publication | `View`, `Render`, `Plan`, `Apply` |
| Subscription Serving | Public authenticated HTTPS delivery of published artifacts | `Serve` |
| Certificate Lifecycle | IP/domain certificate issuance, renewal, validation, activation, and rollback inputs | `View`, `Plan`, `Apply` |
| Cloudflare Tunnel | Scoped token, named Tunnel, DNS records, routes, local-only mappings, and health | `View`, `Plan`, `Apply` |
| Software Lifecycle | Installation, project/core updates, downgrade control, and Complete removal | `View`, `Plan`, `Apply` |
| Health and Diagnostics | Module health, redacted events, scheduled checks, and support bundles | `Check`, `BuildSupportBundle` |
| Network Policy | Ports, address families, exposure, routing, outbound requirements, nftables, and SSH safety | `Evaluate` |
| State | Typed Desired State, validation, migrations, revisions, and persistence | `Load`, `PrepareCommit` |
| System Changes | Mutation lock, Rollback Snapshot, journal, host changes, health gates, and automatic rollback | `Inspect`, `Apply` |

Interface names are conceptual. Each Module owns its exact request and result types. Do not create a generic framework merely because several Interfaces have similar method names.

### 3.2 Dependency rules

Production dependencies flow one way:

```text
cmd/sbxr
    ↓
Owner Console or a private operating mode
    ↓
Module owning the requested Owner outcome
    ↓
Network Policy, State, and System Changes
```

- The Module owning an Owner action coordinates participating Modules with typed inputs and results.
- Network Policy, State, and System Changes never call upward.
- Subscription Serving calls no other SBXR Module and cannot access State or Connection Profiles.
- Services, timers, and Owner Console never mutate the VPS directly.
- Circular dependencies are forbidden.
- Exact Module connections remain forbidden until the design requires and registers them.
- Failures cross Interfaces only as typed secret-safe results saying that nothing changed, rollback succeeded, or Recovery Required was entered.

A root architecture test is the canonical registry of the eleven Modules and permitted imports. It uses Go package information and denies unregistered product packages, generic layers, and Module-to-Module connections.

### 3.3 Real Seams and Adapters

Adapters exist only where behavior genuinely varies:

- Ubuntu host: production Adapter and in-memory test Adapter;
- Desired State storage: permission-controlled file Adapter and in-memory Adapter;
- Cloudflare: production Adapter and deterministic fake;
- release source: verified GitHub Release Adapter and local verified fixtures;
- certificate issuer: Certbot/ACME Adapter and deterministic fake; and
- time and randomness: secure system values and controlled test values.

Everything else uses direct Go calls. Do not wrap each file, command, standard-library package, or dependency. Do not add an Interface with only one meaningful Adapter.

### 3.4 Repository layout and locality

```text
go.mod
dependencies_test.go

cmd/
└── sbxr/                       # startup and wiring only

internal/
├── ownerconsole/
├── connectionprofiles/
├── subscriptionpublication/
├── subscriptionserving/
├── certificatelifecycle/
├── cloudflaretunnel/
├── softwarelifecycle/
├── healthdiagnostics/
├── networkpolicy/
├── state/
└── systemchanges/

acceptance/
└── RELEASE.md

docs/
└── adr/
```

Each Module directory is one Go package. Its Interface, request/result types, hidden Implementation, Interface-first tests, package documentation, Module acceptance instructions, and meaning-owned schemas, migrations, templates, fixtures, or embedded assets stay together. A child `adapter/<real-integration>/` package exists only for a real external Seam.

Do not create separate `interface`, `implementation`, `types`, `models`, `common`, `shared`, `helpers`, `utils`, `services`, central `assets`, central `templates`, central `migrations`, or central `fixtures` packages. `cmd/sbxr` selects a mode, wires Modules and Adapters, and calls an Interface; it contains no product behavior.

## 4. Module contracts

The sections below are in approved implementation order.

### 4.1 State

State owns one typed root-only JSON Desired State as the sole authority for intended configuration.

Desired State contains the last successful revision, Release Identity, six Connection Profiles and credentials, subscription settings and token, Cloudflare binding and Infrastructure Secrets, certificate identifiers and settings, Network Policy inputs, and other approved persistent settings. It contains no Observed State, live health, logs, journal, Rollback Snapshot, generated service copies, extension map, or catch-all settings.

`Load` rejects malformed JSON, duplicate keys, unknown schema versions, unsupported fields, invalid typed values, symbolic links, wrong ownership or permissions, and lineage disagreement. Each owning Module freshly observes what it owns; differences never silently become Desired State.

`PrepareCommit` accepts the exact loaded revision and a complete typed candidate, then returns an opaque one-use prepared commit without publishing it. Fresh installation begins at revision `1`. Every successful mutation advances exactly once from `N` to `N+1`; revisions never go backward.

Migrations are complete sequential Go functions embedded in the release. Each accepts one schema version and returns the next complete typed candidate in memory. There are no skipped, downloaded, plugin, partial, downgrade, or silent-drop migrations. A failure leaves Desired State and live resources unchanged.

Publication writes and flushes the candidate beside `state.json`, atomically renames it, flushes the parent directory, reads it back, and then participates in post-publication gates. Runtime services receive only their narrow prepared copies and never read Desired State directly.

### 4.2 Network Policy

Network Policy evaluates addresses, protocol-specific listeners, public versus loopback exposure, routes, outbound requirements, nftables, and SSH safety. It returns a decision; System Changes performs approved mutations.

IPv4 and IPv6 qualify independently. At least one public address must pass. Only approved address families appear in certificates, firewall rules, subscriptions, and client output. The Owner chooses the primary subscription address when both pass. Adding or removing an address later is a reviewed Change Set.

For a configurable occupied default, choose from `1024–65535` after excluding Ubuntu's actual ephemeral range, the detected SSH port, fixed `80/TCP`, every current listener, and every other SBXR selection. Prove the candidate by binding the intended protocol/address and recheck immediately before Apply.

SBXR owns one clearly named nftables table and never flushes or replaces the host ruleset. An active competing firewall manager, Docker-managed firewall, unexpected base chain, or legacy iptables rule blocks fresh installation. SBXR identifies it but never disables it automatically.

Before changing nftables, System Changes installs a root-owned automatic rollback watchdog and applies the validated candidate atomically. It proves the current SSH session remains responsive and the detected SSH port remains admitted before cancelling the watchdog. One existing SSH session does not prove future provider reachability; provider-firewall correction remains an Owner action. SBXR stores no provider credentials and has no provider Adapter.

Read-only preflight verifies the configured resolver, HTTPS to GitHub, Cloudflare, and the ACME issuer, time service, required certificate endpoints, and cloudflared outbound TCP/UDP `7844`. SBXR never disables TLS verification, substitutes HTTP, changes the resolver silently, installs a VPN, or edits the provider firewall.

### 4.3 System Changes

System Changes owns the global kernel file lock, Change Set application, transaction-scoped Rollback Snapshot, recovery journal, health-gate ordering, automatic rollback during execution and after restart, rollback proof, cleanup after Complete, and entry into Recovery Required.

It treats State material opaquely. Every other participating Module supplies prepared changes, rollback instructions, and checks. Software Lifecycle supplies the prior verified executable when an update needs rollback.

Before mutation it verifies exact ownership, permissions, absence of symbolic links, disk reservation, prepared checksums, rollback completeness, and the ordered journal. It never creates a persistent operation queue, resumes a partially applied forward change after restart, infers a stale lock, or permits automatic rollback to be cancelled.

Valid Desired State plus managed drift may be repaired forward by a new Plan. Missing or corrupt Desired State, lost secrets, a dead VPS, an older revision, or Owner regret require Complete removal and rebuilding from scratch.

### 4.4 Cloudflare Tunnel

Cloudflare Tunnel exclusively owns the scoped Cloudflare management token, selected account and zone IDs, named Tunnel, Tunnel run token, two DNS records, immutable resource IDs, published hostname routes, local-only origins, and Cloudflare health.

SBXR creates exactly one Tunnel and no Mesh node:

- `xhttp.<owned-domain>` routes to `http://127.0.0.1:11080`;
- `ws.<owned-domain>` routes to `http://127.0.0.1:11081`; and
- `direct.<owned-domain>` is DNS-only A/AAAA for qualified addresses and is not a Tunnel route.

The zone must be active, publicly delegated to Cloudflare's assigned nameservers, free of unowned conflicts at the selected hostnames, and compatible with effective CAA. When `xhttp`, `ws`, or `direct` is occupied by an unowned resource, propose an available suffix such as `xhttp-a7k3.<owned-domain>`; never adopt or overwrite it.

For a pending zone, show Cloudflare's assigned nameservers beside the publicly observed nameservers and wait automatically for up to `10 minutes` within Cloudflare's activation-check limits. If it remains pending, offer `Check again`, `Wait another 10 minutes`, and `Back and continue later` with exact registrar instructions. Installation does not enter its Change Set while the zone is pending.

The management token is bound to the selected account and zone and grants only capabilities needed to read and manage the one owned Tunnel, its run token and routes, and owned DNS records. Reject the Global API Key and unrelated-zone, billing, member, Workers, WAF, email, or other product authority. Each qualified release maps these capabilities to Cloudflare's current dashboard permission labels.

The token remains memory-only until revision `1` commits. Afterward it is root-only and reused for approved work. Replacement leaves the old token untouched until verification and Plan approval succeed. The credential screen shows status, first/last four characters, bound account/zone, last check, expiry when available, and current uses.

Ownership is proved by immutable IDs, never names. Record every newly returned ID durably before the next step. Fresh-install rollback deletes only IDs created by that Change Set. Managed work edits only IDs already in Desired State or created by its current Change Set and records exact pre-images for rollback.

### 4.5 Certificate Lifecycle

Certificate Lifecycle owns issuance, renewal, validation, activation, health facts, and rollback inputs for:

- a publicly trusted approximately 160-hour IP certificate used by Subscription Serving; and
- one publicly trusted `direct.<owned-domain>` certificate shared by Hysteria2, TUIC, and AnyTLS.

Use a currently qualified Certbot `5.4` or newer because Ubuntu 24.04 apt's historical `2.9.0` is insufficient for IP issuance. Use Let's Encrypt HTTP-01 with standalone temporary `80/TCP`; TCP `443` remains available to VLESS REALITY. The ACME client receives no Cloudflare token or permission.

For the domain certificate, Cloudflare Tunnel supplies typed DNS and CAA facts. Certificate Lifecycle validates effective CAA but creates no CAA record. HTTP-01 ignores unrelated `_acme-challenge` CNAME, NS, and TXT records. DNS-01 and account-bound CAA are outside v1.

Stage a matched chain/key pair in a versioned directory, atomically switch one serving pointer, activate the affected service in a controlled way, verify identity, chain, key match, lifetime, and every affected listener, then publish Desired State once. Failure restores the prior pointer and proves rollback without rewriting Certbot lineage.

One `sbxr-cert-renew.service` and `sbxr-cert-renew.timer` evaluate both lineages serially at least twice daily with randomized delay and `Persistent=true`, using the global mutation lock for each due Change Set. The standing Certificate Renewal Policy authorizes only the exact certificate material, temporary `80/TCP` rule, affected service activation, and corresponding revision change.

The IP branch begins renewal at `72 hours` or less remaining and ordinarily retries every `6 hours`; with less than `24 hours`, a busy lock retries within `15 minutes`, otherwise within `1 hour`. The domain branch follows ACME Renewal Information and otherwise renews with `15 days` remaining. An expired certificate makes the affected health Failed; SBXR never weakens HTTPS or serves HTTP.

### 4.6 Connection Profiles

All six Connection Profiles exist in Desired State and are enabled by default after installation. A reviewed Change Set may disable one. Disabled profiles retain settings and credentials, have no public exposure, and are omitted from subscriptions. Deliberate disablement is not a failure.

| # | Connection Profile | Core | Public connection | Required rules |
|---|---|---|---|---|
| 1 | VLESS REALITY Vision | Xray | VPS IP, `443/TCP` | VLESS, RAW/TCP, REALITY, `xtls-rprx-vision`, independent UUID/key/short ID, strict safe REALITY target, Chrome-compatible fingerprint, no insecure mode |
| 2 | VLESS XHTTP Cloudflare | Xray | `xhttp.<owned-domain>`, `443/TCP` at Cloudflare | XHTTP `packet-up`, independent UUID, origin only `127.0.0.1:11080`, Tunnel-only exposure |
| 3 | VLESS WebSocket Cloudflare | Xray | `ws.<owned-domain>`, `443/TCP` at Cloudflare | independent UUID, random 32-byte path not derived from UUID, origin only `127.0.0.1:11081`, Tunnel-only exposure |
| 4 | Hysteria2 | sing-box | VPS IP, `443/UDP`, SNI `direct.<owned-domain>` | TLS verification, independent password, HTTP/3 masquerade; optional obfuscation off by default and never described as encryption |
| 5 | TUIC | sing-box | VPS IP, `8443/UDP`, SNI `direct.<owned-domain>` | TLS verification, independent UUID/password, `zero_rtt_handshake: false`; display `TUIC` unless a client format requires `v5` |
| 6 | AnyTLS | sing-box | VPS IP, `9443/TCP`, SNI `direct.<owned-domain>` | TLS verification, independent 32-byte password, maintained padding scheme, no insecure mode |

The direct TLS profiles connect to the VPS IP while sending and verifying `direct.<owned-domain>` as SNI. VMess, Shadowsocks, Trojan, gRPC, direct XHTTP, and additional QUIC profiles are excluded.

Each profile supports view, enable/disable, credential rotation, reviewed port change where configurable, native configuration validation, safe repair, share URI, QR representation, and participation in `Rotate all` and `Revoke all client access`. Revoking all client access atomically replaces the subscription token and all profile credentials, regenerates all representations, applies core configurations, and rolls back the complete Change Set if a required step fails.

### 4.7 Subscription Publication

Subscription Publication owns the one 256-bit random subscription token, all client representation semantics, validation, export, and atomic publication under:

```text
/var/lib/sbxr/subscriptions/current/
```

All representations derive from one typed six-profile source. Missing client support is disclosed; SBXR never substitutes another profile under the missing profile's name.

| Client/format | Current representation |
|---|---|
| v2rayN | base64 URI list, 6/6 |
| Mihomo/Clash Meta | Mihomo YAML, 6/6 |
| sing-box clients | sing-box JSON, 5/6; XHTTP omitted |
| Karing | sing-box JSON or Mihomo YAML, 5/6 when using its sing-box core; XHTTP omitted |
| Shadowrocket | candidate base64 URI list; every profile remains Owner live-device qualified |
| Unknown client | conservative base64 plus an explicit representation header |

Explicit format paths are authoritative; User-Agent selection is convenience only:

```text
https://<VPS-IP>:10443/s/<token>
https://<VPS-IP>:10443/s/<token>/base64
https://<VPS-IP>:10443/s/<token>/sing-box
https://<VPS-IP>:10443/s/<token>/mihomo
https://<VPS-IP>:10443/s/<token>/raw
```

The Owner Console displays the universal link and named Shadowrocket/v2rayN, Karing, Mihomo, and sing-box links without a separate format-selection menu. Rotating only the subscription token stops future downloads but does not revoke configurations already downloaded.

### 4.8 Subscription Serving

Subscription Serving reads only validated immutable published artifacts. It never reads Desired State, profile credentials, source templates, or arbitrary files.

It listens publicly only on `10443/TCP`, requires the trusted IP certificate, uses exact token-path matching, and returns `404` for invalid tokens. It disables directory indexes and public index pages, applies rate limits, connection timeouts, and response-size limits, and returns at least:

```text
Cache-Control: private, no-store
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

It redacts the token and never logs response bodies or generated configurations. It exposes no web management interface. The Owner Console remains SSH-only.

### 4.9 Health and Diagnostics

`Check` returns an installation summary and one Health Result per checked Module. Each result contains time, Module, stable finding code, a short secret-safe explanation, and the next safe action.

An authorized privileged check may inspect protected material internally through a named owning-Module check and return only an allowlisted typed result. There is no raw log browser or arbitrary privileged inspection.

Diagnostic events may contain only time, Module, operation and Change Set identifiers, severity, stable code, secret-safe explanation, and mutation/rollback outcome. Unexpected external output is discarded and reported as Unknown.

`BuildSupportBundle` uses an explicit allowlist, a fresh root-owned `0700` staging directory, symbolic-link and unexpected-file rejection, forbidden-marker scanning, file and total size limits, and a final `0600` archive. Failure deletes staging and publishes no partial bundle.

Redacted events retain `30 days` or `50 MiB`, whichever is reached first. At most three completed bundles remain; creating another requires reviewed deletion of an existing bundle. Diagnostic retention never deletes active transaction evidence.

### 4.10 Software Lifecycle

Software Lifecycle owns fresh installation, application and core updates, downgrade control, repair coordination, and Complete removal.

Installation download, Release Identity verification, input, read-only preflight, and review remain unprivileged. The reviewed Plan names the exact release, files, services, timers, ports, nftables changes, disk use, untouched data, cancellation behavior, and rollback behavior. After approval, sudo is requested once; privileged facts and volatile inputs are rechecked before mutation.

A Clean VPS may contain ordinary non-conflicting Ubuntu software. Existing Xray, sing-box, cloudflared, SBXR remnants, active competing firewall ownership, unexpected listeners, identities, paths, DNS records, or Tunnel resources at an SBXR Seam block installation. SBXR never adopts or overwrites them.

Installation is all-or-nothing. Revision `1` publishes only after the complete local gate passes. Failure removes only resources proved to have been created by that attempt and returns to Not installed unless rollback proof fails.

GitHub Releases are immutable. Each release includes a strict `release-index.json`. Verify the release attestation with `gh release verify`, verify the index and every payload with `gh release verify-asset`, require exact equality between attested and indexed asset sets, and record repository, immutable tag, commit SHA, and index SHA-256 as the Release Identity.

Automatic discovery accepts only a higher attested sequence and may download and verify at most one newest unapplied candidate. Apply always requires Owner review. A downgrade is explicit, freshly downloaded and verified, and must pass current Desired State compatibility. The previous release exists only inside an active update Rollback Snapshot and is deleted after Complete. There is no release history or retained downgrade parcel.

Updates regenerate and validate every subscription representation and stage all work before switching. Only affected services restart or reload. Expected brief client interruption is disclosed. v1 has no blue-green ports, duplicate proxy services, connection draining, dual credentials, or unattended maintenance Apply.

Complete removal is the only uninstall action. It requires review of every removed category, exact typed text `COMPLETE REMOVAL`, and selection of `Permanently remove SBXR`. No CLI flag, ordinary Enter, single button, or pasted partial text bypasses confirmation.

Before `Irreversible removal started`, SBXR removes and verifies active exposure while rollback to Managed is still possible. After that durable checkpoint, restart continues deletion in fixed order and cancellation or rollback is impossible. SBXR first uses the active Cloudflare token to delete only the Tunnel and DNS resources proved to belong to this installation. It then gives the Owner exact dashboard steps to revoke the token, verifies that the token no longer works, and deletes the local copy. Local deletion then removes Desired State, remaining secrets, certificates, transaction material, releases, services, identities, listeners, and the owned nftables table. The removal journal and recovery runner are deleted last. Certificate Transparency records and DNS caches cannot be erased and are reported honestly.

### 4.11 Owner Console

Owner Console is one full-screen sighted terminal interface with persistent left navigation and a main work area. It uses terminal-achievable character cells, separators, foreground/background colors, bold, and reverse-video selection. `80×24` is the minimum. Larger terminals keep navigation stable and may add a second details/evidence/activity column.

Use the terminal's existing background. Detect capability instead of allowlisting terminal names. Degrade through true color, 256 colors, 16 colors, and monochrome; honor `NO_COLOR`; never use color alone. Provide ASCII fallbacks when Unicode is unreliable. Screen-reader support, Accessible Mode, `sbxr --accessible`, and noninteractive Client Access Value output are outside v1.

Every action is keyboard-operable. Arrow keys navigate, `Tab` and `Shift+Tab` move controls, `Enter` or `Space` activates, and `Esc` goes Back. Mouse support is optional. `Q` and `q` never exit. `Ctrl+C` opens the same visible Exit SBXR confirmation. Pasted text is always input data and never an application shortcut.

Show contextual shortcuts on every screen, including waiting screens. Use a measured bar only when total progress is known, a spinner plus elapsed time when duration is unknown, and an animated current step plus a measured bar when that step has real measurements. Never invent a percentage.

On every launch, before sudo or any Client Access Value, warn that values may remain in terminal scrollback, screenshots, recordings, SSH logs, clipboard history, or synchronized clipboards. Offer: continue with Client Access Values, open the limited read-only dashboard, or exit.

Authenticated Client Access Values, share URIs, QR codes, and the subscription URL live in a dedicated `Access` menu. Infrastructure Secrets are absent. Copying is an explicit click or Enter action on an underlined value. Report confirmed success honestly; when confirmation is unavailable, say the request was sent and manual selection may be needed. Never promise to clear clipboard history.

If resized below `80×24`, pause drawing, preserve input/selection/state, show required/current size, and allow exit. Long text wraps. A QR code may be omitted when it cannot fit if the same value remains available as text or export.

Before Change Set approval, disconnect discards uncommitted input and starts no mutation. After approval, closing the TUI, SSH loss, or Ctrl+C does not cancel privileged work. The next launch shows the proven result or Recovery Required. Restore terminal state on every manageable exit; document `reset` for forced termination that prevents restoration.

The navigation covers Overview, Access, six Connection Profiles, Cloudflare, Certificates, Subscription, Network, Services and diagnostics, Updates, Security, and Complete removal. It presents only actions allowed by the current lifecycle state. Correction Flows, cancellation, rollback, recovery evidence, and forward-only removal must match the system rules in section 2.

## 5. End-to-end Owner journeys

### 5.1 Fresh installation

1. The Owner runs the one pasteable installation command.
2. SBXR downloads and verifies the exact release without privilege.
3. It performs unprivileged preflight and shows the current Cloudflare token walkthrough.
4. The Owner enters the scoped token in a masked control; SBXR verifies account, zone, required reads, DNS/Tunnel prerequisites, and token scope without storing it.
5. SBXR gathers non-secret choices, qualifies IPv4/IPv6 separately, checks ports and host conflicts, and builds a complete secret-safe Plan.
6. The Owner reviews the Release Identity, all six profiles, services, timers, files, ports, firewall, Cloudflare resources, certificate work, disk use, cancellation, rollback, and untouched data.
7. Enter approves once; Esc goes Back. The system sudo prompt appears only now.
8. Privileged and volatile facts are rechecked. A changed fact discards the Plan and returns to review.
9. System Changes applies the all-or-nothing Change Set, certificates, Tunnel, profiles, subscription artifacts/service, nftables, services, and timers.
10. Revision `1` publishes last, required gates pass, Complete is durable, and temporary rollback material is deleted.
11. The Owner Console opens in Managed state. Real client-device checks do not keep installation open.

An Installation draft may retain only allowlisted non-secret choices in an Owner-readable `0600` file. Uncommitted secrets remain memory-only and disappear on abandonment, TUI close, SSH loss, restart, session expiry, failed installation, or rollback.

### 5.2 Daily use and changes

The Owner types `sbxr`. Read-only views run directly. A credential rotation, port change, profile enable/disable, Cloudflare replacement, repair, or setting change creates a new Plan from fresh observations. After approval, exactly one Change Set either advances the revision once or restores the prior proven revision.

### 5.3 Optional Live Profile Check

After Managed, the Owner or Codex may start one optional Live Profile Check. It imports the universal subscription once, presents one temporary test URL/QR, and advances automatically as outside authenticated uplink and downlink traffic is attributed to each Connection Profile. Karing may cover its supported five profiles; XHTTP requires a compatible client such as v2rayN or a Codex Acceptance Client.

Evidence is session-only and memory-only. No test token, counter difference, client IP, destination, access log, event, bundle field, or traffic history is retained. The check never keeps installation or another Change Set open.

### 5.4 Updates

The update timer may discover, download, and verify a higher immutable release but cannot Apply, migrate, restart, or mutate. The Owner reviews the exact release and migration effects. Apply runs the full local gate and normal Change Set. Any code, migration, template, embedded tool, index, or payload change creates a new Release Identity and resets integrated/live acceptance.

### 5.5 Certificate renewal

The standing Certificate Renewal Policy permits only the bounded IP or domain renewal branch. Each due lineage creates a fresh one-use Plan, acquires the global lock, opens exact temporary `80/TCP`, performs HTTP-01, validates and activates the candidate, publishes Desired State once, proves agreement, closes `80/TCP`, and completes. Failure restores the prior certificate and exact firewall state.

### 5.6 Recovery Required

The Owner may inspect safe evidence and, only when valid unfinished transaction material remains, retry automatic rollback. Otherwise the Owner must use Complete removal and rebuild from scratch. SBXR does not expose repair-by-adoption, manual transaction completion, historical restore, or force-start controls.

### 5.7 Complete removal

The Owner reviews everything removed, enters the exact confirmation, and explicitly starts removal. Before the irreversible checkpoint, rollback remains possible. Afterward the Owner Console shows forward-only progress; restart resumes removal. Success proves owned local and Cloudflare resources are gone and ends at Not installed without retained recovery material.

## 6. Acceptance and release qualification

### 6.1 Acceptance Ladder

Every change is evaluated in order:

1. **Module Verification — automated:** exercise the Module through its Interface, including success, refusal, failure, rollback outcome, security, and redaction.
2. **Seam Verification — automated:** exercise real formats and boundaries safely with fixtures or official validation commands. Never use Owner credentials.
3. **Integrated Verification — automated:** build the executable and release assets; enforce dependencies; run clean-install, update, rollback, Recovery Required, and Complete-removal scenarios in isolation; scan all output with unique secret markers.
4. **Codex Live Acceptance:** run the exact Release Identity on an explicitly approved disposable Acceptance VPS and Acceptance Client.
5. **Owner Acceptance — risk-based:** Albert operates affected maintained apps, devices, real networks, QR/import/clipboard flows, provider steps, and Owner-facing interactions.

A required failed or Pending stage blocks later claims and Release Qualification. Passing a later stage never erases an earlier failure. Status is exactly **Passed**, **Failed**, **Pending**, or **Not required**, with redacted evidence or the exact Not required reason.

### 6.2 Live authority

`107.175.53.219` is the designated disposable Acceptance VPS, but no live action is authorized merely by this specification. An Acceptance Run requires one explicit written checklist and Owner approval for that exact target and every listed destructive scenario.

Codex stops for an unlisted action, wrong target, secret disclosure, unproven SSH safety, unproven Desired State lineage, or uncertain rollback. Before each destructive scenario it proves an Acceptance Baseline: a known Managed revision or proven Not installed state. Uncertainty requires provider reimage and a new Acceptance Run because the host and SSH identity changed.

An Acceptance Client is a separately approved disposable environment outside the VPS. Codex may use temporary acceptance-only Client Access Values and must remove or rotate them afterward. Codex never uses Albert's personal device, personal configuration, existing subscription, or permanent values.

Albert creates and enters the acceptance Cloudflare token. Codex never receives, prints, copies, or stores the complete value. After entry, Codex may invoke only approved typed SBXR actions and read redacted results. Ordinary later Acceptance Runs may reuse the root-only token without re-entry.

### 6.3 Module live ownership

| Module | Codex Live Acceptance | Owner Acceptance when required |
|---|---|---|
| State | ownership, permissions, atomic publication, migration, corruption refusal, restart, lineage | normally Not required |
| Network Policy | nftables, SSH preservation, exposure, conflicts, temporary `80/TCP`, rollback | provider-firewall action when needed |
| System Changes | lock, cancellation, process death, reboot, rollback, Recovery Required, removal | changed destructive confirmation |
| Cloudflare Tunnel | Tunnel, DNS, private origins, correction, token replacement, cleanup, rollback after Albert enters token | token creation/entry and changed onboarding |
| Certificate Lifecycle | real IP/domain issuance, renewal, temporary `80/TCP`, activation, failure, rollback | normally Not required |
| Connection Profiles | all listeners and outside traffic, rotation, repair, failure, rollback | affected maintained apps and networks |
| Subscription Publication | real parsers and Acceptance Client when a format changes | affected maintained-app imports |
| Subscription Serving | IP HTTPS, authorization, rate limit, token rotation, publication, outside download | changed subscription workflow |
| Health and Diagnostics | systemd/tool inspection, permissions, retention, redaction, fail-closed bundle | changed diagnostic TUI readability |
| Software Lifecycle | release verification, install, update, refusal, migration, interruption, restart, rollback, removal | changed update-review experience |
| Owner Console | SSH terminal, sudo, resize, paste, disconnect, resume, progress, confirmation | TUI, clipboard, QR, and workflow usability |

Owner Acceptance is required for the first release and when a change can affect Owner Console/workflows, Connection Profile behavior, subscription formats or values, maintained-client compatibility, or Cloudflare/provider onboarding. Internal changes that cannot affect those surfaces may mark it Not required with the exact reason. Automation and Codex never claim Owner Acceptance for Albert.

A Module ticket may close after its required automated checks and every currently possible live check pass, while genuinely integrated rows remain `Pending — integrated release`. Its outcome is `Module accepted; Release Qualification pending`, never “release accepted.”

### 6.4 Release gate and evidence

Release Identity is the exact repository, immutable tag, commit SHA, and `release-index.json` SHA-256. Any change to code, migrations, templates, embedded tools, index, or payload resets Integrated Verification, Codex Live Acceptance, and required Owner Acceptance. A byte-identical artifact with the same verified identity does not.

Each `internal/<module>/ACCEPTANCE.md` defines that Module's stable checks, stages, and owners once. `acceptance/RELEASE.md` defines integrated checks once. Procedures contain no run results.

Implementation issue comments hold redacted Module Acceptance results. Each candidate has one GitHub Release Qualification issue containing the full stage matrix. Its closing resolution is the one durable Acceptance Record.

The Acceptance Record contains Release Identity, stable check code, Module/stage, runner, status, time, relevant software versions, secret-safe result, evidence link when the evidence passed redaction, or Not required reason. It excludes Client Access Values, Infrastructure Secrets, complete subscription URLs, authorization headers, raw configurations or tool output, proxy traffic, client IPs and destinations, packet captures, credential-bearing QR screenshots, personal-device identifiers, and exact personal-network details. No secret-bearing acceptance archive exists.

A candidate may be tested, but it cannot become stable/latest or enter automatic-update discovery until every required row is Passed or Not required.

Automated checks use a fake clock for due dates, expiry thresholds, retries, and missed schedules. Live acceptance verifies real systemd timer enablement, persistence, next-run state, reboot survival, and the real service invoked by the timer without changing the VPS clock. Certificate timing uses staging/dry-run plus controlled real activation and distinguishes a manual trigger from natural scheduling.

External unavailability leaves a required success row Pending. Correct failure classification and safe preservation may pass separately, but a provider status page alone is not proof and Release Qualification remains blocked.

The live VPS architecture is detected with `uname -m`. Automated verification covers both architectures. Only the detected live architecture requires live proof when one VPS is available; the other must be labelled `Not live-tested — automated verification only`.

## 7. Staged build plan and handoff

Create twelve normal implementation issues in this exact native dependency chain:

1. Implement the State Module.
2. Implement the Network Policy Module.
3. Implement the System Changes Module.
4. Implement the Cloudflare Tunnel Module.
5. Implement the Certificate Lifecycle Module.
6. Implement the Connection Profiles Module.
7. Implement the Subscription Publication Module.
8. Implement the Subscription Serving Module.
9. Implement the Health and Diagnostics Module.
10. Implement the Software Lifecycle Module.
11. Implement the Owner Console Module.
12. Integrate and qualify the SBXR v1 release.

The State issue creates only the minimum `go.mod`, `cmd/sbxr` wiring needed to exercise State, and root dependency check. There is no setup-only ticket. Later issues extend the same codebase without speculative scaffolding.

Each Module issue must:

- link to its exact section in this specification;
- name its Interface, owned behavior, real Seams, and permitted dependencies;
- implement only that Module and the minimum wiring needed to exercise it;
- add `doc.go`, Interface-first tests, and `internal/<module>/ACCEPTANCE.md`;
- pass Module and Seam Verification;
- run every Codex or Owner live check already possible under an approved Acceptance Run;
- record integrated-only rows as `Pending — integrated release`; and
- close only with a redacted Module Acceptance result.

The next issue begins only after its native blocker closes. Owner Console is last so it presents real Module behavior rather than temporary screens.

The final integration issue creates and verifies the complete executable, both architecture archives, immutable release and strict index, integrated scenarios, Acceptance VPS/Client run, required Owner Acceptance, redacted Acceptance Record, and Release Qualification. It may close only when every required row is Passed or Not required for one exact Release Identity.

## 8. Decision provenance

The Wayfinder map and its closed tickets remain the provenance index: [Specify SBXR v1](https://github.com/albertloky/SBXR/issues/1). Durable architecture trade-offs are also recorded in `docs/adr/0001` through `docs/adr/0006`. Research reports remain evidence; they do not override the adopted decisions or substitute for required live qualification.
