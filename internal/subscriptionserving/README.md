# Subscription Serving

Subscription Serving is the isolated public HTTPS runtime for the active immutable subscription artifacts. Its production entry point is the private `sbxr __subscription-serve` mode used only by `sbxr-subscription.service`.

The exact `/base64`, `/raw`, `/v2rayn`, `/shadowrocket`, `/karing`, `/mihomo`, and `/sing-box` suffixes return the corresponding active published bytes. Explicit suffixes always win over `User-Agent`. The unsuffixed route recognizes conservative case-insensitive v2rayN, Mihomo/Clash Meta, and sing-box format hints; unknown or conflicting hints return base64. Only the unsuffixed route sends `Vary: User-Agent`. Every success names the selected format in `X-SBXR-Representation`; Karing and sing-box also disclose `X-SBXR-Omitted-Profile: vless-xhttp`. Shadowrocket remains labeled as a candidate rather than Owner-accepted.

URI and base64 bodies use `text/plain; charset=utf-8`, Karing and sing-box use `application/json`, and Mihomo uses `application/yaml`. Every success also sends `Cache-Control: private, no-store`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. Every other token, route, suffix, query, encoded path, or method shape receives the same plain `404`. There is no `/<token>` alias, redirect, index, login, HTTP listener, insecure TLS, self-signed fallback, Cloudflare route, or domain fallback.

The production listener binds only the selected IP family and exact selected IP at `10443/TCP`. `Serve` starts only after normal trust-chain, validity, private-key, and exact IP-SAN checks succeed. The controlled `NewAt` constructor replaces only the host root, service ownership, trust roots, and clock for full-TLS Seam Verification; production uses fixed paths and system trust roots.

The runtime reads only:

- `/etc/sbxr/subscription.json`, containing the one minimum authorization fact, selected address, fixed port, and fixed certificate pointer;
- `/var/lib/sbxr/subscriptions/current/`, containing the complete active immutable artifact set; and
- `/var/lib/sbxr/certificates/ip/current/`, containing the active certificate pair.

The configuration and active artifact directory must use the approved root-owned, `sbxr-subscription`-readable `0750`/`0640` boundary. Certificate Lifecycle supplies one narrowly validated relative `current` pointer to a root-owned, `sbxr-subscription`-readable `0750` versioned set with `0640` files. The owning Modules prove every host parent has its exact non-writable mode; inside the systemd namespace, synthetic parents are root-owned on the read-only temporary filesystem. Any other symbolic link, extra or missing artifact, non-regular file, wrong final ownership, wider final mode, oversized file, malformed base64, invalid configuration, or invalid certificate input stops startup. Root-only inactive publication sets and certificate candidates remain `0700`/`0600` behind their owning Modules and are not readable by this service.

The systemd unit runs as the separate non-root `sbxr-subscription` identity, exposes no capabilities or writable SBXR path, disables core dumps, and starts from an otherwise empty read-only filesystem containing only the executable, service configuration, active artifacts, active certificate pointer, and public trust bundle. Desired State, transaction evidence, Certbot material, Cloudflare material, and arbitrary VPS content are absent from that namespace. The package imports no other product Module and offers no file, command, firewall, service, certificate, or VPS mutation operation. Public access logs, traffic history, telemetry, crash reporting, response-body logging, token logging, and raw external errors are absent.

`Failure` carries a stable, secret-safe code. `Result` converts a successful check to `Healthy`, a typed refusal to `Failed`, and an unexpected untyped failure to `Unknown`. Later slices add the remaining public-boundary controls and atomic serving-state switching.
