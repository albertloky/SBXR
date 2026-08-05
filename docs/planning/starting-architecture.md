# SBXR Starting Architecture

> Planning input supplied by the Owner. This is the starting specification, not the final Wayfinder output.

My endpoint is a spec.
The whole project should use deep modules. The TUI should be the Owner's main interactive menu. The Owner should normally type sbxr to open the TUI and adjust settings. The TUI should look like a GUI designed by Apple. The TUI should use light mode and arrow navigation. Pasted text containing Q must not exit the TUI.
The implementation/tickets should be separated step by step, based on each deep modules, so that one modeules pass the test, and then build another module, the whole codebase should be easy AI navigation, take reference from codebase design skill from Matt Pocock installed. After each implementation, testing should be done by chatgpt ssh into vps 107.175.53.219 or by Albert. You should separate tickets based on who should test, for easier progress monitoring.

Revised Single-Owner, Six-Profile Architecture
1. Final scope
The project shall be optimized exclusively for:
•	Ubuntu Server 24.04 LTS
•	One VPS
•	One Owner
•	One management command, sbxr, which requests sudo internally when required
•	Xray and sing-box running concurrently
•	One named Cloudflare Tunnel
•	Six connection profiles
•	Three Xray profiles
•	Three sing-box profiles
•	One IP-based HTTPS subscription system
•	GitHub Release-based project updates
•	Automatic rollback
•	No database for multiple people
•	No quotas, billing, groups, invitations, or account administration
The installed management command shall be:
sbxr
On an existing installation, running sbxr automatically requests sudo authentication once when the VPS requires it, then opens the terminal interface; the Owner never has to type sudo sbxr manually. A short-lived privileged reader supplies only the approved dashboard Client Access Values, while the TUI itself remains non-root and Infrastructure Secrets remain root-only. If authentication is denied, SBXR opens a limited read-only dashboard without Client Access Values. During fresh installation, download, verification, preflight, and review remain unprivileged; sudo is requested only after the Owner approves the installation Plan. Closing the interface does not stop the proxy services.
2. Running services
The normal installation contains:
xray.service
sing-box.service
cloudflared.service
sbxr-subscription.service
Scheduled jobs:
sbxr-ip-cert-renew.timer
sbxr-update-check.timer
sbxr-health-check.timer
The timers are not continuously running services.
3. Meaning of “six protocols”
The project shall expose six named connection profiles.
Three Xray profiles all use VLESS because VLESS, REALITY, Vision and XHTTP are Xray’s strongest native stack. VLESS is lightweight, and the Xray documentation identifies REALITY and Vision as particularly suitable for secure, high-performance direct connections.
Using three different VLESS transports is preferable to adding VMess or Trojan merely to make every protocol name different.
4. Final Xray profiles
Xray profile 1 — VLESS REALITY Vision
Purpose:
Primary secure and fast TCP connection
Direct VPS connection
Primary fallback when UDP is blocked
Configuration:
Core              Xray
Protocol          VLESS
Transport         RAW/TCP
Security          REALITY
Flow              xtls-rprx-vision
Public address    VPS IPv4 or IPv6
Public port       443/TCP
This is the main direct TCP profile.
REALITY is designed to resemble an ordinary TLS connection and can be combined with RAW transport and Vision. Xray describes REALITY as one of its strongest transport-security options and notes that Vision can substantially reduce forwarding overhead in suitable conditions.
Security defaults:
Random UUID
Generated REALITY private/public key pair
Random short ID
Chrome-compatible client fingerprint by default
Carefully validated REALITY destination
No insecure certificate option
No anonymous access
No fallback to an open proxy
Xray profile 2 — VLESS XHTTP through Cloudflare Tunnel
Purpose:
Primary Cloudflare fallback
Useful when the VPS IP route is unstable or blocked
Modern HTTP-compatible Xray transport
Configuration:
Core                    Xray
Protocol                VLESS
Transport               XHTTP
Public security         Cloudflare TLS
Public address          xhttp.<owned-domain>
Public port             443/TCP
Local inbound address   127.0.0.1
Local inbound port      11080/TCP
Exposure                Cloudflare Tunnel only
Traffic path:
Client
  ↓
Cloudflare edge
  ↓
cloudflared
  ↓
127.0.0.1:11080
  ↓
Xray VLESS XHTTP
The local XHTTP inbound must never listen on a public interface.
Cloudflare Tunnel publishes applications by mapping a public hostname to a local service. It uses outbound connections from cloudflared, so the local XHTTP port does not need to be opened publicly.
Xray profile 3 — VLESS WebSocket through Cloudflare Tunnel
Purpose:
Maximum client compatibility
Older-client fallback
Cloudflare-compatible HTTP transport
Configuration:
Core                    Xray
Protocol                VLESS
Transport               WebSocket
Public security         Cloudflare TLS
Public address          ws.<owned-domain>
Public port             443/TCP
Local inbound address   127.0.0.1
Local inbound port      11081/TCP
Exposure                Cloudflare Tunnel only
WebSocket is retained because its client compatibility is broader than newer XHTTP modes. It should not be the default profile because it adds HTTP and WebSocket overhead.
Use a random high-entropy WebSocket path:
/<random-32-byte-path>
Do not use the UUID itself as the WebSocket path.
5. Final sing-box profiles
sing-box profile 1 — Hysteria2
Purpose:
Primary high-speed UDP connection
Good performance on lossy or high-latency networks
Primary mobile-network performance profile
Configuration:
Core              sing-box
Protocol          Hysteria2
Transport         QUIC/UDP
Security          TLS
Public address    VPS IPv4 or IPv6
Public port       443/UDP
TLS SNI           direct.<owned-domain>
TCP port 443 and UDP port 443 can be used simultaneously:
Xray       443/TCP
sing-box   443/UDP
Hysteria2 requires TLS and supports both TCP and UDP proxy traffic through its QUIC-based connection. sing-box also supports bandwidth controls, masquerade behaviour and optional obfuscation.
Security defaults:
Independent random password
Valid domain certificate
Certificate verification enabled
No skip-cert-verify
No 0-RTT setting exposed
Optional obfuscation disabled by default
Masquerade returns an ordinary HTTP/3 response
Obfuscation can be an advanced setting rather than automatically enabled. It may help in some network environments but should not be treated as encryption; TLS remains the security layer.
sing-box profile 2 — TUIC v5
Purpose:
Alternative QUIC implementation
Secondary high-speed UDP option
Fallback when Hysteria2 behaves poorly on a particular network
Configuration:
Core                  sing-box
Protocol              TUIC v5
Transport             QUIC/UDP
Security              TLS
Public address        VPS IPv4 or IPv6
Public port           8443/UDP
TLS SNI               direct.<owned-domain>
Congestion control    BBR or cubic
TUIC requires TLS. The sing-box documentation recommends disabling QUIC 0-RTT because it is vulnerable to replay attacks, so the project must set:
"zero_rtt_handshake": false
Credentials:
Independent random UUID
Independent random password
TUIC must not reuse the Hysteria2 password.
sing-box profile 3 — AnyTLS
Purpose:
Additional secure TCP option
Fallback when UDP is unavailable
Simpler TLS-based sing-box connection
Configuration:
Core              sing-box
Protocol          AnyTLS
Transport         TCP
Security          TLS
Public address    VPS IPv4 or IPv6
Public port       9443/TCP
TLS SNI           direct.<owned-domain>
AnyTLS uses password authentication, TLS and a configurable padding scheme. sing-box has supported AnyTLS inbound and outbound configurations since version 1.12.0.
Security defaults:
Independent 32-byte random password
Valid certificate
Certificate verification enabled
Standard maintained padding scheme
No insecure mode
6. Protocols deliberately excluded
VMess
VMess is excluded because VLESS provides a cleaner modern Xray architecture. Xray’s own transport documentation notes that VMess provides protocol-layer encryption but lacks TLS 1.3-style forward secrecy and does not provide an ordinary HTTPS appearance by itself.
Shadowsocks
Shadowsocks is excluded because it adds another credential and configuration path without providing a stronger option than the selected six profiles. Xray similarly warns that direct Shadowsocks traffic lacks the ordinary HTTPS appearance offered by TLS or REALITY.
Trojan
Trojan is excluded because it would duplicate the direct TLS role already handled by AnyTLS and the direct secure TCP role handled by VLESS REALITY Vision. Xray also requires Trojan to use transport security on public links and documents additional detectability concerns for unsuitable public configurations.
gRPC
gRPC is excluded because XHTTP is the preferred modern Xray HTTP transport and WebSocket is retained for broader compatibility.
XHTTP Direct
XHTTP Direct is excluded because direct TCP is already covered by VLESS REALITY Vision. The selected XHTTP profile is specifically intended to provide path diversity through Cloudflare.
Additional QUIC protocols
No fourth UDP/QUIC protocol shall be added. Hysteria2 and TUIC provide sufficient UDP diversity.
7. Default port registry
22/TCP or detected SSH port     SSH
80/TCP                         IP-certificate ACME validation only
443/TCP                        Xray VLESS REALITY Vision
443/UDP                        sing-box Hysteria2
8443/UDP                       sing-box TUIC
9443/TCP                       sing-box AnyTLS
10443/TCP                      HTTPS subscription service
11080/TCP on 127.0.0.1 only    Xray VLESS XHTTP origin
11081/TCP on 127.0.0.1 only    Xray VLESS WebSocket origin
The following ports must not be opened publicly:
11080/TCP
11081/TCP
The port registry must distinguish TCP and UDP. It must allow TCP and UDP to use the same numerical port.
The detected SSH port and TCP port 80 are fixed. If another configurable default is occupied during fresh installation, SBXR shall propose a random available replacement in the reviewed Plan. A committed selection persists in Desired State and never moves silently later.
8. IP-based subscription URL
The subscription system shall not use the owned domain.
The primary subscription URL shall use the VPS public IP:
https://<VPS-IP>:10443/s/<subscription-token>
Example shape:
https://203.0.113.10:10443/s/8M1...high-entropy-token...WcA
For IPv6:
https://[2001:db8::10]:10443/s/<subscription-token>
The IPv4 and IPv6 examples are alternatives. SBXR shall qualify each address family independently, publish only approved addresses, and let the Owner choose the primary subscription address when both pass.
Cloudflare Tunnel is not involved in subscription delivery. Public Cloudflare Tunnel applications use hostname-to-service mappings, so a bare-IP subscription endpoint must connect directly to the VPS.
9. Subscription HTTPS certificate
Plain HTTP must not be offered as the normal mode because it would expose the complete subscription response and credentials to anyone capable of observing or modifying that connection.
The manager shall obtain a Let’s Encrypt certificate containing each approved VPS IP address as an IP Subject Alternative Name.
Let’s Encrypt IP certificates are:
Publicly trusted
Available for IPv4 and IPv6
Short-lived
Valid for approximately 160 hours
Renewed using HTTP-01 or TLS-ALPN-01
The project shall use HTTP-01 because TCP port 443 is occupied by VLESS REALITY.
Certificate issuance requirements:
Certbot 5.4 or newer
Short-lived certificate profile
VPS public IP
TCP port 80 reachable during validation
Fully automated renewal
Certbot currently provides an --ip-address option and supports standalone authentication. HTTP-01 validation always starts on port 80.
Conceptual issuance:
certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --preferred-profile shortlived \
  --ip-address <VPS-IP>
The implementation must validate the actual installed Certbot syntax during development rather than blindly copying this conceptual command.
10. IP-certificate renewal
Because the certificate lasts only about six days, the manager shall install:
sbxr-ip-cert-renew.service
sbxr-ip-cert-renew.timer
The timer should run at least once per day with randomized delay.
Renewal transaction:
1. Acquire the installation-wide SBXR mutation lock.
2. Check certificate expiration.
3. Skip renewal when safely outside the renewal window.
4. Add the temporary nftables TCP port 80 rule.
5. Start the ACME standalone challenge process.
6. Obtain or renew the IP certificate.
7. Verify that the certificate contains the correct IP SAN.
8. Verify the certificate chain.
9. Atomically replace the subscription certificate files.
10. Reload sbxr-subscription.service.
11. Test HTTPS using the VPS IP.
12. Remove the temporary TCP port 80 rule.
13. Roll back the previous certificate if the health check fails.
Port 80 should normally remain closed and be opened only during issuance or renewal.
11. Single-Owner credential model
Remove:
Multi-person identity table
Device ownership model
Quotas
Expiration
Invitations
Roles
Usage accounting
Multi-person subscription records
Conceptual Owner State shape, not the final file schema:
{
  "owner": {
    "name": "owner",
    "enabled": true,
    "subscription_token": "...",
    "credentials": {
      "xray_reality_uuid": "...",
      "xray_xhttp_uuid": "...",
      "xray_websocket_uuid": "...",
      "hysteria2_password": "...",
      "tuic_uuid": "...",
      "tuic_password": "...",
      "anytls_password": "..."
    }
  }
}
Although there is only one Owner, each Connection Profile should have independent credentials. Compromise of one configuration should not automatically compromise every profile.
The TUI must support:
Display all six Connection Profile credentials, share URIs, QR codes, and the subscription URL on the main dashboard by default
Rotate one profile credential
Rotate all profile credentials
Rotate subscription URL by replacing only the subscription token; this stops future downloads but does not revoke previously downloaded Connection Profile credentials
Revoke all client access by atomically replacing the subscription token and all six Connection Profile credentials, regenerating every representation, applying the new core configurations, and rolling back the complete change if any step fails
Export client configuration

The Owner accepts that these displayed Client Access Values can remain in terminal scrollback, screenshots, screen recordings, or SSH session recordings. The dashboard must never display the Cloudflare tunnel credential, certificate private keys, ACME account material, recovery journals, or Rollback Snapshot contents.
12. Simple subscription endpoints
The default displayed link is:
https://<VPS-IP>:10443/s/<token>
This endpoint detects common client User-Agent values and returns the most suitable supported format.
For reliability, hidden explicit endpoints shall also exist:
https://<VPS-IP>:10443/s/<token>/base64
https://<VPS-IP>:10443/s/<token>/sing-box
https://<VPS-IP>:10443/s/<token>/mihomo
https://<VPS-IP>:10443/s/<token>/raw
They are not different accounts or tokens. They are different representations of the same six profiles.
Client mapping:
Shadowrocket       Base64 URI list
v2rayN              Base64 URI list
Karing              Auto, sing-box JSON or Mihomo YAML
Mihomo/Clash Meta   Mihomo YAML
sing-box clients    sing-box JSON
Unknown clients     Base64 URI list
The subscription-links area should display only:
Universal subscription link
Shadowrocket/v2rayN link
Karing link
Mihomo link
sing-box link
No separate format-selection menu is needed.
14. Subscription service security
sbxr-subscription.service shall:
Listen publicly only on 10443/TCP
Require HTTPS
Use the trusted IP certificate
Use one 256-bit random subscription token
Use exact path matching
Return HTTP 404 for invalid tokens
Disable directory listing
Disable public index pages
Redact the token from logs
Never log generated configuration bodies
Apply request rate limits
Apply connection timeouts
Limit response sizes
Return Cache-Control: private, no-store
Return X-Content-Type-Options: nosniff
Return Referrer-Policy: no-referrer
The service should not expose a web management panel.
The TUI remains available only through SSH.
15. Subscription service implementation
The subscription service should be part of the sbxr codebase, not a separately managed third-party subscription converter.
Subscription Publication owns token semantics, client-representation generation, validation, and atomic artifact publication. Subscription Serving owns only authenticated HTTPS delivery from the published artifact set. The exact Go package placement is deferred to [Define repository navigation and module placement](https://github.com/albertloky/SBXR/issues/17); renderer files must not become shallow public Modules.
It reads generated, non-editable subscription artifacts from:
/var/lib/sbxr/subscriptions/current/
The network service must not read Desired State directly.
The management application generates the subscription files, validates them, and atomically publishes them. The subscription service only serves the already-generated files after validating the token.
16. Simplified TUI
The main interface shall contain:
1. System status
2. Manage six connection profiles
3. Cloudflare Tunnel
4. Domains and TLS certificates
5. IP subscription link
6. Ports and nftables firewall
7. Routing and outbound settings
8. Export client configurations
9. Services and logs
10. Project and core updates
11. Diagnostics
12. Security settings
13. Complete removal
0. Exit

Security invariants are not bypassable. When a check fails, the TUI must identify the cause and provide an exact corrective work plan. If SBXR can safely make the correction within its owned scope, it shall offer a separate reviewable Plan; external or manual corrections shall include detailed step-by-step instructions. It must never reduce the protection merely to continue.

Six-profile management screen
Xray

1. VLESS REALITY Vision
   Status: Running
   Port: 443/TCP

2. VLESS XHTTP Cloudflare
   Status: Running
   Hostname: xhttp.example.com
   Origin: 127.0.0.1:11080

3. VLESS WebSocket Cloudflare
   Status: Running
   Hostname: ws.example.com
   Origin: 127.0.0.1:11081

sing-box

4. Hysteria2
   Status: Running
   Port: 443/UDP

5. TUIC v5
   Status: Running
   Port: 8443/UDP

6. AnyTLS
   Status: Running
   Port: 9443/TCP
Each profile supports:
Enable or disable
Show settings
Display its share URI and QR code on the main dashboard by default
Rotate credential
Change port
Run configuration test
Repair current configuration
The dashboard shall offer one optional post-Managed `Run Live Profile Check` action. It uses the universal subscription once, displays one temporary test URL and QR code, automatically attributes successful outside traffic to each Connection Profile, never gates installation, and retains no test token, counter difference, client-IP history, destination history, access log, or persistent traffic history.
17. Cloudflare use after this revision
SBXR shall store one dedicated, root-only Cloudflare API token with all permissions SBXR needs for the selected Cloudflare account and zone, including tunnel management and the required DNS changes. The token remains memory-only until successful installation commits it; abandonment or rollback discards it. After success, SBXR reuses it automatically for approved DNS, Tunnel, certificate, repair, and update work, so the Owner need not paste it again for normal later changes. Immutable account and zone IDs bind the installation; changing either requires a separately reviewed migration.

For the Cloudflare management token, the TUI shall show status, the first and last four characters, bound account and zone, last successful verification, expiry when present, and current uses. It shall offer `Check now`, `Replace token`, and `Remove from SBXR`; removal is a reviewed Change Set and cannot leave dependent resources falsely reported as Managed or Healthy. For the tunnel run token, it shall offer `Reveal` and genuine `Rotate`. Replacement uses a dedicated masked-entry page with `Verify replacement`, `Back`, and Esc, and leaves the old token untouched until verification and confirmation succeed.

Initial setup shall give a first-time Cloudflare Owner a detailed, current walkthrough containing the exact Cloudflare website address, dashboard pages, buttons, fields, resource selections, and permissions needed to create the single token. Before storing it, SBXR shall verify that the token is active and can access the selected account and zone. The first approved Cloudflare transaction shall prove the required write permissions by completing and health-checking the actual tunnel and DNS changes; missing permission must stop safely with exact corrective guidance. A broad Global API Key is not required.

The owned Cloudflare domain remains required for:
VLESS XHTTP Cloudflare hostname
VLESS WebSocket Cloudflare hostname
Direct TLS SNI for Hysteria2
Direct TLS SNI for TUIC
Direct TLS SNI for AnyTLS
The domain is not used for:
Subscription URL
VLESS REALITY client server address
Direct Hysteria2 server address
Direct TUIC server address
Direct AnyTLS server address
Direct TLS profiles can connect to the VPS IP while sending and verifying:
SNI = direct.<owned-domain>
The client therefore uses the VPS IP as its connection address but validates the certificate using the configured domain name.
18. Default public firewall surface
Normal default public inbound rules:
Detected SSH port/TCP
443/TCP
443/UDP
8443/UDP
9443/TCP
10443/TCP
Temporary inbound rule:
80/TCP during IP-certificate validation
No public exposure:
11080/TCP
11081/TCP
Xray API
sing-box control API
subscription source directory
sbxr state files
sbxr secrets
Cloudflare credentials
Configurable occupied defaults receive only the random alternatives approved in the installation Plan. The detected SSH port and temporary TCP port 80 never move, and a later Network Policy change requires its own reviewed, revalidated Change Set.
19. GitHub update model
The updater must update:
sbxr application
subscription renderer
client compatibility definitions
systemd templates
configuration schema
migration code
It must never silently overwrite:
Owner credentials
Subscription token
Cloudflare tunnel token
Cloudflare management API token
Domain configuration
IP certificate account
Current port selection
Firewall state
An active Rollback Snapshot or recovery journal
Changing an allowed item in this list requires its own reviewed, revalidated Change Set and the owning Module's rollback and health gates.
After each project update, the updater must regenerate and validate all five subscription representations:
Automatic
Base64 URI
Raw URI
sing-box JSON
Mihomo YAML
20. Security ownership and trust boundaries
The Owner Console remains non-root. Running sbxr requests sudo once when required; short-lived privileged processes may read approved Client Access Values or apply a validated, revision-bound Plan, but may not accept arbitrary commands or paths. Denied authentication yields a limited read-only dashboard.

Xray, sing-box, cloudflared, and Subscription Serving run as separate non-root identities. Xray and sing-box receive only `CAP_NET_BIND_SERVICE` when an approved selected port below 1024 requires it. Root-only directories and files use `0700` and `0600`; root-owned service-readable directories and files use `0750` and `0640`. Each service reads only its own prepared configuration and credentials. Secrets never appear in command arguments or environment variables; cloudflared uses `--token-file`.

The authenticated dashboard deliberately displays all Client Access Values by default. Infrastructure Secrets never appear on the dashboard. Cloudflare credentials may reveal only their first and last four characters; certificate private keys, REALITY private keys, ACME account material, recovery journals, and Rollback Snapshot contents are never revealable. Redaction, verified releases, SSH preservation, safe REALITY targets, TLS verification, private origins, service isolation, and file permissions cannot be bypassed. Every refusal includes an exact corrective work plan, with a separate reviewable Plan for any correction SBXR can safely perform.

SBXR stores one scoped Cloudflare API token for one selected account and zone, keeps the active Rollback Snapshot and recovery journal root-only, disables proxy access logs and core dumps, retains no traffic history, uses no third-party credential testing, and sends no telemetry or automatic diagnostic uploads. SBXR v1 keeps no durable backup or historical restore; Complete removal requires separate two-step confirmation.

See [Define security ownership and trust boundaries](https://github.com/albertloky/SBXR/issues/9#issuecomment-5175290085), [Define installation preflight and SSH safety](https://github.com/albertloky/SBXR/issues/12#issuecomment-5187474911), [ADR 0002](../adr/0002-distributed-security-ownership-and-trust-boundaries.md), and [ADR 0006](../adr/0006-installation-preflight-and-ssh-safety.md).

21. Final product boundary
The completed project shall provide exactly:
Two proxy cores
Six connection profiles
One Cloudflare Tunnel
One owner
One subscription token
One IP-based HTTPS subscription endpoint
One terminal management application
One central state model
One GitHub Release updater
One transactional rollback system

22. SBXR v1 recovery boundary
SBXR v1 protects only an unfinished Change Set and the current proven Desired State. System Changes owns one global mutation lock, one root-only Rollback Snapshot, the recovery journal, automatic rollback during an operation or after restart, rollback proof, and Recovery Required. The Rollback Snapshot contains only the prior Desired State, managed files, release material, settings, and evidence needed to reverse its Change Set; it is not Owner-selectable and is deleted after the durable Complete checkpoint.

The installation statuses are exactly Not installed, Managed, Change in progress, and Recovery Required. Recovery Required means SBXR cannot prove either the current Desired State lineage or the safe resolution of an unfinished Change Set. If valid rollback material remains, the Owner may retry automatic rollback. Otherwise SBXR offers safe evidence, read-only diagnostics, and Complete removal; the Owner must rebuild from scratch.

SBXR may prepare a new reviewed Change Set to repair drift toward the current valid Desired State. It cannot recover missing or corrupt Desired State, recreate lost secrets, restore an older revision, recover onto a replacement VPS, or reverse a completed Owner decision. There is no Create backup now action, backup retention setting, selectable Recovery Point, restore menu, old-secret restore, Uninstall and keep recovery action, Recovery retained status, long-term release parcel, offline-versus-online restore rule, or Backup and Recovery Module.

Complete removal is the only forward-only exception. Before the durable Irreversible removal started checkpoint, failure or cancellation rolls back to Managed. After that checkpoint, restart resumes deletion and restore or cancellation is impossible. Success ends at Not installed with no SBXR recovery material retained.
