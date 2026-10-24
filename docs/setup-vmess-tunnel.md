# Set up VMess through your own Cloudflare Tunnel

This guide applies to the implementation in this checkout. It is not yet a
published or live-qualified release. Start on a fresh supported Ubuntu 24.04
amd64 server. Existing installations have no in-place VMess enable action;
finish their supported recovery/removal before a separately planned clean install.

SBXR keeps VLESS REALITY and adds VMess over TLS/WebSocket. You provide your own
Cloudflare domain and tunnel. SBXR neither supplies a domain nor changes your
Cloudflare account, DNS, Access policies or other connector services.

## 1. Choose a domain, hostname and dedicated tunnel

1. Sign into your own Cloudflare account. Your domain must be active there and
   selectable for a published application route. If you do not own a domain,
   obtain one and complete Cloudflare's domain setup first. Do not borrow someone
   else's hostname or replace an existing DNS record.
2. Choose a new hostname under that domain, for example `proxy.example.com`.
   Check that no existing site, DNS record or tunnel route uses it.
3. Open **Networking > Tunnels** in the Cloudflare dashboard. Create a remotely
   managed Cloudflare Tunnel, or select a dedicated unused tunnel you control.
   Give it a recognizable name and note its tunnel ID. Do not reuse a shared
   tunnel or a tunnel with connectors on another server: requests could reach
   the wrong origin. A random Quick Tunnel is unsupported.
4. On that tunnel, choose **Routes > Add route > Published application**. Select
   your domain and hostname. Set the service URL to **`http://127.0.0.1:10000`**
   and leave the route **Path blank**. The origin and connector must run on the
   same host/network namespace. Do not use `https`, TCP forwarding, a container's
   private loopback or port 443 as the origin.

Cloudflare's [tunnel setup instructions](https://developers.cloudflare.com/tunnel/get-started/)
describe this dashboard flow. VMess uses `/sbxr-vmess` inside the WebSocket
request; that is not the dashboard route Path. Edge TLS must cover your hostname,
and [WebSockets](https://developers.cloudflare.com/network/websockets/) must work.
An interactive browser challenge cannot authenticate a VMess client. If an account
policy blocks this use, stop and resolve that policy deliberately; do not disable
account security or TLS verification as a workaround.

## 2. Install cloudflared and save the tunnel token safely

Install the official Ubuntu **amd64** cloudflared package following
[Cloudflare's package instructions](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/).
SBXR expects `/usr/bin/cloudflared`, root-owned mode `0755`, with one link, and
version **2025.4.0 or newer** for
[`--token-file`](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/#token-file).
SBXR does not install or update this package. Do not run the dashboard's
`cloudflared service install <token>` command: SBXR creates its own separate unit.

In your dedicated tunnel's connector instructions, copy **only its tunnel token**.
No account API token, Global API key, account certificate or `cloudflared login`
is required. The token allows another connector to join that tunnel; keep it private.

On your server's trusted interactive terminal, run this command, then paste the
token into its hidden prompt. The command contains no secret. It refuses an
existing token file and unsafe parent, and does not change an existing directory:

```sh
sudo python3 -c '
import getpass, os, stat, sys
if not sys.stdin.isatty():
    raise SystemExit("Use a trusted interactive terminal for the hidden prompt")
parent = "/etc/cloudflared"
try:
    os.mkdir(parent, 0o700)
except FileExistsError:
    pass
info = os.lstat(parent)
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
    raise SystemExit("Unsafe /etc/cloudflared; preserve it and inspect before continuing")
token = getpass.getpass("Paste only the dedicated tunnel token (hidden): ")
if not token or len(token) > 16384 or any(c.isspace() for c in token):
    raise SystemExit("Token must be one nonempty line")
fd = os.open(parent + "/sbxr.token", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(token + "\n")
    f.flush()
    os.fsync(f.fileno())
'
```

Never put the token in chat, a hostname field, a shell command, an environment
variable, a screenshot or a client profile. Clear any clipboard copy after use.
If this file already exists, inspect which tunnel it belongs to through your
secure administrative workflow. For the same dedicated tunnel, keep the existing
protected file and continue the wizard; do not run the creation command again.
SBXR reads and validates that file without overwriting it or adopting another
service. A missing or unsafe file produces a correction and a Retry option;
do not weaken its permissions to make setup continue.

## 3. Review and start SBXR setup

Run `sudo sbxr` and choose **Start setup**:

1. **Choose connection:** Enter selects Standard, with no domain needed. Choose
   `2` for **Standard + Cloudflare**; `h` explains VLESS/VMess in plain language.
2. **Prepare Cloudflare:** follow the dedicated tunnel, route and protected
   token-file instructions above, then press Enter when ready.
3. **Hostname:** enter only your lowercase hostname, such as `proxy.example.com`.
   Invalid input shows a correction in place. Enter keeps an existing draft.
4. **Review:** check the hostname, intended local changes and selected tunnel ID
   against your dashboard. `b` goes Back without losing the draft, and the wizard
   reviews the prerequisites again when you return. `c` cancels. At **Apply setup?
   [y/N]**, Enter or `n` cancels; only `y` applies the reviewed changes.
5. **Install and check:** read installation and fresh connection-test results
   separately. Follow the displayed import, retry or recovery guidance.

Cancel before Apply performs no installation or Cloudflare account changes.
The wizard never accepts a token or other credential; prepare the protected file
in your trusted terminal using the existing workflow above.
The token identifies the selected tunnel; it cannot prove that you own the domain
or configured the route correctly.

SBXR refuses unsafe/missing token files, unsupported cloudflared, occupied TCP
10000 or an occupied/foreign `sbxr-tunnel.service` name. It records the reviewed
token and binary digests without the token itself, then installs only:

- `/etc/systemd/system/sbxr-tunnel.service`
- Its exact `multi-user.target.wants` enablement link and temporary staging file.

The service restarts on failure and after reboot, runs as a dynamic unprivileged
user, loads its token with systemd `LoadCredential`, ignores other cloudflared
configuration files, and binds metrics only to loopback. It never places the token
in its arguments. SBXR does not touch `cloudflared.service` or any other tunnel.
Only its dedicated connector is stopped and removed with reviewed SBXR removal.

## 4. Read the result and recover

**Running is local proxy status.** It does not prove that the tunnel works.
Setup separately checks the local WebSocket origin, trusted public TLS/WebSocket
upgrade, and HTTPS egress through an isolated VMess-only client. The client has
no VLESS/direct fallback, uses an authenticated loopback listener proved to belong
to its process, keeps credentials in memory/stdin, and is stopped afterward.
The HTTPS egress service is `api.ipify.org`; redirects or an egress IPv4 different
from this server fail the check. These checks are bounded and do not store a
permanent readiness assertion.

| Result | What to do |
|---|---|
| Setup incomplete; connector needs completion | Restore the exact reviewed token/binary and dedicated unit, then choose **Finish setup**. The forward recovery checkpoint remains durable. |
| Local WebSocket origin failed | Inspect `sing-box.service` and its fixed loopback origin; do not expose port 10000 publicly. |
| Public TLS/WebSocket failed | Check hostname/DNS, tunnel health, edge certificate, published application origin and blank route Path. Allow time for a new DNS route/certificate, then check again. |
| VMess traffic/egress failed | Verify the tunnel has no connectors pointing at another server, the selected origin is correct, and the current Client Identity reaches it. A check-service outage or changed server egress can also fail verification. |
| VMess connection verified | This server completed the public route and authenticated VMess traffic check. Test a separate outside client before treating it as usable from your network. Karing acceptance remains separate. |

After a route or transient network correction, choose **Check VMess connection**.
It is repeatable and changes no saved profile or durable SBXR state. If the
dedicated service was stopped, inspect its status and start/restart only that
service through your administrative workflow; never restart every cloudflared
service. Logs are suppressed for this connector to keep remote configuration and
credentials out of journals. Use SBXR's staged check and the tunnel dashboard's
health/route view for diagnosis. Do not reinstall to fix DNS or a transient outage.

Automatic cloudflared updates are disabled in this unit. Maintain its official
package deliberately; setup/recovery refuses a binary or token different from
the reviewed digest. Token/package replacement is not an SBXR repair action in
this version. Plan it separately and do not edit the Ownership Record to bypass
that refusal. Recovery and Complete removal never require a network connection
to Cloudflare; removal does not require the token or binary to remain present.

The subscription includes VLESS and VMess with one Client Identity. Client
Identity rotation replaces both; Subscription Link rotation is independent.
HTTP subscription interception/tampering risks remain. Neither this guide nor a
server-side pass establishes the five release journeys or two-node Karing import.

Complete removal preserves your token, cloudflared package, domain, tunnel and
DNS. Separately retire or repoint only those dedicated account resources when
you intend to stop using them. Do not leave a route aimed at a loopback port that
may later serve an unrelated application.
