package terminal

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

const setupChoicePrompt = "Connection [1] (h Help, c Cancel):"
const setupPreparationPrompt = "Press Enter when ready (b Back, c Cancel):"
const setupApplyPrompt = "Apply setup? [y/N]"
const setupGuide = "https://github.com/albertloky/SBXR/blob/main/docs/setup-vmess-tunnel.md"

// Both setup variants share one menu entry; the module still owns their legality.
func menuActions(actions []proxyinstallation.Action) []proxyinstallation.Action {
	visible := make([]proxyinstallation.Action, 0, len(actions))
	for _, action := range actions {
		if action != proxyinstallation.StartVMessSetupAction {
			visible = append(visible, action)
		}
	}
	return visible
}

func runSetup(ctx context.Context, reader *bufio.Reader, output io.Writer, installation proxyinstallation.Interface, current proxyinstallation.Review) (proxyinstallation.Result, bool) {
	cancelled := proxyinstallation.Result{Status: current.Status, Code: proxyinstallation.ActionCancelled, Message: "Setup cancelled. No changes were made."}
	reviewer, supportsCloudflare := installation.(interface {
		ReviewVMessSetup(context.Context, string) proxyinstallation.Review
	})
	supportsCloudflare = supportsCloudflare && slices.Contains(current.LegalActions, proxyinstallation.StartVMessSetupAction)
	cloudflare, hostname := false, ""
	step := 1
	for {
		var prompt string
		switch step {
		case 1:
			if _, err := io.WriteString(output, "Setup 1 — Choose connection\nSet up a proxy on this server. No changes until Apply.\n1. Standard (default; no domain needed)\n"); err != nil {
				return cancelled, false
			}
			if supportsCloudflare {
				if _, err := io.WriteString(output, "2. Standard + Cloudflare (your own hostname and tunnel)\n"); err != nil {
					return cancelled, false
				}
			}
			prompt = setupChoicePrompt
			if cloudflare {
				prompt = "Connection [2] (h Help, c Cancel):"
			}
		case 2:
			if _, err := fmt.Fprintf(output, "Setup 2 — Prepare Cloudflare\nYour domain is a name you own (example.com). Choose an unused hostname under it (proxy.example.com). A tunnel connects that hostname to this server.\n1. Your domain must be active in your own Cloudflare account.\n2. In Networking > Tunnels, create or select a dedicated unused remotely managed tunnel. Never reuse a shared tunnel or one with connectors on another server. Note its tunnel ID.\n3. Add a Published application route: your hostname -> http://127.0.0.1:10000; leave route path blank.\n4. Install official cloudflared >=2025.4.0 at /usr/bin/cloudflared. Prepare /etc/cloudflared/sbxr.token as a root-owned 0600 file (only root can read/write), using the guide's hidden-prompt command in a separate trusted terminal.\nIf that protected file already exists, reuse it only for this dedicated tunnel; do not overwrite it. SBXR checks it and shows its tunnel ID before Apply.\nUse only the tunnel token, never account API credentials; never paste it here. Do not run cloudflared service install.\nSBXR manages only sbxr-tunnel.service; your token, package, domain, DNS and tunnel remain yours.\nSecure token-file instructions: %s\n", setupGuide); err != nil {
				return cancelled, false
			}
			prompt = setupPreparationPrompt
		case 3:
			if _, err := fmt.Fprintf(output, "Setup 3 — Hostname\nEnter only a lowercase DNS hostname, such as proxy.example.com (no https://, port, path or token).\nHostname draft: %s\n", hostname); err != nil {
				return cancelled, false
			}
			prompt = "Hostname (Enter keeps draft, b Back, c Cancel):"
		case 4:
			// Review again after every Back or retry. Never reuse an earlier authority.
			review := proxyinstallation.Review{}
			number, connection := 2, "Standard — no domain needed"
			if cloudflare {
				number, connection = 4, "Standard + Cloudflare"
			}
			if _, err := fmt.Fprintf(output, "Setup %d — Review\nConnection: %s\n", number, connection); err != nil {
				return cancelled, false
			}
			if cloudflare {
				if _, err := fmt.Fprintln(output, "Hostname:", hostname); err != nil {
					return cancelled, false
				}
				review = reviewer.ReviewVMessSetup(ctx, hostname)
			} else {
				review = installation.Review(ctx, proxyinstallation.StartSetupAction)
			}
			if review.Prepared == nil {
				if writeRefusal(output, review.Result) != nil {
					return cancelled, false
				}
				line, ok := readSetupInput(reader, output, "Setup is not ready. r Retry checks, b Back, c Cancel:")
				if !ok {
					return cancelled, false
				}
				switch line {
				case "r":
				case "b":
					step = 1
					if cloudflare {
						step = 3
					}
				case "c", "":
					return cancelled, true
				default:
					if _, err := io.WriteString(output, "Enter r to retry, b to go back, or c to cancel.\n"); err != nil {
						return cancelled, false
					}
				}
				continue
			}
			if _, err := io.WriteString(output, "Install the sing-box proxy and its protected configuration on this server.\nFull reviewed changes follow; scroll up to read them before Apply:\n"); err != nil {
				return cancelled, false
			}
			for _, line := range review.Plan {
				if _, err := fmt.Fprintln(output, line); err != nil {
					return cancelled, false
				}
			}
			if cloudflare {
				if _, err := io.WriteString(output, "Match the selected tunnel ID and hostname above to your Cloudflare dashboard.\n"); err != nil {
					return cancelled, false
				}
			}
			if _, err := io.WriteString(output, "b Back to edit, c Cancel. Only y applies these changes.\n"); err != nil {
				return cancelled, false
			}
			for {
				line, ok := readSetupInput(reader, output, setupApplyPrompt)
				if !ok {
					return cancelled, false
				}
				switch line {
				case "y":
					if _, err := fmt.Fprintf(output, "Setup %d — Install and check\n", number+1); err != nil {
						return cancelled, false
					}
					var progressErr error
					result := installation.Execute(ctx, *review.Prepared, proxyinstallation.Approved, func(progress proxyinstallation.Progress) {
						if progressErr == nil && progress.Phase != "" {
							_, progressErr = fmt.Fprintln(output, "Progress:", progress.Phase)
						}
					})
					return result, progressErr == nil && writeRefusal(output, result) == nil && writeSetupCompletion(output, result) == nil
				case "", "n", "c":
					return cancelled, true
				case "b":
					step = 1
					if cloudflare {
						step = 3
					}
				default:
					if _, err := io.WriteString(output, "Enter y to apply, n to cancel, b to go back, or c to cancel.\n"); err != nil {
						return cancelled, false
					}
					continue
				}
				break
			}
			continue
		}
		line, ok := readSetupInput(reader, output, prompt)
		if !ok {
			return cancelled, false
		}
		if line == "c" {
			return cancelled, true
		}
		switch step {
		case 1:
			switch line {
			case "h":
				if _, err := io.WriteString(output, "Standard uses VLESS REALITY Vision for a direct connection to this server. It needs no domain.\nStandard + Cloudflare adds VMess over WebSocket/TLS through your own dedicated Cloudflare Tunnel. Both share one client identity. Cloudflare account and DNS preparation stay in your hands.\n"); err != nil {
					return cancelled, false
				}
			case "", "1", "2":
				if line == "2" && !supportsCloudflare {
					if _, err := io.WriteString(output, "Choose a displayed connection number, h for help, or c to cancel.\n"); err != nil {
						return cancelled, false
					}
					continue
				}
				if line != "" {
					cloudflare = line == "2"
				}
				step = 4
				if cloudflare {
					step = 2
				}
			default:
				if _, err := io.WriteString(output, "Choose a displayed connection number, h for help, or c to cancel.\n"); err != nil {
					return cancelled, false
				}
			}
		case 2:
			if line == "b" {
				step = 1
			} else if line == "" {
				step = 3
			} else if _, err := io.WriteString(output, "Press Enter to continue, b to go back, or c to cancel.\n"); err != nil {
				return cancelled, false
			}
		case 3:
			if line == "b" {
				step = 2
				continue
			}
			if line == "" {
				line = hostname
			}
			if !singboxadapter.ValidVMessHostname(line) {
				if _, err := io.WriteString(output, "Use a lowercase DNS hostname such as proxy.example.com. Remove any scheme, port, path or spaces; IP addresses are not hostnames. Never enter a token here.\n"); err != nil {
					return cancelled, false
				}
				continue
			}
			hostname, step = line, 4
		}
	}
}

func readSetupInput(reader *bufio.Reader, output io.Writer, prompt string) (string, bool) {
	for {
		if _, err := fmt.Fprintln(output, prompt); err != nil {
			return "", false
		}
		line, err := readLine(reader)
		if errors.Is(err, errInputTooLong) {
			if _, err := io.WriteString(output, "Input is too long. Enter a short choice or hostname; never paste a token here.\n"); err != nil {
				return "", false
			}
			continue
		}
		if err == io.EOF {
			return "c", true
		}
		return line, err == nil
	}
}

func writeSetupCompletion(output io.Writer, result proxyinstallation.Result) error {
	var message string
	switch result.Code {
	case proxyinstallation.SetupComplete:
		message = "Installed: Standard proxy is locally verified. A fresh outside-client connection test has not passed here."
	case proxyinstallation.VMessConnectionReady:
		message = "Installed: local proxy setup complete. Fresh Cloudflare connection test: passed from this server. Outside-client and Karing tests are still needed."
	case proxyinstallation.VMessConnectionPending:
		if result.Status == proxyinstallation.Running {
			message = "Installed: local proxy setup complete. Fresh Cloudflare connection test: pending. Check the correction above, DNS, tunnel health, edge TLS and the route to http://127.0.0.1:10000 (blank path). Then choose Check VMess connection to retry; do not reinstall."
		} else {
			message = "Connection test pending: local runtime could not be verified. Use View details and follow the correction above before retrying Check VMess connection."
		}
	case proxyinstallation.SetupNeedsCompletion:
		message = "Setup is incomplete. Follow the correction above, then choose Finish setup."
	case proxyinstallation.SetupNeedsCleanup:
		message = "Setup is incomplete. Follow the correction above, then choose Finish cleanup before trying setup again."
	default:
		return nil
	}
	if _, err := fmt.Fprintln(output, message); err != nil {
		return err
	}
	if result.Status == proxyinstallation.Running {
		_, err := fmt.Fprintln(output, "Next: choose Enable subscription for an import link, or Show client configuration for manual import.\nImport the link or configuration in your client (for example Karing), then test a connection from your outside network. Keep these values private. A local check does not prove Karing works.")
		return err
	}
	return nil
}
