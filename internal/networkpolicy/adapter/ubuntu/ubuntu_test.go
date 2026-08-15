package ubuntu

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

func TestReadOnlyFirewallPlanningUsesOnlyFixedCachedSudoCommands(t *testing.T) {
	for command, path := range map[string]string{"nft": "/usr/sbin/nft", "iptables-save": "/usr/sbin/iptables-save", "ip6tables-save": "/usr/sbin/ip6tables-save"} {
		cmd, err := sudoReadOnlyFirewallCommand(command, "-j", "list", "ruleset")
		want := []string{"/usr/bin/sudo", "-n", "--", path, "-j", "list", "ruleset"}
		if err != nil || !slices.Equal(cmd.Args, want) {
			t.Fatalf("%s planning command = %v, %v", command, cmd.Args, err)
		}
	}
	if _, err := sudoReadOnlyFirewallCommand("systemctl", "stop", "ufw.service"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("mutating planning command accepted: %v", err)
	}
}

func TestProductionAdapterKeepsSSHObservationOutsideCachedSudo(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "home", "owner", ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("ssh-ed25519 fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"proc/net/tcp":  "  sl  local_address rem_address   st\n   0: 146433C6:0016 0A7100CB:C350 01\n   1: 146433C6:0016 0B7100CB:C351 01\n",
		"proc/net/tcp6": "  sl  local_address rem_address   st\n",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	adapter := New()
	adapter.root = root
	adapter.firewallOutput = func(string, ...string) ([]byte, error) { return nil, os.ErrPermission }
	adapter.output = func(command string, arguments ...string) ([]byte, error) {
		switch command + " " + strings.Join(arguments, " ") {
		case "systemctl is-active ssh.service":
			return []byte("active\n"), nil
		case "systemctl is-active sshd.service":
			return []byte("inactive\n"), nil
		case "getent passwd owner":
			return []byte("owner:x:1000:1000::/home/owner:/bin/bash\n"), nil
		default:
			return nil, os.ErrNotExist
		}
	}
	t.Setenv("SBXR_SSH_CONNECTION", "203.0.113.10 50000 198.51.100.20 22")
	t.Setenv("SUDO_USER", "owner")
	facts := adapter.sshFacts()
	wantSession := fmt.Sprintf("%x", sha256.Sum256([]byte("203.0.113.10 50000 198.51.100.20 22")))
	if facts.Service != "ssh.service" || facts.Listener != "" || !facts.SessionsComplete || facts.AuthorizedKeysPath != "/home/owner/.ssh/authorized_keys" || len(facts.AuthorizedKeysSHA256) != 64 || len(facts.CurrentSessions) != 2 || facts.CurrentSessions[0] != wantSession {
		t.Fatal("SSH facts were incomplete or did not contain only digests")
	}
}

func TestObservedSSHListenerRequiresIndependentSocketOwnership(t *testing.T) {
	facts := networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "203.0.113.10", Service: "ssh.service"}
	listener := networkpolicy.Listener{Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP, Process: "sshd", Service: "ssh.service"}
	if got := observedSSHListener([]networkpolicy.Listener{listener}, facts); got != "0.0.0.0:2222/tcp" {
		t.Fatalf("observed SSH listener = %q", got)
	}
	for _, changed := range []networkpolicy.Listener{{Address: "0.0.0.0", Port: 22, Protocol: networkpolicy.TCP, Service: "ssh.service"}, {Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP, Service: "other.service"}, {Address: "127.0.0.1", Port: 2222, Protocol: networkpolicy.TCP, Service: "ssh.service"}} {
		if got := observedSSHListener([]networkpolicy.Listener{changed}, facts); got != "" {
			t.Fatalf("contradictory SSH listener accepted: %q", got)
		}
	}
}

func TestAdapterCollectsTypedFactsWithoutMutation(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":                        "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
		"var/lib/dpkg/status":                   "Package: ubuntu-server\nStatus: install ok installed\n\nPackage: xray\nStatus: install ok installed\nVersion: 1.2.3\n\nPackage: nginx\nStatus: install ok installed\nVersion: 1.24.0\n\n",
		"var/lib/dpkg/info/ubuntu-server.list":  "/usr/share/doc/ubuntu-server/copyright\n",
		"var/lib/dpkg/info/xray.list":           "/usr/local/bin/xray\n/usr/share/doc/xray/copyright\n",
		"var/lib/dpkg/info/nginx.list":          "/usr/sbin/nginx\n/usr/share/doc/nginx/copyright\n",
		"etc/passwd":                            "xray:x:997:997::/nonexistent:/usr/sbin/nologin\n",
		"etc/group":                             "xray:x:997:\n",
		"proc/self/mountinfo":                   "",
		"proc/meminfo":                          "MemTotal:        1048576 kB\nSwapTotal:       8388608 kB\n",
		"proc/net/tcp":                          "  sl  local_address rem_address   st tx_queue tr tm->when retrnsmt uid timeout inode\n   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 4242\n",
		"proc/net/tcp6":                         "  sl  local_address rem_address   st\n   0: 00000000000000000000000001000000:2B48 00000000000000000000000000000000:0000 0A\n",
		"proc/net/udp":                          "  sl  local_address rem_address   st tx_queue tr tm->when retrnsmt uid timeout inode\n   0: 0100007F:3039 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 5252\n",
		"proc/net/udp6":                         "  sl  local_address rem_address   st\n",
		"proc/net/route":                        "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 010200C0 0003 0 0 0 00000000\n",
		"proc/net/ipv6_route":                   "",
		"proc/123/comm":                         "nginx\n",
		"proc/123/cgroup":                       "0::/system.slice/nginx.service\n",
		"proc/sys/net/ipv4/ip_local_port_range": "32768 60999\n",
		"sys/class/dmi/id/product_name":         "Fixture Hypervisor\n",
		"usr/local/bin/xray":                    "inactive proxy remnant\n",
		"usr/sbin/nginx":                        "active web server\n",
		"proc/125/comm":                         "python3\n",
		"proc/125/cgroup":                       "0::/system.slice/proxy.service\n",
		"proc/125/cmdline":                      "/opt/shared/python\x00/opt/app/server.py\x00",
		"opt/shared/python":                     "shared interpreter\n",
		"opt/app/server.py":                     "print('proxy')\n",
	}
	for name, data := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "usr/local/bin/xray"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "usr/sbin/nginx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "opt/shared/python"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc/123/fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[4242]", filepath.Join(root, "proc/123/fd/4")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/sbin/nginx", filepath.Join(root, "proc/123/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc/124"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/124/comm"), []byte("xray\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/124/cgroup"), []byte("0::/system.slice/xray.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/local/bin/xray", filepath.Join(root, "proc/124/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc/125/fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[5252]", filepath.Join(root, "proc/125/fd/5")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/shared/python", filepath.Join(root, "proc/125/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent := strconv.Itoa(os.Getppid())
	if err := os.MkdirAll(filepath.Join(root, "proc", parent), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/custom/nu", filepath.Join(root, "proc", parent, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", parent, "stat"), []byte(parent+" (nu) S 1 0 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	candidateIntent := networkpolicy.Intent{
		PublicIPv4:       "192.0.2.10",
		PublicIPv6:       "2001:db8::10",
		SSHPort:          2222,
		SubscriptionPort: 10443,
		Profiles: networkpolicy.Profiles{
			TUIC:   networkpolicy.Profile{Enabled: true, Port: 8443},
			AnyTLS: networkpolicy.Profile{Enabled: true, Port: 9443},
		},
	}
	observed, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Intent: candidateIntent, Stage: networkpolicy.PreApproval, ReclamationReview: true})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Host.UbuntuVersion != "24.04" || !observed.Host.Systemd || observed.Host.LogicalCPUs < 1 || observed.Host.PhysicalRAM != 1<<30 || observed.Host.Virtualization != "Fixture Hypervisor" {
		t.Fatalf("host facts = %+v", observed.Host)
	}
	if len(observed.Listeners) != 3 || observed.Listeners[0].Port != 443 || observed.Listeners[0].Protocol != networkpolicy.TCP || observed.Listeners[0].Process != "nginx" || observed.Listeners[0].Service != "nginx.service" || observed.Listeners[0].Executable != "/usr/sbin/nginx" || observed.Listeners[1].Address != "::1" || observed.Listeners[1].Port != 11080 || observed.Listeners[2].Process != "python3" || observed.Listeners[2].Executable != "/opt/shared/python" || observed.Ephemeral != (networkpolicy.PortRange{First: 32768, Last: 60999}) {
		t.Fatalf("network facts = listeners %+v ephemeral %+v", observed.Listeners, observed.Ephemeral)
	}
	if len(observed.PortCandidates) == 0 {
		t.Fatal("Adapter returned no real bind-proven candidates")
	}
	for _, candidate := range observed.PortCandidates {
		if candidate.Port < 1024 || candidate.Port == 2222 || candidate.Port == 80 || candidate.Port == 443 || candidate.Port == 8443 || candidate.Port == 9443 || candidate.Port == 10443 || candidate.Port == 11080 || observed.Ephemeral.First <= candidate.Port && candidate.Port <= observed.Ephemeral.Last || !candidate.BindProven || !candidate.Cryptographic {
			t.Fatalf("unsafe candidate = %+v", candidate)
		}
		address := candidate.Address
		if address == "public" {
			address = "0.0.0.0"
		}
		if candidate.Protocol == networkpolicy.UDP {
			packet, bindErr := net.ListenPacket("udp", net.JoinHostPort(address, fmt.Sprint(candidate.Port)))
			if bindErr != nil {
				t.Fatalf("candidate no longer UDP bindable: %+v: %v", candidate, bindErr)
			}
			packet.Close()
		} else {
			listener, bindErr := net.Listen("tcp", net.JoinHostPort(address, fmt.Sprint(candidate.Port)))
			if bindErr != nil {
				t.Fatalf("candidate no longer TCP bindable: %+v: %v", candidate, bindErr)
			}
			listener.Close()
		}
	}
	if len(observed.ResourcePaths) != 1 || observed.ResourcePaths[0] != "/usr/local/bin/xray" {
		t.Fatalf("proxy remnants = %+v", observed.ResourcePaths)
	}
	if len(observed.Reclamation.Executables) != 2 || observed.Reclamation.Executables[0].SHA256 == "" || observed.Reclamation.Executables[0].Package != "xray" || observed.Reclamation.Executables[0].Process != "xray" || observed.Reclamation.Executables[0].Service != "xray.service" || observed.Reclamation.Executables[1].Path != "/usr/sbin/nginx" || observed.Reclamation.Executables[1].SHA256 == "" || observed.Reclamation.Executables[1].Package != "nginx" || observed.Reclamation.Executables[1].Process != "nginx" || len(observed.Reclamation.Packages) != 2 || observed.Reclamation.Packages[0].Version != "1.2.3" || len(observed.Reclamation.Packages[0].OwnedPaths) != 2 || len(observed.Reclamation.Identities) != 0 {
		t.Fatalf("reclamation facts = %+v", observed.Reclamation)
	}
	if len(observed.Reclamation.Scripts) != 1 || observed.Reclamation.Scripts[0].Path != "/opt/app/server.py" || observed.Reclamation.Scripts[0].ProcessID != "125" || observed.Listeners[2].ProcessID != "125" || !slices.Contains(observed.Reclamation.ProtectedPaths, "/opt/shared/python") || !slices.Contains(observed.Reclamation.ProtectedPaths, "/opt/custom/nu") || slices.ContainsFunc(observed.Reclamation.Executables, func(file networkpolicy.FileConflict) bool { return file.Path == "/opt/shared/python" }) {
		t.Fatalf("script interpreter was not protected: %+v", observed.Reclamation)
	}
	if observed.Firewall.RootVerified {
		t.Fatal("unprivileged fixture observation guessed root-only nftables facts")
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("adapter mutated %s", name)
		}
	}
	if target, err := os.Readlink(filepath.Join(root, "proc/123/fd/4")); err != nil || target != "socket:[4242]" {
		t.Fatalf("Adapter mutated socket ownership link: target %q error %v", target, err)
	}
	if err := os.Remove(filepath.Join(root, "proc/sys/net/ipv4/ip_local_port_range")); err != nil {
		t.Fatal(err)
	}
	withoutRange, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PreApproval})
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutRange.PortCandidates) != 0 {
		t.Fatal("Adapter guessed safe alternatives without the host ephemeral range")
	}
	if err := os.WriteFile(filepath.Join(root, "proc/sys/net/ipv4/ip_local_port_range"), []byte("32768 60999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nftables := `{"nftables":[{"table":{"family":"inet","name":"sbxr"}},{"chain":{"family":"inet","table":"filter","name":"input","hook":"input"}}]}`
	adapter := Adapter{root: root, privileged: true, output: func(command string, _ ...string) ([]byte, error) {
		switch command {
		case "nft":
			return []byte(nftables), nil
		case "iptables-save", "ip6tables-save":
			return []byte{}, nil
		default:
			return nil, os.ErrNotExist
		}
	}}
	privileged, err := adapter.Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PostApproval})
	if err != nil {
		t.Fatal(err)
	}
	if !privileged.Firewall.RootVerified || privileged.Firewall.SBXRTableState != "present" || privileged.Firewall.UnexpectedRule != `manager "nftables"; service "nftables"; table "filter"; chain "input"; rule "base chain hook input"` || privileged.Checksums["sbxr_nftables"] == "" {
		t.Fatalf("typed nftables facts = %+v checksums %+v", privileged.Firewall, privileged.Checksums)
	}
	ownedOnly := `{"nftables":[{"table":{"family":"inet","name":"sbxr"}}]}`
	adapter.output = func(command string, _ ...string) ([]byte, error) {
		switch command {
		case "nft":
			return []byte(ownedOnly), nil
		case "iptables-save":
			return []byte("-A INPUT -s 198.51.100.7 -p tcp --dport 22 -j DROP -m comment --comment private-note\n"), nil
		case "ip6tables-save":
			return []byte{}, nil
		default:
			return nil, os.ErrNotExist
		}
	}
	legacy, err := adapter.Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PostApproval})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Firewall.UnexpectedRule != `manager "legacy iptables"; service "iptables-save"; table "filter"; chain "INPUT"; rule "-A INPUT -p tcp --dport 22 -j DROP"` {
		t.Fatalf("legacy firewall fact = %+v", legacy.Firewall)
	}
	foreignSameName := `{"nftables":[{"table":{"family":"ip","name":"sbxr"}},{"chain":{"family":"ip","table":"sbxr","name":"input","hook":"input"}}]}`
	adapter.output = func(command string, _ ...string) ([]byte, error) {
		if command == "nft" {
			return []byte(foreignSameName), nil
		}
		return []byte{}, nil
	}
	foreign, err := adapter.Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PostApproval})
	if err != nil {
		t.Fatal(err)
	}
	if foreign.Firewall.UnexpectedRule != `manager "nftables"; service "nftables"; table "sbxr"; chain "input"; rule "base chain hook input"` {
		t.Fatalf("foreign same-name table was treated as SBXR-owned: %+v", foreign.Firewall)
	}
	adapter.output = func(command string, _ ...string) ([]byte, error) {
		if command == "ip6tables-save" {
			return nil, os.ErrPermission
		}
		if command == "nft" {
			return []byte(ownedOnly), nil
		}
		return []byte{}, nil
	}
	incomplete, err := adapter.Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PostApproval})
	if err != nil {
		t.Fatal(err)
	}
	if incomplete.Firewall.RootVerified {
		t.Fatal("partial legacy-firewall inspection was marked root-verified")
	}
	unprivileged := adapter
	unprivileged.privileged = false
	guessed, err := unprivileged.Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PostApproval})
	if err != nil {
		t.Fatal(err)
	}
	if guessed.Firewall.RootVerified {
		t.Fatal("unprivileged command output was marked root-verified")
	}
	addressAdapter := NewAt(root)
	addressAdapter.addresses = func() ([]net.Addr, error) {
		return []net.Addr{
			cidr(t, "8.8.8.8/32"), cidr(t, "100.64.0.1/32"), cidr(t, "192.0.2.10/32"), cidr(t, "10.0.0.1/32"),
			cidr(t, "2001:4860:4860::8888/128"), cidr(t, "2001:db8::10/128"), cidr(t, "fd00::1/128"),
		}, nil
	}
	qualified, err := addressAdapter.Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PreApproval})
	if err != nil {
		t.Fatal(err)
	}
	if len(qualified.PublicIPv4) != 1 || qualified.PublicIPv4[0] != "8.8.8.8" || len(qualified.PublicIPv6) != 1 || qualified.PublicIPv6[0] != "2001:4860:4860::8888" {
		t.Fatalf("qualified public addresses = IPv4 %v IPv6 %v", qualified.PublicIPv4, qualified.PublicIPv6)
	}
	parentStat := filepath.Join(root, "proc", parent, "stat")
	if err := os.Remove(parentStat); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PreApproval, ReclamationReview: true}); err == nil {
		t.Fatal("unreadable current-shell ancestry was marked complete")
	}
	if err := os.WriteFile(parentStat, []byte(parent+" (nu) S 1 0 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "opt/app/server.py")
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/sbin/nginx", script); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PreApproval, ReclamationReview: true}); err == nil {
		t.Fatal("symlink script target was accepted")
	}
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("print('proxy')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmdline := filepath.Join(root, "proc/125/cmdline")
	for name, arguments := range map[string]string{
		"evaluation":    "/opt/shared/python\x00-c\x00exec(open('/opt/app/server.py').read())\x00",
		"module":        "/opt/shared/python\x00-m\x00server\x00",
		"extra wrapper": "/opt/shared/python\x00/opt/app/server.py\x00--wrapped\x00",
		"relative":      "/opt/shared/python\x00server.py\x00",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(cmdline, []byte(arguments), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PreApproval, ReclamationReview: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Reclamation.Scripts) != 0 {
				t.Fatalf("ambiguous script form accepted: %+v", got.Reclamation.Scripts)
			}
		})
	}
	if err := os.WriteFile(cmdline, []byte("/opt/shared/python\x00/opt/app/server.py\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "var/lib/dpkg/info/nginx.list")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PreApproval, ReclamationReview: true}); err == nil {
		t.Fatal("incomplete package ownership was marked as a complete reclamation inventory")
	}
}

func TestStableRegularDigestRefusesPathReplacementDuringRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "target")
	if err := os.WriteFile(path, []byte("original"), 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := Adapter{afterFirstDigest: func(name string) {
		if err := os.Rename(name, name+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("replacement"), 0o700); err != nil {
			t.Fatal(err)
		}
	}}
	if _, _, err := adapter.stableRegularDigest(path); err == nil {
		t.Fatal("path replacement retained an executable digest")
	}
}

func TestAdapterUsesRealDNSAndVerifiedHTTPSWithoutCredentials(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"etc/os-release":                       "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
		"etc/passwd":                           "root:x:0:0:root:/root:/bin/bash\n",
		"etc/group":                            "root:x:0:\n",
		"var/lib/dpkg/status":                  "Package: ubuntu-server\nStatus: install ok installed\n\n",
		"var/lib/dpkg/info/ubuntu-server.list": "/usr/share/doc/ubuntu-server/copyright\n",
		"proc/meminfo":                         "MemTotal:        1048576 kB\n",
		"proc/self/mountinfo":                  "",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	adapter := NewAt(root)
	adapter.external = true
	adapter.addresses = func() ([]net.Addr, error) { return nil, nil }
	observed, err := adapter.Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PreApproval})
	if err != nil {
		t.Fatal(err)
	}
	if !observed.Outbound.DNS || !observed.Outbound.GitHubHTTPS || !observed.Outbound.GitHubAttestationHTTPS || !observed.Outbound.CloudflareHTTPS || !observed.Outbound.ACMEHTTPS || !observed.Outbound.CertificateEndpointsHTTPS {
		t.Fatalf("real DNS/verified HTTPS seam = %+v", observed.Outbound)
	}
}

func cidr(t *testing.T, value string) net.Addr {
	t.Helper()
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	network.IP = ip
	return network
}

func TestProductionUbuntuSeam(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controlled production Adapter Seam check requires Ubuntu")
	}
	if os.Geteuid() != 0 {
		t.Skip("controlled production nftables inspection requires the Owner root seam")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatal("production Ubuntu seam requires nft")
	}
	t.Setenv("SBXR_SSH_CONNECTION", "198.51.100.2 12345 192.0.2.10 2222")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	observed, err := New().Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PostApproval})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Host.UbuntuVersion == "" || observed.Host.Architecture == "" || observed.Host.LogicalCPUs < 1 || observed.Host.PhysicalRAM == 0 {
		t.Fatalf("production Ubuntu facts incomplete: %+v", observed.Host)
	}
	if observed.Routes.IPv4 == "" && observed.Routes.IPv6 == "" {
		t.Fatal("production Ubuntu route observation is empty")
	}
	if !observed.Firewall.RootVerified {
		t.Fatal("production Ubuntu nftables inspection was not root-verified")
	}
	foundSocket := false
	for _, found := range observed.Listeners {
		if found.Address == "127.0.0.1" && found.Port == port && found.Protocol == networkpolicy.TCP {
			if found.Process == "" {
				t.Fatal("temporary production socket omitted its process identity")
			}
			foundSocket = true
			break
		}
	}
	if !foundSocket {
		t.Fatalf("temporary production socket 127.0.0.1:%d/TCP was not observed", port)
	}
	if observed.SSH.DetectedPort != 2222 || observed.SSH.ServerAddress != "192.0.2.10" || len(observed.SSH.CurrentSessions) == 0 {
		t.Fatal("controlled production SSH-session facts were incomplete")
	}
	if !observed.Outbound.DNS || !observed.Outbound.GitHubHTTPS || !observed.Outbound.GitHubAttestationHTTPS || !observed.Outbound.CloudflareHTTPS || !observed.Outbound.ACMEHTTPS || !observed.Outbound.CertificateEndpointsHTTPS {
		t.Fatalf("production DNS/verified HTTPS facts = %+v", observed.Outbound)
	}
	result := networkpolicy.New(candidateAdapter{}).Evaluate(networkpolicy.Request{Intent: productionCandidateIntent(), Stage: networkpolicy.PostApproval})
	if result.Policy.Nftables == "" {
		t.Fatal("production native validation received an empty candidate")
	}
	command := exec.Command("nft", "--check", "--file", "-")
	command.Stdin = strings.NewReader(result.Policy.Nftables)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native candidate validation failed without Apply: %v: %s", err, output)
	}
}

type candidateAdapter struct{}

func (candidateAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return networkpolicy.Observations{
		PublicIPv4: []string{"192.0.2.10"},
		SSH:        networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "192.0.2.10", CurrentSessions: []string{"current"}},
		Firewall:   networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true},
		Certificate: networkpolicy.CertificateFacts{
			DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com", IPv4: []string{"192.0.2.10"}},
			CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true},
		},
		Checksums: map[string]string{},
	}, nil
}

func productionCandidateIntent() networkpolicy.Intent {
	return networkpolicy.Intent{
		Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10", CertificateHostname: "direct.example.com", SSHPort: 2222, SubscriptionPort: 10443,
		Profiles: networkpolicy.Profiles{
			VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443},
			VLESSXHTTP:         networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080},
			VLESSWebSocket:     networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081},
			Hysteria2:          networkpolicy.Profile{Port: 443},
			TUIC:               networkpolicy.Profile{Port: 8443},
			AnyTLS:             networkpolicy.Profile{Port: 9443},
		},
	}
}
