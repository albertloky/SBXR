package ubuntu

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

func TestAdapterCollectsTypedFactsWithoutMutation(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":                        "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
		"var/lib/dpkg/status":                   "Package: ubuntu-server\nStatus: install ok installed\n\n",
		"proc/meminfo":                          "MemTotal:        1048576 kB\nSwapTotal:       8388608 kB\n",
		"proc/net/tcp":                          "  sl  local_address rem_address   st\n   0: 00000000:01BB 00000000:0000 0A\n",
		"proc/net/tcp6":                         "  sl  local_address rem_address   st\n   0: 00000000000000000000000001000000:2B48 00000000000000000000000000000000:0000 0A\n",
		"proc/net/udp":                          "  sl  local_address rem_address   st\n",
		"proc/net/udp6":                         "  sl  local_address rem_address   st\n",
		"proc/net/route":                        "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 010200C0 0003 0 0 0 00000000\n",
		"proc/net/ipv6_route":                   "",
		"proc/sys/net/ipv4/ip_local_port_range": "32768 60999\n",
		"sys/class/dmi/id/product_name":         "Fixture Hypervisor\n",
		"usr/local/bin/xray":                    "inactive proxy remnant\n",
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
	if err := os.MkdirAll(filepath.Join(root, "run/systemd/system"), 0o700); err != nil {
		t.Fatal(err)
	}

	observed, err := NewAt(root).Observe(networkpolicy.ObservationRequest{Intent: networkpolicy.Intent{SSHPort: 2222}, Stage: networkpolicy.PreApproval})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Host.UbuntuVersion != "24.04" || !observed.Host.Systemd || observed.Host.LogicalCPUs < 1 || observed.Host.PhysicalRAM != 1<<30 || observed.Host.Virtualization != "Fixture Hypervisor" {
		t.Fatalf("host facts = %+v", observed.Host)
	}
	if len(observed.Listeners) != 2 || observed.Listeners[0].Port != 443 || observed.Listeners[0].Protocol != networkpolicy.TCP || observed.Listeners[1].Address != "::1" || observed.Listeners[1].Port != 11080 || observed.Ephemeral != (networkpolicy.PortRange{First: 32768, Last: 60999}) {
		t.Fatalf("network facts = listeners %+v ephemeral %+v", observed.Listeners, observed.Ephemeral)
	}
	if len(observed.ResourcePaths) != 1 || observed.ResourcePaths[0] != "/usr/local/bin/xray" {
		t.Fatalf("proxy remnants = %+v", observed.ResourcePaths)
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
	if !privileged.Firewall.RootVerified || privileged.Firewall.SBXRTableState != "present" || privileged.Firewall.UnexpectedRule == "" || privileged.Checksums["sbxr_nftables"] == "" {
		t.Fatalf("typed nftables facts = %+v checksums %+v", privileged.Firewall, privileged.Checksums)
	}
	ownedOnly := `{"nftables":[{"table":{"family":"inet","name":"sbxr"}}]}`
	adapter.output = func(command string, _ ...string) ([]byte, error) {
		switch command {
		case "nft":
			return []byte(ownedOnly), nil
		case "iptables-save":
			return []byte("-A INPUT -j DROP\n"), nil
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
	if legacy.Firewall.UnexpectedRule != "unexpected legacy iptables rule" {
		t.Fatalf("legacy firewall fact = %+v", legacy.Firewall)
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
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	observed, err := New().Observe(networkpolicy.ObservationRequest{Stage: networkpolicy.PreApproval})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Host.UbuntuVersion == "" || observed.Host.Architecture == "" || observed.Host.LogicalCPUs < 1 || observed.Host.PhysicalRAM == 0 {
		t.Fatalf("production Ubuntu facts incomplete: %+v", observed.Host)
	}
	if observed.Routes.IPv4 == "" && observed.Routes.IPv6 == "" {
		t.Fatal("production Ubuntu route observation is empty")
	}
	for _, found := range observed.Listeners {
		if found.Address == "127.0.0.1" && found.Port == port && found.Protocol == networkpolicy.TCP {
			return
		}
	}
	t.Fatalf("temporary production socket 127.0.0.1:%d/TCP was not observed", port)
}
