// Package ubuntu supplies the Network Policy Module's one read-only host Adapter.
package ubuntu

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

type Adapter struct {
	root       string
	external   bool
	privileged bool
	output     func(string, ...string) ([]byte, error)
	addresses  func() ([]net.Addr, error)
}

func New() Adapter { return Adapter{root: "/", external: true, privileged: os.Geteuid() == 0} }

// NewAt creates the same read-only Adapter over a controlled filesystem seam.
func NewAt(root string) Adapter { return Adapter{root: root} }

func (a Adapter) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	if request.Scope == networkpolicy.ExternalObservations {
		if !a.external {
			return networkpolicy.Observations{}, nil
		}
		return networkpolicy.Observations{Outbound: outboundFacts(timeFacts().Synchronized)}, nil
	}
	version, err := a.ubuntuVersion()
	if err != nil {
		return networkpolicy.Observations{}, err
	}
	memory, err := a.physicalRAM()
	if err != nil {
		return networkpolicy.Observations{}, err
	}
	observed := networkpolicy.Observations{
		Host: networkpolicy.HostFacts{
			UbuntuVersion:  version,
			UbuntuServer:   a.ubuntuServer(),
			Architecture:   runtime.GOARCH,
			Systemd:        isDirectory(a.path("/run/systemd/system")),
			LogicalCPUs:    runtime.NumCPU(),
			PhysicalRAM:    memory,
			Virtualization: strings.TrimSpace(readOptional(a.path("/sys/class/dmi/id/product_name"))),
		},
		Listeners:         a.listeners(),
		ServiceIdentities: a.serviceIdentities(),
		ResourcePaths:     a.resourcePaths(),
		SSH:               sshFacts(),
		Routes: networkpolicy.RouteFacts{
			IPv4: present(a.path("/proc/net/route")),
			IPv6: present(a.path("/proc/net/ipv6_route")),
		},
		Ephemeral: a.ephemeralRange(),
		Checksums: map[string]string{},
	}
	observed.Reclamation, err = a.reclamationFacts(observed.ResourcePaths, observed.Listeners)
	if err != nil {
		return networkpolicy.Observations{}, err
	}
	observed.ReclamationComplete = true
	observed.Disk = diskFacts(a.root)
	observed.Checksums["routes"] = checksumFiles(a.path("/proc/net/route"), a.path("/proc/net/ipv6_route"))
	observed.Checksums["listeners"] = checksumFiles(a.path("/proc/net/tcp"), a.path("/proc/net/tcp6"), a.path("/proc/net/udp"), a.path("/proc/net/udp6"))
	if a.external || a.addresses != nil {
		observed.PublicIPv4, observed.PublicIPv6 = a.publicAddresses()
	}
	if a.external {
		observed.Time = timeFacts()
		if request.Scope != networkpolicy.LocalObservations {
			observed.Outbound = outboundFacts(observed.Time.Synchronized)
		}
		observed.Firewall.ActiveManager = activeFirewallManager()
	}
	if request.Stage == networkpolicy.PostApproval && a.privileged {
		if rules, commandErr := a.privilegedOutput("nft", "-j", "list", "ruleset"); commandErr == nil {
			state, unexpected, sbxrChecksum, parseErr := inspectNftables(rules)
			if parseErr == nil {
				legacy, legacyErr := a.legacyIPTablesRule()
				if legacyErr == nil {
					observed.Firewall.RootVerified = true
					observed.Firewall.SBXRTableState = state
					observed.Firewall.UnexpectedRule = unexpected
					if observed.Firewall.UnexpectedRule == "" && legacy != "" {
						observed.Firewall.UnexpectedRule = legacy
					}
					observed.Checksums["nftables"] = checksum(rules)
					observed.Checksums["sbxr_nftables"] = sbxrChecksum
				}
			}
		}
	}
	observed.PortCandidates = availableCandidates(request.Intent, observed)
	return observed, nil
}

func (a Adapter) reclamationFacts(paths []string, listeners []networkpolicy.Listener) (networkpolicy.ReclamationFacts, error) {
	status, err := os.ReadFile(a.path("/var/lib/dpkg/status"))
	if err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	passwd, err := os.ReadFile(a.path("/etc/passwd"))
	if err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	group, err := os.ReadFile(a.path("/etc/group"))
	if err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	if _, err := os.ReadFile(a.path("/proc/self/mountinfo")); err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	facts := networkpolicy.ReclamationFacts{ProtectedPaths: a.currentShells()}
	processes, scripts, err := a.reclamationProcesses()
	if err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	facts.Scripts = scripts
	for _, listener := range listeners {
		if listener.Executable != "" && !slices.Contains(paths, listener.Executable) {
			paths = append(paths, listener.Executable)
		}
	}
	for _, paragraph := range strings.Split(string(status), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(paragraph, "\n") {
			if key, value, ok := strings.Cut(line, ": "); ok {
				fields[key] = value
			}
		}
		name := fields["Package"]
		if name == "" || fields["Status"] != "install ok installed" {
			continue
		}
		listName := name + ".list"
		if architecture := fields["Architecture"]; architecture != "" {
			if _, statErr := os.Stat(a.path("/var/lib/dpkg/info/" + name + ":" + architecture + ".list")); statErr == nil {
				listName = name + ":" + architecture + ".list"
			}
		}
		ownedData, readErr := os.ReadFile(a.path("/var/lib/dpkg/info/" + listName))
		if readErr != nil {
			return networkpolicy.ReclamationFacts{}, readErr
		}
		owned := strings.Fields(string(ownedData))
		for _, path := range paths {
			if slices.Contains(owned, path) {
				facts.Packages = append(facts.Packages, networkpolicy.PackageConflict{Name: name, Version: fields["Version"], Owns: path, OwnedPaths: append([]string(nil), owned...)})
				break
			}
		}
		if slices.Contains([]string{"docker.io", "docker-ce", "containerd.io"}, name) {
			if facts.Docker == nil {
				facts.Docker = &networkpolicy.DockerConflict{Service: "docker.service", Status: "installed", PreservedData: []string{"images", "volumes", "Compose definitions", "bind mounts", "application data"}}
			}
			facts.Docker.Packages = append(facts.Docker.Packages, name+" "+fields["Version"])
		}
	}
	for _, path := range paths {
		info, err := os.Lstat(a.path(path))
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || a.mountPoint(path) {
			facts.UnsafePaths = append(facts.UnsafePaths, path)
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		data, err := os.ReadFile(a.path(path))
		if err != nil {
			return networkpolicy.ReclamationFacts{}, err
		}
		stat, _ := info.Sys().(*syscall.Stat_t)
		file := networkpolicy.FileConflict{Path: path, SHA256: checksum(data), Mode: uint32(info.Mode().Perm()), Links: 1, Mount: a.mountPoint(path)}
		if owner, ok := processes[path]; ok {
			file.Process, file.Service = owner.process, owner.service
		}
		if stat != nil {
			file.OwnerUID, file.Links = stat.Uid, uint64(stat.Nlink)
		}
		for _, pkg := range facts.Packages {
			if pkg.Owns == path {
				file.Package = pkg.Name
			}
		}
		facts.Executables = append(facts.Executables, file)
	}
	for _, source := range []struct {
		data []byte
		kind string
	}{{passwd, "service user"}, {group, "service group"}} {
		for _, line := range strings.Split(string(source.data), "\n") {
			name, _, ok := strings.Cut(line, ":")
			if ok && slices.Contains([]string{"xray", "sing-box", "cloudflared", "sbxr"}, name) {
				facts.Identities = append(facts.Identities, networkpolicy.IdentityConflict{Name: name, Kind: source.kind})
			}
		}
	}
	return facts, nil
}

func (a Adapter) currentShells() []string {
	var shells []string
	pid := os.Getppid()
	for range 16 {
		base := filepath.Join("/proc", strconv.Itoa(pid))
		executable, err := os.Readlink(a.path(filepath.Join(base, "exe")))
		if err == nil && slices.Contains([]string{"sh", "bash", "dash", "zsh", "fish"}, filepath.Base(executable)) {
			shells = append(shells, executable)
		}
		stat := readOptional(a.path(filepath.Join(base, "stat")))
		end := strings.LastIndex(stat, ") ")
		if end < 0 {
			break
		}
		fields := strings.Fields(stat[end+2:])
		if len(fields) < 2 {
			break
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent <= 1 || parent == pid {
			break
		}
		pid = parent
	}
	return shells
}

func (a Adapter) reclamationProcesses() (map[string]socketOwner, []networkpolicy.ScriptConflict, error) {
	executables := map[string]socketOwner{}
	var scripts []networkpolicy.ScriptConflict
	processes, err := os.ReadDir(a.path("/proc"))
	if err != nil {
		return nil, nil, err
	}
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		base := filepath.Join("/proc", process.Name())
		name := strings.TrimSpace(readOptional(a.path(filepath.Join(base, "comm"))))
		service := ""
		for _, line := range strings.Split(readOptional(a.path(filepath.Join(base, "cgroup"))), "\n") {
			_, path, ok := strings.Cut(line, "::")
			if candidate := filepath.Base(path); ok && strings.HasSuffix(candidate, ".service") {
				service = candidate
				break
			}
		}
		executable, err := os.Readlink(a.path(filepath.Join(base, "exe")))
		if err == nil && filepath.IsAbs(executable) {
			executables[executable] = socketOwner{name, service, executable}
		}
		if !slices.Contains([]string{"sh", "bash", "dash", "python", "python3", "perl", "ruby", "node"}, filepath.Base(executable)) {
			continue
		}
		arguments := strings.Split(readOptional(a.path(filepath.Join(base, "cmdline"))), "\x00")
		if len(arguments) < 2 || !filepath.IsAbs(arguments[1]) {
			continue
		}
		data, readErr := os.ReadFile(a.path(arguments[1]))
		if readErr != nil {
			return nil, nil, readErr
		}
		links := uint64(1)
		if info, statErr := os.Lstat(a.path(arguments[1])); statErr == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				links = uint64(stat.Nlink)
			}
		}
		scripts = append(scripts, networkpolicy.ScriptConflict{Interpreter: executable, Path: arguments[1], SHA256: checksum(data), Process: name, Service: service, Links: links, Mount: a.mountPoint(arguments[1])})
	}
	return executables, scripts, nil
}

func (a Adapter) mountPoint(path string) bool {
	for _, line := range strings.Split(readOptional(a.path("/proc/self/mountinfo")), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == path {
			return true
		}
	}
	return false
}

func (a Adapter) ubuntuServer() bool {
	status := readOptional(a.path("/var/lib/dpkg/status"))
	for _, paragraph := range strings.Split(status, "\n\n") {
		if strings.Contains(paragraph, "Package: ubuntu-server\n") && strings.Contains(paragraph, "Status: install ok installed") {
			return true
		}
	}
	return strings.Contains(readOptional(a.path("/var/log/installer/media-info")), "Ubuntu-Server")
}

func (a Adapter) privilegedOutput(command string, arguments ...string) ([]byte, error) {
	if a.output != nil {
		return a.output(command, arguments...)
	}
	for _, directory := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(directory, command)
		if _, err := os.Stat(path); err == nil {
			return exec.Command(path, arguments...).Output()
		}
	}
	return nil, os.ErrNotExist
}

func (a Adapter) legacyIPTablesRule() (string, error) {
	for _, command := range []string{"iptables-save", "ip6tables-save"} {
		output, err := a.privilegedOutput(command)
		if err != nil {
			return "", err
		}
		table := "filter"
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "*") {
				table = strings.TrimPrefix(line, "*")
			}
			if strings.HasPrefix(line, "-A ") {
				fields := strings.Fields(line)
				chain := "unknown"
				if len(fields) > 1 {
					chain = fields[1]
				}
				return fmt.Sprintf("manager %q; service %q; table %q; chain %q; rule %q", "legacy iptables", command, table, chain, safeRule(line)), nil
			}
		}
	}
	return "", nil
}

func safeRule(rule string) string {
	fields := strings.Fields(rule)
	if len(fields) < 2 {
		return "legacy append rule present"
	}
	safe := fields[:2]
	for index := 2; index+1 < len(fields); index++ {
		switch fields[index] {
		case "-p", "--sport", "--dport", "--ctstate", "-j":
			safe = append(safe, fields[index], fields[index+1])
			index++
		}
	}
	return strings.Join(safe, " ")
}

func inspectNftables(data []byte) (state, unexpected, sbxrChecksum string, err error) {
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err = json.Unmarshal(data, &document); err != nil {
		return "", "", "", err
	}
	state = "absent"
	var owned []map[string]json.RawMessage
	for _, item := range document.Nftables {
		for kind, raw := range item {
			var identity struct {
				Family string          `json:"family"`
				Table  string          `json:"table"`
				Name   string          `json:"name"`
				Hook   json.RawMessage `json:"hook"`
			}
			if decodeErr := json.Unmarshal(raw, &identity); decodeErr != nil {
				return "", "", "", decodeErr
			}
			table := identity.Table
			if kind == "table" {
				table = identity.Name
			}
			if identity.Family == "inet" && table == "sbxr" {
				state = "present"
				owned = append(owned, item)
			}
			if kind == "chain" && len(identity.Hook) > 0 && (identity.Family != "inet" || table != "sbxr") && unexpected == "" {
				var hook string
				_ = json.Unmarshal(identity.Hook, &hook)
				unexpected = fmt.Sprintf("manager %q; service %q; table %q; chain %q; rule %q", "nftables", "nftables", table, identity.Name, "base chain hook "+hook)
			}
		}
	}
	encoded, _ := json.Marshal(owned)
	return state, unexpected, checksum(encoded), nil
}

func (a Adapter) resourcePaths() []string {
	var found []string
	for _, path := range []string{
		"/var/lib/sbxr", "/etc/sbxr", "/usr/local/bin/sbxr", "/usr/bin/sbxr",
		"/etc/xray", "/usr/local/etc/xray", "/usr/local/bin/xray", "/usr/bin/xray",
		"/etc/sing-box", "/usr/local/etc/sing-box", "/usr/local/bin/sing-box", "/usr/bin/sing-box",
		"/etc/cloudflared", "/usr/local/etc/cloudflared", "/usr/local/bin/cloudflared", "/usr/bin/cloudflared",
	} {
		if _, err := os.Lstat(a.path(path)); err == nil {
			found = append(found, path)
		}
	}
	return found
}

func (a Adapter) serviceIdentities() []string {
	var found []string
	for _, service := range []string{"xray.service", "sing-box.service", "cloudflared.service", "sbxr-subscription.service"} {
		for _, directory := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
			if _, err := os.Lstat(a.path(filepath.Join(directory, service))); err == nil {
				found = append(found, service)
				break
			}
		}
	}
	processes, _ := os.ReadDir(a.path("/proc"))
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		name := strings.TrimSpace(readOptional(a.path(filepath.Join("/proc", process.Name(), "comm"))))
		if name == "xray" || name == "sing-box" || name == "cloudflared" || strings.HasPrefix(name, "sbxr") {
			found = append(found, "process:"+name)
		}
	}
	return found
}

func (a Adapter) path(name string) string {
	return filepath.Join(a.root, strings.TrimPrefix(name, "/"))
}

func (a Adapter) ubuntuVersion() (string, error) {
	file, err := os.Open(a.path("/etc/os-release"))
	if err != nil {
		return "", err
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			values[key] = strings.Trim(value, "\"")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return values["VERSION_ID"], nil
}

func (a Adapter) physicalRAM() (uint64, error) {
	file, err := os.Open(a.path("/proc/meminfo"))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kilobytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
			return kilobytes << 10, parseErr
		}
	}
	return 0, scanner.Err()
}

func (a Adapter) listeners() []networkpolicy.Listener {
	var listeners []networkpolicy.Listener
	owners := a.socketOwners()
	for _, source := range []struct {
		name     string
		protocol networkpolicy.Protocol
	}{
		{"/proc/net/tcp", networkpolicy.TCP},
		{"/proc/net/tcp6", networkpolicy.TCP},
		{"/proc/net/udp", networkpolicy.UDP},
		{"/proc/net/udp6", networkpolicy.UDP},
	} {
		file, err := os.Open(a.path(source.name))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || !strings.Contains(fields[1], ":") || source.protocol == networkpolicy.TCP && fields[3] != "0A" {
				continue
			}
			address, portText, _ := strings.Cut(fields[1], ":")
			port, parseErr := strconv.ParseUint(portText, 16, 16)
			if parseErr == nil {
				owner := socketOwner{}
				if len(fields) > 9 {
					owner = owners[fields[9]]
				}
				listeners = append(listeners, networkpolicy.Listener{Address: procAddress(address), Port: uint16(port), Protocol: source.protocol, Process: owner.process, Service: owner.service, Executable: owner.executable, Ownership: networkpolicy.Unproved})
			}
		}
		file.Close()
	}
	return listeners
}

type socketOwner struct{ process, service, executable string }

func (a Adapter) socketOwners() map[string]socketOwner {
	owners := map[string]socketOwner{}
	processes, _ := os.ReadDir(a.path("/proc"))
	for _, process := range processes {
		if _, err := strconv.Atoi(process.Name()); err != nil {
			continue
		}
		name := strings.TrimSpace(readOptional(a.path(filepath.Join("/proc", process.Name(), "comm"))))
		executable, _ := os.Readlink(a.path(filepath.Join("/proc", process.Name(), "exe")))
		service := ""
		for _, line := range strings.Split(readOptional(a.path(filepath.Join("/proc", process.Name(), "cgroup"))), "\n") {
			_, path, ok := strings.Cut(line, "::")
			if candidate := filepath.Base(path); ok && strings.HasSuffix(candidate, ".service") {
				service = candidate
				break
			}
		}
		files, _ := os.ReadDir(a.path(filepath.Join("/proc", process.Name(), "fd")))
		for _, file := range files {
			target, err := os.Readlink(a.path(filepath.Join("/proc", process.Name(), "fd", file.Name())))
			if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				owners[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = socketOwner{name, service, executable}
			}
		}
	}
	return owners
}

func procAddress(value string) string {
	if strings.Trim(value, "0") == "" {
		if len(value) == 32 {
			return "::"
		}
		return "0.0.0.0"
	}
	if len(value) == 8 {
		bytes, err := hex.DecodeString(value)
		if err == nil {
			return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]).String()
		}
	}
	if len(value) == 32 {
		bytes, err := hex.DecodeString(value)
		if err == nil {
			for start := 0; start < len(bytes); start += 4 {
				bytes[start], bytes[start+3] = bytes[start+3], bytes[start]
				bytes[start+1], bytes[start+2] = bytes[start+2], bytes[start+1]
			}
			return net.IP(bytes).String()
		}
	}
	return value
}

func (a Adapter) ephemeralRange() networkpolicy.PortRange {
	fields := strings.Fields(readOptional(a.path("/proc/sys/net/ipv4/ip_local_port_range")))
	if len(fields) != 2 {
		return networkpolicy.PortRange{}
	}
	first, firstErr := strconv.ParseUint(fields[0], 10, 16)
	last, lastErr := strconv.ParseUint(fields[1], 10, 16)
	if firstErr != nil || lastErr != nil {
		return networkpolicy.PortRange{}
	}
	return networkpolicy.PortRange{First: uint16(first), Last: uint16(last)}
}

func availableCandidates(intent networkpolicy.Intent, observed networkpolicy.Observations) []networkpolicy.PortCandidate {
	if observed.Ephemeral.First == 0 || observed.Ephemeral.Last < observed.Ephemeral.First {
		return nil
	}
	used := map[uint16]bool{80: true}
	for _, port := range intent.SelectedPorts() {
		used[port] = true
	}
	for _, listener := range observed.Listeners {
		used[listener.Port] = true
	}
	var candidates []networkpolicy.PortCandidate
	for _, target := range []struct {
		protocol networkpolicy.Protocol
		address  string
	}{{networkpolicy.TCP, "public"}, {networkpolicy.UDP, "public"}, {networkpolicy.TCP, "127.0.0.1"}} {
		added := 0
		for attempts := 0; attempts < 256 && added < 4; attempts++ {
			value, err := rand.Int(rand.Reader, big.NewInt(65535-1024+1))
			if err != nil {
				break
			}
			port := uint16(value.Int64() + 1024)
			if used[port] || observed.Ephemeral.First <= port && port <= observed.Ephemeral.Last || !bindable(target.protocol, target.address, port, intent) {
				continue
			}
			used[port] = true
			candidates = append(candidates, networkpolicy.PortCandidate{Port: port, Protocol: target.protocol, Address: target.address, BindProven: true, Cryptographic: true})
			added++
		}
	}
	return candidates
}

func bindable(protocol networkpolicy.Protocol, address string, port uint16, intent networkpolicy.Intent) bool {
	addresses := []string{address}
	if address == "public" {
		addresses = nil
		if intent.PublicIPv4 != "" {
			addresses = append(addresses, "0.0.0.0")
		}
		if intent.PublicIPv6 != "" {
			addresses = append(addresses, "::")
		}
	}
	if len(addresses) == 0 {
		return false
	}
	var opened []io.Closer
	defer func() {
		for _, socket := range opened {
			socket.Close()
		}
	}()
	for _, current := range addresses {
		socket, err := bindSocket(protocol, current, port)
		if err != nil {
			return false
		}
		opened = append(opened, socket)
	}
	return true
}

func bindSocket(protocol networkpolicy.Protocol, address string, port uint16) (io.Closer, error) {
	network := "tcp4"
	if strings.Contains(address, ":") {
		network = "tcp6"
	}
	if protocol == networkpolicy.UDP {
		network = strings.Replace(network, "tcp", "udp", 1)
		packet, err := net.ListenPacket(network, net.JoinHostPort(address, strconv.Itoa(int(port))))
		if err != nil {
			return nil, err
		}
		return packet, nil
	}
	return net.Listen(network, net.JoinHostPort(address, strconv.Itoa(int(port))))
}

func (a Adapter) publicAddresses() (ipv4, ipv6 []string) {
	addressSource := net.InterfaceAddrs
	if a.addresses != nil {
		addressSource = a.addresses
	}
	addresses, _ := addressSource()
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || !usablePublicAddress(ip) {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip.String())
		} else {
			ipv6 = append(ipv6, ip.String())
		}
	}
	return ipv4, ipv6
}

func usablePublicAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return false
	}
	blocked := ipv6SpecialUse
	if address.Is4() {
		blocked = ipv4SpecialUse
	} else if !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range blocked {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var ipv4SpecialUse = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

var ipv6SpecialUse = prefixes(
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001::/23", "2001:db8::/32",
	"2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)

func prefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func sshFacts() networkpolicy.SSHFacts {
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	facts := networkpolicy.SSHFacts{}
	if len(fields) == 4 {
		if port, err := strconv.ParseUint(fields[3], 10, 16); err == nil {
			facts.DetectedPort = uint16(port)
		}
		facts.ServerAddress = fields[2]
		facts.CurrentSessions = []string{checksum([]byte(os.Getenv("SSH_CONNECTION")))}
	}
	if sessions, err := exec.Command("who").Output(); err == nil {
		for _, session := range strings.Split(strings.TrimSpace(string(sessions)), "\n") {
			if session != "" {
				facts.CurrentSessions = append(facts.CurrentSessions, checksum([]byte(session)))
			}
		}
	}
	return facts
}

func timeFacts() networkpolicy.TimeFacts {
	output, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
	return networkpolicy.TimeFacts{Synchronized: err == nil && strings.TrimSpace(string(output)) == "yes", Owner: activeTimeOwner()}
}

func activeTimeOwner() string {
	for _, service := range []string{"systemd-timesyncd.service", "chrony.service", "ntp.service"} {
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil {
			return service
		}
	}
	return ""
}

func activeFirewallManager() string {
	for _, service := range []string{"ufw.service", "firewalld.service", "docker.service"} {
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil {
			return service
		}
	}
	return ""
}

func outboundFacts(timeOK bool) networkpolicy.OutboundFacts {
	type check struct {
		name string
		fn   func() bool
	}
	checks := []check{
		{"dns", func() bool { _, err := net.LookupHost("github.com"); return err == nil }},
		{"github", func() bool { return httpsReachable("https://github.com") }},
		{"github-attestations", func() bool { return httpsReachable("https://api.github.com/repos/albertloky/SBXR/attestations") }},
		{"cloudflare", func() bool { return httpsReachable("https://api.cloudflare.com/client/v4/") }},
		{"acme", func() bool { return httpsReachable("https://acme-v02.api.letsencrypt.org/directory") }},
		{"certificate-endpoints", func() bool { return httpsReachable("https://letsencrypt.org/certs/isrgrootx1.der") }},
		{"tunnel-tcp", func() bool { return dialReachable("tcp", "region1.v2.argotunnel.com:7844") }},
		{"tunnel-udp", func() bool { return quicVersionResponse("region1.v2.argotunnel.com:7844") }},
	}
	results := map[string]bool{}
	var mutex sync.Mutex
	var group sync.WaitGroup
	for _, current := range checks {
		group.Add(1)
		go func() {
			defer group.Done()
			value := current.fn()
			mutex.Lock()
			results[current.name] = value
			mutex.Unlock()
		}()
	}
	group.Wait()
	return networkpolicy.OutboundFacts{DNS: results["dns"], GitHubHTTPS: results["github"], GitHubAttestationHTTPS: results["github-attestations"], CloudflareHTTPS: results["cloudflare"], ACMEHTTPS: results["acme"], CertificateEndpointsHTTPS: results["certificate-endpoints"], TimeService: timeOK, TunnelTCP7844: results["tunnel-tcp"], TunnelUDP7844: results["tunnel-udp"]}
}

func httpsReachable(url string) bool {
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" {
			return fmt.Errorf("refusing non-HTTPS redirect")
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodHead, url, nil)
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode < 500
}

func dialReachable(network, address string) bool {
	connection, err := net.DialTimeout(network, address, 3*time.Second)
	if err == nil {
		connection.Close()
	}
	return err == nil
}

func quicVersionResponse(address string) bool {
	target, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return false
	}
	connection, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return false
	}
	defer connection.Close()
	packet := make([]byte, 1200)
	packet[0] = 0xc0
	copy(packet[1:5], []byte{0x0a, 0x0a, 0x0a, 0x0a}) // unsupported QUIC version requests a Version Negotiation response
	packet[5] = 8
	if _, err := rand.Read(packet[6:14]); err != nil {
		return false
	}
	packet[14] = 0
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return false
	}
	if _, err := connection.Write(packet); err != nil {
		return false
	}
	response := make([]byte, 1500)
	n, err := connection.Read(response)
	return err == nil && n > 0
}

func diskFacts(path string) networkpolicy.DiskFacts {
	var stats syscall.Statfs_t
	if syscall.Statfs(path, &stats) != nil {
		return networkpolicy.DiskFacts{}
	}
	return networkpolicy.DiskFacts{FilesystemBytes: uint64(stats.Blocks) * uint64(stats.Bsize), AvailableBytes: uint64(stats.Bavail) * uint64(stats.Bsize)}
}

func readOptional(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func checksumFiles(paths ...string) string {
	hash := sha256.New()
	for _, path := range paths {
		data, _ := os.ReadFile(path)
		hash.Write(data)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func checksum(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func present(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "absent"
	}
	return fmt.Sprintf("present (%d bytes)", info.Size())
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
