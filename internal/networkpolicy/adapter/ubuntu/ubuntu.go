// Package ubuntu supplies the Network Policy Module's one read-only host Adapter.
package ubuntu

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	root             string
	external         bool
	privileged       bool
	selfProcessID    string
	output           func(string, ...string) ([]byte, error)
	firewallOutput   func(string, ...string) ([]byte, error)
	addresses        func() ([]net.Addr, error)
	afterFirstDigest func(string)
}

func New() Adapter {
	adapter := Adapter{root: "/", external: true, privileged: true, selfProcessID: strconv.Itoa(os.Getpid())}
	if os.Geteuid() != 0 {
		adapter.firewallOutput = sudoReadOnlyFirewallOutput
	}
	return adapter
}

func sudoReadOnlyFirewallOutput(command string, arguments ...string) ([]byte, error) {
	cmd, err := sudoReadOnlyFirewallCommand(command, arguments...)
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}

func sudoReadOnlyFirewallCommand(command string, arguments ...string) (*exec.Cmd, error) {
	paths := map[string]string{"nft": "/usr/sbin/nft", "iptables-save": "/usr/sbin/iptables-save", "ip6tables-save": "/usr/sbin/ip6tables-save"}
	if command == "ufw" && slices.Equal(arguments, []string{"status"}) {
		return exec.Command("/usr/bin/sudo", "-n", "--", "/usr/bin/env", "LC_ALL=C", "LANG=C", "/usr/sbin/ufw", "status"), nil
	}
	path := paths[command]
	if path == "" {
		return nil, os.ErrPermission
	}
	return exec.Command("/usr/bin/sudo", append([]string{"-n", "--", path}, arguments...)...), nil
}

// NewAt creates the same read-only Adapter over a controlled filesystem seam.
func NewAt(root string) Adapter { return Adapter{root: root} }

func (a Adapter) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	if request.Scope == networkpolicy.ExternalObservations {
		if !a.external {
			return networkpolicy.Observations{}, nil
		}
		return networkpolicy.Observations{Outbound: outboundFacts(timeFacts().Synchronized, request.Intent)}, nil
	}
	version, err := a.ubuntuVersion()
	if err != nil {
		return networkpolicy.Observations{}, err
	}
	memory, err := a.physicalRAM()
	if err != nil {
		return networkpolicy.Observations{}, err
	}
	listeners, err := a.listeners(request.ReclamationReview)
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
		Listeners:         listeners,
		ServiceIdentities: a.serviceIdentities(),
		ResourcePaths:     a.resourcePaths(),
		SSH:               a.sshFacts(),
		Routes: networkpolicy.RouteFacts{
			IPv4: present(a.path("/proc/net/route")),
			IPv6: present(a.path("/proc/net/ipv6_route")),
		},
		Ephemeral: a.ephemeralRange(),
		Checksums: map[string]string{},
	}
	observed.SSH.Listener = observedSSHListener(observed.Listeners, observed.SSH)
	if request.ReclamationReview {
		collisions := slices.DeleteFunc(append([]networkpolicy.Listener(nil), observed.Listeners...), func(listener networkpolicy.Listener) bool {
			return !slices.ContainsFunc(request.ListenerSeams, func(seam networkpolicy.ListenerSeam) bool { return seam.Collides(listener) })
		})
		observed.Reclamation, err = a.reclamationFacts(observed.ResourcePaths, collisions)
		if err != nil {
			return networkpolicy.Observations{}, err
		}
		observed.ReclamationComplete = true
	}
	observed.Disk = diskFacts(a.root)
	observed.Checksums["routes"] = checksumFiles(a.path("/proc/net/route"), a.path("/proc/net/ipv6_route"))
	observed.Checksums["listeners"] = checksumFiles(a.path("/proc/net/tcp"), a.path("/proc/net/tcp6"), a.path("/proc/net/udp"), a.path("/proc/net/udp6"))
	if a.external || a.addresses != nil {
		observed.PublicIPv4, observed.PublicIPv6 = a.publicAddresses()
	}
	if a.external {
		observed.Time = timeFacts()
		if request.Scope != networkpolicy.LocalObservations {
			observed.Outbound = outboundFacts(observed.Time.Synchronized, request.Intent)
		}
		observed.Firewall.ActiveManager, observed.Firewall.UFWConfiguredState, observed.Firewall.UFWReportedState = a.firewallManagerFacts()
	}
	if a.privileged {
		if rules, commandErr := a.readOnlyFirewallOutput("nft", "-j", "list", "ruleset"); commandErr == nil {
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
					if observed.Reclamation.Docker != nil {
						if dockerDigest, objects, dockerErr := dockerFirewallDigest(rules); dockerErr == nil && len(objects) > 0 {
							observed.Reclamation.Docker.FirewallSHA256 = dockerDigest
							observed.Reclamation.Docker.FirewallObjects = objects
						}
					}
					if request.ReclamationReview && observed.Reclamation.Docker == nil && observed.Firewall.ActiveManager != "" && observed.Firewall.ActiveManager != "docker.service" && unexpected != "" {
						if digest, objects, outboundDigest, outbound, firewallErr := firewallDigests(rules); firewallErr == nil && len(objects) > 0 {
							observed.Reclamation.Firewall = &networkpolicy.FirewallConflict{Manager: observed.Firewall.ActiveManager, SHA256: digest, Objects: objects, OutboundSHA256: outboundDigest, OutboundObjects: outbound}
						}
					}
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
	if _, err := os.ReadFile(a.path("/proc/self/mountinfo")); err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	shells, err := a.currentShells()
	if err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	facts := networkpolicy.ReclamationFacts{ProtectedPaths: shells}
	processes, scripts, err := a.reclamationProcesses(listeners)
	if err != nil {
		return networkpolicy.ReclamationFacts{}, err
	}
	facts.Scripts = scripts
	interpreters := map[string]bool{}
	for _, script := range scripts {
		interpreters[script.Interpreter] = true
		if !slices.Contains(facts.ProtectedPaths, script.Interpreter) {
			facts.ProtectedPaths = append(facts.ProtectedPaths, script.Interpreter)
		}
	}
	for _, listener := range listeners {
		if listener.Executable != "" && !interpreters[listener.Executable] && !slices.Contains(paths, listener.Executable) {
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
		if slices.Contains([]string{"docker.io", "docker-ce", "docker-ce-cli", "containerd", "containerd.io"}, name) {
			if facts.Docker == nil {
				facts.Docker = &networkpolicy.DockerConflict{Service: "docker.service", PreservedData: []string{"images", "volumes", "Compose definitions", "bind mounts", "container configuration", "application data"}}
			}
			pkg := networkpolicy.PackageConflict{Name: name, Version: fields["Version"], OwnedPaths: append([]string(nil), owned...)}
			if slices.Contains(owned, "/usr/bin/dockerd") && slices.ContainsFunc(owned, func(path string) bool { return strings.HasSuffix(path, "/docker.service") }) {
				pkg.ControlSHA256, err = a.dockerPackageControlDigest(name)
				if err != nil {
					return networkpolicy.ReclamationFacts{}, err
				}
				pkg.Owns = "/usr/bin/dockerd"
				facts.Docker.Packages = append(facts.Docker.Packages, pkg)
			} else if ownedRuntimePath(owned) != "" || name == "docker-ce-cli" {
				pkg.Owns = ownedRuntimePath(owned)
				facts.Docker.RuntimePackages = append(facts.Docker.RuntimePackages, pkg)
			}
		}
	}
	for _, path := range paths {
		if a.mountPoint(path) {
			facts.UnsafePaths = append(facts.UnsafePaths, path)
			continue
		}
		ownedPackage := ""
		for _, pkg := range facts.Packages {
			if slices.Contains(pkg.OwnedPaths, path) {
				ownedPackage = pkg.Name
				break
			}
		}
		if info, err := os.Lstat(a.path(path)); err == nil && info.IsDir() && ownedPackage != "" {
			continue
		}
		digest, info, err := a.stableRegularDigest(a.path(path))
		if err != nil {
			facts.UnsafePaths = append(facts.UnsafePaths, path)
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			continue
		}
		stat, _ := info.Sys().(*syscall.Stat_t)
		file := networkpolicy.FileConflict{Path: path, SHA256: digest, Mode: uint32(info.Mode().Perm()), Links: 1}
		if owner, ok := processes[path]; ok {
			file.Process, file.Service, file.ProcessID = owner.process, owner.service, owner.processID
		}
		if stat != nil {
			file.OwnerUID, file.Links = stat.Uid, uint64(stat.Nlink)
		}
		file.Package = ownedPackage
		facts.Executables = append(facts.Executables, file)
	}
	if facts.Docker != nil {
		if owner, ok := processes["/usr/bin/dockerd"]; ok && owner.service == "docker.service" {
			digest, _, digestErr := a.stableRegularDigest(a.path(owner.executable))
			if digestErr != nil {
				return networkpolicy.ReclamationFacts{}, digestErr
			}
			facts.Docker.Status, facts.Docker.ServiceExecutable, facts.Docker.ServiceSHA256, facts.Docker.ProcessID = "active", owner.executable, digest, owner.processID
		} else if len(facts.Docker.Packages) > 0 {
			return networkpolicy.ReclamationFacts{}, errors.New("active Docker service ownership unavailable")
		} else {
			facts.Docker = nil
		}
		if facts.Docker != nil {
			facts.Docker.PreservedPaths, facts.Docker.PreservedSHA256, err = a.dockerPreservedPaths()
			if err != nil {
				return networkpolicy.ReclamationFacts{}, err
			}
		}
	}
	return facts, nil
}

func (a Adapter) dockerPackageControlDigest(packageName string) (string, error) {
	files, err := filepath.Glob(a.path("/var/lib/dpkg/info/" + packageName + ".*"))
	qualified, qualifiedErr := filepath.Glob(a.path("/var/lib/dpkg/info/" + packageName + ":*.*"))
	if err != nil || qualifiedErr != nil {
		return "", errors.New("Docker package control inventory unavailable")
	}
	files = append(files, qualified...)
	slices.Sort(files)
	digest := sha256.New()
	for _, name := range files {
		body, err := os.ReadFile(name)
		info, statErr := os.Lstat(name)
		if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", err
		}
		fmt.Fprintf(digest, "%s\x00%d\x00", filepath.Base(name), info.Mode().Perm())
		digest.Write(body)
	}
	if len(files) == 0 {
		return "", errors.New("Docker package control inventory unavailable")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (a Adapter) dockerPreservedPaths() ([]string, []string, error) {
	paths := []string{"/var/lib/docker", "/etc/docker"}
	containers := a.path("/var/lib/docker/containers")
	if _, err := os.Stat(containers); err == nil {
		if err := filepath.Walk(containers, func(name string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return errors.New("Docker container inventory unavailable")
			}
			if !info.Mode().IsRegular() || filepath.Ext(name) != ".json" {
				return nil
			}
			body, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			var value any
			if json.Unmarshal(body, &value) != nil {
				return errors.New("Docker container configuration invalid")
			}
			collectDockerPaths("", value, &paths)
			return nil
		}); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	var existing, digests []string
	for _, preserved := range paths {
		if _, err := os.Lstat(a.path(preserved)); errors.Is(err, os.ErrNotExist) {
			continue
		}
		digest, err := a.digestPreservedTree(preserved)
		if err != nil {
			return nil, nil, err
		}
		existing, digests = append(existing, preserved), append(digests, digest)
	}
	if len(existing) == 0 {
		return nil, nil, errors.New("Docker preserved data inventory unavailable")
	}
	return existing, digests, nil
}

func collectDockerPaths(key string, value any, paths *[]string) {
	switch value := value.(type) {
	case map[string]any:
		for childKey, child := range value {
			collectDockerPaths(childKey, child, paths)
		}
	case []any:
		for _, child := range value {
			collectDockerPaths(key, child, paths)
		}
	case string:
		lower := strings.ToLower(key)
		if !strings.Contains(lower, "source") && !strings.Contains(lower, "bind") && !strings.Contains(lower, "working_dir") && !strings.Contains(lower, "config_files") {
			return
		}
		for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' }) {
			if strings.Contains(lower, "bind") {
				field, _, _ = strings.Cut(field, ":")
			}
			field = strings.TrimSpace(field)
			if filepath.IsAbs(field) && !strings.HasPrefix(field, "/var/lib/docker/") && !strings.HasPrefix(field, "/etc/docker/") && !slices.Contains(*paths, filepath.Clean(field)) {
				*paths = append(*paths, filepath.Clean(field))
			}
		}
	}
}

func dockerFirewallDigest(data []byte) (string, []string, error) {
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return "", nil, err
	}
	chains := map[string]bool{}
	for _, item := range document.Nftables {
		raw, ok := item["chain"]
		if !ok {
			continue
		}
		var chain struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(raw, &chain) != nil {
			return "", nil, errors.New("Docker firewall inventory invalid")
		}
		lower := strings.ToLower(chain.Name)
		if lower == "docker" || strings.HasPrefix(lower, "docker-") {
			chains[chain.Family+"\x00"+chain.Table+"\x00"+chain.Name] = true
		}
	}
	var docker []map[string]json.RawMessage
	for _, item := range document.Nftables {
		if dockerFirewallItem(item, chains) {
			docker = append(docker, item)
		}
	}
	encoded, _ := json.Marshal(docker)
	objects := make([]string, len(docker))
	for index, item := range docker {
		itemBody, _ := json.Marshal(item)
		objects[index] = string(itemBody)
	}
	return checksum(encoded), objects, nil
}

func dockerFirewallItem(item map[string]json.RawMessage, chains map[string]bool) bool {
	for kind, raw := range item {
		var identity struct{ Family, Table, Name, Chain string }
		if json.Unmarshal(raw, &identity) != nil {
			return false
		}
		if kind == "chain" && chains[identity.Family+"\x00"+identity.Table+"\x00"+identity.Name] {
			return true
		}
		if kind == "rule" {
			if chains[identity.Family+"\x00"+identity.Table+"\x00"+identity.Chain] {
				return true
			}
			var rule any
			if json.Unmarshal(raw, &rule) != nil {
				return false
			}
			for key := range chains {
				parts := strings.Split(key, "\x00")
				if parts[0] == identity.Family && parts[1] == identity.Table && referencesTarget(rule, parts[2]) {
					return true
				}
			}
		}
	}
	return false
}

func referencesTarget(value any, target string) bool {
	switch value := value.(type) {
	case map[string]any:
		if got, ok := value["target"].(string); ok && got == target {
			return true
		}
		for _, child := range value {
			if referencesTarget(child, target) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if referencesTarget(child, target) {
				return true
			}
		}
	}
	return false
}

func (a Adapter) digestPreservedTree(root string) (string, error) {
	digest := sha256.New()
	err := filepath.Walk(a.path(root), func(name string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Docker preserved data is unproved")
		}
		relative := strings.TrimPrefix(name, a.root)
		fmt.Fprintf(digest, "%s\x00%d\x00%d\x00", relative, info.Mode(), info.Size())
		if info.Mode().IsRegular() {
			body, readErr := os.ReadFile(name)
			if readErr != nil {
				return readErr
			}
			digest.Write(body)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func ownedRuntimePath(paths []string) string {
	for _, path := range paths {
		if path == "/usr/bin/containerd" || strings.HasSuffix(path, "/containerd.service") {
			return path
		}
	}
	return ""
}

func (a Adapter) currentShells() ([]string, error) {
	var shells []string
	pid := os.Getppid()
	for range 16 {
		base := filepath.Join("/proc", strconv.Itoa(pid))
		executable, err := os.Readlink(a.path(filepath.Join(base, "exe")))
		if err != nil {
			return nil, err
		}
		shells = append(shells, executable)
		statData, err := os.ReadFile(a.path(filepath.Join(base, "stat")))
		if err != nil {
			return nil, err
		}
		stat := string(statData)
		end := strings.LastIndex(stat, ") ")
		if end < 0 {
			return nil, errors.New("current shell ancestry is malformed")
		}
		fields := strings.Fields(stat[end+2:])
		if len(fields) < 2 {
			return nil, errors.New("current shell ancestry is incomplete")
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent <= 1 || parent == pid {
			break
		}
		pid = parent
	}
	return shells, nil
}

func (a Adapter) reclamationProcesses(listeners []networkpolicy.Listener) (map[string]socketOwner, []networkpolicy.ScriptConflict, error) {
	executables := map[string]socketOwner{}
	var scripts []networkpolicy.ScriptConflict
	listenerProcesses := map[string]bool{}
	for _, listener := range listeners {
		listenerProcesses[listener.ProcessID] = true
	}
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
			executables[executable] = socketOwner{name, service, executable, process.Name()}
		}
		if !listenerProcesses[process.Name()] || !slices.Contains([]string{"sh", "bash", "dash", "python", "python3", "perl", "ruby", "node"}, filepath.Base(executable)) {
			continue
		}
		arguments := strings.Split(readOptional(a.path(filepath.Join(base, "cmdline"))), "\x00")
		if len(arguments) != 3 || arguments[2] != "" || !filepath.IsAbs(arguments[0]) || filepath.Clean(arguments[0]) != arguments[0] || !filepath.IsAbs(arguments[1]) || filepath.Clean(arguments[1]) != arguments[1] {
			continue
		}
		if a.mountPoint(arguments[1]) {
			return nil, nil, errors.New("script target is not an exact regular unmounted file")
		}
		digest, _, readErr := a.stableRegularDigest(a.path(arguments[1]))
		if readErr != nil {
			return nil, nil, readErr
		}
		scripts = append(scripts, networkpolicy.ScriptConflict{Interpreter: executable, Path: arguments[1], SHA256: digest, Process: name, Service: service, ProcessID: process.Name(), Regular: true, Links: 1})
	}
	return executables, scripts, nil
}

func (a Adapter) stableRegularDigest(path string) (string, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("target is not a regular file")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return "", nil, errors.New("target is shared or unproved")
	}
	hash := func() (string, error) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		digest := sha256.New()
		if _, err := io.Copy(digest, file); err != nil {
			return "", err
		}
		return hex.EncodeToString(digest.Sum(nil)), nil
	}
	first, err := hash()
	if err != nil {
		return "", nil, err
	}
	if a.afterFirstDigest != nil {
		a.afterFirstDigest(path)
	}
	middle, err := file.Stat()
	if err != nil {
		return "", nil, err
	}
	second, err := hash()
	if err != nil {
		return "", nil, err
	}
	after, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || first != second || !sameRegularFile(before, middle) || !sameRegularFile(middle, after) || !os.SameFile(after, pathInfo) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("target changed while reading")
	}
	return first, after, nil
}

func sameRegularFile(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && first.Mode() == second.Mode() && first.Size() == second.Size() && first.ModTime() == second.ModTime() && firstStat.Dev == secondStat.Dev && firstStat.Ino == secondStat.Ino && firstStat.Nlink == 1 && secondStat.Nlink == 1
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

func (a Adapter) readOnlyFirewallOutput(command string, arguments ...string) ([]byte, error) {
	if a.firewallOutput != nil {
		return a.firewallOutput(command, arguments...)
	}
	if a.output != nil {
		return a.privilegedOutput(command, arguments...)
	}
	if command == "ufw" && slices.Equal(arguments, []string{"status"}) {
		cmd := exec.Command("/usr/sbin/ufw", "status")
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		return cmd.Output()
	}
	return a.privilegedOutput(command, arguments...)
}

func (a Adapter) legacyIPTablesRule() (string, error) {
	for _, command := range []string{"iptables-save", "ip6tables-save"} {
		output, err := a.readOnlyFirewallOutput(command)
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

func firewallDigests(data []byte) (string, []string, string, []string, error) {
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return "", nil, "", nil, err
	}
	chains := map[string]bool{}
	for _, item := range document.Nftables {
		var chain struct {
			Family, Table, Name, Hook string
		}
		if raw := item["chain"]; len(raw) > 0 && json.Unmarshal(raw, &chain) == nil && chain.Hook == "input" && !(chain.Family == "inet" && chain.Table == "sbxr") {
			chains[chain.Family+"\x00"+chain.Table+"\x00"+chain.Name] = true
		}
	}
	var objects, outbound []string
	for _, item := range document.Nftables {
		delete(item, "counter")
		if rule := item["rule"]; len(rule) > 0 {
			var value map[string]any
			if json.Unmarshal(rule, &value) == nil {
				delete(value, "counter")
				for _, field := range []string{"expr"} {
					if expressions, ok := value[field].([]any); ok {
						for _, expression := range expressions {
							if object, ok := expression.(map[string]any); ok {
								delete(object, "counter")
							}
						}
					}
				}
				item["rule"], _ = json.Marshal(value)
			}
		}
		var identity struct{ Family, Table, Name, Chain string }
		encoded, _ := json.Marshal(item)
		if strings.Contains(string(encoded), `"family":"inet","name":"sbxr"`) || strings.Contains(string(encoded), `"family":"inet","table":"sbxr"`) {
			continue
		}
		objects = append(objects, string(encoded))
		chainRaw, ruleRaw := item["chain"], item["rule"]
		chainDeleted := len(chainRaw) > 0 && json.Unmarshal(chainRaw, &identity) == nil && chains[identity.Family+"\x00"+identity.Table+"\x00"+identity.Name]
		ruleDeleted := len(ruleRaw) > 0 && json.Unmarshal(ruleRaw, &identity) == nil && chains[identity.Family+"\x00"+identity.Table+"\x00"+identity.Chain]
		if !chainDeleted && !ruleDeleted {
			outbound = append(outbound, string(encoded))
		}
	}
	if len(objects) == 0 {
		return "", nil, "", nil, errors.New("inbound firewall unavailable")
	}
	digest := sha256.Sum256([]byte(strings.Join(objects, "\n")))
	outboundDigest := sha256.Sum256([]byte(strings.Join(outbound, "\n")))
	return hex.EncodeToString(digest[:]), objects, hex.EncodeToString(outboundDigest[:]), outbound, nil
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
		if process.Name() == a.selfProcessID {
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

func (a Adapter) listeners(strict bool) ([]networkpolicy.Listener, error) {
	var listeners []networkpolicy.Listener
	owners, err := a.socketOwners(strict)
	if err != nil {
		return nil, err
	}
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
			if strict {
				return nil, err
			}
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
				listeners = append(listeners, networkpolicy.Listener{Address: procAddress(address), Port: uint16(port), Protocol: source.protocol, Process: owner.process, Service: owner.service, Executable: owner.executable, ProcessID: owner.processID, Ownership: networkpolicy.Unproved})
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, err
		}
		file.Close()
	}
	return listeners, nil
}

type socketOwner struct{ process, service, executable, processID string }

func (a Adapter) socketOwners(strict bool) (map[string]socketOwner, error) {
	owners := map[string]socketOwner{}
	processes, err := os.ReadDir(a.path("/proc"))
	if err != nil {
		if strict {
			return nil, err
		}
		return owners, nil
	}
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
				owners[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = socketOwner{name, service, executable, process.Name()}
			}
		}
	}
	return owners, nil
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
	return networkpolicy.UsablePublicAddress(ip.String())
}

func observedSSHListener(listeners []networkpolicy.Listener, facts networkpolicy.SSHFacts) string {
	for _, listener := range listeners {
		if listener.Port == facts.DetectedPort && listener.Protocol == networkpolicy.TCP && listener.Service == facts.Service && networkpolicy.ListenerCoversAddress(listener.Address, facts.ServerAddress) {
			return net.JoinHostPort(listener.Address, strconv.Itoa(int(listener.Port))) + "/tcp"
		}
	}
	return ""
}

func (a Adapter) sshFacts() networkpolicy.SSHFacts {
	fields := strings.Fields(os.Getenv("SBXR_SSH_CONNECTION"))
	facts := networkpolicy.SSHFacts{}
	if len(fields) == 4 {
		if port, err := strconv.ParseUint(fields[3], 10, 16); err == nil {
			facts.DetectedPort = uint16(port)
		}
		if address, err := netip.ParseAddr(fields[2]); err == nil {
			facts.ServerAddress = address.String()
		}
	}
	facts.CurrentSessions, facts.SessionsComplete = a.establishedTCPSessions()
	for _, service := range []string{"ssh.service", "sshd.service"} {
		if state, err := a.privilegedOutput("systemctl", "is-active", service); err == nil && strings.TrimSpace(string(state)) == "active" {
			facts.Service = service
			break
		}
	}
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user != "" {
		if home, err := a.privilegedOutput("getent", "passwd", user); err == nil {
			fields := strings.Split(strings.TrimSpace(string(home)), ":")
			if len(fields) == 7 {
				facts.AuthorizedKeysPath = filepath.Join(fields[5], ".ssh", "authorized_keys")
				if digest, info, err := a.stableRegularDigest(a.path(facts.AuthorizedKeysPath)); err == nil && info.Size() > 0 {
					facts.AuthorizedKeysSHA256 = digest
				}
			}
		}
	}
	return facts
}

func (a Adapter) establishedTCPSessions() ([]string, bool) {
	var sessions []string
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(a.path(name))
		if err != nil {
			return nil, false
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != "01" {
				continue
			}
			serverAddress, serverPort, serverOK := procEndpoint(fields[1])
			clientAddress, clientPort, clientOK := procEndpoint(fields[2])
			if serverOK && clientOK {
				sessions = append(sessions, checksum([]byte(fmt.Sprintf("%s %d %s %d", clientAddress, clientPort, serverAddress, serverPort))))
			}
		}
		err = scanner.Err()
		file.Close()
		if err != nil {
			return nil, false
		}
	}
	return sessions, true
}

func procEndpoint(value string) (string, uint16, bool) {
	address, portText, ok := strings.Cut(value, ":")
	port, err := strconv.ParseUint(portText, 16, 16)
	parsed, addressErr := netip.ParseAddr(procAddress(address))
	return parsed.String(), uint16(port), ok && err == nil && addressErr == nil && port != 0
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

func (a Adapter) firewallManagerFacts() (manager string, configured networkpolicy.UFWConfiguredState, reported networkpolicy.UFWReportedState) {
	_, ufwActiveErr := a.privilegedOutput("systemctl", "is-active", "--quiet", "ufw.service")
	loaded, loadedErr := a.privilegedOutput("systemctl", "show", "-p", "LoadState", "--value", "ufw.service")
	_, configErr := os.Stat(a.path("/etc/ufw/ufw.conf"))
	ufwPresent := ufwActiveErr == nil || loadedErr == nil && strings.TrimSpace(string(loaded)) == "loaded" || configErr == nil || !errors.Is(configErr, os.ErrNotExist)
	if ufwPresent {
		manager = "ufw.service"
		configured = a.ufwConfiguredState()
		status, err := a.readOnlyFirewallOutput("ufw", "status")
		switch {
		case err != nil:
			reported = networkpolicy.UFWStatusUnavailable
		case strings.TrimSpace(string(status)) == "Status: inactive":
			reported = networkpolicy.UFWStatusInactive
		case strings.HasPrefix(strings.TrimSpace(string(status)), "Status: active"):
			reported = networkpolicy.UFWStatusActive
		default:
			reported = networkpolicy.UFWStatusMalformed
		}
	}
	for _, service := range []string{"firewalld.service", "nftables.service", "docker.service"} {
		if _, err := a.privilegedOutput("systemctl", "is-active", "--quiet", service); err == nil {
			return service, configured, reported
		}
	}
	return manager, configured, reported
}

func (a Adapter) ufwConfiguredState() networkpolicy.UFWConfiguredState {
	data, err := os.ReadFile(a.path("/etc/ufw/ufw.conf"))
	if errors.Is(err, os.ErrNotExist) {
		return networkpolicy.UFWConfigMissing
	}
	if err != nil {
		return networkpolicy.UFWConfigUnreadable
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ENABLED=") {
			if found {
				return networkpolicy.UFWConfigMalformed
			}
			if line == "ENABLED=yes" {
				return networkpolicy.UFWConfigActive
			}
			if line != "ENABLED=no" {
				return networkpolicy.UFWConfigMalformed
			}
			found = true
		}
	}
	if !found {
		return networkpolicy.UFWConfigMalformed
	}
	return networkpolicy.UFWConfigDisabled
}

func outboundFacts(timeOK bool, intent networkpolicy.Intent) networkpolicy.OutboundFacts {
	type check struct {
		name string
		fn   func() bool
	}
	checks := []check{
		{"dns", func() bool { _, err := net.LookupHost("github.com"); return err == nil }},
		{"github", func() bool { return httpsReachable("https://github.com") }},
		{"github-attestations", func() bool { return httpsReachable("https://api.github.com/repos/albertloky/SBXR/attestations") }},
		{"acme", func() bool { return httpsReachable("https://acme-v02.api.letsencrypt.org/directory") }},
		{"certificate-endpoints", func() bool { return httpsReachable("https://letsencrypt.org/certs/isrgrootx1.der") }},
	}
	cloudflare := intent.Profiles.VLESSXHTTP.Enabled || intent.Profiles.VLESSWebSocket.Enabled || intent.Profiles.Hysteria2.Enabled || intent.Profiles.TUIC.Enabled || intent.Profiles.AnyTLS.Enabled
	if cloudflare {
		checks = append(checks, check{"cloudflare", func() bool { return httpsReachable("https://api.cloudflare.com/client/v4/") }})
	}
	if intent.Profiles.VLESSXHTTP.Enabled || intent.Profiles.VLESSWebSocket.Enabled {
		checks = append(checks,
			check{"tunnel-tcp", func() bool { return dialReachable("tcp", "region1.v2.argotunnel.com:7844") }},
			check{"tunnel-udp", func() bool { return quicVersionResponse("region1.v2.argotunnel.com:7844") }},
		)
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
