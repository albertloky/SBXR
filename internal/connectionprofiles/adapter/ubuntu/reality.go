package ubuntu

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
)

const realityConfigurationPath = "etc/sbxr/xray/config.json"

type commandRunner func(context.Context, io.Reader, string, ...string) (string, error)

type RealityHost struct {
	root      string
	run       commandRunner
	probe     func(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation
	now       func() time.Time
	rootUID   uint32
	xrayGID   uint32
	xrayGroup bool
	xrayUser  bool
}

type xrayServiceObservation struct {
	checkedAt         time.Time
	configurationSafe bool
	installed         bool
	unit              string
	identity          string
	running           bool
	netBindService    bool
	listeners         string
}

func NewRealityHost(root string) RealityHost {
	group, _ := user.LookupGroup("xray")
	account, _ := user.Lookup("xray")
	gid := uint64(0)
	groupValid := false
	if group != nil {
		var err error
		gid, err = strconv.ParseUint(group.Gid, 10, 32)
		groupValid = err == nil
	}
	uid, uidErr := strconv.ParseUint(accountID(account), 10, 32)
	userValid := uidErr == nil && uid != 0 && groupValid && account.Gid == group.Gid
	return RealityHost{root: root, run: runRealityCommand, probe: probeRealityTarget, now: time.Now, rootUID: 0, xrayGID: uint32(gid), xrayGroup: groupValid, xrayUser: userValid}
}

func accountID(account *user.User) string {
	if account == nil {
		return ""
	}
	return account.Uid
}

func (host RealityHost) ObserveReality(ctx context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	if host.probe == nil {
		host.probe = probeRealityTarget
	}
	observation := host.probe(ctx, target)
	service := host.observeXrayService(ctx, target.ListenerPort)
	observation.CheckedAt, observation.ConfigurationSafe = service.checkedAt, service.configurationSafe
	observation.ServiceInstalled, observation.ServiceUnit, observation.ServiceIdentity = service.installed, service.unit, service.identity
	observation.ServiceRunning, observation.NetBindService = service.running, service.netBindService
	if listener, ok := exactListener(service.listeners, target.ListenerPort, func(address string) bool { return address == "0.0.0.0" || address == "::" || address == "*" }); ok {
		observation.Listener = listener
	}
	return observation
}

func (host RealityHost) ObserveXHTTP(ctx context.Context, listenerPort uint16) connectionprofiles.XHTTPObservation {
	service := host.observeXrayService(ctx, listenerPort)
	observation := connectionprofiles.XHTTPObservation{
		CheckedAt: service.checkedAt, ConfigurationSafe: service.configurationSafe, ServiceUnit: service.unit,
		ServiceIdentity: service.identity, ServiceRunning: service.running,
	}
	if observation.ConfigurationSafe {
		validation, cancel := context.WithTimeout(ctx, 60*time.Second)
		_, validationErr := host.run(validation, nil, "xray", "run", "-test", "-config", filepath.Join(host.root, realityConfigurationPath))
		cancel()
		observation.ConfigurationValid = validationErr == nil
	}
	if listener, ok := exactListener(service.listeners, listenerPort, func(address string) bool { return address == "127.0.0.1" }); ok {
		observation.Listener = listener
	}
	return observation
}

func (host RealityHost) observeXrayService(ctx context.Context, listenerPort uint16) xrayServiceObservation {
	if host.now == nil {
		host.now = time.Now
	}
	if host.run == nil {
		host.run = runRealityCommand
	}
	unit, _ := host.run(ctx, nil, "systemctl", "show", "--property=Id", "--value", "xray.service")
	identity, _ := host.run(ctx, nil, "systemctl", "show", "--property=User", "--value", "xray.service")
	group, _ := host.run(ctx, nil, "systemctl", "show", "--property=Group", "--value", "xray.service")
	active, activeErr := host.run(ctx, nil, "systemctl", "is-active", "xray.service")
	capabilities, _ := host.run(ctx, nil, "systemctl", "show", "--property=CapabilityBoundingSet", "--value", "xray.service")
	ambient, _ := host.run(ctx, nil, "systemctl", "show", "--property=AmbientCapabilities", "--value", "xray.service")
	listeners, _ := host.run(ctx, nil, "ss", "-H", "-ltn", "sport", "=", ":"+strconv.Itoa(int(listenerPort)))
	service := xrayServiceObservation{
		checkedAt: host.now().UTC(), configurationSafe: host.safeConfiguration(), installed: strings.TrimSpace(unit) == "xray.service", unit: strings.TrimSpace(unit),
		running: activeErr == nil && strings.TrimSpace(active) == "active", netBindService: strings.TrimSpace(capabilities) == "CAP_NET_BIND_SERVICE" && strings.TrimSpace(ambient) == "CAP_NET_BIND_SERVICE", listeners: listeners,
	}
	if host.xrayUser && strings.TrimSpace(identity) == "xray" && strings.TrimSpace(group) == "xray" {
		service.identity = "xray"
	}
	return service
}

func (host RealityHost) ValidateReality(ctx context.Context, version string, configuration io.Reader) error {
	if version != "v26.3.27" || configuration == nil {
		return errors.New("qualified Xray validation unavailable")
	}
	if host.run == nil {
		host.run = runRealityCommand
	}
	validation, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := host.run(validation, configuration, "xray", "run", "-test", "-config", "stdin:"); err != nil {
		return errors.New("complete Xray configuration validation failed")
	}
	return nil
}

func (host RealityHost) safeConfiguration() bool {
	if !host.xrayGroup || !host.xrayUser {
		return false
	}
	directoryName := filepath.Join(host.root, "etc/sbxr/xray")
	fileName := filepath.Join(host.root, realityConfigurationPath)
	for _, ancestor := range []string{filepath.Join(host.root, "etc"), filepath.Join(host.root, "etc/sbxr")} {
		info, err := os.Lstat(ancestor)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Uid != host.rootUID {
			return false
		}
	}
	directory, directoryErr := os.Lstat(directoryName)
	file, fileErr := os.Lstat(fileName)
	if directoryErr != nil || fileErr != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0o750 || !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 || file.Mode().Perm() != 0o640 || file.Size() <= 0 || file.Size() > 1<<20 {
		return false
	}
	directoryStat, directoryOK := directory.Sys().(*syscall.Stat_t)
	fileStat, fileOK := file.Sys().(*syscall.Stat_t)
	return directoryOK && fileOK && directoryStat.Uid == host.rootUID && directoryStat.Gid == host.xrayGID && fileStat.Uid == host.rootUID && fileStat.Gid == host.xrayGID && fileStat.Nlink == 1
}

func exactListener(output string, expectedPort uint16, allowed func(string) bool) (connectionprofiles.Listener, bool) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if expectedPort == 0 || len(lines) != 1 {
		return connectionprofiles.Listener{}, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 4 {
		return connectionprofiles.Listener{}, false
	}
	address, port, ok := listenAddress(fields[3])
	if !ok || port != expectedPort || !allowed(address) {
		return connectionprofiles.Listener{}, false
	}
	return connectionprofiles.Listener{Address: address, Port: port, Protocol: "tcp"}, true
}

func publicListenAddress(value string) (string, uint16, bool) {
	host, port, ok := listenAddress(value)
	return host, port, ok && (host == "0.0.0.0" || host == "::" || host == "*")
}

func listenAddress(value string) (string, uint16, bool) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return "", 0, false
	}
	return host, uint16(port), true
}

func runRealityCommand(ctx context.Context, input io.Reader, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = input
	output, err := command.Output()
	if err != nil {
		return "", errors.New("Connection Profiles command failed")
	}
	return string(output), nil
}

func probeRealityTarget(ctx context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	observation := connectionprofiles.RealityObservation{Probe: connectionprofiles.ProbeInconclusive}
	host, port, err := net.SplitHostPort(target.Address)
	if err != nil || port != "443" || host != target.ServerName {
		return observation
	}
	if appleOrICloud(host) {
		observation.Class = connectionprofiles.AppleICloudTarget
		observation.Probe = connectionprofiles.ProbeFailed
		return observation
	}
	probe, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := runRealityCommand(probe, nil, "xray", "tls", "ping", target.Address); err != nil {
		observation.Probe = connectionprofiles.ProbeFailed
		return observation
	}
	addresses, err := net.DefaultResolver.LookupNetIP(probe, "ip", host)
	if err != nil || len(addresses) == 0 {
		return observation
	}
	providerNetwork, validProviderPrefixes := addressInPrefixes(addresses, target.ProviderPrefixes)
	if !validProviderPrefixes {
		return observation
	}
	observation.ProviderNetwork = providerNetwork
	prefixes, err := cloudflarePrefixes(probe)
	if err != nil {
		return observation
	}
	for _, address := range addresses {
		if slicesContainsPrefix(prefixes, address) {
			observation.Class = connectionprofiles.CloudflareTarget
			observation.Probe = connectionprofiles.ProbeFailed
			return observation
		}
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", target.Address, &tls.Config{ServerName: target.ServerName, MinVersion: tls.VersionTLS12})
	if err != nil {
		observation.Probe = connectionprofiles.ProbeFailed
		return observation
	}
	defer connection.Close()
	certificates := connection.ConnectionState().PeerCertificates
	if len(certificates) == 0 || certificates[0].VerifyHostname(target.ServerName) != nil {
		observation.Probe = connectionprofiles.ProbeFailed
		return observation
	}
	observation.AcceptedNames = append([]string(nil), certificates[0].DNSNames...)
	if certificates[0].VerifyHostname(target.ServerName) == nil && !slices.Contains(observation.AcceptedNames, target.ServerName) {
		observation.AcceptedNames = append(observation.AcceptedNames, target.ServerName)
	}
	observation.Class = connectionprofiles.OrdinaryTarget
	observation.RouteVerified = true
	observation.Probe = connectionprofiles.ProbePassed
	return observation
}

func cloudflarePrefixes(ctx context.Context) ([]netip.Prefix, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var prefixes []netip.Prefix
	for _, address := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		content, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			return nil, errors.New("Cloudflare address list unavailable")
		}
		for _, line := range strings.Fields(string(content)) {
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, errors.New("Cloudflare address list invalid")
			}
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) == 0 {
		return nil, errors.New("Cloudflare address list empty")
	}
	return prefixes, nil
}

func slicesContainsPrefix(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address.Unmap()) {
			return true
		}
	}
	return false
}

func addressInPrefixes(addresses []netip.Addr, values []string) (bool, bool) {
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return false, false
		}
		for _, address := range addresses {
			if prefix.Contains(address.Unmap()) {
				return true, true
			}
		}
	}
	return false, true
}

func appleOrICloud(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, suffix := range []string{"apple.com", "icloud.com", "me.com", "mac.com"} {
		if hostname == suffix || strings.HasSuffix(hostname, "."+suffix) {
			return true
		}
	}
	return false
}
