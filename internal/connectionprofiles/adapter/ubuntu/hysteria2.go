package ubuntu

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
)

const singBoxConfigurationPath = "etc/sbxr/sing-box/config.json"

func (host RealityHost) ObserveHysteria2(ctx context.Context, request connectionprofiles.Hysteria2ViewRequest) connectionprofiles.Hysteria2Observation {
	destination, port, serverName, certificatePointer := request.DestinationIP, request.Port, request.ServerName, request.CertificatePointer
	if host.now == nil {
		host.now = time.Now
	}
	if host.run == nil {
		host.run = runRealityCommand
	}
	unit, _ := host.run(ctx, nil, "systemctl", "show", "--property=Id", "--value", "sing-box.service")
	identity, _ := host.run(ctx, nil, "systemctl", "show", "--property=User", "--value", "sing-box.service")
	group, _ := host.run(ctx, nil, "systemctl", "show", "--property=Group", "--value", "sing-box.service")
	active, activeErr := host.run(ctx, nil, "systemctl", "is-active", "sing-box.service")
	capabilities, _ := host.run(ctx, nil, "systemctl", "show", "--property=CapabilityBoundingSet", "--value", "sing-box.service")
	ambient, _ := host.run(ctx, nil, "systemctl", "show", "--property=AmbientCapabilities", "--value", "sing-box.service")
	listeners, _ := host.run(ctx, nil, "ss", "-H", "-lun", "sport", "=", ":"+strconv.Itoa(int(port)))
	observation := connectionprofiles.Hysteria2Observation{CheckedAt: host.now().UTC(), ConfigurationSafe: host.safeSingBoxConfiguration(), ServiceUnit: strings.TrimSpace(unit), ServiceRunning: activeErr == nil && strings.TrimSpace(active) == "active", NetBindService: strings.TrimSpace(capabilities) == "CAP_NET_BIND_SERVICE" && strings.TrimSpace(ambient) == "CAP_NET_BIND_SERVICE"}
	if host.singBoxUser && strings.TrimSpace(identity) == "sing-box" && strings.TrimSpace(group) == "sing-box" {
		observation.ServiceIdentity = "sing-box"
	}
	if listener, ok := exactUDPListener(listeners, port); ok {
		observation.Listener = listener
	}
	if observation.ConfigurationSafe {
		configuration := filepath.Join(host.root, singBoxConfigurationPath)
		validation, cancel := context.WithTimeout(ctx, 60*time.Second)
		_, err := host.run(validation, nil, "sing-box", "check", "-c", configuration)
		cancel()
		observation.ConfigurationValid = err == nil
		content, readErr := os.ReadFile(configuration)
		observation.ConfigurationMatches = readErr == nil && connectionprofiles.Hysteria2ConfigurationAgreement(content, request)
		observation.CertificateMatches = observation.ConfigurationMatches && host.safeDomainServingPair(certificatePointer)
		if observation.CertificateMatches {
			certificate := filepath.Join(host.root, strings.TrimPrefix(certificatePointer, "/"), "fullchain.pem")
			_, err := host.run(ctx, nil, "openssl", "x509", "-in", certificate, "-noout", "-checkhost", serverName)
			observation.CertificateMatches = err == nil
		}
	}
	probe := filepath.Join(host.root, probeConfiguration)
	passed := observation.ConfigurationValid && observation.CertificateMatches && validateProbeConfiguration(host.root, destination, serverName) == nil
	if passed {
		for _, network := range []string{"tcp", "udp"} {
			_, err := host.run(ctx, nil, "sing-box", "-c", probe, "tools", "-o", "sbxr-proof-hysteria2", "connect", "-n", network, net.JoinHostPort(destination, strconv.Itoa(int(port))))
			passed = passed && err == nil
		}
	}
	if passed {
		observation.ServerFunction = connectionprofiles.ProbePassed
	} else {
		observation.ServerFunction = connectionprofiles.ProbeFailed
	}
	return observation
}

func (host RealityHost) ValidateHysteria2(ctx context.Context, version string, configuration io.Reader) error {
	if version != "1.13.16" || configuration == nil {
		return errors.New("qualified sing-box validation unavailable")
	}
	if host.run == nil {
		host.run = runRealityCommand
	}
	validation, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := host.run(validation, configuration, "sing-box", "check", "-c", "/dev/stdin"); err != nil {
		return errors.New("complete sing-box configuration validation failed")
	}
	return nil
}

func (host RealityHost) safeSingBoxConfiguration() bool {
	if !host.singBoxGroup || !host.singBoxUser {
		return false
	}
	directoryName, fileName := filepath.Join(host.root, "etc/sbxr/sing-box"), filepath.Join(host.root, singBoxConfigurationPath)
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
	return directoryOK && fileOK && directoryStat.Uid == host.rootUID && directoryStat.Gid == host.singBoxGID && fileStat.Uid == host.rootUID && fileStat.Gid == host.singBoxGID && fileStat.Nlink == 1
}

func (host RealityHost) safeDomainServingPair(pointer string) bool {
	if pointer != "/var/lib/sbxr/certificates/domain/current" {
		return false
	}
	for _, ancestor := range []string{"var", "var/lib", "var/lib/sbxr", "var/lib/sbxr/certificates"} {
		info, err := os.Lstat(filepath.Join(host.root, ancestor))
		stat, ok := fileStat(info)
		if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || stat.Uid != host.rootUID {
			return false
		}
	}
	base := filepath.Join(host.root, "var/lib/sbxr/certificates/domain")
	baseInfo, baseErr := os.Lstat(base)
	pointerInfo, pointerErr := os.Lstat(filepath.Join(base, "current"))
	pointerStat, pointerStatOK := fileStat(pointerInfo)
	target, targetErr := os.Readlink(filepath.Join(base, "current"))
	if baseErr != nil || !safeServiceDirectory(baseInfo, host.rootUID, host.singBoxGID) || pointerErr != nil || !pointerStatOK || pointerInfo.Mode()&os.ModeSymlink == 0 || pointerStat.Uid != host.rootUID || pointerStat.Nlink != 1 || targetErr != nil || !safeDomainTarget(target) {
		return false
	}
	setInfo, setErr := os.Lstat(filepath.Join(base, target))
	if setErr != nil || !safeServiceDirectory(setInfo, host.rootUID, host.singBoxGID) {
		return false
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		info, err := os.Lstat(filepath.Join(base, target, name))
		stat, ok := fileStat(info)
		if err != nil || !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o640 || info.Size() <= 0 || info.Size() > 1<<20 || stat.Uid != host.rootUID || stat.Gid != host.singBoxGID || stat.Nlink != 1 {
			return false
		}
	}
	return true
}

func safeServiceDirectory(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := fileStat(info)
	return ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o750 && stat.Uid == uid && stat.Gid == gid
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func safeDomainTarget(target string) bool {
	suffix, ok := strings.CutPrefix(target, "sets/domain-")
	if !ok || suffix == "" || len(suffix) > 128 || strings.ContainsAny(suffix, "/\\.") {
		return false
	}
	for _, character := range suffix {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func exactUDPListener(output string, expectedPort uint16) (connectionprofiles.Listener, bool) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if expectedPort == 0 || len(lines) != 1 {
		return connectionprofiles.Listener{}, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 4 {
		return connectionprofiles.Listener{}, false
	}
	address, port, ok := listenAddress(fields[3])
	if !ok || port != expectedPort || address != "0.0.0.0" && address != "::" && address != "*" {
		return connectionprofiles.Listener{}, false
	}
	return connectionprofiles.Listener{Address: address, Port: port, Protocol: "udp"}, true
}
