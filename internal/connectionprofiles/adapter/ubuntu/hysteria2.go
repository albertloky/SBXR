package ubuntu

import (
	"bytes"
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

type singBoxListenerProtocol string

const (
	singBoxTCP singBoxListenerProtocol = "tcp"
	singBoxUDP singBoxListenerProtocol = "udp"
)

type singBoxObservationSpec struct {
	destination, serverName, certificatePointer, profile string
	port                                                 uint16
	listener                                             singBoxListenerProtocol
	probeNetworks                                        []string
	agrees                                               func([]byte) bool
}

func (host RealityHost) ObserveHysteria2(ctx context.Context, request connectionprofiles.Hysteria2ViewRequest) connectionprofiles.Hysteria2Observation {
	return host.observeSingBoxProfile(ctx, singBoxObservationSpec{destination: request.DestinationIP, port: request.Port, serverName: request.ServerName, certificatePointer: request.CertificatePointer, profile: "hysteria2", listener: singBoxUDP, probeNetworks: []string{"tcp", "udp"}, agrees: func(content []byte) bool {
		return connectionprofiles.Hysteria2ConfigurationAgreement(content, request)
	}})
}

func (host RealityHost) ObserveTUIC(ctx context.Context, hysteria2 connectionprofiles.Hysteria2ViewRequest, request connectionprofiles.TUICViewRequest) connectionprofiles.TUICObservation {
	return host.observeSingBoxProfile(ctx, singBoxObservationSpec{destination: request.DestinationIP, port: request.Port, serverName: request.ServerName, certificatePointer: request.CertificatePointer, profile: "tuic", listener: singBoxUDP, probeNetworks: []string{"tcp", "udp"}, agrees: func(content []byte) bool {
		return connectionprofiles.TUICConfigurationAgreement(content, hysteria2)
	}})
}

func (host RealityHost) ObserveAnyTLS(ctx context.Context, hysteria2 connectionprofiles.Hysteria2ViewRequest, tuic connectionprofiles.TUICViewRequest, request connectionprofiles.AnyTLSViewRequest) connectionprofiles.AnyTLSObservation {
	return host.observeSingBoxProfile(ctx, singBoxObservationSpec{destination: request.DestinationIP, port: request.Port, serverName: request.ServerName, certificatePointer: request.CertificatePointer, profile: "anytls", listener: singBoxTCP, probeNetworks: []string{"tcp"}, agrees: func(content []byte) bool {
		return connectionprofiles.AnyTLSConfigurationAgreement(content, hysteria2)
	}})
}

func (host RealityHost) observeSingBoxProfile(ctx context.Context, spec singBoxObservationSpec) connectionprofiles.Hysteria2Observation {
	observation, content := host.observeSingBox(ctx, spec.port, spec.listener)
	if observation.ConfigurationSafe {
		observation.ConfigurationMatches = spec.agrees(content)
	}
	probe, _, probeErr := probeConfigurationBytes(content, spec.destination, spec.serverName, spec.profile)
	passed := observation.ConfigurationValid && observation.ConfigurationMatches && probeErr == nil
	if passed {
		for _, network := range spec.probeNetworks {
			_, err := host.run(ctx, bytes.NewReader(probe), "sing-box", "-c", "/dev/stdin", "tools", "-o", "sbxr-proof-"+spec.profile, "connect", "-n", network, net.JoinHostPort(spec.destination, strconv.Itoa(int(spec.port))))
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

func (host *RealityHost) observeSingBox(ctx context.Context, port uint16, protocol singBoxListenerProtocol) (connectionprofiles.Hysteria2Observation, []byte) {
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
	flag := "-lun"
	if protocol == singBoxTCP {
		flag = "-ltn"
	}
	listeners, _ := host.run(ctx, nil, "ss", "-H", flag, "sport", "=", ":"+strconv.Itoa(int(port)))
	observation := connectionprofiles.Hysteria2Observation{CheckedAt: host.now().UTC(), ConfigurationSafe: host.safeSingBoxConfiguration(), ServiceUnit: strings.TrimSpace(unit), ServiceRunning: activeErr == nil && strings.TrimSpace(active) == "active", ServiceContained: host.serviceContained(ctx, "sing-box.service"), NetBindService: strings.TrimSpace(capabilities) == "CAP_NET_BIND_SERVICE" && strings.TrimSpace(ambient) == "CAP_NET_BIND_SERVICE", NoCapabilities: strings.TrimSpace(capabilities) == "" && strings.TrimSpace(ambient) == ""}
	if strings.TrimSpace(identity) == "root" && strings.TrimSpace(group) == "root" {
		observation.ServiceIdentity = "root"
	}
	if protocol == singBoxUDP {
		if listener, ok := exactUDPListener(listeners, port); ok {
			observation.Listener = listener
		}
	} else if listener, ok := exactListener(listeners, port, func(address string) bool { return address == "0.0.0.0" || address == "::" || address == "*" }); ok {
		observation.Listener = listener
	}
	if !observation.ConfigurationSafe {
		return observation, nil
	}
	configuration := filepath.Join(host.root, singBoxConfigurationPath)
	validation, cancel := context.WithTimeout(ctx, 60*time.Second)
	_, err := host.run(validation, nil, "sing-box", "check", "-c", configuration)
	cancel()
	observation.ConfigurationValid = err == nil
	content, _ := os.ReadFile(configuration)
	return observation, content
}

func (host RealityHost) ValidateSingBox(ctx context.Context, version string, configuration io.Reader) error {
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
	directoryName, fileName := filepath.Join(host.root, "etc/sbxr/sing-box"), filepath.Join(host.root, singBoxConfigurationPath)
	for _, ancestor := range []string{filepath.Join(host.root, "etc"), filepath.Join(host.root, "etc/sbxr")} {
		info, err := os.Lstat(ancestor)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Uid != host.rootUID {
			return false
		}
	}
	directory, directoryErr := os.Lstat(directoryName)
	file, fileErr := os.Lstat(fileName)
	if directoryErr != nil || fileErr != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0o755 || !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 || file.Mode().Perm() != 0o644 || file.Size() <= 0 || file.Size() > 1<<20 {
		return false
	}
	directoryStat, directoryOK := directory.Sys().(*syscall.Stat_t)
	fileStat, fileOK := file.Sys().(*syscall.Stat_t)
	return directoryOK && fileOK && directoryStat.Uid == host.rootUID && directoryStat.Gid == host.rootGID && fileStat.Uid == host.rootUID && fileStat.Gid == host.rootGID && fileStat.Nlink == 1
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
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
