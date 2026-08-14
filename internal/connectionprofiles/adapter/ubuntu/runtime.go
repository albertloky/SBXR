package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type RuntimeExecutor struct {
	run     func(context.Context, string, ...string) error
	observe commandRunner
	prove   func(context.Context, string, string, string, string) error
}

func NewRuntimeExecutor() RuntimeExecutor {
	return RuntimeExecutor{observe: runRealityCommand}
}

func (executor RuntimeExecutor) ValidateConfiguration(root, destination, hostname string, runtime systemchanges.ConnectionProfilesRuntimeBinding, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	active, err := os.ReadFile(filepath.Join(root, singBoxConfigurationPath))
	if err != nil || runtime.SingBoxSHA256 == "" || runtimeDigest(active) != runtime.SingBoxSHA256 || executor.commandInput(ctx, bytes.NewReader(active), "sing-box", "check", "-c", "/dev/stdin") != nil {
		return errors.New("complete sing-box configuration validation failed")
	}
	probe, _, probeErr := probeConfigurationBytes(active, destination, hostname, "")
	if err != nil || probeErr != nil || executor.commandInput(ctx, bytes.NewReader(probe), "sing-box", "check", "-c", "/dev/stdin") != nil {
		return errors.New("Direct TLS probe configuration is invalid")
	}
	return nil
}

func (executor RuntimeExecutor) Activate(root, destination, hostname string, runtime systemchanges.ConnectionProfilesRuntimeBinding, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if executor.command(ctx, "systemctl", "restart", "sing-box.service") != nil {
		return errors.New("sing-box restart failed")
	}
	return executor.proveAll(ctx, root, destination, hostname, runtime)
}

func (executor RuntimeExecutor) Restore(root, destination, hostname string, runtime systemchanges.ConnectionProfilesRuntimeBinding, timeout time.Duration) error {
	return executor.Activate(root, destination, hostname, runtime, timeout)
}

func (executor RuntimeExecutor) Check(root, destination, hostname, code string, runtime systemchanges.ConnectionProfilesRuntimeBinding, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if strings.HasPrefix(code, "CONNECTION-PROFILES-") && !strings.HasSuffix(code, "-DIRECT-TLS") {
		return executor.checkRootRuntime(ctx, root, destination, hostname, code, runtime)
	}
	profile := map[string]string{
		"CONNECTION-PROFILES-HYSTERIA2-DIRECT-TLS": "hysteria2",
		"CONNECTION-PROFILES-TUIC-DIRECT-TLS":      "tuic",
		"CONNECTION-PROFILES-ANYTLS-DIRECT-TLS":    "anytls",
	}[code]
	if profile == "" {
		return false, errors.New("Direct TLS check unavailable")
	}
	active, err := os.ReadFile(filepath.Join(root, singBoxConfigurationPath))
	_, profiles, _, factsErr := runtimeFacts(active, nil, runtime.SingBoxSHA256)
	if err != nil || factsErr != nil {
		return false, errors.New("active Connection Profiles runtime unavailable")
	}
	if !slices.Contains(profiles, profile) {
		return true, nil
	}
	if executor.proofConfiguration(ctx, root, active, profile, destination, hostname) != nil {
		return false, errors.New("Direct TLS consumer proof failed")
	}
	return true, nil
}

func (executor RuntimeExecutor) checkRootRuntime(ctx context.Context, root, destination, hostname, code string, runtime systemchanges.ConnectionProfilesRuntimeBinding) (bool, error) {
	xraySHA256, singBoxSHA256 := runtime.XraySHA256, runtime.SingBoxSHA256
	host := RealityHost{root: root, run: executor.observe, now: time.Now, rootUID: uint32(os.Geteuid()), rootGID: uint32(os.Getegid())}
	listeners, profiles, xrayConfiguration, singBoxConfiguration, factsErr := reviewedRuntimeFacts(root, xraySHA256, singBoxSHA256)
	switch {
	case strings.HasSuffix(code, "-CONFIGURATION"):
		if factsErr != nil || xraySHA256 != "" && !host.safeConfiguration() || singBoxSHA256 != "" && !host.safeSingBoxConfiguration() {
			return false, nil
		}
		commands := []struct {
			name, argument string
			content        []byte
		}{}
		if xraySHA256 != "" {
			commands = append(commands, struct {
				name, argument string
				content        []byte
			}{"xray", "stdin:", xrayConfiguration})
		}
		if singBoxSHA256 != "" {
			commands = append(commands, struct {
				name, argument string
				content        []byte
			}{"sing-box", "/dev/stdin", singBoxConfiguration})
		}
		for _, command := range commands {
			arguments := []string{"check", "-c", command.argument}
			if command.name == "xray" {
				arguments = []string{"run", "-test", "-config", command.argument}
			}
			if executor.commandInput(ctx, bytes.NewReader(command.content), command.name, arguments...) != nil {
				return false, nil
			}
		}
		return true, nil
	case strings.HasSuffix(code, "-SERVICE"):
		if factsErr != nil {
			return false, nil
		}
		xrayPort, singBoxPort := uint16(1), uint16(1)
		xrayNeedsBind, singBoxNeedsBind := false, false
		for _, listener := range listeners {
			if listener.service == "xray.service" {
				xrayPort, xrayNeedsBind = listener.port, xrayNeedsBind || listener.port < 1024
			} else {
				singBoxPort, singBoxNeedsBind = listener.port, singBoxNeedsBind || listener.port < 1024
			}
		}
		if xraySHA256 != "" {
			xray := host.observeXrayService(ctx, xrayPort)
			if xray.unit != "xray.service" || xray.identity != "root" || !xray.running || !xray.contained || xray.netBindService != xrayNeedsBind || (!xrayNeedsBind != xray.noCapabilities) {
				return false, nil
			}
		}
		if singBoxSHA256 != "" {
			singBox, _ := host.observeSingBox(ctx, singBoxPort, singBoxTCP)
			if singBox.ServiceUnit != "sing-box.service" || singBox.ServiceIdentity != "root" || !singBox.ServiceRunning || !singBox.ServiceContained || singBox.NetBindService != singBoxNeedsBind || (!singBoxNeedsBind != singBox.NoCapabilities) {
				return false, nil
			}
		}
		return true, nil
	case strings.HasSuffix(code, "-LISTENER"):
		if factsErr != nil {
			return false, nil
		}
		for _, listener := range listeners {
			flag := "-ltn"
			if listener.protocol == "udp" {
				flag = "-lun"
			}
			output, err := host.run(ctx, nil, "ss", "-H", flag, "sport", "=", ":"+strconv.Itoa(int(listener.port)))
			if err != nil || !listener.matches(output) {
				return false, nil
			}
		}
		return true, nil
	case strings.HasSuffix(code, "-FUNCTION"):
		if factsErr != nil {
			return false, nil
		}
		for _, profile := range profiles {
			if executor.proofConfiguration(ctx, root, singBoxConfiguration, profile, destination, hostname) != nil {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, errors.New("Connection Profiles root-runtime check unavailable")
	}
}

type runtimeListenerFact struct {
	address, protocol, service string
	port                       uint16
}

func (fact runtimeListenerFact) matches(output string) bool {
	if fact.protocol == "udp" {
		listener, ok := exactUDPListener(output, fact.port)
		return ok && listener.Address == fact.address
	}
	_, ok := exactListener(output, fact.port, func(address string) bool { return address == fact.address })
	return ok
}

func reviewedRuntimeFacts(root, xraySHA256, singBoxSHA256 string) ([]runtimeListenerFact, []string, []byte, []byte, error) {
	if xraySHA256 == "" && singBoxSHA256 == "" {
		return nil, nil, nil, nil, errors.New("reviewed runtime configuration unavailable")
	}
	listeners, profiles := []runtimeListenerFact{}, []string{}
	var xrayBytes []byte
	var singBoxBytes []byte
	if xraySHA256 != "" {
		var xray struct {
			Inbounds []struct {
				Listen string
				Port   uint16
			}
		}
		var xrayErr error
		xrayBytes, xrayErr = os.ReadFile(filepath.Join(root, realityConfigurationPath))
		if xrayErr != nil || runtimeDigest(xrayBytes) != xraySHA256 || json.Unmarshal(xrayBytes, &xray) != nil {
			return nil, nil, nil, nil, errors.New("active Xray configuration unavailable")
		}
		for _, inbound := range xray.Inbounds {
			if inbound.Listen == "" || inbound.Port == 0 {
				return nil, nil, nil, nil, errors.New("active Xray listener unavailable")
			}
			listeners = append(listeners, runtimeListenerFact{address: inbound.Listen, port: inbound.Port, protocol: "tcp", service: "xray.service"})
		}
	}
	if singBoxSHA256 != "" {
		var singBoxErr error
		singBoxBytes, singBoxErr = os.ReadFile(filepath.Join(root, singBoxConfigurationPath))
		var runtimeErr error
		listeners, profiles, singBoxBytes, runtimeErr = runtimeFacts(singBoxBytes, listeners, singBoxSHA256)
		if singBoxErr != nil || runtimeErr != nil {
			return nil, nil, nil, nil, errors.New("active sing-box configuration unavailable")
		}
	}
	return listeners, profiles, xrayBytes, singBoxBytes, nil
}

func runtimeFacts(content []byte, listeners []runtimeListenerFact, expectedSHA256 string) ([]runtimeListenerFact, []string, []byte, error) {
	var singBox struct {
		Inbounds []struct {
			Type, Listen string
			ListenPort   uint16 `json:"listen_port"`
		}
	}
	if runtimeDigest(content) != expectedSHA256 || json.Unmarshal(content, &singBox) != nil {
		return nil, nil, nil, errors.New("active sing-box configuration unavailable")
	}
	profiles := make([]string, 0, len(singBox.Inbounds))
	for _, inbound := range singBox.Inbounds {
		protocol := map[string]string{"hysteria2": "udp", "tuic": "udp", "anytls": "tcp"}[inbound.Type]
		if protocol == "" || inbound.Listen == "" || inbound.ListenPort == 0 {
			return nil, nil, nil, errors.New("active sing-box listener unavailable")
		}
		listeners = append(listeners, runtimeListenerFact{address: inbound.Listen, port: inbound.ListenPort, protocol: protocol, service: "sing-box.service"})
		profiles = append(profiles, inbound.Type)
	}
	return listeners, profiles, content, nil
}

func runtimeDigest(content []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(content))
}

func (executor RuntimeExecutor) proveAll(ctx context.Context, root, destination, hostname string, runtime systemchanges.ConnectionProfilesRuntimeBinding) error {
	active, err := os.ReadFile(filepath.Join(root, singBoxConfigurationPath))
	_, profiles, _, factsErr := runtimeFacts(active, nil, runtime.SingBoxSHA256)
	if err != nil || factsErr != nil {
		return errors.New("active Direct TLS consumers unavailable")
	}
	for _, profile := range profiles {
		if executor.proofConfiguration(ctx, root, active, profile, destination, hostname) != nil {
			return errors.New("Direct TLS consumer proof failed")
		}
	}
	return nil
}

func (executor RuntimeExecutor) command(ctx context.Context, name string, arguments ...string) error {
	if executor.run != nil {
		return executor.run(ctx, name, arguments...)
	}
	return run(ctx, name, arguments...)
}

func (executor RuntimeExecutor) commandInput(ctx context.Context, input io.Reader, name string, arguments ...string) error {
	if executor.run != nil {
		return executor.run(ctx, name, arguments...)
	}
	return runInput(ctx, input, name, arguments...)
}

func (executor RuntimeExecutor) proofConfiguration(ctx context.Context, root string, active []byte, profile, destination, hostname string) error {
	if executor.prove != nil {
		return executor.prove(ctx, root, profile, destination, hostname)
	}
	return proveDirectTLS(ctx, active, profile, destination, hostname)
}

func run(ctx context.Context, name string, arguments ...string) error {
	if exec.CommandContext(ctx, name, arguments...).Run() != nil {
		return errors.New("Connection Profiles command failed")
	}
	return nil
}

func runInput(ctx context.Context, input io.Reader, name string, arguments ...string) error {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = input
	if command.Run() != nil {
		return errors.New("Connection Profiles command failed")
	}
	return nil
}

func proveDirectTLS(ctx context.Context, active []byte, profile, destination, hostname string) error {
	probe, port, err := probeConfigurationBytes(active, destination, hostname, profile)
	if err != nil {
		return err
	}
	network := "udp"
	if profile == "anytls" {
		network = "tcp"
	}
	return runInput(ctx, bytes.NewReader(probe), "sing-box", "-c", "/dev/stdin", "tools", "-o", "sbxr-proof-"+profile, "connect", "-n", network, net.JoinHostPort(defaultProbeDestination(destination), strconv.Itoa(int(port))))
}

func probeConfigurationBytes(content []byte, destination, hostname, selected string) ([]byte, uint16, error) {
	var active struct {
		Inbounds []struct {
			Type       string
			ListenPort uint16 `json:"listen_port"`
			Users      []struct{ UUID, Password string }
			TLS        struct {
				ServerName string `json:"server_name"`
			}
		}
	}
	if json.Unmarshal(content, &active) != nil {
		return nil, 0, errors.New("active sing-box configuration unavailable")
	}
	outbounds := make([]map[string]any, 0, len(active.Inbounds))
	selectedPort := uint16(0)
	for _, inbound := range active.Inbounds {
		if (inbound.Type != "hysteria2" && inbound.Type != "tuic" && inbound.Type != "anytls") || inbound.ListenPort == 0 || len(inbound.Users) != 1 || inbound.Users[0].Password == "" || inbound.Type == "tuic" && inbound.Users[0].UUID == "" || inbound.TLS.ServerName == "" || hostname != "" && inbound.TLS.ServerName != hostname {
			return nil, 0, errors.New("active Direct TLS consumer unavailable")
		}
		outbound := map[string]any{"type": inbound.Type, "tag": "sbxr-proof-" + inbound.Type, "server": defaultProbeDestination(destination), "server_port": inbound.ListenPort, "password": inbound.Users[0].Password, "tls": map[string]any{"enabled": true, "server_name": inbound.TLS.ServerName}}
		if inbound.Type == "tuic" {
			outbound["uuid"] = inbound.Users[0].UUID
		}
		outbounds = append(outbounds, outbound)
		if inbound.Type == selected {
			selectedPort = inbound.ListenPort
		}
	}
	if len(outbounds) == 0 || selected != "" && selectedPort == 0 {
		return nil, 0, errors.New("Direct TLS consumer configuration incomplete")
	}
	probe, err := json.Marshal(map[string]any{"log": map[string]any{"level": "warn"}, "outbounds": outbounds})
	if err != nil {
		return nil, 0, err
	}
	return probe, selectedPort, nil
}

func defaultProbeDestination(destination string) string {
	if destination == "" {
		return "127.0.0.1"
	}
	return destination
}
