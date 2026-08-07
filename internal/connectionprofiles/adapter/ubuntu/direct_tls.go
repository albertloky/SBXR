package ubuntu

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const probeConfiguration = "var/lib/sbxr/connection-profiles/direct-tls-probes.json"

type DirectTLSExecutor struct {
	run   func(context.Context, string, ...string) error
	prove func(context.Context, string, string, string, string) error
}

func NewDirectTLSExecutor() DirectTLSExecutor {
	return DirectTLSExecutor{run: run, prove: proveDirectTLS}
}

func (executor DirectTLSExecutor) ValidateConfiguration(root, destination, hostname string, timeout time.Duration) error {
	if validateProbeConfiguration(root, destination, hostname) != nil {
		return errors.New("Direct TLS probe configuration is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, configuration := range []string{filepath.Join(root, "etc/sing-box/config.json"), filepath.Join(root, probeConfiguration)} {
		if executor.command(ctx, "sing-box", "check", "-c", configuration) != nil {
			return errors.New("complete sing-box configuration validation failed")
		}
	}
	return nil
}

func (executor DirectTLSExecutor) Activate(root, destination, hostname string, timeout time.Duration) error {
	if validateProbeConfiguration(root, destination, hostname) != nil {
		return errors.New("Direct TLS probe configuration is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if executor.command(ctx, "systemctl", "restart", "sing-box.service") != nil {
		return errors.New("sing-box restart failed")
	}
	return executor.proveAll(ctx, root, destination, hostname)
}

func (executor DirectTLSExecutor) Restore(root, destination, hostname string, timeout time.Duration) error {
	return executor.Activate(root, destination, hostname, timeout)
}

func (executor DirectTLSExecutor) Check(root, destination, hostname, code string, timeout time.Duration) (bool, error) {
	if validateProbeConfiguration(root, destination, hostname) != nil {
		return false, errors.New("Direct TLS probe configuration is invalid")
	}
	profile := map[string]string{
		"CONNECTION-PROFILES-HYSTERIA2-DIRECT-TLS": "hysteria2",
		"CONNECTION-PROFILES-TUIC-DIRECT-TLS":      "tuic",
		"CONNECTION-PROFILES-ANYTLS-DIRECT-TLS":    "anytls",
	}[code]
	if profile == "" {
		return false, errors.New("Direct TLS check unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if executor.proof(ctx, root, profile, destination, hostname) != nil {
		return false, errors.New("Direct TLS consumer proof failed")
	}
	return true, nil
}

func (executor DirectTLSExecutor) proveAll(ctx context.Context, root, destination, hostname string) error {
	for _, profile := range []string{"hysteria2", "tuic", "anytls"} {
		if executor.proof(ctx, root, profile, destination, hostname) != nil {
			return errors.New("Direct TLS consumer proof failed")
		}
	}
	return nil
}

func (executor DirectTLSExecutor) command(ctx context.Context, name string, arguments ...string) error {
	if executor.run != nil {
		return executor.run(ctx, name, arguments...)
	}
	return run(ctx, name, arguments...)
}

func (executor DirectTLSExecutor) proof(ctx context.Context, root, profile, destination, hostname string) error {
	if executor.prove != nil {
		return executor.prove(ctx, root, profile, destination, hostname)
	}
	return proveDirectTLS(ctx, root, profile, destination, hostname)
}

func run(ctx context.Context, name string, arguments ...string) error {
	if exec.CommandContext(ctx, name, arguments...).Run() != nil {
		return errors.New("Connection Profiles command failed")
	}
	return nil
}

func proveDirectTLS(ctx context.Context, root, profile, destination, _ string) error {
	port, network := map[string]string{"hysteria2": "443", "tuic": "8443", "anytls": "9443"}[profile], "udp"
	if profile == "anytls" {
		network = "tcp"
	}
	if port == "" {
		return errors.New("unsupported Direct TLS consumer")
	}
	arguments := []string{"-c", filepath.Join(root, probeConfiguration), "tools", "-o", "sbxr-proof-" + profile, "connect", "-n", network, net.JoinHostPort(destination, port)}
	return run(ctx, "sing-box", arguments...)
}

func validateProbeConfiguration(root, destination, hostname string) error {
	name := filepath.Join(root, probeConfiguration)
	directory, directoryErr := os.Lstat(filepath.Dir(name))
	info, err := os.Lstat(name)
	if directoryErr != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm() != 0o700 || directory.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 1<<20 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("Direct TLS probe configuration is unsafe")
	}
	content, err := os.ReadFile(name)
	var configuration struct {
		Outbounds []struct {
			Type, Tag, Server string
			ServerPort        uint16 `json:"server_port"`
			TLS               struct {
				Enabled                    bool
				ServerName                 string `json:"server_name"`
				Insecure                   bool
				DisableSNI                 bool `json:"disable_sni"`
				Certificate                string
				CertificatePath            string   `json:"certificate_path"`
				CertificatePublicKeySHA256 []string `json:"certificate_public_key_sha256"`
				Reality                    map[string]any
			}
		}
	}
	if err != nil || json.Unmarshal(content, &configuration) != nil || len(configuration.Outbounds) != 3 {
		return errors.New("Direct TLS probe configuration is incomplete")
	}
	want := map[string]struct {
		typeName string
		port     uint16
	}{"sbxr-proof-hysteria2": {"hysteria2", 443}, "sbxr-proof-tuic": {"tuic", 8443}, "sbxr-proof-anytls": {"anytls", 9443}}
	for _, outbound := range configuration.Outbounds {
		expected, ok := want[outbound.Tag]
		if !ok || outbound.Type != expected.typeName || outbound.Server != destination || outbound.ServerPort != expected.port || !outbound.TLS.Enabled || outbound.TLS.ServerName != hostname || outbound.TLS.Insecure || outbound.TLS.DisableSNI || outbound.TLS.Certificate != "" || outbound.TLS.CertificatePath != "" || len(outbound.TLS.CertificatePublicKeySHA256) != 0 || len(outbound.TLS.Reality) != 0 {
			return errors.New("Direct TLS probe configuration weakens verification")
		}
		delete(want, outbound.Tag)
	}
	if len(want) != 0 {
		return errors.New("Direct TLS probe consumers disagree")
	}
	return nil
}
