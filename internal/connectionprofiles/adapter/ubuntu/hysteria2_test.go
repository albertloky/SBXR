package ubuntu

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

func TestObserveHysteria2ProvesProtectedConfigurationServiceUDPAndFunction(t *testing.T) {
	if listener, ok := exactUDPListener("UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n", 443); !ok || listener.Address != "0.0.0.0" {
		t.Fatalf("test UDP listener fixture is invalid: %+v, %v", listener, ok)
	}
	root := t.TempDir()
	writeHysteria2Configuration(t, root, 0o750, 0o640)
	writeProbeConfigurationAt(t, root)
	writeDomainServingPair(t, root, 0o750, 0o640)
	host := RealityHost{root: root, now: func() time.Time { return time.Unix(1, 0) }, rootUID: uint32(os.Geteuid()), singBoxGID: uint32(os.Getegid()), singBoxGroup: true, singBoxUser: true}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		command := name + " " + strings.Join(arguments, " ")
		switch {
		case command == "systemctl show --property=Id --value sing-box.service":
			return "sing-box.service\n", nil
		case command == "systemctl show --property=User --value sing-box.service":
			return "sing-box\n", nil
		case command == "systemctl show --property=Group --value sing-box.service":
			return "sing-box\n", nil
		case command == "systemctl is-active sing-box.service":
			return "active\n", nil
		case strings.Contains(command, "CapabilityBoundingSet"), strings.Contains(command, "AmbientCapabilities"):
			return "CAP_NET_BIND_SERVICE\n", nil
		case strings.HasPrefix(command, "ss -H -lun"):
			return "UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n", nil
		case strings.HasPrefix(command, "sing-box check -c "):
			return "", nil
		case strings.HasPrefix(command, "openssl x509 -in "):
			return "", nil
		case strings.Contains(command, "tools -o sbxr-proof-hysteria2 connect -n tcp 192.0.2.10:443"), strings.Contains(command, "tools -o sbxr-proof-hysteria2 connect -n udp 192.0.2.10:443"):
			return "", nil
		default:
			t.Fatalf("unexpected command: %s", command)
			return "", nil
		}
	}
	request := hysteria2AdapterRequest(t)
	observation := host.ObserveHysteria2(t.Context(), request)
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.ConfigurationMatches || !observation.CertificateMatches || observation.ServiceUnit != "sing-box.service" || observation.ServiceIdentity != "sing-box" || !observation.ServiceRunning || !observation.NetBindService || observation.Listener != (connectionprofiles.Listener{Address: "0.0.0.0", Port: 443, Protocol: "udp"}) || observation.ServerFunction != connectionprofiles.ProbePassed {
		t.Fatalf("ObserveHysteria2() = %+v", observation)
	}
	writeHysteria2Configuration(t, root, 0o750, 0o600)
	if unsafe := host.ObserveHysteria2(t.Context(), request); unsafe.ConfigurationSafe {
		t.Fatalf("unsafe Hysteria2 configuration accepted: %+v", unsafe)
	}
	writeHysteria2Configuration(t, root, 0o750, 0o640)
	if err := os.Chmod(filepath.Join(root, probeConfiguration), 0o640); err != nil {
		t.Fatal(err)
	}
	if unsafe := host.ObserveHysteria2(t.Context(), request); unsafe.ServerFunction == connectionprofiles.ProbePassed {
		t.Fatalf("unsafe root-only probe configuration accepted: %+v", unsafe)
	}
	if err := os.Chmod(filepath.Join(root, "var/lib/sbxr/certificates/domain/sets/domain-test/privkey.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if unsafe := host.ObserveHysteria2(t.Context(), request); unsafe.CertificateMatches {
		t.Fatalf("unsafe shared certificate pair accepted: %+v", unsafe)
	}
	key := filepath.Join(root, "var/lib/sbxr/certificates/domain/sets/domain-test/privkey.pem")
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, key+".extra-link"); err != nil {
		t.Fatal(err)
	}
	if unsafe := host.ObserveHysteria2(t.Context(), request); unsafe.CertificateMatches {
		t.Fatalf("multiply linked shared private key accepted: %+v", unsafe)
	}
}

func TestObserveTUICProvesCompleteConfigurationListenerTLSAndFunction(t *testing.T) {
	root := t.TempDir()
	writeTUICConfiguration(t, root)
	writeProbeConfigurationAt(t, root)
	writeDomainServingPair(t, root, 0o750, 0o640)
	host := RealityHost{root: root, now: func() time.Time { return time.Unix(1, 0) }, rootUID: uint32(os.Geteuid()), singBoxGID: uint32(os.Getegid()), singBoxGroup: true, singBoxUser: true}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		command := name + " " + strings.Join(arguments, " ")
		switch {
		case strings.Contains(command, "Id"):
			return "sing-box.service", nil
		case strings.Contains(command, "User"), strings.Contains(command, "Group"):
			return "sing-box", nil
		case strings.Contains(command, "is-active"):
			return "active", nil
		case strings.Contains(command, "CapabilityBoundingSet"), strings.Contains(command, "AmbientCapabilities"):
			return "CAP_NET_BIND_SERVICE", nil
		case strings.HasPrefix(command, "ss -H -lun"):
			if strings.HasSuffix(command, ":443") {
				return "UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n", nil
			}
			return "UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*\n", nil
		case strings.HasPrefix(command, "sing-box check"), strings.HasPrefix(command, "openssl x509"):
			return "", nil
		case strings.Contains(command, "tools -o sbxr-proof-tuic connect -n tcp 192.0.2.10:8443"), strings.Contains(command, "tools -o sbxr-proof-tuic connect -n udp 192.0.2.10:8443"):
			return "", nil
		case strings.Contains(command, "tools -o sbxr-proof-hysteria2 connect -n tcp 192.0.2.10:443"), strings.Contains(command, "tools -o sbxr-proof-hysteria2 connect -n udp 192.0.2.10:443"):
			return "", nil
		default:
			t.Fatalf("unexpected command: %s", command)
			return "", nil
		}
	}
	hysteria2, tuic := hysteria2AdapterRequest(t), tuicAdapterRequest(t)
	hysteria2.Profiles = &connectionprofiles.SingBoxProfileSet{TUIC: &tuic}
	observation := host.ObserveTUIC(t.Context(), hysteria2, tuic)
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.ConfigurationMatches || !observation.CertificateMatches || !observation.ServiceRunning || observation.Listener.Port != 8443 || observation.Listener.Protocol != "udp" || observation.ServerFunction != connectionprofiles.ProbePassed {
		t.Fatalf("ObserveTUIC() = %+v", observation)
	}
	if observation := host.ObserveHysteria2(t.Context(), hysteria2); !observation.ConfigurationMatches || observation.Listener.Port != 443 || observation.ServerFunction != connectionprofiles.ProbePassed {
		t.Fatalf("combined Hysteria2 observation = %+v", observation)
	}
}

func TestObserveAnyTLSProvesCombinedConfigurationTCPAndCorePadding(t *testing.T) {
	root := t.TempDir()
	writeAnyTLSConfiguration(t, root)
	writeProbeConfigurationAt(t, root)
	writeDomainServingPair(t, root, 0o750, 0o640)
	host := RealityHost{root: root, now: func() time.Time { return time.Unix(1, 0) }, rootUID: uint32(os.Geteuid()), singBoxGID: uint32(os.Getegid()), singBoxGroup: true, singBoxUser: true}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		command := name + " " + strings.Join(arguments, " ")
		switch {
		case strings.Contains(command, "Id"):
			return "sing-box.service", nil
		case strings.Contains(command, "User"), strings.Contains(command, "Group"):
			return "sing-box", nil
		case strings.Contains(command, "is-active"):
			return "active", nil
		case strings.Contains(command, "CapabilityBoundingSet"), strings.Contains(command, "AmbientCapabilities"):
			return "CAP_NET_BIND_SERVICE", nil
		case strings.HasPrefix(command, "ss -H -ltn"):
			return "LISTEN 0 4096 0.0.0.0:9443 0.0.0.0:*\n", nil
		case strings.HasPrefix(command, "ss -H -lun") && strings.HasSuffix(command, ":443"):
			return "UNCONN 0 0 0.0.0.0:443 0.0.0.0:*\n", nil
		case strings.HasPrefix(command, "ss -H -lun") && strings.HasSuffix(command, ":8443"):
			return "UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*\n", nil
		case strings.HasPrefix(command, "sing-box check"), strings.HasPrefix(command, "openssl x509"):
			return "", nil
		case strings.Contains(command, "tools -o sbxr-proof-anytls connect -n tcp 192.0.2.10:9443"):
			return "", nil
		case strings.Contains(command, "tools -o sbxr-proof-hysteria2 connect -n tcp 192.0.2.10:443"), strings.Contains(command, "tools -o sbxr-proof-hysteria2 connect -n udp 192.0.2.10:443"):
			return "", nil
		case strings.Contains(command, "tools -o sbxr-proof-tuic connect -n tcp 192.0.2.10:8443"), strings.Contains(command, "tools -o sbxr-proof-tuic connect -n udp 192.0.2.10:8443"):
			return "", nil
		default:
			t.Fatalf("unexpected command: %s", command)
			return "", nil
		}
	}
	hysteria2, tuic, anyTLS := hysteria2AdapterRequest(t), tuicAdapterRequest(t), anyTLSAdapterRequest(t)
	hysteria2.Profiles = &connectionprofiles.SingBoxProfileSet{TUIC: &tuic, AnyTLS: &anyTLS}
	observation := host.ObserveAnyTLS(t.Context(), hysteria2, tuic, anyTLS)
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.ConfigurationMatches || !observation.CertificateMatches || !observation.ServiceRunning || observation.Listener != (connectionprofiles.Listener{Address: "0.0.0.0", Port: 9443, Protocol: "tcp"}) || observation.ServerFunction != connectionprofiles.ProbePassed {
		t.Fatalf("ObserveAnyTLS() = %+v", observation)
	}
	if previous := host.ObserveHysteria2(t.Context(), hysteria2); !previous.ConfigurationMatches || previous.Listener.Port != 443 || previous.ServerFunction != connectionprofiles.ProbePassed {
		t.Fatalf("combined Hysteria2 observation = %+v", previous)
	}
	if previous := host.ObserveTUIC(t.Context(), hysteria2, tuic); !previous.ConfigurationMatches || previous.Listener.Port != 8443 || previous.ServerFunction != connectionprofiles.ProbePassed {
		t.Fatalf("combined TUIC observation = %+v", previous)
	}
	path := filepath.Join(root, singBoxConfigurationPath)
	content, _ := os.ReadFile(path)
	content = []byte(strings.Replace(string(content), `"listen_port":9443`, `"listen_port":9443,"padding_scheme":["stop=8"]`, 1))
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
	if drift := host.ObserveAnyTLS(t.Context(), hysteria2, tuic, anyTLS); drift.ConfigurationMatches {
		t.Fatalf("copied AnyTLS padding agreed with core-owned defaults: %+v", drift)
	}
}

func TestObserveHysteria2RefusesMultipleUDPListenersAndWrongCertificate(t *testing.T) {
	root := t.TempDir()
	writeHysteria2Configuration(t, root, 0o750, 0o640)
	writeDomainServingPair(t, root, 0o750, 0o640)
	content, _ := os.ReadFile(filepath.Join(root, "etc/sbxr/sing-box/config.json"))
	content = []byte(strings.Replace(string(content), "direct.example.com", "other.example.com", 1))
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/sing-box/config.json"), content, 0o640); err != nil {
		t.Fatal(err)
	}
	host := RealityHost{root: root, now: time.Now, rootUID: uint32(os.Geteuid()), singBoxGID: uint32(os.Getegid()), singBoxGroup: true, singBoxUser: true}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		command := name + " " + strings.Join(arguments, " ")
		switch {
		case strings.HasPrefix(command, "ss "):
			return "UNCONN 0 0 0.0:443 0.0.0.0:*\nUNCONN 0 0 [::]:443 [::]:*\n", nil
		case strings.Contains(command, "Id"):
			return "sing-box.service", nil
		case strings.Contains(command, "User"), strings.Contains(command, "Group"):
			return "sing-box", nil
		case strings.Contains(command, "is-active"):
			return "active", nil
		case strings.Contains(command, "Capabilities"), strings.Contains(command, "CapabilityBoundingSet"):
			return "CAP_NET_BIND_SERVICE", nil
		case strings.HasPrefix(command, "sing-box check"):
			return "", nil
		default:
			return "", nil
		}
	}
	observation := host.ObserveHysteria2(t.Context(), hysteria2AdapterRequest(t))
	if observation.Listener != (connectionprofiles.Listener{}) || observation.CertificateMatches {
		t.Fatalf("unsafe listener or certificate accepted: %+v", observation)
	}
}

func TestValidateSingBoxUsesPinnedNativeRelease(t *testing.T) {
	var command string
	host := RealityHost{run: func(_ context.Context, input io.Reader, name string, arguments ...string) (string, error) {
		command = name + " " + strings.Join(arguments, " ")
		if input == nil {
			t.Fatal("native configuration not supplied")
		}
		return "", nil
	}}
	if err := host.ValidateSingBox(t.Context(), "1.13.16", strings.NewReader(`{"inbounds":[]}`)); err != nil || command != "sing-box check -c /dev/stdin" {
		t.Fatalf("ValidateSingBox() = %v, command=%q", err, command)
	}
	if err := host.ValidateSingBox(t.Context(), "1.13.15", strings.NewReader(`{}`)); err == nil {
		t.Fatal("unqualified sing-box accepted")
	}
}

func writeHysteria2Configuration(t *testing.T, root string, directoryMode, fileMode os.FileMode) {
	t.Helper()
	directory := filepath.Join(root, "etc/sbxr/sing-box")
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/sbxr"), 0o755); err != nil {
		t.Fatal(err)
	}
	configuration := `{"inbounds":[{"listen":"0.0.0.0","listen_port":443,"masquerade":{"content":"Not Found\n","headers":{"content-type":["text/plain; charset=utf-8"]},"status_code":404,"type":"string"},"tag":"hysteria2-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"hysteria2","users":[{"password":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}],"log":{"level":"warn"},"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}`
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(configuration), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(directory, "config.json"), fileMode); err != nil {
		t.Fatal(err)
	}
}

func hysteria2AdapterRequest(t *testing.T) connectionprofiles.Hysteria2ViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewHysteria2Credentials(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	return connectionprofiles.Hysteria2ViewRequest{Enabled: true, DestinationIP: "192.0.2.10", Port: 443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", MasqueradeResponse: "Not Found\n", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", Credentials: credentials}
}

func tuicAdapterRequest(t *testing.T) connectionprofiles.TUICViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewTUICCredentials("55555555-5555-4555-8555-555555555555", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	return connectionprofiles.TUICViewRequest{Enabled: true, DestinationIP: "192.0.2.10", Port: 8443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", CongestionControl: state.CongestionCubic, Credentials: credentials}
}

func anyTLSAdapterRequest(t *testing.T) connectionprofiles.AnyTLSViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewAnyTLSCredentials(strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	return connectionprofiles.AnyTLSViewRequest{Enabled: true, DestinationIP: "192.0.2.10", Port: 9443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", MinimumSingBoxVersion: "1.12.0", SingBoxVersion: "1.13.16", UseCorePadding: true, Credentials: credentials}
}

func writeTUICConfiguration(t *testing.T, root string) {
	t.Helper()
	writeHysteria2Configuration(t, root, 0o750, 0o640)
	path := filepath.Join(root, singBoxConfigurationPath)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), `}],"log"`, `},{"congestion_control":"cubic","listen":"0.0.0.0","listen_port":8443,"tag":"tuic-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"tuic","users":[{"password":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","uuid":"55555555-5555-4555-8555-555555555555"}],"zero_rtt_handshake":false}],"log"`, 1))
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
}

func writeAnyTLSConfiguration(t *testing.T, root string) {
	t.Helper()
	writeTUICConfiguration(t, root)
	path := filepath.Join(root, singBoxConfigurationPath)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.Replace(string(content), `}],"log"`, `},{"listen":"0.0.0.0","listen_port":9443,"tag":"anytls-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"anytls","users":[{"password":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}],"log"`, 1))
	if err := os.WriteFile(path, content, 0o640); err != nil {
		t.Fatal(err)
	}
}

func writeDomainServingPair(t *testing.T, root string, directoryMode, fileMode os.FileMode) {
	t.Helper()
	base := filepath.Join(root, "var/lib/sbxr/certificates/domain")
	set := filepath.Join(base, "sets/domain-test")
	if err := os.MkdirAll(set, directoryMode); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{base, set} {
		if err := os.Chmod(directory, directoryMode); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		if err := os.WriteFile(filepath.Join(set, name), []byte("protected"), fileMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("sets/domain-test", filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
}
