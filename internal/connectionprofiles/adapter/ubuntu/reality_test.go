package ubuntu

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
)

func TestRealityHostReturnsOnlyTypedSafeUbuntuAndXrayFacts(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/sbxr/xray")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configuration, []byte(`{"secret":"REALITY-SECRET-MARKER"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	host := RealityHost{
		root: root,
		probe: func(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
			return connectionprofiles.RealityObservation{Probe: connectionprofiles.ProbePassed, Class: connectionprofiles.OrdinaryTarget, AcceptedNames: []string{"edge.example.net"}, RouteVerified: true}
		},
		now:       func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) },
		rootUID:   uint32(os.Geteuid()),
		xrayGID:   uint32(os.Getegid()),
		xrayGroup: true,
		xrayUser:  true,
		run: func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
			command := name + " " + strings.Join(arguments, " ")
			switch command {
			case "systemctl show --property=Id --value xray.service":
				return "xray.service\n", nil
			case "systemctl show --property=User --value xray.service":
				return "xray\n", nil
			case "systemctl show --property=Group --value xray.service":
				return "xray\n", nil
			case "systemctl is-active xray.service":
				return "active\n", nil
			case "systemctl show --property=CapabilityBoundingSet --value xray.service":
				return "CAP_NET_BIND_SERVICE\n", nil
			case "systemctl show --property=AmbientCapabilities --value xray.service":
				return "CAP_NET_BIND_SERVICE\n", nil
			case "ss -H -ltn sport = :443":
				return "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n", nil
			default:
				return "", fmt.Errorf("unexpected command %s", command)
			}
		},
	}
	observation := host.ObserveReality(t.Context(), connectionprofiles.RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net", ListenerPort: 443})
	if !observation.ConfigurationSafe || !observation.ServiceInstalled || !observation.ServiceRunning || observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "xray" || !observation.NetBindService || observation.Listener != (connectionprofiles.Listener{Address: "0.0.0.0", Port: 443, Protocol: "tcp"}) {
		t.Fatalf("ObserveReality() = %+v", observation)
	}
	if strings.Contains(fmt.Sprintf("%+v", observation), "REALITY-SECRET-MARKER") {
		t.Fatalf("typed observation leaked protected configuration: %+v", observation)
	}

	if err := os.Chmod(configuration, 0o644); err != nil {
		t.Fatal(err)
	}
	if unsafe := host.ObserveReality(t.Context(), connectionprofiles.RealityTarget{}); unsafe.ConfigurationSafe {
		t.Fatalf("world-readable configuration accepted: %+v", unsafe)
	}
	if err := os.Chmod(configuration, 0o640); err != nil {
		t.Fatal(err)
	}
	host.xrayGroup = false
	if host.safeConfiguration() {
		t.Fatal("missing xray group accepted root-group material")
	}

	linkedRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(linkedRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "etc/sbxr"), filepath.Join(linkedRoot, "etc/sbxr")); err != nil {
		t.Fatal(err)
	}
	linked := host
	linked.root = linkedRoot
	linked.xrayGroup = true
	if linked.safeConfiguration() {
		t.Fatal("symbolic-link ancestor accepted protected configuration")
	}
}

func TestRealityHostRequiresDistinctXrayUserAndRecognizesProviderNetwork(t *testing.T) {
	host := RealityHost{xrayGroup: true}
	if host.safeConfiguration() {
		t.Fatal("missing non-root xray user accepted protected configuration")
	}
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	if matched, valid := addressInPrefixes(addresses, []string{"192.0.2.0/24"}); !matched || !valid {
		t.Fatalf("provider network match = (%t, %t)", matched, valid)
	}
	if matched, valid := addressInPrefixes(addresses, []string{"bad-prefix"}); matched || valid {
		t.Fatalf("invalid provider prefix = (%t, %t)", matched, valid)
	}
}

func TestRealityHostRunsOnlyPinnedNativeValidationWithConfigurationOnStdin(t *testing.T) {
	var command string
	var input string
	host := RealityHost{run: func(_ context.Context, reader io.Reader, name string, arguments ...string) (string, error) {
		command = name + " " + strings.Join(arguments, " ")
		content, _ := io.ReadAll(reader)
		input = string(content)
		return "ignored native output REALITY-SECRET-MARKER", nil
	}}
	if err := host.ValidateReality(t.Context(), "v26.3.27", strings.NewReader(`{"privateKey":"REALITY-SECRET-MARKER"}`)); err != nil {
		t.Fatal(err)
	}
	if command != "xray run -test -config stdin:" || input != `{"privateKey":"REALITY-SECRET-MARKER"}` || strings.Contains(command, "REALITY-SECRET-MARKER") {
		t.Fatalf("native validation command = %q input = %q", command, input)
	}

	host.run = func(context.Context, io.Reader, string, ...string) (string, error) {
		return "REALITY-SECRET-MARKER", fmt.Errorf("REALITY-SECRET-MARKER")
	}
	if err := host.ValidateReality(t.Context(), "v26.3.27", strings.NewReader(`{}`)); err == nil || strings.Contains(err.Error(), "REALITY-SECRET-MARKER") {
		t.Fatalf("unsafe native failure = %v", err)
	}
	if err := host.ValidateReality(t.Context(), "v26.3.23", strings.NewReader(`{}`)); err == nil {
		t.Fatal("unqualified Xray release accepted")
	}
}

func TestRealityHostObservesExactXHTTPLoopbackListener(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/sbxr/xray")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(`{"inbounds":[]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	host := RealityHost{root: root, now: func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) }, rootUID: uint32(os.Geteuid()), xrayGID: uint32(os.Getegid()), xrayGroup: true, xrayUser: true}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		switch name + " " + strings.Join(arguments, " ") {
		case "systemctl show --property=Id --value xray.service":
			return "xray.service\n", nil
		case "systemctl show --property=User --value xray.service", "systemctl show --property=Group --value xray.service":
			return "xray\n", nil
		case "systemctl is-active xray.service":
			return "active\n", nil
		case "ss -H -ltn sport = :11080":
			return "LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:*\n", nil
		case "xray run -test -config " + filepath.Join(root, realityConfigurationPath):
			return "configuration OK\n", nil
		default:
			return "", fmt.Errorf("unexpected command")
		}
	}
	observation := host.ObserveXHTTP(t.Context(), 11080)
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "xray" || !observation.ServiceRunning || observation.Listener != (connectionprofiles.Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"}) {
		t.Fatalf("ObserveXHTTP() = %+v", observation)
	}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		switch name + " " + strings.Join(arguments, " ") {
		case "systemctl show --property=Id --value xray.service":
			return "xray.service\n", nil
		case "systemctl show --property=User --value xray.service", "systemctl show --property=Group --value xray.service":
			return "xray\n", nil
		case "systemctl is-active xray.service":
			return "active\n", nil
		case "ss -H -ltn sport = :11080":
			return "LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:11080 0.0.0.0:*\n", nil
		case "xray run -test -config " + filepath.Join(root, realityConfigurationPath):
			return "configuration OK\n", nil
		default:
			return "", fmt.Errorf("unexpected command")
		}
	}
	if unsafe := host.ObserveXHTTP(t.Context(), 11080); unsafe.Listener != (connectionprofiles.Listener{}) {
		t.Fatalf("ObserveXHTTP() hid an additional public listener: %+v", unsafe)
	}
}

func TestRealityHostObservesExactWebSocketLoopbackListener(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/sbxr/xray")
	if err := os.MkdirAll(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(`{"inbounds":[{"tag":"vless-websocket","listen":"127.0.0.1","port":11081,"streamSettings":{"method":"websocket","security":"none","wsSettings":{"host":"ws.example.com","path":"/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	listeners := "LISTEN 0 4096 127.0.0.1:11081 0.0.0.0:*\n"
	host := RealityHost{root: root, now: func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) }, rootUID: uint32(os.Geteuid()), xrayGID: uint32(os.Getegid()), xrayGroup: true, xrayUser: true}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		switch name + " " + strings.Join(arguments, " ") {
		case "systemctl show --property=Id --value xray.service":
			return "xray.service\n", nil
		case "systemctl show --property=User --value xray.service", "systemctl show --property=Group --value xray.service":
			return "xray\n", nil
		case "systemctl is-active xray.service":
			return "active\n", nil
		case "ss -H -ltn sport = :11081":
			return listeners, nil
		case "xray run -test -config " + filepath.Join(root, realityConfigurationPath):
			return "configuration OK\n", nil
		default:
			return "", fmt.Errorf("unexpected command")
		}
	}
	observation := host.ObserveWebSocket(t.Context(), 11081, "ws.example.com", "/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.HostMatches || !observation.PathMatches || observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "xray" || !observation.ServiceRunning || observation.Listener != (connectionprofiles.Listener{Address: "127.0.0.1", Port: 11081, Protocol: "tcp"}) {
		t.Fatalf("ObserveWebSocket() = %+v", observation)
	}
	if mismatch := host.ObserveWebSocket(t.Context(), 11081, "wrong.example.com", "/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"); mismatch.HostMatches || mismatch.PathMatches {
		t.Fatalf("ObserveWebSocket() accepted a wrong Host or path: %+v", mismatch)
	}
	listeners += "LISTEN 0 4096 0.0.0.0:11081 0.0.0.0:*\n"
	if unsafe := host.ObserveWebSocket(t.Context(), 11081, "ws.example.com", "/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"); unsafe.Listener != (connectionprofiles.Listener{}) {
		t.Fatalf("ObserveWebSocket() hid an additional public listener: %+v", unsafe)
	}
}

func TestRealityTargetClassHelpersFailClosed(t *testing.T) {
	for _, hostname := range []string{"apple.com", "www.apple.com", "icloud.com", "private.me.com", "mail.mac.com"} {
		if !appleOrICloud(hostname) {
			t.Fatalf("%q was not classified as Apple or iCloud", hostname)
		}
	}
	for _, hostname := range []string{"example.com", "notapple.com", "apple.com.example.net"} {
		if appleOrICloud(hostname) {
			t.Fatalf("%q was falsely classified as Apple or iCloud", hostname)
		}
	}
}

func TestRealityListenerParserNeverPromotesLoopbackToPublic(t *testing.T) {
	for _, value := range []string{"127.0.0.1:443", "[::1]:443", "192.0.2.10:443", "bad"} {
		if address, port, ok := publicListenAddress(value); ok {
			t.Fatalf("publicListenAddress(%q) = (%q, %d, true)", value, address, port)
		}
	}
	for _, value := range []string{"0.0.0.0:443", "[::]:443", "*:443"} {
		if _, port, ok := publicListenAddress(value); !ok || port != 443 {
			t.Fatalf("publicListenAddress(%q) = (_, %d, %t)", value, port, ok)
		}
	}
}
