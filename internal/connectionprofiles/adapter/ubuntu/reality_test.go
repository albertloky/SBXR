package ubuntu

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type realityProbeResultHost struct {
	observation connectionprofiles.RealityObservation
}

func (host realityProbeResultHost) ObserveReality(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
	return host.observation
}

func (realityProbeResultHost) ValidateReality(context.Context, string, io.Reader) error { return nil }

type authenticatedCandidateStager struct {
	staged        softwarelifecycle.StagedRelease
	authenticated bool
}

func (stager *authenticatedCandidateStager) Stage(_ context.Context, request softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
	stager.authenticated = request.Authenticated()
	return stager.staged, nil
}

func TestObserveCoreCapabilitiesRequiresSuccessfulEmptyServiceSets(t *testing.T) {
	host := RealityHost{now: func() time.Time { return time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC) }, run: func(context.Context, io.Reader, string, ...string) (string, error) { return "\n", nil }}
	observation := host.ObserveCoreCapabilities(t.Context())
	if !observation.XrayNone || !observation.SingBoxNone || observation.CheckedAt.IsZero() {
		t.Fatalf("empty core capabilities = %+v", observation)
	}
	host.run = func(_ context.Context, _ io.Reader, _ string, command ...string) (string, error) {
		if command[len(command)-1] == "sing-box.service" {
			return "", fmt.Errorf("controlled observation failure")
		}
		return "\n", nil
	}
	if failed := host.ObserveCoreCapabilities(t.Context()); !failed.XrayNone || failed.SingBoxNone {
		t.Fatalf("failed capability observation passed: %+v", failed)
	}
}

func TestObserveDeferredRegistryRequiresRealityOnlyAndInactiveSingBox(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/sbxr/xray")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(`{"inbounds":[{"tag":"vless-reality-vision"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	host := RealityHost{root: root, now: time.Now, run: func(_ context.Context, _ io.Reader, _ string, arguments ...string) (string, error) {
		switch arguments[0] {
		case "show":
			if arguments[1] == "--property=UnitFileState" {
				return "disabled\n", nil
			}
			if arguments[1] == "--property=ActiveState" {
				return "inactive\n", nil
			}
		}
		return "", fmt.Errorf("unexpected command %v", arguments)
	}}
	observed := host.ObserveDeferredRegistry(t.Context())
	if !observed.XrayRealityOnly || !observed.SingBoxConfigurationAbsent || !observed.SingBoxServiceDisabled || !observed.SingBoxServiceInactive || observed.CheckedAt.IsZero() {
		t.Fatalf("deferred registry = %+v", observed)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/sbxr/sing-box"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/sbxr/sing-box/config.json"), []byte(`{"inbounds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if residue := host.ObserveDeferredRegistry(t.Context()); residue.SingBoxConfigurationAbsent {
		t.Fatalf("sing-box residue passed: %+v", residue)
	}
}

func TestRealityHostReturnsOnlyTypedSafeUbuntuAndXrayFacts(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "etc/sbxr/xray")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configuration, []byte(`{"secret":"REALITY-SECRET-MARKER"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	serviceGroup := "root\n"
	host := RealityHost{
		root: root,
		probe: func(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityObservation {
			return connectionprofiles.RealityObservation{Probe: connectionprofiles.ProbePassed, Class: connectionprofiles.OrdinaryTarget, AcceptedNames: []string{"edge.example.net"}, RouteVerified: true}
		},
		now:     func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) },
		rootUID: uint32(os.Geteuid()), rootGID: uint32(os.Getegid()),
		run: func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
			command := name + " " + strings.Join(arguments, " ")
			switch command {
			case "systemctl show --property=Id --value xray.service":
				return "xray.service\n", nil
			case "systemctl show --property=User --value xray.service":
				return "root\n", nil
			case "systemctl show --property=Group --value xray.service":
				return serviceGroup, nil
			case "systemctl is-active xray.service":
				return "active\n", nil
			case "systemctl show --property=CapabilityBoundingSet --value xray.service":
				return "CAP_NET_BIND_SERVICE\n", nil
			case "systemctl show --property=AmbientCapabilities --value xray.service":
				return "CAP_NET_BIND_SERVICE\n", nil
			case "systemctl show --property=NoNewPrivileges --value xray.service", "systemctl show --property=ProtectHome --value xray.service":
				return "yes\n", nil
			case "systemctl show --property=ProtectSystem --value xray.service":
				return "strict\n", nil
			case "ss -H -ltn sport = :443":
				return "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n", nil
			default:
				return "", fmt.Errorf("unexpected command %s", command)
			}
		},
	}
	observation := host.ObserveReality(t.Context(), connectionprofiles.RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net", ListenerPort: 443})
	if !observation.ConfigurationSafe || !observation.ServiceInstalled || !observation.ServiceRunning || !observation.ServiceContained || observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "root" || !observation.NetBindService || observation.Listener != (connectionprofiles.Listener{Address: "0.0.0.0", Port: 443, Protocol: "tcp"}) {
		t.Fatalf("ObserveReality() = %+v", observation)
	}
	if strings.Contains(fmt.Sprintf("%+v", observation), "REALITY-SECRET-MARKER") {
		t.Fatalf("typed observation leaked protected configuration: %+v", observation)
	}
	serviceGroup = "xray\n"
	if mixed := host.ObserveReality(t.Context(), connectionprofiles.RealityTarget{ListenerPort: 443}); mixed.ServiceIdentity != "" {
		t.Fatalf("mixed root and xray identity accepted: %+v", mixed)
	}
	serviceGroup = "root\n"

	if err := os.Chmod(configuration, 0o600); err != nil {
		t.Fatal(err)
	}
	if unsafe := host.ObserveReality(t.Context(), connectionprofiles.RealityTarget{}); unsafe.ConfigurationSafe {
		t.Fatalf("wrong root-runtime mode accepted: %+v", unsafe)
	}
	if err := os.Chmod(configuration, 0o644); err != nil {
		t.Fatal(err)
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
	if linked.safeConfiguration() {
		t.Fatal("symbolic-link ancestor accepted protected configuration")
	}
}

func TestInstallationRealityTargetReviewUsesTheProductionProbeSeam(t *testing.T) {
	target := connectionprofiles.RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net"}
	base := realityProbeDependencies{
		ping: func(context.Context, string) error { return nil },
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
		},
		cloudflare: func(context.Context) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, nil
		},
		tlsState: func(context.Context, string, string) (tls.ConnectionState, error) {
			return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"edge.example.net"}}}}, nil
		},
		verify: func([]*x509.Certificate) error { return nil },
	}
	review := connectionprofiles.New(realityProbeResultHost{probeRealityTargetWith(t.Context(), target, base)}).ReviewRealityTarget(t.Context(), target)
	if review.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("production target Review = %+v", review)
	}

	for _, unsafe := range []struct {
		name, code string
		target     connectionprofiles.RealityTarget
		change     func(*realityProbeDependencies)
	}{
		{name: "Cloudflare", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", target: target, change: func(dependencies *realityProbeDependencies) {
			dependencies.cloudflare = func(context.Context) ([]netip.Prefix, error) {
				return []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, nil
			}
		}},
		{name: "Apple or iCloud", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", target: connectionprofiles.RealityTarget{Address: "apple.com:443", ServerName: "apple.com"}},
		{name: "iCloud", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", target: connectionprofiles.RealityTarget{Address: "icloud.com:443", ServerName: "icloud.com"}},
		{name: "unknown class", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", target: target, change: func(dependencies *realityProbeDependencies) {
			dependencies.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, fmt.Errorf("controlled DNS failure")
			}
		}},
		{name: "invalid certificate", code: "CONNECTION-PROFILES-REALITY-CERTIFICATE", target: target, change: func(dependencies *realityProbeDependencies) {
			dependencies.verify = func([]*x509.Certificate) error { return fmt.Errorf("controlled certificate failure") }
		}},
		{name: "failed probe", code: "CONNECTION-PROFILES-REALITY-PROBE", target: target, change: func(dependencies *realityProbeDependencies) {
			dependencies.ping = func(context.Context, string) error { return fmt.Errorf("controlled native failure") }
		}},
		{name: "mismatched name", code: "CONNECTION-PROFILES-REALITY-NAME", target: target, change: func(dependencies *realityProbeDependencies) {
			dependencies.tlsState = func(context.Context, string, string) (tls.ConnectionState, error) {
				return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"other.example.net"}}}}, nil
			}
		}},
		{name: "failed route", code: "CONNECTION-PROFILES-REALITY-ROUTE", target: target, change: func(dependencies *realityProbeDependencies) {
			dependencies.tlsState = func(context.Context, string, string) (tls.ConnectionState, error) {
				return tls.ConnectionState{}, fmt.Errorf("controlled route failure")
			}
		}},
	} {
		dependencies := base
		if unsafe.change != nil {
			unsafe.change(&dependencies)
		}
		observation := probeRealityTargetWith(t.Context(), unsafe.target, dependencies)
		if failed := connectionprofiles.New(realityProbeResultHost{observation}).ReviewRealityTarget(t.Context(), unsafe.target); failed.Health.Outcome != connectionprofiles.Failed || failed.Health.Code != unsafe.code || failed.Health.CorrectionFlow().OwnerWork == "" {
			t.Fatalf("%s production target Review = %+v", unsafe.name, failed)
		}
	}
}

func TestRealityTargetReviewRunsAuthenticatedCandidateXray(t *testing.T) {
	xray := []byte("#!/bin/sh\n[ \"$*\" = \"tls ping edge.example.net:443\" ]\n")
	files := map[string][]byte{
		"xray": xray, "sing-box": []byte("qualified sing-box"), "cloudflared": []byte("qualified cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	components, err := softwarelifecycle.BuildComponentArchive(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	application := []byte("authenticated application archive")
	applicationDigest, componentDigest := sha256.Sum256(application), sha256.Sum256(components)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	applicationAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Size: int64(len(application)), SHA256: hex.EncodeToString(applicationDigest[:])}
	componentAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Size: int64(len(components)), SHA256: hex.EncodeToString(componentDigest[:])}
	staged := softwarelifecycle.StagedRelease{Identity: identity, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("c", 64)}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: strings.Repeat("d", 64), ComponentsSHA256: hex.EncodeToString(componentDigest[:]), InstallPath: softwarelifecycle.ReleaseInstallPath(identity), StateSchema: 1}
	handoff := softwarelifecycle.InstallCandidateHandoff{Verified: softwarelifecycle.VerifiedRelease{Identity: identity, Sequence: 1, StateSchema: 1, Assets: []softwarelifecycle.AssetProof{applicationAsset, componentAsset}}, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components}
	stager := &authenticatedCandidateStager{staged: staged}
	candidate, err := softwarelifecycle.RebuildInstallCandidate(t.Context(), handoff, stager)
	if err != nil || !stager.authenticated {
		t.Fatalf("authenticated candidate = (%v, %t)", err, stager.authenticated)
	}
	host, err := NewCandidateHost(candidate)
	if err != nil {
		t.Fatal(err)
	}
	host.probe.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.20")}, nil
	}
	host.probe.cloudflare = func(context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, nil
	}
	host.probe.tlsState = func(context.Context, string, string) (tls.ConnectionState, error) {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{"edge.example.net"}}}}, nil
	}
	host.probe.verify = func([]*x509.Certificate) error { return nil }
	target := connectionprofiles.RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net"}
	if review := connectionprofiles.New(host).ReviewRealityTarget(t.Context(), target); review.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("authenticated candidate target Review = %+v", review)
	}
}

func TestRealityHostRecognizesProviderNetwork(t *testing.T) {
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
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(`{"inbounds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	host := RealityHost{root: root, now: func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) }, rootUID: uint32(os.Geteuid()), rootGID: uint32(os.Getegid())}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		switch name + " " + strings.Join(arguments, " ") {
		case "systemctl show --property=Id --value xray.service":
			return "xray.service\n", nil
		case "systemctl show --property=User --value xray.service", "systemctl show --property=Group --value xray.service":
			return "root\n", nil
		case "systemctl show --property=NoNewPrivileges --value xray.service", "systemctl show --property=ProtectHome --value xray.service":
			return "yes\n", nil
		case "systemctl show --property=ProtectSystem --value xray.service":
			return "strict\n", nil
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
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "root" || !observation.ServiceRunning || !observation.ServiceContained || observation.Listener != (connectionprofiles.Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"}) {
		t.Fatalf("ObserveXHTTP() = %+v", observation)
	}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		switch name + " " + strings.Join(arguments, " ") {
		case "systemctl show --property=Id --value xray.service":
			return "xray.service\n", nil
		case "systemctl show --property=User --value xray.service", "systemctl show --property=Group --value xray.service":
			return "root\n", nil
		case "systemctl show --property=NoNewPrivileges --value xray.service", "systemctl show --property=ProtectHome --value xray.service":
			return "yes\n", nil
		case "systemctl show --property=ProtectSystem --value xray.service":
			return "strict\n", nil
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
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(`{"inbounds":[{"tag":"vless-websocket","listen":"127.0.0.1","port":11081,"streamSettings":{"method":"websocket","security":"none","wsSettings":{"host":"ws.example.com","path":"/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	listeners := "LISTEN 0 4096 127.0.0.1:11081 0.0.0.0:*\n"
	host := RealityHost{root: root, now: func() time.Time { return time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC) }, rootUID: uint32(os.Geteuid()), rootGID: uint32(os.Getegid())}
	host.run = func(_ context.Context, _ io.Reader, name string, arguments ...string) (string, error) {
		switch name + " " + strings.Join(arguments, " ") {
		case "systemctl show --property=Id --value xray.service":
			return "xray.service\n", nil
		case "systemctl show --property=User --value xray.service", "systemctl show --property=Group --value xray.service":
			return "root\n", nil
		case "systemctl show --property=NoNewPrivileges --value xray.service", "systemctl show --property=ProtectHome --value xray.service":
			return "yes\n", nil
		case "systemctl show --property=ProtectSystem --value xray.service":
			return "strict\n", nil
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
	if !observation.ConfigurationSafe || !observation.ConfigurationValid || !observation.HostMatches || !observation.PathMatches || observation.ServiceUnit != "xray.service" || observation.ServiceIdentity != "root" || !observation.ServiceRunning || !observation.ServiceContained || observation.Listener != (connectionprofiles.Listener{Address: "127.0.0.1", Port: 11081, Protocol: "tcp"}) {
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
