package connectionprofiles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const hysteria2PasswordMarker = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type hysteria2Host struct {
	*webSocketHost
	observation connectionprofiles.Hysteria2Observation
	validated   []byte
	validation  error
}

func (host *hysteria2Host) ObserveHysteria2(context.Context, connectionprofiles.Hysteria2ViewRequest) connectionprofiles.Hysteria2Observation {
	return host.observation
}

func (host *hysteria2Host) ValidateSingBox(_ context.Context, version string, configuration io.Reader) error {
	if version != "1.13.16" {
		return fmt.Errorf("wrong version")
	}
	host.validated, _ = io.ReadAll(configuration)
	return host.validation
}

func TestHysteria2ViewRequiresDirectTLSUDPAndSafeService(t *testing.T) {
	request := validHysteria2Request(t)
	result := connectionprofiles.New(healthyHysteria2Host()).ViewHysteria2(t.Context(), request)
	if result.Health.Outcome != connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-HYSTERIA2-HEALTHY" || result.Profile.Listener.Protocol != "udp" {
		t.Fatalf("ViewHysteria2() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, hysteria2PasswordMarker) {
		t.Fatalf("ViewHysteria2() leaked password: %s", rendered)
	}
	for _, test := range []struct {
		name, code string
		edit       func(*connectionprofiles.Hysteria2ViewRequest, *connectionprofiles.Hysteria2Observation)
	}{
		{"wrong certificate identity", "CONNECTION-PROFILES-HYSTERIA2-CERTIFICATE", func(_ *connectionprofiles.Hysteria2ViewRequest, observation *connectionprofiles.Hysteria2Observation) {
			observation.CertificateMatches = false
		}},
		{"TCP listener", "CONNECTION-PROFILES-HYSTERIA2-LISTENER", func(_ *connectionprofiles.Hysteria2ViewRequest, observation *connectionprofiles.Hysteria2Observation) {
			observation.Listener.Protocol = "tcp"
		}},
		{"service failure", "CONNECTION-PROFILES-HYSTERIA2-SERVICE", func(_ *connectionprofiles.Hysteria2ViewRequest, observation *connectionprofiles.Hysteria2Observation) {
			observation.ServiceRunning = false
		}},
		{"unsafe configuration", "CONNECTION-PROFILES-HYSTERIA2-CONFIGURATION", func(_ *connectionprofiles.Hysteria2ViewRequest, observation *connectionprofiles.Hysteria2Observation) {
			observation.ConfigurationSafe = false
		}},
		{"unsafe function", "CONNECTION-PROFILES-HYSTERIA2-FUNCTION", func(_ *connectionprofiles.Hysteria2ViewRequest, observation *connectionprofiles.Hysteria2Observation) {
			observation.ServerFunction = connectionprofiles.ProbeFailed
		}},
		{"broad capability", "CONNECTION-PROFILES-HYSTERIA2-CAPABILITY", func(_ *connectionprofiles.Hysteria2ViewRequest, observation *connectionprofiles.Hysteria2Observation) {
			observation.NetBindService = false
		}},
		{"missing UDP policy", "CONNECTION-PROFILES-HYSTERIA2-NETWORK", func(request *connectionprofiles.Hysteria2ViewRequest, _ *connectionprofiles.Hysteria2Observation) {
			request.Network = networkpolicy.NewListenerContribution(networkpolicy.Result{})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validHysteria2Request(t)
			observation := healthyHysteria2Observation()
			test.edit(&request, &observation)
			host := healthyHysteria2Host()
			host.observation = observation
			got := connectionprofiles.New(host).ViewHysteria2(t.Context(), request)
			if got.Health.Outcome == connectionprofiles.Healthy || got.Health.Code != test.code {
				t.Fatalf("ViewHysteria2() = %+v", got)
			}
		})
	}
}

func TestGenerateHysteria2CredentialsRequiresIndependent32BytePassword(t *testing.T) {
	credentials, err := connectionprofiles.GenerateHysteria2Credentials()
	if err != nil || fmt.Sprintf("%#v", credentials) != "Hysteria2 credentials: ready" {
		t.Fatalf("GenerateHysteria2Credentials() = (%#v, %v)", credentials, err)
	}
	if _, err := connectionprofiles.NewHysteria2Credentials(strings.Repeat("a", 63)); err == nil {
		t.Fatal("short Hysteria2 password accepted")
	}
}

func TestHysteria2PlanValidatesExactSingBoxConfiguration(t *testing.T) {
	host := healthyHysteria2Host()
	request := validHysteria2PlanRequest(t, "profiles-hysteria2-0001")
	result := connectionprofiles.New(host).PlanHysteria2(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) != 5 {
		t.Fatalf("PlanHysteria2() = %+v", result)
	}
	var configuration struct {
		Inbounds []struct {
			Type, Tag, Listen string
			ListenPort        uint16 `json:"listen_port"`
			Users             []struct{ Password string }
			Obfs              map[string]any
			TLS               struct {
				Enabled         bool
				CertificatePath string `json:"certificate_path"`
				KeyPath         string `json:"key_path"`
			}
			Masquerade struct {
				Type       string
				StatusCode int `json:"status_code"`
				Content    string
			}
		}
	}
	if err := json.Unmarshal(host.validated, &configuration); err != nil || len(configuration.Inbounds) != 1 {
		t.Fatalf("complete sing-box configuration = %s, %v", host.validated, err)
	}
	inbound := configuration.Inbounds[0]
	wantPointer := "/var/lib/sbxr/certificates/domain/current"
	if inbound.Type != "hysteria2" || inbound.Tag != "hysteria2-in" || inbound.Listen != "0.0.0.0" || inbound.ListenPort != 443 || len(inbound.Users) != 1 || inbound.Users[0].Password != hysteria2PasswordMarker || len(inbound.Obfs) != 0 || !inbound.TLS.Enabled || inbound.TLS.CertificatePath != wantPointer+"/fullchain.pem" || inbound.TLS.KeyPath != wantPointer+"/privkey.pem" || inbound.Masquerade.Type != "string" || inbound.Masquerade.StatusCode != 404 || inbound.Masquerade.Content != "Not Found\n" || bytes.Contains(host.validated, []byte("zero_rtt")) || bytes.Contains(host.validated, []byte("insecure")) {
		t.Fatalf("Hysteria2 inbound = %+v; raw=%s", inbound, host.validated)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, hysteria2PasswordMarker) || strings.Contains(rendered, string(host.validated)) {
		t.Fatalf("PlanHysteria2() leaked protected material: %s", rendered)
	}
	failedHost := healthyHysteria2Host()
	failedHost.validation = fmt.Errorf("HYSTERIA2-SECRET-MARKER")
	failed := connectionprofiles.New(failedHost).PlanHysteria2(t.Context(), request)
	if failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-HYSTERIA2-NATIVE" || strings.Contains(fmt.Sprintf("%+v", failed), "HYSTERIA2-SECRET-MARKER") {
		t.Fatalf("native Hysteria2 refusal = %+v", failed)
	}
}

func TestHysteria2ConfigurationAgreementRejectsCredentialAndExtraFieldDrift(t *testing.T) {
	host := healthyHysteria2Host()
	request := validHysteria2PlanRequest(t, "profiles-hysteria2-agreement")
	if result := connectionprofiles.New(host).PlanHysteria2(t.Context(), request); result.Plan == nil {
		t.Fatalf("PlanHysteria2() = %+v", result)
	}
	if !connectionprofiles.Hysteria2ConfigurationAgreement(host.validated, request.View) {
		t.Fatal("exact reviewed Hysteria2 configuration did not agree")
	}
	changedPassword := bytes.Replace(host.validated, []byte(hysteria2PasswordMarker), []byte(strings.Repeat("b", 64)), 1)
	if connectionprofiles.Hysteria2ConfigurationAgreement(changedPassword, request.View) {
		t.Fatal("changed active Hysteria2 password agreed with the reviewed Plan")
	}
	extraField := bytes.Replace(host.validated, []byte(`"listen_port":443`), []byte(`"listen_port":443,"up_mbps":100`), 1)
	if connectionprofiles.Hysteria2ConfigurationAgreement(extraField, request.View) {
		t.Fatal("unreviewed active Hysteria2 field agreed with the reviewed Plan")
	}
}

func TestHysteria2PlanBindsStateAndRejectsStaleApply(t *testing.T) {
	host := healthyHysteria2Host()
	request := validHysteria2PlanRequest(t, "profiles-hysteria2-state")
	plan := connectionprofiles.New(host).PlanHysteria2(t.Context(), request).Plan
	profiles, secrets := completeProfileStateForHysteria2()
	xray, singBox, err := plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil || xray == nil || !bytes.Equal(singBox, host.validated) {
		t.Fatalf("reviewed Hysteria2 State configuration = (%s, %s, %v)", xray, singBox, err)
	}
	secrets.clients[profiles.Hysteria2.Password] = strings.Repeat("b", 64)
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("changed Hysteria2 password accepted by reviewed Plan")
	}
	secrets.clients[profiles.Hysteria2.Password] = hysteria2PasswordMarker
	profiles.Hysteria2.Obfuscation = true
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("Hysteria2 obfuscation accepted by reviewed Plan")
	}
	profiles.Hysteria2.Obfuscation = false
	profiles.Hysteria2.MasqueradeURL = "https://other.example.com/"
	if _, _, err := plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("changed Hysteria2 masquerade accepted by reviewed Plan")
	}
	prepared := &realityPreparedState{changeSet: request.ChangeSet, revision: 8, starting: request.StartingStateSHA256, candidate: request.DesiredStateSHA256, planIdentity: plan.Identity(), planSHA: plan.SHA256()}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: request.StartingStateSHA256}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	if result := plan.Apply(systemchanges.Interface{}, prepared, starting, strings.Repeat("c", 64), disk); result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("stale Hysteria2 Apply = %+v", result)
	}
}

func validHysteria2Request(t *testing.T) connectionprofiles.Hysteria2ViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewHysteria2Credentials(hysteria2PasswordMarker)
	if err != nil {
		t.Fatal(err)
	}
	directTLS := connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{Revision: 7, DestinationIP: "192.0.2.10", Hostname: "direct.example.com", Hysteria2: connectionprofiles.DirectTLSConsumer{Port: 443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, TUIC: connectionprofiles.DirectTLSConsumer{Port: 8443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, AnyTLS: connectionprofiles.DirectTLSConsumer{Port: 9443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}})
	return connectionprofiles.Hysteria2ViewRequest{Revision: 7, Enabled: true, DestinationIP: "192.0.2.10", Port: 443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", MasqueradeResponse: "Not Found\n", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", Credentials: credentials, DirectTLS: directTLS, Network: boundRegistryPolicy()}
}

func validHysteria2PlanRequest(t *testing.T, changeSet string) connectionprofiles.Hysteria2PlanRequest {
	t.Helper()
	return connectionprofiles.Hysteria2PlanRequest{Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), WebSocket: validWebSocketRequest(t), View: validHysteria2Request(t), ChangeSet: changeSet, StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
}

func healthyHysteria2Host() *hysteria2Host {
	return &hysteria2Host{webSocketHost: &webSocketHost{xhttpHost: &xhttpHost{realityHost: &realityHost{observation: healthyRealityObservation()}, observation: healthyXHTTPObservation()}, observation: healthyWebSocketObservation()}, observation: healthyHysteria2Observation()}
}

func healthyHysteria2Observation() connectionprofiles.Hysteria2Observation {
	return connectionprofiles.Hysteria2Observation{CheckedAt: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC), ConfigurationSafe: true, ConfigurationValid: true, ConfigurationMatches: true, CertificateMatches: true, ServiceUnit: "sing-box.service", ServiceIdentity: "sing-box", ServiceRunning: true, Listener: connectionprofiles.Listener{Address: "0.0.0.0", Port: 443, Protocol: "udp"}, NetBindService: true, ServerFunction: connectionprofiles.ProbePassed}
}

func completeProfileStateForHysteria2() (state.ConnectionProfiles, profileSecrets) {
	realityUUID, privateKey, shortID := state.NewClientAccessValue("reality-uuid"), state.NewInfrastructureSecret("private"), state.NewClientAccessValue("short-id")
	xhttpUUID, xhttpPath := state.NewClientAccessValue("xhttp-uuid"), state.NewClientAccessValue("xhttp-path")
	websocketUUID, websocketPath := state.NewClientAccessValue("websocket-uuid"), state.NewClientAccessValue("websocket-path")
	hysteriaPassword := state.NewClientAccessValue("hysteria-password")
	profiles := state.ConnectionProfiles{VLESSRealityVision: state.VLESSRealityVision{Enabled: true, Port: 443, UUID: realityUUID, PrivateKey: privateKey, PublicKey: publicKeyMarker, ShortID: shortID, Target: "edge.example.net:443", ServerName: "edge.example.net", Fingerprint: "chrome"}, VLESSXHTTP: state.VLESSXHTTP{Enabled: true, UUID: xhttpUUID, Path: xhttpPath, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp}, VLESSWebSocket: state.VLESSWebSocket{Enabled: true, UUID: websocketUUID, Path: websocketPath, Hostname: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 11081}, Hysteria2: state.Hysteria2{Enabled: true, Port: 443, Password: hysteriaPassword, ServerName: "direct.example.com", CertificateID: "sbxr-domain", MasqueradeURL: "https://example.com/"}}
	secrets := profileSecrets{clients: map[state.ClientAccessValue]string{realityUUID: uuidMarker, shortID: shortIDMarker, xhttpUUID: xhttpUUIDMarker, xhttpPath: xhttpPathMarker, websocketUUID: webSocketUUIDMarker, websocketPath: webSocketPathMarker, hysteriaPassword: hysteria2PasswordMarker}, infrastructure: map[state.InfrastructureSecret]string{privateKey: privateKeyMarker}}
	return profiles, secrets
}

func TestPinnedNativeSingBoxAcceptsCompleteHysteria2Configuration(t *testing.T) {
	binary := os.Getenv("SBXR_SING_BOX_BIN")
	if binary == "" {
		t.Skip("SBXR_SING_BOX_BIN is not set")
	}
	host := healthyHysteria2Host()
	host.validation = nil
	host.webSocketHost.xhttpHost.realityHost.validation = nil
	request := validHysteria2PlanRequest(t, "profiles-hysteria2-native")
	hostValidator := &nativeHysteria2Host{hysteria2Host: host, binary: binary, root: t.TempDir()}
	if result := connectionprofiles.New(hostValidator).PlanHysteria2(t.Context(), request); result.Plan == nil {
		t.Fatalf("native Hysteria2 Plan = %+v", result)
	}
}

type nativeHysteria2Host struct {
	*hysteria2Host
	binary string
	root   string
}

func (host *nativeHysteria2Host) ValidateSingBox(ctx context.Context, version string, configuration io.Reader) error {
	if version != "1.13.16" {
		return fmt.Errorf("wrong version")
	}
	host.validated, _ = io.ReadAll(configuration)
	certificate, key := filepath.Join(host.root, "fullchain.pem"), filepath.Join(host.root, "privkey.pem")
	generate := exec.CommandContext(ctx, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=direct.example.com", "-keyout", key, "-out", certificate, "-days", "1")
	if err := generate.Run(); err != nil {
		return err
	}
	native := bytes.ReplaceAll(host.validated, []byte("/var/lib/sbxr/certificates/domain/current/fullchain.pem"), []byte(certificate))
	native = bytes.ReplaceAll(native, []byte("/var/lib/sbxr/certificates/domain/current/privkey.pem"), []byte(key))
	command := exec.CommandContext(ctx, host.binary, "check", "-c", "/dev/stdin")
	command.Stdin = bytes.NewReader(native)
	return command.Run()
}
