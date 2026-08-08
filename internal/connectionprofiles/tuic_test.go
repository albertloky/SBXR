package connectionprofiles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/state"
)

const (
	tuicUUIDMarker     = "55555555-5555-4555-8555-555555555555"
	tuicPasswordMarker = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type tuicHost struct {
	*hysteria2Host
	observation connectionprofiles.TUICObservation
}

func (host *tuicHost) ObserveTUIC(context.Context, connectionprofiles.Hysteria2ViewRequest, connectionprofiles.TUICViewRequest) connectionprofiles.TUICObservation {
	return host.observation
}

func TestTUICViewRequiresReplaySafeCubicDirectTLSAndUDP(t *testing.T) {
	host := healthyTUICHost()
	request := validTUICRequest(t)
	result := connectionprofiles.New(host).ViewTUIC(t.Context(), validHysteria2Request(t), request)
	if result.Health.Outcome != connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-TUIC-HEALTHY" || result.Profile.Name != "TUIC" || result.Profile.Port != 8443 {
		t.Fatalf("ViewTUIC() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, tuicUUIDMarker) || strings.Contains(rendered, tuicPasswordMarker) || strings.Contains(rendered, "TUIC v5") {
		t.Fatalf("ViewTUIC() leaked credentials or mislabeled the product: %s", rendered)
	}
	for _, test := range []struct {
		name, code string
		edit       func(*connectionprofiles.TUICViewRequest, *connectionprofiles.TUICObservation)
	}{
		{"zero RTT", "CONNECTION-PROFILES-TUIC-INPUT", func(request *connectionprofiles.TUICViewRequest, _ *connectionprofiles.TUICObservation) {
			request.ZeroRTT = true
		}},
		{"BBR", "CONNECTION-PROFILES-TUIC-INPUT", func(request *connectionprofiles.TUICViewRequest, _ *connectionprofiles.TUICObservation) {
			request.CongestionControl = state.CongestionBBR
		}},
		{"wrong TLS name", "CONNECTION-PROFILES-TUIC-CERTIFICATE", func(_ *connectionprofiles.TUICViewRequest, observation *connectionprofiles.TUICObservation) {
			observation.CertificateMatches = false
		}},
		{"TCP listener", "CONNECTION-PROFILES-TUIC-LISTENER", func(_ *connectionprofiles.TUICViewRequest, observation *connectionprofiles.TUICObservation) {
			observation.Listener.Protocol = "tcp"
		}},
		{"service failure", "CONNECTION-PROFILES-TUIC-SERVICE", func(_ *connectionprofiles.TUICViewRequest, observation *connectionprofiles.TUICObservation) {
			observation.ServiceRunning = false
		}},
		{"missing UDP policy", "CONNECTION-PROFILES-TUIC-NETWORK", func(request *connectionprofiles.TUICViewRequest, _ *connectionprofiles.TUICObservation) {
			request.Network = networkpolicy.NewListenerContribution(networkpolicy.Result{})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, observation := validTUICRequest(t), healthyTUICObservation()
			test.edit(&request, &observation)
			host := healthyTUICHost()
			host.observation = observation
			got := connectionprofiles.New(host).ViewTUIC(t.Context(), validHysteria2Request(t), request)
			if got.Health.Outcome == connectionprofiles.Healthy || got.Health.Code != test.code {
				t.Fatalf("ViewTUIC() = %+v", got)
			}
		})
	}
}

func TestGenerateTUICCredentialsUsesIndependentUUIDAndPassword(t *testing.T) {
	credentials, err := connectionprofiles.GenerateTUICCredentials()
	if err != nil || fmt.Sprintf("%#v", credentials) != "TUIC credentials: ready" {
		t.Fatalf("GenerateTUICCredentials() = (%#v, %v)", credentials, err)
	}
	if _, err := connectionprofiles.NewTUICCredentials(tuicUUIDMarker, strings.Repeat("b", 63)); err == nil {
		t.Fatal("short TUIC password accepted")
	}
}

func TestTUICPlanValidatesCompleteReplaySafeSingBoxConfiguration(t *testing.T) {
	host := healthyTUICHost()
	request := validTUICPlanRequest(t, "profiles-tuic-0001")
	result := connectionprofiles.New(host).PlanTUIC(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || len(result.Plan.Checks()) != 5 {
		t.Fatalf("PlanTUIC() = %+v", result)
	}
	var configuration struct {
		Inbounds []struct {
			Type, Tag, Listen string
			ListenPort        uint16 `json:"listen_port"`
			CongestionControl string `json:"congestion_control"`
			ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
			Users             []struct{ UUID, Password string }
			TLS               struct {
				Enabled    bool
				ServerName string `json:"server_name"`
			}
		}
	}
	if err := json.Unmarshal(host.validated, &configuration); err != nil || len(configuration.Inbounds) != 2 {
		t.Fatalf("complete sing-box configuration = %s, %v", host.validated, err)
	}
	tuic := configuration.Inbounds[1]
	if tuic.Type != "tuic" || tuic.Tag != "tuic-in" || tuic.Listen != "0.0.0.0" || tuic.ListenPort != 8443 || len(tuic.Users) != 1 || tuic.Users[0].UUID != tuicUUIDMarker || tuic.Users[0].Password != tuicPasswordMarker || tuic.CongestionControl != "cubic" || tuic.ZeroRTTHandshake || !bytes.Contains(host.validated, []byte(`"zero_rtt_handshake":false`)) || !tuic.TLS.Enabled || tuic.TLS.ServerName != "direct.example.com" || bytes.Contains(host.validated, []byte("insecure")) || bytes.Contains(host.validated, []byte("TUIC v5")) {
		t.Fatalf("TUIC inbound = %+v; raw=%s", tuic, host.validated)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, tuicUUIDMarker) || strings.Contains(rendered, tuicPasswordMarker) || strings.Contains(rendered, string(host.validated)) {
		t.Fatalf("PlanTUIC() leaked protected material: %s", rendered)
	}
	hysteria2 := request.Hysteria2
	hysteria2.Profiles = &connectionprofiles.SingBoxProfileSet{TUIC: &request.View}
	if !connectionprofiles.TUICConfigurationAgreement(host.validated, hysteria2) || connectionprofiles.TUICConfigurationAgreement(bytes.Replace(host.validated, []byte(`"zero_rtt_handshake":false`), []byte(`"zero_rtt_handshake":true`), 1), hysteria2) {
		t.Fatal("TUIC exact active configuration agreement accepted replay drift")
	}
	profiles, secrets := completeProfileStateForTUIC()
	_, singBox, err := result.Plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil || !bytes.Equal(singBox, host.validated) {
		t.Fatalf("reviewed TUIC State configuration = (%s, %v)", singBox, err)
	}
	secrets.clients[profiles.TUIC.Password] = hysteria2PasswordMarker
	if _, _, err := result.Plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("TUIC reused the Hysteria2 password")
	}
	secrets.clients[profiles.TUIC.Password] = tuicPasswordMarker
	secrets.clients[profiles.TUIC.UUID] = uuidMarker
	if _, _, err := result.Plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("TUIC reused the REALITY UUID")
	}
	profiles, secrets = completeProfileStateForTUIC()
	profiles.Hysteria2.Enabled = false
	if _, _, err := connectionprofiles.New(host).PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("TUIC without its required complete Hysteria2 configuration was accepted")
	}
	failedHost := healthyTUICHost()
	failedHost.validation = fmt.Errorf("TUIC-PASSWORD-SECRET-MARKER")
	failed := connectionprofiles.New(failedHost).PlanTUIC(t.Context(), request)
	if failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-TUIC-NATIVE" || strings.Contains(fmt.Sprintf("%+v", failed), "TUIC-PASSWORD-SECRET-MARKER") {
		t.Fatalf("native TUIC refusal = %+v", failed)
	}
}

func TestTUICPlanAcceptsHysteria2OnlyCurrentStateAndCombinedReplay(t *testing.T) {
	for _, name := range []string{"Hysteria2-only current state", "combined replay needing repair"} {
		t.Run(name, func(t *testing.T) {
			host := healthyTUICHost()
			host.hysteria2Host.observation = connectionprofiles.Hysteria2Observation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true}
			host.observation = connectionprofiles.TUICObservation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true}
			if result := connectionprofiles.New(host).PlanTUIC(t.Context(), validTUICPlanRequest(t, "profiles-tuic-transition")); result.Plan == nil {
				t.Fatalf("PlanTUIC() blocked candidate validation on current active health: %+v", result)
			}
		})
	}
}

func TestHysteria2RemainsHealthyWithReviewedTUICArtifact(t *testing.T) {
	hysteria2, tuic := validHysteria2Request(t), validTUICRequest(t)
	hysteria2.Profiles = &connectionprofiles.SingBoxProfileSet{TUIC: &tuic}
	if result := connectionprofiles.New(healthyTUICHost()).ViewHysteria2(t.Context(), hysteria2); result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("combined Hysteria2 View = %+v", result)
	}
}

func TestPinnedNativeSingBoxAcceptsCompleteTUICConfiguration(t *testing.T) {
	binary := os.Getenv("SBXR_SING_BOX_BIN")
	if binary == "" {
		t.Skip("SBXR_SING_BOX_BIN is not set")
	}
	host := healthyTUICHost()
	host.webSocketHost.xhttpHost.realityHost.validation = nil
	validator := &nativeTUICHost{tuicHost: host, native: &nativeHysteria2Host{hysteria2Host: host.hysteria2Host, binary: binary, root: t.TempDir()}}
	if result := connectionprofiles.New(validator).PlanTUIC(t.Context(), validTUICPlanRequest(t, "profiles-tuic-native")); result.Plan == nil {
		t.Fatalf("native TUIC Plan = %+v", result)
	}
}

type nativeTUICHost struct {
	*tuicHost
	native *nativeHysteria2Host
}

func (host *nativeTUICHost) ValidateSingBox(ctx context.Context, version string, configuration io.Reader) error {
	return host.native.ValidateSingBox(ctx, version, configuration)
}

func validTUICRequest(t *testing.T) connectionprofiles.TUICViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewTUICCredentials(tuicUUIDMarker, tuicPasswordMarker)
	if err != nil {
		t.Fatal(err)
	}
	base := validHysteria2Request(t)
	policy := networkpolicy.Result{Outcome: networkpolicy.Healthy, Policy: networkpolicy.Policy{Exposures: []networkpolicy.Exposure{
		{Purpose: "VLESS REALITY Vision", Address: "public", Port: 443, Protocol: networkpolicy.TCP},
		{Purpose: "Hysteria2", Address: "public", Port: 443, Protocol: networkpolicy.UDP},
		{Purpose: "TUIC", Address: "public", Port: 8443, Protocol: networkpolicy.UDP},
	}}}
	return connectionprofiles.TUICViewRequest{Revision: 7, Enabled: true, DestinationIP: "192.0.2.10", Port: 8443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", CongestionControl: state.CongestionCubic, ZeroRTT: false, Credentials: credentials, DirectTLS: base.DirectTLS, Network: networkpolicy.NewListenerContribution(policy)}
}

func validTUICPlanRequest(t *testing.T, changeSet string) connectionprofiles.TUICPlanRequest {
	t.Helper()
	return connectionprofiles.TUICPlanRequest{Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), WebSocket: validWebSocketRequest(t), Hysteria2: validHysteria2Request(t), View: validTUICRequest(t), ChangeSet: changeSet, StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
}

func healthyTUICHost() *tuicHost {
	return &tuicHost{hysteria2Host: healthyHysteria2Host(), observation: healthyTUICObservation()}
}

func healthyTUICObservation() connectionprofiles.TUICObservation {
	return connectionprofiles.TUICObservation{CheckedAt: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC), ConfigurationSafe: true, ConfigurationValid: true, ConfigurationMatches: true, CertificateMatches: true, ServiceUnit: "sing-box.service", ServiceIdentity: "sing-box", ServiceRunning: true, Listener: connectionprofiles.Listener{Address: "0.0.0.0", Port: 8443, Protocol: "udp"}, NetBindService: true, ServerFunction: connectionprofiles.ProbePassed}
}

func completeProfileStateForTUIC() (state.ConnectionProfiles, profileSecrets) {
	profiles, secrets := completeProfileStateForHysteria2()
	uuid, password := state.NewClientAccessValue("tuic-uuid"), state.NewClientAccessValue("tuic-password")
	profiles.TUIC = state.TUIC{Enabled: true, Port: 8443, UUID: uuid, Password: password, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CongestionControl: state.CongestionCubic, ZeroRTT: false}
	secrets.clients[uuid], secrets.clients[password] = tuicUUIDMarker, tuicPasswordMarker
	return profiles, secrets
}
