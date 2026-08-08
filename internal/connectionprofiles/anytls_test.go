package connectionprofiles_test

import (
	"bytes"
	"context"
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

const anyTLSPasswordMarker = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

type anyTLSHost struct {
	*tuicHost
	observation      connectionprofiles.AnyTLSObservation
	coreCapabilities connectionprofiles.CoreCapabilityObservation
}

func (host *anyTLSHost) ObserveAnyTLS(context.Context, connectionprofiles.Hysteria2ViewRequest, connectionprofiles.TUICViewRequest, connectionprofiles.AnyTLSViewRequest) connectionprofiles.AnyTLSObservation {
	return host.observation
}

func (host *anyTLSHost) ObserveCoreCapabilities(context.Context) connectionprofiles.CoreCapabilityObservation {
	return host.coreCapabilities
}

func TestAnyTLSViewRequiresVersionFloorCorePaddingDirectTLSAndTCP(t *testing.T) {
	host := healthyAnyTLSHost()
	request := validAnyTLSRequest(t)
	result := connectionprofiles.New(host).ViewAnyTLS(t.Context(), validHysteria2Request(t), validTUICRequest(t), request)
	if result.Health.Outcome != connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-ANYTLS-HEALTHY" || result.Profile.Name != "AnyTLS" || result.Profile.Port != 9443 {
		t.Fatalf("ViewAnyTLS() = %+v", result)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, anyTLSPasswordMarker) {
		t.Fatalf("ViewAnyTLS() leaked its password: %s", rendered)
	}
	for _, test := range []struct {
		name, code string
		edit       func(*connectionprofiles.AnyTLSViewRequest, *connectionprofiles.AnyTLSObservation)
	}{
		{"below version floor", "CONNECTION-PROFILES-ANYTLS-INPUT", func(request *connectionprofiles.AnyTLSViewRequest, _ *connectionprofiles.AnyTLSObservation) {
			request.MinimumSingBoxVersion = "1.11.0"
		}},
		{"unqualified installed version", "CONNECTION-PROFILES-ANYTLS-INPUT", func(request *connectionprofiles.AnyTLSViewRequest, _ *connectionprofiles.AnyTLSObservation) {
			request.SingBoxVersion = "1.14.0"
		}},
		{"copied padding", "CONNECTION-PROFILES-ANYTLS-INPUT", func(request *connectionprofiles.AnyTLSViewRequest, _ *connectionprofiles.AnyTLSObservation) {
			request.UseCorePadding = false
		}},
		{"wrong TLS identity", "CONNECTION-PROFILES-ANYTLS-CERTIFICATE", func(_ *connectionprofiles.AnyTLSViewRequest, observation *connectionprofiles.AnyTLSObservation) {
			observation.CertificateMatches = false
		}},
		{"UDP listener", "CONNECTION-PROFILES-ANYTLS-LISTENER", func(_ *connectionprofiles.AnyTLSViewRequest, observation *connectionprofiles.AnyTLSObservation) {
			observation.Listener.Protocol = "udp"
		}},
		{"service failure", "CONNECTION-PROFILES-ANYTLS-SERVICE", func(_ *connectionprofiles.AnyTLSViewRequest, observation *connectionprofiles.AnyTLSObservation) {
			observation.ServiceRunning = false
		}},
		{"missing TCP policy", "CONNECTION-PROFILES-ANYTLS-NETWORK", func(request *connectionprofiles.AnyTLSViewRequest, _ *connectionprofiles.AnyTLSObservation) {
			request.Network = networkpolicy.NewListenerContribution(networkpolicy.Result{})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, observation := validAnyTLSRequest(t), healthyAnyTLSObservation()
			test.edit(&request, &observation)
			host := healthyAnyTLSHost()
			host.observation = observation
			got := connectionprofiles.New(host).ViewAnyTLS(t.Context(), validHysteria2Request(t), validTUICRequest(t), request)
			if got.Health.Outcome == connectionprofiles.Healthy || got.Health.Code != test.code {
				t.Fatalf("ViewAnyTLS() = %+v", got)
			}
		})
	}
}

func TestGenerateAnyTLSCredentialsUsesIndependent32BytePassword(t *testing.T) {
	credentials, err := connectionprofiles.GenerateAnyTLSCredentials()
	if err != nil || fmt.Sprintf("%#v", credentials) != "AnyTLS credentials: ready" {
		t.Fatalf("GenerateAnyTLSCredentials() = (%#v, %v)", credentials, err)
	}
	if _, err := connectionprofiles.NewAnyTLSCredentials(strings.Repeat("c", 63)); err == nil {
		t.Fatal("short AnyTLS password accepted")
	}
}

func TestAnyTLSPlanValidatesCompleteConfigurationWithoutCopiedPadding(t *testing.T) {
	host := healthyAnyTLSHost()
	request := validAnyTLSPlanRequest(t, "profiles-anytls-0001")
	result := connectionprofiles.New(host).PlanAnyTLS(t.Context(), request)
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || len(result.Plan.Checks()) != 5 {
		t.Fatalf("PlanAnyTLS() = %+v", result)
	}
	if bytes.Count(host.validated, []byte(`"type"`)) < 4 || !bytes.Contains(host.validated, []byte(`"type":"anytls"`)) || !bytes.Contains(host.validated, []byte(`"listen_port":9443`)) || !bytes.Contains(host.validated, []byte(anyTLSPasswordMarker)) || bytes.Contains(host.validated, []byte(`"padding_scheme"`)) || bytes.Contains(host.validated, []byte(`"insecure"`)) {
		t.Fatalf("complete AnyTLS configuration = %s", host.validated)
	}
	if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, anyTLSPasswordMarker) || strings.Contains(rendered, string(host.validated)) {
		t.Fatalf("PlanAnyTLS() leaked protected material: %s", rendered)
	}
	hysteria2 := request.Hysteria2
	hysteria2.Profiles = &connectionprofiles.SingBoxProfileSet{TUIC: &request.TUIC, AnyTLS: &request.View}
	if !connectionprofiles.AnyTLSConfigurationAgreement(host.validated, hysteria2) || connectionprofiles.AnyTLSConfigurationAgreement(bytes.Replace(host.validated, []byte(`"listen_port":9443`), []byte(`"listen_port":9443,"padding_scheme":["stop=8"]`), 1), hysteria2) {
		t.Fatal("AnyTLS agreement accepted copied or unreviewed padding")
	}
	profiles, secrets := completeProfileStateForAnyTLS()
	_, singBox, err := result.Plan.PrepareConnectionProfiles(profiles, secrets)
	if err != nil || !bytes.Equal(singBox, host.validated) {
		t.Fatalf("reviewed AnyTLS State configuration = (%s, %v)", singBox, err)
	}
	secrets.clients[profiles.AnyTLS.Password] = tuicPasswordMarker
	if _, _, err := result.Plan.PrepareConnectionProfiles(profiles, secrets); err == nil {
		t.Fatal("AnyTLS reused the TUIC password")
	}
	failedHost := healthyAnyTLSHost()
	failedHost.validation = fmt.Errorf("ANYTLS-PASSWORD-SECRET-MARKER")
	failed := connectionprofiles.New(failedHost).PlanAnyTLS(t.Context(), request)
	if failed.Plan != nil || failed.Health.Code != "CONNECTION-PROFILES-ANYTLS-NATIVE" || strings.Contains(fmt.Sprintf("%+v", failed), "ANYTLS-PASSWORD-SECRET-MARKER") {
		t.Fatalf("native AnyTLS refusal = %+v", failed)
	}
}

func TestPinnedNativeSingBoxAcceptsCompleteAnyTLSAndRefusesLaterField(t *testing.T) {
	binary := os.Getenv("SBXR_SING_BOX_BIN")
	if binary == "" {
		t.Skip("SBXR_SING_BOX_BIN is not set")
	}
	host := healthyAnyTLSHost()
	host.webSocketHost.xhttpHost.realityHost.validation = nil
	native := &nativeAnyTLSHost{anyTLSHost: host, native: &nativeHysteria2Host{hysteria2Host: host.hysteria2Host, binary: binary, root: t.TempDir()}}
	if result := connectionprofiles.New(native).PlanAnyTLS(t.Context(), validAnyTLSPlanRequest(t, "profiles-anytls-native")); result.Plan == nil {
		t.Fatalf("native AnyTLS Plan = %+v", result)
	}
	unsupported := bytes.Replace(native.native.validated, []byte(`"enabled":true`), []byte(`"enabled":true,"certificate_provider":"uninstalled-later-field"`), 1)
	if err := native.ValidateSingBox(t.Context(), "1.13.16", bytes.NewReader(unsupported)); err == nil {
		t.Fatal("field from an uninstalled later sing-box release was accepted")
	}
}

type nativeAnyTLSHost struct {
	*anyTLSHost
	native *nativeHysteria2Host
}

func (host *nativeAnyTLSHost) ValidateSingBox(ctx context.Context, version string, configuration io.Reader) error {
	return host.native.ValidateSingBox(ctx, version, configuration)
}

func validAnyTLSRequest(t *testing.T) connectionprofiles.AnyTLSViewRequest {
	t.Helper()
	credentials, err := connectionprofiles.NewAnyTLSCredentials(anyTLSPasswordMarker)
	if err != nil {
		t.Fatal(err)
	}
	base := validHysteria2Request(t)
	return connectionprofiles.AnyTLSViewRequest{Revision: 7, Enabled: true, DestinationIP: "192.0.2.10", Port: 9443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", MinimumSingBoxVersion: "1.12.0", SingBoxVersion: "1.13.16", UseCorePadding: true, Credentials: credentials, DirectTLS: base.DirectTLS, Network: boundRegistryPolicy()}
}

func validAnyTLSPlanRequest(t *testing.T, changeSet string) connectionprofiles.AnyTLSPlanRequest {
	t.Helper()
	return connectionprofiles.AnyTLSPlanRequest{Reality: validRealityRequest(t), XHTTP: validXHTTPRequest(t), WebSocket: validWebSocketRequest(t), Hysteria2: validHysteria2Request(t), TUIC: validTUICRequest(t), View: validAnyTLSRequest(t), ChangeSet: changeSet, StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)}
}

func healthyAnyTLSHost() *anyTLSHost {
	return &anyTLSHost{tuicHost: healthyTUICHost(), observation: healthyAnyTLSObservation()}
}

func healthyAnyTLSObservation() connectionprofiles.AnyTLSObservation {
	return connectionprofiles.AnyTLSObservation{CheckedAt: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC), ConfigurationSafe: true, ConfigurationValid: true, ConfigurationMatches: true, CertificateMatches: true, ServiceUnit: "sing-box.service", ServiceIdentity: "sing-box", ServiceRunning: true, Listener: connectionprofiles.Listener{Address: "0.0.0.0", Port: 9443, Protocol: "tcp"}, NetBindService: true, ServerFunction: connectionprofiles.ProbePassed}
}

func completeProfileStateForAnyTLS() (state.ConnectionProfiles, profileSecrets) {
	profiles, secrets := completeProfileStateForTUIC()
	password := state.NewClientAccessValue("anytls-password")
	profiles.AnyTLS = state.AnyTLS{Enabled: true, Port: 9443, Password: password, ServerName: "direct.example.com", CertificateID: "sbxr-domain", PaddingScheme: "upstream-default"}
	secrets.clients[password] = anyTLSPasswordMarker
	return profiles, secrets
}
