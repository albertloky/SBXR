package connectionprofiles

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type QualificationFixture struct {
	xray, singBox []byte
	source        PublicationSource
	access        map[state.ClientAccessValue]string
}

// ControlledCloudflareProfileSetupModule uses no native process or network.
func ControlledCloudflareProfileSetupModule() Interface { return New(controlledProfileSetupHost{}) }

type controlledProfileSetupHost struct{ repair bool }

func (controlledProfileSetupHost) ValidateReality(context.Context, string, io.Reader) error {
	return nil
}
func (controlledProfileSetupHost) ValidateSingBox(context.Context, string, io.Reader) error {
	return nil
}
func (host controlledProfileSetupHost) ObserveReality(context.Context, RealityTarget) RealityObservation {
	return RealityObservation{CheckedAt: time.Now(), Probe: ProbePassed, Class: OrdinaryTarget, AcceptedNames: []string{"www.microsoft.com"}, RouteVerified: true, ServiceInstalled: true, ServiceUnit: "xray.service", ServiceIdentity: "root", ServiceRunning: !host.repair, ServiceContained: true, ConfigurationSafe: true, Listener: Listener{Address: "0.0.0.0", Port: 443, Protocol: "tcp"}, NetBindService: true, ProviderNetwork: true}
}
func (controlledProfileSetupHost) ObserveXHTTP(context.Context, uint16) XHTTPObservation {
	return XHTTPObservation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true, ServiceUnit: "xray.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, Listener: Listener{Address: "127.0.0.1", Port: 11080, Protocol: "tcp"}}
}
func (controlledProfileSetupHost) ObserveWebSocket(context.Context, uint16, string, string) WebSocketObservation {
	return WebSocketObservation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true, ServiceUnit: "xray.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, Listener: Listener{Address: "127.0.0.1", Port: 11081, Protocol: "tcp"}, HostMatches: true, PathMatches: true}
}
func controlledSingBoxObservation(port uint16, protocol string) Hysteria2Observation {
	return Hysteria2Observation{CheckedAt: time.Now(), ConfigurationSafe: true, ConfigurationValid: true, ConfigurationMatches: true, ServiceUnit: "sing-box.service", ServiceIdentity: "root", ServiceRunning: true, ServiceContained: true, Listener: Listener{Address: "0.0.0.0", Port: port, Protocol: protocol}, NetBindService: true, ServerFunction: ProbePassed}
}
func (controlledProfileSetupHost) ObserveHysteria2(context.Context, Hysteria2ViewRequest) Hysteria2Observation {
	return controlledSingBoxObservation(443, "udp")
}
func (controlledProfileSetupHost) ObserveTUIC(context.Context, Hysteria2ViewRequest, TUICViewRequest) TUICObservation {
	return controlledSingBoxObservation(8443, "udp")
}
func (controlledProfileSetupHost) ObserveAnyTLS(context.Context, Hysteria2ViewRequest, TUICViewRequest, AnyTLSViewRequest) AnyTLSObservation {
	return controlledSingBoxObservation(9443, "tcp")
}
func (controlledProfileSetupHost) ObserveCoreCapabilities(context.Context) CoreCapabilityObservation {
	return CoreCapabilityObservation{CheckedAt: time.Now()}
}
func (controlledProfileSetupHost) CheckLiveProfiles(_ context.Context, subscription *LiveProfileSubscription, profiles []ProfileID) []LiveProfileEvidence {
	if _, ok := subscription.Consume(); !ok {
		return nil
	}
	result := make([]LiveProfileEvidence, len(profiles))
	for index, profile := range profiles {
		result[index] = LiveProfileEvidence{Profile: profile, Authenticated: true, Uplink: true, Downlink: true}
	}
	return result
}
func (controlledProfileSetupHost) ObserveDeferredRegistry(context.Context) DeferredRegistryObservation {
	return DeferredRegistryObservation{CheckedAt: time.Now(), XrayRealityOnly: true, SingBoxConfigurationAbsent: true, SingBoxServiceDisabled: true, SingBoxServiceInactive: true}
}

// ControlledCloudflareProfileSetup builds the complete later registry from one
// exact Managed revision-1 State lease.
func ControlledCloudflareProfileSetup(snapshot state.Snapshot, secrets state.ConnectionProfileSecretReader, exposure RegistryExposureAuthority) (RegistryViewRequest, RegistryViewRequest, QualificationFixture, error) {
	profiles := snapshot.DesiredState.ConnectionProfiles
	software := snapshot.DesiredState.Software
	singBoxVersion := strings.TrimPrefix(software.SingBoxVersion, "v")
	network := snapshot.DesiredState.NetworkPolicy
	if snapshot.Revision != 1 || profiles.VLESSRealityVision.Lifecycle != state.ProfileEnabled || secrets == nil {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, errors.New("controlled revision 1 registry unavailable")
	}
	reality, err := NewRealityCredentials(secrets.ReadClientAccessValue(profiles.VLESSRealityVision.UUID), secrets.ReadInfrastructureSecret(profiles.VLESSRealityVision.PrivateKey), profiles.VLESSRealityVision.PublicKey, secrets.ReadClientAccessValue(profiles.VLESSRealityVision.ShortID))
	if err != nil {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, err
	}
	current, err := NewRevisionOneRegistry(RegistryViewRequest{ClientAddress: network.PrimarySubscriptionAddress, Reality: ViewRequest{Revision: 1, Port: profiles.VLESSRealityVision.Port, Target: RealityTarget{Address: profiles.VLESSRealityVision.Target, ServerName: profiles.VLESSRealityVision.ServerName}, Fingerprint: profiles.VLESSRealityVision.Fingerprint, XrayVersion: software.XrayVersion}}, reality)
	if err != nil {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, err
	}
	deferred, err := controlledDeferredCredentials()
	if err != nil {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, err
	}
	direct := NewDirectTLSContribution(DirectTLSRequest{Revision: 2, DestinationIP: network.PublicIPv4, Hostname: "direct.example.com", Hysteria2: DirectTLSConsumer{Port: 443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, TUIC: DirectTLSConsumer{Port: 8443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, AnyTLS: DirectTLSConsumer{Port: 9443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}})
	candidate := current
	candidate.Reality.Revision = 2
	candidate.XHTTP = XHTTPViewRequest{Revision: 2, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp, XrayVersion: software.XrayVersion}
	candidate.WebSocket = WebSocketViewRequest{Revision: 2, Hostname: "ws.example.com", TLSName: "ws.example.com", HTTPHost: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 11081, XrayVersion: software.XrayVersion}
	candidate.Hysteria2 = Hysteria2ViewRequest{Revision: 2, DestinationIP: network.PublicIPv4, Port: 443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", MasqueradeResponse: "Not Found\n", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: singBoxVersion, DirectTLS: direct}
	candidate.TUIC = TUICViewRequest{Revision: 2, DestinationIP: network.PublicIPv4, Port: 8443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: singBoxVersion, CongestionControl: state.CongestionCubic, DirectTLS: direct}
	candidate.AnyTLS = AnyTLSViewRequest{Revision: 2, DestinationIP: network.PublicIPv4, Port: 9443, ServerName: "direct.example.com", CertificateID: "sbxr-domain", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", MinimumSingBoxVersion: "1.12.0", SingBoxVersion: singBoxVersion, UseCorePadding: true, DirectTLS: direct}
	candidate, err = NewDeferredRegistry(candidate, deferred)
	if err != nil {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, err
	}
	candidate.Exposure = exposure
	desired, ok := DesiredProfiles(candidate)
	if !ok {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, fmt.Errorf("controlled setup registry invalid: %+v", validateRegistryCandidate(candidate))
	}
	xray, singBox, _ := registryConfigurations(candidate)
	access := map[state.ClientAccessValue]string{}
	for _, value := range []state.ClientAccessValue{desired.VLESSRealityVision.UUID, desired.VLESSRealityVision.ShortID, desired.VLESSXHTTP.UUID, desired.VLESSXHTTP.Path, desired.VLESSWebSocket.UUID, desired.VLESSWebSocket.Path, desired.Hysteria2.Password, desired.Hysteria2.ObfuscationSecret, desired.TUIC.UUID, desired.TUIC.Password, desired.AnyTLS.Password} {
		if secrets.ReadClientAccessValue(value) != "" {
			continue
		}
		if raw := secretForCandidate(value, candidate, nil); raw != "" {
			access[value] = raw
		}
	}
	source, err := PublicationSourceFor(network.PrimarySubscriptionAddress, desired)
	if err != nil {
		return RegistryViewRequest{}, RegistryViewRequest{}, QualificationFixture{}, err
	}
	return current, candidate, QualificationFixture{xray: xray, singBox: singBox, source: source, access: access}, nil
}

func controlledDeferredCredentials() (DeferredRegistryCredentials, error) {
	xhttp, e1 := NewXHTTPCredentials("22222222-2222-4222-8222-222222222222", "/2222222222222222222222222222222222222222222222222222222222222222")
	websocket, e2 := NewWebSocketCredentials("33333333-3333-4333-8333-333333333333", "/3333333333333333333333333333333333333333333333333333333333333333")
	hysteria2, e3 := NewHysteria2Credentials("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tuic, e4 := NewTUICCredentials("55555555-5555-4555-8555-555555555555", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	anyTLS, e5 := NewAnyTLSCredentials("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if err := errors.Join(e1, e2, e3, e4, e5); err != nil {
		return DeferredRegistryCredentials{}, err
	}
	return DeferredRegistryCredentials{XHTTP: xhttp, WebSocket: websocket, Hysteria2: hysteria2, TUIC: tuic, AnyTLS: anyTLS}, nil
}

func secretForCandidate(value state.ClientAccessValue, candidate RegistryViewRequest, current state.ConnectionProfileSecretReader) string {
	if current != nil {
		if raw := current.ReadClientAccessValue(value); raw != "" {
			return raw
		}
	}
	for _, raw := range []string{candidate.XHTTP.Credentials.uuid.value, candidate.XHTTP.Credentials.path.value, candidate.WebSocket.Credentials.uuid.value, candidate.WebSocket.Credentials.path.value, candidate.Hysteria2.Credentials.password.value, candidate.Hysteria2.Credentials.obfuscationSecret.value, candidate.TUIC.Credentials.uuid.value, candidate.TUIC.Credentials.password.value, candidate.AnyTLS.Credentials.password.value} {
		if state.NewClientAccessValue(raw) == value {
			return raw
		}
	}
	return ""
}

func (QualificationFixture) String() string {
	return "Connection Profile qualification fixture: redacted"
}
func (QualificationFixture) GoString() string {
	return "Connection Profile qualification fixture: redacted"
}
func (fixture QualificationFixture) Configurations() ([]byte, []byte) {
	return append([]byte(nil), fixture.xray...), append([]byte(nil), fixture.singBox...)
}
func (fixture QualificationFixture) PublicationSource() PublicationSource { return fixture.source }
func (fixture QualificationFixture) ReadClientAccessValue(value state.ClientAccessValue) string {
	return fixture.access[value]
}

type controlledRepairObservation struct{ observation systemchanges.Observation }

func (adapter controlledRepairObservation) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (controlledRepairObservation) TryLock() (systemchanges.Lock, bool, error) {
	return nil, false, nil
}

// ControlledRepairPlan returns one genuine Connection Profiles repair Plan
// for the exact controlled registry and current State lineage.
func ControlledRepairPlan(ctx context.Context, registry RegistryViewRequest, changeSet, stateSHA string) (*Plan, error) {
	observation := systemchanges.Observation{Status: systemchanges.RecoveryRequired, LastChangeSet: changeSet, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, ForwardRepairAvailable: true, RecoveryCause: systemchanges.CurrentStateDrift, StateRevision: registry.Reality.Revision, StateSHA256: stateSHA, VolatileSHA256: strings.Repeat("9", 64)}
	result := New(controlledProfileSetupHost{repair: true}).PlanRegistry(ctx, RegistryPlanRequest{Current: registry, Candidate: registry, ChangeSet: changeSet, StartingStateSHA256: stateSHA, DesiredStateSHA256: stateSHA, Repair: systemchanges.New(controlledRepairObservation{observation: observation}).ForwardRepairAuthority()})
	if result.Plan == nil {
		return nil, fmt.Errorf("controlled Connection Profiles repair unavailable: %s", result.Health.Code)
	}
	return result.Plan, nil
}

// NewQualificationFixture returns public, no-authority material generated by
// the same complete six-profile renderers used for reviewed Plans.
func NewQualificationFixture() (QualificationFixture, error) {
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		return QualificationFixture{}, err
	}
	reality, realityErr := NewRealityCredentials("11111111-1111-4111-8111-111111111111", base64.RawURLEncoding.EncodeToString(private.Bytes()), base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "0123456789abcdef")
	xhttp, xhttpErr := NewXHTTPCredentials("22222222-2222-4222-8222-222222222222", "/2222222222222222222222222222222222222222222222222222222222222222")
	websocket, websocketErr := NewWebSocketCredentials("33333333-3333-4333-8333-333333333333", "/3333333333333333333333333333333333333333333333333333333333333333")
	hysteria2, hysteria2Err := NewHysteria2Credentials("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tuic, tuicErr := NewTUICCredentials("55555555-5555-4555-8555-555555555555", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	anyTLS, anyTLSErr := NewAnyTLSCredentials("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if errors.Join(realityErr, xhttpErr, websocketErr, hysteria2Err, tuicErr, anyTLSErr) != nil {
		return QualificationFixture{}, errors.New("qualification credentials unavailable")
	}
	directTLS := NewDirectTLSContribution(DirectTLSRequest{Revision: 1, DestinationIP: "192.0.2.10", Hostname: "direct.example.com", Hysteria2: DirectTLSConsumer{Port: 443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, TUIC: DirectTLSConsumer{Port: 8443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}, AnyTLS: DirectTLSConsumer{Port: 9443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"}})
	request := RegistryViewRequest{
		ClientAddress: "192.0.2.10",
		Reality:       ViewRequest{Revision: 1, Enabled: true, Port: 443, Target: RealityTarget{Address: "edge.example.net:443", ServerName: "edge.example.net"}, Fingerprint: "chrome", XrayVersion: "v26.3.27", Credentials: reality},
		XHTTP:         XHTTPViewRequest{Revision: 1, Enabled: true, Hostname: "xhttp.example.com", OriginAddress: "127.0.0.1", OriginPort: 11080, Mode: state.XHTTPPacketUp, XrayVersion: "v26.3.27", Credentials: xhttp},
		WebSocket:     WebSocketViewRequest{Revision: 1, Enabled: true, Hostname: "ws.example.com", TLSName: "ws.example.com", HTTPHost: "ws.example.com", OriginAddress: "127.0.0.1", OriginPort: 11081, XrayVersion: "v26.3.27", Credentials: websocket},
		Hysteria2:     Hysteria2ViewRequest{Revision: 1, Enabled: true, DestinationIP: "192.0.2.10", Port: 443, ServerName: "direct.example.com", CertificateID: "qualification", MasqueradeResponse: "Not Found\n", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", Credentials: hysteria2, DirectTLS: directTLS},
		TUIC:          TUICViewRequest{Revision: 1, Enabled: true, DestinationIP: "192.0.2.10", Port: 8443, ServerName: "direct.example.com", CertificateID: "qualification", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", SingBoxVersion: "1.13.16", CongestionControl: state.CongestionCubic, Credentials: tuic, DirectTLS: directTLS},
		AnyTLS:        AnyTLSViewRequest{Revision: 1, Enabled: true, DestinationIP: "192.0.2.10", Port: 9443, ServerName: "direct.example.com", CertificateID: "qualification", CertificatePointer: "/var/lib/sbxr/certificates/domain/current", MinimumSingBoxVersion: "1.12.0", SingBoxVersion: "1.13.16", UseCorePadding: true, Credentials: anyTLS, DirectTLS: directTLS},
	}
	xrayConfiguration, singBoxConfiguration, _ := registryConfigurations(request)
	if len(xrayConfiguration) == 0 || len(singBoxConfiguration) == 0 {
		return QualificationFixture{}, errors.New("qualification configurations unavailable")
	}
	access := map[state.ClientAccessValue]string{}
	for _, value := range []string{"11111111-1111-4111-8111-111111111111", "0123456789abcdef", "22222222-2222-4222-8222-222222222222", "/2222222222222222222222222222222222222222222222222222222222222222", "33333333-3333-4333-8333-333333333333", "/3333333333333333333333333333333333333333333333333333333333333333", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "55555555-5555-4555-8555-555555555555", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"} {
		access[state.NewClientAccessValue(value)] = value
	}
	return QualificationFixture{xray: xrayConfiguration, singBox: singBoxConfiguration, source: registryPublication(request), access: access}, nil
}
