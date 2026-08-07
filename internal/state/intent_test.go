package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var testRelease = ReleaseIdentity{
	Repository:         "https://github.com/albertloky/SBXR",
	Tag:                "v1.0.0",
	Commit:             "0123456789abcdef0123456789abcdef01234567",
	ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
}

type intentStorage struct{ document string }

func (s intentStorage) Read() ([]byte, error) { return []byte(s.document), nil }
func (s intentStorage) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("publication is not used by intent tests")
}

func intentManagedRequest() LoadRequest {
	return LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 7, LastCompletedChangeSet: "change-0007", ReleaseIdentity: testRelease}}
}

func TestLoadCompleteDesiredState(t *testing.T) {
	want := completeDesiredState()
	result, err := New(intentStorage{document: documentFor(t, want)}).Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Snapshot == nil || !reflect.DeepEqual(result.Snapshot.DesiredState, want) {
		t.Fatalf("Load() Desired State = %#v, want the complete typed installation intent", result.Snapshot)
	}
}

func TestLoadRefusesIncompleteOrUnsafeIntent(t *testing.T) {
	secretMarker := "CLOUDFLARE-MANAGEMENT-SECRET-MARKER"
	tests := []struct {
		name   string
		change func(*DesiredState)
		code   string
	}{
		{name: "installation identity", change: func(s *DesiredState) { s.Installation.ID = "" }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "REALITY profile", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSRealityVision.UUID = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "WebSocket path", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSWebSocket.Path = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Hysteria2 credential", change: func(s *DesiredState) { s.ConnectionProfiles.Hysteria2.Password = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "AnyTLS credential", change: func(s *DesiredState) { s.ConnectionProfiles.AnyTLS.Password = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "subscription", change: func(s *DesiredState) { s.Subscription.Token = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Cloudflare authority", change: func(s *DesiredState) { s.Cloudflare.ManagementToken = InfrastructureSecret{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Network Policy address", change: func(s *DesiredState) { s.NetworkPolicy.PublicIPv4 = "" }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "software versions", change: func(s *DesiredState) { s.Software.SingBoxVersion = "" }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Cloudflare XHTTP binding", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSXHTTP.Hostname = "other.example.com" }, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "aliased Cloudflare profile credential", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSWebSocket.UUID = s.ConnectionProfiles.VLESSXHTTP.UUID }, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "aliased Cloudflare profile hostname", change: func(s *DesiredState) {
			s.ConnectionProfiles.VLESSWebSocket.Hostname = s.ConnectionProfiles.VLESSXHTTP.Hostname
			s.Cloudflare.WebSocketHostname = s.Cloudflare.XHTTPHostname
		}, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "direct certificate binding", change: func(s *DesiredState) { s.Certificates.DomainHostname = "other.example.com" }, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "primary subscription address", change: func(s *DesiredState) { s.NetworkPolicy.PrimarySubscriptionAddress = "192.0.2.11" }, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "TCP port conflict", change: func(s *DesiredState) { s.NetworkPolicy.SSHPort = s.ConnectionProfiles.VLESSRealityVision.Port }, code: "STATE-INTENT-CROSS-SECTION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := completeDesiredState()
			tt.change(&desired)
			result, err := New(intentStorage{document: documentFor(t, desired)}).Load(intentManagedRequest())
			if result.Status != RecoveryRequired {
				t.Fatalf("status = %q, want Recovery Required", result.Status)
			}
			var finding *Finding
			if !errors.As(err, &finding) || finding.Code != tt.code {
				t.Fatalf("error = %#v, want finding %s", err, tt.code)
			}
			if strings.Contains(err.Error(), secretMarker) {
				t.Fatal("finding exposed an Infrastructure Secret")
			}
		})
	}
}

func TestLoadRequiresExactIntentSchema(t *testing.T) {
	document := documentFor(t, completeDesiredState())
	for _, tt := range []struct {
		name     string
		document string
	}{
		{name: "case-changed section", document: strings.Replace(document, `"installation":`, `"Installation":`, 1)},
		{name: "Observed State", document: strings.Replace(document, `"software":`, `"observed_state":{},"software":`, 1)},
		{name: "generic extension", document: strings.Replace(document, `"software":`, `"extensions":{},"software":`, 1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := New(intentStorage{document: tt.document}).Load(intentManagedRequest())
			var finding *Finding
			if result.Status != RecoveryRequired || !errors.As(err, &finding) || finding.Code != "STATE-DOCUMENT-UNSUPPORTED-FIELD" {
				t.Fatalf("Load() = (%+v, %v), want exact-schema refusal", result, err)
			}
		})
	}
}

func TestLoadTreatsSecretsAsOpaqueAndDoesNotRenderThem(t *testing.T) {
	desired := completeDesiredState()
	if rendered, err := json.Marshal(desired); err == nil || strings.Contains(string(rendered), "CLOUDFLARE-MANAGEMENT-SECRET-MARKER") {
		t.Fatal("general JSON rendering exposed protected Desired State")
	}
	result, err := New(intentStorage{document: documentFor(t, desired)}).Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	if rendered, err := json.Marshal(result.Snapshot); err == nil || strings.Contains(string(rendered), "CLOUDFLARE-MANAGEMENT-SECRET-MARKER") {
		t.Fatal("Snapshot JSON rendering exposed protected Desired State")
	}
}

func TestLoadAllowsPortReuseByDisabledProfiles(t *testing.T) {
	desired := completeDesiredState()
	desired.ConnectionProfiles.VLESSRealityVision.Enabled = false
	desired.NetworkPolicy.SSHPort = desired.ConnectionProfiles.VLESSRealityVision.Port
	result, err := New(intentStorage{document: documentFor(t, desired)}).Load(intentManagedRequest())
	if err != nil || result.Status != Managed {
		t.Fatalf("Load() = (%+v, %v), want disabled listener port ignored", result, err)
	}
}

func completeDesiredState() DesiredState {
	return DesiredState{
		Installation: InstallationIdentity{
			ID:     "550e8400-e29b-41d4-a716-446655440000",
			Domain: "example.com",
		},
		ConnectionProfiles: ConnectionProfiles{
			VLESSRealityVision: VLESSRealityVision{
				Enabled:     true,
				Port:        443,
				UUID:        NewClientAccessValue("11111111-1111-4111-8111-111111111111"),
				PrivateKey:  NewInfrastructureSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				PublicKey:   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
				ShortID:     NewClientAccessValue("1111111111111111"),
				Target:      "www.microsoft.com:443",
				ServerName:  "www.microsoft.com",
				Fingerprint: "chrome",
			},
			VLESSXHTTP: VLESSXHTTP{
				Enabled:       true,
				UUID:          NewClientAccessValue("22222222-2222-4222-8222-222222222222"),
				Hostname:      "xhttp.example.com",
				OriginAddress: "127.0.0.1",
				OriginPort:    11080,
				Mode:          XHTTPPacketUp,
			},
			VLESSWebSocket: VLESSWebSocket{
				Enabled:       true,
				UUID:          NewClientAccessValue("33333333-3333-4333-8333-333333333333"),
				Hostname:      "ws.example.com",
				OriginAddress: "127.0.0.1",
				OriginPort:    11081,
				Path:          NewClientAccessValue("/4444444444444444444444444444444444444444444444444444444444444444"),
			},
			Hysteria2: Hysteria2{
				Enabled:           true,
				Port:              443,
				Password:          NewClientAccessValue("HYSTERIA2-SECRET-MARKER-00000001"),
				ServerName:        "direct.example.com",
				CertificateID:     "domain-certificate",
				MasqueradeURL:     "https://example.com/",
				Obfuscation:       false,
				ObfuscationSecret: ClientAccessValue{},
			},
			TUIC: TUIC{
				Enabled:           true,
				Port:              8443,
				UUID:              NewClientAccessValue("55555555-5555-4555-8555-555555555555"),
				Password:          NewClientAccessValue("TUIC-PASSWORD-SECRET-MARKER-00001"),
				ServerName:        "direct.example.com",
				CertificateID:     "domain-certificate",
				CongestionControl: CongestionBBR,
				ZeroRTT:           false,
			},
			AnyTLS: AnyTLS{
				Enabled:       true,
				Port:          9443,
				Password:      NewClientAccessValue("ANYTLS-PASSWORD-SECRET-MARKER-01"),
				ServerName:    "direct.example.com",
				CertificateID: "domain-certificate",
				PaddingScheme: "stop=8",
			},
		},
		Subscription: SubscriptionSettings{
			Token:         NewClientAccessValue("6666666666666666666666666666666666666666666666666666666666666666"),
			ListenPort:    10443,
			CertificateID: "ip-certificate",
		},
		Cloudflare: CloudflareSettings{
			AccountID:            "cloudflare-account",
			ZoneID:               "cloudflare-zone",
			ZoneName:             "example.com",
			TunnelID:             "cloudflare-tunnel-id",
			TunnelName:           "sbxr",
			ManagementToken:      NewInfrastructureSecret("CLOUDFLARE-MANAGEMENT-SECRET-MARKER"),
			TunnelRunToken:       NewInfrastructureSecret("CLOUDFLARE-RUN-SECRET-MARKER-00001"),
			XHTTPHostname:        "xhttp.example.com",
			WebSocketHostname:    "ws.example.com",
			DirectHostname:       "direct.example.com",
			XHTTPDNSRecordID:     "dns-xhttp",
			WebSocketDNSRecordID: "dns-websocket",
			DirectIPv4RecordID:   "dns-direct-ipv4",
		},
		Certificates: CertificateSettings{
			RenewalPolicy:        true,
			ACMEAccountID:        "acme-account",
			IPCertificateID:      "ip-certificate",
			IPServingPointer:     "/var/lib/sbxr/certificates/ip/current",
			DomainCertificateID:  "domain-certificate",
			DomainServingPointer: "/var/lib/sbxr/certificates/domain/current",
			DomainHostname:       "direct.example.com",
		},
		NetworkPolicy: NetworkPolicyInputs{
			SSHPort:                    22,
			PublicIPv4:                 "192.0.2.10",
			PrimarySubscriptionAddress: "192.0.2.10",
		},
		Software: SoftwareSettings{
			XrayVersion:              "25.8.3",
			SingBoxVersion:           "1.12.0",
			CloudflaredVersion:       "2026.7.0",
			CertbotVersion:           "5.4.0",
			AutomaticUpdateDiscovery: true,
		},
	}
}

func documentFor(t *testing.T, desired DesiredState) string {
	t.Helper()
	payload, err := marshalProtectedJSON(desired)
	if err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(payload)
	document, err := json.Marshal(struct {
		SchemaVersion          uint64            `json:"schema_version"`
		Revision               uint64            `json:"revision"`
		ReleaseIdentity        ReleaseIdentity   `json:"release_identity"`
		LastCompletedChangeSet ChangeSetIdentity `json:"last_completed_change_set"`
		Payload                json.RawMessage   `json:"payload"`
		Checksum               string            `json:"checksum"`
	}{1, 7, testRelease, "change-0007", payload, hex.EncodeToString(checksum[:])})
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}
