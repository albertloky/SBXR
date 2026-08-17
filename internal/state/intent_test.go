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

func TestLoadRevisionOneWithOnlyRealitySetUp(t *testing.T) {
	desired := realityOnlyDesiredState()
	document := strings.Replace(documentFor(t, desired), `"revision":7`, `"revision":1`, 1)
	document = strings.Replace(document, `"last_completed_change_set":"change-0007"`, `"last_completed_change_set":"change-0001"`, 1)
	request := intentManagedRequest()
	request.Lineage.Revision = 1
	request.Lineage.LastCompletedChangeSet = "change-0001"

	result, err := New(intentStorage{document: document}).Load(request)
	if err != nil || result.Status != Managed || result.Snapshot == nil || !reflect.DeepEqual(result.Snapshot.DesiredState, desired) {
		t.Fatalf("Load() reality-only revision 1 = (%+v, %v)", result, err)
	}

	complete := strings.Replace(documentFor(t, completeDesiredState()), `"revision":7`, `"revision":1`, 1)
	complete = strings.Replace(complete, `"last_completed_change_set":"change-0007"`, `"last_completed_change_set":"change-0001"`, 1)
	result, err = New(intentStorage{document: complete}).Load(request)
	var problem *Finding
	if result.Status != RecoveryRequired || !errors.As(err, &problem) || problem.Code != "STATE-PROFILE-LIFECYCLE" {
		t.Fatalf("Load() six-profile revision 1 = (%+v, %v)", result, err)
	}
}

func TestLoadRefusesMixedNotSetUpAndConfiguredProfiles(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*DesiredState)
	}{
		{"one deferred profile configured", func(desired *DesiredState) {
			desired.ConnectionProfiles.AnyTLS.Password = NewClientAccessValue("DEFERRED-CLIENT-SECRET-MARKER")
		}},
		{"one deferred profile enabled", func(desired *DesiredState) {
			desired.ConnectionProfiles.AnyTLS.Lifecycle = ProfileEnabled
			desired.ConnectionProfiles.AnyTLS.Enabled = true
		}},
		{"placeholder Cloudflare facts", func(desired *DesiredState) {
			desired.Cloudflare.TunnelID = "deferred"
		}},
		{"placeholder domain certificate", func(desired *DesiredState) {
			desired.Certificates.DomainCertificateID = "deferred"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			desired := realityOnlyDesiredState()
			test.change(&desired)
			result, err := New(intentStorage{document: documentFor(t, desired)}).Load(intentManagedRequest())
			var problem *Finding
			if result.Status != RecoveryRequired || !errors.As(err, &problem) || problem.Code != "STATE-PROFILE-LIFECYCLE" || strings.Contains(err.Error(), "DEFERRED-CLIENT-SECRET-MARKER") {
				t.Fatalf("Load() placeholder refusal = (%+v, %v)", result, err)
			}
		})
	}
}

func TestLoadPreservesExplicitEnabledAndDisabledProfiles(t *testing.T) {
	desired := completeDesiredState()
	desired.ConnectionProfiles.VLESSRealityVision.Lifecycle = ProfileEnabled
	desired.ConnectionProfiles.VLESSXHTTP.Lifecycle = ProfileDisabled
	desired.ConnectionProfiles.VLESSXHTTP.Enabled = false
	result, err := New(intentStorage{document: documentFor(t, desired)}).Load(intentManagedRequest())
	if err != nil || result.Snapshot == nil || result.Snapshot.DesiredState.ConnectionProfiles.VLESSXHTTP.Lifecycle != ProfileDisabled {
		t.Fatalf("Load() configured lifecycle = (%+v, %v)", result, err)
	}
}

func TestLoadDistinguishesRemovedManagementTokenFromMissingSecret(t *testing.T) {
	removed := completeDesiredState()
	removed.Cloudflare.ManagementToken = InfrastructureSecret{}
	removed.Cloudflare.ManagementTokenRemoved = true
	removed.Cloudflare.ManagementTokenState = CloudflareManagementUnmanaged
	result, err := New(intentStorage{document: documentFor(t, removed)}).Load(intentManagedRequest())
	if err != nil || result.Status != Managed || result.Snapshot == nil || !result.Snapshot.DesiredState.Cloudflare.ManagementTokenRemoved {
		t.Fatalf("deliberately removed token Load() = (%+v, %v)", result, err)
	}

	inconsistent := completeDesiredState()
	inconsistent.Cloudflare.ManagementTokenRemoved = true
	inconsistent.Cloudflare.ManagementTokenState = CloudflareManagementUnmanaged
	result, err = New(intentStorage{document: documentFor(t, inconsistent)}).Load(intentManagedRequest())
	var finding *Finding
	if result.Status != RecoveryRequired || !errors.As(err, &finding) || finding.Code != "STATE-INTENT-INCOMPLETE" {
		t.Fatalf("removed flag with stored token Load() = (%+v, %v)", result, err)
	}

	missingOutcome := completeDesiredState()
	missingOutcome.Cloudflare.ManagementToken = InfrastructureSecret{}
	missingOutcome.Cloudflare.ManagementTokenRemoved = true
	result, err = New(intentStorage{document: documentFor(t, missingOutcome)}).Load(intentManagedRequest())
	if result.Status != RecoveryRequired || !errors.As(err, &finding) || finding.Code != "STATE-INTENT-INCOMPLETE" {
		t.Fatalf("removed token without dependency outcome Load() = (%+v, %v)", result, err)
	}
}

func TestManagementTokenTemplateSHA256AcceptsOnlyTheReviewedEmptySlot(t *testing.T) {
	candidate := completeDesiredState()
	candidate.Cloudflare.ManagementToken = InfrastructureSecret{}
	replacement, err := ManagementTokenTemplateSHA256(candidate)
	if err != nil || len(replacement) != 64 {
		t.Fatalf("replacement template = (%q, %v)", replacement, err)
	}
	candidate.Cloudflare.ManagementTokenRemoved = true
	candidate.Cloudflare.ManagementTokenState = CloudflareManagementUnmanaged
	removal, err := ManagementTokenTemplateSHA256(candidate)
	if err != nil || len(removal) != 64 || removal == replacement {
		t.Fatalf("removal template = (%q, %v)", removal, err)
	}
	candidate.Cloudflare.ManagementToken = NewInfrastructureSecret("cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := ManagementTokenTemplateSHA256(candidate); err == nil {
		t.Fatal("caller-supplied management token was accepted as an empty template")
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
		{name: "XHTTP path", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSXHTTP.Path = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "WebSocket path", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSWebSocket.Path = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Hysteria2 credential", change: func(s *DesiredState) { s.ConnectionProfiles.Hysteria2.Password = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "AnyTLS credential", change: func(s *DesiredState) { s.ConnectionProfiles.AnyTLS.Password = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "subscription", change: func(s *DesiredState) { s.Subscription.Token = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Cloudflare authority", change: func(s *DesiredState) { s.Cloudflare.ManagementToken = InfrastructureSecret{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Network Policy address", change: func(s *DesiredState) { s.NetworkPolicy.PublicIPv4 = "" }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "software versions", change: func(s *DesiredState) { s.Software.SingBoxVersion = "" }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "Cloudflare XHTTP binding", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSXHTTP.Hostname = "other.example.com" }, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "aliased Cloudflare profile credential", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSWebSocket.UUID = s.ConnectionProfiles.VLESSXHTTP.UUID }, code: "STATE-INTENT-CROSS-SECTION"},
		{name: "aliased Cloudflare profile path", change: func(s *DesiredState) { s.ConnectionProfiles.VLESSWebSocket.Path = s.ConnectionProfiles.VLESSXHTTP.Path }, code: "STATE-INTENT-CROSS-SECTION"},
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
		{name: "schema 2 lifecycle in schema 1", document: strings.Replace(document, `"schema_version":2`, `"schema_version":1`, 1)},
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

func TestLoadKeepsExistingSchemaTwoProfilesValidWithoutLifecycleFields(t *testing.T) {
	document := strings.Replace(schemaOneDocumentFor(t, completeDesiredState()), `"schema_version":1`, `"schema_version":2`, 1)
	result, err := New(intentStorage{document: document}).Load(intentManagedRequest())
	if err != nil || result.Status != Managed {
		t.Fatalf("Load() existing schema 2 = (%+v, %v), want Managed", result, err)
	}
}

func TestSoftwareLifecycleCapabilityProvesBothManagedProfileStates(t *testing.T) {
	for _, test := range []struct {
		name                 string
		desired              DesiredState
		cloudflareProfilesUp bool
	}{
		{name: "VLESS REALITY Vision only", desired: realityOnlyDesiredState()},
		{name: "all profiles set up", desired: completeDesiredState(), cloudflareProfilesUp: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := New(intentStorage{document: documentFor(t, test.desired)})
			result, err := module.Load(intentManagedRequest())
			if err != nil {
				t.Fatal(err)
			}
			capability := module.SoftwareLifecycleCapability(result)
			revision, stateSHA256, cloudflareProfilesUp, valid := capability.SoftwareLifecycleManagedCapability()
			if !valid || revision != 7 || stateSHA256 == "" || cloudflareProfilesUp != test.cloudflareProfilesUp {
				t.Fatalf("SoftwareLifecycleManagedCapability() = (%d, %q, %t, %t)", revision, stateSHA256, cloudflareProfilesUp, valid)
			}
		})
	}

	module := New(intentStorage{document: documentFor(t, completeDesiredState())})
	request := intentManagedRequest()
	request.Lineage.ActiveChangeSet = "change-0008"
	result, err := module.Load(request)
	if err != nil || result.Status != ChangeInProgress {
		t.Fatalf("Load() = (%+v, %v), want Change in progress", result, err)
	}
	result.Status = Managed
	if capability := module.SoftwareLifecycleCapability(result); capability != nil {
		t.Fatalf("SoftwareLifecycleCapability() trusted a caller-relabeled Change in progress result: %v", capability)
	}
}

func TestLoadAllowsPortReuseByDisabledProfiles(t *testing.T) {
	desired := completeDesiredState()
	desired.ConnectionProfiles.VLESSRealityVision.Enabled = false
	desired.ConnectionProfiles.VLESSRealityVision.Lifecycle = ProfileDisabled
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
				Lifecycle:   ProfileEnabled,
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
				Lifecycle:     ProfileEnabled,
				Enabled:       true,
				UUID:          NewClientAccessValue("22222222-2222-4222-8222-222222222222"),
				Path:          NewClientAccessValue("/2222222222222222222222222222222222222222222222222222222222222222"),
				Hostname:      "xhttp.example.com",
				OriginAddress: "127.0.0.1",
				OriginPort:    11080,
				Mode:          XHTTPPacketUp,
			},
			VLESSWebSocket: VLESSWebSocket{
				Lifecycle:     ProfileEnabled,
				Enabled:       true,
				UUID:          NewClientAccessValue("33333333-3333-4333-8333-333333333333"),
				Hostname:      "ws.example.com",
				OriginAddress: "127.0.0.1",
				OriginPort:    11081,
				Path:          NewClientAccessValue("/4444444444444444444444444444444444444444444444444444444444444444"),
			},
			Hysteria2: Hysteria2{
				Lifecycle:         ProfileEnabled,
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
				Lifecycle:         ProfileEnabled,
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
				Lifecycle:     ProfileEnabled,
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
			OwnerEmail:           "owner@example.com",
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

func realityOnlyDesiredState() DesiredState {
	desired := completeDesiredState()
	desired.Installation.Domain = ""
	desired.ConnectionProfiles.VLESSRealityVision.Lifecycle = ProfileEnabled
	desired.ConnectionProfiles.VLESSXHTTP = VLESSXHTTP{Lifecycle: ProfileNotSetUp}
	desired.ConnectionProfiles.VLESSWebSocket = VLESSWebSocket{Lifecycle: ProfileNotSetUp}
	desired.ConnectionProfiles.Hysteria2 = Hysteria2{Lifecycle: ProfileNotSetUp}
	desired.ConnectionProfiles.TUIC = TUIC{Lifecycle: ProfileNotSetUp}
	desired.ConnectionProfiles.AnyTLS = AnyTLS{Lifecycle: ProfileNotSetUp}
	desired.Cloudflare = CloudflareSettings{}
	desired.Certificates.DomainCertificateID = ""
	desired.Certificates.DomainServingPointer = ""
	desired.Certificates.DomainHostname = ""
	return desired
}

func TestDesiredStateAcceptsOnlySafeCurrentReclamationPolicy(t *testing.T) {
	desired := completeDesiredState()
	desired.Reclamation = ReclamationPolicy{Version: 1, Held: HeldPackagePolicy{Name: "vendor-proxy", Version: "4.5.6", DeletedExecutable: "/opt/vendor-proxy/proxy", SHA256: strings.Repeat("a", 64)}}
	if finding := validateDesiredState(desired); finding != nil {
		t.Fatalf("safe reclamation policy refused: %+v", finding)
	}
	for _, alter := range []func(*DesiredState){
		func(value *DesiredState) { value.Reclamation.Version = 2 },
		func(value *DesiredState) { value.Reclamation.Held.DeletedExecutable = "relative" },
		func(value *DesiredState) { value.Reclamation.Held.SHA256 = "SECRET-MARKER" },
		func(value *DesiredState) { value.Reclamation.Held.Name = "" },
	} {
		candidate := desired
		alter(&candidate)
		if finding := validateDesiredState(candidate); finding == nil || finding.Code != "STATE-RECLAMATION-POLICY" {
			t.Fatalf("unsafe reclamation policy accepted: %+v", candidate.Reclamation)
		}
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
	}{2, 7, testRelease, "change-0007", payload, hex.EncodeToString(checksum[:])})
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

func schemaOneDocumentFor(t *testing.T, desired DesiredState) string {
	desired.ConnectionProfiles.VLESSRealityVision.Lifecycle = ""
	desired.ConnectionProfiles.VLESSXHTTP.Lifecycle = ""
	desired.ConnectionProfiles.VLESSWebSocket.Lifecycle = ""
	desired.ConnectionProfiles.Hysteria2.Lifecycle = ""
	desired.ConnectionProfiles.TUIC.Lifecycle = ""
	desired.ConnectionProfiles.AnyTLS.Lifecycle = ""
	return strings.Replace(documentFor(t, desired), `"schema_version":2`, `"schema_version":1`, 1)
}
