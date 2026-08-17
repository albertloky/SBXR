package softwarelifecycle_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func managedCapability(t *testing.T, cloudflareProfilesSetUp bool) (*state.SoftwareLifecycleCapability, string) {
	t.Helper()
	document := []byte(repairStateDocument)
	if !cloudflareProfilesSetUp {
		var envelope map[string]any
		if err := json.Unmarshal(document, &envelope); err != nil {
			t.Fatal(err)
		}
		payload := envelope["payload"].(map[string]any)
		payload["installation"].(map[string]any)["domain"] = ""
		profiles := payload["connection_profiles"].(map[string]any)
		for name, value := range profiles {
			profile := value.(map[string]any)
			if name == "vless_reality_vision" {
				profile["lifecycle"] = "Enabled"
				continue
			}
			for field, current := range profile {
				switch current.(type) {
				case string:
					profile[field] = ""
				case bool:
					profile[field] = false
				case float64:
					profile[field] = float64(0)
				}
			}
			profile["lifecycle"] = "Not set up"
		}
		for field, current := range payload["cloudflare"].(map[string]any) {
			switch current.(type) {
			case string:
				payload["cloudflare"].(map[string]any)[field] = ""
			case bool:
				payload["cloudflare"].(map[string]any)[field] = false
			}
		}
		certificates := payload["certificates"].(map[string]any)
		for _, field := range []string{"domain_certificate_id", "domain_serving_pointer", "domain_hostname"} {
			certificates[field] = ""
		}
		envelope["schema_version"] = float64(2)
		encodedPayload, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encodedPayload)
		envelope["checksum"] = hex.EncodeToString(digest[:])
		document, err = json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	release := state.ReleaseIdentity{Repository: "https://github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	module := state.New(&repairStorage{document: document})
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 7, LastCompletedChangeSet: "change-0007", ReleaseIdentity: release}})
	if err != nil {
		t.Fatal(err)
	}
	capability := module.SoftwareLifecycleCapability(loaded)
	_, stateSHA256, _, valid := capability.SoftwareLifecycleManagedCapability()
	if !valid {
		t.Fatal("managed capability unavailable")
	}
	return capability, stateSHA256
}

const repairStateDocument = `{"schema_version":1,"revision":7,"release_identity":{"repository":"https://github.com/albertloky/SBXR","tag":"v1.0.0","commit":"0123456789abcdef0123456789abcdef01234567","release_index_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"last_completed_change_set":"change-0007","payload":{"certificates":{"acme_account_id":"acme-account","domain_certificate_id":"domain-certificate","domain_hostname":"direct.example.com","domain_serving_pointer":"/var/lib/sbxr/certificates/domain/current","ip_certificate_id":"ip-certificate","ip_serving_pointer":"/var/lib/sbxr/certificates/ip/current","renewal_policy":true},"cloudflare":{"account_id":"cloudflare-account","direct_hostname":"direct.example.com","direct_ipv4_record_id":"dns-direct-ipv4","direct_ipv6_record_id":"","management_token":"CLOUDFLARE-MANAGEMENT-SECRET-MARKER","dedicated_broad_policy_confirmed":true,"tunnel_id":"cloudflare-tunnel-id","tunnel_name":"sbxr","tunnel_run_token":"CLOUDFLARE-RUN-SECRET-MARKER-00001","websocket_dns_record_id":"dns-websocket","websocket_hostname":"ws.example.com","xhttp_dns_record_id":"dns-xhttp","xhttp_hostname":"xhttp.example.com","zone_id":"cloudflare-zone","zone_name":"example.com"},"connection_profiles":{"anytls":{"certificate_id":"domain-certificate","enabled":true,"padding_scheme":"stop=8","password":"ANYTLS-PASSWORD-SECRET-MARKER-01","port":9443,"server_name":"direct.example.com"},"hysteria2":{"certificate_id":"domain-certificate","enabled":true,"masquerade_url":"https://example.com/","obfuscation":false,"obfuscation_secret":"","password":"HYSTERIA2-SECRET-MARKER-00000001","port":443,"server_name":"direct.example.com"},"tuic":{"certificate_id":"domain-certificate","congestion_control":"bbr","enabled":true,"password":"TUIC-PASSWORD-SECRET-MARKER-00001","port":8443,"server_name":"direct.example.com","uuid":"55555555-5555-4555-8555-555555555555","zero_rtt":false},"vless_reality_vision":{"enabled":true,"fingerprint":"chrome","port":443,"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","server_name":"www.microsoft.com","short_id":"1111111111111111","target":"www.microsoft.com:443","uuid":"11111111-1111-4111-8111-111111111111"},"vless_websocket":{"enabled":true,"hostname":"ws.example.com","origin_address":"127.0.0.1","origin_port":11081,"path":"/4444444444444444444444444444444444444444444444444444444444444444","uuid":"33333333-3333-4333-8333-333333333333"},"vless_xhttp":{"enabled":true,"hostname":"xhttp.example.com","mode":"packet-up","origin_address":"127.0.0.1","origin_port":11080,"path":"/2222222222222222222222222222222222222222222222222222222222222222","uuid":"22222222-2222-4222-8222-222222222222"}},"installation":{"domain":"example.com","id":"550e8400-e29b-41d4-a716-446655440000"},"network_policy":{"primary_subscription_address":"192.0.2.10","public_ipv4":"192.0.2.10","public_ipv6":"","ssh_port":22},"software":{"automatic_update_discovery":true,"certbot_version":"5.4.0","cloudflared_version":"2026.7.0","sing_box_version":"1.12.0","xray_version":"25.8.3"},"subscription":{"certificate_id":"ip-certificate","listen_port":10443,"token":"6666666666666666666666666666666666666666666666666666666666666666"}},"checksum":"ab76945ea6e878e5be9f97f79a293000c8334ea709bbd3659d1db79cecc4261a"}`

type repairStorage struct{ document []byte }

func (storage *repairStorage) Read() ([]byte, error) {
	return append([]byte(nil), storage.document...), nil
}
func (*repairStorage) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("publication is not reached by this handoff test")
}

type repairValidators struct{}

func (repairValidators) ValidateConnectionProfiles(state.ConnectionProfiles, state.ConnectionProfileSecretReader) error {
	return nil
}
func (repairValidators) PrepareConnectionProfiles(state.ConnectionProfiles, state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return []byte(`{}`), []byte(`{}`), nil
}
func (repairValidators) ValidateSubscription(state.SubscriptionSettings, state.ClientAccessReader) error {
	return nil
}
func (repairValidators) ValidateCloudflare(state.CloudflareSettings, state.InfrastructureSecretReader) error {
	return nil
}
func (repairValidators) ValidateCertificates(state.CertificateSettings) error          { return nil }
func (repairValidators) ValidateNetworkPolicy(state.NetworkPolicyInputs) error         { return nil }
func (repairValidators) ValidateSoftwareLifecycle(state.SoftwareLifecycleIntent) error { return nil }
func (repairValidators) ValidateMihomo(context.Context, io.Reader) error               { return nil }
func (repairValidators) ValidateSingBox(context.Context, io.Reader) error              { return nil }

type repairSecrets map[state.ClientAccessValue]string

func (reader repairSecrets) ReadClientAccessValue(value state.ClientAccessValue) string {
	return reader[value]
}

type repairObservationAdapter struct{ observation systemchanges.Observation }

func (adapter repairObservationAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (repairObservationAdapter) TryLock() (systemchanges.Lock, bool, error) { return nil, false, nil }

type repairApproval struct {
	recheck softwarelifecycle.RepairRecheck
}

func (approval repairApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.RepairRecheck, error) {
	return approval.recheck, nil
}

type forgedSoftwareRepairAuthority struct {
	revision uint64
	sha      string
}

func (authority forgedSoftwareRepairAuthority) StateSoftwareRepair() (uint64, string, bool) {
	return authority.revision, authority.sha, true
}

func TestSoftwareRepairPreparesOnlyTheExactUnchangedCurrentDesiredState(t *testing.T) {
	release := state.ReleaseIdentity{Repository: "https://github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	storage := &repairStorage{document: []byte(repairStateDocument)}
	stateModule := state.New(storage)
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 7, LastCompletedChangeSet: "change-0007", ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		t.Fatalf("Load() = (%+v, %v)", loaded, err)
	}
	capability := stateModule.SoftwareLifecycleCapability(loaded)
	stateSHA, volatileSHA := "ab76945ea6e878e5be9f97f79a293000c8334ea709bbd3659d1db79cecc4261a", strings.Repeat("c", 64)
	observation := systemchanges.Observation{Status: systemchanges.RecoveryRequired, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, ForwardRepairAvailable: true, RecoveryCause: systemchanges.CurrentStateDrift, StateRevision: 7, StateSHA256: stateSHA, VolatileSHA256: volatileSHA}
	changes := systemchanges.New(repairObservationAdapter{observation})
	view := (softwarelifecycle.Interface{}).ViewRepair(changes)
	omissions := []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSRealityVisionProfileID, Name: "VLESS REALITY Vision", Lifecycle: state.ProfileDisabled}, {ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Lifecycle: state.ProfileDisabled}, {ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Lifecycle: state.ProfileDisabled}, {ID: connectionprofiles.Hysteria2ProfileID, Name: "Hysteria2", Lifecycle: state.ProfileDisabled}, {ID: connectionprofiles.TUICProfileID, Name: "TUIC", Lifecycle: state.ProfileDisabled}, {ID: connectionprofiles.AnyTLSProfileID, Name: "AnyTLS", Lifecycle: state.ProfileDisabled}}
	source, err := connectionprofiles.NewPublicationSource(nil, omissions)
	if err != nil {
		t.Fatal(err)
	}
	token := state.NewClientAccessValue("REPAIR-SUBSCRIPTION-TOKEN")
	secrets := repairSecrets{token: "REPAIR-SUBSCRIPTION-TOKEN"}
	validators := repairValidators{}
	publication := subscriptionpublication.New(validators, validators).Plan(t.Context(), subscriptionpublication.PlanRequest{Source: source, Secrets: secrets, Subscription: state.SubscriptionSettings{Token: token, ListenPort: 10443, CertificateID: "ip-certificate"}, ChangeSet: "software-repair-revision-8", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: stateSHA}, DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: volatileSHA, RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("e", 64), Subscription: strings.Repeat("f", 64)}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10", ReleaseIdentity: release, Repair: true})
	if publication.Plan == nil || publication.Finding != nil {
		t.Fatalf("publication Plan = %+v", publication)
	}
	plan, finding := softwarelifecycle.PlanRepair(softwarelifecycle.RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: publication.Plan, ChangeSet: "software-repair-revision-8", Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if finding != nil {
		t.Fatal(finding)
	}
	managed, err := state.NewManagedInputChecksums(strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64))
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(plan.Identity()), plan.SHA256(), managed)
	if err != nil {
		t.Fatal(err)
	}
	request := state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: release, ChangeSet: "software-repair-revision-8", Candidate: loaded.Snapshot.DesiredState, SemanticValidators: state.SemanticValidators{ConnectionProfiles: validators, Subscription: validators, Cloudflare: validators, Certificates: validators, NetworkPolicy: validators, SoftwareLifecycle: validators}, ServiceMaterials: repairServiceMaterials(loaded.Snapshot.DesiredState), ReviewedInputs: reviewed}
	changed := request
	changed.Candidate.NetworkPolicy.PublicIPv4 = "203.0.113.99"
	if prepared, err := stateModule.PrepareSoftwareRepairCommit(changed, plan); err == nil || prepared != nil {
		t.Fatalf("changed intent = (%+v, %v)", prepared, err)
	}
	wrongRelease := request
	wrongRelease.CandidateReleaseIdentity.Tag = "v1.0.1"
	if prepared, err := stateModule.PrepareSoftwareRepairCommit(wrongRelease, plan); err == nil || prepared != nil {
		t.Fatalf("changed release = (%+v, %v)", prepared, err)
	}
	if prepared, err := stateModule.PrepareSoftwareRepairCommit(request, forgedSoftwareRepairAuthority{7, stateSHA}); err == nil || prepared != nil {
		t.Fatalf("forged authority = (%+v, %v)", prepared, err)
	}
	prepared, err := stateModule.PrepareSoftwareRepairCommit(request, plan)
	if err != nil || prepared.Revision() != 8 {
		t.Fatalf("PrepareSoftwareRepairCommit() = (%+v, %v)", prepared, err)
	}
	rechecked := (softwarelifecycle.Interface{}).ViewRepair(changes).RepairCandidate()
	result := plan.Apply(t.Context(), softwarelifecycle.RepairApplyRequest{Approval: repairApproval{softwarelifecycle.RepairRecheck{Candidate: rechecked, Contribution: publication.Plan, Capability: capability}}, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" {
		t.Fatalf("Apply handoff = %+v", result)
	}
}

func repairServiceMaterials(candidate state.DesiredState) state.ServiceMaterials {
	p := candidate.ConnectionProfiles
	xray := &state.XrayServiceMaterial{VLESSRealityVision: &state.XrayRealityMaterial{Port: p.VLESSRealityVision.Port, UUID: p.VLESSRealityVision.UUID, PrivateKey: p.VLESSRealityVision.PrivateKey, ShortID: p.VLESSRealityVision.ShortID, Target: p.VLESSRealityVision.Target, ServerName: p.VLESSRealityVision.ServerName, Fingerprint: p.VLESSRealityVision.Fingerprint}, VLESSXHTTP: &state.XrayXHTTPMaterial{UUID: p.VLESSXHTTP.UUID, Path: p.VLESSXHTTP.Path, OriginAddress: p.VLESSXHTTP.OriginAddress, OriginPort: p.VLESSXHTTP.OriginPort, Mode: p.VLESSXHTTP.Mode}, VLESSWebSocket: &state.XrayWebSocketMaterial{UUID: p.VLESSWebSocket.UUID, OriginAddress: p.VLESSWebSocket.OriginAddress, OriginPort: p.VLESSWebSocket.OriginPort, Path: p.VLESSWebSocket.Path}}
	singBox := &state.SingBoxServiceMaterial{Hysteria2: &state.SingBoxHysteria2Material{Port: p.Hysteria2.Port, Password: p.Hysteria2.Password, ServerName: p.Hysteria2.ServerName, CertificatePointer: candidate.Certificates.DomainServingPointer, MasqueradeURL: p.Hysteria2.MasqueradeURL, Obfuscation: p.Hysteria2.Obfuscation, ObfuscationSecret: p.Hysteria2.ObfuscationSecret}, TUIC: &state.SingBoxTUICMaterial{Port: p.TUIC.Port, UUID: p.TUIC.UUID, Password: p.TUIC.Password, ServerName: p.TUIC.ServerName, CertificatePointer: candidate.Certificates.DomainServingPointer, CongestionControl: p.TUIC.CongestionControl, ZeroRTT: p.TUIC.ZeroRTT}, AnyTLS: &state.SingBoxAnyTLSMaterial{Port: p.AnyTLS.Port, Password: p.AnyTLS.Password, ServerName: p.AnyTLS.ServerName, CertificatePointer: candidate.Certificates.DomainServingPointer, PaddingScheme: p.AnyTLS.PaddingScheme}}
	cloudflared := &state.CloudflaredServiceMaterial{TunnelID: candidate.Cloudflare.TunnelID, TunnelRunToken: candidate.Cloudflare.TunnelRunToken, Routes: []state.CloudflareRoute{{Hostname: p.VLESSXHTTP.Hostname, Origin: "http://127.0.0.1:11080"}, {Hostname: p.VLESSWebSocket.Hostname, Origin: "http://127.0.0.1:11081"}}}
	return state.ServiceMaterials{Xray: xray, SingBox: singBox, Cloudflared: cloudflared, Subscription: state.SubscriptionServiceMaterial{Token: candidate.Subscription.Token, ListenPort: candidate.Subscription.ListenPort, CertificatePointer: candidate.Certificates.IPServingPointer, PrimaryAddress: candidate.NetworkPolicy.PrimarySubscriptionAddress}}
}
