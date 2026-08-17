package subscriptionpublication_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRevisionOnePublishesOnlyRealityAndNamesFiveNotSetUpProfiles(t *testing.T) {
	source, complete, reader := stagedSources(t, "198.51.100.10")
	omissions := source.Omissions()
	wantNames := []string{"VLESS XHTTP", "VLESS WebSocket", "Hysteria2", "TUIC", "AnyTLS"}

	artifacts, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.ProfileCount != 1 || strings.Count(string(artifacts.Raw), "\n") != 0 || !strings.Contains(string(artifacts.Raw), "VLESS%20REALITY%20Vision") {
		t.Fatalf("revision 1 Render() = count %d raw %q", artifacts.ProfileCount, artifacts.Raw)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(artifacts.Base64))
	if err != nil || !bytes.Equal(decoded, artifacts.Raw) {
		t.Fatalf("revision 1 universal output = %q, %v", decoded, err)
	}
	var singBox struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(artifacts.SingBox.Body, &singBox) != nil || len(singBox.Outbounds) != 2 || singBox.Outbounds[0].Tag != "VLESS REALITY Vision" || singBox.Outbounds[1].Tag != "SBXR" {
		t.Fatalf("revision 1 /sing-box = %s", artifacts.SingBox.Body)
	}
	for _, identity := range []subscriptionpublication.RepresentationIdentity{subscriptionpublication.Base64Representation, subscriptionpublication.RawRepresentation, subscriptionpublication.V2RayNRepresentation, subscriptionpublication.ShadowrocketRepresentation, subscriptionpublication.KaringRepresentation, subscriptionpublication.MihomoRepresentation, subscriptionpublication.SingBoxRepresentation} {
		body, _ := artifacts.RepresentationBody(identity)
		for _, marker := range []string{"22222222-2222-4222-8222-222222222222", "VLESS%20XHTTP", "VLESS%20WebSocket", "Hysteria2", "TUIC", "AnyTLS"} {
			if bytes.Contains(body, []byte(marker)) {
				t.Fatalf("revision 1 %s exposed omitted profile marker %q", identity, marker)
			}
		}
	}
	later, err := newAcceptingTestModule().Render(t.Context(), complete, reader)
	if err != nil || later.ProfileCount != 6 || strings.Count(string(later.Raw), "\n") != 5 || later.SingBox.ProfileCount != 5 || len(later.SingBox.Omissions) != 1 || later.SingBox.Omissions[0].Status != subscriptionpublication.NotOffered {
		t.Fatalf("later six-profile Render() = count %d sing-box %#v error %v", later.ProfileCount, later.SingBox, err)
	}

	view := newAcceptingTestModule().View(subscriptionpublication.ViewRequest{
		Source: source, SubscriptionAddress: "https://198.51.100.10:10443",
		DesiredStateRevision: 1, DesiredStateSHA256: strings.Repeat("a", 64),
	})
	for _, representation := range view.Representations {
		if representation.ProfileCount != 1 || len(representation.Omissions) != 5 || !slices.EqualFunc(representation.Omissions, wantNames, func(got subscriptionpublication.RepresentationOmission, want string) bool {
			return got.Name == want && got.Status == subscriptionpublication.NotSetUp
		}) {
			t.Fatalf("revision 1 %s summary = %#v", representation.Name, representation)
		}
	}

	token := access(reader, strings.Repeat("6", 64))
	result := newAcceptingTestModule().Plan(t.Context(), subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: state.SubscriptionSettings{Token: token, ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "installation-revision-1", StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled},
		DesiredStateRevision: 1, DesiredStateSHA256: strings.Repeat("b", 64), ManagedInputsSHA256: strings.Repeat("c", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("d", 64), Subscription: strings.Repeat("e", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10",
		ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("f", 64)},
	})
	if result.Plan == nil || result.Finding != nil || result.Plan.Summary().ProfileCount != 1 || !slices.Equal(result.Plan.Summary().Omissions, omissions) || result.Plan.SoftwareLifecycleInstallContribution().Name != "Subscription Publication" {
		t.Fatalf("revision 1 Plan() = %+v", result)
	}
	bundle, err := result.Plan.PrepareSubscriptionPublication()
	if err != nil {
		t.Fatal(err)
	}
	set, err := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil || len(set.Files()) != 8 {
		t.Fatalf("revision 1 prepared artifact set = %d files, %v", len(set.Files()), err)
	}
	files := set.Files()
	var metadata map[string]any
	if json.Unmarshal(files[7].Body, &metadata) != nil {
		t.Fatal("decode prepared metadata")
	}
	metadata["omissions"].([]any)[0].(map[string]any)["id"] = "vless-reality-vision"
	metadata["omissions"].([]any)[0].(map[string]any)["name"] = "VLESS REALITY Vision"
	files[7].Body, _ = json.Marshal(metadata)
	if _, err := subscriptionpublication.DecodePreparedArtifactFiles(files); err == nil {
		t.Fatal("mismatched emitted and omitted Connection Profile identities were accepted")
	}
	malformed := set.Files()
	malformed[1].Body = []byte("vless://reality\x00")
	if _, err := subscriptionpublication.DecodePreparedArtifactFiles(malformed); err == nil {
		t.Fatal("malformed raw Connection Profile was accepted")
	}
}

type stagedStateStorage struct{ document []byte }

func (storage *stagedStateStorage) Read() ([]byte, error) {
	if len(storage.document) == 0 {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), storage.document...), nil
}
func (storage *stagedStateStorage) Publish(_, candidate []byte, _ string) ([]byte, error) {
	storage.document = append([]byte(nil), candidate...)
	return append([]byte(nil), candidate...), nil
}

type stagedStateValidators struct{ identity, sha256 string }

func (validator stagedStateValidators) Identity() string { return validator.identity }
func (validator stagedStateValidators) SHA256() string   { return validator.sha256 }
func (stagedStateValidators) ValidateConnectionProfiles(state.ConnectionProfiles, state.ConnectionProfileSecretReader) error {
	return nil
}
func (stagedStateValidators) PrepareConnectionProfiles(profiles state.ConnectionProfiles, _ state.ConnectionProfileSecretReader) ([]byte, []byte, error) {
	return []byte("{}"), nil, nil
}
func (stagedStateValidators) ValidateCloudflare(state.CloudflareSettings, state.InfrastructureSecretReader) error {
	return nil
}
func (stagedStateValidators) ValidateCertificates(state.CertificateSettings) error  { return nil }
func (stagedStateValidators) ValidateNetworkPolicy(state.NetworkPolicyInputs) error { return nil }
func (stagedStateValidators) ValidateSoftwareLifecycle(state.SoftwareLifecycleIntent) error {
	return nil
}

type stagedTransactionAdapter struct {
	events []string
	closed atomic.Bool
}

type stagedLock struct{ closed *atomic.Bool }

func (lock stagedLock) Close() error { lock.closed.Store(true); return nil }
func (*stagedTransactionAdapter) Observe() (systemchanges.Observation, error) {
	return systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: strings.Repeat("c", 64), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}, nil
}
func (adapter *stagedTransactionAdapter) TryLock() (systemchanges.Lock, bool, error) {
	return stagedLock{closed: &adapter.closed}, true, nil
}
func (adapter *stagedTransactionAdapter) Prepare(_ systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	adapter.events = append(adapter.events, string(systemchanges.Prepared))
	return preparation.WriteStateArtifacts(func(_ string, _ uint32, source io.Reader) error {
		_, err := io.Copy(io.Discard, source)
		return err
	})
}
func (adapter *stagedTransactionAdapter) Record(_ systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	adapter.events = append(adapter.events, record.String())
	return nil
}
func (adapter *stagedTransactionAdapter) Execute(_ systemchanges.ExecutionLease, _ string, _ int, _ systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	adapter.events = append(adapter.events, "atomic activation")
	return systemchanges.StepEvidence{Code: "subscription-artifacts-activated", SHA256: strings.Repeat("a", 64)}, nil
}
func (*stagedTransactionAdapter) Reverse(systemchanges.ExecutionLease, string, int, systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error) {
	return systemchanges.StepEvidence{Code: "subscription-artifacts-restored", SHA256: strings.Repeat("b", 64)}, nil
}
func (*stagedTransactionAdapter) Check(systemchanges.ExecutionLease, systemchanges.Check, systemchanges.GatePhase, time.Duration) (systemchanges.HealthStatus, error) {
	return systemchanges.Healthy, nil
}
func (*stagedTransactionAdapter) VerifyAgreement(systemchanges.ExecutionLease, systemchanges.Agreement, time.Duration) error {
	return nil
}
func (*stagedTransactionAdapter) VerifyRollback(systemchanges.ExecutionLease, systemchanges.RollbackAgreement, time.Duration) error {
	return nil
}
func (*stagedTransactionAdapter) Cleanup(systemchanges.ExecutionLease, string) error { return nil }

func TestRevisionOnePlanApplyCompletesAfterAtomicActivationAndStatePublication(t *testing.T) {
	source, _, reader := stagedSources(t, "198.51.100.10")
	reality := source.Profiles()[0]
	token := access(reader, strings.Repeat("6", 64))
	candidate := state.DesiredState{
		Installation: state.InstallationIdentity{ID: "550e8400-e29b-41d4-a716-446655440000"},
		ConnectionProfiles: state.ConnectionProfiles{
			VLESSRealityVision: state.VLESSRealityVision{Lifecycle: state.ProfileEnabled, Enabled: true, Port: reality.Port, UUID: reality.UUID, PrivateKey: state.NewInfrastructureSecret(strings.Repeat("A", 43)), PublicKey: reality.PublicKey, ShortID: reality.ShortID, Target: "direct.example.com:443", ServerName: reality.ServerName, Fingerprint: reality.Fingerprint},
			VLESSXHTTP:         state.VLESSXHTTP{Lifecycle: state.ProfileNotSetUp},
			VLESSWebSocket:     state.VLESSWebSocket{Lifecycle: state.ProfileNotSetUp},
			Hysteria2:          state.Hysteria2{Lifecycle: state.ProfileNotSetUp},
			TUIC:               state.TUIC{Lifecycle: state.ProfileNotSetUp},
			AnyTLS:             state.AnyTLS{Lifecycle: state.ProfileNotSetUp},
		},
		Subscription:  state.SubscriptionSettings{Token: token, ListenPort: 10443, CertificateID: "ip-certificate"},
		Certificates:  state.CertificateSettings{RenewalPolicy: true, OwnerEmail: "owner@example.com", ACMEAccountID: "acme-account", IPCertificateID: "ip-certificate", IPServingPointer: "/var/lib/sbxr/certificates/ip/current"},
		NetworkPolicy: state.NetworkPolicyInputs{SSHPort: 22, PublicIPv4: "198.51.100.10", PrimarySubscriptionAddress: "198.51.100.10"},
		Software:      state.SoftwareSettings{XrayVersion: "25.8.3", SingBoxVersion: "1.13.16", CloudflaredVersion: "2026.8.0", CertbotVersion: "5.4.0", AutomaticUpdateDiscovery: true},
	}
	desiredSHA256, err := state.CandidateSHA256(candidate)
	if err != nil {
		t.Fatal(err)
	}
	release := state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("f", 64)}
	result := newAcceptingTestModule().Plan(t.Context(), subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: candidate.Subscription,
		ChangeSet: "installation-revision-1", StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled},
		DesiredStateRevision: 1, DesiredStateSHA256: desiredSHA256, ManagedInputsSHA256: strings.Repeat("c", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("d", 64), Subscription: strings.Repeat("e", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10", ReleaseIdentity: release,
	})
	if result.Plan == nil || result.Finding != nil {
		t.Fatalf("revision 1 Plan() = %+v", result)
	}
	checksums, err := state.NewManagedInputChecksums(strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64))
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(result.Plan.Identity()), result.Plan.SHA256(), checksums)
	if err != nil {
		t.Fatal(err)
	}
	storage := &stagedStateStorage{}
	stateModule := state.New(storage)
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.CleanVPS})
	if err != nil {
		t.Fatal(err)
	}
	validators := stagedStateValidators{identity: result.Plan.Identity(), sha256: result.Plan.SHA256()}
	prepared, err := stateModule.PrepareCommit(state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: release, ChangeSet: "installation-revision-1", Candidate: candidate, SemanticValidators: state.SemanticValidators{ConnectionProfiles: validators, Subscription: result.Plan, Cloudflare: validators, Certificates: validators, NetworkPolicy: validators, SoftwareLifecycle: validators}, ServiceMaterials: state.ServiceMaterialsFor(candidate), SubscriptionPublication: result.Plan, ReviewedInputs: reviewed})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &stagedTransactionAdapter{}
	disk := systemchanges.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100}
	applied := result.Plan.Apply(systemchanges.New(adapter), prepared, systemchanges.StateLineage{Status: systemchanges.NotInstalled}, result.Plan.VolatileSHA256(), disk)
	events := strings.Join(adapter.events, "\n")
	activation := strings.Index(events, "atomic activation")
	statePublication := strings.Index(events, string(systemchanges.StatePublicationStarted))
	complete := strings.Index(events, string(systemchanges.Complete))
	if applied.Outcome != systemchanges.Completed || !applied.PlanConsumed || !adapter.closed.Load() || activation < 0 || statePublication <= activation || complete <= statePublication {
		t.Fatalf("revision 1 Apply() = %+v events=%v", applied, adapter.events)
	}
}

func stagedSources(t *testing.T, address string) (connectionprofiles.PublicationSource, connectionprofiles.PublicationSource, clientAccessReader) {
	t.Helper()
	complete, reader := sixProfileSource(t, address)
	profiles := complete.Profiles()
	names := []string{"VLESS XHTTP", "VLESS WebSocket", "Hysteria2", "TUIC", "AnyTLS"}
	omissions := make([]connectionprofiles.PublicationOmission, 0, 5)
	for index, profile := range profiles[1:] {
		omissions = append(omissions, connectionprofiles.PublicationOmission{ID: profile.ID, Name: names[index], Lifecycle: state.ProfileNotSetUp})
	}
	revisionOne, err := connectionprofiles.NewPublicationSource(profiles[:1], omissions)
	if err != nil {
		t.Fatal(err)
	}
	return revisionOne, complete, reader
}
