package subscriptionpublication_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type repairStatusAdapter struct{ observation systemchanges.Observation }

type capabilityStorage struct{ document []byte }

func (storage capabilityStorage) Read() ([]byte, error) { return storage.document, nil }
func (capabilityStorage) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("not used")
}

func softwareLifecycleCapability(t *testing.T) (*state.SoftwareLifecycleCapability, string) {
	t.Helper()
	document, err := os.ReadFile("../state/testdata/complete-state.json")
	if err != nil {
		t.Fatal(err)
	}
	release := state.ReleaseIdentity{Repository: "https://github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	module := state.New(capabilityStorage{document})
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

func (adapter repairStatusAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (repairStatusAdapter) TryLock() (systemchanges.Lock, bool, error) { return nil, false, nil }

func TestPlanBindsOneCompleteValidatedArtifactSetWithoutRenderingSecrets(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	token := access(reader, "SUBSCRIPTION-TOKEN-MARKER")
	release := state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)}
	result := newAcceptingTestModule().Plan(t.Context(), subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: state.SubscriptionSettings{Token: token, ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "change-0008", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)},
		DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10", ReleaseIdentity: release,
	})
	if result.Plan == nil || result.Finding != nil {
		t.Fatalf("Plan() = %+v", result)
	}
	if result.Plan.Identity() == "" || len(result.Plan.SHA256()) != 64 || len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) != 3 {
		t.Fatalf("Plan bindings are incomplete: %s %s steps=%d checks=%d", result.Plan.Identity(), result.Plan.SHA256(), len(result.Plan.Steps()), len(result.Plan.Checks()))
	}
	if contribution := result.Plan.SoftwareLifecycleUpdateContribution(); contribution.Name != "Subscription Publication" || contribution.ChangeSet != "change-0008" || contribution.Owner != systemchanges.SubscriptionModule {
		t.Fatalf("update contribution = %+v", contribution)
	}
	summary := result.Plan.Summary()
	if summary.ProfileCount != 6 || len(summary.Representations) != 7 || summary.ChangeSet != "change-0008" || summary.DesiredStateRevision != 8 || summary.ReleaseIdentity != release || summary.SelectedAddress != "198.51.100.10" || summary.CompatibilityDefinition != string(subscriptionpublication.CurrentCompatibilityDefinition) || !validSummaryChecksums(summary.RelevantChecksums) || !summary.ValidationComplete || summary.Replacement != "complete artifact set N to N+1" || summary.Rollback != "restore the exact prior complete artifact set" {
		t.Fatalf("Plan summary = %+v", summary)
	}
	for _, rendered := range []string{fmt.Sprint(result.Plan), fmt.Sprintf("%+v", result.Plan), fmt.Sprintf("%#v", result.Plan)} {
		if strings.Contains(rendered, "SUBSCRIPTION-TOKEN-MARKER") || strings.Contains(rendered, "11111111-1111-4111-8111-111111111111") {
			t.Fatalf("Plan formatting exposed a Client Access Value: %s", rendered)
		}
	}
	if encoded, err := json.Marshal(result.Plan); err == nil || bytes.Contains(encoded, []byte("SUBSCRIPTION-TOKEN-MARKER")) {
		t.Fatalf("json.Marshal(Plan) = %s, %v", encoded, err)
	}
	bundle, err := result.Plan.PrepareSubscriptionPublication()
	set, decodeErr := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil || decodeErr != nil || len(set.Files()) != 8 {
		t.Fatalf("PrepareSubscriptionPublication() = %d bytes, %v, decode %v", len(bundle), err, decodeErr)
	}
	if _, err := result.Plan.PrepareSubscriptionPublication(); err == nil {
		t.Fatal("prepared artifact authority was reusable")
	}
	prepared := &preparedPlanBinding{changeSet: "change-0008", revision: 8, starting: strings.Repeat("c", 64), candidate: strings.Repeat("d", 64), identity: result.Plan.Identity(), sha256: result.Plan.SHA256()}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	firstApply := result.Plan.Apply(systemchanges.New(nil), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)}, strings.Repeat("e", 64), disk)
	secondApply := result.Plan.Apply(systemchanges.New(nil), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)}, strings.Repeat("e", 64), disk)
	if firstApply.Outcome != systemchanges.Refused || secondApply.Outcome != systemchanges.Refused || prepared.bindings != 1 {
		t.Fatalf("one-use Plan.Apply = first %+v, second %+v, prepared bindings %d", firstApply, secondApply, prepared.bindings)
	}
}

func TestPlanContributesOnlyAnExplicitCurrentStateRepair(t *testing.T) {
	capability, stateSHA256 := softwareLifecycleCapability(t)
	source, reader := sixProfileSource(t, "198.51.100.10")
	request := subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: state.SubscriptionSettings{Token: access(reader, "SUBSCRIPTION-REPAIR-MARKER"), ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "subscriptions-current-state-repair", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: stateSHA256},
		DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64), Repair: true,
		RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)}, CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition,
		SelectedAddress: "198.51.100.10", ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)},
	}
	result := newAcceptingTestModule().Plan(t.Context(), request)
	if result.Plan == nil || result.Finding != nil {
		t.Fatalf("repair Plan = %+v", result)
	}
	contribution := result.Plan.SoftwareLifecycleRepairContribution()
	if contribution.Name != "Subscription Publication" || contribution.Owner != systemchanges.SubscriptionModule || contribution.CurrentRevision != 7 || contribution.CurrentStateSHA256 != request.StartingState.SHA256 || len(contribution.Steps) != 1 || len(contribution.Checks) != 3 {
		t.Fatalf("Software Lifecycle repair contribution = %+v", contribution)
	}
	if update := result.Plan.SoftwareLifecycleUpdateContribution(); update.Name != "" {
		t.Fatalf("repair Plan also exposed update authority = %+v", update)
	}
	observation := systemchanges.Observation{Status: systemchanges.RecoveryRequired, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, ForwardRepairAvailable: true, RecoveryCause: systemchanges.CurrentStateDrift, StateRevision: 7, StateSHA256: request.StartingState.SHA256, VolatileSHA256: request.ManagedInputsSHA256}
	view := (softwarelifecycle.FullProductModule{}).ViewRepair(systemchanges.New(repairStatusAdapter{observation}))
	repair, finding := softwarelifecycle.PlanRepair(softwarelifecycle.RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: result.Plan, ChangeSet: request.ChangeSet, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if finding != nil || repair == nil {
		t.Fatalf("Software Lifecycle PlanRepair() = (%+v, %+v)", repair, finding)
	}
	bundle, err := repair.PrepareSubscriptionPublication()
	set, decodeErr := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil || decodeErr != nil || len(set.Files()) != 8 {
		t.Fatalf("repair prepared artifact set = %d bytes, %v, decode %v", len(bundle), err, decodeErr)
	}
	request.Repair = false
	ordinary := newAcceptingTestModule().Plan(t.Context(), request)
	if ordinary.Plan == nil || ordinary.Plan.SoftwareLifecycleRepairContribution().Name != "" {
		t.Fatalf("ordinary publication became repair = %+v", ordinary)
	}
}

type preparedPlanBinding struct {
	changeSet, starting, candidate, identity, sha256 string
	revision                                         uint64
	bindings                                         int
}

func (prepared *preparedPlanBinding) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	prepared.bindings++
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.identity, prepared.sha256, true
}

func (*preparedPlanBinding) SystemChangesConsume(any, string, string) (any, error) {
	return nil, errors.New("unavailable test Adapter")
}

func validSummaryChecksums(checksums subscriptionpublication.RelevantChecksums) bool {
	return len(checksums.ConnectionProfiles) == 64 && len(checksums.Subscription) == 64
}

func TestPlanRefusesStaleIncompleteAndSecretBearingInputs(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	base := subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader, Subscription: state.SubscriptionSettings{Token: access(reader, "SUBSCRIPTION-TOKEN-MARKER"), ListenPort: 10443, CertificateID: "ip-certificate"},
		ChangeSet: "change-0008", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)},
		DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10",
		ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)},
	}
	for _, mutate := range []func(*subscriptionpublication.PlanRequest){
		func(request *subscriptionpublication.PlanRequest) { request.DesiredStateRevision = 7 },
		func(request *subscriptionpublication.PlanRequest) {
			request.CompatibilityDefinition = "stale-definition"
		},
		func(request *subscriptionpublication.PlanRequest) {
			request.ManagedInputsSHA256 = "SUBSCRIPTION-TOKEN-MARKER"
		},
		func(request *subscriptionpublication.PlanRequest) {
			request.DesiredStateSHA256 = strings.Repeat("D", 64)
		},
		func(request *subscriptionpublication.PlanRequest) {
			request.ReleaseIdentity.Commit = strings.Repeat("A", 40)
		},
		func(request *subscriptionpublication.PlanRequest) { request.Secrets = nil },
	} {
		request := base
		mutate(&request)
		result := newAcceptingTestModule().Plan(t.Context(), request)
		if result.Plan != nil || result.Finding == nil || strings.Contains(fmt.Sprintf("%+v", result.Finding), "SUBSCRIPTION-TOKEN-MARKER") {
			t.Fatalf("invalid Plan request was accepted or leaked: %+v", result)
		}
	}
}

func TestPlanBindsTheTruthfulClientAccessEffectIntoTheCompleteArtifactSet(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	sourceProfiles := source.Profiles()
	for index := range sourceProfiles {
		if sourceProfiles[index].ID == connectionprofiles.Hysteria2ProfileID {
			sourceProfiles[index].Obfuscation = true
			sourceProfiles[index].ObfuscationSecret = access(reader, strings.Repeat("7", 64))
		}
	}
	var err error
	source, err = connectionprofiles.NewPublicationSource(sourceProfiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	profiles := stateProfilesForPublication(source)
	subscription := state.SubscriptionSettings{Token: access(reader, strings.Repeat("6", 64)), ListenPort: 10443, CertificateID: "ip-certificate"}
	base := subscriptionpublication.PlanRequest{
		Source: source, Secrets: reader,
		ChangeSet: "change-0008", StartingState: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: strings.Repeat("c", 64)},
		DesiredStateRevision: 8, DesiredStateSHA256: strings.Repeat("d", 64), ManagedInputsSHA256: strings.Repeat("e", 64),
		RelevantChecksums:       subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		CompatibilityDefinition: subscriptionpublication.CurrentCompatibilityDefinition, SelectedAddress: "198.51.100.10",
		ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)},
	}
	rotation, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RotateSubscriptionToken, "198.51.100.10", subscription, profiles, source)
	if err != nil {
		t.Fatal(err)
	}
	base.Source, base.Subscription, base.ClientAccessMutation = rotation.PublicationSource(), rotation.Subscription(), rotation
	rotated := newAcceptingTestModule().Plan(t.Context(), base)
	revocation, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RevokeAllClientAccess, "198.51.100.10", subscription, profiles, source)
	if err != nil {
		t.Fatal(err)
	}
	base.Source = revocation.PublicationSource()
	base.Subscription, base.ClientAccessMutation = revocation.Subscription(), revocation
	revoked := newAcceptingTestModule().Plan(t.Context(), base)
	if rotated.Plan == nil || revoked.Plan == nil {
		t.Fatalf("client access Plans = rotate %+v, revoke %+v", rotated, revoked)
	}
	if rotated.Plan.Summary().ClientAccessEffect != "future downloads at the prior URL are revoked; already downloaded Connection Profile credentials remain valid" || revoked.Plan.Summary().ClientAccessEffect != "future downloads and all six prior Connection Profile credentials are revoked together" {
		t.Fatalf("client access effects = rotate %q, revoke %q", rotated.Plan.Summary().ClientAccessEffect, revoked.Plan.Summary().ClientAccessEffect)
	}
	if rotated.Plan.SHA256() == revoked.Plan.SHA256() {
		t.Fatal("different Client Access mutations produced the same artifact-set binding")
	}
	bundle, err := revoked.Plan.PrepareSubscriptionPublication()
	set, decodeErr := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil || decodeErr != nil {
		t.Fatalf("revoked artifact set = %v, %v", err, decodeErr)
	}
	bodies := map[string][]byte{}
	for _, file := range set.Files() {
		bodies[file.Name] = file.Body
	}
	if !bytes.Contains(bodies["raw"], []byte("obfs=salamander")) || !bytes.Contains(bodies["raw"], []byte("obfs-password=")) || !bytes.Contains(bodies["mihomo"], []byte("obfs: salamander")) || !bytes.Contains(bodies["mihomo"], []byte("obfs-password:")) || !bytes.Contains(bodies["sing-box"], []byte(`"obfs"`)) || bytes.Contains(bodies["raw"], []byte(strings.Repeat("7", 64))) {
		t.Fatal("revoked Hysteria2 obfuscation was absent or stale in a client representation")
	}
	disabledProfiles := profiles
	disabledProfiles.VLESSXHTTP.Enabled = false
	disabledSource := sourceForCandidateProfiles(t, source, disabledProfiles)
	disabled, err := subscriptionpublication.PrepareClientAccessMutation(subscriptionpublication.RevokeAllClientAccess, "198.51.100.10", subscription, disabledProfiles, disabledSource)
	if err != nil {
		t.Fatal(err)
	}
	base.Source = disabled.PublicationSource()
	base.Subscription, base.ClientAccessMutation = disabled.Subscription(), disabled
	disabledPlan := newAcceptingTestModule().Plan(t.Context(), base)
	if disabledPlan.Plan == nil || disabledPlan.Plan.Summary().ProfileCount != 5 || len(disabledPlan.Plan.Summary().Omissions) != 1 || disabledPlan.Plan.Summary().Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID {
		t.Fatalf("disabled-profile revocation Plan = %+v", disabledPlan)
	}
	staleProfiles := revocation.PublicationSource().Profiles()
	for index := range staleProfiles {
		if staleProfiles[index].ID == connectionprofiles.AnyTLSProfileID {
			staleProfiles[index].Port--
		}
	}
	staleSource, err := connectionprofiles.NewPublicationSource(staleProfiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.Source, base.Subscription, base.ClientAccessMutation = staleSource, revocation.Subscription(), revocation
	invalid := newAcceptingTestModule().Plan(t.Context(), base)
	if invalid.Plan != nil || invalid.Finding == nil {
		t.Fatalf("stale non-credential source = %+v", invalid)
	}
}

func stateProfilesForPublication(source connectionprofiles.PublicationSource) state.ConnectionProfiles {
	var candidate state.ConnectionProfiles
	for _, profile := range source.Profiles() {
		switch profile.ID {
		case connectionprofiles.VLESSRealityVisionProfileID:
			candidate.VLESSRealityVision = state.VLESSRealityVision{Enabled: true, Port: profile.Port, UUID: profile.UUID, PublicKey: profile.PublicKey, ShortID: profile.ShortID, ServerName: profile.ServerName, Fingerprint: profile.Fingerprint}
		case connectionprofiles.VLESSXHTTPProfileID:
			candidate.VLESSXHTTP = state.VLESSXHTTP{Enabled: true, UUID: profile.UUID, Path: profile.Path, Hostname: profile.Hostname, Mode: profile.XHTTPServerMode}
		case connectionprofiles.VLESSWebSocketProfileID:
			candidate.VLESSWebSocket = state.VLESSWebSocket{Enabled: true, UUID: profile.UUID, Path: profile.Path, Hostname: profile.Hostname}
		case connectionprofiles.Hysteria2ProfileID:
			candidate.Hysteria2 = state.Hysteria2{Enabled: true, Port: profile.Port, Password: profile.Password, ServerName: profile.ServerName, Obfuscation: profile.Obfuscation, ObfuscationSecret: profile.ObfuscationSecret}
		case connectionprofiles.TUICProfileID:
			candidate.TUIC = state.TUIC{Enabled: true, Port: profile.Port, UUID: profile.UUID, Password: profile.Password, ServerName: profile.ServerName, CongestionControl: profile.CongestionControl}
		case connectionprofiles.AnyTLSProfileID:
			candidate.AnyTLS = state.AnyTLS{Enabled: true, Port: profile.Port, Password: profile.Password, ServerName: profile.ServerName}
		}
	}
	return candidate
}

func sourceForCandidateProfiles(t *testing.T, template connectionprofiles.PublicationSource, candidate state.ConnectionProfiles) connectionprofiles.PublicationSource {
	t.Helper()
	profiles := make([]connectionprofiles.PublicationProfile, 0, 6)
	omissions := make([]connectionprofiles.PublicationOmission, 0, 6)
	for _, profile := range template.Profiles() {
		enabled := true
		switch profile.ID {
		case connectionprofiles.VLESSRealityVisionProfileID:
			enabled = candidate.VLESSRealityVision.Enabled
			profile.UUID, profile.ShortID, profile.PublicKey = candidate.VLESSRealityVision.UUID, candidate.VLESSRealityVision.ShortID, candidate.VLESSRealityVision.PublicKey
		case connectionprofiles.VLESSXHTTPProfileID:
			enabled = candidate.VLESSXHTTP.Enabled
			profile.UUID, profile.Path = candidate.VLESSXHTTP.UUID, candidate.VLESSXHTTP.Path
		case connectionprofiles.VLESSWebSocketProfileID:
			enabled = candidate.VLESSWebSocket.Enabled
			profile.UUID, profile.Path = candidate.VLESSWebSocket.UUID, candidate.VLESSWebSocket.Path
		case connectionprofiles.Hysteria2ProfileID:
			enabled = candidate.Hysteria2.Enabled
			profile.Password = candidate.Hysteria2.Password
		case connectionprofiles.TUICProfileID:
			enabled = candidate.TUIC.Enabled
			profile.UUID, profile.Password = candidate.TUIC.UUID, candidate.TUIC.Password
		case connectionprofiles.AnyTLSProfileID:
			enabled = candidate.AnyTLS.Enabled
			profile.Password = candidate.AnyTLS.Password
		}
		if enabled {
			profiles = append(profiles, profile)
		} else {
			name := profile.Name
			if profile.ID == connectionprofiles.VLESSXHTTPProfileID {
				name = "VLESS XHTTP"
			}
			omissions = append(omissions, connectionprofiles.PublicationOmission{ID: profile.ID, Name: name, Lifecycle: state.ProfileDisabled})
		}
	}
	source, err := connectionprofiles.NewPublicationSource(profiles, omissions)
	if err != nil {
		t.Fatal(err)
	}
	return source
}
