package connectionprofiles_test

import (
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestRevisionOneViewProvesFiveProfilesNotSetUp(t *testing.T) {
	request := validRegistryRequest(t)
	credentials, err := connectionprofiles.GenerateRealityCredentials()
	if err != nil {
		t.Fatal(err)
	}
	request, err = connectionprofiles.NewRevisionOneRegistry(request, credentials)
	if err != nil {
		t.Fatal(err)
	}
	request.Exposure = registryPolicyContribution(request)

	result := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
	if result.Health.Outcome != connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-REGISTRY-EXPECTED-ABSENCE" || len(result.Profiles) != 6 || len(result.Publication.Profiles()) != 1 || len(result.Publication.Omissions()) != 5 {
		t.Fatalf("revision 1 View = %+v", result)
	}
	if result.Profiles[0].Lifecycle != state.ProfileEnabled || result.Profiles[0].Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("revision 1 REALITY = %+v", result.Profiles[0])
	}
	for _, profile := range result.Profiles[1:] {
		if profile.Lifecycle != state.ProfileNotSetUp || profile.Enabled || profile.CredentialsReady || profile.SelectedListener != (connectionprofiles.Listener{}) || profile.Listener != (connectionprofiles.Listener{}) || profile.Health.Outcome != "" || profile.Health.Code != "" {
			t.Fatalf("deferred profile = %+v", profile)
		}
	}
	profiles, valid := connectionprofiles.DesiredProfiles(request)
	if !valid || profiles.VLESSRealityVision.Lifecycle != state.ProfileEnabled || profiles.VLESSXHTTP != (state.VLESSXHTTP{Lifecycle: state.ProfileNotSetUp}) || profiles.VLESSWebSocket != (state.VLESSWebSocket{Lifecycle: state.ProfileNotSetUp}) || profiles.Hysteria2 != (state.Hysteria2{Lifecycle: state.ProfileNotSetUp}) || profiles.TUIC != (state.TUIC{Lifecycle: state.ProfileNotSetUp}) || profiles.AnyTLS != (state.AnyTLS{Lifecycle: state.ProfileNotSetUp}) {
		t.Fatalf("revision 1 DesiredProfiles = (%+v, %t)", profiles, valid)
	}
}

func TestNotSetUpProfilesHaveNoIndividualOrRotationAction(t *testing.T) {
	request := validRegistryRequest(t)
	request, err := connectionprofiles.NewRevisionOneRegistry(request, request.Reality.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	request.Exposure = registryPolicyContribution(request)
	result := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
	profiles, valid := connectionprofiles.DesiredProfiles(request)
	if result.Health.Outcome != connectionprofiles.Healthy || !valid {
		t.Fatalf("revision 1 registry = (%+v, %v)", result, valid)
	}
	for _, action := range []connectionprofiles.RegistryMutationAction{connectionprofiles.EnableProfile, connectionprofiles.DisableProfile, connectionprofiles.RotateProfileCredential} {
		if _, err := connectionprofiles.PrepareRegistryMutation(action, connectionprofiles.VLESSXHTTPProfileID, request.ClientAddress, profiles, result.Publication); err == nil {
			t.Fatalf("%s accepted a Not set up profile", action)
		}
	}
	if _, err := connectionprofiles.PrepareRegistryMutation(connectionprofiles.RotateEveryProfileCredential, "", request.ClientAddress, profiles, result.Publication); err == nil {
		t.Fatal("all-profile rotation accepted Not set up profiles")
	}
}

func TestCloudflareSetupPlanCreatesAllFiveDeferredProfilesAtomically(t *testing.T) {
	current := validRegistryRequest(t)
	current, err := connectionprofiles.NewRevisionOneRegistry(current, current.Reality.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	current.Reality.Revision, current.XHTTP.Revision, current.WebSocket.Revision = 7, 7, 7
	current.Hysteria2.Revision, current.TUIC.Revision, current.AnyTLS.Revision = 7, 7, 7
	current.Exposure = registryPolicyContribution(current)

	candidate := validRegistryRequest(t)
	candidate.Reality = current.Reality
	setRegistryRevision(&candidate, 8)
	directTLSForSelectedPorts(&candidate)
	credentials, err := connectionprofiles.GenerateDeferredRegistryCredentials()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = connectionprofiles.NewDeferredRegistry(candidate, credentials)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Exposure = registryPolicyContribution(candidate)

	const changeSet = "profiles-cloudflare-setup-0008"
	starting, desired := strings.Repeat("a", 64), strings.Repeat("b", 64)
	result := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: changeSet, StartingStateSHA256: starting, DesiredStateSHA256: desired})
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy {
		t.Fatalf("Cloudflare setup Plan = %+v", result)
	}
	start, next, gotStarting, gotDesired, gotChangeSet, valid := result.Plan.StateProfileSetupConnectionProfiles()
	if !valid || start != 7 || next != 8 || gotStarting != starting || gotDesired != desired || gotChangeSet != changeSet {
		t.Fatalf("setup contribution = (%d, %d, %q, %q, %q, %t)", start, next, gotStarting, gotDesired, gotChangeSet, valid)
	}
	origins := result.Plan.ProfileSetupSteps()
	if len(origins) != 1 || origins[0].Forward() != systemchanges.ActivatePreparedOrigins || origins[0].Rollback() != systemchanges.RestorePriorOrigins {
		t.Fatalf("setup origins = %+v", origins)
	}
	if _, _, _, _, _, reused := result.Plan.StateProfileSetupConnectionProfiles(); reused {
		t.Fatal("setup contribution was reusable")
	}
	prepared := &realityPreparedState{changeSet: changeSet, revision: 8, starting: starting, candidate: desired, planIdentity: result.Plan.Identity(), planSHA: result.Plan.SHA256()}
	confirmation := systemchanges.CloudflareSetupConfirmation(func(systemchanges.CloudflareSetupConfirmationRequest) bool { return true })
	startingLineage := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: starting}
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	applied := result.Plan.Apply(systemchanges.Interface{}, prepared, startingLineage, result.Plan.VolatileSHA256(), disk, confirmation)
	if applied.Finding == nil || applied.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !applied.PlanConsumed {
		t.Fatalf("Cloudflare setup Apply = %+v", applied)
	}
}

func TestCloudflareSetupPlanRejectsPartialAndCrossRevisionCandidates(t *testing.T) {
	current := validRegistryRequest(t)
	current, err := connectionprofiles.NewRevisionOneRegistry(current, current.Reality.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	current.Reality.Revision, current.XHTTP.Revision, current.WebSocket.Revision = 7, 7, 7
	current.Hysteria2.Revision, current.TUIC.Revision, current.AnyTLS.Revision = 7, 7, 7
	current.Exposure = registryPolicyContribution(current)
	candidate := validRegistryRequest(t)
	candidate.Reality = current.Reality
	setRegistryRevision(&candidate, 8)
	directTLSForSelectedPorts(&candidate)
	credentials, err := connectionprofiles.GenerateDeferredRegistryCredentials()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err = connectionprofiles.NewDeferredRegistry(candidate, credentials)
	if err != nil {
		t.Fatal(err)
	}

	for _, change := range []func(*connectionprofiles.RegistryViewRequest){
		func(request *connectionprofiles.RegistryViewRequest) {
			request.AnyTLS = connectionprofiles.AnyTLSViewRequest{Revision: 8}
			request.Lifecycles.AnyTLS = state.ProfileNotSetUp
		},
		func(request *connectionprofiles.RegistryViewRequest) { request.AnyTLS.Revision = 9 },
	} {
		invalid := candidate
		change(&invalid)
		invalid.Exposure = registryPolicyContribution(invalid)
		result := connectionprofiles.New(healthyRegistryHost(current)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: invalid, ChangeSet: "profiles-cloudflare-setup-invalid", StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64)})
		if result.Plan != nil || result.Health.Outcome == connectionprofiles.Healthy {
			t.Fatalf("invalid setup Plan = %+v", result)
		}
	}
}

func TestRevisionOnePlanAndApplyUseOnlyTheRealityConfiguration(t *testing.T) {
	candidate := validRegistryRequest(t)
	candidate.Reality.Revision = 1
	candidate, err := connectionprofiles.NewRevisionOneRegistry(candidate, candidate.Reality.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Exposure = registryPolicyContribution(candidate)
	current := candidate
	current.Reality.Revision, current.XHTTP.Revision, current.WebSocket.Revision = 0, 0, 0
	current.Hysteria2.Revision, current.TUIC.Revision, current.AnyTLS.Revision = 0, 0, 0
	current.Reality.Port = 0
	fresh := systemchanges.New(managedStatusAdapter{observation: systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased}}).FreshInstallationAuthority()
	desired := strings.Repeat("b", 64)
	result := connectionprofiles.New(healthyRegistryHost(candidate)).PlanRegistry(t.Context(), connectionprofiles.RegistryPlanRequest{Current: current, Candidate: candidate, ChangeSet: "profiles-revision-one", DesiredStateSHA256: desired, FreshInstallation: fresh})
	if result.Plan == nil || result.Health.Outcome != connectionprofiles.Healthy || len(result.Plan.Steps()) != 1 || len(result.Plan.Checks()) == 0 {
		t.Fatalf("revision 1 Plan = %+v", result)
	}
	profiles, valid := connectionprofiles.DesiredProfiles(candidate)
	if !valid {
		t.Fatal("revision 1 Desired Profiles were invalid")
	}
	secrets := profileSecrets{clients: map[state.ClientAccessValue]string{profiles.VLESSRealityVision.UUID: uuidMarker, profiles.VLESSRealityVision.ShortID: shortIDMarker}, infrastructure: map[state.InfrastructureSecret]string{profiles.VLESSRealityVision.PrivateKey: privateKeyMarker}}
	xray, singBox, prepareErr := result.Plan.PrepareConnectionProfiles(profiles, secrets)
	if prepareErr != nil || !strings.Contains(string(xray), "vless-reality-vision") || strings.Contains(string(xray), "vless-xhttp") || len(singBox) != 0 {
		t.Fatalf("revision 1 configurations = (xray=%s sing-box=%s err=%v)", xray, singBox, prepareErr)
	}
	prepared := &realityPreparedState{changeSet: "profiles-revision-one", revision: 1, candidate: desired, planIdentity: result.Plan.Identity(), planSHA: result.Plan.SHA256()}
	applied := result.Plan.Apply(systemchanges.Interface{}, prepared, systemchanges.StateLineage{Status: systemchanges.NotInstalled}, result.Plan.VolatileSHA256(), systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1})
	if applied.Finding == nil || applied.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !applied.PlanConsumed {
		t.Fatalf("revision 1 Apply = %+v", applied)
	}
}

func TestRevisionOneViewRefusesDeferredPlaceholders(t *testing.T) {
	request := validRegistryRequest(t)
	credentials, err := connectionprofiles.GenerateRealityCredentials()
	if err != nil {
		t.Fatal(err)
	}
	request, err = connectionprofiles.NewRevisionOneRegistry(request, credentials)
	if err != nil {
		t.Fatal(err)
	}
	request.XHTTP.Hostname = "placeholder.example.com"
	request.Exposure = registryPolicyContribution(request)

	result := connectionprofiles.New(healthyRegistryHost(request)).ViewRegistry(t.Context(), request)
	if result.Health.Outcome == connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-REGISTRY-EXPECTED-ABSENCE" || len(result.Publication.Profiles()) != 0 {
		t.Fatalf("deferred placeholder View = %+v", result)
	}
}

func TestRevisionOneViewRefusesDeferredServiceResidue(t *testing.T) {
	request := validRegistryRequest(t)
	request, err := connectionprofiles.NewRevisionOneRegistry(request, request.Reality.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	request.Exposure = registryPolicyContribution(request)
	host := healthyRegistryHost(request)
	host.deferred.SingBoxServiceInactive = false

	result := connectionprofiles.New(host).ViewRegistry(t.Context(), request)
	if result.Health.Outcome == connectionprofiles.Healthy || result.Health.Code != "CONNECTION-PROFILES-REGISTRY-EXPECTED-ABSENCE" || len(result.Publication.Profiles()) != 0 {
		t.Fatalf("deferred service residue View = %+v", result)
	}
}
