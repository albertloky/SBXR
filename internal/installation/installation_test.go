package installation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func newCloudflareTestModule(api cloudflaretunnel.API, clock cloudflaretunnel.Clock) cloudflaretunnel.Interface {
	return cloudflaretunnel.New(api, clock, func(context.Context, []byte) error { return nil })
}

func TestComposedInstallBuildsAndPreparesTheCompleteRevisionOnePlan(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := newCloudflareTestModule(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedNetworkObserver{})
	built, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network:    networkModule.Evaluate,
		cloudflare: cloudflareModule.Plan,
		random:     newInstallEntropyReader(request.Entropy),
		inventory:  cloudflareAPI,
	})
	if err != nil {
		t.Fatal(err)
	}
	summary := built.plan.Summary()
	if summary.Revision != 1 || summary.InstallationStatus != softwarelifecycle.NotInstalled || summary.Result != softwarelifecycle.Managed || len(summary.Units) != 11 || len(summary.Profiles) != 6 || len(summary.SubscriptionRepresentations) != 7 || len(summary.Certificates) != 2 {
		t.Fatalf("incomplete composed install summary: %+v", summary)
	}
	prepared, err := built.prepareState(state.New(absentInstallState{}))
	if err != nil || prepared == nil {
		t.Fatalf("prepareState() = (%+v, %v)", prepared, err)
	}
	rendered := fmt.Sprintf("%+v %+v %+v", built.plan, built.wiring, prepared)
	for _, marker := range []string{request.CloudflareToken, hex.EncodeToString(request.Entropy), "COMPOSED-INSTALL-SECRET-MARKER"} {
		if strings.Contains(rendered, marker) {
			t.Fatalf("composed installation evidence exposed protected marker %q", marker)
		}
	}
}

func TestRootRuntimeArtifactsCrossStateAndSystemChangesInterfaces(t *testing.T) {
	build := func(session string) *builtInstall {
		request := composedInstallRequest(t)
		request.Session = strings.Repeat(session, 64)
		cloudflareAPI := composedCloudflareAPI{}
		built, err := buildInstallWith(t.Context(), request, buildDependencies{
			stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
				return request.Candidate.Staged, nil
			},
			network: networkpolicy.New(composedNetworkObserver{}).Evaluate, cloudflare: newCloudflareTestModule(cloudflareAPI, composedClock{}).Plan,
			random: newInstallEntropyReader(request.Entropy), inventory: cloudflareAPI,
		})
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	built := build("b")
	apply := func(failPost bool) (*runtimeArtifactTransactionAdapter, systemchanges.ApplyResult) {
		prepared, prepareErr := prepareRootRuntimeStateForTest(t, built, state.New(&publishingInstallState{}))
		if prepareErr != nil {
			t.Fatal(prepareErr)
		}
		changeSetID, _, _, candidateSHA, planID, planSHA, valid := prepared.SystemChangesPreparedState()
		if !valid {
			t.Fatal("prepared State binding unavailable")
		}
		volatile := strings.Repeat("9", 64)
		adapter := &runtimeArtifactTransactionAdapter{failPost: failPost, observation: systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: volatile, FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}}
		changeSet, changeSetErr := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{Identity: changeSetID, Mutation: systemchanges.InstallationMutation, OutcomeOwner: systemchanges.CloudflareModule, StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled}, TargetStateSHA256: candidateSHA, Plan: systemchanges.PlanBinding{Identity: planID, SHA256: planSHA, VolatileSHA256: volatile}, PreparedState: prepared, Steps: built.wiring.cloudflare.Steps(), Checks: built.wiring.cloudflare.Checks(), Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second}, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
		if changeSetErr != nil {
			t.Fatal(changeSetErr)
		}
		return adapter, systemchanges.New(adapter).Apply(changeSet)
	}
	rolledBackAdapter, rolledBack := apply(true)
	if rolledBack.Outcome != systemchanges.RollbackSucceeded || rolledBackAdapter.reversed != len(built.wiring.cloudflare.Steps()) {
		t.Fatalf("System Changes rollback = %+v, reversed=%d", rolledBack, rolledBackAdapter.reversed)
	}
	built = build("c")
	adapter, result := apply(false)
	if result.Outcome != systemchanges.Completed {
		t.Fatalf("System Changes Apply = %+v", result)
	}
	for _, name := range []string{"xray", "sing_box", "cloudflared"} {
		if !strings.Contains(string(adapter.artifacts["prepared/manifests.json"]), `"`+name+`"`) || !strings.Contains(string(adapter.artifacts["prepared/manifests.json"]), `"Group":"root"`) || !strings.Contains(string(adapter.artifacts["prepared/manifests.json"]), `"FileMode":420`) {
			t.Fatalf("root-runtime manifests = %s", adapter.artifacts["prepared/manifests.json"])
		}
	}
}

type rootRuntimeTestWiring struct{ *installWiring }

func (*rootRuntimeTestWiring) ValidateCloudflare(state.CloudflareSettings, state.InfrastructureSecretReader) error {
	return nil
}

func prepareRootRuntimeStateForTest(t *testing.T, built *builtInstall, module state.Interface) (*state.PreparedCommit, error) {
	t.Helper()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.CleanVPS})
	if err != nil {
		return nil, err
	}
	candidate := built.desired
	candidate.Cloudflare.TunnelID = "550e8400-e29b-41d4-a716-446655440001"
	candidate.Cloudflare.XHTTPDNSRecordID = "dns-xhttp-root-runtime"
	candidate.Cloudflare.WebSocketDNSRecordID = "dns-websocket-root-runtime"
	candidate.Cloudflare.DirectIPv4RecordID = "dns-direct-root-runtime"
	candidate.Cloudflare.TunnelRunToken = state.NewInfrastructureSecret("ROOT-RUNTIME-RUN-TOKEN")
	proofs := map[softwarelifecycle.InstallContributionName]softwarelifecycle.InstallContributionProof{}
	for _, contribution := range built.contributions {
		proof := contribution.SoftwareLifecycleInstallContribution()
		proofs[softwarelifecycle.InstallContributionName(proof.Name)] = proof
	}
	certificateDigest := sha256.Sum256([]byte(proofs[softwarelifecycle.IPCertificateInstallContribution].SHA256 + proofs[softwarelifecycle.DomainCertificateInstallContribution].SHA256))
	checksums, err := state.NewManagedInputChecksums(proofs[softwarelifecycle.ProfilesInstallContribution].SHA256, proofs[softwarelifecycle.SubscriptionInstallContribution].SHA256, proofs[softwarelifecycle.CloudflareInstallContribution].SHA256, hex.EncodeToString(certificateDigest[:]), proofs[softwarelifecycle.NetworkInstallContribution].SHA256, built.plan.SHA256())
	if err != nil {
		return nil, err
	}
	reviewed, err := state.NewReviewedInputs(state.PlanIdentity(built.plan.Identity()), built.plan.SHA256(), checksums)
	if err != nil {
		return nil, err
	}
	wiring := &rootRuntimeTestWiring{built.wiring}
	release := candidateRelease(built.candidate)
	return module.PrepareCommit(state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: state.ReleaseIdentity{Repository: release.Repository, Tag: release.Tag, Commit: release.Commit, ReleaseIndexSHA256: release.IndexSHA256}, ChangeSet: state.ChangeSetIdentity("install-" + built.desired.Installation.ID[:16]), Candidate: candidate, SemanticValidators: state.SemanticValidators{ConnectionProfiles: wiring, Subscription: wiring, Cloudflare: wiring, Certificates: wiring, NetworkPolicy: wiring, SoftwareLifecycle: wiring}, ServiceMaterials: state.ServiceMaterialsFor(candidate), RuntimeArtifacts: state.RuntimeArtifactContributions{built.wiring.profiles, built.wiring.cloudflare}, SubscriptionPublication: wiring, ReviewedInputs: reviewed})
}

type publishingInstallState struct{ document []byte }

func (storage *publishingInstallState) Read() ([]byte, error) {
	if storage.document == nil {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), storage.document...), nil
}
func (storage *publishingInstallState) Publish(_ []byte, candidate []byte, _ string) ([]byte, error) {
	storage.document = append([]byte(nil), candidate...)
	return append([]byte(nil), candidate...), nil
}
func (storage *publishingInstallState) Restore(_ []byte, prior []byte) ([]byte, error) {
	storage.document = append([]byte(nil), prior...)
	return append([]byte(nil), prior...), nil
}

type runtimeArtifactLock struct{}

func (runtimeArtifactLock) Close() error { return nil }

type runtimeArtifactTransactionAdapter struct {
	observation systemchanges.Observation
	artifacts   map[string][]byte
	failPost    bool
	reversed    int
}

func (adapter *runtimeArtifactTransactionAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (*runtimeArtifactTransactionAdapter) TryLock() (systemchanges.Lock, bool, error) {
	return runtimeArtifactLock{}, true, nil
}
func (adapter *runtimeArtifactTransactionAdapter) Prepare(_ systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	adapter.artifacts = map[string][]byte{}
	return preparation.WriteStateArtifacts(func(name string, _ uint32, source io.Reader) error {
		body, err := io.ReadAll(source)
		adapter.artifacts[name] = body
		return err
	})
}
func (*runtimeArtifactTransactionAdapter) Record(systemchanges.ExecutionLease, systemchanges.CheckpointRecord) error {
	return nil
}

func (adapter *runtimeArtifactTransactionAdapter) Execute(_ systemchanges.ExecutionLease, _ string, number int, step systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	adapter.artifacts["active/xray.json"] = append([]byte(nil), adapter.artifacts["prepared/xray.json"]...)
	adapter.artifacts["active/sing-box.json"] = append([]byte(nil), adapter.artifacts["prepared/sing-box.json"]...)
	adapter.artifacts["active/cloudflared.json"] = append([]byte(nil), adapter.artifacts["prepared/cloudflared.json"]...)
	if change, ok := step.CloudflareChange(); ok {
		evidence := systemchanges.StepEvidence{Code: "root-runtime-applied", SHA256: strings.Repeat("a", 64), ResourceID: fmt.Sprintf("resource-%d", number)}
		switch change.Action {
		case systemchanges.CloudflareTunnelCreate:
			evidence.ResourceType = string(systemchanges.CloudflareTunnelResource)
		case systemchanges.CloudflareRoutesPut:
			evidence.ResourceType = string(systemchanges.CloudflareRouteResource)
		case systemchanges.CloudflareDNSCreate:
			evidence.ResourceType = string(systemchanges.CloudflareDNSRecordResource)
		}
		return evidence, nil
	}
	return systemchanges.StepEvidence{Code: "root-runtime-applied", SHA256: strings.Repeat("a", 64)}, nil
}
func (adapter *runtimeArtifactTransactionAdapter) Reverse(systemchanges.ExecutionLease, string, int, systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error) {
	adapter.reversed++
	return systemchanges.StepEvidence{Code: "root-runtime-restored", SHA256: strings.Repeat("b", 64)}, nil
}
func (adapter *runtimeArtifactTransactionAdapter) Check(_ systemchanges.ExecutionLease, _ systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	if adapter.failPost && phase == systemchanges.PostPublication {
		adapter.artifacts["active/cloudflared.json"] = []byte(`{"routes":[]}`)
	}
	var manifests struct {
		Xray        *struct{ SHA256 string } `json:"xray"`
		SingBox     *struct{ SHA256 string } `json:"sing_box"`
		Cloudflared *struct{ SHA256 string } `json:"cloudflared"`
	}
	if err := json.Unmarshal(adapter.artifacts["prepared/manifests.json"], &manifests); err != nil || manifests.Xray == nil || manifests.SingBox == nil || manifests.Cloudflared == nil {
		return systemchanges.Unknown, err
	}
	for name, expected := range map[string]string{"active/xray.json": manifests.Xray.SHA256, "active/sing-box.json": manifests.SingBox.SHA256, "active/cloudflared.json": manifests.Cloudflared.SHA256} {
		digest := sha256.Sum256(adapter.artifacts[name])
		if hex.EncodeToString(digest[:]) != expected {
			return systemchanges.Failed, nil
		}
	}
	return systemchanges.Healthy, nil
}
func (*runtimeArtifactTransactionAdapter) VerifyAgreement(systemchanges.ExecutionLease, systemchanges.Agreement, time.Duration) error {
	return nil
}
func (*runtimeArtifactTransactionAdapter) VerifyRollback(systemchanges.ExecutionLease, systemchanges.RollbackAgreement, time.Duration) error {
	return nil
}
func (*runtimeArtifactTransactionAdapter) Cleanup(systemchanges.ExecutionLease, string) error {
	return nil
}

func TestDestructiveReclamationCompositionBindsAllOwningModulesToOneChangeSet(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	built, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network:    networkpolicy.New(composedNetworkObserver{}).Evaluate,
		cloudflare: newCloudflareTestModule(cloudflareAPI, composedClock{}).Plan,
		random:     newInstallEntropyReader(request.Entropy),
		inventory:  cloudflareAPI,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		string(softwarelifecycle.NetworkInstallContribution):           true,
		string(softwarelifecycle.ProfilesInstallContribution):          true,
		string(softwarelifecycle.CloudflareInstallContribution):        true,
		string(softwarelifecycle.IPCertificateInstallContribution):     true,
		string(softwarelifecycle.DomainCertificateInstallContribution): true,
		string(softwarelifecycle.SubscriptionInstallContribution):      true,
	}
	changeSet := string(requestChangeSet(request))
	for _, contribution := range built.contributions {
		proof := contribution.SoftwareLifecycleInstallContribution()
		if !want[proof.Name] || proof.ChangeSet != changeSet || proof.DesiredStateSHA256 != built.desiredSHA256 || len(proof.Steps) == 0 {
			t.Fatalf("incomplete contribution in composed Change Set: %+v", proof)
		}
		delete(want, proof.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing owning Module contributions: %v", want)
	}
}

func TestComposedInstallRoutesAReclaimableVPSToReviewBeforeProviderPlanning(t *testing.T) {
	request := composedInstallRequest(t)
	plan := &networkpolicy.ReclamationPlan{Digest: strings.Repeat("f", 64), Targets: []string{"executable /usr/local/bin/xray"}}
	providerCalled := false
	_, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: func(networkpolicy.Request) networkpolicy.Result {
			return networkpolicy.Result{InstallationClass: networkpolicy.ReclaimableVPS, Reclamation: plan}
		},
		cloudflare: func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult {
			providerCalled = true
			return cloudflaretunnel.PlanResult{}
		},
		random:    newInstallEntropyReader(request.Entropy),
		inventory: composedCloudflareAPI{},
	})
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan != plan || providerCalled {
		t.Fatalf("reclaimable routing = error %v review %+v provider-called %t", err, review, providerCalled)
	}
}

func TestComposedInstallCarriesTheExactReviewedStandaloneTargetIntoOneInstallPlan(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := newCloudflareTestModule(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := buildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, cloudflare: cloudflareModule.Plan, random: newInstallEntropyReader(request.Entropy), inventory: cloudflareAPI}
	_, err := buildInstallWith(t.Context(), request, dependencies)
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan == nil {
		t.Fatalf("initial reclamation review = %v", err)
	}
	request.ReviewedReclamationSHA256 = review.plan.Digest
	built, err := buildInstallWith(t.Context(), request, dependencies)
	if err != nil || built == nil || built.plan == nil || built.plan.Summary().Result != softwarelifecycle.Managed {
		t.Fatalf("reviewed reclamation install = (%+v, %v)", built, err)
	}
	recheck, _, err := recheckInstall(t.Context(), request, built)
	if err != nil || recheck.Reclamation == nil {
		t.Fatalf("privileged reclamation recheck = (%+v, %v)", recheck, err)
	}
	_, reviewed, kinds, paths, digests, _, processIDs, _, _, _, _, _, valid := recheck.Reclamation.SystemChangesReclamation()
	if !valid || len(kinds) != 1 || kinds[0] != "executable" || paths[0] != "/opt/standalone/proxy" || digests[0] != strings.Repeat("9", 64) || processIDs[0] != "4242" || reviewed != request.ReviewedReclamationSHA256 {
		t.Fatalf("reclamation Apply authority = (%v, %v, %v, %v, %q, %t)", kinds, paths, digests, processIDs, reviewed, valid)
	}
}

func TestDestructiveReclamationCompositionKeepsTheExactFactsInTheConfirmedPlan(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := newCloudflareTestModule(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := buildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, cloudflare: cloudflareModule.Plan, random: newInstallEntropyReader(request.Entropy), inventory: cloudflareAPI}
	_, err := buildInstallWith(t.Context(), request, dependencies)
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan == nil {
		t.Fatalf("initial reclamation review = %v", err)
	}
	request.ReviewedReclamationSHA256 = review.plan.Digest
	built, err := buildInstallWith(t.Context(), request, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := finalPlan(built, request, review.plan)
	if confirmed == nil || !slices.Contains(confirmed.Effects, "executable /opt/standalone/proxy sha256 "+strings.Repeat("9", 64)) || !slices.Contains(confirmed.Effects, "identity proxy kind service user exclusive true") {
		t.Fatalf("confirmed reclamation Plan lost exact effects: %+v", confirmed)
	}
	for _, effect := range installPlanEffects() {
		if !slices.Contains(confirmed.Effects, effect) {
			t.Fatalf("confirmed reclamation Plan lost install effect %q: %+v", effect, confirmed)
		}
	}
}

func TestDestructiveReclamationCompositionKeepsLongFirewallFactsWithoutUnsafeLines(t *testing.T) {
	first := strings.Repeat("a", 319)
	second := strings.Repeat("b", 160) + "\n" + strings.Repeat("c", 161)
	plan := &networkpolicy.ReclamationPlan{Targets: []string{first, second}}
	effects, ok := reclamationPlanEffects(plan, 64)
	if strings.Join(effects, "") != first+strings.ReplaceAll(second, "\n", "") || slices.ContainsFunc(effects, func(effect string) bool {
		return effect == "" || len(effect) > 320 || strings.ContainsAny(effect, "\r\n")
	}) || !ok {
		t.Fatalf("exact firewall facts were lost or unsafe: %q", effects)
	}
}

type composedPlanAPI interface {
	cloudflaretunnel.API
	cloudflaretunnel.MutationPlanner
}

func composedBuiltInstall(t *testing.T, request softwareubuntu.InstallHandoffRequest, observer networkpolicy.Adapter, api composedPlanAPI) *builtInstall {
	t.Helper()
	built, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(observer).Evaluate, cloudflare: newCloudflareTestModule(api, composedClock{}).Plan,
		random: newInstallEntropyReader(request.Entropy), inventory: api,
	})
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func TestDestructiveReclamationCompositionCarriesEveryApprovedEffectThroughPrivilegedRecheck(t *testing.T) {
	tests := []struct {
		name     string
		observer networkpolicy.Adapter
		api      composedPlanAPI
		verify   func(*testing.T, any)
	}{
		{name: "standalone executable and preserved identity", observer: composedReclamationObserver{}, api: composedCloudflareAPI{}, verify: func(t *testing.T, value any) {
			verifyLocalAuthority(t, value, "executable", "/opt/standalone/proxy", "", true)
		}},
		{name: "script", observer: composedScriptObserver{}, api: composedCloudflareAPI{}, verify: func(t *testing.T, value any) {
			verifyLocalAuthority(t, value, "script", "/opt/proxy/server.py", "", false)
		}},
		{name: "package purge", observer: composedPackageObserver{}, api: composedCloudflareAPI{}, verify: func(t *testing.T, value any) {
			verifyLocalAuthority(t, value, "package-purge", "/opt/xray/proxy", "xray", false)
		}},
		{name: "package hold", observer: composedHeldPackageObserver{}, api: composedCloudflareAPI{}, verify: func(t *testing.T, value any) {
			verifyLocalAuthority(t, value, "package-hold", "/opt/vendor-proxy/proxy", "vendor-proxy", false)
		}},
		{name: "Docker and preserved data", observer: composedDockerObserver{}, api: composedCloudflareAPI{}, verify: verifyDockerAuthority},
		{name: "firewall and SSH", observer: composedFirewallObserver{}, api: composedCloudflareAPI{}, verify: verifyFirewallAuthority},
		{name: "Cloudflare DNS routes and Tunnel", observer: composedNetworkObserver{}, api: composedConflictAPI{}, verify: verifyCloudflareAuthority},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := composedInstallRequest(t)
			dependencies := composedInstallDependencies(request, test.observer, test.api)
			_, err := buildInstallWith(t.Context(), request, dependencies)
			var review *reclamationReviewError
			if !errors.As(err, &review) || review.plan == nil {
				t.Fatalf("review = %v", err)
			}
			request.ReviewedReclamationSHA256 = review.plan.Digest
			built, err := buildInstallWith(t.Context(), request, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			rechecked, _, err := recheckInstall(t.Context(), request, built)
			if err != nil {
				t.Fatalf("privileged authority = (%+v, %v)", rechecked, err)
			}
			test.verify(t, rechecked.Reclamation)
		})
	}
}

func composedInstallDependencies(request softwareubuntu.InstallHandoffRequest, observer networkpolicy.Adapter, api composedPlanAPI) buildDependencies {
	return buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(observer).Evaluate, cloudflare: newCloudflareTestModule(api, composedClock{}).Plan,
		random: newInstallEntropyReader(request.Entropy), inventory: api,
	}
}

func verifyLocalAuthority(t *testing.T, value any, wantKind, wantPath, wantPackage string, preservedIdentity bool) {
	t.Helper()
	authority, ok := value.(systemchanges.ReclamationAuthority)
	if !ok {
		t.Fatalf("local authority type = %T", value)
	}
	_, _, kinds, paths, digests, interpreters, pids, packages, versions, ownedPaths, identities, identityKinds, valid := authority.SystemChangesReclamation()
	wantVersion := map[string]string{"xray": "1.2.3", "vendor-proxy": "4.5.6"}[wantPackage]
	if !valid || !slices.Equal(kinds, []string{wantKind}) || !slices.Equal(paths, []string{wantPath}) || len(digests) != 1 || len(digests[0]) != 64 || !slices.Equal(pids, []string{"4242"}) || packages[0] != wantPackage || wantKind == "script" && interpreters[0] != "/usr/bin/python3" || wantPackage != "" && (versions[0] != wantVersion || len(ownedPaths[0]) == 0) || preservedIdentity && (len(identities[0]) != 0 || len(identityKinds[0]) != 0) {
		t.Fatalf("local authority = %v %v %v %v %v %v %v %v %v %v valid=%t", kinds, paths, digests, interpreters, pids, packages, versions, ownedPaths, identities, identityKinds, valid)
	}
}

func verifyDockerAuthority(t *testing.T, value any) {
	t.Helper()
	authority, ok := value.(interface {
		SystemChangesDockerReclamation() (string, string, string, string, string, string, []string, []string, []string, []string, [][]string, []string, []string, [][]string, []string, []string, []string, bool)
		SystemChangesDockerReclamationAvailable() bool
	})
	if !ok || !authority.SystemChangesDockerReclamationAvailable() {
		t.Fatalf("Docker authority type = %T", value)
	}
	_, service, executable, executableSHA, pid, firewallSHA, objects, packages, versions, controls, owned, runtimes, runtimeVersions, runtimeOwned, preserved, paths, digests, valid := authority.SystemChangesDockerReclamation()
	if !valid || service != "docker.service" || executable != "/usr/bin/dockerd" || len(executableSHA) != 64 || pid != "4242" || len(firewallSHA) != 64 || len(objects) != 1 || !slices.Equal(packages, []string{"docker.io"}) || !slices.Equal(versions, []string{"26.1.3"}) || len(controls[0]) != 64 || len(owned[0]) != 2 || !slices.Equal(runtimes, []string{"containerd"}) || !slices.Equal(runtimeVersions, []string{"1.7.24"}) || len(runtimeOwned[0]) != 2 || len(preserved) != 6 || len(paths) != 2 || len(digests) != 2 {
		t.Fatalf("Docker authority incomplete: service=%s executable=%s packages=%v runtime=%v preserved=%v valid=%t", service, executable, packages, runtimes, preserved, valid)
	}
}

func verifyFirewallAuthority(t *testing.T, value any) {
	t.Helper()
	authority, ok := value.(interface {
		SystemChangesFirewallReclamation() (string, string, string, string, string, string, string, string, string, string, []string, []string, bool)
		SystemChangesFirewallReclamationAvailable() bool
	})
	if !ok || !authority.SystemChangesFirewallReclamationAvailable() {
		t.Fatalf("firewall authority type = %T", value)
	}
	_, manager, prior, outbound, candidate, service, listener, session, keysPath, keysSHA, objects, _, valid := authority.SystemChangesFirewallReclamation()
	if !valid || manager != "ufw.service" || len(prior) != 64 || len(outbound) != 64 || !strings.Contains(candidate, "policy drop") || service != "ssh.service" || listener != "0.0.0.0:22/tcp" || len(session) != 64 || keysPath != "/root/.ssh/authorized_keys" || len(keysSHA) != 64 || len(objects) != 1 {
		t.Fatalf("firewall authority incomplete: manager=%s service=%s listener=%s objects=%v valid=%t", manager, service, listener, objects, valid)
	}
}

func verifyCloudflareAuthority(t *testing.T, value any) {
	t.Helper()
	authority, ok := value.(interface {
		SystemChangesCloudflareReclamation() (string, []string, []string, []string, [][]string, bool)
		SystemChangesCloudflareReclamationAvailable() bool
	})
	if !ok || !authority.SystemChangesCloudflareReclamationAvailable() {
		t.Fatalf("Cloudflare authority type = %T", value)
	}
	_, kinds, ids, names, routes, valid := authority.SystemChangesCloudflareReclamation()
	if !valid || len(kinds) < 3 || !slices.Contains(kinds, "DNS record") || !slices.Contains(kinds, "Tunnel routes") || !slices.Contains(kinds, "Tunnel") || !slices.Contains(ids, "11111111-1111-4111-8111-111111111111") || !slices.Contains(names, "sbxr-main") || !slices.ContainsFunc(routes, func(values []string) bool {
		return slices.Contains(values, "xhttp.example.com\x00http://127.0.0.1:11080") && slices.Contains(values, "\x00http_status:404")
	}) {
		t.Fatalf("Cloudflare authority = %v %v %v %v valid=%t", kinds, ids, names, routes, valid)
	}
}

func TestComposedInstallPersistsOnlyTheReviewedHeldPackagePolicy(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := newCloudflareTestModule(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedHeldPackageObserver{})
	dependencies := buildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, cloudflare: cloudflareModule.Plan, random: newInstallEntropyReader(request.Entropy), inventory: cloudflareAPI}
	_, err := buildInstallWith(t.Context(), request, dependencies)
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan == nil {
		t.Fatalf("held package review = %v", err)
	}
	request.ReviewedReclamationSHA256 = review.plan.Digest
	built, err := buildInstallWith(t.Context(), request, dependencies)
	want := state.ReclamationPolicy{Version: 1, Held: state.HeldPackagePolicy{Name: "vendor-proxy", Version: "4.5.6", DeletedExecutable: "/opt/vendor-proxy/proxy", SHA256: strings.Repeat("9", 64)}}
	if err != nil || built == nil || built.desired.Reclamation != want {
		t.Fatalf("persisted reclamation policy = %+v, error %v", built, err)
	}
}

func TestComposedInstallRefusesAnIncompleteReclaimableInventory(t *testing.T) {
	request := composedInstallRequest(t)
	providerCalled := false
	module := networkpolicy.New(incompleteReclamationObserver{})
	_, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: module.Evaluate,
		cloudflare: func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult {
			providerCalled = true
			return cloudflaretunnel.PlanResult{}
		},
		random: newInstallEntropyReader(request.Entropy), inventory: composedCloudflareAPI{},
	})
	if err == nil || providerCalled {
		t.Fatalf("incomplete reclamation inventory continued: error %v provider-called %t", err, providerCalled)
	}
}

func TestReclamationInventoryBindsExactCloudflareConflictIdentifiers(t *testing.T) {
	token, err := cloudflaretunnel.NewManagementToken("cfat_COMPOSED-INSTALL-SECRET-MARKER-000000000")
	if err != nil {
		t.Fatal(err)
	}
	facts, _, err := observeReclamationCloudflare(t.Context(), conflictInventoryAPI{}, strings.Repeat("a", 32), strings.Repeat("b", 32), token, "sbxr-main", []string{"xhttp.example.com", "ws.example.com"})
	if err != nil || len(facts.Conflicts) != 4 {
		t.Fatalf("Cloudflare reclamation facts = %+v error %v", facts, err)
	}
}

func TestInstallationInterfaceValidatesDependenciesAndTypedDraft(t *testing.T) {
	if module, err := New(Dependencies{}); err == nil || module != nil {
		t.Fatalf("New() = (%+v, %v), want construction refusal", module, err)
	}
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	result := module.Review(t.Context(), Draft{})
	if result.Invalid == nil || result.Invalid.Field != "release-tag" || result.Plan != nil || result.Reclamation != nil {
		t.Fatalf("invalid Draft = %+v", result)
	}
}

func TestInstallationInterfaceOwnsPartialDraftUntilDiscard(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	if result := module.Review(t.Context(), Draft{Tag: "v1.0.0"}); result.Invalid == nil || result.Invalid.Field != "domain" {
		t.Fatalf("partial draft = %+v", result)
	}
	if result := module.Review(t.Context(), Draft{}); result.Invalid == nil || result.Invalid.Field != "domain" {
		t.Fatalf("active process forgot partial draft = %+v", result)
	}
	if result := module.Review(t.Context(), DiscardDraft()); result.Invalid == nil || result.Invalid.Field != "release-tag" {
		t.Fatalf("discard retained partial draft = %+v", result)
	}
}

func TestInstallationInterfaceCancellationBeforeApplyDiscardsDraftAndApproval(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	review := module.Review(t.Context(), composedDraft(t))
	if review.Plan == nil || review.Approval.cell == nil {
		t.Fatalf("Review = %+v", review)
	}
	if result := module.RequestCancellation(t.Context(), ""); result.Kind != CancellationRequested {
		t.Fatalf("pre-Apply cancellation = %+v", result)
	}
	if result := module.Apply(t.Context(), review.Approval); result.Kind != ApplyRefused {
		t.Fatalf("cancelled Approval remained usable: %+v", result)
	}
	if fresh := module.Review(t.Context(), Draft{}); fresh.Invalid == nil || fresh.Invalid.Field != "release-tag" {
		t.Fatalf("cancelled draft remained available: %+v", fresh)
	}
}

func TestInstallationInterfaceReviewsCleanVPSAndKeepsOneUseApprovalMemoryOnly(t *testing.T) {
	observer := &countingInstallationObserver{}
	module := newTestInstallation(t, observer, nil)
	review := module.Review(t.Context(), composedDraft(t))
	if review.Plan == nil || review.Plan.DesiredStateRevision != 1 || len(review.Plan.Effects) != 5 || review.Approval.cell == nil {
		t.Fatalf("clean VPS Review = %+v", review)
	}
	if _, err := review.Approval.MarshalJSON(); err == nil || strings.Contains(fmt.Sprintf("%v %#v", review.Approval, review.Approval), "COMPOSED-INSTALL-SECRET-MARKER") {
		t.Fatal("Approval became renderable or exposed protected material")
	}
	observations := observer.calls
	restarted := newTestInstallation(t, observer, nil)
	if result := restarted.Apply(t.Context(), review.Approval); result.Kind != ApplyRefused {
		t.Fatalf("pre-Apply restart retained authority: %+v", result)
	}
	if fresh := restarted.Review(t.Context(), composedDraft(t)); fresh.Plan == nil || observer.calls <= observations {
		t.Fatalf("later launch did not perform a fresh Review: review=%+v observations=%d before=%d", fresh, observer.calls, observations)
	}
	if result := module.Apply(t.Context(), review.Approval); result.Kind != ApplyStarted {
		t.Fatalf("Apply() = %+v", result)
	}
	if result := module.Apply(t.Context(), review.Approval); result.Kind != ApplyRefused {
		t.Fatalf("Approval replay = %+v", result)
	}
	changed := newTestInstallation(t, composedNetworkObserver{}, nil)
	stale := changed.Review(t.Context(), composedDraft(t))
	current := changed.Review(t.Context(), composedDraft(t))
	if result := changed.Apply(t.Context(), stale.Approval); result.Kind != ApplyRefused {
		t.Fatalf("stale Approval = %+v", result)
	}
	if result := changed.Apply(t.Context(), current.Approval); result.Kind != ApplyStarted {
		t.Fatalf("current Approval = %+v", result)
	}
}

func TestInstallationInterfaceRequiresExactReclamationConfirmation(t *testing.T) {
	module := newTestInstallation(t, composedReclamationObserver{}, nil)
	review := module.Review(t.Context(), composedDraft(t))
	if review.Reclamation == nil || review.Reclamation.ReclamationConfirmed || review.Reclamation.ReclamationDigest == "" {
		t.Fatalf("Reclaimable VPS Review = %+v", review)
	}
	wrong := module.ConfirmReclamation(t.Context(), ReclamationConfirmation{Identity: review.Reclamation.Identity, Digest: review.Reclamation.ReclamationDigest, Phrase: "reclaim this vps"})
	if wrong.Invalid == nil || wrong.Plan != nil {
		t.Fatalf("changed confirmation accepted: %+v", wrong)
	}
	review = module.Review(t.Context(), composedDraft(t))
	confirmed := module.ConfirmReclamation(t.Context(), ReclamationConfirmation{Identity: review.Reclamation.Identity, Digest: review.Reclamation.ReclamationDigest, Phrase: ReclamationPhrase})
	if confirmed.Plan == nil || !confirmed.Plan.ReclamationConfirmed || confirmed.Plan.ReclamationDigest != review.Reclamation.ReclamationDigest || confirmed.Approval.cell == nil {
		t.Fatalf("exact confirmation = %+v", confirmed)
	}
	for _, effect := range installPlanEffects() {
		if !slices.Contains(confirmed.Plan.Effects, effect) {
			t.Fatalf("confirmed Plan lost %q", effect)
		}
	}
}

func TestInstallationInterfaceTracksOneOperationCancellationAndTerminalState(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	module := newTestInstallation(t, composedNetworkObserver{}, func(_ context.Context, _ softwareubuntu.InstallHandoffRequest, cancellation <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
		close(started)
		<-cancellation
		close(cancelled)
		return softwareubuntu.InstallRolledBack, nil
	})
	first := module.Review(t.Context(), composedDraft(t))
	result := module.Apply(t.Context(), first.Approval)
	if result.Kind != ApplyStarted || result.Operation == "" {
		t.Fatalf("Apply() = %+v", result)
	}
	<-started
	second := module.Review(t.Context(), composedDraft(t))
	if got := module.Apply(t.Context(), second.Approval); got.Kind != ApplyRefused {
		t.Fatalf("second active operation = %+v", got)
	}
	if _, err := module.Inspect(t.Context(), "install-stale"); err == nil {
		t.Fatal("Inspect accepted stale Operation Identity")
	}
	if got := module.RequestCancellation(t.Context(), "install-stale"); got.Kind != ApplyRefused {
		t.Fatalf("stale cancellation = %+v", got)
	}
	if got := module.RequestCancellation(t.Context(), result.Operation); got.Kind != CancellationRequested {
		t.Fatalf("cancellation = %+v", got)
	}
	<-cancelled
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		operation, err := module.Inspect(t.Context(), result.Operation)
		if err == nil && operation.Status == RolledBack {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("operation did not report Rolled back")
}

func TestInstallationInterfaceReportsEveryTerminalAndOwnsOnlyInstallationRecovery(t *testing.T) {
	for _, test := range []struct {
		name     string
		terminal softwareubuntu.InstallApplyOutcome
		err      error
		want     OperationStatus
	}{
		{"Completed", softwareubuntu.InstallCompleted, nil, Completed},
		{"Rolled back", softwareubuntu.InstallRolledBack, nil, RolledBack},
		{"Recovery Required", 0, errors.New("worker ended"), RecoveryRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := newTestInstallation(t, composedNetworkObserver{}, func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
				return test.terminal, test.err
			})
			review := module.Review(t.Context(), composedDraft(t))
			result := module.Apply(t.Context(), review.Approval)
			for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
				operation, err := module.Inspect(t.Context(), result.Operation)
				if err == nil && operation.Status != OperationActive {
					if operation.Status != test.want {
						t.Fatalf("terminal = %+v", operation)
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("terminal operation unavailable")
		})
	}
	recovered := false
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	module.dependencies.Recover = func(context.Context, systemchanges.PendingChangeSet) error { recovered = true; return nil }
	if err := module.Recover(t.Context(), systemchanges.PendingChangeSet{Identity: "install-aaaaaaaaaaaaaaaa", Kind: systemchanges.UpdateMutation}); err == nil || recovered {
		t.Fatal("Installation recovered another mutation kind")
	}
	if err := module.Recover(t.Context(), systemchanges.PendingChangeSet{Identity: "install-aaaaaaaaaaaaaaaa", Kind: systemchanges.InstallationMutation}); err != nil || !recovered {
		t.Fatalf("Installation recovery = %v", err)
	}
}

func TestInstallationPrivilegedBoundaryRefusesChangedFactsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Interface)
	}{
		{name: "release", change: func(module *Interface) {
			module.dependencies.Stage = func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
				return softwarelifecycle.StagedRelease{}, errors.New("changed release")
			}
		}},
		{name: "provider", change: func(module *Interface) { module.dependencies.Inventory = composedConflictAPI{} }},
		{name: "Network Policy", change: func(module *Interface) {
			module.dependencies.Network = func(networkpolicy.Request) networkpolicy.Result {
				return networkpolicy.Result{Outcome: networkpolicy.Failed}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := false
			module := newTestInstallation(t, composedNetworkObserver{}, func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
				mutated = true
				return softwareubuntu.InstallCompleted, nil
			})
			review := module.Review(t.Context(), composedDraft(t))
			if review.Approval.cell == nil {
				t.Fatal("Review did not retain Approval")
			}
			test.change(module)
			if apply, err := PreparePrivilegedApply(module, t.Context(), review.Approval.cell.request); err == nil || apply != nil || mutated {
				t.Fatalf("changed %s facts: prepared=%t error=%v mutation=%t", test.name, apply != nil, err, mutated)
			}
		})
	}
}

func TestInstallationPrivilegedBoundaryRefusesAnotherModulesRecovery(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	reader := &pendingReaderStub{pending: systemchanges.PendingChangeSet{Identity: "update-aaaaaaaaaaaaaaaa", Kind: systemchanges.UpdateMutation}, found: true}
	module.dependencies.Pending = reader
	if apply, err := PreparePrivilegedApply(module, t.Context(), composedInstallRequest(t)); err == nil || apply != nil {
		t.Fatalf("non-Installation recovery: prepared=%t error=%v", apply != nil, err)
	}
}

type pendingReaderStub struct {
	pending systemchanges.PendingChangeSet
	found   bool
	err     error
}

func (reader pendingReaderStub) PendingChangeSet() (systemchanges.PendingChangeSet, bool, error) {
	return reader.pending, reader.found, reader.err
}

func composedDraft(t *testing.T) Draft {
	request := composedInstallRequest(t)
	return Draft{Tag: request.Tag, Architecture: request.Architecture, Installation: request.Draft, CloudflareAccountID: request.CloudflareAccountID, CloudflareZoneID: request.CloudflareZoneID, CloudflareToken: request.CloudflareToken, RealityTarget: request.RealityTarget, RealityServerName: request.RealityServerName}
}

func newTestInstallation(t *testing.T, observer networkpolicy.Adapter, launch func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error)) *Interface {
	t.Helper()
	request := composedInstallRequest(t)
	api := interfaceTestAPI{}
	cloudflare := newCloudflareTestModule(api, composedClock{})
	if launch == nil {
		launch = func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
			return softwareubuntu.InstallCompleted, nil
		}
	}
	module, err := New(Dependencies{
		ReleaseCandidate: func(context.Context, string, softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error) {
			return request.Candidate, nil
		},
		Stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		Network: networkpolicy.New(observer).Evaluate, Cloudflare: cloudflare.Plan, CloudflareAPI: api, Inventory: api, Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)), Launch: launch,
		Recover: func(context.Context, systemchanges.PendingChangeSet) error { return nil }, Pending: pendingReaderStub{}, WriteReceipt: func(string, softwarelifecycle.ReleaseIdentity, string) error { return nil }, RemoveReceipt: func() error { return nil }, ObserveState: func() (systemchanges.Observation, error) {
			return systemchanges.Observation{Status: systemchanges.NotInstalled}, nil
		}, LoadManaged: func() (systemchanges.Observation, state.ReleaseIdentity, error) {
			return systemchanges.Observation{}, state.ReleaseIdentity{}, nil
		}, ProveSubscription: func(context.Context, string, uint16) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return module
}

type interfaceTestAPI struct{ composedCloudflareAPI }

func (interfaceTestAPI) CreateTunnel(context.Context, cloudflaretunnel.CreateTunnelRequest) (cloudflaretunnel.CreatedTunnel, error) {
	return cloudflaretunnel.CreatedTunnel{}, nil
}
func (interfaceTestAPI) PutConfiguration(context.Context, cloudflaretunnel.PutConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{}, nil
}
func (interfaceTestAPI) GetConfiguration(context.Context, cloudflaretunnel.GetConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{}, nil
}
func (interfaceTestAPI) GetTunnel(context.Context, cloudflaretunnel.GetTunnelRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{}, nil
}
func (interfaceTestAPI) CreateDNSRecord(context.Context, cloudflaretunnel.CreateDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{}, nil
}
func (interfaceTestAPI) GetDNSRecord(context.Context, cloudflaretunnel.GetDNSRecordRequest) (cloudflaretunnel.DNSObservation, error) {
	return cloudflaretunnel.DNSObservation{}, nil
}
func (interfaceTestAPI) PutDNSRecord(context.Context, cloudflaretunnel.PutDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{}, nil
}
func (interfaceTestAPI) ObserveWholeTunnel(context.Context, cloudflaretunnel.WholeTunnelRequest) (cloudflaretunnel.WholeTunnelObservation, error) {
	return cloudflaretunnel.WholeTunnelObservation{}, nil
}
func (interfaceTestAPI) ObserveCertificateDNS(context.Context, cloudflaretunnel.CertificateDNSRequest) (cloudflaretunnel.CertificateDNSFacts, error) {
	return cloudflaretunnel.CertificateDNSFacts{}, nil
}
func (interfaceTestAPI) DeleteDNSRecord(context.Context, cloudflaretunnel.DeleteDNSRecordRequest) error {
	return nil
}
func (interfaceTestAPI) DeleteTunnel(context.Context, cloudflaretunnel.DeleteTunnelRequest) error {
	return nil
}

type conflictInventoryAPI struct{}

func (conflictInventoryAPI) ObserveMutation(_ context.Context, request cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{Tunnels: []cloudflaretunnel.OwnedResource{{ID: "11111111-1111-4111-8111-111111111111", Name: "sbxr-main"}}, DNSRecords: []cloudflaretunnel.OwnedResource{{ID: strings.Repeat("d", 32), Name: request.Hostname}}}, nil
}

func composedInstallRequest(t *testing.T) softwareubuntu.InstallHandoffRequest {
	t.Helper()
	application := []byte("authenticated application archive")
	componentFiles := map[string][]byte{
		"xray": []byte("#!/bin/sh\nexit 0\n"), "sing-box": []byte("#!/bin/sh\nexit 0\n"), "cloudflared": []byte("#!/bin/sh\nexit 0\n"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	components, err := softwarelifecycle.BuildComponentArchive(manifest, componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	applicationDigest, componentDigest := sha256.Sum256(application), sha256.Sum256(components)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("1", 40), IndexSHA256: strings.Repeat("2", 64)}
	applicationAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Size: int64(len(application)), SHA256: hex.EncodeToString(applicationDigest[:])}
	componentAsset := softwarelifecycle.AssetProof{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Size: int64(len(components)), SHA256: hex.EncodeToString(componentDigest[:])}
	verified := softwarelifecycle.VerifiedRelease{Identity: identity, Version: "1.0.0", Sequence: 1, StateSchema: 2, MinimumUpdaterSchema: 1, Assets: []softwarelifecycle.AssetProof{applicationAsset, componentAsset}}
	staged := softwarelifecycle.StagedRelease{Identity: identity, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: strings.Repeat("3", 64)}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: strings.Repeat("4", 64), ComponentsSHA256: componentAsset.SHA256, InstallPath: softwarelifecycle.ReleaseInstallPath(identity), StateSchema: 2}
	return softwareubuntu.InstallHandoffRequest{
		Schema: 1, Session: strings.Repeat("a", 64), Tag: identity.Tag, Architecture: softwarelifecycle.AMD64,
		Draft:               softwarelifecycle.InstallationDraft{Domain: "example.com", OwnerEmail: "owner@example.com", PublicIPv4: "192.0.2.10", PrimaryAddress: "192.0.2.10", SSHPort: 22, RealityPort: 443, Hysteria2Port: 443, TUICPort: 8443, AnyTLSPort: 9443, SubscriptionPort: 10443},
		CloudflareAccountID: strings.Repeat("b", 32), CloudflareZoneID: strings.Repeat("c", 32), CloudflareToken: "cfat_COMPOSED-INSTALL-SECRET-MARKER-000000000", RealityTarget: "www.microsoft.com:443", RealityServerName: "www.microsoft.com", Entropy: bytes.Repeat([]byte{0x42}, 32),
		Candidate: softwarelifecycle.InstallCandidateHandoff{Verified: verified, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components},
	}
}

type composedNetworkObserver struct{}

func (composedNetworkObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return networkpolicy.Observations{
		Host:       networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 22, ServerAddress: "192.0.2.10", CurrentSessions: []string{strings.Repeat("6", 64)}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: request.Stage == networkpolicy.PostApproval}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com"}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
		ReclamationComplete: true,
	}, nil
}

type countingInstallationObserver struct{ calls int }

func (observer *countingInstallationObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observer.calls++
	return (composedNetworkObserver{}).Observe(request)
}

type incompleteReclamationObserver struct{ composedNetworkObserver }

func (incompleteReclamationObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Reclamation.Docker = &networkpolicy.DockerConflict{Service: "docker.service", Status: "unknown"}
	observed.ReclamationComplete = false
	return observed, err
}

type composedReclamationObserver struct{ composedNetworkObserver }

func (composedReclamationObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Listeners = append(observed.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "standalone-proxy", Executable: "/opt/standalone/proxy", ProcessID: "4242"})
	observed.Reclamation.Executables = []networkpolicy.FileConflict{{Path: "/opt/standalone/proxy", SHA256: strings.Repeat("9", 64), Process: "standalone-proxy", ProcessID: "4242", Mode: 0o755, Links: 1}}
	observed.Reclamation.Identities = []networkpolicy.IdentityConflict{{Name: "proxy", Kind: "service user", Exclusive: true}}
	return observed, err
}

type composedScriptObserver struct{ composedNetworkObserver }

func (composedScriptObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Listeners = append(observed.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "python3", Executable: "/usr/bin/python3", ProcessID: "4242"})
	observed.Reclamation.Scripts = []networkpolicy.ScriptConflict{{Interpreter: "/usr/bin/python3", Path: "/opt/proxy/server.py", SHA256: strings.Repeat("8", 64), Process: "python3", ProcessID: "4242", Regular: true, Links: 1}}
	return observed, err
}

type composedPackageObserver struct{ composedNetworkObserver }

func (composedPackageObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Listeners = append(observed.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "xray", Service: "xray.service", Executable: "/opt/xray/proxy", ProcessID: "4242"})
	observed.ServiceIdentities = []string{"xray.service"}
	observed.ResourcePaths = []string{"/opt/xray/proxy"}
	observed.Reclamation.Packages = []networkpolicy.PackageConflict{{Name: "xray", Version: "1.2.3", Owns: "/opt/xray/proxy", OwnedPaths: []string{"/opt/xray/proxy"}}}
	observed.Reclamation.Executables = []networkpolicy.FileConflict{{Path: "/opt/xray/proxy", SHA256: strings.Repeat("7", 64), Process: "xray", Service: "xray.service", ProcessID: "4242", Package: "xray", Mode: 0o755, Links: 1}}
	return observed, err
}

type composedDockerObserver struct{ composedNetworkObserver }

func (composedDockerObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Firewall.ActiveManager = "docker.service"
	observed.Firewall.UnexpectedRule = "Docker FORWARD integration"
	observed.Reclamation.Docker = &networkpolicy.DockerConflict{
		Service: "docker.service", Status: "active", ServiceExecutable: "/usr/bin/dockerd", ServiceSHA256: strings.Repeat("d", 64), ProcessID: "4242", FirewallSHA256: strings.Repeat("f", 64),
		Packages:        []networkpolicy.PackageConflict{{Name: "docker.io", Version: "26.1.3", Owns: "/usr/bin/dockerd", ControlSHA256: strings.Repeat("c", 64), OwnedPaths: []string{"/usr/bin/dockerd", "/usr/lib/systemd/system/docker.service"}}},
		RuntimePackages: []networkpolicy.PackageConflict{{Name: "containerd", Version: "1.7.24", Owns: "/usr/bin/containerd", OwnedPaths: []string{"/usr/bin/containerd", "/usr/lib/systemd/system/containerd.service"}}},
		PreservedData:   []string{"images", "volumes", "Compose definitions", "bind mounts", "container configuration", "application data"},
		PreservedPaths:  []string{"/var/lib/docker", "/etc/docker"}, PreservedSHA256: []string{strings.Repeat("1", 64), strings.Repeat("2", 64)},
		FirewallObjects: []string{`{"chain":{"family":"ip","name":"DOCKER","table":"filter"}}`},
	}
	return observed, err
}

type composedFirewallObserver struct{ composedNetworkObserver }

func (composedFirewallObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Firewall.ActiveManager = "ufw.service"
	observed.Firewall.RootVerified = true
	observed.Firewall.UnexpectedRule = `manager "ufw"; table "filter"; chain "input"`
	observed.Reclamation.Firewall = &networkpolicy.FirewallConflict{Manager: "ufw.service", SHA256: strings.Repeat("f", 64), OutboundSHA256: strings.Repeat("d", 64), Objects: []string{`{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","prio":0,"policy":"accept"}}`}}
	observed.SSH.Service = "ssh.service"
	observed.SSH.Listener = "0.0.0.0:22/tcp"
	observed.SSH.AuthorizedKeysPath = "/root/.ssh/authorized_keys"
	observed.SSH.AuthorizedKeysSHA256 = strings.Repeat("e", 64)
	return observed, err
}

type composedConflictAPI struct{ composedCloudflareAPI }

func (composedConflictAPI) ObserveMutation(_ context.Context, request cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{
		Digest:     strings.Repeat("e", 64),
		Tunnels:    []cloudflaretunnel.OwnedResource{{ID: "11111111-1111-4111-8111-111111111111", Name: "sbxr-main"}},
		DNSRecords: []cloudflaretunnel.OwnedResource{{ID: strings.Repeat("d", 32), Name: request.Hostname}},
		Routes:     []cloudflaretunnel.Route{{Hostname: "xhttp.example.com", Service: "http://127.0.0.1:11080"}, {Service: "http_status:404"}},
	}, nil
}

type composedHeldPackageObserver struct{ composedNetworkObserver }

func (composedHeldPackageObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Listeners = append(observed.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "vendor-proxy", Service: "vendor-proxy.service", Executable: "/opt/vendor-proxy/proxy", ProcessID: "4242"})
	observed.ServiceIdentities = []string{"vendor-proxy.service"}
	observed.ResourcePaths = []string{"/opt/vendor-proxy/proxy"}
	observed.Reclamation.Packages = []networkpolicy.PackageConflict{{Name: "vendor-proxy", Version: "4.5.6", Owns: "/opt/vendor-proxy/proxy", OwnedPaths: []string{"/opt/vendor-proxy/proxy"}}}
	observed.Reclamation.Executables = []networkpolicy.FileConflict{{Path: "/opt/vendor-proxy/proxy", SHA256: strings.Repeat("9", 64), Process: "vendor-proxy", Service: "vendor-proxy.service", ProcessID: "4242", Package: "vendor-proxy", Mode: 0o755, Links: 1}}
	return observed, err
}

type composedCloudflareAPI struct{}

func (composedCloudflareAPI) Observe(context.Context, cloudflaretunnel.ObservationRequest) (cloudflaretunnel.Observation, error) {
	account, zone := strings.Repeat("b", 32), strings.Repeat("c", 32)
	return cloudflaretunnel.Observation{Account: cloudflaretunnel.AccountObservation{ID: account}, Zone: cloudflaretunnel.ZoneObservation{ID: zone, AccountID: account, Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: cloudflaretunnel.TokenObservation{ID: strings.Repeat("d", 32), Status: "active"}, Policies: []cloudflaretunnel.TokenPolicy{{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + account: "*"}}, {Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + zone: "*"}}}}, nil
}

func (composedCloudflareAPI) ObserveMutation(context.Context, cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	return cloudflaretunnel.MutationObservation{Digest: strings.Repeat("e", 64)}, nil
}

type composedClock struct{}

func (composedClock) Now() time.Time                             { return time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC) }
func (composedClock) Sleep(context.Context, time.Duration) error { return nil }

type absentInstallState struct{}

func (absentInstallState) Read() ([]byte, error) { return nil, fs.ErrNotExist }
func (absentInstallState) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("unexpected publication")
}
