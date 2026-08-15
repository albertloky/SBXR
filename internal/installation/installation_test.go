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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
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

type rootRuntimeInstallApproval struct {
	recheck softwarelifecycle.InstallRecheck
}

func (approval rootRuntimeInstallApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.InstallRecheck, error) {
	return approval.recheck, nil
}

func TestInstallationInterfaceOwnsRootRuntimeTransactionOutcomes(t *testing.T) {
	for index, test := range []struct {
		name        string
		failPost    bool
		failReverse bool
		want        OperationStatus
	}{
		{name: "Managed", want: Completed},
		{name: "rollback to Not installed", failPost: true, want: RolledBack},
		{name: "Recovery Required", failPost: true, failReverse: true, want: RecoveryRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			var adapter *runtimeArtifactTransactionAdapter
			var launchErr error
			var transaction systemchanges.ApplyResult
			module := newTestInstallation(t, composedNetworkObserver{}, func(ctx context.Context, request softwareubuntu.InstallHandoffRequest, _ <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
				api := runtimeCloudflareAPI{}
				built, err := buildInstallWith(ctx, request, buildDependencies{
					stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
						return request.Candidate.Staged, nil
					},
					network: networkpolicy.New(composedNetworkObserver{}).Evaluate, cloudflare: newCloudflareTestModule(api, composedClock{}).Plan,
					random: newInstallEntropyReader(request.Entropy), cloudflareAPI: api, inventory: api,
				})
				if err != nil {
					launchErr = err
					return 0, err
				}
				prepared, err := built.prepareState(state.New(&publishingInstallState{}))
				if err != nil {
					launchErr = err
					return 0, err
				}
				recheck, volatile, err := recheckInstall(ctx, request, built)
				if err != nil {
					launchErr = err
					return 0, err
				}
				cloudflareExecutor, err := built.cloudflare.Executor(api)
				if err != nil {
					launchErr = err
					return 0, err
				}
				adapter = &runtimeArtifactTransactionAdapter{cloudflare: &cloudflareExecutor, failPost: test.failPost, failReverse: test.failReverse, observation: systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: volatile, FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}}
				result := built.plan.Apply(ctx, softwarelifecycle.InstallApplyRequest{Approval: rootRuntimeInstallApproval{recheck: recheck}, PreparedState: prepared, SystemChanges: systemchanges.New(adapter)})
				transaction = result
				switch result.Outcome {
				case systemchanges.Completed:
					return softwareubuntu.InstallCompleted, nil
				case systemchanges.RollbackSucceeded:
					return softwareubuntu.InstallRolledBack, nil
				default:
					return 0, fmt.Errorf("System Changes outcome %s", result.Outcome)
				}
			})
			module.dependencies.Entropy = bytes.NewReader(bytes.Repeat([]byte{byte(0x50 + index)}, 4096))
			review := module.Review(t.Context(), composedDraft(t))
			if review.Plan == nil {
				t.Fatalf("Review = %+v", review)
			}
			started := module.Apply(t.Context(), review.Approval)
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				operation, err := module.Inspect(t.Context(), started.Operation)
				if err == nil && operation.Status != OperationActive {
					if operation.Status != test.want || adapter == nil {
						reversed := 0
						var executed []string
						if adapter != nil {
							reversed = adapter.reversed
							executed = adapter.executed
						}
						t.Fatalf("Installation outcome = %+v, adapter=%t, reversed=%d, executed=%v, launch error=%v, transaction=%+v", operation, adapter != nil, reversed, executed, launchErr, transaction)
					}
					if test.want == Completed {
						for _, owner := range []systemchanges.Module{systemchanges.SoftwareModule, systemchanges.NetworkPolicyModule, systemchanges.ConnectionProfilesModule, systemchanges.CloudflareModule, systemchanges.CertificateModule, systemchanges.SubscriptionModule} {
							if !adapter.checked[owner][systemchanges.PrePublication] || !adapter.checked[owner][systemchanges.PostPublication] {
								t.Fatalf("Managed omitted Required %s gates: %+v", owner, adapter.checked)
							}
						}
					}
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("Installation outcome unavailable")
		})
	}
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
	cloudflare  *cloudflaretunnel.Executor
	evidence    []systemchanges.StepEvidence
	checked     map[systemchanges.Module]map[systemchanges.GatePhase]bool
	failPost    bool
	failReverse bool
	reversed    int
	executed    []string
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
func (adapter *runtimeArtifactTransactionAdapter) ReplaceStateArtifacts(_ systemchanges.ExecutionLease, changeSet string, binding systemchanges.StateTransactionBinding, stream func(func(string, uint32, io.Reader) error) error) error {
	if binding.ChangeSet != changeSet {
		return errors.New("final State binding mismatch")
	}
	for name := range adapter.artifacts {
		if strings.HasPrefix(name, "prepared/") {
			delete(adapter.artifacts, name)
		}
	}
	return stream(func(name string, _ uint32, source io.Reader) error {
		body, err := io.ReadAll(source)
		adapter.artifacts[name] = body
		return err
	})
}
func (*runtimeArtifactTransactionAdapter) Record(systemchanges.ExecutionLease, systemchanges.CheckpointRecord) error {
	return nil
}

func (adapter *runtimeArtifactTransactionAdapter) Execute(_ systemchanges.ExecutionLease, _ string, number int, step systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	adapter.executed = append(adapter.executed, fmt.Sprintf("%d:%s:%s", number, step.Owner(), step.Forward()))
	adapter.artifacts["active/xray.json"] = append([]byte(nil), adapter.artifacts["prepared/xray.json"]...)
	adapter.artifacts["active/sing-box.json"] = append([]byte(nil), adapter.artifacts["prepared/sing-box.json"]...)
	adapter.artifacts["active/cloudflared.json"] = append([]byte(nil), adapter.artifacts["prepared/cloudflared.json"]...)
	adapter.artifacts["active/subscription.json"] = append([]byte(nil), adapter.artifacts["prepared/subscription.json"]...)
	if change, ok := step.CloudflareChange(); ok && adapter.cloudflare != nil {
		resolved := ""
		if change.TunnelIDFromStep > 0 && change.TunnelIDFromStep <= len(adapter.evidence) {
			resolved = adapter.evidence[change.TunnelIDFromStep-1].ResourceID
		}
		evidence, err := adapter.cloudflare.Execute(step, resolved, time.Second)
		adapter.evidence = append(adapter.evidence, evidence)
		return evidence, err
	}
	if change, ok := step.CloudflareChange(); ok {
		evidence := systemchanges.StepEvidence{Code: "root-runtime-applied", SHA256: strings.Repeat("a", 64), ResourceID: fmt.Sprintf("resource-%d", number)}
		switch change.Action {
		case systemchanges.CloudflareTunnelCreate:
			evidence.ResourceType = string(systemchanges.CloudflareTunnelResource)
			evidence.ResourceID = "550e8400-e29b-41d4-a716-446655440001"
		case systemchanges.CloudflareRoutesPut:
			evidence.ResourceType = string(systemchanges.CloudflareRouteResource)
		case systemchanges.CloudflareDNSCreate:
			evidence.ResourceType = string(systemchanges.CloudflareDNSRecordResource)
		}
		adapter.evidence = append(adapter.evidence, evidence)
		return evidence, nil
	}
	evidence := systemchanges.StepEvidence{Code: "root-runtime-applied", SHA256: strings.Repeat("a", 64)}
	adapter.evidence = append(adapter.evidence, evidence)
	return evidence, nil
}
func (adapter *runtimeArtifactTransactionAdapter) Reverse(systemchanges.ExecutionLease, string, int, systemchanges.Step, time.Duration) (systemchanges.StepEvidence, error) {
	adapter.reversed++
	if adapter.failReverse {
		return systemchanges.StepEvidence{}, errors.New("controlled rollback failure")
	}
	return systemchanges.StepEvidence{Code: "root-runtime-restored", SHA256: strings.Repeat("b", 64)}, nil
}
func (adapter *runtimeArtifactTransactionAdapter) Check(_ systemchanges.ExecutionLease, check systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	if adapter.checked == nil {
		adapter.checked = map[systemchanges.Module]map[systemchanges.GatePhase]bool{}
	}
	if adapter.checked[check.Owner] == nil {
		adapter.checked[check.Owner] = map[systemchanges.GatePhase]bool{}
	}
	if check.Classification == systemchanges.Required {
		adapter.checked[check.Owner][phase] = true
	}
	if adapter.failPost && phase == systemchanges.PostPublication {
		adapter.artifacts["active/cloudflared.json"] = []byte(`{"routes":[]}`)
	}
	var manifests struct {
		Xray         *state.ServiceManifest `json:"xray"`
		SingBox      *state.ServiceManifest `json:"sing_box"`
		Cloudflared  *state.ServiceManifest `json:"cloudflared"`
		Subscription *state.ServiceManifest `json:"subscription"`
	}
	if err := json.Unmarshal(adapter.artifacts["prepared/manifests.json"], &manifests); err != nil || manifests.Xray == nil || manifests.SingBox == nil || manifests.Cloudflared == nil || manifests.Subscription == nil {
		return systemchanges.Unknown, err
	}
	for _, manifest := range []*state.ServiceManifest{manifests.Xray, manifests.SingBox, manifests.Cloudflared, manifests.Subscription} {
		if manifest.Owner != "root" || manifest.Group != "root" || manifest.DirectoryMode != 0o755 || manifest.FileMode != 0o644 {
			return systemchanges.Failed, nil
		}
	}
	for name, expected := range map[string]string{"active/xray.json": manifests.Xray.SHA256, "active/sing-box.json": manifests.SingBox.SHA256, "active/cloudflared.json": manifests.Cloudflared.SHA256, "active/subscription.json": manifests.Subscription.SHA256} {
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
		string(softwarelifecycle.NetworkInstallContribution):      true,
		string(softwarelifecycle.ProfilesInstallContribution):     true,
		string(softwarelifecycle.CloudflareInstallContribution):   true,
		"Certificate Lifecycle":                                   true,
		string(softwarelifecycle.SubscriptionInstallContribution): true,
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
	if result.Invalid == nil || result.Invalid.Field != "domain" || result.Plan != nil || result.Reclamation != nil {
		t.Fatalf("invalid Draft = %+v", result)
	}
}

func TestInstallationReviewSuppliesDomainHelpAndRejectsItsExample(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	review := module.Review(t.Context(), Draft{})
	want := FieldHelp{
		Purpose:        "Choose SBXR's public domain.",
		Instructions:   []string{"Enter your Cloudflare domain."},
		AcceptedFormat: "Lowercase DNS name only.",
		CommonMistakes: []string{"No URL, port, or final dot."},
		Recovery:       "Correct it; prior values remain.",
		Example:        "vpn.example",
		URL:            "https://developers.cloudflare.com/fundamentals/manage-domains/add-site/",
		Sensitivity:    PublicInformation,
	}
	if review.Invalid == nil || !reflect.DeepEqual(review.Invalid.Help, want) {
		t.Fatalf("Domain Help = %+v", review.Invalid)
	}
	review = module.Review(t.Context(), Draft{SubmittedField: "domain", SubmittedValue: want.Example})
	if review.Invalid == nil || review.Invalid.Field != "domain" || review.Plan != nil || !strings.Contains(review.Invalid.Problem, "tutorial") {
		t.Fatalf("tutorial Domain Review = %+v", review)
	}
}

func TestInstallationReviewGuidesEveryFirstInstallationFieldAndRejectsTutorialValues(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	complete := composedDraft(t)
	type expectedHelp struct {
		purpose, malformed, example, url string
		sensitivity                      FieldSensitivity
	}
	want := map[string]expectedHelp{
		"domain":             {"public domain", "https://bad", "vpn.example", "https://developers.cloudflare.com/fundamentals/manage-domains/add-site/", PublicInformation},
		"owner-email":        {"ACME account", "owner", "owner@sbxr.example", "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options", PersonalInformation},
		"public-ipv4":        {"public IPv4", "999.1.1.1", "192.0.2.10", "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml", PublicInformation},
		"reality-port":       {"REALITY", "not-a-port", "10444", "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", PublicInformation},
		"hysteria2-port":     {"Hysteria2", "not-a-port", "10445", "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", PublicInformation},
		"tuic-port":          {"TUIC", "not-a-port", "10446", "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", PublicInformation},
		"anytls-port":        {"AnyTLS", "not-a-port", "10447", "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", PublicInformation},
		"subscription-port":  {"Subscription HTTPS", "not-a-port", "10448", "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml", PublicInformation},
		"cloudflare-account": {"Cloudflare account", "not-an-id", "11111111111111111111111111111111", "https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/", PublicInformation},
		"cloudflare-zone":    {"Cloudflare domain", "not-an-id", "22222222222222222222222222222222", "https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/", PublicInformation},
		"cloudflare-token":   {"Cloudflare work", "user-token", "", "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/", InfrastructureSecret},
		"reality-target":     {"REALITY Vision", "https://bad", "target.example", "https://xtls.github.io/en/config/transport.html#realityobject", PublicInformation},
	}
	placeholder := map[string]string{
		"domain":           "placeholder",
		"owner-email":      "owner@your-domain",
		"cloudflare-token": "cfat_placeholder________________________________",
		"reality-target":   "your-hostname",
	}
	steps := []struct{ field, valid string }{
		{"domain", complete.Installation.Domain},
		{"owner-email", complete.Installation.OwnerEmail},
		{"public-ipv4", complete.Installation.PublicIPv4},
		{"reality-port", "443"},
		{"hysteria2-port", "443"},
		{"tuic-port", "8443"},
		{"anytls-port", "9443"},
		{"subscription-port", "10443"},
		{"cloudflare-account", complete.CloudflareAccountID},
		{"cloudflare-zone", complete.CloudflareZoneID},
		{"cloudflare-token", complete.CloudflareToken},
		{"reality-target", complete.RealityServerName},
	}
	for _, step := range steps {
		review := module.Review(t.Context(), Draft{})
		if review.Invalid == nil || review.Invalid.Field != step.field {
			t.Fatalf("%s initial Review = %+v", step.field, review)
		}
		expected, guided := want[step.field]
		if guided {
			help := review.Invalid.Help
			if !strings.Contains(help.Purpose, expected.purpose) || len(help.Instructions) == 0 || help.AcceptedFormat == "" || len(help.CommonMistakes) == 0 || help.Recovery == "" || help.Example != expected.example || help.URL != expected.url || help.Sensitivity != expected.sensitivity {
				t.Fatalf("%s Help = %+v", step.field, help)
			}
			for _, submitted := range []string{expected.malformed, expected.example} {
				if submitted == "" {
					continue
				}
				rejected := module.Review(t.Context(), Draft{SubmittedField: step.field, SubmittedValue: submitted})
				if rejected.Invalid == nil || rejected.Invalid.Field != step.field || rejected.Plan != nil || rejected.Invalid.Help.Recovery == "" {
					t.Fatalf("%s accepted %q or lost field Help: %+v", step.field, submitted, rejected)
				}
				if submitted == expected.example && !strings.Contains(rejected.Invalid.Problem, "tutorial") {
					t.Fatalf("%s tutorial rejection = %+v", step.field, rejected.Invalid)
				}
			}
			if submitted := placeholder[step.field]; submitted != "" {
				rejected := module.Review(t.Context(), Draft{SubmittedField: step.field, SubmittedValue: submitted})
				if rejected.Invalid == nil || rejected.Invalid.Field != step.field || rejected.Plan != nil {
					t.Fatalf("%s placeholder rejection = %+v", step.field, rejected)
				}
			}
			if step.field == "hysteria2-port" {
				if !slices.ContainsFunc(review.Invalid.Facts, func(fact ReviewFact) bool {
					return fact.Label == "Primary subscription address" && fact.Value == complete.Installation.PublicIPv4
				}) {
					t.Fatalf("derived Primary subscription address is not a read-only fact: %+v", review.Invalid.Facts)
				}
			}
		}
		review = module.Review(t.Context(), Draft{SubmittedField: step.field, SubmittedValue: step.valid})
		if step.field == "reality-target" && review.Plan == nil {
			t.Fatalf("complete guided journey = %+v", review)
		}
		if step.field == "reality-target" && !slices.ContainsFunc(review.Plan.Effects, func(effect string) bool {
			return strings.Contains(effect, "Primary subscription address") && strings.Contains(effect, complete.Installation.PublicIPv4) && strings.Contains(effect, "server name "+complete.RealityServerName)
		}) {
			t.Fatalf("derived values are not visible in the read-only Plan: %+v", review.Plan.Effects)
		}
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
	if result := module.Review(t.Context(), DiscardDraft()); result.Invalid == nil || result.Invalid.Field != "domain" {
		t.Fatalf("discard retained partial draft = %+v", result)
	}
}

func TestInstallationReviewOwnsFirstDraftDefaultsAndProgression(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	complete := composedDraft(t)
	fields := []struct {
		identity string
		update   Draft
		want     string
	}{
		{"domain", Draft{SubmittedField: "domain", Installation: softwarelifecycle.InstallationDraft{Domain: complete.Installation.Domain}}, ""},
		{"owner-email", Draft{SubmittedField: "owner-email", Installation: softwarelifecycle.InstallationDraft{OwnerEmail: complete.Installation.OwnerEmail}}, ""},
		{"public-ipv4", Draft{SubmittedField: "public-ipv4", Installation: softwarelifecycle.InstallationDraft{PublicIPv4: complete.Installation.PublicIPv4}}, complete.Installation.PublicIPv4},
		{"reality-port", Draft{SubmittedField: "reality-port", Installation: softwarelifecycle.InstallationDraft{RealityPort: 443}}, "443"},
		{"hysteria2-port", Draft{SubmittedField: "hysteria2-port", Installation: softwarelifecycle.InstallationDraft{Hysteria2Port: 443}}, "443"},
		{"tuic-port", Draft{SubmittedField: "tuic-port", Installation: softwarelifecycle.InstallationDraft{TUICPort: 8443}}, "8443"},
		{"anytls-port", Draft{SubmittedField: "anytls-port", Installation: softwarelifecycle.InstallationDraft{AnyTLSPort: 9443}}, "9443"},
		{"subscription-port", Draft{SubmittedField: "subscription-port", Installation: softwarelifecycle.InstallationDraft{SubscriptionPort: 10443}}, "10443"},
		{"cloudflare-account", Draft{SubmittedField: "cloudflare-account", CloudflareAccountID: complete.CloudflareAccountID}, ""},
		{"cloudflare-zone", Draft{SubmittedField: "cloudflare-zone", CloudflareZoneID: complete.CloudflareZoneID}, ""},
		{"cloudflare-token", Draft{SubmittedField: "cloudflare-token", CloudflareToken: complete.CloudflareToken}, ""},
		{"reality-target", Draft{SubmittedField: "reality-target", SubmittedValue: complete.RealityServerName}, ""},
	}
	for _, field := range fields {
		review := module.Review(t.Context(), Draft{})
		if review.Invalid == nil || review.Invalid.Field != field.identity || review.Invalid.Value != field.want {
			t.Fatalf("next field before %s = %+v", field.identity, review)
		}
		if len(review.Invalid.Facts) < 2 || review.Invalid.Facts[0] != (ReviewFact{Label: "Running release tag", Value: complete.Tag}) || review.Invalid.Facts[1] != (ReviewFact{Label: "Active SSH port", Value: "22"}) {
			t.Fatalf("read-only Installation facts = %+v", review.Invalid.Facts)
		}
		if field.identity == "public-ipv4" && !review.Invalid.Detected {
			t.Fatalf("proven Public IPv4 was not marked detected: %+v", review.Invalid)
		}
		review = module.Review(t.Context(), field.update)
		if field.identity == "reality-target" && review.Plan == nil {
			t.Fatalf("complete default journey = %+v", review)
		}
	}
}

func TestInstallationReviewGuidesUnprovedAndAmbiguousNetworkFacts(t *testing.T) {
	for _, test := range []struct {
		name      string
		preflight networkpolicy.InstallationPreflightResult
		wantValue string
	}{
		{name: "zero public IPv4 candidates", preflight: networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222}},
		{name: "multiple public IPv4 candidates", preflight: networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222, UsablePublicIPv4: []string{"1.1.1.1", "9.9.9.9"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, test.preflight)
			if review := module.Review(t.Context(), Draft{}); review.Invalid == nil || review.Invalid.Field != "domain" || len(review.Invalid.Facts) < 2 || review.Invalid.Facts[1] != (ReviewFact{Label: "Active SSH port", Value: "2222"}) {
				t.Fatalf("initial Review = %+v", review)
			}
			if review := module.Review(t.Context(), Draft{SubmittedField: "domain", SubmittedValue: "example.com"}); review.Invalid == nil || review.Invalid.Field != "owner-email" {
				t.Fatalf("Domain Review = %+v", review)
			}
			review := module.Review(t.Context(), Draft{SubmittedField: "owner-email", SubmittedValue: "owner@example.com"})
			if review.Invalid == nil || review.Invalid.Field != "public-ipv4" || review.Invalid.Value != test.wantValue || review.Invalid.Detected || len(review.Invalid.Facts) < 3 || review.Invalid.Facts[2].Label != "Public IPv4 guidance" {
				t.Fatalf("guided Public IPv4 Review = %+v", review)
			}
			module.Review(t.Context(), Draft{SubmittedField: "public-ipv4", SubmittedValue: "8.8.8.8"})
			if module.draft.Installation.PublicIPv4 != "8.8.8.8" || module.draft.Installation.PrimaryAddress != "8.8.8.8" || module.draft.Installation.SSHPort != 2222 {
				t.Fatalf("derived Installation network facts = %+v", module.draft.Installation)
			}
		})
	}

	finding := networkpolicy.Finding{Code: "NETWORK-INSTALLATION-SSH-UNPROVED", Problem: "The active SSH session could not be proved", Found: "no session", Required: "one active SSH session", WhyStopped: "SSH access cannot be preserved", Fix: networkpolicy.Fix{OwnerChecklist: []string{"Reconnect through SSH, then start Installation again."}}}
	module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{Failure: &finding})
	review := module.Review(t.Context(), Draft{})
	if review.Correction == nil || review.Correction.InputLabel != "" || len(review.Correction.OwnerSteps) != 1 || review.Invalid != nil {
		t.Fatalf("unproved SSH did not stop with exact recovery guidance: %+v", review)
	}
}

func TestInstallationReviewDerivesAndImmediatelyChecksOneRealityHostname(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	complete := composedDraft(t)
	for _, input := range []Draft{
		{SubmittedField: "domain", SubmittedValue: complete.Installation.Domain},
		{SubmittedField: "owner-email", SubmittedValue: complete.Installation.OwnerEmail},
		{SubmittedField: "public-ipv4", SubmittedValue: complete.Installation.PublicIPv4},
		{SubmittedField: "reality-port", SubmittedValue: "443"},
		{SubmittedField: "hysteria2-port", SubmittedValue: "443"},
		{SubmittedField: "tuic-port", SubmittedValue: "8443"},
		{SubmittedField: "anytls-port", SubmittedValue: "9443"},
		{SubmittedField: "subscription-port", SubmittedValue: "10443"},
		{SubmittedField: "cloudflare-account", SubmittedValue: complete.CloudflareAccountID},
		{SubmittedField: "cloudflare-zone", SubmittedValue: complete.CloudflareZoneID},
		{SubmittedField: "cloudflare-token", SubmittedValue: complete.CloudflareToken},
	} {
		module.Review(t.Context(), input)
	}

	var target connectionprofiles.RealityTarget
	for _, test := range []struct{ name, code, found string }{
		{name: "Cloudflare", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", found: "cloudflare-fronted"},
		{name: "Apple", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", found: "apple-or-icloud"},
		{name: "iCloud", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", found: "apple-or-icloud"},
		{name: "unknown", code: "CONNECTION-PROFILES-REALITY-TARGET-CLASS", found: "unknown"},
		{name: "invalid certificate", code: "CONNECTION-PROFILES-REALITY-CERTIFICATE", found: "certificate invalid"},
		{name: "mismatched name", code: "CONNECTION-PROFILES-REALITY-NAME", found: "other.example.net"},
		{name: "failed route", code: "CONNECTION-PROFILES-REALITY-ROUTE", found: "unproved"},
		{name: "failed probe", code: "CONNECTION-PROFILES-REALITY-PROBE", found: "failed"},
	} {
		module.dependencies.ReviewRealityTarget = func(_ context.Context, reviewed connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
			target = reviewed
			return connectionprofiles.RealityTargetReview{Target: reviewed, Health: connectionprofiles.Health{Outcome: connectionprofiles.Failed, Code: test.code, Problem: "The REALITY target is unsafe", Found: test.found, Required: "one ordinary target", WhyStopped: "Connection Profiles fails closed", BlockerOwner: connectionprofiles.ExternalBlocker, BlockerAction: "Enter one ordinary hostname, then Check again."}}
		}
		review := module.Review(t.Context(), Draft{SubmittedField: "reality-target", SubmittedValue: "edge.example.net"})
		if review.Invalid == nil || review.Invalid.Field != "reality-target" || review.Invalid.Value != "edge.example.net" || target.Address != "edge.example.net:443" || target.ServerName != "edge.example.net" || module.nextField != len(draftFields)-1 || module.draft.RealityTarget != "" || len(review.Invalid.Facts) < 4 || review.Invalid.Facts[len(review.Invalid.Facts)-2].Value != "Enter one ordinary hostname, then Check again." || !strings.Contains(review.Invalid.Facts[len(review.Invalid.Facts)-1].Value, test.code) {
			t.Fatalf("%s REALITY target Review = %+v, target = %+v, draft = %+v", test.name, review, target, module.draft)
		}
	}

	module.dependencies.ReviewRealityTarget = func(_ context.Context, reviewed connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
		return connectionprofiles.RealityTargetReview{Target: reviewed, Health: connectionprofiles.Health{Outcome: connectionprofiles.Healthy}}
	}
	review := module.Review(t.Context(), Draft{SubmittedField: "reality-target", SubmittedValue: "edge.example.net"})
	if review.Plan == nil || module.draft.RealityTarget != "edge.example.net:443" || module.draft.RealityServerName != "edge.example.net" {
		t.Fatalf("safe REALITY target Review = %+v, draft = %+v", review, module.draft)
	}
}

func TestInstallationReviewRejectsSpecialUseIPv4AndDerivesTheBatchPrimaryAddress(t *testing.T) {
	module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22})
	module.Review(t.Context(), Draft{SubmittedField: "domain", SubmittedValue: "example.com"})
	module.Review(t.Context(), Draft{SubmittedField: "owner-email", SubmittedValue: "owner@example.com"})
	review := module.Review(t.Context(), Draft{SubmittedField: "public-ipv4", SubmittedValue: "10.0.0.1"})
	if review.Invalid == nil || review.Invalid.Field != "public-ipv4" || module.draft.Installation.PrimaryAddress != "" {
		t.Fatalf("special-use Public IPv4 Review = %+v, draft = %+v", review, module.draft.Installation)
	}

	module = newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"1.1.1.1"}})
	review = module.Review(t.Context(), composedDraft(t))
	if review.Plan == nil || module.draft.Installation.PublicIPv4 != "8.8.8.8" || module.draft.Installation.PrimaryAddress != "8.8.8.8" {
		t.Fatalf("batch-derived Primary subscription address = %+v, draft = %+v", review, module.draft.Installation)
	}
}

func TestInstallationReviewShowsEveryExplicitPortReplacementInThePlan(t *testing.T) {
	module := newTestInstallationWithPreflight(t, replacementPortObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222, UsablePublicIPv4: []string{"8.8.8.8"}})
	draft := composedDraft(t)
	draft.Installation.SSHPort = 2222
	draft.Installation.RealityPort = 1443
	draft.Installation.Hysteria2Port = 2443
	draft.Installation.TUICPort = 38443
	draft.Installation.AnyTLSPort = 39443
	draft.Installation.SubscriptionPort = 40443
	review := module.Review(t.Context(), draft)
	if review.Plan == nil {
		t.Fatalf("replacement Review = %+v", review)
	}
	want := "Use SSH 2222/TCP, REALITY 1443/TCP, Hysteria2 2443/UDP, TUIC 38443/UDP, AnyTLS 39443/TCP, and Subscription HTTPS 40443/TCP"
	if !slices.Contains(review.Plan.Effects, want) {
		t.Fatalf("reviewed Plan omitted explicit replacements: %+v", review.Plan.Effects)
	}
}

func TestInstallationReviewKeepsTheRunningReleaseReadOnlyAfterCandidateFailure(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	calls := 0
	original := module.dependencies.ReleaseCandidate
	module.dependencies.ReleaseCandidate = func(ctx context.Context, tag string, architecture softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error) {
		calls++
		if calls == 1 {
			return softwarelifecycle.InstallCandidateHandoff{}, errors.New("release unavailable")
		}
		return original(ctx, tag, architecture)
	}
	review := module.Review(t.Context(), composedDraft(t))
	if review.Correction == nil || review.Correction.InputLabel != "" || review.Correction.FixWithSBXR || len(review.Correction.OwnerSteps) != 1 || review.Invalid != nil {
		t.Fatalf("running release failure became editable: %+v", review)
	}
	review = module.Review(t.Context(), Draft{})
	if review.Plan == nil {
		t.Fatalf("release retry lost the complete earlier draft: %+v", review)
	}
}

type replacementPortObserver struct{ composedNetworkObserver }

func (replacementPortObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.SSH.DetectedPort = 2222
	return observed, err
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
	if fresh := module.Review(t.Context(), Draft{}); fresh.Invalid == nil || fresh.Invalid.Field != "domain" {
		t.Fatalf("cancelled draft remained available: %+v", fresh)
	}
}

func TestInstallationInterfaceReviewsCleanVPSAndKeepsOneUseApprovalMemoryOnly(t *testing.T) {
	observer := &countingInstallationObserver{}
	module := newTestInstallation(t, observer, nil)
	review := module.Review(t.Context(), composedDraft(t))
	if review.Plan == nil || review.Plan.DesiredStateRevision != 1 || review.Approval.cell == nil {
		t.Fatalf("clean VPS Review = %+v", review)
	}
	for _, effect := range []string{
		"Run xray.service, sing-box.service, cloudflared.service, and sbxr-subscription.service as root:root without separate Linux identities",
		"Retain NoNewPrivileges=true, ProtectHome=true, ProtectSystem=strict, AmbientCapabilities=CAP_NET_BIND_SERVICE, and CapabilityBoundingSet=CAP_NET_BIND_SERVICE for Xray and sing-box",
		"Retain NoNewPrivileges=true, ProtectHome=true, ProtectSystem=strict, and PrivateTmp=true for cloudflared",
		"Retain UMask=0027, NoNewPrivileges=true, PrivateTmp=true, ProtectHome=true, ProtectSystem=strict, PrivateDevices=true, ProtectControlGroups=true, ProtectKernelModules=true, ProtectKernelTunables=true, ProtectProc=invisible, and ProcSubset=pid for Subscription Serving",
		"Retain RestrictAddressFamilies=AF_INET AF_INET6, RestrictSUIDSGID=true, LockPersonality=true, MemoryDenyWriteExecute=true, LimitCORE=0, TemporaryFileSystem=/:ro, BindReadOnlyPaths=/usr/local/bin/sbxr, BindReadOnlyPaths=/var/lib/sbxr/subscriptions/current, BindReadOnlyPaths=/var/lib/sbxr/certificates/ip/current, and BindReadOnlyPaths=/etc/ssl/certs/ca-certificates.crt for Subscription Serving",
		"Store runtime service configuration, proxy credentials, subscription material, the Cloudflare Tunnel run token, and TLS private keys as root:root 0644",
		"Every local Linux identity can read the runtime proxy credentials, subscription material, Cloudflare Tunnel run token, and TLS private keys",
	} {
		if !slices.Contains(review.Plan.Effects, effect) {
			t.Fatalf("root-runtime Plan omitted %q: %+v", effect, review.Plan.Effects)
		}
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

func TestReclamationConfirmationGuidanceOwnsTheExactDestructiveBoundary(t *testing.T) {
	guidance := ReclamationConfirmationGuidance()
	joined := strings.Join(guidance.Lines, " ")
	for _, want := range []string{"RECLAIM THIS VPS", "Reclamation Boundary", "without autoremove", "Protected Host Foundation", "SSH access", "Irreversible Reclamation Started", "forward recovery to Managed", "does not confirm"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("ReclamationConfirmationGuidance() omitted %q: %+v", want, guidance)
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
	request := composedInstallRequest(t)
	return newTestInstallationWith(t, observer, launch, networkpolicy.InstallationPreflightResult{ActiveSSHPort: request.Draft.SSHPort, UsablePublicIPv4: []string{request.Draft.PublicIPv4}})
}

func newTestInstallationWithPreflight(t *testing.T, observer networkpolicy.Adapter, preflight networkpolicy.InstallationPreflightResult) *Interface {
	return newTestInstallationWith(t, observer, nil, preflight)
}

func newTestInstallationWith(t *testing.T, observer networkpolicy.Adapter, launch func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error), preflight networkpolicy.InstallationPreflightResult) *Interface {
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
		Preflight: func() networkpolicy.InstallationPreflightResult { return preflight },
		ReviewRealityTarget: func(_ context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
			return connectionprofiles.RealityTargetReview{Target: target, Health: connectionprofiles.Health{Outcome: connectionprofiles.Healthy}}
		},
		RunningRelease: func() (RunningRelease, error) {
			return RunningRelease{Tag: request.Tag, Architecture: request.Architecture}, nil
		},
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

type runtimeCloudflareAPI struct{ interfaceTestAPI }

func (runtimeCloudflareAPI) CreateTunnel(context.Context, cloudflaretunnel.CreateTunnelRequest) (cloudflaretunnel.CreatedTunnel, error) {
	return cloudflaretunnel.NewCreatedTunnelResult("550e8400-e29b-41d4-a716-446655440001", "sbxr-main", "ROOT-RUNTIME-RUN-TOKEN")
}
func (runtimeCloudflareAPI) PutConfiguration(_ context.Context, request cloudflaretunnel.PutConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{TunnelID: request.TunnelID, Version: 1, Routes: append([]cloudflaretunnel.Route(nil), request.Routes...)}, nil
}
func (runtimeCloudflareAPI) CreateDNSRecord(_ context.Context, request cloudflaretunnel.CreateDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	identities := map[string]string{"xhttp.example.com": "dns-xhttp-root-runtime", "ws.example.com": "dns-websocket-root-runtime", "direct.example.com": "dns-direct-root-runtime"}
	return cloudflaretunnel.OwnedResource{ID: identities[request.Name], Name: request.Name}, nil
}

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
		Draft:               softwarelifecycle.InstallationDraft{Domain: "example.com", OwnerEmail: "owner@example.com", PublicIPv4: "8.8.8.8", PrimaryAddress: "8.8.8.8", SSHPort: 22, RealityPort: 443, Hysteria2Port: 443, TUICPort: 8443, AnyTLSPort: 9443, SubscriptionPort: 10443},
		CloudflareAccountID: strings.Repeat("b", 32), CloudflareZoneID: strings.Repeat("c", 32), CloudflareToken: "cfat_COMPOSED-INSTALL-SECRET-MARKER-000000000", RealityTarget: "www.microsoft.com:443", RealityServerName: "www.microsoft.com", Entropy: bytes.Repeat([]byte{0x42}, 32),
		Candidate: softwarelifecycle.InstallCandidateHandoff{Verified: verified, Staged: staged, ApplicationAsset: applicationAsset, ComponentAsset: componentAsset, ApplicationArchive: application, ComponentArchive: components},
	}
}

type composedNetworkObserver struct{}

func (composedNetworkObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return networkpolicy.Observations{
		Host:       networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{"8.8.8.8"}, SSH: networkpolicy.SSHFacts{DetectedPort: 22, ServerAddress: "8.8.8.8", CurrentSessions: []string{strings.Repeat("6", 64)}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: request.Stage == networkpolicy.PostApproval}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
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
