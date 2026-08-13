package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestComposedInstallBuildsAndPreparesTheCompleteRevisionOnePlan(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	cloudflareModule := cloudflaretunnel.New(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedNetworkObserver{})
	built, err := buildInstallWith(t.Context(), request, installBuildDependencies{
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

func TestDestructiveReclamationCompositionBindsAllOwningModulesToOneChangeSet(t *testing.T) {
	request := composedInstallRequest(t)
	cloudflareAPI := composedCloudflareAPI{}
	built, err := buildInstallWith(t.Context(), request, installBuildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network:    networkpolicy.New(composedNetworkObserver{}).Evaluate,
		cloudflare: cloudflaretunnel.New(cloudflareAPI, composedClock{}).Plan,
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
	_, err := buildInstallWith(t.Context(), request, installBuildDependencies{
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
	cloudflareModule := cloudflaretunnel.New(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := installBuildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
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
	cloudflareModule := cloudflaretunnel.New(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := installBuildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
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
	confirmed := reclamationInstallReview(built, request, review.plan)
	if confirmed.Plan == nil || !slices.Contains(confirmed.Plan.Effects, "executable /opt/standalone/proxy sha256 "+strings.Repeat("9", 64)) || !slices.Contains(confirmed.Plan.Effects, "identity proxy kind service user exclusive true") {
		t.Fatalf("confirmed reclamation Plan lost exact effects: %+v", confirmed.Plan)
	}
	for _, effect := range installPlanEffects() {
		if !slices.Contains(confirmed.Plan.Effects, effect) {
			t.Fatalf("confirmed reclamation Plan lost install effect %q: %+v", effect, confirmed.Plan)
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

func TestDestructiveReclamationCompositionRefusesAnUnrenderableExactPlan(t *testing.T) {
	plan := &networkpolicy.ReclamationPlan{Digest: strings.Repeat("9", 64), Targets: make([]string, 65)}
	for index := range plan.Targets {
		plan.Targets[index] = fmt.Sprintf("exact firewall fact %d", index)
	}
	review := reclamationReview(plan, false)
	if review.Correction == nil || review.Correction.Evidence != "INSTALL-RECLAMATION-PLAN-TOO-LARGE" || !slices.Equal(review.Correction.Selections, []ownerconsole.CorrectionSelection{{Identity: "firewall-simplified", Label: "The firewall policy is now simpler"}}) {
		t.Fatalf("large exact Plan = %+v", review)
	}
}

func TestDestructiveReclamationCompositionReportsApplyCancellationFailureAndManagedCompletion(t *testing.T) {
	request := composedInstallRequest(t)
	built := composedBuiltInstall(t, request, composedNetworkObserver{}, composedCloudflareAPI{})
	for _, test := range []struct {
		name     string
		terminal softwareubuntu.InstallApplyOutcome
		err      error
		want     ownerconsole.ChangeSetStatus
	}{
		{name: "Managed completion", terminal: softwareubuntu.InstallCompleted, want: ownerconsole.ChangeSetSucceeded},
		{name: "safe rollback", terminal: softwareubuntu.InstallRolledBack, want: ownerconsole.ChangeSetRolledBack},
		{name: "terminal loss", err: errors.New("worker ended"), want: ownerconsole.ChangeSetRecoveryRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome := &installOutcome{values: map[string]string{}, request: request, built: built}
			outcome.launch = func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
				return test.terminal, test.err
			}
			if got := outcome.Apply(t.Context(), ownerconsole.PlanIdentity(built.plan.Identity())); got.Kind != ownerconsole.ChangeStarted {
				t.Fatalf("Apply() = %+v", got)
			}
			for deadline := time.Now().Add(time.Second); outcome.Inspect(t.Context()).Kind == ownerconsole.ChangeSetActive && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
			if got := outcome.Inspect(t.Context()); got.Kind != test.want {
				t.Fatalf("terminal result = %+v", got)
			}
		})
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	outcome := &installOutcome{values: map[string]string{}, request: request, built: built, launch: func(_ context.Context, _ softwareubuntu.InstallHandoffRequest, cancellation <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
		once.Do(func() { close(started) })
		<-cancellation
		close(release)
		return softwareubuntu.InstallRolledBack, nil
	}}
	if got := outcome.Apply(t.Context(), ownerconsole.PlanIdentity(built.plan.Identity())); got.Kind != ownerconsole.ChangeStarted {
		t.Fatalf("Apply() = %+v", got)
	}
	<-started
	operation := outcome.Inspect(t.Context()).OperationID
	if got := outcome.RequestCancellation(t.Context(), operation); got.Kind != ownerconsole.ChangeCancellationRequested {
		t.Fatalf("RequestCancellation() = %+v", got)
	}
	<-release
	if got := outcome.Apply(t.Context(), "changed-plan"); got.Kind != ownerconsole.ChangePlanRejected {
		t.Fatalf("stale review = %+v", got)
	}
}

type composedPlanAPI interface {
	cloudflaretunnel.API
	cloudflaretunnel.MutationPlanner
}

func composedBuiltInstall(t *testing.T, request softwareubuntu.InstallHandoffRequest, observer networkpolicy.Adapter, api composedPlanAPI) *builtInstall {
	t.Helper()
	built, err := buildInstallWith(t.Context(), request, installBuildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(observer).Evaluate, cloudflare: cloudflaretunnel.New(api, composedClock{}).Plan,
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

func composedInstallDependencies(request softwareubuntu.InstallHandoffRequest, observer networkpolicy.Adapter, api composedPlanAPI) installBuildDependencies {
	return installBuildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(observer).Evaluate, cloudflare: cloudflaretunnel.New(api, composedClock{}).Plan,
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
	cloudflareModule := cloudflaretunnel.New(cloudflareAPI, composedClock{})
	networkModule := networkpolicy.New(composedHeldPackageObserver{})
	dependencies := installBuildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
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
	_, err := buildInstallWith(t.Context(), request, installBuildDependencies{
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
