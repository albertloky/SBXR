package installation

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func newCloudflareTestModule(api cloudflaretunnel.API, clock cloudflaretunnel.Clock) cloudflaretunnel.Interface {
	return cloudflaretunnel.New(api, clock, func(context.Context, []byte) error { return nil })
}

func TestComposedInstallBuildsAndPreparesTheCompleteRevisionOnePlan(t *testing.T) {
	request := composedInstallRequest(t)
	request.Entropy = []byte("QUALIFICATION-SETUP-ENTROPY-00000000000000000008")
	networkModule := networkpolicy.New(composedNetworkObserver{})
	built, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkModule.Evaluate,
		random:  newInstallEntropyReader(request.Entropy),
	})
	if err != nil {
		t.Fatal(err)
	}
	summary := built.plan.Summary()
	if summary.Revision != 1 || summary.InstallationStatus != softwarelifecycle.NotInstalled || summary.Result != softwarelifecycle.Managed || len(summary.Units) != 11 || len(summary.Profiles) != 6 || len(summary.SubscriptionRepresentations) != 7 || len(summary.Certificates) != 1 || len(summary.Cloudflare) != 1 {
		t.Fatalf("incomplete composed install summary: %+v", summary)
	}
	if built.desired.Cloudflare != (state.CloudflareSettings{}) || built.desired.Certificates.DomainCertificateID != "" || built.desired.ConnectionProfiles.VLESSRealityVision.Lifecycle != state.ProfileEnabled || built.desired.ConnectionProfiles.VLESSXHTTP != (state.VLESSXHTTP{Lifecycle: state.ProfileNotSetUp}) || built.desired.ConnectionProfiles.AnyTLS != (state.AnyTLS{Lifecycle: state.ProfileNotSetUp}) {
		t.Fatalf("revision 1 contains deferred provider or profile facts: %+v", built.desired)
	}
	var contributionOrder []string
	for _, contribution := range built.contributions {
		contributionOrder = append(contributionOrder, contribution.SoftwareLifecycleInstallContribution().Name)
	}
	if got, want := strings.Join(contributionOrder, ","), "Network Policy,Connection Profiles,Subscription Publication,Certificate Lifecycle"; got != want {
		t.Fatalf("install contribution order = %s, want %s", got, want)
	}
	prepared, err := built.prepareState(state.New(absentInstallState{}))
	if err != nil || prepared == nil {
		t.Fatalf("prepareState() = (%+v, %v)", prepared, err)
	}
	rendered := fmt.Sprintf("%+v %+v %+v", built.plan, built.wiring, prepared)
	for _, marker := range []string{string(request.Entropy), hex.EncodeToString(request.Entropy), "COMPOSED-INSTALL-SECRET-MARKER"} {
		if strings.Contains(rendered, marker) {
			t.Fatalf("composed installation evidence exposed protected marker %q", marker)
		}
	}
	t.Log("RELEASE-STAGED-ONBOARDING-MARKER-SETUP-ENTROPY")
}

func TestInstallationCorrectionCarriesTypedFirewallFinding(t *testing.T) {
	productionNetwork := networkpolicy.New(composedFirewallObserver{}).Evaluate
	module := newTestInstallationWithNetwork(t, func(request networkpolicy.Request) networkpolicy.Result {
		result := productionNetwork(request)
		for _, finding := range result.Findings {
			if finding.Code == "NETWORK-FIREWALL-CONFLICT" {
				return networkpolicy.Result{Outcome: networkpolicy.Failed, Findings: []networkpolicy.Finding{finding}}
			}
		}
		t.Fatal("production-shaped firewall conflict finding unavailable")
		return networkpolicy.Result{}
	})

	review := module.Review(t.Context(), composedDraft(t))
	if review.Correction == nil {
		t.Fatalf("Installation review = %+v", review)
	}
	correction := review.Correction
	if correction.Problem != "A competing firewall owner or unexpected rule is active" || correction.Required != "no active competing firewall owner and no unexpected base-chain or legacy rule" || correction.WhyStopped != "SBXR never disables another firewall owner or flushes the host ruleset" {
		t.Fatalf("firewall Correction = %+v", correction)
	}
	if len(correction.OwnerSteps) != 1 || correction.OwnerSteps[0] != "Review the named firewall owner and correct it outside SBXR, then check again." {
		t.Fatalf("firewall correction steps = %+v", correction.OwnerSteps)
	}
	for _, want := range []string{"INSTALL-PLAN-REFUSED", "NETWORK-FIREWALL-CONFLICT", correction.Found, correction.Required} {
		if !strings.Contains(correction.Evidence, want) {
			t.Fatalf("firewall evidence omitted %q: %q", want, correction.Evidence)
		}
	}
}

func TestInstallationCorrectionCarriesTypedProtectedReclamationFinding(t *testing.T) {
	observations := 0
	productionNetwork := networkpolicy.New(protectedPackageObserver{}).Evaluate
	module := newTestInstallationWithNetwork(t, func(request networkpolicy.Request) networkpolicy.Result {
		observations++
		return productionNetwork(request)
	})

	review := module.Review(t.Context(), composedDraft(t))
	if review.Correction == nil {
		t.Fatalf("Installation review = %+v", review)
	}
	correction := review.Correction
	if correction.Problem != "A package conflict owns part of the Protected Host Foundation" || correction.Required != "no package owning SSH, system tools, shared libraries, mounts, or recovery dependencies" || correction.WhyStopped != "SBXR never offers removal of a package that owns the host foundation" {
		t.Fatalf("protected reclamation Correction = %+v", correction)
	}
	if len(correction.OwnerSteps) != 1 || correction.OwnerSteps[0] != "Reimage the VPS or remove the conflict through its proven owner." {
		t.Fatalf("protected reclamation steps = %+v", correction.OwnerSteps)
	}
	for _, want := range []string{"INSTALL-PLAN-REFUSED", "NETWORK-RECLAMATION-PROTECTED", correction.Found, correction.Required} {
		if !strings.Contains(correction.Evidence, want) {
			t.Fatalf("protected reclamation evidence omitted %q: %q", want, correction.Evidence)
		}
	}
	before := observations
	if checked := module.Review(t.Context(), Draft{}); checked.Correction == nil || observations <= before {
		t.Fatalf("Check again did not repeat production Installation review: observations %d -> %d, review %+v", before, observations, checked)
	}
}

type rootRuntimeInstallApproval struct {
	recheck softwarelifecycle.InstallRecheck
	marker  string
}

func (approval rootRuntimeInstallApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.InstallRecheck, error) {
	return approval.recheck, nil
}

func (rootRuntimeInstallApproval) String() string {
	return "controlled Installation approval: redacted"
}
func (rootRuntimeInstallApproval) GoString() string {
	return "controlled Installation approval: redacted"
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
			var adapter *systemubuntu.ControlledInstallationAdapter
			var launchErr error
			var transaction systemchanges.ApplyResult
			module := newTestInstallation(t, composedNetworkObserver{}, func(ctx context.Context, request softwareubuntu.InstallHandoffRequest, _ <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error) {
				built, err := buildInstallWith(ctx, request, buildDependencies{
					stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
						return request.Candidate.Staged, nil
					},
					network: networkpolicy.New(composedNetworkObserver{}).Evaluate,
					random:  newInstallEntropyReader(request.Entropy), sshProof: composedSSHProof(t),
				})
				if err != nil {
					launchErr = err
					return 0, err
				}
				root := t.TempDir()
				if err := os.Chmod(root, 0o700); err != nil {
					launchErr = err
					return 0, err
				}
				prepared, err := built.prepareState(statefilesystem.NewAt(root))
				if err != nil {
					launchErr = err
					return 0, err
				}
				recheck, volatile, err := recheckInstall(ctx, request, built)
				if err != nil {
					launchErr = err
					return 0, err
				}
				adapter = systemubuntu.NewRefusingControlledInstallationAdapter(systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: volatile, FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}, test.failPost, test.failReverse)
				approval := rootRuntimeInstallApproval{recheck: recheck, marker: "QUALIFICATION-SETUP-APPROVAL-00000000000000000009"}
				result := built.plan.Apply(ctx, softwarelifecycle.InstallApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(adapter)})
				if strings.Contains(fmt.Sprintf("%+v %+v", approval, result), approval.marker) {
					return 0, errors.New("controlled Installation approval marker escaped")
				}
				t.Log("RELEASE-STAGED-ONBOARDING-MARKER-SETUP-APPROVAL")
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
							reversed = adapter.ReversedSteps()
							executed = adapter.ExecutedSteps()
						}
						t.Fatalf("Installation outcome = %+v, adapter=%t, reversed=%d, executed=%v, launch error=%v, transaction=%+v", operation, adapter != nil, reversed, executed, launchErr, transaction)
					}
					if test.want == Completed {
						for _, owner := range []systemchanges.Module{systemchanges.SoftwareModule, systemchanges.NetworkPolicyModule, systemchanges.ConnectionProfilesModule, systemchanges.CertificateModule, systemchanges.SubscriptionModule} {
							if !adapter.RequiredGatePassed(owner, systemchanges.PrePublication) || !adapter.RequiredGatePassed(owner, systemchanges.PostPublication) {
								t.Fatalf("Managed omitted Required %s gates", owner)
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

func TestDestructiveReclamationCompositionBindsAllOwningModulesToOneChangeSet(t *testing.T) {
	request := composedInstallRequest(t)
	built, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(composedNetworkObserver{}).Evaluate,
		random:  newInstallEntropyReader(request.Entropy),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		string(softwarelifecycle.NetworkInstallContribution):      true,
		string(softwarelifecycle.ProfilesInstallContribution):     true,
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
	_, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: func(networkpolicy.Request) networkpolicy.Result {
			return networkpolicy.Result{InstallationClass: networkpolicy.ReclaimableVPS, Reclamation: plan}
		},
		random: newInstallEntropyReader(request.Entropy),
	})
	var review *reclamationReviewError
	if !errors.As(err, &review) || review.plan != plan {
		t.Fatalf("reclaimable routing = error %v review %+v", err, review)
	}
}

func TestComposedInstallCarriesTheExactReviewedStandaloneTargetIntoOneInstallPlan(t *testing.T) {
	request := composedInstallRequest(t)
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := buildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, random: newInstallEntropyReader(request.Entropy)}
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
	networkModule := networkpolicy.New(composedReclamationObserver{})
	dependencies := buildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, random: newInstallEntropyReader(request.Entropy)}
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
	if !slices.Contains(confirmed.VerifiedExternalInputs, "Direct SSH Preservation Proof") || !slices.Contains(confirmed.RequiredChecks, "Post-publication VLESS REALITY Vision, sbxr-ip, Subscription HTTPS, nftables, temporary TCP 80 cleanup, unit, timer, and permission agreement") {
		t.Fatalf("confirmed reclamation Plan lost installation safety proof: %+v", confirmed)
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

func composedBuiltInstall(t *testing.T, request softwareubuntu.InstallHandoffRequest, observer networkpolicy.Adapter, _ composedPlanAPI) *builtInstall {
	t.Helper()
	built, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(observer).Evaluate,
		random:  newInstallEntropyReader(request.Entropy),
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

func composedInstallDependencies(request softwareubuntu.InstallHandoffRequest, observer networkpolicy.Adapter, _ composedPlanAPI) buildDependencies {
	return buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: networkpolicy.New(observer).Evaluate,
		random:  newInstallEntropyReader(request.Entropy),
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
	networkModule := networkpolicy.New(composedHeldPackageObserver{})
	dependencies := buildDependencies{stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
		return request.Candidate.Staged, nil
	}, network: networkModule.Evaluate, random: newInstallEntropyReader(request.Entropy)}
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
	module := networkpolicy.New(incompleteReclamationObserver{})
	_, err := buildInstallWith(t.Context(), request, buildDependencies{
		stage: func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error) {
			return request.Candidate.Staged, nil
		},
		network: module.Evaluate,
		random:  newInstallEntropyReader(request.Entropy),
	})
	if err == nil {
		t.Fatalf("incomplete reclamation inventory continued: error %v", err)
	}
}

func TestInstallationInterfaceValidatesDependenciesAndTypedDraft(t *testing.T) {
	if module, err := New(Dependencies{}); err == nil || module != nil {
		t.Fatalf("New() = (%+v, %v), want construction refusal", module, err)
	}
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	result := module.Review(t.Context(), Draft{})
	if result.Invalid == nil || result.Invalid.Field != "owner-email" || result.Plan != nil || result.Reclamation != nil {
		t.Fatalf("invalid Draft = %+v", result)
	}
}

func TestInstallationReviewSuppliesACMEHelpAndRequiresAgreement(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	review := module.Review(t.Context(), Draft{})
	want := FieldHelp{
		Purpose:        "Register and recover the ACME account.",
		Instructions:   []string{"Enter one address you monitor."},
		AcceptedFormat: "local-part@domain; no spaces.",
		CommonMistakes: []string{"No name or multiple addresses."},
		Recovery:       "Correct it; prior values remain.",
		Example:        "owner@sbxr.example",
		URL:            "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options",
		Sensitivity:    PersonalInformation,
	}
	if review.Invalid == nil || !reflect.DeepEqual(review.Invalid.Help, want) {
		t.Fatalf("Owner email Help = %+v", review.Invalid)
	}
	review = module.Review(t.Context(), Draft{SubmittedField: "owner-email", SubmittedValue: "owner@example.com"})
	if review.Invalid == nil || review.Invalid.Field != "subscriber-agreement" || review.Plan != nil {
		t.Fatalf("ACME agreement Review = %+v", review)
	}
	help := review.Invalid.Help
	if help.Purpose == "" || len(help.Instructions) == 0 || help.AcceptedFormat == "" || len(help.CommonMistakes) == 0 || help.Recovery == "" || help.Example != "" || help.URL != "https://letsencrypt.org/repository/" || help.Sensitivity != PublicInformation {
		t.Fatalf("ACME agreement Help = %+v", help)
	}
	review = module.Review(t.Context(), Draft{SubmittedField: "subscriber-agreement", SubmittedValue: "yes"})
	if review.Invalid == nil || review.Invalid.Field != "subscriber-agreement" || review.Plan != nil {
		t.Fatalf("unreviewed ACME agreement = %+v", review)
	}
}

func TestInstallationReviewGuidesEveryFirstInstallationFieldAndRejectsTutorialValues(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	complete := composedDraft(t)
	steps := []struct{ field, valid string }{{"owner-email", complete.Installation.OwnerEmail}, {"subscriber-agreement", "accepted"}, {"reality-target", complete.RealityServerName}}
	for _, step := range steps {
		review := module.Review(t.Context(), Draft{})
		if review.Invalid == nil || review.Invalid.Field != step.field {
			t.Fatalf("%s initial Review = %+v", step.field, review)
		}
		help := review.Invalid.Help
		if help.Purpose == "" || len(help.Instructions) == 0 || help.AcceptedFormat == "" || len(help.CommonMistakes) == 0 || help.Recovery == "" || help.URL == "" {
			t.Fatalf("%s Help = %+v", step.field, help)
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
	if result := module.Review(t.Context(), Draft{Tag: "v1.0.0"}); result.Invalid == nil || result.Invalid.Field != "owner-email" {
		t.Fatalf("partial draft = %+v", result)
	}
	if result := module.Review(t.Context(), Draft{}); result.Invalid == nil || result.Invalid.Field != "owner-email" {
		t.Fatalf("active process forgot partial draft = %+v", result)
	}
	if result := module.Review(t.Context(), DiscardDraft()); result.Invalid == nil || result.Invalid.Field != "owner-email" {
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
		{"owner-email", Draft{SubmittedField: "owner-email", Installation: softwarelifecycle.InstallationDraft{OwnerEmail: complete.Installation.OwnerEmail}}, ""},
		{"subscriber-agreement", Draft{SubmittedField: "subscriber-agreement", SubmittedValue: "accepted"}, ""},
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
	}{
		{name: "zero public IPv4 candidates", preflight: networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222}},
		{name: "multiple public IPv4 candidates", preflight: networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222, UsablePublicIPv4: []string{"1.1.1.1", "9.9.9.9"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, test.preflight)
			if review := module.Review(t.Context(), Draft{}); review.Correction == nil || review.Correction.Evidence != "INSTALL-PUBLIC-ADDRESS-AMBIGUOUS" {
				t.Fatalf("initial Review = %+v", review)
			}
		})
	}

	finding := networkpolicy.Finding{Code: "NETWORK-INSTALLATION-SSH-UNPROVED", Problem: "The active SSH session could not be proved", Found: "no session", Required: "one active SSH session", WhyStopped: "SSH access cannot be preserved", Fix: networkpolicy.Fix{OwnerChecklist: []string{"Reconnect through SSH, then start Installation again."}}}
	module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{Failure: &finding, SSHFailureCause: networkpolicy.SSHOriginalSessionLost})
	review := module.Review(t.Context(), Draft{})
	if review.Correction == nil || review.Correction.InputLabel != "" || len(review.Correction.OwnerSteps) != 1 || review.Correction.SSHFailureCause != networkpolicy.SSHOriginalSessionLost || review.Invalid != nil {
		t.Fatalf("unproved SSH did not stop with exact recovery guidance: %+v", review)
	}
	module = newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{Failure: &finding, SSHFailureCause: networkpolicy.SSHObservationUnavailable})
	if review := module.Review(t.Context(), Draft{}); review.Correction == nil || review.Correction.SSHFailureCause != networkpolicy.SSHObservationUnavailable {
		t.Fatalf("temporary SSH observation failure removed Check again: %+v", review)
	}
}

func TestInstallationReviewDerivesAndImmediatelyChecksOneRealityHostname(t *testing.T) {
	module := newTestInstallation(t, composedNetworkObserver{}, nil)
	complete := composedDraft(t)
	for _, input := range []Draft{
		{SubmittedField: "owner-email", SubmittedValue: complete.Installation.OwnerEmail},
		{SubmittedField: "subscriber-agreement", SubmittedValue: "accepted"},
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
		if review.Invalid == nil || review.Invalid.Field != "reality-target" || review.Invalid.Value != "edge.example.net" || target.Address != "edge.example.net:443" || target.ServerName != "edge.example.net" || module.nextField != len(module.fields)-1 || module.draft.RealityTarget != "" || len(review.Invalid.Facts) < 4 || review.Invalid.Facts[len(review.Invalid.Facts)-2].Value != "Enter one ordinary hostname, then Check again." || !strings.Contains(review.Invalid.Facts[len(review.Invalid.Facts)-1].Value, test.code) {
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

func TestInstallationReviewAsksForPrimaryAddressOnlyWhenBothFamiliesQualify(t *testing.T) {
	module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"8.8.8.8"}, UsablePublicIPv6: []string{"2606:4700:4700::1111"}})
	module.Review(t.Context(), Draft{SubmittedField: "owner-email", SubmittedValue: "owner@example.com"})
	module.Review(t.Context(), Draft{SubmittedField: "subscriber-agreement", SubmittedValue: "accepted"})
	review := module.Review(t.Context(), Draft{SubmittedField: "primary-address", SubmittedValue: "10.0.0.1"})
	if review.Invalid == nil || review.Invalid.Field != "primary-address" || module.draft.Installation.PrimaryAddress != "" {
		t.Fatalf("special-use primary-address Review = %+v, draft = %+v", review, module.draft.Installation)
	}
	review = module.Review(t.Context(), Draft{SubmittedField: "primary-address", SubmittedValue: "2606:4700:4700::1111"})
	if review.Invalid == nil || review.Invalid.Field != "reality-target" || module.draft.Installation.PrimaryAddress != "2606:4700:4700::1111" {
		t.Fatalf("selected primary-address = %+v, draft = %+v", review, module.draft.Installation)
	}
}

func TestInstallationReviewShowsEveryExplicitPortReplacementInThePlan(t *testing.T) {
	module := newTestInstallationWithPreflight(t, replacementPortObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222, UsablePublicIPv4: []string{"8.8.8.8"}, RealityPortReplacementRequired: true, SubscriptionReplacementRequired: true})
	draft := composedDraft(t)
	draft.Installation.SSHPort = 2222
	draft.Installation.RealityPort = 1443
	draft.Installation.SubscriptionPort = 40443
	review := module.Review(t.Context(), draft)
	if review.Plan == nil {
		t.Fatalf("replacement Review = %+v", review)
	}
	want := "Use SSH 2222/TCP, VLESS REALITY Vision 1443/TCP, and Subscription HTTPS 40443/TCP"
	if !slices.Contains(review.Plan.Effects, want) {
		t.Fatalf("reviewed Plan omitted explicit replacements: %+v", review.Plan.Effects)
	}
}

func TestInstallationReviewUsesSafeRecommendationAndAsksOnlyForRequiredPortReplacements(t *testing.T) {
	module := newTestInstallationWithPreflight(t, replacementPortObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222, UsablePublicIPv4: []string{"8.8.8.8"}, RealityPortReplacementRequired: true, SubscriptionReplacementRequired: true})
	module.dependencies.RecommendedRealityTarget = "www.microsoft.com"
	for _, step := range []struct{ field, value, next string }{
		{"owner-email", "owner@example.com", "subscriber-agreement"},
		{"subscriber-agreement", "accepted", "reality-port"},
		{"reality-port", "1443", "subscription-port"},
		{"subscription-port", "40443", ""},
	} {
		review := module.Review(t.Context(), Draft{SubmittedField: step.field, SubmittedValue: step.value})
		if step.next != "" && (review.Invalid == nil || review.Invalid.Field != step.next) || step.next == "" && review.Plan == nil {
			t.Fatalf("%s Review = %+v", step.field, review)
		}
	}
	if module.draft.RealityServerName != "www.microsoft.com" {
		t.Fatalf("recommended REALITY target = %+v", module.draft)
	}
}

func TestInstallationReviewReturnsAFullDraftFailureToTheActiveConditionalField(t *testing.T) {
	module := newTestInstallationWithPreflight(t, replacementPortObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 2222, UsablePublicIPv4: []string{"8.8.8.8"}, RealityPortReplacementRequired: true})
	module.dependencies.ReviewRealityTarget = func(_ context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
		return connectionprofiles.RealityTargetReview{Target: target, Health: connectionprofiles.Health{Outcome: connectionprofiles.Failed}}
	}
	draft := composedDraft(t)
	draft.Installation.SSHPort = 2222
	draft.RealityTarget, draft.RealityServerName = "bad target:443", "bad target"
	review := module.Review(t.Context(), draft)
	if review.Invalid == nil || review.Invalid.Field != "reality-target" || module.nextField != 3 {
		t.Fatalf("conditional full-draft correction = %+v, next field = %d", review, module.nextField)
	}
}

func TestInstallationReviewAddsAnInvalidOmittedDefaultToTheCorrectionJourney(t *testing.T) {
	module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"8.8.8.8"}})
	module.dependencies.RecommendedRealityTarget = "www.microsoft.com"
	draft := composedDraft(t)
	draft.RealityTarget, draft.RealityServerName = "bad target:443", "bad target"
	review := module.Review(t.Context(), draft)
	if review.Invalid == nil || review.Invalid.Field != "reality-target" || module.nextField != len(module.fields)-1 || module.fields[module.nextField] != "reality-target" {
		t.Fatalf("omitted default correction = %+v, fields = %v, next field = %d", review, module.fields, module.nextField)
	}
}

func TestInstallationReviewRoutesMultipleFullDraftFailuresThroughTheCorrectionJourney(t *testing.T) {
	module := newTestInstallationWithPreflight(t, composedNetworkObserver{}, networkpolicy.InstallationPreflightResult{ActiveSSHPort: 22, UsablePublicIPv4: []string{"8.8.8.8"}})
	module.dependencies.RecommendedRealityTarget = "www.microsoft.com"
	module.dependencies.ReviewRealityTarget = func(_ context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
		outcome := connectionprofiles.Healthy
		if target.ServerName == "blocked.test.net" {
			outcome = connectionprofiles.Failed
		}
		return connectionprofiles.RealityTargetReview{Target: target, Health: connectionprofiles.Health{Outcome: outcome, Code: "CONNECTION-PROFILES-REALITY-PROBE"}}
	}
	draft := composedDraft(t)
	draft.Installation.OwnerEmail = "invalid"
	draft.RealityTarget, draft.RealityServerName = "blocked.test.net:443", "blocked.test.net"
	if review := module.Review(t.Context(), draft); review.Invalid == nil || review.Invalid.Field != "owner-email" {
		t.Fatalf("first full-draft correction = %+v", review)
	}
	if review := module.Review(t.Context(), Draft{SubmittedField: "owner-email", SubmittedValue: "owner@example.com"}); review.Invalid == nil || review.Invalid.Field != "subscriber-agreement" {
		t.Fatalf("agreement correction = %+v", review)
	}
	review := module.Review(t.Context(), Draft{SubmittedField: "subscriber-agreement", SubmittedValue: "accepted"})
	if review.Invalid == nil || review.Invalid.Field != "reality-target" || module.nextField != len(module.fields)-1 {
		t.Fatalf("later target correction = %+v, fields = %v", review, module.fields)
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
	if fresh := module.Review(t.Context(), Draft{}); fresh.Invalid == nil || fresh.Invalid.Field != "owner-email" {
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
		"Run only xray.service and sbxr-subscription.service; keep sing-box.service and cloudflared.service disabled and inactive",
		"Create VLESS REALITY Vision Enabled and keep the other five Connection Profiles Not set up without placeholders",
		"Issue and activate only the sbxr-ip certificate lineage and remove the exact temporary TCP 80 rule on every outcome",
		"Leave all Cloudflare credentials, identifiers, resources, routes, DNS, Tunnel, and domain-certificate facts unchanged and absent",
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
	return Draft{Tag: request.Tag, Architecture: request.Architecture, Installation: request.Draft, RealityTarget: request.RealityTarget, RealityServerName: request.RealityServerName}
}

func newTestInstallation(t *testing.T, observer networkpolicy.Adapter, launch func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error)) *Interface {
	request := composedInstallRequest(t)
	return newTestInstallationWith(t, observer, launch, networkpolicy.InstallationPreflightResult{ActiveSSHPort: request.Draft.SSHPort, UsablePublicIPv4: []string{request.Draft.PublicIPv4}})
}

func newTestInstallationWithPreflight(t *testing.T, observer networkpolicy.Adapter, preflight networkpolicy.InstallationPreflightResult) *Interface {
	return newTestInstallationWith(t, observer, nil, preflight)
}

func newTestInstallationWith(t *testing.T, observer networkpolicy.Adapter, launch func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error), preflight networkpolicy.InstallationPreflightResult) *Interface {
	return newTestInstallationWithDependencies(t, networkpolicy.New(observer).Evaluate, launch, preflight)
}

func newTestInstallationWithNetwork(t *testing.T, network func(networkpolicy.Request) networkpolicy.Result) *Interface {
	request := composedInstallRequest(t)
	return newTestInstallationWithDependencies(t, network, nil, networkpolicy.InstallationPreflightResult{ActiveSSHPort: request.Draft.SSHPort, UsablePublicIPv4: []string{request.Draft.PublicIPv4}})
}

func newTestInstallationWithDependencies(t *testing.T, network func(networkpolicy.Request) networkpolicy.Result, launch func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error), preflight networkpolicy.InstallationPreflightResult) *Interface {
	t.Helper()
	request := composedInstallRequest(t)
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
		Network: network, Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)), Launch: launch,
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
	request, err := controlledInstallRequest()
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type composedNetworkObserver struct{}

func (composedNetworkObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return networkpolicy.ControlledInstallationAdapter().Observe(request)
}

func composedSSHProof(t *testing.T) networkpolicy.SSHPreservationProof {
	t.Helper()
	proof, err := networkpolicy.ControlledInstallationSSHPreservationProof()
	if err != nil {
		t.Fatal(err)
	}
	return proof
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

type protectedPackageObserver struct{ composedPackageObserver }

func (protectedPackageObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedPackageObserver{}).Observe(request)
	observed.Reclamation.Packages[0].OwnedPaths = append(observed.Reclamation.Packages[0].OwnedPaths, "/usr/lib/libshared.so")
	return observed, err
}

type composedDockerObserver struct{ composedNetworkObserver }

func (composedDockerObserver) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	observed, err := (composedNetworkObserver{}).Observe(request)
	observed.Firewall.ActiveManager = "docker.service"
	observed.Firewall.UnexpectedRule = "Docker FORWARD integration"
	observed.Firewall.UFWConfiguredState = networkpolicy.UFWConfigMissing
	observed.Firewall.UFWReportedState = networkpolicy.UFWStatusUnavailable
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
	observed.Firewall.UFWConfiguredState = networkpolicy.UFWConfigActive
	observed.Firewall.UFWReportedState = networkpolicy.UFWStatusActive
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
	return cloudflaretunnel.Observation{Account: cloudflaretunnel.AccountObservation{ID: account}, Zone: cloudflaretunnel.ZoneObservation{ID: zone, AccountID: account, Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: cloudflaretunnel.TokenObservation{ID: strings.Repeat("d", 32), Status: "active"}, DNSListProven: true, TunnelListProven: true}, nil
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
