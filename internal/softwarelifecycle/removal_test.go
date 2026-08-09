package softwarelifecycle_test

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type removalStatusAdapter struct{ observation systemchanges.Observation }

func (adapter removalStatusAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}

type forgedCompleteRemovalStateAuthority struct {
	revision uint64
	sha256   string
}

type forgedRemovalReview struct{}

func (forgedRemovalReview) SoftwareLifecycleCompleteRemovalReview() (string, bool) {
	return "forged-complete-removal-review", true
}

type missingRemovalStorage struct{}

func (missingRemovalStorage) Read() ([]byte, error) { return nil, fs.ErrNotExist }
func (missingRemovalStorage) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("Complete removal never publishes State")
}

func (authority forgedCompleteRemovalStateAuthority) StateCompleteRemoval() (uint64, string, bool) {
	return authority.revision, authority.sha256, true
}
func (forgedCompleteRemovalStateAuthority) StateUnprovenCompleteRemoval() (string, string, string, bool) {
	return "forged-removal", "forged-plan", strings.Repeat("f", 64), true
}
func (removalStatusAdapter) TryLock() (systemchanges.Lock, bool, error) { return nil, false, nil }

type removalReviewObserver struct{}

func (removalReviewObserver) ReviewedCategories(string) ([]string, error) {
	return completeRemovalReviewCategories(), nil
}
func (removalReviewObserver) TypedPhrase(string) (string, bool, error) {
	return "COMPLETE REMOVAL", true, nil
}
func (removalReviewObserver) PermanentRemovalSelected(string) (bool, error) { return true, nil }

type publicRemovalObserver struct{ inventory map[string][]string }

func (observer publicRemovalObserver) ObserveRemovalResource(review, resource, immutableID string) (networkpolicy.RemovalObservation, error) {
	return networkpolicy.RemovalObservation{ReviewID: review, Resource: resource, ImmutableID: immutableID, OwnedBySBXR: true, Inventory: observer.inventory}, nil
}

type cloudflareRemovalObserver struct{ inventory map[string][]string }

func (observer cloudflareRemovalObserver) ObserveRemovalResource(review, resource, immutableID string) (cloudflaretunnel.RemovalObservation, error) {
	return cloudflaretunnel.RemovalObservation{ReviewID: review, Resource: resource, ImmutableID: immutableID, OwnedBySBXR: true, TokenActive: true, TokenAvailableLocally: true, Inventory: observer.inventory}, nil
}

type completeRemovalApproval struct {
	recheck softwarelifecycle.CompleteRemovalRecheck
	calls   int
}

func (approval *completeRemovalApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.CompleteRemovalRecheck, error) {
	approval.calls++
	return approval.recheck, nil
}

type completeRemovalPrepared struct {
	changeSet, starting, candidate, planIdentity, planSHA256 string
	revision                                                 uint64
}

func (prepared completeRemovalPrepared) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.planIdentity, prepared.planSHA256, true
}
func (completeRemovalPrepared) SystemChangesConsume(any, string, string) (any, error) {
	return nil, nil
}

func TestViewAndPlanCompleteRemovalDiscloseTheWholeRollbackSafeJourney(t *testing.T) {
	stateSHA, volatileSHA := strings.Repeat("a", 64), strings.Repeat("b", 64)
	changes := systemchanges.New(removalStatusAdapter{systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: 7, StateSHA256: stateSHA, VolatileSHA256: volatileSHA}})
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes)
	if view.Status != softwarelifecycle.Managed || view.StateRevision != 7 || view.StateSHA256 != stateSHA || !reflect.DeepEqual(view.PermittedActions, []softwarelifecycle.Action{softwarelifecycle.ReviewCompleteRemoval}) || view.Candidate() == (softwarelifecycle.CompleteRemovalCandidate{}) {
		t.Fatalf("ViewCompleteRemoval() = %+v", view)
	}

	console := ownerconsole.New(removalReviewObserver{})
	review, err := console.StartRemovalReview("complete-removal-review-0007")
	if err != nil {
		t.Fatal(err)
	}
	public, external := completeRemovalAuthorities(t, "complete-removal-review-0007")
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 2, SnapshotBytes: 3, JournalBytes: 4, RollbackBytes: 5, OverheadBytes: 6}
	plan, finding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{Candidate: view.Candidate(), Review: review, ChangeSet: "complete-removal-revision-7", PublicAuthorities: public, CloudflareAuthorities: external, Disk: disk})
	if finding != nil || plan == nil {
		t.Fatalf("PlanCompleteRemoval() = (%+v, %+v)", plan, finding)
	}
	summary := plan.Summary()
	if summary.StartingStatus != softwarelifecycle.Managed || summary.StateRevision != 7 || summary.Disk != disk || !summary.OneUse || !summary.SudoAfterApproval || len(summary.OwnedLocalCategories) != 15 || !reflect.DeepEqual(summary.CloudflareCategories, []string{"DNS records", "Tunnel routes", "Tunnel"}) || !reflect.DeepEqual(summary.IrreversibleRemnants, []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"}) || summary.CancellationBoundary == "" || summary.TokenRevocationResponsibility == "" || summary.Rollback == "" || summary.FinalProof != "Not installed with no retained SBXR recovery material" {
		t.Fatalf("Complete removal summary = %+v", summary)
	}
	if strings.Contains(plan.String(), "REMOVAL-SECRET-MARKER") {
		t.Fatalf("Complete removal Plan exposed protected material: %s", plan)
	}
}

func TestPlanCompleteRemovalRefusesIncompleteCallerMadeAndReusedInputs(t *testing.T) {
	stateSHA, volatileSHA := strings.Repeat("a", 64), strings.Repeat("b", 64)
	observation := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: 7, StateSHA256: stateSHA, VolatileSHA256: volatileSHA}
	changes := systemchanges.New(removalStatusAdapter{observation})
	console := ownerconsole.New(removalReviewObserver{})
	review, err := console.StartRemovalReview("complete-removal-hostile-0007")
	if err != nil {
		t.Fatal(err)
	}
	public, external := completeRemovalAuthorities(t, "complete-removal-hostile-0007")
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}
	request := softwarelifecycle.CompleteRemovalPlanRequest{Review: review, ChangeSet: "complete-removal-hostile-0007", PublicAuthorities: public, CloudflareAuthorities: external, Disk: disk}

	request.Candidate = (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate()
	request.PublicAuthorities = public[:len(public)-1]
	if plan, finding := softwarelifecycle.PlanCompleteRemoval(request); plan != nil || finding == nil {
		t.Fatalf("incomplete public proof = (%+v, %+v)", plan, finding)
	}

	request.Candidate = (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate()
	request.PublicAuthorities = public
	request.Review = forgedRemovalReview{}
	if plan, finding := softwarelifecycle.PlanCompleteRemoval(request); plan != nil || finding == nil {
		t.Fatalf("caller-made review = (%+v, %+v)", plan, finding)
	}

	request.Candidate = (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate()
	request.Review = review
	if plan, finding := softwarelifecycle.PlanCompleteRemoval(request); plan == nil || finding != nil {
		t.Fatalf("valid Plan = (%+v, %+v)", plan, finding)
	}
	if plan, finding := softwarelifecycle.PlanCompleteRemoval(request); plan != nil || finding == nil {
		t.Fatalf("reused candidate = (%+v, %+v)", plan, finding)
	}
}

func TestPlanCompleteRemovalPreservesARecoveryRequiredStart(t *testing.T) {
	volatileSHA := strings.Repeat("b", 64)
	observation := systemchanges.Observation{Status: systemchanges.RecoveryRequired, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, RecoveryCause: systemchanges.StateLineageUnprovable, VolatileSHA256: volatileSHA}
	changes := systemchanges.New(removalStatusAdapter{observation})
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes)
	console := ownerconsole.New(removalReviewObserver{})
	review, err := console.StartRemovalReview("complete-removal-recovery-0007")
	if err != nil {
		t.Fatal(err)
	}
	public, external := completeRemovalAuthorities(t, "complete-removal-recovery-0007")
	plan, finding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{Candidate: view.Candidate(), Review: review, ChangeSet: "complete-removal-recovery-0007", PublicAuthorities: public, CloudflareAuthorities: external, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if finding != nil || plan == nil || plan.Summary().StartingStatus != softwarelifecycle.RecoveryRequired || !strings.Contains(plan.Summary().Rollback, "Recovery Required") {
		t.Fatalf("Recovery Required Plan = (%+v, %+v)", plan, finding)
	}
	prepared, err := state.New(missingRemovalStorage{}).PrepareUnprovenCompleteRemovalCommit(plan)
	if err != nil {
		t.Fatal(err)
	}
	changeSet, revision, starting, candidate, identity, checksum, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != "complete-removal-recovery-0007" || revision != 0 || starting != "" || candidate != "" || identity != plan.Identity() || checksum != plan.SHA256() {
		t.Fatalf("unproven removal State = change_set=%q revision=%d starting=%q candidate=%q identity=%q checksum=%q valid=%t", changeSet, revision, starting, candidate, identity, checksum, valid)
	}
	typed, err := console.RecordTypedPhrase(review)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := console.SelectPermanentRemoval(review, typed)
	if err != nil {
		t.Fatal(err)
	}
	rechecked := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate()
	approval := &completeRemovalApproval{recheck: softwarelifecycle.CompleteRemovalRecheck{Candidate: rechecked, Review: review, PublicAuthorities: public, CloudflareAuthorities: external, TypedConfirmation: typed, PermanentSelection: selected}}
	result := plan.Apply(t.Context(), softwarelifecycle.CompleteRemovalApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" {
		t.Fatalf("Recovery Required Apply handoff = %+v", result)
	}

	corruptReview, err := console.StartRemovalReview("complete-removal-corrupt-0007")
	if err != nil {
		t.Fatal(err)
	}
	corruptPublic, corruptExternal := completeRemovalAuthorities(t, "complete-removal-corrupt-0007")
	corruptPlan, corruptFinding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{Candidate: (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate(), Review: corruptReview, ChangeSet: "complete-removal-corrupt-0007", PublicAuthorities: corruptPublic, CloudflareAuthorities: corruptExternal, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if corruptFinding != nil {
		t.Fatal(corruptFinding)
	}
	corruptPrepared, err := state.New(&repairStorage{document: []byte("{")}).PrepareUnprovenCompleteRemovalCommit(corruptPlan)
	if err != nil || !corruptPrepared.SystemChangesRemovalLineageUnavailable() {
		t.Fatalf("corrupt raw State baseline = (%+v, %v)", corruptPrepared, err)
	}
}

func TestViewCompleteRemovalRefusesAnUnfinishedRollback(t *testing.T) {
	observation := systemchanges.Observation{
		Status: systemchanges.RecoveryRequired, CurrentChangeSet: "unfinished-change-0007", LastChangeSet: "change-0006", Checkpoint: systemchanges.PreparedCheckpoint,
		TotalSteps: 8, Lock: systemchanges.LockReleased, RollbackAvailable: true, RecoveryCause: systemchanges.ForwardCheckpointUnprovable,
		StateRevision: 7, StateSHA256: strings.Repeat("a", 64), VolatileSHA256: strings.Repeat("b", 64),
	}
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(systemchanges.New(removalStatusAdapter{observation}))
	if view.Candidate() != (softwarelifecycle.CompleteRemovalCandidate{}) || len(view.PermittedActions) != 0 {
		t.Fatalf("unfinished rollback Complete removal View = %+v", view)
	}
}

func TestApplyCompleteRemovalRechecksBothOwnerActsAndHandsOneChangeSetToSystemChanges(t *testing.T) {
	stateSHA, volatileSHA := strings.Repeat("a", 64), strings.Repeat("b", 64)
	observation := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: 7, StateSHA256: stateSHA, VolatileSHA256: volatileSHA}
	changes := systemchanges.New(removalStatusAdapter{observation})
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes)
	console := ownerconsole.New(removalReviewObserver{})
	review, err := console.StartRemovalReview("complete-removal-apply-0007")
	if err != nil {
		t.Fatal(err)
	}
	public, external := completeRemovalAuthorities(t, "complete-removal-apply-0007")
	request := softwarelifecycle.CompleteRemovalPlanRequest{Candidate: view.Candidate(), Review: review, ChangeSet: "complete-removal-apply-0007", PublicAuthorities: public, CloudflareAuthorities: external, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	plan, finding := softwarelifecycle.PlanCompleteRemoval(request)
	if finding != nil {
		t.Fatal(finding)
	}
	typed, typedErr := console.RecordTypedPhrase(review)
	selected, selectedErr := console.SelectPermanentRemoval(review, typed)
	if typedErr != nil || selectedErr != nil {
		t.Fatalf("Owner authorization = (%v, %v)", typedErr, selectedErr)
	}
	rechecked := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate()
	approval := &completeRemovalApproval{recheck: softwarelifecycle.CompleteRemovalRecheck{Candidate: rechecked, Review: review, PublicAuthorities: public, CloudflareAuthorities: external, TypedConfirmation: typed, PermanentSelection: selected}}
	prepared := completeRemovalPrepared{changeSet: request.ChangeSet, revision: 8, starting: stateSHA, candidate: stateSHA, planIdentity: plan.Identity(), planSHA256: plan.SHA256()}
	result := plan.Apply(t.Context(), softwarelifecycle.CompleteRemovalApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || approval.calls != 1 {
		t.Fatalf("Apply() = %+v; approval calls=%d", result, approval.calls)
	}
	repeated := plan.Apply(t.Context(), softwarelifecycle.CompleteRemovalApplyRequest{Approval: approval})
	if repeated.Finding == nil || repeated.Finding.Code != "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-PLAN-USED" || approval.calls != 1 {
		t.Fatalf("reused Apply() = %+v; approval calls=%d", repeated, approval.calls)
	}
}

func TestCompleteRemovalPreparesOnlyUnchangedCurrentStateForRollback(t *testing.T) {
	release := state.ReleaseIdentity{Repository: "https://github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	stateModule := state.New(&repairStorage{document: []byte(repairStateDocument)})
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: 7, LastCompletedChangeSet: "change-0007", ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		t.Fatalf("Load() = (%+v, %v)", loaded, err)
	}
	stateSHA, volatileSHA := "47c176e0230ce70ce742a55d2f8956331b97a43e7791cda080a269f9c4e4f412", strings.Repeat("b", 64)
	observation := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, StateRevision: 7, StateSHA256: stateSHA, VolatileSHA256: volatileSHA}
	changes := systemchanges.New(removalStatusAdapter{observation})
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes)
	console := ownerconsole.New(removalReviewObserver{})
	review, err := console.StartRemovalReview("complete-removal-state-0007")
	if err != nil {
		t.Fatal(err)
	}
	public, external := completeRemovalAuthorities(t, "complete-removal-state-0007")
	plan, finding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{Candidate: view.Candidate(), Review: review, ChangeSet: "complete-removal-state-0007", PublicAuthorities: public, CloudflareAuthorities: external, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
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
	validators := repairValidators{}
	prepare := state.PrepareRequest{Loaded: loaded, CandidateReleaseIdentity: release, ChangeSet: "complete-removal-state-0007", Candidate: loaded.Snapshot.DesiredState, SemanticValidators: state.SemanticValidators{ConnectionProfiles: validators, Subscription: validators, Cloudflare: validators, Certificates: validators, NetworkPolicy: validators, SoftwareLifecycle: validators}, ServiceMaterials: repairServiceMaterials(loaded.Snapshot.DesiredState), ReviewedInputs: reviewed}
	changed := prepare
	changed.Candidate.NetworkPolicy.PublicIPv4 = "203.0.113.99"
	if prepared, err := stateModule.PrepareCompleteRemovalCommit(changed, plan); err == nil || prepared != nil {
		t.Fatalf("changed Desired State = (%+v, %v)", prepared, err)
	}
	if prepared, err := stateModule.PrepareCompleteRemovalCommit(prepare, forgedCompleteRemovalStateAuthority{7, stateSHA}); err == nil || prepared != nil {
		t.Fatalf("forged removal authority = (%+v, %v)", prepared, err)
	}
	prepared, err := stateModule.PrepareCompleteRemovalCommit(prepare, plan)
	if err != nil || prepared.Revision() != 8 {
		t.Fatalf("PrepareCompleteRemovalCommit() = (%+v, %v)", prepared, err)
	}
	changeSet, _, starting, candidate, _, _, valid := prepared.SystemChangesPreparedState()
	if !valid || changeSet != "complete-removal-state-0007" || starting != stateSHA || candidate != stateSHA {
		t.Fatalf("prepared removal binding = change_set=%q starting=%q candidate=%q valid=%t", changeSet, starting, candidate, valid)
	}
	typed, _ := console.RecordTypedPhrase(review)
	selected, _ := console.SelectPermanentRemoval(review, typed)
	rechecked := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes).Candidate()
	approval := &completeRemovalApproval{recheck: softwarelifecycle.CompleteRemovalRecheck{Candidate: rechecked, Review: review, PublicAuthorities: public, CloudflareAuthorities: external, TypedConfirmation: typed, PermanentSelection: selected}}
	result := plan.Apply(t.Context(), softwarelifecycle.CompleteRemovalApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" {
		t.Fatalf("real State Apply handoff = %+v", result)
	}
}

func completeRemovalAuthorities(t *testing.T, review string) ([]systemchanges.PublicRemovalAuthority, []systemchanges.CloudflareRemovalAuthority) {
	t.Helper()
	publicInventory := map[string][]string{"firewall-table": {"inet-sbxr"}, "public-listener": {"listener-xray"}, "public-service": {"service-xray"}}
	cloudflareInventory := map[string][]string{"cloudflare-dns-record": {"dns-direct", "dns-websocket", "dns-xhttp"}, "cloudflare-route": {"tunnel-routes"}, "cloudflare-tunnel": {"tunnel-id"}}
	public := make([]systemchanges.PublicRemovalAuthority, 0, 3)
	for category, identities := range publicInventory {
		for _, identity := range identities {
			authority, err := networkpolicy.NewRemoval(publicRemovalObserver{publicInventory}).ProveRemovalResource(review, category, identity)
			if err != nil {
				t.Fatal(err)
			}
			public = append(public, authority)
		}
	}
	external := make([]systemchanges.CloudflareRemovalAuthority, 0, 5)
	for category, identities := range cloudflareInventory {
		for _, identity := range identities {
			authority, err := cloudflaretunnel.NewRemoval(cloudflareRemovalObserver{cloudflareInventory}).ProveRemovalResource(review, category, identity)
			if err != nil {
				t.Fatal(err)
			}
			external = append(external, authority)
		}
	}
	return public, external
}

func completeRemovalReviewCategories() []string {
	return []string{"desired-state", "client-access-values", "infrastructure-secrets", "certificates-and-acme", "transaction-journal", "rollback-snapshot", "installed-release", "verified-update-candidate", "services-and-timers", "service-identities", "prepared-artifacts", "subscription-artifacts", "firewall-table", "public-listener", "public-service", "cloudflare-dns-record", "cloudflare-route", "cloudflare-tunnel", "certificate-transparency-remnant", "dns-cache-remnant"}
}
