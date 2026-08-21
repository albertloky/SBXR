package softwarelifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type controlledRepairContribution struct{ proof RepairContributionProof }

func (value controlledRepairContribution) SoftwareLifecycleRepairContribution() RepairContributionProof {
	return value.proof
}

type controlledRepairApproval struct {
	recheck RepairRecheck
	calls   int
}

func (approval *controlledRepairApproval) AuthorizeAndRecheck(context.Context) (RepairRecheck, error) {
	approval.calls++
	return approval.recheck, nil
}

type controlledRepairPrepared struct {
	changeSet                string
	revision                 uint64
	starting, candidate      string
	planIdentity, planSHA256 string
}

func (prepared controlledRepairPrepared) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return prepared.changeSet, prepared.revision, prepared.starting, prepared.candidate, prepared.planIdentity, prepared.planSHA256, true
}
func (controlledRepairPrepared) SystemChangesConsume(any, string, string) (any, error) {
	return nil, nil
}

type repairObservationAdapter struct{ observation systemchanges.Observation }

func (adapter *repairObservationAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (*repairObservationAdapter) TryLock() (systemchanges.Lock, bool, error) { return nil, false, nil }

func TestViewRepairOffersOnlyCurrentDesiredStateDrift(t *testing.T) {
	stateSHA := strings.Repeat("a", 64)
	adapter := &repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)}
	result := (LegacyInterface{}).ViewRepair(systemchanges.New(adapter))
	if result.Status != RecoveryRequired || result.Cause != systemchanges.CurrentStateDrift || result.StateRevision != 7 || result.StateSHA256 != stateSHA || !reflect.DeepEqual(result.PermittedActions, []Action{ReviewRepair}) || result.RepairCandidate() == (RepairCandidate{}) {
		t.Fatalf("ViewRepair() = %+v", result)
	}
	if _, err := json.Marshal(result.RepairCandidate()); err == nil || strings.Contains(fmt.Sprintf("%#v", result), "OWNER-SECRET") {
		t.Fatalf("repair authority rendered: %+v", result)
	}
}

func TestViewRepairKeepsRollbackAndProhibitedRecoverySeparate(t *testing.T) {
	rollback := repairObservation(systemchanges.RollbackStepUnprovable, strings.Repeat("a", 64))
	rollback.CurrentChangeSet, rollback.LastChangeSet, rollback.Checkpoint, rollback.TotalSteps = "change-active", "change-0007", systemchanges.PreparedCheckpoint, 1
	rollback.RollbackAvailable, rollback.ForwardRepairAvailable = true, false
	got := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: rollback}))
	if !reflect.DeepEqual(got.PermittedActions, []Action{RetryAutomaticRollback}) || got.RepairCandidate() != (RepairCandidate{}) {
		t.Fatalf("rollback ViewRepair() = %+v", got)
	}

	for _, cause := range []systemchanges.RecoveryCause{systemchanges.StateLineageUnprovable, systemchanges.MissingSecrets, systemchanges.ReplacementVPS, systemchanges.OlderRevision, systemchanges.OwnerRegret} {
		t.Run(string(cause), func(t *testing.T) {
			observation := repairObservation(cause, strings.Repeat("a", 64))
			observation.ForwardRepairAvailable = false
			result := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: observation}))
			if !reflect.DeepEqual(result.PermittedActions, []Action{CompleteRemoval}) || result.RepairCandidate() != (RepairCandidate{}) || len(result.Guidance) < 2 {
				t.Fatalf("prohibited ViewRepair() = %+v", result)
			}
		})
	}
}

func TestViewRepairRefusesRepairWhileTheGlobalLockIsHeld(t *testing.T) {
	observation := repairObservation(systemchanges.CurrentStateDrift, strings.Repeat("a", 64))
	observation.Lock = systemchanges.LockHeld
	result := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: observation}))
	if !reflect.DeepEqual(result.PermittedActions, []Action{CompleteRemoval}) || result.RepairCandidate() != (RepairCandidate{}) {
		t.Fatalf("lock-held ViewRepair() = %+v", result)
	}
}

func repairObservation(cause systemchanges.RecoveryCause, stateSHA string) systemchanges.Observation {
	return systemchanges.Observation{Status: systemchanges.RecoveryRequired, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, ForwardRepairAvailable: true, RecoveryCause: cause, StateRevision: 7, StateSHA256: stateSHA, VolatileSHA256: strings.Repeat("c", 64)}
}

func TestPlanRepairDisclosesOneCurrentStateForwardRepair(t *testing.T) {
	capability, stateSHA := controlledManagedCapability(t, true)
	view := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)}))
	contribution := controlledRepairProof(t, "repair-revision-8", 7, stateSHA)
	disk := systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 2, SnapshotBytes: 3, JournalBytes: 4, RollbackBytes: 5, OverheadBytes: 6}
	plan, finding := controlledPlanRepair(RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{contribution}, ChangeSet: "repair-revision-8", Capability: capability, Disk: disk})
	if finding != nil || plan == nil {
		t.Fatalf("PlanRepair() = (%+v, %+v)", plan, finding)
	}
	summary := plan.Summary()
	if summary.CurrentRevision != 7 || summary.CandidateRevision != 8 || summary.CurrentStateSHA256 != stateSHA || summary.OwningModule != systemchanges.ConnectionProfilesModule || summary.Disk != disk || !summary.OneUse || !summary.PrivilegedMutationAfterApproval || len(summary.Steps) != 1 || len(summary.Checks) != 2 || summary.StateEffect != "publish revision 8 with unchanged Owner intent after repaired resources pass required gates" || summary.Rollback == "" {
		t.Fatalf("repair summary = %+v", summary)
	}
	if _, err := json.Marshal(plan); err == nil || strings.Contains(fmt.Sprintf("%#v", plan), "OWNER-SECRET") {
		t.Fatalf("repair Plan rendered protected material: %#v", plan)
	}
	if repeated, finding := controlledPlanRepair(RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{contribution}, ChangeSet: "repair-revision-8", Capability: capability, Disk: disk}); repeated != nil || finding == nil {
		t.Fatalf("reused repair candidate = (%+v, %+v)", repeated, finding)
	}
}

func TestPlanRepairPreservesRealityOnlyCapabilityWithoutProviderWork(t *testing.T) {
	capability, stateSHA := controlledManagedCapability(t, false)
	view := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)}))
	proof := controlledRepairProof(t, "repair-reality-only", 7, stateSHA)
	request := RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{proof}, ChangeSet: proof.ChangeSet, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	plan, finding := controlledPlanRepair(request)
	if finding != nil || plan == nil || plan.Summary().OwningModule != systemchanges.ConnectionProfilesModule {
		t.Fatalf("reality-only PlanRepair() = (%+v, %+v)", plan, finding)
	}
	rechecked := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)})).RepairCandidate()
	approval := &controlledRepairApproval{recheck: RepairRecheck{Candidate: rechecked, Contribution: controlledRepairContribution{proof}, Capability: capability}}
	prepared := controlledRepairPrepared{changeSet: proof.ChangeSet, revision: 8, starting: stateSHA, candidate: strings.Repeat("d", 64), planIdentity: plan.Identity(), planSHA256: plan.SHA256()}
	result := plan.Apply(t.Context(), RepairApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || approval.calls != 1 {
		t.Fatalf("reality-only ApplyRepair() = %+v; calls=%d", result, approval.calls)
	}

	cloudflareStep, err := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	proof.Name, proof.Owner, proof.Steps = "Cloudflare Tunnel", systemchanges.CloudflareModule, []systemchanges.Step{cloudflareStep}
	for index := range proof.Checks {
		proof.Checks[index].Owner = systemchanges.CloudflareModule
	}
	request.Candidate = (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)})).RepairCandidate()
	request.Contribution = controlledRepairContribution{proof}
	if plan, finding := controlledPlanRepair(request); plan != nil || finding == nil {
		t.Fatalf("reality-only provider repair = (%+v, %+v)", plan, finding)
	}
}

func TestPlanRepairRejectsObservationChangedAfterView(t *testing.T) {
	capability, stateSHA := controlledManagedCapability(t, true)
	adapter := &repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)}
	view := (LegacyInterface{}).ViewRepair(systemchanges.New(adapter))
	proof := controlledRepairProof(t, "repair-revision-8-changed", 7, stateSHA)
	adapter.observation.VolatileSHA256 = strings.Repeat("e", 64)
	plan, finding := controlledPlanRepair(RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{proof}, ChangeSet: proof.ChangeSet, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if plan != nil || finding == nil {
		t.Fatalf("changed observation PlanRepair() = (%+v, %+v)", plan, finding)
	}
}

func TestPlanRepairRejectsCallerAuthoredContributions(t *testing.T) {
	capability, stateSHA := controlledManagedCapability(t, true)
	view := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)}))
	proof := controlledRepairProof(t, "repair-forged-contribution", 7, stateSHA)
	plan, finding := PlanRepair(RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{proof}, ChangeSet: proof.ChangeSet, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if plan != nil || finding == nil {
		t.Fatalf("caller-authored contribution = (%+v, %+v)", plan, finding)
	}
}

func controlledPlanRepair(request RepairPlanRequest) (*RepairPlan, *InstallFinding) {
	revision, stateSHA256, volatileSHA256, valid := consumeRepairCandidate(request.Candidate)
	if !valid {
		return nil, &InstallFinding{Code: RepairPlanRefused}
	}
	return buildRepairPlan(request, request.Contribution.SoftwareLifecycleRepairContribution(), revision, stateSHA256, volatileSHA256)
}

func controlledRepairProof(t *testing.T, changeSet string, revision uint64, stateSHA string) RepairContributionProof {
	t.Helper()
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	return RepairContributionProof{
		Name: "Connection Profiles", Owner: systemchanges.ConnectionProfilesModule, Identity: "profiles-current-state-repair", SHA256: strings.Repeat("b", 64), StableSHA256: strings.Repeat("c", 64),
		ChangeSet: changeSet, CurrentRevision: revision, CurrentStateSHA256: stateSHA, Steps: []systemchanges.Step{step},
		Checks: []systemchanges.Check{
			{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REPAIR-CANDIDATE"},
			{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REPAIR-AGREEMENT"},
		},
		Details: []string{"restore generated Xray and sing-box configuration from current Desired State; do not adopt Observed State"},
	}
}

func TestApplyRepairRechecksAndHandsOneRepairChangeSetToSystemChanges(t *testing.T) {
	capability, stateSHA := controlledManagedCapability(t, true)
	candidateSHA := strings.Repeat("d", 64)
	changes := systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)})
	view := (LegacyInterface{}).ViewRepair(changes)
	proof := controlledRepairProof(t, "repair-revision-8-apply", 7, stateSHA)
	plan, finding := controlledPlanRepair(RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{proof}, ChangeSet: proof.ChangeSet, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if finding != nil {
		t.Fatal(finding)
	}
	rechecked := (LegacyInterface{}).ViewRepair(changes).RepairCandidate()
	approval := &controlledRepairApproval{recheck: RepairRecheck{Candidate: rechecked, Contribution: controlledRepairContribution{proof}, Capability: capability}}
	prepared := controlledRepairPrepared{changeSet: proof.ChangeSet, revision: 8, starting: stateSHA, candidate: candidateSHA, planIdentity: plan.Identity(), planSHA256: plan.SHA256()}
	result := plan.Apply(t.Context(), RepairApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: systemchanges.New(nil)})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || approval.calls != 1 {
		t.Fatalf("Apply() = %+v; calls=%d", result, approval.calls)
	}
	if repeated := plan.Apply(t.Context(), RepairApplyRequest{Approval: approval}); repeated.Finding == nil || repeated.Finding.Code != "SOFTWARE-LIFECYCLE-REPAIR-PLAN-USED" || approval.calls != 1 {
		t.Fatalf("reused Apply() = %+v; calls=%d", repeated, approval.calls)
	}
}

func TestApplyRepairRejectsAStaleObservedState(t *testing.T) {
	capability, stateSHA := controlledManagedCapability(t, true)
	view := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: repairObservation(systemchanges.CurrentStateDrift, stateSHA)}))
	proof := controlledRepairProof(t, "repair-revision-8-stale", 7, stateSHA)
	plan, finding := controlledPlanRepair(RepairPlanRequest{Candidate: view.RepairCandidate(), Contribution: controlledRepairContribution{proof}, ChangeSet: proof.ChangeSet, Capability: capability, Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}})
	if finding != nil {
		t.Fatal(finding)
	}
	changed := repairObservation(systemchanges.CurrentStateDrift, stateSHA)
	changed.VolatileSHA256 = strings.Repeat("e", 64)
	rechecked := (LegacyInterface{}).ViewRepair(systemchanges.New(&repairObservationAdapter{observation: changed})).RepairCandidate()
	approval := &controlledRepairApproval{recheck: RepairRecheck{Candidate: rechecked, Contribution: controlledRepairContribution{proof}, Capability: capability}}
	result := plan.Apply(t.Context(), RepairApplyRequest{Approval: approval})
	if result.Finding == nil || result.Finding.Code != "SOFTWARE-LIFECYCLE-REPAIR-STALE" || !result.NothingChanged {
		t.Fatalf("stale Apply() = %+v", result)
	}
}
