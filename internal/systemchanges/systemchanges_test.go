package systemchanges_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type memoryAdapter struct {
	observation systemchanges.Observation
	lockHeld    bool
	lockErr     error
	closeErr    error
	lockCloses  atomic.Int32
}

func (a *memoryAdapter) Observe() (systemchanges.Observation, error) { return a.observation, nil }
func (a *memoryAdapter) TryLock() (systemchanges.Lock, bool, error) {
	if a.lockErr != nil {
		return nil, false, a.lockErr
	}
	if a.lockHeld {
		return nil, false, nil
	}
	return memoryLock{closes: &a.lockCloses, err: a.closeErr}, true, nil
}

type memoryLock struct {
	closes *atomic.Int32
	err    error
}

func (lock memoryLock) Close() error { lock.closes.Add(1); return lock.err }

type preparedState struct{}

func (preparedState) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return "change-0008", 8, sha('1'), sha('3'), "caller-plan", sha('4'), true
}
func (preparedState) SystemChangesConsume(any, string, string) (any, error) { return nil, nil }
func (preparedState) String() string                                        { return "SECRET-MARKER-prepared-state" }

func TestInspectReportsOnlyFourSecretSafeTransactionStates(t *testing.T) {
	tests := []struct {
		status     systemchanges.InstallationStatus
		current    string
		last       string
		rollback   bool
		cause      systemchanges.RecoveryCause
		checkpoint systemchanges.Checkpoint
		completed  int
		total      int
		actions    []systemchanges.Action
	}{
		{status: systemchanges.NotInstalled, checkpoint: systemchanges.NoCheckpoint, actions: []systemchanges.Action{systemchanges.InspectAction, systemchanges.ApplyAction}},
		{status: systemchanges.Managed, last: "change-0007", checkpoint: systemchanges.NoCheckpoint, actions: []systemchanges.Action{systemchanges.InspectAction, systemchanges.ApplyAction}},
		{status: systemchanges.ChangeInProgress, current: "change-0008", last: "change-0007", rollback: true, checkpoint: systemchanges.PreparedCheckpoint, completed: 2, total: 5, actions: []systemchanges.Action{systemchanges.InspectAction}},
		{status: systemchanges.RecoveryRequired, current: "change-0008", last: "change-0007", rollback: true, cause: systemchanges.RollbackStepUnprovable, checkpoint: systemchanges.PreparedCheckpoint, completed: 2, total: 5, actions: []systemchanges.Action{systemchanges.InspectAction, systemchanges.DiagnosticsAction, systemchanges.RetryRollbackAction, systemchanges.CheckAgainAction, systemchanges.BackAction, systemchanges.CompleteRemovalAction}},
	}
	for _, test := range tests {
		t.Run(string(test.status), func(t *testing.T) {
			adapter := &memoryAdapter{observation: systemchanges.Observation{
				Status: test.status, CurrentChangeSet: test.current, LastChangeSet: test.last,
				Checkpoint: test.checkpoint, CompletedSteps: test.completed, TotalSteps: test.total,
				Lock: systemchanges.LockHeld, RollbackAvailable: test.rollback, RecoveryCause: test.cause,
			}}
			result := systemchanges.New(adapter).Inspect()
			if result.Status != test.status || result.CurrentChangeSet != test.current || result.LastChangeSet != test.last || result.Checkpoint != test.checkpoint || result.CompletedSteps != test.completed || result.TotalSteps != test.total || result.Lock != systemchanges.LockHeld || result.RollbackAvailable != test.rollback || fmt.Sprint(result.AllowedActions) != fmt.Sprint(test.actions) {
				t.Fatalf("Inspect() = %+v", result)
			}
			wantPolicies := []systemchanges.ActivityPolicy{
				{Activity: systemchanges.ScheduledHealthActivity, Decision: systemchanges.ActivityDeferred},
				{Activity: systemchanges.UpdateDiscoveryActivity, Decision: systemchanges.ActivityAllowed},
				{Activity: systemchanges.ReleaseVerificationActivity, Decision: systemchanges.ActivityAllowed},
				{Activity: systemchanges.CertificateRenewalActivity, Decision: systemchanges.ActivityDeferredAndReplan},
			}
			if fmt.Sprint(result.ActivityPolicies) != fmt.Sprint(wantPolicies) {
				t.Fatalf("activity policies = %+v", result.ActivityPolicies)
			}
			encoded, err := json.Marshal(result)
			if err != nil || strings.Contains(string(encoded), "SECRET-MARKER") || strings.Contains(fmt.Sprintf("%+v", result), "SECRET-MARKER") || test.status != systemchanges.RecoveryRequired && strings.Contains(string(encoded), `"correction"`) {
				t.Fatalf("Inspect exposed protected material: %s %v", encoded, err)
			}
		})
	}
}

func TestRecoveryRequiredExposesOnlyItsExactSafeActions(t *testing.T) {
	for _, test := range []struct {
		name        string
		observation systemchanges.Observation
		actions     []systemchanges.Action
		option      systemchanges.Action
		freshPlan   bool
		external    bool
	}{
		{
			name: "valid unfinished rollback", observation: systemchanges.Observation{
				Status: systemchanges.RecoveryRequired, CurrentChangeSet: "change-0008", LastChangeSet: "change-0007", Checkpoint: systemchanges.PreparedCheckpoint,
				TotalSteps: 1, Lock: systemchanges.LockReleased, RollbackAvailable: true, RecoveryCause: systemchanges.RollbackStepUnprovable,
			},
			actions: []systemchanges.Action{systemchanges.InspectAction, systemchanges.DiagnosticsAction, systemchanges.RetryRollbackAction, systemchanges.CheckAgainAction, systemchanges.BackAction, systemchanges.CompleteRemovalAction}, option: systemchanges.RetryRollbackAction,
		},
		{
			name: "valid current State drift", observation: systemchanges.Observation{
				Status: systemchanges.RecoveryRequired, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
				StateRevision: 7, StateSHA256: sha('1'), ForwardRepairAvailable: true, RecoveryCause: systemchanges.CurrentStateDrift,
			},
			actions: []systemchanges.Action{systemchanges.InspectAction, systemchanges.DiagnosticsAction, systemchanges.ForwardRepairAction, systemchanges.CheckAgainAction, systemchanges.BackAction, systemchanges.CompleteRemovalAction}, option: systemchanges.ForwardRepairAction, freshPlan: true,
		},
		{
			name: "missing State", observation: systemchanges.Observation{
				Status: systemchanges.RecoveryRequired, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, RecoveryCause: systemchanges.StateLineageUnprovable,
			},
			actions: []systemchanges.Action{systemchanges.InspectAction, systemchanges.DiagnosticsAction, systemchanges.CheckAgainAction, systemchanges.BackAction, systemchanges.CompleteRemovalAction}, external: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := systemchanges.New(&memoryAdapter{observation: test.observation}).Inspect()
			wantSource := systemchanges.SBXROwnedCorrection
			if test.external {
				wantSource = systemchanges.ExternalCorrection
			}
			if result.Status != systemchanges.RecoveryRequired || fmt.Sprint(result.AllowedActions) != fmt.Sprint(test.actions) || result.Correction == nil || result.Correction.Source != wantSource || result.Correction.SBXROption != test.option || result.Correction.FreshPlanRequired != test.freshPlan || (len(result.Correction.OwnerWorkPlan) > 0) != test.external || result.Correction.CheckAgain == "" || result.Correction.Back == "" {
				t.Fatalf("Recovery Required inspection = %+v", result)
			}
			for _, forbidden := range []systemchanges.Action{"Adopt discovered State", "Bypass journal", "Mark transaction complete", "Force service start", "Delete evidence", "Force unlock", "Select historical item", "Restore", "Reconstruct secret", "Repair missing Desired State"} {
				if containsAction(result.AllowedActions, forbidden) {
					t.Fatalf("unsafe action %q offered in %+v", forbidden, result.AllowedActions)
				}
			}
			encoded, err := json.Marshal(result)
			if err != nil || strings.Contains(string(encoded), "Continue anyway") || strings.Contains(string(encoded), "restore menu") || strings.Contains(string(encoded), "SECRET-MARKER") {
				t.Fatalf("unsafe recovery inspection = %s, %v", encoded, err)
			}
		})
	}
	for _, cause := range []systemchanges.RecoveryCause{
		systemchanges.StateLineageUnprovable, systemchanges.SnapshotUnprovable, systemchanges.JournalUnprovable,
		systemchanges.ForwardCheckpointUnprovable, systemchanges.RollbackStepUnprovable, systemchanges.PriorAgreementUnprovable,
		systemchanges.MissingSecrets, systemchanges.ReplacementVPS, systemchanges.OlderRevision, systemchanges.OwnerRegret,
	} {
		t.Run(string(cause), func(t *testing.T) {
			adapter := &memoryAdapter{observation: systemchanges.Observation{Status: systemchanges.RecoveryRequired, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, RecoveryCause: cause}}
			module := systemchanges.New(adapter)
			result := module.CheckAgain()
			want := []systemchanges.Action{systemchanges.InspectAction, systemchanges.DiagnosticsAction, systemchanges.CheckAgainAction, systemchanges.BackAction, systemchanges.CompleteRemovalAction}
			if fmt.Sprint(result.AllowedActions) != fmt.Sprint(want) || result.Correction == nil || result.Correction.Source != systemchanges.ExternalCorrection || len(result.Correction.OwnerWorkPlan) != 3 || adapter.lockCloses.Load() != 0 {
				t.Fatalf("%s correction = %+v", cause, result)
			}
		})
	}
}

func TestRecoveryOptionsRequireExactEligibilityFacts(t *testing.T) {
	for _, observation := range []systemchanges.Observation{
		{Status: systemchanges.RecoveryRequired, CurrentChangeSet: "change-0008", Checkpoint: systemchanges.PreparedCheckpoint, TotalSteps: 1, Lock: systemchanges.LockReleased, RollbackAvailable: true, RecoveryCause: systemchanges.JournalUnprovable},
		{Status: systemchanges.RecoveryRequired, CurrentChangeSet: "change-0008", Checkpoint: systemchanges.PreparedCheckpoint, TotalSteps: 1, Lock: systemchanges.LockReleased, ForwardRepairAvailable: true, RecoveryCause: systemchanges.CurrentStateDrift, StateRevision: 7, StateSHA256: sha('1')},
	} {
		result := systemchanges.New(&memoryAdapter{observation: observation}).Inspect()
		if result.Status != systemchanges.RecoveryRequired || result.RollbackAvailable || result.ForwardRepairAvailable || containsAction(result.AllowedActions, systemchanges.RetryRollbackAction) || containsAction(result.AllowedActions, systemchanges.ForwardRepairAction) {
			t.Fatalf("invalid recovery eligibility = %+v", result)
		}
	}
}

func containsAction(actions []systemchanges.Action, wanted systemchanges.Action) bool {
	for _, action := range actions {
		if action == wanted {
			return true
		}
	}
	return false
}

func TestRecoveryRequiredBlocksNormalMutationAndAdmitsOnlyValidForwardRepair(t *testing.T) {
	unsafe := systemchanges.Observation{
		Status: systemchanges.RecoveryRequired, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
		RecoveryCause: systemchanges.StateLineageUnprovable, StateRevision: 7, StateSHA256: sha('1'), VolatileSHA256: sha('2'),
		FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service",
	}
	for _, mutation := range []systemchanges.MutationClass{
		systemchanges.InstallationMutation, systemchanges.RepairMutation, systemchanges.SettingChangeMutation,
		systemchanges.RotationMutation, systemchanges.UpdateMutation, systemchanges.CertificateRenewalMutation,
	} {
		blockedChange, err := systemchanges.NewChangeSet(completeSpec(t, mutation))
		if err != nil {
			t.Fatal(err)
		}
		result := systemchanges.New(&memoryAdapter{observation: unsafe}).Apply(blockedChange)
		if result.Outcome != systemchanges.Refused || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-RECOVERY-BLOCKED" || !result.NothingChanged {
			t.Fatalf("normal Recovery Required %s = %+v", mutation, result)
		}
	}

	repair := completeSpec(t, systemchanges.RepairMutation)
	repairChange, err := systemchanges.NewChangeSet(repair)
	if err != nil {
		t.Fatal(err)
	}
	drift := unsafe
	drift.LastChangeSet = "change-0007"
	drift.RecoveryCause = systemchanges.CurrentStateDrift
	drift.ForwardRepairAvailable = true
	result := systemchanges.New(&memoryAdapter{observation: drift}).Apply(repairChange)
	if result.Outcome != systemchanges.Refused || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-PREPARED-STATE" {
		t.Fatalf("valid forward repair admission = %+v", result)
	}
}

func TestApplyRejectsCallerMadePreparedState(t *testing.T) {
	adapter := &memoryAdapter{observation: completeObservation()}
	result := systemchanges.New(adapter).Apply(completeChangeSet(t, systemchanges.SettingChangeMutation))
	if result.Outcome != systemchanges.Refused || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-PREPARED-STATE" || adapter.lockCloses.Load() != 1 {
		t.Fatalf("caller-made prepared State = %+v; lock closes = %d", result, adapter.lockCloses.Load())
	}
}

func TestApplyRefusesUnsafeWorkBeforeMutation(t *testing.T) {
	tests := []struct {
		name    string
		observe func(*systemchanges.Observation)
		spec    func(*systemchanges.ChangeSetSpec)
		check   func(*systemchanges.Check)
		code    string
		found   string
	}{
		{name: "changed State revision", observe: func(observed *systemchanges.Observation) { observed.StateRevision = 8 }, code: "SYSTEM-CHANGES-STALE"},
		{name: "changed State checksum", observe: func(observed *systemchanges.Observation) { observed.StateSHA256 = sha('9') }, code: "SYSTEM-CHANGES-STALE"},
		{name: "changed volatile binding", observe: func(observed *systemchanges.Observation) { observed.VolatileSHA256 = sha('9') }, code: "SYSTEM-CHANGES-STALE"},
		{name: "no-op", spec: func(spec *systemchanges.ChangeSetSpec) { spec.TargetStateSHA256 = spec.StartingState.SHA256 }, code: "SYSTEM-CHANGES-NO-OP"},
		{name: "low disk", observe: func(observed *systemchanges.Observation) { observed.AvailableBytes = 2 << 30 }, code: "SYSTEM-CHANGES-DISK", found: "2147483648 bytes available"},
		{name: "unsynchronized time", observe: func(observed *systemchanges.Observation) { observed.WallTimeSynchronized = false }, code: "SYSTEM-CHANGES-TIME"},
		{name: "missing monotonic clock", observe: func(observed *systemchanges.Observation) { observed.MonotonicClock = false }, code: "SYSTEM-CHANGES-TIME"},
		{name: "Required Needs attention", check: func(check *systemchanges.Check) { check.Status = systemchanges.NeedsAttention }, code: "SYSTEM-CHANGES-CHECK"},
		{name: "Required Failed", check: func(check *systemchanges.Check) { check.Status = systemchanges.Failed }, code: "SYSTEM-CHANGES-CHECK"},
		{name: "Required Unknown", check: func(check *systemchanges.Check) { check.Status = systemchanges.Unknown }, code: "SYSTEM-CHANGES-CHECK"},
		{name: "undisclosed Advisory Needs attention", check: func(check *systemchanges.Check) {
			check.Classification = systemchanges.Advisory
			check.Status = systemchanges.NeedsAttention
			check.Disclosed = false
		}, code: "SYSTEM-CHANGES-CHECK"},
		{name: "Advisory Failed", check: func(check *systemchanges.Check) {
			check.Classification = systemchanges.Advisory
			check.Status = systemchanges.Failed
		}, code: "SYSTEM-CHANGES-CHECK"},
		{name: "Advisory Unknown", check: func(check *systemchanges.Check) {
			check.Classification = systemchanges.Advisory
			check.Status = systemchanges.Unknown
		}, code: "SYSTEM-CHANGES-CHECK"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observed := completeObservation()
			if test.observe != nil {
				test.observe(&observed)
			}
			spec := completeSpec(t, systemchanges.SettingChangeMutation)
			if test.spec != nil {
				test.spec(&spec)
			}
			if test.check != nil {
				test.check(&spec.Checks[0])
			}
			changeSet, err := systemchanges.NewChangeSet(spec)
			if err != nil {
				t.Fatal(err)
			}
			adapter := &memoryAdapter{observation: observed}
			module := systemchanges.New(adapter)
			result := module.Apply(changeSet)
			if result.Outcome != systemchanges.Refused || !result.NothingChanged || !result.PlanConsumed || result.Finding == nil || result.Finding.Code != test.code || result.Evidence != (systemchanges.EvidenceRules{SecretSafeOnly: true}) || result.QueueCreated || adapter.lockCloses.Load() != 1 {
				t.Fatalf("Apply() = %+v; lock closes = %d", result, adapter.lockCloses.Load())
			}
			if test.found != "" && result.Finding.Found != test.found {
				t.Fatalf("found = %q, want %q", result.Finding.Found, test.found)
			}
			encoded, err := json.Marshal(result)
			if err != nil || strings.Contains(string(encoded), "SECRET-MARKER") || strings.Contains(fmt.Sprintf("%+v", result), "SECRET-MARKER") {
				t.Fatalf("Apply exposed protected material: %s %v", encoded, err)
			}
			reused := module.Apply(changeSet)
			if reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
				t.Fatalf("refused authority was reusable: %+v", reused)
			}
		})
	}
}

func TestApplyNeverQueuesOrStealsHeldLock(t *testing.T) {
	for _, mutation := range []systemchanges.MutationClass{systemchanges.SettingChangeMutation, systemchanges.CertificateRenewalMutation} {
		adapter := &memoryAdapter{observation: completeObservation(), lockHeld: true}
		module := systemchanges.New(adapter)
		changeSet := completeChangeSet(t, mutation)
		result := module.Apply(changeSet)
		want, replan := systemchanges.Refused, false
		if mutation == systemchanges.CertificateRenewalMutation {
			want, replan = systemchanges.Deferred, true
		}
		if result.Outcome != want || !result.NothingChanged || !result.PlanConsumed || result.QueueCreated || result.RebuildPlan != replan || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-BUSY" || adapter.lockCloses.Load() != 0 {
			t.Fatalf("held-lock %s result = %+v", mutation, result)
		}
		if reused := module.Apply(changeSet); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
			t.Fatalf("held-lock %s authority was reusable: %+v", mutation, reused)
		}
	}
}

func TestChangeInProgressDefersScheduledActivityAfterWorkerExit(t *testing.T) {
	result := systemchanges.New(&memoryAdapter{observation: systemchanges.Observation{
		Status: systemchanges.ChangeInProgress, CurrentChangeSet: "change-0008", LastChangeSet: "change-0007",
		Checkpoint: systemchanges.PreparedCheckpoint, TotalSteps: 5, Lock: systemchanges.LockReleased,
	}}).Inspect()
	if result.ActivityPolicies[0].Decision != systemchanges.ActivityDeferred || result.ActivityPolicies[1].Decision != systemchanges.ActivityAllowed || result.ActivityPolicies[2].Decision != systemchanges.ActivityAllowed || result.ActivityPolicies[3].Decision != systemchanges.ActivityDeferredAndReplan {
		t.Fatalf("released-lock in-progress policies = %+v", result.ActivityPolicies)
	}
}

func TestApplyDistinguishesUnsafeLockInfrastructureAndReleaseFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		adapter *memoryAdapter
		code    string
	}{
		{name: "lock infrastructure error", adapter: &memoryAdapter{observation: completeObservation(), lockErr: errors.New("unsafe lock path")}, code: "SYSTEM-CHANGES-LOCK-UNPROVABLE"},
		{name: "lock release error", adapter: &memoryAdapter{observation: completeObservation(), closeErr: errors.New("unlock failed")}, code: "SYSTEM-CHANGES-LOCK-RELEASE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := systemchanges.New(test.adapter).Apply(completeChangeSet(t, systemchanges.SettingChangeMutation))
			if result.Outcome != systemchanges.Refused || result.Finding == nil || result.Finding.Code != test.code || !result.NothingChanged || !result.PlanConsumed {
				t.Fatalf("Apply() = %+v", result)
			}
		})
	}
}

func TestChangeSetRejectsUntypedMutationSurfaces(t *testing.T) {
	spec := completeSpec(t, systemchanges.SettingChangeMutation)
	spec.PreparedState = nil
	if _, err := systemchanges.NewChangeSet(spec); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-CHANGE-SET-INVALID") {
		t.Fatalf("untyped prepared State error = %v", err)
	}
	if _, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.OperationKind("/bin/sh"), systemchanges.RestorePriorConfiguration); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-STEP-INVALID") {
		t.Fatalf("arbitrary operation error = %v", err)
	}
	if _, err := systemchanges.NewStep(systemchanges.StateModule, systemchanges.OperationKind("Publish prepared State"), systemchanges.RestorePriorConfiguration); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-STEP-INVALID") {
		t.Fatalf("ordinary State publication step error = %v", err)
	}
	clientCheck := completeSpec(t, systemchanges.SettingChangeMutation)
	clientCheck.Checks[0].Scope = systemchanges.ClientDeviceCheck
	if _, err := systemchanges.NewChangeSet(clientCheck); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-CHECK-INVALID") {
		t.Fatalf("client device gate error = %v", err)
	}
	unphased := completeSpec(t, systemchanges.SettingChangeMutation)
	for index := range unphased.Checks {
		unphased.Checks[index].Phase = systemchanges.PrePublication
	}
	if _, err := systemchanges.NewChangeSet(unphased); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-CHECK-INVALID") {
		t.Fatalf("missing post-publication gate error = %v", err)
	}
	unreversible := completeSpec(t, systemchanges.SettingChangeMutation)
	unreversible.Steps[0] = systemchanges.Step{}
	if _, err := systemchanges.NewChangeSet(unreversible); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-STEP-INVALID") {
		t.Fatalf("unproven reverse step error = %v", err)
	}
	for _, change := range []func(*systemchanges.ChangeSetSpec){
		func(spec *systemchanges.ChangeSetSpec) { spec.Timeouts.Step = 24*time.Hour + time.Nanosecond },
		func(spec *systemchanges.ChangeSetSpec) { spec.Timeouts.Check = time.Hour + time.Nanosecond },
		func(spec *systemchanges.ChangeSetSpec) { spec.Disk.PreparationBytes = ^uint64(0) },
	} {
		invalid := completeSpec(t, systemchanges.SettingChangeMutation)
		change(&invalid)
		if _, err := systemchanges.NewChangeSet(invalid); err == nil || !strings.Contains(err.Error(), "SYSTEM-CHANGES-CHANGE-SET-INVALID") {
			t.Fatalf("unbounded Change Set error = %v", err)
		}
	}
	result := systemchanges.New(&memoryAdapter{observation: completeObservation()}).Apply(nil)
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" || !result.NothingChanged {
		t.Fatalf("nil Apply = %+v", result)
	}
}

func completeObservation() systemchanges.Observation {
	return systemchanges.Observation{
		Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
		StateRevision: 7, StateSHA256: sha('1'), VolatileSHA256: sha('2'),
		FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30,
		WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service",
	}
}

func completeChangeSet(t *testing.T, mutation systemchanges.MutationClass) *systemchanges.ChangeSet {
	t.Helper()
	changeSet, err := systemchanges.NewChangeSet(completeSpec(t, mutation))
	if err != nil {
		t.Fatal(err)
	}
	return changeSet
}

func completeSpec(t *testing.T, mutation systemchanges.MutationClass) systemchanges.ChangeSetSpec {
	t.Helper()
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	spec := systemchanges.ChangeSetSpec{
		Identity: "change-0008", Mutation: mutation, OutcomeOwner: systemchanges.ConnectionProfilesModule,
		StartingState:     systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: sha('1')},
		TargetStateSHA256: sha('3'),
		Plan:              systemchanges.PlanBinding{Identity: fmt.Sprintf("plan-systemchanges-%d", planSequence.Add(1)), SHA256: sha('4'), VolatileSHA256: sha('2')},
		PreparedState:     preparedState{}, Steps: []systemchanges.Step{step},
		Checks: []systemchanges.Check{
			{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"},
			{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-REQUIRED"},
			{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-ACTIVE"},
			{Owner: systemchanges.HealthDiagnosticsModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Advisory, Status: systemchanges.NeedsAttention, Code: "HEALTH-ADVISORY", Disclosed: true},
		},
		Timeouts: systemchanges.Timeouts{Step: 30 * time.Second, Check: 60 * time.Second},
		Disk:     systemchanges.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100},
	}
	if mutation == systemchanges.InstallationMutation {
		spec.StartingState = systemchanges.StateLineage{Status: systemchanges.NotInstalled}
	}
	return spec
}

func sha(character byte) string { return strings.Repeat(string(character), 64) }

var planSequence atomic.Uint64
