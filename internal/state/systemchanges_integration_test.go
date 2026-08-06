package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
	"github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type systemChangesAdapter struct {
	observation     systemchanges.Observation
	closes          atomic.Int32
	events          []string
	artifacts       map[string][]byte
	statuses        map[systemchanges.GatePhase]systemchanges.HealthStatus
	beforeStep      func() error
	prepareErr      error
	closeErr        error
	stepEvidence    *systemchanges.StepEvidence
	lease           systemchanges.ExecutionLease
	executeCount    int
	failStep        int
	failReverse     bool
	agreementErr    error
	serviceErr      error
	holdErr         error
	recoveryLoadErr error
	inspectionErr   error
	restoreErr      error
	noRecovery      bool
	recovery        *systemchanges.RecoveryTransaction
	stateRecovery   systemchanges.StateRecovery
	stateBinding    []byte
	crashBefore     systemchanges.DurableCheckpoint
	crashAfter      systemchanges.DurableCheckpoint
	crashed         bool
}

func (a *systemChangesAdapter) Observe() (systemchanges.Observation, error) {
	return a.observation, nil
}

func (a *systemChangesAdapter) TryLock() (systemchanges.Lock, bool, error) {
	return systemChangesLock{closes: &a.closes, err: a.closeErr}, true, nil
}

type systemChangesLock struct {
	closes *atomic.Int32
	err    error
}

func (lock systemChangesLock) Close() error { lock.closes.Add(1); return lock.err }

func (a *systemChangesAdapter) Prepare(lease systemchanges.ExecutionLease, preparation systemchanges.Preparation) error {
	a.lease = lease
	if a.prepareErr != nil {
		return a.prepareErr
	}
	a.artifacts = map[string][]byte{}
	if err := preparation.WriteStateArtifacts(func(name string, _ uint32, source io.Reader) error {
		content, err := io.ReadAll(source)
		if err == nil {
			a.artifacts[name] = content
		}
		return err
	}); err != nil {
		return err
	}
	if a.crashBefore == systemchanges.Prepared && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	a.events = append(a.events, string(systemchanges.Prepared))
	a.recovery = &systemchanges.RecoveryTransaction{
		ChangeSet: preparation.ChangeSet, Starting: preparation.Starting, StartingRelease: preparation.State.StartingRelease,
		Candidate: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: preparation.State.CandidateRevision, SHA256: preparation.State.CandidateSHA256}, CandidateRelease: preparation.State.CandidateRelease,
		OutcomeOwner: preparation.OutcomeOwner, Steps: append([]systemchanges.Step(nil), preparation.Steps...), LastCheckpoint: systemchanges.Prepared, Timeouts: preparation.Timeouts,
	}
	a.stateBinding, _ = json.Marshal(preparation.State)
	if a.crashAfter == systemchanges.Prepared && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	return nil
}

func (a *systemChangesAdapter) Record(_ systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	if a.crashBefore == record.Checkpoint && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	a.events = append(a.events, record.String())
	if a.recovery != nil {
		a.recovery.LastCheckpoint = record.Checkpoint
		switch record.Checkpoint {
		case systemchanges.StepStarted:
			if record.Step > a.recovery.AttemptedSteps {
				a.recovery.AttemptedSteps = record.Step
			}
		case systemchanges.RollbackStarted:
			a.recovery.RollbackStep = a.recovery.AttemptedSteps
		case systemchanges.RollbackStepStarted:
			a.recovery.RollbackStep = record.Step
		case systemchanges.RollbackStepCompleted:
			a.recovery.RollbackStep = record.Step - 1
		case systemchanges.RollbackVerified, systemchanges.RolledBack:
			a.recovery.RollbackStep = 0
		}
	}
	if a.crashAfter == record.Checkpoint && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	return nil
}

func (a *systemChangesAdapter) Execute(_ systemchanges.ExecutionLease, step systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	a.executeCount++
	a.events = append(a.events, "execute "+string(step.Forward()))
	if a.executeCount == a.failStep {
		return systemchanges.StepEvidence{}, errors.New("controlled deterministic step failure")
	}
	if a.beforeStep != nil {
		if err := a.beforeStep(); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if a.stepEvidence != nil {
		return *a.stepEvidence, nil
	}
	return systemchanges.StepEvidence{Code: "step-ok", SHA256: testSHA('a')}, nil
}

func (a *systemChangesAdapter) Reverse(_ systemchanges.ExecutionLease, _ string, _ int, step systemchanges.Step, _ time.Duration) (systemchanges.StepEvidence, error) {
	a.events = append(a.events, "reverse "+string(step.Rollback()))
	if a.failReverse {
		return systemchanges.StepEvidence{}, errors.New("controlled rollback failure")
	}
	return systemchanges.StepEvidence{Code: "rollback-ok", SHA256: testSHA('b')}, nil
}

func (a *systemChangesAdapter) VerifyRollback(_ systemchanges.ExecutionLease, _ systemchanges.RollbackAgreement, _ time.Duration) error {
	a.events = append(a.events, "rollback verified")
	return nil
}

func (a *systemChangesAdapter) Check(_ systemchanges.ExecutionLease, check systemchanges.Check, phase systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	a.events = append(a.events, "check "+string(phase)+" "+check.Code)
	if status := a.statuses[phase]; status != "" && check.Code == "NETWORK-GATE" {
		return status, nil
	}
	return check.Status, nil
}

func (a *systemChangesAdapter) VerifyAgreement(systemchanges.ExecutionLease, systemchanges.Agreement, time.Duration) error {
	a.events = append(a.events, "agreement verified")
	return a.agreementErr
}

func (a *systemChangesAdapter) Cleanup(systemchanges.ExecutionLease, string) error {
	a.events = append(a.events, "cleanup")
	a.recovery = nil
	return nil
}

func (a *systemChangesAdapter) LoadRecovery(systemchanges.ExecutionLease) (systemchanges.RecoveryTransaction, error) {
	if a.recoveryLoadErr != nil {
		return systemchanges.RecoveryTransaction{}, a.recoveryLoadErr
	}
	if a.noRecovery {
		return systemchanges.RecoveryTransaction{}, systemchanges.ErrNoRecoveryTransaction
	}
	if a.recovery == nil {
		return systemchanges.RecoveryTransaction{}, errors.New("no durable recovery transaction")
	}
	return *a.recovery, nil
}

func (a *systemChangesAdapter) HoldServices(systemchanges.ExecutionLease) error {
	a.events = append(a.events, "hold public services and timers")
	return nil
}

func (a *systemChangesAdapter) AllowProvenServices(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction, time.Duration) error {
	a.events = append(a.events, "allow proven unrelated services")
	return a.holdErr
}

func (a *systemChangesAdapter) InspectStep(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction, int, systemchanges.Step, time.Duration) (systemchanges.StepEffect, error) {
	a.events = append(a.events, "inspect uncertain step")
	if a.inspectionErr != nil {
		return "", a.inspectionErr
	}
	return systemchanges.StepEffectPresent, nil
}

func (a *systemChangesAdapter) RestoreRecoveryState(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction) (systemchanges.RollbackAgreement, error) {
	a.events = append(a.events, "restore durable State")
	if a.restoreErr != nil {
		return systemchanges.RollbackAgreement{}, a.restoreErr
	}
	if a.stateRecovery != nil {
		agreementJSON, err := a.stateRecovery.SystemChangesRestoreDurable(lease, a.stateBinding, bytes.NewReader(a.artifacts["snapshot/prior-state.json"]), bytes.NewReader(a.artifacts["prepared/state.json"]))
		var agreement systemchanges.RollbackAgreement
		if err != nil || json.Unmarshal(agreementJSON, &agreement) != nil {
			return systemchanges.RollbackAgreement{}, errors.New("State recovery agreement unavailable")
		}
		return agreement, nil
	}
	return systemchanges.RollbackAgreement{Status: recovery.Starting.Status, Revision: recovery.Starting.Revision, SHA256: recovery.Starting.SHA256, Release: recovery.StartingRelease}, nil
}

func (a *systemChangesAdapter) VerifyStartingServices(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction, time.Duration) error {
	a.events = append(a.events, "starting services verified")
	return a.serviceErr
}

func TestPreparedCommitDurablyCompletesOneSystemChangesChangeSet(t *testing.T) {
	stateModule, changeSet, duplicate, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, beforeStep: func() error {
		loaded, err := stateModule.Load(intentManagedRequest())
		if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.Snapshot.LastCompletedChangeSet != "change-0007" {
			return errors.New("old Desired State was not current during forward work")
		}
		return nil
	}}
	boundary := systemchanges.New(adapter)
	result := boundary.Apply(changeSet)
	if result.Outcome != systemchanges.Completed || result.NothingChanged || !result.PlanConsumed || adapter.closes.Load() != 1 || adapter.lease.Authorized() {
		t.Fatalf("Apply() = %+v; lock closes = %d", result, adapter.closes.Load())
	}
	wantEvents := "Prepared,Step started 1,execute Activate prepared configuration,Step completed 1,check Pre-publication NETWORK-PREFLIGHT,Pre-publication health passed,Desired State publication started,Desired State published,check Post-publication NETWORK-PREFLIGHT,agreement verified,Post-publication health passed,Complete,cleanup"
	if got := strings.Join(adapter.events, ","); got != wantEvents {
		t.Fatalf("durable success checkpoints = %s, want %s", got, wantEvents)
	}
	if len(adapter.artifacts) == 0 || strings.Contains(fmt.Sprintf("%+v", result), "SECRET-MARKER") {
		t.Fatal("opaque transaction artifacts were missing or exposed as evidence")
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 8 || loaded.Snapshot.LastCompletedChangeSet != "change-0008" {
		t.Fatalf("published State readback = (%+v, %v)", loaded, err)
	}
	if replayed := boundary.Apply(duplicate); replayed.Finding == nil || replayed.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
		t.Fatalf("duplicate wrapper replayed prepared authority: %+v", replayed)
	}
	if reused := boundary.Apply(changeSet); reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
		t.Fatalf("prepared authority was reusable: %+v", reused)
	}
}

func TestLiveStepFailureRestoresBaselineInSafeReverseOrder(t *testing.T) {
	second, err := systemchanges.NewStep(systemchanges.NetworkPolicyModule, systemchanges.ApplyApprovedNetworkPolicy, systemchanges.RestorePriorNetworkPolicy)
	if err != nil {
		t.Fatal(err)
	}
	stateModule, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, second)
	adapter := &systemChangesAdapter{observation: observed, failStep: 2}
	result := systemchanges.New(adapter).Apply(changeSet)
	if string(result.Outcome) != "Rollback succeeded" || result.RestoredStatus != systemchanges.Managed || result.NothingChanged || !result.PlanConsumed || adapter.closes.Load() != 1 {
		t.Fatalf("failed Apply() = %+v; lock closes = %d", result, adapter.closes.Load())
	}
	wantEvents := "Prepared,Step started 1,execute Activate prepared configuration,Step completed 1,Step started 2,execute Apply approved Network Policy,Rollback started,Rollback step started 2,reverse Restore prior Network Policy,Rollback step completed 2,Rollback step started 1,reverse Restore prior configuration,Rollback step completed 1,rollback verified,Rollback verified,Rolled back,cleanup"
	if got := strings.Join(adapter.events, ","); got != wantEvents {
		t.Fatalf("rollback checkpoints = %s, want %s", got, wantEvents)
	}
	loaded, loadErr := stateModule.Load(intentManagedRequest())
	if loadErr != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.Snapshot.LastCompletedChangeSet != "change-0007" {
		t.Fatalf("restored baseline = (%+v, %v)", loaded, loadErr)
	}
}

func TestExplicitCancellationWaitsForSafeCheckpointThenRollsBack(t *testing.T) {
	cancellation := systemchanges.NewCancellation()
	second, err := systemchanges.NewStep(systemchanges.NetworkPolicyModule, systemchanges.ApplyApprovedNetworkPolicy, systemchanges.RestorePriorNetworkPolicy)
	if err != nil {
		t.Fatal(err)
	}
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, second)
	adapter := &systemChangesAdapter{observation: observed, beforeStep: func() error {
		cancellation.Request()
		cancellation.Request()
		return nil
	}}
	result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
	if result.Outcome != systemchanges.RollbackSucceeded || adapter.executeCount != 1 {
		t.Fatalf("cancelled Apply() = %+v; executed=%d", result, adapter.executeCount)
	}
	want := "Prepared,Step started 1,execute Activate prepared configuration,Step completed 1,Cancellation requested 1,Rollback started,Rollback step started 1,reverse Restore prior configuration,Rollback step completed 1,rollback verified,Rollback verified,Rolled back,cleanup"
	if got := strings.Join(adapter.events, ","); got != want {
		t.Fatalf("cancellation checkpoints = %s, want %s", got, want)
	}
}

func TestCancellationBeforeApplyChangesNothing(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	cancellation := systemchanges.NewCancellation()
	cancellation.Request()
	adapter := &systemChangesAdapter{observation: observed}
	result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
	if result.Outcome != systemchanges.Refused || !result.NothingChanged || !result.PlanConsumed || adapter.closes.Load() != 0 || len(adapter.events) != 0 {
		t.Fatalf("pre-Apply cancellation = %+v; closes=%d events=%v", result, adapter.closes.Load(), adapter.events)
	}
	if duplicate := systemchanges.New(adapter).Apply(changeSet); duplicate.Finding == nil || duplicate.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" {
		t.Fatalf("cancelled Plan was reusable: %+v", duplicate)
	}
}

func TestPostPublicationFailureRestoresPriorDesiredState(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, agreementErr: errors.New("SECRET-MARKER controlled active agreement failure")}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.RollbackSucceeded || result.Finding == nil || result.Finding.Owner != systemchanges.ConnectionProfilesModule || strings.Contains(fmt.Sprintf("%+v", result), "SECRET-MARKER") {
		t.Fatalf("post-publication rollback = %+v", result)
	}
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.Snapshot.LastCompletedChangeSet != "change-0007" {
		t.Fatalf("post-publication restored State = (%+v, %v)", loaded, err)
	}
}

func TestPublicationFailureBeforeOrAfterReplacementRestoresPriorDesiredState(t *testing.T) {
	for _, test := range []struct {
		name    string
		options systemChangeTestOptions
	}{
		{name: "before replacement", options: systemChangeTestOptions{stepTimeout: 30 * time.Second, publishBeforeError: true}},
		{name: "after replacement", options: systemChangeTestOptions{stepTimeout: 30 * time.Second, publishAfterError: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, test.options)
			result := systemchanges.New(&systemChangesAdapter{observation: observed}).Apply(changeSet)
			if result.Outcome != systemchanges.RollbackSucceeded || result.Finding == nil || result.Finding.WhyStopped != "SYSTEM-CHANGES-PUBLICATION" {
				t.Fatalf("publication failure rollback = %+v", result)
			}
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 {
				t.Fatalf("publication failure restored State = (%+v, %v)", loaded, err)
			}
		})
	}
}

func TestUnprovableReversePathEntersRecoveryRequired(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, failStep: 1, failReverse: true}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.NothingChanged || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-RECOVERY-REQUIRED" || result.Finding.Owner != systemchanges.ConnectionProfilesModule {
		t.Fatalf("failed reverse path = %+v", result)
	}
}

func TestFailedInstallationRestoresProvenNotInstalledBaseline(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.InstallationMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"})
	result := systemchanges.New(&systemChangesAdapter{observation: observed, failStep: 1}).Apply(changeSet)
	if result.Outcome != systemchanges.RollbackSucceeded {
		t.Fatalf("installation rollback = %+v", result)
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: CleanVPS})
	if err != nil || loaded.Status != NotInstalled || loaded.Snapshot != nil {
		t.Fatalf("restored clean baseline = (%+v, %v)", loaded, err)
	}
}

func preparedSystemChange(t *testing.T) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeWithCheck(t, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"})
}

func preparedSystemChangeWithCheck(t *testing.T, check systemchanges.Check) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, check)
}

func preparedSystemChangeForMutation(t *testing.T, mutation systemchanges.MutationClass, check systemchanges.Check, extraSteps ...systemchanges.Step) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeWithOptions(t, mutation, check, systemChangeTestOptions{extraSteps: extraSteps, stepTimeout: 30 * time.Second})
}

type systemChangeTestOptions struct {
	extraSteps         []systemchanges.Step
	stepTimeout        time.Duration
	identity           string
	publishBeforeError bool
	publishAfterError  bool
}

func preparedSystemChangeWithOptions(t *testing.T, mutation systemchanges.MutationClass, check systemchanges.Check, options systemChangeTestOptions) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	t.Helper()
	candidate := completeDesiredState()
	candidate.Subscription.Token = NewClientAccessValue(testSHA('e'))
	var module Interface
	var request PrepareRequest
	if mutation == systemchanges.InstallationMutation {
		module = New(&mutableStateStorage{err: fs.ErrNotExist})
		loaded, err := module.Load(LoadRequest{Baseline: CleanVPS})
		if err != nil {
			t.Fatal(err)
		}
		request = preparedRequest(t, loaded, candidate, "change-0001")
	} else {
		storage := &mutableStateStorage{document: documentFor(t, completeDesiredState()), publishBeforeError: options.publishBeforeError, publishAfterError: options.publishAfterError}
		module = New(storage)
		loaded, err := module.Load(intentManagedRequest())
		if err != nil {
			t.Fatal(err)
		}
		identity := options.identity
		if identity == "" {
			identity = "change-0008"
		}
		request = preparedRequest(t, loaded, candidate, ChangeSetIdentity(identity))
	}
	prepared, err := module.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	identity, revision, startingSHA256, target, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid {
		t.Fatal("State returned an invalid prepared binding")
	}
	starting := systemchanges.StateLineage{Status: systemchanges.Managed, Revision: revision - 1, SHA256: startingSHA256}
	observed := systemchanges.Observation{
		Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased,
		StateRevision: revision - 1, StateSHA256: startingSHA256, VolatileSHA256: testSHA('2'),
		FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service",
	}
	if mutation == systemchanges.InstallationMutation {
		starting = systemchanges.StateLineage{Status: systemchanges.NotInstalled}
		observed.Status, observed.LastChangeSet, observed.StateRevision, observed.StateSHA256 = systemchanges.NotInstalled, "", 0, ""
	}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	steps := append([]systemchanges.Step{step}, options.extraSteps...)
	spec := systemchanges.ChangeSetSpec{
		Identity: identity, Mutation: mutation, OutcomeOwner: systemchanges.ConnectionProfilesModule,
		StartingState: starting, TargetStateSHA256: target,
		Plan:          systemchanges.PlanBinding{Identity: planIdentity, SHA256: planSHA256, VolatileSHA256: testSHA('2')},
		PreparedState: prepared, Steps: steps,
		Checks: func() []systemchanges.Check {
			pre, post := check, check
			pre.Phase, post.Phase = systemchanges.PrePublication, systemchanges.PostPublication
			checks := []systemchanges.Check{pre, post}
			if check.Classification == systemchanges.Advisory {
				checks = append(checks,
					systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-REQUIRED-PRE"},
					systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-REQUIRED-POST"},
				)
			}
			return checks
		}(),
		Timeouts: systemchanges.Timeouts{Step: options.stepTimeout, Check: 60 * time.Second},
		Disk: systemchanges.DiskRequirement{
			PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100,
			JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100,
		},
	}
	changeSet, err := systemchanges.NewChangeSet(spec)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := systemchanges.NewChangeSet(spec)
	if err != nil {
		t.Fatal(err)
	}
	return module, changeSet, duplicate, observed
}

func TestEveryMutationClassUsesOneSystemChangesLockBeforeLiveWork(t *testing.T) {
	check := systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}
	for _, mutation := range []systemchanges.MutationClass{
		systemchanges.InstallationMutation, systemchanges.RepairMutation, systemchanges.SettingChangeMutation,
		systemchanges.RotationMutation, systemchanges.UpdateMutation, systemchanges.CertificateRenewalMutation, systemchanges.CompleteRemovalMutation,
	} {
		t.Run(string(mutation), func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChangeForMutation(t, mutation, check)
			adapter := &systemChangesAdapter{observation: observed, prepareErr: errors.New("controlled preparation stop")}
			result := systemchanges.New(adapter).Apply(changeSet)
			if result.Outcome != systemchanges.Refused || !result.NothingChanged || adapter.closes.Load() != 1 || result.Finding == nil || result.Finding.Owner != systemchanges.ConnectionProfilesModule {
				t.Fatalf("%s lock boundary = %+v; closes=%d", mutation, result, adapter.closes.Load())
			}
		})
	}
}

func TestValidCurrentStateDriftCreatesOnlyAFreshForwardRepairChangeSet(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.RepairMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"})
	observed.Status = systemchanges.RecoveryRequired
	observed.RecoveryCause = systemchanges.CurrentStateDrift
	observed.ForwardRepairAvailable = true
	adapter := &systemChangesAdapter{observation: observed}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Completed || adapter.recovery != nil || !strings.HasPrefix(strings.Join(adapter.events, ","), "Prepared,Step started 1") {
		t.Fatalf("forward repair = %+v; events=%v recovery=%+v", result, adapter.events, adapter.recovery)
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 8 {
		t.Fatalf("forward-repair State = (%+v, %v)", loaded, err)
	}
}

func TestSuccessfulChangeSetEnforcesFreshRequiredAndAdvisoryGates(t *testing.T) {
	for _, test := range []struct {
		name          string
		check         systemchanges.Check
		fresh         systemchanges.HealthStatus
		wantCompleted bool
	}{
		{name: "Required Healthy", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Healthy, wantCompleted: true},
		{name: "Required Needs attention", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.NeedsAttention},
		{name: "Required Failed", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Failed},
		{name: "Required Unknown", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Unknown},
		{name: "reviewed Advisory Needs attention", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Advisory, Status: systemchanges.NeedsAttention, Code: "NETWORK-GATE", Disclosed: true}, fresh: systemchanges.NeedsAttention, wantCompleted: true},
		{name: "Advisory Failed", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Advisory, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Failed},
		{name: "Advisory Unknown", check: systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Advisory, Status: systemchanges.Healthy, Code: "NETWORK-GATE"}, fresh: systemchanges.Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChangeWithCheck(t, test.check)
			adapter := &systemChangesAdapter{observation: observed, statuses: map[systemchanges.GatePhase]systemchanges.HealthStatus{systemchanges.PrePublication: test.fresh, systemchanges.PostPublication: test.fresh}}
			result := systemchanges.New(adapter).Apply(changeSet)
			if test.wantCompleted && result.Outcome != systemchanges.Completed || !test.wantCompleted && (result.Outcome != systemchanges.RollbackSucceeded || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ROLLED-BACK") {
				t.Fatalf("fresh gate result = %+v", result)
			}
		})
	}
}

func TestChangedWorkIsNeverReportedAsNothingChangedWhenLockReleaseIsUncertain(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, closeErr: errors.New("unlock failed")}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.NothingChanged || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-LOCK-RELEASE" || result.Finding.Owner != systemchanges.ConnectionProfilesModule {
		t.Fatalf("post-change lock release = %+v", result)
	}
}

func TestStateTransactionBridgeRejectsCallerMadeLease(t *testing.T) {
	candidate := completeDesiredState()
	candidate.Subscription.Token = NewClientAccessValue(testSHA('e'))
	module, request, _ := managedPrepareRequest(t, candidate)
	prepared, err := module.PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
	if !valid {
		t.Fatal("prepared State binding is invalid")
	}
	if _, err := prepared.SystemChangesConsume(systemchanges.ExecutionLease{}, planIdentity, planSHA256); err == nil {
		t.Fatal("caller-made lease consumed State transaction authority")
	}
}

func TestStateRecoveryBridgeRejectsActiveApplyLease(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChange(t)
	rejected := false
	var adapter *systemChangesAdapter
	adapter = &systemChangesAdapter{observation: observed, beforeStep: func() error {
		_, err := stateModule.SystemChangesRestoreDurable(adapter.lease, adapter.stateBinding, bytes.NewReader(adapter.artifacts["snapshot/prior-state.json"]), bytes.NewReader(adapter.artifacts["prepared/state.json"]))
		rejected = err != nil
		return nil
	}}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Completed || !rejected {
		t.Fatalf("ordinary Apply recovery authority = %+v; rejected=%t", result, rejected)
	}
}

func TestStepCompletionRequiresDurableTypedEvidence(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, stepEvidence: &systemchanges.StepEvidence{Code: "step-ok", SHA256: "not-a-checksum"}}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.RollbackSucceeded || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ROLLED-BACK" || strings.Contains(strings.Join(adapter.events, ","), string(systemchanges.StepCompleted)) {
		t.Fatalf("invalid step evidence = %+v; events=%v", result, adapter.events)
	}
}

type controlledUbuntuHost struct {
	root           string
	executed       int
	checks         int
	agreements     int
	rollbacks      int
	waitCancel     bool
	failExecute    bool
	waitReverse    bool
	delay          time.Duration
	started        chan struct{}
	startedFile    string
	reverseFile    string
	recoveryEvents []string
	reversed       []systemchanges.OperationKind
	startingState  string
	services       map[string]*controlledService
}

type controlledService struct {
	owner    systemchanges.Module
	state    string
	known    bool
	running  bool
	affected bool
}

type cleanupFailingUbuntuAdapter struct{ ubuntu.Adapter }

func (cleanupFailingUbuntuAdapter) Cleanup(systemchanges.ExecutionLease, string) error {
	return errors.New("controlled cleanup interruption")
}

func (host *controlledUbuntuHost) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	active := filepath.Join(host.root, "run/sbxr/active-subscription.json")
	prior, err := os.ReadFile(active)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(prior) == 0 {
		prior = []byte(`{"status":"absent"}`)
	}
	return write(bytes.NewReader(prior))
}

func (host *controlledUbuntuHost) Execute(_ systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	host.executed++
	if host.startedFile != "" {
		if err := os.WriteFile(host.startedFile, []byte("started"), 0o600); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if host.started != nil {
		select {
		case <-host.started:
		default:
			close(host.started)
		}
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	if host.waitCancel {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			if cancellation.Requested() {
				return systemchanges.StepEvidence{}, errors.New("cancelled at declared safe checkpoint")
			}
			select {
			case <-ticker.C:
			case <-deadline.C:
				return systemchanges.StepEvidence{}, errors.New("step timeout at declared safe checkpoint")
			}
		}
	}
	if host.delay > 0 {
		delay := time.NewTimer(host.delay)
		defer delay.Stop()
		select {
		case <-delay.C:
		case <-deadline.C:
			return systemchanges.StepEvidence{}, errors.New("step timeout at declared safe checkpoint")
		}
	}
	transaction := filepath.Join(host.root, "var/lib/sbxr/transactions/change-0008")
	if err := filepath.WalkDir(transaction, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symbolic link in transaction material")
		}
		if entry.IsDir() && info.Mode().Perm() != 0o700 || !entry.IsDir() && info.Mode().Perm() != 0o600 {
			return fmt.Errorf("unsafe transaction mode %s on %s", info.Mode(), name)
		}
		return nil
	}); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	manifestBytes, err := os.ReadFile(filepath.Join(transaction, "manifest.json"))
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	var manifest struct {
		SchemaVersion int                          `json:"schema_version"`
		Release       systemchanges.ReleaseBinding `json:"release_identity"`
		Reason        systemchanges.MutationClass  `json:"reason"`
		Files         map[string]string            `json:"sha256"`
	}
	wantRelease := systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256}
	if json.Unmarshal(manifestBytes, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Release != wantRelease || manifest.Reason != systemchanges.SettingChangeMutation || len(manifest.Files) < 3 {
		return systemchanges.StepEvidence{}, errors.New("snapshot manifest binding is incomplete")
	}
	journalBytes, err := os.ReadFile(filepath.Join(transaction, "journal.jsonl"))
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	var preparedEntry struct {
		Checkpoint string                                `json:"checkpoint"`
		ChangeSet  string                                `json:"change_set"`
		PlanSHA256 string                                `json:"plan_sha256"`
		State      systemchanges.StateTransactionBinding `json:"state"`
		Steps      []map[string]any                      `json:"steps"`
		Checks     []systemchanges.Check                 `json:"health_gates"`
	}
	first, _, _ := bytes.Cut(journalBytes, []byte{'\n'})
	if json.Unmarshal(first, &preparedEntry) != nil || preparedEntry.Checkpoint != "Prepared" || preparedEntry.ChangeSet != "change-0008" || len(preparedEntry.PlanSHA256) != 64 || preparedEntry.State.StartingRevision != 7 || preparedEntry.State.CandidateRevision != 8 || len(preparedEntry.Steps) != 1 || preparedEntry.Steps[0]["cancellation"] != string(systemchanges.SafeCheckpointCancellation) || len(preparedEntry.Checks) != 2 || bytes.Contains(journalBytes, []byte("SECRET-MARKER")) || bytes.Contains(manifestBytes, []byte("SECRET-MARKER")) {
		return systemchanges.StepEvidence{}, errors.New("Prepared journal binding is incomplete or unsafe")
	}
	preparedConfig, err := os.ReadFile(filepath.Join(transaction, "prepared/subscription.json"))
	if err != nil || !json.Valid(preparedConfig) {
		return systemchanges.StepEvidence{}, errors.New("prepared native configuration is invalid")
	}
	active := filepath.Join(host.root, "run/sbxr/active-subscription.json")
	if err := os.WriteFile(active, preparedConfig, 0o600); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if host.failExecute {
		return systemchanges.StepEvidence{}, errors.New("controlled native step failure")
	}
	digest := sha256.Sum256(preparedConfig)
	return systemchanges.StepEvidence{Code: "native-valid", SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (host *controlledUbuntuHost) Reverse(step systemchanges.Step, snapshot io.Reader, _ time.Duration) (systemchanges.StepEvidence, error) {
	if host.reverseFile != "" {
		if err := os.WriteFile(host.reverseFile, []byte("started"), 0o600); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	for host.waitReverse {
		time.Sleep(10 * time.Millisecond)
	}
	host.reversed = append(host.reversed, step.Rollback())
	active := filepath.Join(host.root, "run/sbxr/active-subscription.json")
	prior, err := io.ReadAll(snapshot)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if string(prior) == `{"status":"absent"}` {
		if err := os.Remove(active); err != nil && !errors.Is(err, os.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	} else if err := os.WriteFile(active, prior, 0o600); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	for _, service := range host.services {
		if service.owner == step.Owner() {
			service.state = host.startingState
		}
	}
	return systemchanges.StepEvidence{Code: "rollback-valid", SHA256: testSHA('b')}, nil
}

func (host *controlledUbuntuHost) HoldServices() error {
	host.recoveryEvents = append(host.recoveryEvents, "hold services")
	for _, service := range host.services {
		service.running = false
	}
	return nil
}

func (host *controlledUbuntuHost) AllowProvenServices(recovery systemchanges.RecoveryTransaction, _ time.Duration) error {
	expected := recovery.Starting.SHA256
	completed := recovery.LastCheckpoint == systemchanges.Complete
	if completed {
		expected = recovery.Candidate.SHA256
		host.recoveryEvents = append(host.recoveryEvents, "allow proven completed")
	} else {
		host.recoveryEvents = append(host.recoveryEvents, "allow proven unrelated")
		host.startingState = expected
		for _, step := range recovery.Steps {
			for _, service := range host.services {
				service.affected = service.affected || service.owner == step.Owner()
			}
		}
	}
	for _, service := range host.services {
		service.running = (completed || !service.affected) && service.known && service.state == expected
	}
	return nil
}

func (host *controlledUbuntuHost) InspectStep(step systemchanges.Step, snapshot io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	host.recoveryEvents = append(host.recoveryEvents, "inspect uncertain")
	if _, err := io.ReadAll(snapshot); err != nil {
		return "", err
	}
	for name, service := range host.services {
		shouldRun := !service.affected && service.known && service.state == host.startingState
		if service.running != shouldRun || service.owner == step.Owner() && service.running {
			return "", fmt.Errorf("service %s was released without last-State agreement", name)
		}
	}
	return systemchanges.StepEffectPresent, nil
}

func (host *controlledUbuntuHost) VerifyStartingServices(recovery systemchanges.RecoveryTransaction, _ time.Duration) error {
	host.recoveryEvents = append(host.recoveryEvents, "starting services proven")
	for _, service := range host.services {
		if service.affected {
			if !service.known || service.state != recovery.Starting.SHA256 {
				return errors.New("affected service does not match the last successful State")
			}
			service.running = true
		}
	}
	return nil
}

func TestModuleReverseRetryWithSameSnapshotIsIdempotent(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "run/sbxr/active-subscription.json")
	if err := os.MkdirAll(filepath.Dir(active), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, []byte(`{"candidate":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root}
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := host.Reverse(step, strings.NewReader(`{"status":"absent"}`), time.Second); err != nil {
			t.Fatalf("Reverse retry %d: %v", attempt+1, err)
		}
	}
	if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) || len(host.reversed) != 2 {
		t.Fatalf("idempotent reverse left active=%v reversed=%v", err, host.reversed)
	}
}

func TestFreshSystemChangesInstanceRollsBackInterruptedForwardStep(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	adapter := &systemChangesAdapter{recovery: &recovery}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.Managed || result.Finding == nil || result.Finding.Owner != systemchanges.ConnectionProfilesModule {
		t.Fatalf("Recover() = %+v", result)
	}
	want := "hold public services and timers,allow proven unrelated services,inspect uncertain step,Rollback started,restore durable State,Rollback step started 1,reverse Restore prior configuration,Rollback step completed 1,rollback verified,starting services verified,Rollback verified,Rolled back,cleanup"
	if got := strings.Join(adapter.events, ","); got != want {
		t.Fatalf("recovery events = %s, want %s", got, want)
	}
}

func TestRetryAutomaticRollbackUsesOnlyTheAuthorizedRecoveryPath(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	observation := systemchanges.Observation{
		Status: systemchanges.RecoveryRequired, CurrentChangeSet: "change-0008", LastChangeSet: "change-0007", Checkpoint: systemchanges.PreparedCheckpoint,
		TotalSteps: 1, Lock: systemchanges.LockReleased, RollbackAvailable: true, RecoveryCause: systemchanges.RollbackStepUnprovable,
	}
	adapter := &systemChangesAdapter{observation: observation, recovery: &recovery}
	result := systemchanges.New(adapter).RetryAutomaticRollback()
	if result.Outcome != systemchanges.RollbackSucceeded || adapter.recovery != nil || !strings.Contains(strings.Join(adapter.events, ","), "inspect uncertain step") {
		t.Fatalf("retry rollback = %+v; events=%v", result, adapter.events)
	}

	observation.RollbackAvailable = false
	observation.CurrentChangeSet = ""
	observation.Checkpoint = systemchanges.NoCheckpoint
	observation.TotalSteps = 0
	observation.RecoveryCause = systemchanges.JournalUnprovable
	adapter = &systemChangesAdapter{observation: observation, recovery: &recovery}
	result = systemchanges.New(adapter).RetryAutomaticRollback()
	if result.Outcome != systemchanges.Refused || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ROLLBACK-NOT-AVAILABLE" || len(adapter.events) != 0 {
		t.Fatalf("invalid retry = %+v; events=%v", result, adapter.events)
	}
}

func TestRecoveryRequiredCoversEveryIntegrityAndLineageFailure(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	base := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	for _, test := range []struct {
		name   string
		change func(*systemchanges.RecoveryTransaction, *systemChangesAdapter)
	}{
		{name: "current State lineage", change: func(_ *systemchanges.RecoveryTransaction, adapter *systemChangesAdapter) {
			adapter.recoveryLoadErr = errors.New("SECRET-MARKER-lineage")
		}},
		{name: "snapshot integrity", change: func(_ *systemchanges.RecoveryTransaction, adapter *systemChangesAdapter) {
			adapter.inspectionErr = errors.New("SECRET-MARKER-snapshot")
		}},
		{name: "journal integrity", change: func(_ *systemchanges.RecoveryTransaction, adapter *systemChangesAdapter) {
			adapter.recoveryLoadErr = errors.New("SECRET-MARKER-journal")
		}},
		{name: "forward checkpoint", change: func(recovery *systemchanges.RecoveryTransaction, _ *systemChangesAdapter) {
			recovery.LastCheckpoint = systemchanges.CancellationRequested
		}},
		{name: "rollback step", change: func(_ *systemchanges.RecoveryTransaction, adapter *systemChangesAdapter) { adapter.failReverse = true }},
		{name: "final prior-State agreement", change: func(_ *systemchanges.RecoveryTransaction, adapter *systemChangesAdapter) {
			adapter.serviceErr = errors.New("SECRET-MARKER-agreement")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			recovery := base
			adapter := &systemChangesAdapter{recovery: &recovery}
			test.change(&recovery, adapter)
			result := systemchanges.New(adapter).Recover()
			encoded, err := json.Marshal(result)
			if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Evidence != (systemchanges.EvidenceRules{SecretSafeOnly: true}) || strings.Contains(strings.Join(adapter.events, ","), "cleanup") || err != nil || strings.Contains(string(encoded), "SECRET-MARKER") {
				t.Fatalf("%s recovery = %+v; events=%v encoded=%s err=%v", test.name, result, adapter.events, encoded, err)
			}
		})
	}
}

func TestFreshSystemChangesInstanceNeverResumesOrdinaryForwardWork(t *testing.T) {
	for index, checkpoint := range []systemchanges.DurableCheckpoint{
		systemchanges.Prepared, systemchanges.StepStarted, systemchanges.StepCompleted,
		systemchanges.PrePublicationHealthPassed, systemchanges.StatePublicationStarted,
		systemchanges.StatePublished, systemchanges.PostPublicationHealthPassed,
	} {
		for _, side := range []string{"before", "after"} {
			t.Run(side+"_"+string(checkpoint), func(t *testing.T) {
				identity := fmt.Sprintf("change-restart-%02d-%s", index+1, side)
				stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, systemChangeTestOptions{identity: identity, stepTimeout: time.Second})
				adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule}
				if side == "before" {
					adapter.crashBefore = checkpoint
				} else {
					adapter.crashAfter = checkpoint
				}
				func() {
					defer func() { _ = recover() }()
					_ = systemchanges.New(adapter).Apply(changeSet)
				}()
				if !adapter.crashed {
					t.Fatalf("worker did not die %s %s", side, checkpoint)
				}
				executedBeforeRecovery := adapter.executeCount
				result := systemchanges.New(adapter).Recover()
				want := systemchanges.RollbackSucceeded
				if side == "before" && checkpoint == systemchanges.Prepared {
					want = systemchanges.RecoveryRequiredOutcome
				}
				if result.Outcome != want || adapter.executeCount != executedBeforeRecovery || !strings.Contains(strings.Join(adapter.events, ","), "hold public services and timers") {
					t.Fatalf("Recover(%s %s) = %+v; execute before=%d after=%d events=%v", side, checkpoint, result, executedBeforeRecovery, adapter.executeCount, adapter.events)
				}
				loaded, err := stateModule.Load(intentManagedRequest())
				if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.loaded == nil || loaded.loaded.payloadChecksum != observed.StateSHA256 {
					t.Fatalf("State after Recover(%s %s) = (%+v, %v)", side, checkpoint, loaded, err)
				}
			})
		}
	}
}

func TestFreshSystemChangesInstanceResumesInterruptedRollbackFromDurableEvidence(t *testing.T) {
	for _, checkpoint := range []systemchanges.DurableCheckpoint{
		systemchanges.RollbackStarted, systemchanges.RollbackStepStarted, systemchanges.RollbackStepCompleted,
		systemchanges.RollbackVerified, systemchanges.RolledBack,
	} {
		for _, side := range []string{"before", "after"} {
			t.Run(side+"_"+string(checkpoint), func(t *testing.T) {
				stateModule, changeSet, _, observed := preparedSystemChange(t)
				adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, failStep: 1}
				if side == "before" {
					adapter.crashBefore = checkpoint
				} else {
					adapter.crashAfter = checkpoint
				}
				func() {
					defer func() { _ = recover() }()
					_ = systemchanges.New(adapter).Apply(changeSet)
				}()
				if !adapter.crashed {
					t.Fatalf("worker did not die %s %s", side, checkpoint)
				}
				reversedBefore := strings.Count(strings.Join(adapter.events, ","), "reverse Restore prior configuration")
				result := systemchanges.New(adapter).Recover()
				reversedAfter := strings.Count(strings.Join(adapter.events, ","), "reverse Restore prior configuration")
				wantAdditionalReverse := 1
				if checkpoint == systemchanges.RollbackStepCompleted && side == "after" || checkpoint == systemchanges.RollbackVerified || checkpoint == systemchanges.RolledBack {
					wantAdditionalReverse = 0
				}
				if result.Outcome != systemchanges.RollbackSucceeded || reversedAfter-reversedBefore != wantAdditionalReverse || adapter.recovery != nil {
					t.Fatalf("Recover(%s %s) = %+v; additional reverse=%d events=%v", side, checkpoint, result, reversedAfter-reversedBefore, adapter.events)
				}
				loaded, err := stateModule.Load(intentManagedRequest())
				if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 || loaded.loaded == nil || loaded.loaded.payloadChecksum != observed.StateSHA256 {
					t.Fatalf("State after Recover(%s %s) = (%+v, %v)", side, checkpoint, loaded, err)
				}
			})
		}
	}
}

func TestRollbackCanSurviveASecondProcessDeath(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, failStep: 1, crashAfter: systemchanges.RollbackStarted}
	func() {
		defer func() { _ = recover() }()
		_ = systemchanges.New(adapter).Apply(changeSet)
	}()
	adapter.crashed = false
	adapter.crashAfter = systemchanges.RollbackStepStarted
	func() {
		defer func() { _ = recover() }()
		_ = systemchanges.New(adapter).Recover()
	}()
	if !adapter.crashed || adapter.recovery == nil || adapter.recovery.LastCheckpoint != systemchanges.RollbackStepStarted {
		t.Fatalf("second process death was not durable: recovery=%+v events=%v", adapter.recovery, adapter.events)
	}
	adapter.crashed = false
	adapter.crashAfter = ""
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RollbackSucceeded || adapter.recovery != nil || strings.Count(strings.Join(adapter.events, ","), "reverse Restore prior configuration") != 1 {
		t.Fatalf("second restart = %+v; events=%v", result, adapter.events)
	}
}

func TestRestartAfterCompleteCleansUpWithoutRollback(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChange(t)
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, crashAfter: systemchanges.Complete}
	func() {
		defer func() { _ = recover() }()
		_ = systemchanges.New(adapter).Apply(changeSet)
	}()
	if !adapter.crashed || adapter.recovery == nil || adapter.recovery.LastCheckpoint != systemchanges.Complete {
		t.Fatalf("durable Complete was not retained: recovery=%+v events=%v", adapter.recovery, adapter.events)
	}
	reversedBefore := strings.Count(strings.Join(adapter.events, ","), "reverse Restore prior configuration")
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Completed || adapter.recovery != nil || strings.Count(strings.Join(adapter.events, ","), "reverse Restore prior configuration") != reversedBefore || strings.Contains(strings.Join(adapter.events[len(adapter.events)-3:], ","), "restore durable State") {
		t.Fatalf("post-Complete recovery = %+v; events=%v", result, adapter.events)
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 8 {
		t.Fatalf("post-Complete State = (%+v, %v)", loaded, err)
	}
}

func TestRecoveryKeepsAffectedServicesStoppedWithoutStartingStateAgreement(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepCompleted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	adapter := &systemChangesAdapter{recovery: &recovery, serviceErr: errors.New("controlled service agreement failure")}
	result := systemchanges.New(adapter).Recover()
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Finding.Owner != systemchanges.ConnectionProfilesModule || strings.Contains(events, string(systemchanges.RollbackVerified)) || strings.Contains(events, string(systemchanges.RolledBack)) || strings.Contains(events, "cleanup") {
		t.Fatalf("unproven service recovery = %+v; events=%s", result, events)
	}
}

func TestRecoveryRefusesBeforeInspectionWhenUnrelatedServiceAgreementIsUnknown(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	adapter := &systemChangesAdapter{recovery: &recovery, holdErr: errors.New("controlled unrelated service agreement failure")}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Finding.Owner != systemchanges.ConnectionProfilesModule || strings.Join(adapter.events, ",") != "hold public services and timers,allow proven unrelated services" {
		t.Fatalf("unproven unrelated service recovery = %+v; events=%v", result, adapter.events)
	}
}

func TestRecoveryRunnerChangesNothingWithoutAnUnfinishedJournal(t *testing.T) {
	adapter := &systemChangesAdapter{noRecovery: true, observation: systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockHeld}}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Refused || !result.NothingChanged || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-RECOVERY-NOT-NEEDED" || result.Finding.Owner != systemchanges.StateModule || adapter.closes.Load() != 1 || strings.Join(adapter.events, ",") != "hold public services and timers" {
		t.Fatalf("no-op Recover() = %+v; closes=%d events=%v", result, adapter.closes.Load(), adapter.events)
	}
}

func TestRecoveryHoldsServicesBeforeReadingAnUnprovableJournal(t *testing.T) {
	adapter := &systemChangesAdapter{}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Finding.Owner != systemchanges.StateModule || strings.Join(adapter.events, ",") != "hold public services and timers" {
		t.Fatalf("unprovable recovery = %+v; events=%v", result, adapter.events)
	}
}

func (host *controlledUbuntuHost) Check(_ systemchanges.Check, _ systemchanges.GatePhase, _ time.Duration) (systemchanges.HealthStatus, error) {
	host.checks++
	return systemchanges.Healthy, nil
}

func (host *controlledUbuntuHost) VerifyAgreement(agreement systemchanges.Agreement, _ time.Duration) error {
	host.agreements++
	if agreement.Revision != 8 || agreement.ChangeSet != "change-0008" || agreement.CandidateSHA256 == "" || agreement.PublishedStateSHA256 == "" || agreement.PreparedManifestSHA256 == "" {
		return errors.New("incomplete active agreement")
	}
	if active, err := os.ReadFile(filepath.Join(host.root, "run/sbxr/active-subscription.json")); err != nil || !json.Valid(active) {
		return errors.New("active configuration agreement failed")
	}
	return nil
}

func (host *controlledUbuntuHost) VerifyRollback(agreement systemchanges.RollbackAgreement, _ time.Duration) error {
	host.rollbacks++
	wantRelease := systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256}
	if agreement.Status != systemchanges.Managed || agreement.Revision != 7 || agreement.SHA256 == "" || agreement.Release != wantRelease {
		return errors.New("rollback State agreement failed")
	}
	active := filepath.Join(host.root, "run/sbxr/active-subscription.json")
	if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) {
		return errors.New("rollback active-file agreement failed")
	}
	journal, err := os.ReadFile(filepath.Join(host.root, "var/lib/sbxr/transactions/change-0008/journal.jsonl"))
	if err != nil || !bytes.Contains(journal, []byte(`"checkpoint":"Rollback started"`)) || !bytes.Contains(journal, []byte(`"checkpoint":"Rollback step completed"`)) || bytes.Contains(journal, []byte("SECRET-MARKER")) {
		return errors.New("rollback journal agreement failed")
	}
	return nil
}

func TestUbuntuAdapterDurablyProtectsAndCleansSuccessfulTransaction(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	root := t.TempDir()
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	unauthorizedStep, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(systemchanges.ExecutionLease{}, unauthorizedStep, time.Second, nil); err == nil || host.executed != 0 {
		t.Fatal("Ubuntu Adapter exposed a second mutation path outside Apply")
	}
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Completed || host.executed != 1 || host.checks != 2 || host.agreements != 1 {
		t.Fatalf("controlled Ubuntu success = (%+v, executed=%d checks=%d agreements=%d)", result, host.executed, host.checks, host.agreements)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed transaction material still exists: %v", err)
	}
}

func TestUbuntuAdapterKeepsSupervisedWorkAliveUntilExplicitCancellation(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChange(t)
	root := t.TempDir()
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	host := &controlledUbuntuHost{root: root, waitCancel: true, started: started}
	source := func() (systemchanges.Observation, error) {
		select {
		case <-started:
			active := observed
			active.Status, active.CurrentChangeSet, active.LastChangeSet = systemchanges.ChangeInProgress, "change-0008", "change-0007"
			active.Checkpoint, active.TotalSteps, active.Lock, active.RollbackAvailable = systemchanges.PreparedCheckpoint, 1, systemchanges.LockHeld, true
			return active, nil
		default:
			return observed, nil
		}
	}
	adapter := ubuntu.NewAt(root, source, host)
	cancellation := systemchanges.NewCancellation()
	result := make(chan systemchanges.ApplyResult, 1)
	go func() { result <- systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("supervised step did not start")
	}
	inspection := systemchanges.New(adapter).Inspect()
	if inspection.Status != systemchanges.ChangeInProgress || fmt.Sprint(inspection.AllowedActions) != fmt.Sprint([]systemchanges.Action{systemchanges.InspectAction}) || len(inspection.Findings) != 0 {
		t.Fatalf("later-session Inspect() = %+v", inspection)
	}
	select {
	case early := <-result:
		t.Fatalf("presentation loss stopped supervised work: %+v", early)
	default:
	}
	cancellation.Request()
	select {
	case cancelled := <-result:
		if cancelled.Outcome != systemchanges.RollbackSucceeded || host.executed != 1 || host.rollbacks != 1 || fmt.Sprint(host.reversed) != fmt.Sprint([]systemchanges.OperationKind{systemchanges.RestorePriorConfiguration}) {
			t.Fatalf("controlled cancellation = %+v; host=%+v", cancelled, host)
		}
		if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rolled-back transaction material still exists: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("explicit cancellation did not reach a safe checkpoint")
	}
}

func TestUbuntuAdapterBoundsLiveStepAndRollsBackOnTimeout(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, systemChangeTestOptions{stepTimeout: 10 * time.Millisecond})
	root := t.TempDir()
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root, delay: time.Second}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	started := time.Now()
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.RollbackSucceeded || time.Since(started) >= time.Second || host.rollbacks != 1 {
		t.Fatalf("bounded timeout rollback = %+v after %s; rollbacks=%d", result, time.Since(started), host.rollbacks)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timed-out transaction material still exists: %v", err)
	}
}

func TestSystemChangesRecoveryProcess(t *testing.T) {
	root := os.Getenv("SBXR_RECOVERY_TEST_ROOT")
	if root == "" {
		t.Skip("recovery subprocess only")
	}
	_, changeSet, _, observed := preparedSystemChange(t)
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root}
	if os.Getenv("SBXR_RECOVERY_TEST_MODE") == "rollback" {
		host.failExecute = true
		host.waitReverse = true
		host.reverseFile = filepath.Join(root, "rollback-step-started")
	} else {
		host.waitCancel = true
		host.startedFile = filepath.Join(root, "forward-step-started")
	}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	result := systemchanges.New(adapter).Apply(changeSet)
	t.Fatalf("recovery subprocess returned without process death: %+v", result)
}

func rollbackDeathRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestSystemChangesRecoveryProcess$")
	command.Env = append(os.Environ(), "SBXR_RECOVERY_TEST_ROOT="+root, "SBXR_RECOVERY_TEST_MODE=rollback")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(root, "rollback-step-started")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
			t.Fatal("subprocess did not reach the durable rollback checkpoint")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = command.Process.Wait()
	return root
}

func TestUbuntuRecoveryResumesProcessDeathDuringRollback(t *testing.T) {
	root := rollbackDeathRoot(t)
	stateModule, _, _, observed := preparedSystemChange(t)
	observed.Status, observed.CurrentChangeSet, observed.LastChangeSet = systemchanges.ChangeInProgress, "change-0008", "change-0007"
	observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, 1, true
	host := &controlledUbuntuHost{root: root, services: map[string]*controlledService{
		"affected":         {owner: systemchanges.ConnectionProfilesModule, state: testSHA('8'), known: true, running: true},
		"unrelated-proven": {owner: systemchanges.NetworkPolicyModule, state: observed.StateSHA256, known: true, running: true},
	}}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RollbackSucceeded || fmt.Sprint(host.reversed) != fmt.Sprint([]systemchanges.OperationKind{systemchanges.RestorePriorConfiguration}) || strings.Join(host.recoveryEvents, ",") != "hold services,allow proven unrelated,inspect uncertain,starting services proven" || !host.services["affected"].running || !host.services["unrelated-proven"].running {
		t.Fatalf("rollback-death recovery = %+v; recovery=%v reversed=%v", result, host.recoveryEvents, host.reversed)
	}
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 {
		t.Fatalf("rollback-death State = (%+v, %v)", loaded, err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback-death material remains: %v", err)
	}
}

func TestUbuntuRecoveryRefusesMissingRollbackEvidence(t *testing.T) {
	root := rollbackDeathRoot(t)
	if err := os.Remove(filepath.Join(root, "var/lib/sbxr/transactions/change-0008/snapshot/step-001.rollback")); err != nil {
		t.Fatal(err)
	}
	stateModule, _, _, observed := preparedSystemChange(t)
	observed.Status, observed.CurrentChangeSet, observed.LastChangeSet = systemchanges.ChangeInProgress, "change-0008", "change-0007"
	observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, 1, true
	host := &controlledUbuntuHost{root: root}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || len(host.reversed) != 0 {
		t.Fatalf("missing rollback evidence = %+v; reversed=%v", result, host.reversed)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); err != nil {
		t.Fatalf("unproven transaction was removed: %v", err)
	}
}

func interruptedComplete(t *testing.T) (string, Interface, systemchanges.Observation) {
	t.Helper()
	stateModule, changeSet, _, observed := preparedSystemChange(t)
	root := t.TempDir()
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root}
	base := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
	result := systemchanges.New(cleanupFailingUbuntuAdapter{Adapter: base}).Apply(changeSet)
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Finding.Found != string(systemchanges.Complete) {
		t.Fatalf("interrupted cleanup = %+v", result)
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.loaded == nil {
		t.Fatalf("completed State = (%+v, %v)", loaded, err)
	}
	observed.Status, observed.CurrentChangeSet, observed.LastChangeSet = systemchanges.Managed, "", "change-0008"
	observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.NoCheckpoint, 0, false
	observed.StateRevision, observed.StateSHA256 = 8, loaded.loaded.payloadChecksum
	return root, stateModule, observed
}

func TestUbuntuRecoveryAfterCompleteOnlyCleansResolvedMaterial(t *testing.T) {
	root, stateModule, observed := interruptedComplete(t)
	host := &controlledUbuntuHost{root: root}
	host.services = map[string]*controlledService{
		"completed": {owner: systemchanges.ConnectionProfilesModule, state: observed.StateSHA256, known: true},
	}
	fresh := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
	result := systemchanges.New(fresh).Recover()
	if result.Outcome != systemchanges.Completed || len(host.reversed) != 0 || !host.services["completed"].running {
		t.Fatalf("post-Complete cleanup = %+v; recovery=%v services=%+v", result, host.recoveryEvents, host.services)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed transaction material remains: %v", err)
	}
}

func TestUbuntuRecoveryRefusesContradictoryCompleteEvidence(t *testing.T) {
	root, stateModule, observed := interruptedComplete(t)
	journal := filepath.Join(root, "var/lib/sbxr/transactions/change-0008/journal.jsonl")
	file, err := os.OpenFile(journal, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("{\"checkpoint\":\"Rolled back\"}\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatalf("contradictory journal write = (%v, %v, %v)", writeErr, syncErr, closeErr)
	}
	host := &controlledUbuntuHost{root: root}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || len(host.reversed) != 0 {
		t.Fatalf("contradictory Complete evidence = %+v; reversed=%v", result, host.reversed)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); err != nil {
		t.Fatalf("contradictory transaction was removed: %v", err)
	}
}

func TestUbuntuRecoveryAcquiresProcessReleasedLockBeforeServicesAndRollsBack(t *testing.T) {
	root := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestSystemChangesRecoveryProcess$")
	command.Env = append(os.Environ(), "SBXR_RECOVERY_TEST_ROOT="+root)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(root, "forward-step-started")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
			t.Fatal("subprocess did not reach the durable forward checkpoint")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = command.Process.Wait()
	stateModule, _, _, observed := preparedSystemChange(t)
	observed.Status, observed.CurrentChangeSet, observed.LastChangeSet = systemchanges.ChangeInProgress, "change-0008", "change-0007"
	observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, 1, true
	host := &controlledUbuntuHost{root: root, services: map[string]*controlledService{
		"affected":             {owner: systemchanges.ConnectionProfilesModule, state: testSHA('8'), known: true, running: true},
		"unrelated-proven":     {owner: systemchanges.NetworkPolicyModule, state: observed.StateSHA256, known: true, running: true},
		"unrelated-candidate":  {owner: systemchanges.HealthDiagnosticsModule, state: testSHA('8'), known: true, running: true},
		"unrelated-unprovable": {owner: systemchanges.CertificateModule, state: observed.StateSHA256, running: true},
	}}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RollbackSucceeded || strings.Join(host.recoveryEvents, ",") != "hold services,allow proven unrelated,inspect uncertain,starting services proven" || host.executed != 0 || fmt.Sprint(host.reversed) != fmt.Sprint([]systemchanges.OperationKind{systemchanges.RestorePriorConfiguration}) {
		t.Fatalf("process-death recovery = %+v; recovery=%v executed=%d reversed=%v", result, host.recoveryEvents, host.executed, host.reversed)
	}
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 {
		t.Fatalf("State-owned restart restoration = (%+v, %v)", loaded, err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered transaction material remains: %v", err)
	}
	if !host.services["affected"].running || !host.services["unrelated-proven"].running || host.services["unrelated-candidate"].running || host.services["unrelated-unprovable"].running {
		t.Fatalf("service holdback after recovery = %+v", host.services)
	}
}

func TestUbuntuAdapterRefusesUnsafeTransactionPathsBeforeLiveWork(t *testing.T) {
	for _, test := range []struct {
		name  string
		plant func(string) error
	}{
		{name: "broad transaction directory", plant: func(base string) error { return os.MkdirAll(base, 0o755) }},
		{name: "symbolic link preparing path", plant: func(base string) error {
			if err := os.MkdirAll(base, 0o700); err != nil {
				return err
			}
			return os.Symlink("elsewhere", filepath.Join(base, "change-0008.preparing"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChange(t)
			root := t.TempDir()
			lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
			if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(root, "var/lib/sbxr/transactions")
			if err := test.plant(base); err != nil {
				t.Fatal(err)
			}
			host := &controlledUbuntuHost{root: root}
			adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
			result := systemchanges.New(adapter).Apply(changeSet)
			if result.Outcome != systemchanges.Refused || !result.NothingChanged || host.executed != 0 || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-PREPARATION" || result.Finding.Owner != systemchanges.ConnectionProfilesModule {
				t.Fatalf("unsafe path result = %+v; executed=%d", result, host.executed)
			}
		})
	}
}
