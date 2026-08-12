package state

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
	"github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

type systemChangesAdapter struct {
	observation        systemchanges.Observation
	closes             atomic.Int32
	events             []string
	artifacts          map[string][]byte
	statuses           map[systemchanges.GatePhase]systemchanges.HealthStatus
	beforeStep         func() error
	afterPrepare       func()
	beforeCheck        func()
	prepareErr         error
	closeErr           error
	stepEvidence       *systemchanges.StepEvidence
	lease              systemchanges.ExecutionLease
	executeCount       int
	failStep           int
	failReverse        bool
	agreementErr       error
	serviceErr         error
	removalReadyErr    error
	tokenRevoked       bool
	failRemoval        systemchanges.IrreversibleRemovalPhase
	removalErr         error
	finalAbsent        bool
	holdErr            error
	recoveryLoadErr    error
	inspectionErr      error
	restoreErr         error
	noRecovery         bool
	recovery           *systemchanges.RecoveryTransaction
	stateRecovery      systemchanges.StateRecovery
	stateBinding       []byte
	crashBefore        systemchanges.DurableCheckpoint
	crashAfter         systemchanges.DurableCheckpoint
	crashStep          int
	failRecord         systemchanges.DurableCheckpoint
	crashed            bool
	lockHeld           bool
	cloudflare         *cloudflaretunnel.Executor
	rotationChanged    bool
	reclamationPresent bool
}

type controlledInfrastructureSecret struct {
	value string
	used  atomic.Bool
}

func (secret *controlledInfrastructureSecret) ConsumeInfrastructureSecret() (string, bool) {
	if secret == nil || secret.value == "" || !secret.used.CompareAndSwap(false, true) {
		return "", false
	}
	return secret.value, true
}

type controlledRemovalObserver struct{}

func (controlledRemovalObserver) ObserveRemovalResource(review, resource, immutableID string) (cloudflaretunnel.RemovalObservation, error) {
	return cloudflaretunnel.RemovalObservation{ReviewID: review, Resource: resource, ImmutableID: immutableID, OwnedBySBXR: true, TokenActive: true, TokenAvailableLocally: true, Inventory: controlledCloudflareRemovalInventory()}, nil
}

type controlledPublicRemovalObserver struct{}

func (controlledPublicRemovalObserver) ObserveRemovalResource(review, resource, immutableID string) (networkpolicy.RemovalObservation, error) {
	return networkpolicy.RemovalObservation{ReviewID: review, Resource: resource, ImmutableID: immutableID, OwnedBySBXR: true, Inventory: controlledPublicRemovalInventory()}, nil
}

func controlledPublicRemovalInventory() map[string][]string {
	return map[string][]string{"firewall-table": {"inet-sbxr"}, "public-listener": {"listener-xray"}, "public-service": {"service-xray"}}
}

func controlledCloudflareRemovalInventory() map[string][]string {
	return map[string][]string{"cloudflare-dns-record": {"dns-xhttp", "dns-websocket", "dns-direct-ipv4"}, "cloudflare-route": {"route-xhttp"}, "cloudflare-tunnel": {"tunnel-xhttp"}}
}

type controlledOwnerRemovalObserver struct{}

func (controlledOwnerRemovalObserver) ReviewedCategories(string) ([]string, error) {
	return []string{"desired-state", "client-access-values", "infrastructure-secrets", "certificates-and-acme", "transaction-journal", "rollback-snapshot", "installed-release", "verified-update-candidate", "services-and-timers", "service-identities", "prepared-artifacts", "subscription-artifacts", "firewall-table", "public-listener", "public-service", "removal-journal", "recovery-runner", "cloudflare-dns-record", "cloudflare-route", "cloudflare-tunnel", "certificate-transparency-remnant", "dns-cache-remnant"}, nil
}
func (controlledOwnerRemovalObserver) TypedPhrase(string) (string, bool, error) {
	return "COMPLETE REMOVAL", true, nil
}
func (controlledOwnerRemovalObserver) PermanentRemovalSelected(string) (bool, error) {
	return true, nil
}

type controlledCompleteRemovalApproval struct {
	recheck softwarelifecycle.CompleteRemovalRecheck
}

func (approval controlledCompleteRemovalApproval) AuthorizeAndRecheck(context.Context) (softwarelifecycle.CompleteRemovalRecheck, error) {
	return approval.recheck, nil
}

func (a *systemChangesAdapter) Observe() (systemchanges.Observation, error) {
	return a.observation, nil
}

func (a *systemChangesAdapter) TryLock() (systemchanges.Lock, bool, error) {
	if a.lockHeld {
		return nil, false, nil
	}
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
		ChangeSet: preparation.ChangeSet, Mutation: preparation.Mutation, Starting: preparation.Starting, StartingRelease: preparation.State.StartingRelease,
		Candidate: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: preparation.State.CandidateRevision, SHA256: preparation.State.CandidateSHA256}, CandidateRelease: preparation.State.CandidateRelease,
		OutcomeOwner: preparation.OutcomeOwner, State: preparation.State, Steps: append([]systemchanges.Step(nil), preparation.Steps...), Checks: append([]systemchanges.Check(nil), preparation.Checks...), LastCheckpoint: systemchanges.Prepared, Timeouts: preparation.Timeouts, Reclamation: preparation.Reclamation,
	}
	a.stateBinding, _ = json.Marshal(preparation.State)
	if a.afterPrepare != nil {
		a.afterPrepare()
	}
	if a.crashAfter == systemchanges.Prepared && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	return nil
}

func (a *systemChangesAdapter) Record(_ systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	if a.crashBefore == record.Checkpoint && (a.crashStep == 0 || a.crashStep == record.Step) && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	if a.failRecord == record.Checkpoint {
		return errors.New("controlled checkpoint write failure")
	}
	a.events = append(a.events, record.String())
	if a.recovery != nil {
		a.recovery.LastCheckpoint = record.Checkpoint
		if record.Checkpoint == systemchanges.IrreversibleRemovalStarted {
			a.recovery.IrreversibleRemovalStarted = true
		}
		if record.Checkpoint == systemchanges.IrreversibleReclamationStarted {
			a.recovery.IrreversibleReclamationStarted = true
		}
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
		if record.State != nil {
			a.recovery.State = *record.State
			a.recovery.Candidate.SHA256 = record.State.CandidateSHA256
		}
	}
	if a.crashAfter == record.Checkpoint && (a.crashStep == 0 || a.crashStep == record.Step) && !a.crashed {
		a.crashed = true
		panic("controlled worker death")
	}
	return nil
}

func (a *systemChangesAdapter) StartRunTokenRotation(_ systemchanges.ExecutionLease, _ string) (bool, error) {
	a.events = append(a.events, string(systemchanges.IrreversibleRunTokenRotationStarted))
	if a.recovery == nil {
		return false, errors.New("rotation recovery unavailable")
	}
	a.recovery.LastCheckpoint = systemchanges.IrreversibleRunTokenRotationStarted
	a.recovery.PriorRunTokenSHA256 = testSHA('9')
	delete(a.artifacts, "snapshot/prior-state.json")
	return true, nil
}

func (a *systemChangesAdapter) FinalizeRunTokenRotation(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction, _ time.Duration) (any, systemchanges.StateTransactionBinding, bool, error) {
	a.events = append(a.events, "retrieve changed Tunnel token")
	if !a.rotationChanged {
		return nil, systemchanges.StateTransactionBinding{}, false, nil
	}
	binding, _ := json.Marshal(recovery.State)
	material, err := a.stateRecovery.SystemChangesFinalizeRunTokenRotation(lease, binding, bytes.NewReader(a.artifacts["prepared/state.json"]), &controlledInfrastructureSecret{value: "CLOUDFLARE-ROTATED-RUN-TOKEN-MARKER"})
	stateMaterial, ok := material.(interface {
		SystemChangesBindings(any) ([]byte, error)
		SystemChangesWriteArtifacts(any, func(string, uint32, io.Reader) error) error
	})
	if err != nil || !ok {
		return nil, systemchanges.StateTransactionBinding{}, false, err
	}
	finalJSON, err := stateMaterial.SystemChangesBindings(lease)
	var final systemchanges.StateTransactionBinding
	if err != nil || json.Unmarshal(finalJSON, &final) != nil {
		return nil, systemchanges.StateTransactionBinding{}, false, errors.New("final binding unavailable")
	}
	if err := a.ReplaceStateArtifacts(lease, recovery.ChangeSet, final, func(write func(string, uint32, io.Reader) error) error {
		return stateMaterial.SystemChangesWriteArtifacts(lease, write)
	}); err != nil {
		return nil, systemchanges.StateTransactionBinding{}, false, err
	}
	return material, final, true, nil
}

func (a *systemChangesAdapter) LoadRunTokenRotationState(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction) (any, error) {
	binding, _ := json.Marshal(recovery.State)
	return a.stateRecovery.SystemChangesLoadRunTokenRotation(lease, binding, bytes.NewReader(a.artifacts["prepared/state.json"]), bytes.NewReader(a.artifacts["prepared/manifests.json"]))
}

func (a *systemChangesAdapter) LoadForwardInstallationState(lease systemchanges.ExecutionLease, recovery systemchanges.RecoveryTransaction) (any, error) {
	binding, _ := json.Marshal(recovery.State)
	return a.stateRecovery.SystemChangesLoadForwardInstallation(lease, binding, bytes.NewReader(a.artifacts["prepared/state.json"]), bytes.NewReader(a.artifacts["prepared/manifests.json"]))
}

func (a *systemChangesAdapter) LoadForwardInstallationEvidence(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction) ([]systemchanges.StepEvidence, error) {
	evidence := make([]systemchanges.StepEvidence, len(a.recovery.Steps))
	for index := 0; index < a.recovery.AttemptedSteps && index < len(evidence); index++ {
		evidence[index] = systemchanges.StepEvidence{Code: "step-ok", SHA256: testSHA('a')}
	}
	return evidence, nil
}

func (a *systemChangesAdapter) VerifyReclamationReady(systemchanges.ExecutionLease, string, systemchanges.ReclamationTarget, time.Duration) error {
	a.events = append(a.events, "verify exact reclamation target")
	if !a.reclamationPresent {
		return errors.New("target changed")
	}
	return nil
}

func (a *systemChangesAdapter) StopReclamationProcess(systemchanges.ExecutionLease, systemchanges.ReclamationTarget, time.Duration) (systemchanges.StepEvidence, error) {
	a.events = append(a.events, "stop exact reclamation process")
	return systemchanges.StepEvidence{Code: "reclamation-process-stopped", SHA256: testSHA('c')}, nil
}

func (a *systemChangesAdapter) DeleteReclamationTarget(_ systemchanges.ExecutionLease, _ string, _ systemchanges.ReclamationTarget, _ time.Duration) (systemchanges.StepEvidence, error) {
	a.events = append(a.events, "delete exact reclamation target")
	a.reclamationPresent = false
	return systemchanges.StepEvidence{Code: "reclamation-target-deleted", SHA256: testSHA('d')}, nil
}

func (a *systemChangesAdapter) InspectReclamationTarget(systemchanges.ExecutionLease, string, systemchanges.ReclamationTarget, time.Duration) (systemchanges.StepEffect, error) {
	a.events = append(a.events, "inspect exact reclamation target")
	if a.reclamationPresent {
		return systemchanges.StepEffectPresent, nil
	}
	return systemchanges.StepEffectAbsent, nil
}

func (a *systemChangesAdapter) Execute(_ systemchanges.ExecutionLease, _ string, _ int, step systemchanges.Step, _ time.Duration, _ *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
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
	if change, ok := step.CloudflareChange(); ok && a.cloudflare != nil {
		resolved := ""
		if change.TunnelIDFromStep > 0 {
			resolved = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
		}
		return a.cloudflare.Execute(step, resolved, time.Minute)
	}
	if change, ok := step.CloudflareChange(); ok && change.Action == systemchanges.CloudflareTunnelCreate {
		return systemchanges.StepEvidence{Code: "step-ok", SHA256: testSHA('a'), ResourceType: string(systemchanges.CloudflareTunnelResource), ResourceID: "tunnel-123"}, nil
	}
	return systemchanges.StepEvidence{Code: "step-ok", SHA256: testSHA('a')}, nil
}

func (a *systemChangesAdapter) ReplaceStateArtifacts(_ systemchanges.ExecutionLease, changeSet string, binding systemchanges.StateTransactionBinding, stream func(func(string, uint32, io.Reader) error) error) error {
	if binding.ChangeSet != changeSet {
		return errors.New("final State binding mismatch")
	}
	for name := range a.artifacts {
		if strings.HasPrefix(name, "prepared/") {
			delete(a.artifacts, name)
		}
	}
	if err := stream(func(name string, _ uint32, source io.Reader) error {
		content, err := io.ReadAll(source)
		if err == nil {
			a.artifacts[name] = content
		}
		return err
	}); err != nil {
		return err
	}
	a.stateBinding, _ = json.Marshal(binding)
	return nil
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
	if a.beforeCheck != nil {
		a.beforeCheck()
	}
	if status := a.statuses[phase]; status != "" && (check.Code == "NETWORK-GATE" || check.Code == "REMOVAL-EXTERNAL-ABSENT" || check.Code == "CLOUDFLARE-WHOLE-TUNNEL") {
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

func (a *systemChangesAdapter) VerifyIrreversibleRemovalReady(systemchanges.ExecutionLease, string, time.Duration) error {
	a.events = append(a.events, "verify irreversible removal ready")
	return a.removalReadyErr
}

func (a *systemChangesAdapter) VerifyCloudflareTokenRevoked(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction, time.Duration) (bool, error) {
	a.events = append(a.events, "verify revoked Cloudflare token")
	return a.tokenRevoked, nil
}

func (a *systemChangesAdapter) DeleteIrreversibleRemovalPhase(_ systemchanges.ExecutionLease, _ systemchanges.RecoveryTransaction, phase systemchanges.IrreversibleRemovalPhase, _ time.Duration) (systemchanges.StepEvidence, error) {
	a.events = append(a.events, "delete "+string(phase))
	if phase == a.failRemoval {
		return systemchanges.StepEvidence{}, a.removalErr
	}
	return systemchanges.StepEvidence{Code: "removal-phase-absent", SHA256: testSHA('d')}, nil
}

func (a *systemChangesAdapter) VerifyFinalRemovalAbsence(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction, time.Duration) (systemchanges.Observation, error) {
	a.events = append(a.events, "verify final removal absence")
	if !a.finalAbsent {
		return systemchanges.Observation{}, errors.New("controlled final absence failure")
	}
	return systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased}, nil
}

func (a *systemChangesAdapter) FinalizeRemoval(systemchanges.ExecutionLease, systemchanges.RecoveryTransaction, time.Duration) error {
	a.events = append(a.events, "finalize removal journal and recovery runner")
	a.recovery = nil
	return nil
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
	second := testFirewallStep(t)
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
	second := testFirewallStep(t)
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

type reclamationNetworkObserver struct{ observed networkpolicy.Observations }

func (observer reclamationNetworkObserver) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return observer.observed, nil
}

func reviewedReclamationAuthority(t *testing.T) systemchanges.ReclamationAuthority {
	t.Helper()
	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10", CertificateHostname: "direct.example.com", SSHPort: 2222, SubscriptionPort: 10443, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443}, VLESSXHTTP: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080}, VLESSWebSocket: networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081}, Hysteria2: networkpolicy.Profile{Enabled: true, Port: 443}, TUIC: networkpolicy.Profile{Enabled: true, Port: 8443}, AnyTLS: networkpolicy.Profile{Enabled: true, Port: 9443}}, Disk: networkpolicy.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100}}
	observed := networkpolicy.Observations{Host: networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20}, PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session-1"}}, Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"}, Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true}, Disk: networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"}, Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com", IPv4: []string{"192.0.2.10"}}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"}, ReclamationComplete: true}
	observed.Listeners = []networkpolicy.Listener{{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "standalone-proxy", Executable: "/opt/standalone/proxy", ProcessID: "4242"}}
	observed.Reclamation.Executables = []networkpolicy.FileConflict{{Path: "/opt/standalone/proxy", SHA256: testSHA('a'), Process: "standalone-proxy", ProcessID: "4242", Mode: 0o755, Links: 1}}
	module := networkpolicy.New(reclamationNetworkObserver{observed})
	review := module.Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PreApproval, ReclamationReview: true})
	if review.Reclamation == nil {
		t.Fatalf("reclamation review = %+v", review.Findings)
	}
	approved := module.Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval, ReclamationReview: true, ReviewedReclamationSHA256: review.Reclamation.Digest})
	return approved.ReclamationAuthority()
}

func TestReclamationInstallationCrossesOneDurableForwardOnlyBoundary(t *testing.T) {
	authority := reviewedReclamationAuthority(t)
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.InstallationMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, systemChangeTestOptions{stepTimeout: 30 * time.Second, reclamation: authority})
	cancellation := systemchanges.NewCancellation()
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, reclamationPresent: true}
	adapter.beforeStep = func() error {
		if adapter.executeCount == 2 {
			cancellation.Request()
		}
		return nil
	}
	result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
	if result.Outcome != systemchanges.Completed || adapter.reclamationPresent || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
		t.Fatalf("reclamation install = %+v events=%v", result, adapter.events)
	}
	events := strings.Join(adapter.events, ",")
	if !strings.Contains(events, "Step completed 1,verify exact reclamation target,Irreversible reclamation started 1,stop exact reclamation process,Reclamation process stopped 1,delete exact reclamation target,Reclamation target deleted 1,Step started 2") {
		t.Fatalf("durable reclamation order = %s", events)
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 1, LastCompletedChangeSet: "change-0001", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 1 || adapter.recovery != nil {
		t.Fatalf("final Managed proof = (%+v, %v), recovery=%+v", loaded, err, adapter.recovery)
	}
}

func TestReclamationInstallationCancellationBeforeCheckpointRestoresNotInstalled(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.InstallationMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, systemChangeTestOptions{stepTimeout: 30 * time.Second, reclamation: reviewedReclamationAuthority(t)})
	cancellation := systemchanges.NewCancellation()
	adapter := &systemChangesAdapter{observation: observed, reclamationPresent: true, beforeStep: func() error {
		cancellation.Request()
		return nil
	}}
	result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.NotInstalled || !adapter.reclamationPresent || !strings.Contains(strings.Join(adapter.events, ","), "reverse Delete created Cloudflare resource") {
		t.Fatalf("pre-checkpoint cancellation = %+v events=%v", result, adapter.events)
	}
}

func TestReclamationInstallationRestartsForwardAfterEveryDurableCheckpoint(t *testing.T) {
	checkpoints := []systemchanges.DurableCheckpoint{systemchanges.IrreversibleReclamationStarted, systemchanges.ReclamationProcessStopped, systemchanges.ReclamationTargetDeleted, systemchanges.StepStarted, systemchanges.StepCompleted, systemchanges.PrePublicationHealthPassed, systemchanges.StatePublicationStarted, systemchanges.StatePublished, systemchanges.PostPublicationHealthPassed, systemchanges.Complete}
	for _, checkpoint := range checkpoints {
		t.Run(string(checkpoint), func(t *testing.T) {
			stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.InstallationMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, systemChangeTestOptions{stepTimeout: 30 * time.Second, reclamation: reviewedReclamationAuthority(t)})
			adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, reclamationPresent: true, crashAfter: checkpoint}
			if checkpoint == systemchanges.StepStarted || checkpoint == systemchanges.StepCompleted {
				adapter.crashStep = 2
			}
			func() {
				defer func() { _ = recover() }()
				systemchanges.New(adapter).Apply(changeSet)
			}()
			adapter.crashAfter, adapter.crashed = "", false
			result := systemchanges.New(adapter).Recover()
			if result.Outcome != systemchanges.Completed || adapter.reclamationPresent || adapter.recovery != nil || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
				t.Fatalf("recovery after %s = %+v events=%v", checkpoint, result, adapter.events)
			}
		})
	}
}

func TestReclamationInstallationRecoverySurvivesASecondWorkerDeath(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.InstallationMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-PREFLIGHT"}, systemChangeTestOptions{stepTimeout: 30 * time.Second, reclamation: reviewedReclamationAuthority(t)})
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, reclamationPresent: true, crashAfter: systemchanges.ReclamationTargetDeleted}
	crash := func(run func()) { defer func() { _ = recover() }(); run() }
	crash(func() { systemchanges.New(adapter).Apply(changeSet) })
	adapter.crashAfter, adapter.crashStep, adapter.crashed = systemchanges.StepStarted, 2, false
	crash(func() { systemchanges.New(adapter).Recover() })
	adapter.crashAfter, adapter.crashed = "", false
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Completed || adapter.recovery != nil || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
		t.Fatalf("second forward recovery = %+v events=%v", result, adapter.events)
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

func TestRunTokenRotationCancellationImmediatelyBeforeTheCheckpointRollsBack(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.RotationMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-GATE"})
	cancellation := systemchanges.NewCancellation()
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule, afterPrepare: cancellation.Request}
	result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
	if result.Outcome != systemchanges.RollbackSucceeded || slices.Contains(adapter.events, string(systemchanges.IrreversibleRunTokenRotationStarted)) {
		t.Fatalf("pre-checkpoint cancellation = %+v; events=%v", result, adapter.events)
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

func TestConnectionProfileLifecycleArtifactsUseStatePublicationAndRollback(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutation systemchanges.MutationClass
	}{
		{"reviewed alternatives", systemchanges.SettingChangeMutation},
		{"credential rotation", systemchanges.RotationMutation},
		{"proven-lineage repair", systemchanges.RepairMutation},
	} {
		t.Run(test.name, func(t *testing.T) {
			xray := []byte(`{"inbounds":[{"tag":"PROFILE-LIFECYCLE-XRAY-MARKER"}]}`)
			singBox := []byte(`{"inbounds":[{"tag":"PROFILE-LIFECYCLE-SING-BOX-MARKER"}]}`)
			stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, test.mutation, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-REGISTRY-CONFIGURATION"}, systemChangeTestOptions{nativeXray: xray, nativeSingBox: singBox, stepTimeout: 30 * time.Second})
			if test.mutation == systemchanges.RepairMutation {
				observed.Status, observed.RecoveryCause, observed.ForwardRepairAvailable = systemchanges.RecoveryRequired, systemchanges.CurrentStateDrift, true
			}
			adapter := &systemChangesAdapter{observation: observed, agreementErr: errors.New("controlled post-publication lifecycle failure")}
			adapter.afterPrepare = func() {
				if !bytes.Contains(adapter.artifacts["prepared/xray.json"], []byte("PROFILE-LIFECYCLE-XRAY-MARKER")) || !bytes.Contains(adapter.artifacts["prepared/sing-box.json"], []byte("PROFILE-LIFECYCLE-SING-BOX-MARKER")) {
					t.Fatal("reviewed Connection Profiles artifacts did not enter protected State preparation")
				}
			}
			result := systemchanges.New(adapter).Apply(changeSet)
			if result.Outcome != systemchanges.RollbackSucceeded || !strings.Contains(strings.Join(adapter.events, ","), "Desired State published") {
				t.Fatalf("lifecycle rollback = %+v events=%v", result, adapter.events)
			}
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 {
				t.Fatalf("lifecycle rollback restored State = (%+v, %v)", loaded, err)
			}
		})
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

func TestSubscriptionArtifactSetUsesOneSystemChangesTransaction(t *testing.T) {
	check := systemchanges.Check{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"}
	serving, stopServe := transactionServeProof(t)
	defer stopServe()
	stateModule, changeSet, reused, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, check, systemChangeTestOptions{subscription: true, subscriptionBundle: serving.bundle, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root}
	proofs := 0
	executor := &transactionSubscriptionExecutor{activate: serving.activate, reverse: serving.reverse, prove: func() error {
		proofs++
		err := serving.prove()
		if err != nil {
			t.Logf("Serve proof: %v", err)
		}
		return err
	}}
	adapter := ubuntu.NewAtWithSubscriptionPublication(root, func() (systemchanges.Observation, error) { return observed, nil }, host, executor, stateModule)
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.Completed || !result.PlanConsumed || result.NothingChanged || proofs != 2 || host.agreements != 1 {
		t.Fatalf("subscription Apply = %+v proofs=%d agreements=%d", result, proofs, host.agreements)
	}
	loaded, err := stateModule.Load(LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}})
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 8 {
		t.Fatalf("published State = (%+v, %v)", loaded, err)
	}
	if !executor.current {
		t.Fatal("Subscription Publication candidate was not active at Complete")
	}
	if second := systemchanges.New(adapter).Apply(reused); second.Outcome != systemchanges.Refused || !second.NothingChanged {
		t.Fatalf("reused subscription Plan = %+v", second)
	}
}

func TestSubscriptionServingFailureRestoresStateAndPriorArtifactSet(t *testing.T) {
	check := systemchanges.Check{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"}
	serving, stopServe := transactionServeProof(t)
	defer stopServe()
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, check, systemChangeTestOptions{subscription: true, subscriptionBundle: serving.bundle, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root}
	executor := &transactionSubscriptionExecutor{activate: serving.activate, reverse: serving.reverse, prove: serving.prove, beforeCheck: func(check int) {
		if check == 2 {
			serving.breakCandidate(t)
		}
	}}
	adapter := ubuntu.NewAtWithSubscriptionPublication(root, func() (systemchanges.Observation, error) { return observed, nil }, host, executor, stateModule)
	result := systemchanges.New(adapter).Apply(changeSet)
	encoded, _ := json.Marshal(result)
	if result.Outcome != systemchanges.RollbackSucceeded || result.NothingChanged || bytes.Contains(encoded, []byte("SECRET-MARKER")) {
		t.Fatalf("failed subscription Apply = %+v", result)
	}
	if executor.current {
		t.Fatal("rollback left an active artifact set")
	}
	if err := serving.prove(); err != nil {
		t.Fatalf("rolled-back Serve state = %v", err)
	}
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil || loaded.Snapshot == nil || loaded.Snapshot.Revision != 7 {
		t.Fatalf("rolled-back State = (%+v, %v)", loaded, err)
	}
}

func TestSubscriptionRollbackFailureEntersRecoveryRequired(t *testing.T) {
	check := systemchanges.Check{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"}
	serving, stopServe := transactionServeProof(t)
	defer stopServe()
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, check, systemChangeTestOptions{subscription: true, subscriptionBundle: serving.bundle, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root}
	executor := &transactionSubscriptionExecutor{activate: serving.activate, prove: serving.prove, beforeCheck: func(check int) {
		if check == 2 {
			serving.breakCandidate(t)
		}
	}, reverseErr: true}
	adapter := ubuntu.NewAtWithSubscriptionPublication(root, func() (systemchanges.Observation, error) { return observed, nil }, host, executor, stateModule)
	result := systemchanges.New(adapter).Apply(changeSet)
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Finding.Owner != systemchanges.SubscriptionModule {
		t.Fatalf("unprovable Subscription Publication rollback = %+v", result)
	}
	if err := serving.prove(); err == nil {
		t.Fatal("Recovery Required left an invalid candidate reported healthy")
	}
}

func TestAllClientAccessRevocationCommitsOrRollsBackAsOneTransaction(t *testing.T) {
	check := systemchanges.Check{Owner: systemchanges.SubscriptionModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"}
	for _, test := range []struct {
		name      string
		failCheck int
		outcome   systemchanges.ApplyOutcome
	}{
		{"commit", 0, systemchanges.Completed},
		{"post-publication rollback", 2, systemchanges.RollbackSucceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, check, systemChangeTestOptions{subscription: true, stepTimeout: time.Second, candidateEdit: replaceAllClientAccessValues})
			root := t.TempDir()
			prepareLock(t, root)
			executor := &transactionSubscriptionExecutor{failCheck: test.failCheck}
			result := systemchanges.New(ubuntu.NewAtWithSubscriptionPublication(root, func() (systemchanges.Observation, error) { return observed, nil }, &controlledUbuntuHost{root: root}, executor, stateModule)).Apply(changeSet)
			if result.Outcome != test.outcome {
				t.Fatalf("all-client revocation = %+v", result)
			}
			lineage := intentManagedRequest()
			want := completeDesiredState()
			if test.outcome == systemchanges.Completed {
				lineage = LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: 8, LastCompletedChangeSet: "change-0008", ReleaseIdentity: testRelease}}
				replaceAllClientAccessValues(&want)
			}
			loaded, err := stateModule.Load(lineage)
			if err != nil || loaded.Snapshot == nil || !reflect.DeepEqual(loaded.Snapshot.DesiredState, want) {
				t.Fatalf("published Desired State = (%+v, %v)", loaded, err)
			}
			encoded, _ := json.Marshal(result)
			if bytes.Contains(encoded, []byte("CLIENT-ACCESS-REVOCATION-MARKER")) {
				t.Fatal("transaction evidence exposed a Client Access Value")
			}
		})
	}
}

func replaceAllClientAccessValues(candidate *DesiredState) {
	access := func(name string) ClientAccessValue {
		return NewClientAccessValue("CLIENT-ACCESS-REVOCATION-MARKER-" + name)
	}
	candidate.Subscription.Token = NewClientAccessValue(testSHA('9'))
	candidate.ConnectionProfiles.VLESSRealityVision.UUID = access("reality-uuid")
	candidate.ConnectionProfiles.VLESSRealityVision.PrivateKey = NewInfrastructureSecret("CLIENT-ACCESS-REVOCATION-MARKER-reality-private")
	candidate.ConnectionProfiles.VLESSRealityVision.PublicKey = "CLIENT-ACCESS-REVOCATION-MARKER-reality-public"
	candidate.ConnectionProfiles.VLESSRealityVision.ShortID = access("reality-short-id")
	candidate.ConnectionProfiles.VLESSXHTTP.Enabled = false
	candidate.ConnectionProfiles.VLESSXHTTP.UUID = access("xhttp-uuid")
	candidate.ConnectionProfiles.VLESSXHTTP.Path = access("xhttp-path")
	candidate.ConnectionProfiles.VLESSWebSocket.UUID = access("websocket-uuid")
	candidate.ConnectionProfiles.VLESSWebSocket.Path = access("websocket-path")
	candidate.ConnectionProfiles.Hysteria2.Password = access("hysteria2-password")
	candidate.ConnectionProfiles.TUIC.UUID = access("tuic-uuid")
	candidate.ConnectionProfiles.TUIC.Password = access("tuic-password")
	candidate.ConnectionProfiles.AnyTLS.Password = access("anytls-password")
}

type transactionSubscriptionExecutor struct {
	current     bool
	activate    func(string) error
	reverse     func() error
	prove       func() error
	beforeCheck func(int)
	checks      int
	failCheck   int
	reverseErr  bool
}

type transactionServingFixture struct {
	server         subscriptionserving.Server
	root           string
	client         *http.Client
	endpoint       string
	activeToken    string
	priorToken     string
	candidateToken string
	activeBody     []byte
	priorBody      []byte
	candidateBody  []byte
	bundle         []byte
}

func transactionServeProof(t *testing.T) (*transactionServingFixture, context.CancelFunc) {
	t.Helper()
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	for _, directory := range []struct {
		name string
		mode fs.FileMode
	}{{"var", 0o755}, {"var/lib", 0o755}, {"var/lib/sbxr", 0o755}, {"var/lib/sbxr/subscriptions", 0o750}, {"var/lib/sbxr/subscriptions/current", 0o750}, {"var/lib/sbxr/certificates", 0o755}, {"var/lib/sbxr/certificates/ip", 0o750}, {"var/lib/sbxr/certificates/ip/sets", 0o750}, {"var/lib/sbxr/certificates/ip/sets/ip-transaction", 0o750}} {
		if err := os.Mkdir(filepath.Join(root, directory.name), directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	token := strings.Repeat("7", 64)
	configuration, _ := json.Marshal(map[string]any{"token": token, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": "192.0.2.10"})
	write := func(name string, body []byte) {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("var/lib/sbxr/subscriptions/current/serving.json", configuration)
	artifactSet := func(raw []byte) map[string][]byte {
		encoded := []byte(base64.StdEncoding.EncodeToString(raw))
		bodies := map[string][]byte{"base64": encoded, "raw": raw, "v2rayn": encoded, "shadowrocket": encoded, "karing": []byte("{}"), "mihomo": []byte("proxies: []\n"), "sing-box": []byte("{}")}
		digests := map[string]string{}
		for name, body := range bodies {
			digest := sha256.Sum256(body)
			digests[name] = hex.EncodeToString(digest[:])
		}
		bodies["metadata"], _ = json.Marshal(map[string]any{
			"schema": "sbxr-subscription-artifact-set-v1", "change_set": "transaction-proof", "selected_address": "192.0.2.10", "desired_state_sha256": strings.Repeat("d", 64), "managed_inputs_sha256": strings.Repeat("e", 64),
			"relevant_checksums": map[string]string{"connection_profiles": strings.Repeat("f", 64), "subscription": strings.Repeat("1", 64)}, "compatibility_definition": "sbxr-subscription-representations-v1", "desired_state_revision": 8,
			"release_identity": map[string]string{"repository": "github.com/albertloky/SBXR", "tag": "v1.0.0", "commit": strings.Repeat("a", 40), "release_index_sha256": strings.Repeat("b", 64)}, "representations": []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box"},
			"artifact_sha256": digests, "profile_count": 1, "omissions": []map[string]string{{"id": "vless-xhttp"}, {"id": "vless-websocket"}, {"id": "hysteria2"}, {"id": "tuic"}, {"id": "anytls"}}, "validation_complete": true,
		})
		return bodies
	}
	prior := artifactSet([]byte("vless://transaction-prior"))
	for name, body := range prior {
		write("var/lib/sbxr/subscriptions/current/"+name, body)
	}
	candidate := artifactSet([]byte("vless://transaction-candidate"))
	var bundle bytes.Buffer
	writer := tar.NewWriter(&bundle)
	for _, name := range []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box", "metadata"} {
		body := candidate[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "transaction root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	write("var/lib/sbxr/certificates/ip/sets/ip-transaction/fullchain.pem", chain)
	write("var/lib/sbxr/certificates/ip/sets/ip-transaction/privkey.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err := os.Symlink("sets/ip-transaction", filepath.Join(root, "var/lib/sbxr/certificates/ip/current")); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	rootCertificate, _ := x509.ParseCertificate(rootDER)
	roots.AddCert(rootCertificate)
	server := subscriptionserving.NewAt(root, uid, gid, roots, now)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _ = server.Serve(ctx, listener) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "192.0.2.10", MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}}
	return &transactionServingFixture{server: server, root: root, client: client, endpoint: "https://" + listener.Addr().String() + "/s/", activeToken: token, priorToken: token, activeBody: prior["base64"], priorBody: prior["base64"], candidateBody: candidate["base64"], bundle: bundle.Bytes()}, cancel
}

func (fixture *transactionServingFixture) activate(prepared string) error {
	configuration, err := os.ReadFile(filepath.Join(prepared, "subscription.json"))
	var decoded struct {
		Token string `json:"token"`
	}
	if err != nil || json.Unmarshal(configuration, &decoded) != nil || decoded.Token == "" {
		return errors.New("prepared Subscription Serving configuration unavailable")
	}
	bundle, bundleErr := os.Open(filepath.Join(prepared, "subscriptions.bundle"))
	if bundleErr != nil {
		return errors.New("prepared Subscription Publication bundle unavailable")
	}
	defer bundle.Close()
	current := filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/current")
	candidate := filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/candidate")
	if err := os.Mkdir(candidate, 0o750); err != nil {
		return err
	}
	reader := tar.NewReader(bundle)
	files := 0
	for {
		header, readErr := reader.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil || header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != header.Name {
			return errors.New("candidate serving bundle invalid")
		}
		body, readErr := io.ReadAll(reader)
		if readErr != nil || os.WriteFile(filepath.Join(candidate, header.Name), body, 0o640) != nil {
			return errors.New("candidate serving snapshot unavailable")
		}
		files++
	}
	if files != 8 || os.WriteFile(filepath.Join(candidate, "serving.json"), configuration, 0o640) != nil {
		return errors.New("candidate serving snapshot incomplete")
	}
	prior := filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/prior")
	if os.Rename(current, prior) != nil || os.Rename(candidate, current) != nil {
		return errors.New("candidate serving snapshot activation failed")
	}
	fixture.activeToken = decoded.Token
	fixture.candidateToken = decoded.Token
	fixture.activeBody = fixture.candidateBody
	return nil
}

func (fixture *transactionServingFixture) reverse() error {
	current := filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/current")
	prior := filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/prior")
	rejected := filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/rejected")
	if os.Rename(current, rejected) != nil || os.Rename(prior, current) != nil {
		return errors.New("prior serving snapshot restore failed")
	}
	configuration, err := os.ReadFile(filepath.Join(current, "serving.json"))
	var decoded struct {
		Token string `json:"token"`
	}
	if err != nil || json.Unmarshal(configuration, &decoded) != nil {
		return errors.New("restored serving authorization unavailable")
	}
	fixture.activeToken = decoded.Token
	fixture.activeBody = fixture.priorBody
	return nil
}

func (fixture *transactionServingFixture) breakCandidate(t *testing.T) {
	t.Helper()
	if err := os.Remove(filepath.Join(fixture.root, "var/lib/sbxr/subscriptions/current/metadata")); err != nil {
		t.Fatal(err)
	}
}

func (fixture *transactionServingFixture) prove() error {
	if health := fixture.server.Health(); health.Status != subscriptionserving.Healthy {
		return errors.New(health.Code)
	}
	response, err := fixture.client.Get(fixture.endpoint + fixture.activeToken)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, fixture.activeBody) {
		return errors.New("running Subscription Serving proof failed")
	}
	rejectedToken := fixture.priorToken
	if fixture.activeToken == fixture.priorToken {
		rejectedToken = fixture.candidateToken
	}
	if rejectedToken != "" && rejectedToken != fixture.activeToken {
		rejected, requestErr := fixture.client.Get(fixture.endpoint + rejectedToken)
		if requestErr != nil {
			return requestErr
		}
		defer rejected.Body.Close()
		_, readErr := io.Copy(io.Discard, rejected.Body)
		if readErr != nil || rejected.StatusCode != http.StatusNotFound {
			return errors.New("inactive Subscription Serving authorization remained usable")
		}
	}
	return nil
}

func (executor *transactionSubscriptionExecutor) CaptureRollback(_ string, write func(io.Reader) error) error {
	return write(strings.NewReader(`{"target":""}`))
}

func (executor *transactionSubscriptionExecutor) Activate(root string, prepared string, _ systemchanges.StateTransactionBinding, expectedSHA256 string, _ time.Duration) (systemchanges.StepEvidence, error) {
	bundle, err := os.ReadFile(filepath.Join(prepared, "subscriptions.bundle"))
	digest := sha256.Sum256(bundle)
	if err != nil || fmt.Sprintf("%x", digest) != expectedSHA256 {
		return systemchanges.StepEvidence{}, errors.New("prepared Subscription Publication bundle mismatch")
	}
	if err := os.MkdirAll(filepath.Join(root, "run/sbxr"), 0o700); err != nil || os.WriteFile(filepath.Join(root, "run/sbxr/active-subscription.json"), []byte(`{"active":true}`), 0o600) != nil {
		return systemchanges.StepEvidence{}, errors.New("active Subscription Publication fixture unavailable")
	}
	if executor.activate != nil {
		if err := executor.activate(prepared); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	executor.current = true
	return systemchanges.StepEvidence{Code: "subscription-artifacts-activated", SHA256: expectedSHA256}, nil
}

func (executor *transactionSubscriptionExecutor) Reverse(root string, _ io.Reader, _ time.Duration) (systemchanges.StepEvidence, error) {
	if executor.reverseErr {
		return systemchanges.StepEvidence{}, errors.New("controlled Subscription Publication reverse failure")
	}
	if executor.reverse != nil {
		if err := executor.reverse(); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	_ = os.Remove(filepath.Join(root, "run/sbxr/active-subscription.json"))
	executor.current = false
	return systemchanges.StepEvidence{Code: "subscription-artifacts-restored", SHA256: testSHA('0')}, nil
}

func (executor *transactionSubscriptionExecutor) Inspect(_ string, _ io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	if executor.current {
		return systemchanges.StepEffectPresent, nil
	}
	return systemchanges.StepEffectAbsent, nil
}

func (executor *transactionSubscriptionExecutor) Check(_ string, _ string, _ systemchanges.StateTransactionBinding, _ string, _ time.Duration) (systemchanges.HealthStatus, error) {
	executor.checks++
	if executor.beforeCheck != nil {
		executor.beforeCheck(executor.checks)
	}
	if executor.checks == executor.failCheck {
		return systemchanges.Failed, errors.New("Subscription Serving health proof failed")
	}
	if executor.prove != nil {
		if err := executor.prove(); err != nil {
			return systemchanges.Failed, errors.New("Subscription Serving health proof failed")
		}
	}
	return systemchanges.Healthy, nil
}

func (*transactionSubscriptionExecutor) Cleanup(string) error { return nil }

func TestDeferredCloudflareFinalizationPublishesProviderValuesInRevisionOne(t *testing.T) {
	candidate := completeDesiredState()
	candidate.Cloudflare.AccountID = strings.Repeat("1", 32)
	candidate.Cloudflare.ZoneID = strings.Repeat("2", 32)
	candidate.Cloudflare.TunnelName = "sbxr-main"
	candidate.Cloudflare.TunnelID = ""
	candidate.Cloudflare.TunnelRunToken = InfrastructureSecret{}
	candidate.Cloudflare.XHTTPDNSRecordID = ""
	candidate.Cloudflare.WebSocketDNSRecordID = ""
	candidate.Cloudflare.DirectIPv4RecordID = ""
	candidate.Cloudflare.DirectIPv6RecordID = ""
	candidate.Software.CloudflaredVersion = "2026.7.3"
	template, err := marshalProtectedJSON(candidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(template)
	templateSHA := fmt.Sprintf("%x", digest)
	managementToken, err := cloudflaretunnel.NewManagementToken("cfat_" + strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	provider := &deferredCloudflareAPI{}
	module := cloudflaretunnel.New(provider, cloudflaretunnel.SystemClock{})
	planResult := module.Plan(t.Context(), cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: candidate.Cloudflare.AccountID, ZoneID: candidate.Cloudflare.ZoneID, ZoneName: candidate.Cloudflare.ZoneName, Token: managementToken, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: "cloudflare-change-0001", DesiredStateSHA256: templateSHA, TunnelName: candidate.Cloudflare.TunnelName,
		XHTTPHostname: candidate.Cloudflare.XHTTPHostname, WebSocketHostname: candidate.Cloudflare.WebSocketHostname,
		DirectHostname: candidate.Cloudflare.DirectHostname, PublicIPv4: candidate.NetworkPolicy.PublicIPv4,
		CloudflaredVersion: candidate.Software.CloudflaredVersion,
	})
	if planResult.Plan == nil {
		t.Fatalf("Cloudflare Plan: %+v", planResult.Health)
	}
	storage := &mutableStateStorage{err: fs.ErrNotExist}
	stateModule := New(storage)
	loaded, err := stateModule.Load(LoadRequest{Baseline: CleanVPS})
	if err != nil {
		t.Fatal(err)
	}
	request := preparedRequest(t, loaded, candidate, "cloudflare-change-0001")
	validator := request.SemanticValidators.Cloudflare.(*validatingSeams)
	validator.dynamicCloudflare = true
	request.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(planResult.Plan.Identity()), planResult.Plan.SHA256(), request.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	validator.planIdentity = string(request.ReviewedInputs.planIdentity)
	validator.planSHA256 = request.ReviewedInputs.planSHA256
	prepared, err := stateModule.PrepareDeferredCloudflareCommit(request, planResult.Plan)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := planResult.Plan.Executor(provider)
	if err != nil {
		t.Fatal(err)
	}
	observed := systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: testSHA('2'), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	authority := reviewedReclamationAuthority(t)
	changeSet, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: "cloudflare-change-0001", Mutation: systemchanges.InstallationMutation, OutcomeOwner: systemchanges.CloudflareModule,
		StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled}, TargetStateSHA256: templateSHA,
		Plan:          systemchanges.PlanBinding{Identity: planResult.Plan.Identity(), SHA256: planResult.Plan.SHA256(), VolatileSHA256: testSHA('2')},
		PreparedState: prepared, Steps: planResult.Plan.Steps(), Checks: planResult.Plan.Checks(), Reclamation: authority,
		Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute},
		Disk:     systemchanges.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &systemChangesAdapter{observation: observed, cloudflare: &executor, stateRecovery: stateModule, reclamationPresent: true, crashAfter: systemchanges.IrreversibleReclamationStarted}
	func() {
		defer func() { _ = recover() }()
		systemchanges.New(adapter).Apply(changeSet)
	}()
	adapter.crashAfter, adapter.crashed = "", false
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Completed {
		t.Fatalf("Apply = %+v, events=%v", result, adapter.events)
	}
	document := string(storage.document)
	for _, value := range []string{"f70ff985-a4ef-4643-bbbc-4a0ed4fc8415", "CLOUDFLARE-DEFERRED-RUN-TOKEN-MARKER", strings.Repeat("3", 32), strings.Repeat("4", 32), strings.Repeat("5", 32)} {
		if !strings.Contains(document, value) {
			t.Fatalf("published revision 1 omitted finalized value %q", value)
		}
	}
	finalized := slices.ContainsFunc(adapter.events, func(event string) bool { return strings.HasPrefix(event, string(systemchanges.StateFinalized)) })
	if strings.Count(document, "CLOUDFLARE-DEFERRED-RUN-TOKEN-MARKER") != 1 || !finalized {
		t.Fatalf("deferred finalization was not one-use and durable: events=%v", adapter.events)
	}
	events := strings.Join(adapter.events, ",")
	if strings.Index(events, string(systemchanges.StateFinalized)) > strings.Index(events, string(systemchanges.IrreversibleReclamationStarted)) {
		t.Fatalf("recovery material was not durable before reclamation: %v", adapter.events)
	}
	if strings.Contains(strings.Join(adapter.events, "\n")+fmt.Sprintf("%+v", result), "CLOUDFLARE-DEFERRED-RUN-TOKEN-MARKER") {
		t.Fatal("run token escaped protected State artifacts")
	}
}

func TestOwnerAssistedRunTokenRotationPausesThenRecoversForwardWithBothRoutes(t *testing.T) {
	starting := completeDesiredState()
	starting.Cloudflare.AccountID = strings.Repeat("1", 32)
	starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
	starting.Cloudflare.TunnelID = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	starting.Cloudflare.XHTTPDNSRecordID = strings.Repeat("3", 32)
	starting.Cloudflare.WebSocketDNSRecordID = strings.Repeat("4", 32)
	starting.Cloudflare.DirectIPv4RecordID = strings.Repeat("5", 32)
	starting.Software.CloudflaredVersion = "2026.7.3"
	storage := &mutableStateStorage{document: documentFor(t, starting)}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	template, _ := marshalProtectedJSON(starting)
	templateDigest := sha256.Sum256(template)
	managementToken, _ := cloudflaretunnel.NewManagementToken("cfat_ROTATION-MANAGEMENT-TOKEN-MARKER-0000")
	provider := &deferredCloudflareAPI{}
	planResult := cloudflaretunnel.New(provider, cloudflaretunnel.SystemClock{}).Plan(t.Context(), cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName, Token: managementToken, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: "cloudflare-run-token-rotation-integration", StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: fmt.Sprintf("%x", templateDigest),
		XHTTPHostname: starting.Cloudflare.XHTTPHostname, WebSocketHostname: starting.Cloudflare.WebSocketHostname, DirectHostname: starting.Cloudflare.DirectHostname, PublicIPv4: starting.NetworkPolicy.PublicIPv4, CloudflaredVersion: starting.Software.CloudflaredVersion,
		RunTokenRotation: cloudflaretunnel.RunTokenRotation{TunnelID: starting.Cloudflare.TunnelID, XHTTPDNSRecordID: starting.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: starting.Cloudflare.WebSocketDNSRecordID, DirectIPv4RecordID: starting.Cloudflare.DirectIPv4RecordID},
	})
	if planResult.Plan == nil {
		t.Fatalf("rotation Plan = %+v", planResult.Health)
	}
	request := preparedRequest(t, loaded, starting, "cloudflare-run-token-rotation-integration")
	request.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(planResult.Plan.Identity()), planResult.Plan.SHA256(), request.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := stateModule.PrepareRunTokenRotationCommit(request, planResult.Plan)
	if err != nil {
		t.Fatal(err)
	}
	observed := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "installed-state", StateRevision: 7, StateSHA256: loaded.loaded.payloadChecksum, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: testSHA('2'), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule}
	result := planResult.Plan.Apply(systemchanges.New(adapter), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: observed.StateSHA256}, observed.VolatileSHA256, tokenChangeDisk())
	if result.Outcome != systemchanges.AwaitingRunTokenRotation || !slices.Contains(adapter.events, string(systemchanges.IrreversibleRunTokenRotationStarted)) || adapter.artifacts["snapshot/prior-state.json"] != nil {
		t.Fatalf("initial rotation = %+v; events=%v artifacts=%v", result, adapter.events, adapter.artifacts)
	}
	if waiting := systemchanges.New(adapter).Recover(); waiting.Outcome != systemchanges.AwaitingRunTokenRotation {
		t.Fatalf("unchanged provider token = %+v", waiting)
	}
	adapter.rotationChanged = true
	adapter.failStep = 1
	if failed := systemchanges.New(adapter).Recover(); failed.Outcome != systemchanges.RecoveryRequiredOutcome || slices.ContainsFunc(adapter.events, func(event string) bool { return strings.HasPrefix(event, "reverse ") }) {
		t.Fatalf("failed reconnect was not forward-only = %+v; events=%v", failed, adapter.events)
	}
	checks := adapter.recovery.Checks
	adapter.recovery.Checks = nil
	if unproved := systemchanges.New(adapter).Recover(); unproved.Outcome != systemchanges.RecoveryRequiredOutcome {
		t.Fatalf("missing recovery health gates = %+v", unproved)
	}
	adapter.recovery.Checks = checks
	adapter.failStep = 0
	adapter.statuses = map[systemchanges.GatePhase]systemchanges.HealthStatus{systemchanges.PrePublication: systemchanges.Failed}
	if partial := systemchanges.New(adapter).Recover(); partial.Outcome != systemchanges.RecoveryRequiredOutcome || slices.ContainsFunc(adapter.events, func(event string) bool { return strings.HasPrefix(event, "reverse ") }) {
		t.Fatalf("one-route failure was not forward-only = %+v; events=%v", partial, adapter.events)
	}
	adapter.statuses = nil
	completed := systemchanges.New(adapter).Recover()
	if completed.Outcome != systemchanges.Completed {
		t.Fatalf("forward rotation recovery = %+v; events=%v", completed, adapter.events)
	}
	if adapter.artifacts["snapshot/prior-state.json"] != nil {
		t.Fatal("forward recovery recreated the deleted old-token rollback snapshot")
	}
	document := string(storage.document)
	if !strings.Contains(document, "CLOUDFLARE-ROTATED-RUN-TOKEN-MARKER") || strings.Contains(document, "CLOUDFLARE-RUN-SECRET-MARKER-00001") {
		t.Fatalf("published rotation State = %s", document)
	}
	rendered := strings.Join(adapter.events, "\n") + fmt.Sprintf("%+v %+v", result, completed)
	for _, secret := range []string{"CLOUDFLARE-ROTATED-RUN-TOKEN-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("run token leaked through ordinary output: %s", rendered)
		}
	}
}

func TestManagedCloudflareRepairUsesOneReviewedTransactionAndPublishesTheUnchangedIntent(t *testing.T) {
	starting := completeDesiredState()
	starting.Cloudflare.AccountID = strings.Repeat("1", 32)
	starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
	starting.Cloudflare.TunnelID = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
	starting.Cloudflare.XHTTPDNSRecordID = strings.Repeat("3", 32)
	starting.Cloudflare.WebSocketDNSRecordID = strings.Repeat("4", 32)
	starting.Cloudflare.DirectIPv4RecordID = strings.Repeat("5", 32)
	starting.Software.CloudflaredVersion = "2026.7.3"
	storage := &mutableStateStorage{document: documentFor(t, starting)}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	template, _ := marshalProtectedJSON(starting)
	digest := sha256.Sum256(template)
	token, _ := cloudflaretunnel.NewManagementToken("cfat_REPAIR-MANAGEMENT-TOKEN-MARKER-000000")
	provider := &deferredCloudflareAPI{repair: true, whole: cloudflaretunnel.WholeTunnelObservation{
		TunnelID: starting.Cloudflare.TunnelID, Connected: false,
		Routes: []cloudflaretunnel.Route{{Hostname: starting.Cloudflare.XHTTPHostname, Service: "https://wrong.example"}},
		DNSRecords: []cloudflaretunnel.DNSObservation{
			{ID: starting.Cloudflare.XHTTPDNSRecordID, Name: starting.Cloudflare.XHTTPHostname, Type: "CNAME", Content: "wrong.example", Proxied: true},
			{ID: starting.Cloudflare.WebSocketDNSRecordID, Name: starting.Cloudflare.WebSocketHostname, Type: "CNAME", Content: starting.Cloudflare.TunnelID + ".cfargotunnel.com", Proxied: true},
			{ID: starting.Cloudflare.DirectIPv4RecordID, Name: starting.Cloudflare.DirectHostname, Type: "A", Content: starting.NetworkPolicy.PublicIPv4},
		}, XHTTPOriginReachable: true, WebSocketOriginReachable: true,
	}}
	request := cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName, Token: token, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: "cloudflare-managed-repair-integration", StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: fmt.Sprintf("%x", digest), TunnelName: starting.Cloudflare.TunnelName,
		XHTTPHostname: starting.Cloudflare.XHTTPHostname, WebSocketHostname: starting.Cloudflare.WebSocketHostname, DirectHostname: starting.Cloudflare.DirectHostname, PublicIPv4: starting.NetworkPolicy.PublicIPv4, CloudflaredVersion: starting.Software.CloudflaredVersion,
		ManagedRepair: cloudflaretunnel.RunTokenRotation{TunnelID: starting.Cloudflare.TunnelID, XHTTPDNSRecordID: starting.Cloudflare.XHTTPDNSRecordID, WebSocketDNSRecordID: starting.Cloudflare.WebSocketDNSRecordID, DirectIPv4RecordID: starting.Cloudflare.DirectIPv4RecordID},
	}
	planResult := cloudflaretunnel.New(provider, cloudflaretunnel.SystemClock{}).Plan(t.Context(), request)
	if planResult.Plan == nil {
		t.Fatalf("repair Plan = %+v", planResult.Health)
	}
	prepare := preparedRequest(t, loaded, starting, "cloudflare-managed-repair-integration")
	prepare.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(planResult.Plan.Identity()), planResult.Plan.SHA256(), prepare.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	changed := prepare
	changed.Candidate.Cloudflare.TunnelID = "11111111-1111-4111-8111-111111111111"
	if _, err := stateModule.PrepareCloudflareRepairCommit(changed, planResult.Plan); err == nil {
		t.Fatal("State accepted a repair Plan for a changed Tunnel identifier")
	}
	prepared, err := stateModule.PrepareCloudflareRepairCommit(prepare, planResult.Plan)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := planResult.Plan.Executor(provider)
	if err != nil {
		t.Fatal(err)
	}
	observed := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "installed-state", StateRevision: 7, StateSHA256: loaded.loaded.payloadChecksum, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: testSHA('2'), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	adapter := &systemChangesAdapter{observation: observed, cloudflare: &executor}
	result := planResult.Plan.Apply(systemchanges.New(adapter), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: observed.StateSHA256}, observed.VolatileSHA256, tokenChangeDisk())
	if result.Outcome != systemchanges.Completed {
		t.Fatalf("repair Apply = %+v; events=%v", result, adapter.events)
	}
	loadedAfter, err := stateModule.Load(intentManagedRequestForRevision(8, "cloudflare-managed-repair-integration"))
	if err != nil || loadedAfter.Snapshot == nil || loadedAfter.Snapshot.DesiredState.Cloudflare.TunnelID != starting.Cloudflare.TunnelID {
		t.Fatalf("repaired State = (%+v, %v)", loadedAfter, err)
	}
}

func TestManagementTokenChangePublishesOnceWithoutExposingEitherToken(t *testing.T) {
	for _, action := range []cloudflaretunnel.ManagementTokenAction{cloudflaretunnel.ManagementTokenReplace, cloudflaretunnel.ManagementTokenRemove} {
		t.Run(string(action), func(t *testing.T) {
			stateModule, plan, prepared, observed, storage := preparedManagementTokenChange(t, action, "success-"+string(action))
			adapter := &systemChangesAdapter{observation: observed, beforeStep: func() error {
				if !strings.Contains(storage.document, "CLOUDFLARE-MANAGEMENT-SECRET-MARKER") || strings.Contains(storage.document, "REPLACEMENT-TOKEN-SECRET-MARKER") {
					return errors.New("stored token changed before State publication")
				}
				return nil
			}}
			result := plan.Apply(systemchanges.New(adapter), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: observed.StateSHA256}, observed.VolatileSHA256, tokenChangeDisk())
			if result.Outcome != systemchanges.Completed {
				t.Fatalf("token change Apply = %+v; events=%v", result, adapter.events)
			}
			loaded, err := stateModule.Load(intentManagedRequestForRevision(8, ChangeSetIdentity("cloudflare-token-success-"+string(action))))
			if err != nil || loaded.Snapshot == nil {
				t.Fatalf("published token State = (%+v, %v)", loaded, err)
			}
			cloudflare := loaded.Snapshot.DesiredState.Cloudflare
			if action == cloudflaretunnel.ManagementTokenReplace && (cloudflare.ManagementTokenRemoved || cloudflare.ManagementTokenState != "" || cloudflare.ManagementToken.value != "cfat_REPLACEMENT-TOKEN-SECRET-MARKER-000000") || action == cloudflaretunnel.ManagementTokenRemove && (!cloudflare.ManagementTokenRemoved || cloudflare.ManagementTokenState != CloudflareManagementUnmanaged || cloudflare.ManagementToken.isSet()) {
				t.Fatalf("published token facts = %+v", cloudflare)
			}
			rendered := strings.Join(adapter.events, "\n") + fmt.Sprintf("%+v", result)
			if strings.Contains(rendered, "MANAGEMENT-SECRET-MARKER") || strings.Contains(rendered, "REPLACEMENT-TOKEN-SECRET-MARKER") {
				t.Fatal("token change escaped protected State artifacts")
			}
		})
	}
}

func TestManagementTokenReplacementRollbackAndRestartRestoreTheOldToken(t *testing.T) {
	for _, test := range []struct {
		name    string
		restart bool
	}{
		{name: "required failure"},
		{name: "restart after publication", restart: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateModule, plan, prepared, observed, _ := preparedManagementTokenChange(t, cloudflaretunnel.ManagementTokenReplace, strings.ReplaceAll(test.name, " ", "-"))
			adapter := &systemChangesAdapter{observation: observed, stateRecovery: stateModule}
			if test.restart {
				adapter.crashAfter = systemchanges.StatePublished
				func() {
					defer func() { _ = recover() }()
					_ = plan.Apply(systemchanges.New(adapter), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: observed.StateSHA256}, observed.VolatileSHA256, tokenChangeDisk())
				}()
				if !adapter.crashed {
					t.Fatal("controlled token-replacement worker did not stop")
				}
				if result := systemchanges.New(adapter).Recover(); result.Outcome != systemchanges.RollbackSucceeded {
					t.Fatalf("replacement restart recovery = %+v; events=%v", result, adapter.events)
				}
			} else {
				adapter.agreementErr = errors.New("controlled replacement agreement failure")
				result := plan.Apply(systemchanges.New(adapter), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: observed.StateSHA256}, observed.VolatileSHA256, tokenChangeDisk())
				if result.Outcome != systemchanges.RollbackSucceeded {
					t.Fatalf("replacement rollback = %+v; events=%v", result, adapter.events)
				}
			}
			loaded, err := stateModule.Load(intentManagedRequest())
			if err != nil || loaded.Snapshot == nil || loaded.Snapshot.DesiredState.Cloudflare.ManagementToken.value != "CLOUDFLARE-MANAGEMENT-SECRET-MARKER" || loaded.Snapshot.DesiredState.Cloudflare.ManagementTokenRemoved {
				t.Fatalf("replacement rollback State = (%+v, %v)", loaded, err)
			}
		})
	}
}

func preparedManagementTokenChange(t *testing.T, action cloudflaretunnel.ManagementTokenAction, suffix string) (Interface, *cloudflaretunnel.Plan, *PreparedCommit, systemchanges.Observation, *mutableStateStorage) {
	t.Helper()
	starting := completeDesiredState()
	starting.Cloudflare.AccountID = strings.Repeat("1", 32)
	starting.Cloudflare.ZoneID = strings.Repeat("2", 32)
	storage := &mutableStateStorage{document: documentFor(t, starting)}
	stateModule := New(storage)
	loaded, err := stateModule.Load(intentManagedRequest())
	if err != nil {
		t.Fatal(err)
	}
	template := starting
	template.Cloudflare.ManagementToken = InfrastructureSecret{}
	if action == cloudflaretunnel.ManagementTokenRemove {
		template.Cloudflare.ManagementTokenRemoved = true
		template.Cloudflare.ManagementTokenState = CloudflareManagementUnmanaged
	}
	templateJSON, err := marshalProtectedJSON(template)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(templateJSON)
	changeSet := "cloudflare-token-" + suffix
	managementToken := cloudflaretunnel.ManagementToken{}
	final := template
	if action == cloudflaretunnel.ManagementTokenReplace {
		managementToken, err = cloudflaretunnel.NewManagementToken("cfat_REPLACEMENT-TOKEN-SECRET-MARKER-000000")
		if err != nil {
			t.Fatal(err)
		}
		final.Cloudflare.ManagementToken = NewInfrastructureSecret("cfat_REPLACEMENT-TOKEN-SECRET-MARKER-000000")
	}
	provider := &deferredCloudflareAPI{}
	var inventory cloudflaretunnel.ManagementTokenInventoryAuthority
	if action == cloudflaretunnel.ManagementTokenRemove {
		inventory, err = stateModule.ManagementTokenInventory(loaded)
		if err != nil {
			t.Fatal(err)
		}
	}
	planResult := cloudflaretunnel.New(provider, cloudflaretunnel.SystemClock{}).Plan(t.Context(), cloudflaretunnel.PlanRequest{
		Authority: cloudflaretunnel.ViewRequest{AccountID: starting.Cloudflare.AccountID, ZoneID: starting.Cloudflare.ZoneID, ZoneName: starting.Cloudflare.ZoneName, Token: managementToken, NetworkPath: networkpolicy.CloudflareTunnelPath{HTTPS: networkpolicy.ProofPassed, TCP7844: networkpolicy.ProofPassed, UDP7844: networkpolicy.ProofPassed}},
		ChangeSet: changeSet, StartingRevision: 7, StartingStateSHA256: loaded.loaded.payloadChecksum, DesiredStateSHA256: fmt.Sprintf("%x", digest), ManagementToken: stateTestManagementTokenChange(action, inventory),
	})
	if planResult.Plan == nil {
		t.Fatalf("management-token Plan = %+v", planResult.Health)
	}
	request := preparedRequest(t, loaded, template, ChangeSetIdentity(changeSet))
	validator := request.SemanticValidators.Cloudflare.(*validatingSeams)
	validator.want = final
	request.ServiceMaterials = serviceMaterialsFor(final)
	request.ReviewedInputs, err = NewReviewedInputs(PlanIdentity(planResult.Plan.Identity()), planResult.Plan.SHA256(), request.ReviewedInputs.managed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := stateModule.PrepareManagementTokenCommit(request, planResult.Plan)
	if err != nil {
		t.Fatal(err)
	}
	observed := systemchanges.Observation{Status: systemchanges.Managed, LastChangeSet: "change-0007", StateRevision: 7, StateSHA256: loaded.loaded.payloadChecksum, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, VolatileSHA256: testSHA('2'), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	return stateModule, planResult.Plan, prepared, observed, storage
}

func tokenChangeDisk() systemchanges.DiskRequirement {
	return systemchanges.DiskRequirement{PreparationBytes: 100, TemporaryBytes: 100, SnapshotBytes: 100, JournalBytes: 100, RollbackBytes: 100, OverheadBytes: 100}
}

func intentManagedRequestForRevision(revision uint64, changeSet ChangeSetIdentity) LoadRequest {
	return LoadRequest{Baseline: ManagedEvidence, SupportedRelease: testRelease, Lineage: &LineageProof{Revision: revision, LastCompletedChangeSet: changeSet, ReleaseIdentity: testRelease}}
}

type deferredCloudflareAPI struct {
	dns    int
	repair bool
	whole  cloudflaretunnel.WholeTunnelObservation
}

func (api *deferredCloudflareAPI) Observe(context.Context, cloudflaretunnel.ObservationRequest) (cloudflaretunnel.Observation, error) {
	return cloudflaretunnel.Observation{Account: cloudflaretunnel.AccountObservation{ID: strings.Repeat("1", 32)}, Zone: cloudflaretunnel.ZoneObservation{ID: strings.Repeat("2", 32), AccountID: strings.Repeat("1", 32), Name: "example.com", Status: "active", AssignedNameServers: []string{"a.ns.cloudflare.com"}, ObservedNameServers: []string{"a.ns.cloudflare.com"}}, Token: cloudflaretunnel.TokenObservation{ID: strings.Repeat("6", 32), Status: "active"}, Policies: []cloudflaretunnel.TokenPolicy{{Effect: "allow", PermissionGroups: []string{"Account API Tokens Read", "Cloudflare Tunnel Edit"}, Resources: map[string]string{"com.cloudflare.api.account." + strings.Repeat("1", 32): "*"}}, {Effect: "allow", PermissionGroups: []string{"DNS Write"}, Resources: map[string]string{"com.cloudflare.api.account.zone." + strings.Repeat("2", 32): "*"}}}}, nil
}
func (api *deferredCloudflareAPI) ObserveMutation(_ context.Context, request cloudflaretunnel.MutationRequest) (cloudflaretunnel.MutationObservation, error) {
	if api.repair {
		ids := map[string][]string{"xhttp.example.com": {strings.Repeat("3", 32)}, "ws.example.com": {strings.Repeat("4", 32)}, "direct.example.com": {strings.Repeat("5", 32)}}
		dns := make([]cloudflaretunnel.OwnedResource, len(ids[request.Hostname]))
		for index, id := range ids[request.Hostname] {
			dns[index] = cloudflaretunnel.OwnedResource{ID: id, Name: request.Hostname}
		}
		return cloudflaretunnel.MutationObservation{Digest: testSHA('a'), Tunnels: []cloudflaretunnel.OwnedResource{{ID: "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415", Name: request.Tunnel}}, DNSRecords: dns}, nil
	}
	return cloudflaretunnel.MutationObservation{Digest: testSHA('a')}, nil
}
func (api *deferredCloudflareAPI) CreateTunnel(context.Context, cloudflaretunnel.CreateTunnelRequest) (cloudflaretunnel.CreatedTunnel, error) {
	return cloudflaretunnel.NewCreatedTunnelResult("f70ff985-a4ef-4643-bbbc-4a0ed4fc8415", "sbxr-main", "CLOUDFLARE-DEFERRED-RUN-TOKEN-MARKER")
}
func (api *deferredCloudflareAPI) PutConfiguration(_ context.Context, request cloudflaretunnel.PutConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{TunnelID: request.TunnelID, Version: 1, Routes: request.Routes}, nil
}
func (*deferredCloudflareAPI) GetConfiguration(_ context.Context, request cloudflaretunnel.GetConfigurationRequest) (cloudflaretunnel.Configuration, error) {
	return cloudflaretunnel.Configuration{TunnelID: request.TunnelID, Version: 1}, nil
}
func (api *deferredCloudflareAPI) CreateDNSRecord(_ context.Context, request cloudflaretunnel.CreateDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	api.dns++
	return cloudflaretunnel.OwnedResource{ID: strings.Repeat(string(rune('2'+api.dns)), 32), Name: request.Name}, nil
}
func (*deferredCloudflareAPI) GetDNSRecord(_ context.Context, request cloudflaretunnel.GetDNSRecordRequest) (cloudflaretunnel.DNSObservation, error) {
	return cloudflaretunnel.DNSObservation{ID: request.ID, Name: "xhttp.example.com", Type: "CNAME", Content: "old.example.com", Proxied: true}, nil
}
func (*deferredCloudflareAPI) PutDNSRecord(_ context.Context, request cloudflaretunnel.PutDNSRecordRequest) (cloudflaretunnel.OwnedResource, error) {
	return cloudflaretunnel.OwnedResource{ID: request.ID, Name: request.Name}, nil
}
func (api *deferredCloudflareAPI) ObserveWholeTunnel(_ context.Context, request cloudflaretunnel.WholeTunnelRequest) (cloudflaretunnel.WholeTunnelObservation, error) {
	if api.whole.TunnelID != "" {
		return api.whole, nil
	}
	dns := []cloudflaretunnel.DNSObservation{}
	for index, record := range request.DNSRecords {
		switch index {
		case 0:
			dns = append(dns, cloudflaretunnel.DNSObservation{ID: record.ID, Name: "xhttp.example.com", Type: "CNAME", Content: request.TunnelID + ".cfargotunnel.com", Proxied: true})
		case 1:
			dns = append(dns, cloudflaretunnel.DNSObservation{ID: record.ID, Name: "ws.example.com", Type: "CNAME", Content: request.TunnelID + ".cfargotunnel.com", Proxied: true})
		case 2:
			dns = append(dns, cloudflaretunnel.DNSObservation{ID: record.ID, Name: "direct.example.com", Type: "A", Content: "192.0.2.10"})
		}
	}
	return cloudflaretunnel.WholeTunnelObservation{TunnelID: request.TunnelID, Connected: true, Routes: []cloudflaretunnel.Route{{Hostname: "xhttp.example.com", Service: "http://127.0.0.1:11080"}, {Hostname: "ws.example.com", Service: "http://127.0.0.1:11081"}, {Service: "http_status:404"}}, DNSRecords: dns, XHTTPOriginReachable: true, WebSocketOriginReachable: true}, nil
}
func (*deferredCloudflareAPI) ObserveCertificateDNS(context.Context, cloudflaretunnel.CertificateDNSRequest) (cloudflaretunnel.CertificateDNSFacts, error) {
	return cloudflaretunnel.CertificateDNSFacts{}, nil
}
func (*deferredCloudflareAPI) DeleteDNSRecord(context.Context, cloudflaretunnel.DeleteDNSRecordRequest) error {
	return nil
}
func (*deferredCloudflareAPI) DeleteTunnel(context.Context, cloudflaretunnel.DeleteTunnelRequest) error {
	return nil
}

func testFirewallStep(t *testing.T) systemchanges.Step {
	t.Helper()
	step, err := systemchanges.NewFirewallPolicyStep("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2222 accept\n }\n}", 2222)
	if err != nil {
		t.Fatal(err)
	}
	return step
}

func preparedSystemChangeWithCheck(t *testing.T, check systemchanges.Check) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, check)
}

func preparedSystemChangeForMutation(t *testing.T, mutation systemchanges.MutationClass, check systemchanges.Check, extraSteps ...systemchanges.Step) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	return preparedSystemChangeWithOptions(t, mutation, check, systemChangeTestOptions{extraSteps: extraSteps, stepTimeout: 30 * time.Second})
}

type systemChangeTestOptions struct {
	extraSteps         []systemchanges.Step
	steps              []systemchanges.Step
	stepTimeout        time.Duration
	identity           string
	startingStatus     systemchanges.InstallationStatus
	publishBeforeError bool
	publishAfterError  bool
	nativeXray         []byte
	nativeSingBox      []byte
	candidateEdit      func(*DesiredState)
	subscription       bool
	subscriptionBundle []byte
	reclamation        systemchanges.ReclamationAuthority
}

func preparedSystemChangeWithOptions(t *testing.T, mutation systemchanges.MutationClass, check systemchanges.Check, options systemChangeTestOptions) (Interface, *systemchanges.ChangeSet, *systemchanges.ChangeSet, systemchanges.Observation) {
	t.Helper()
	candidate := completeDesiredState()
	candidate.Subscription.Token = NewClientAccessValue(testSHA('e'))
	if options.candidateEdit != nil {
		options.candidateEdit(&candidate)
	}
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
	if len(options.nativeXray) > 0 {
		validator := request.SemanticValidators.ConnectionProfiles.(*validatingSeams)
		singBox := options.nativeSingBox
		if len(singBox) == 0 {
			var err error
			singBox, err = marshalProtectedJSON(expectedServiceMaterials(candidate).SingBox)
			if err != nil {
				t.Fatal(err)
			}
		}
		request.SemanticValidators.ConnectionProfiles = &nativeProfilesPreparer{validatingSeams: validator, xray: options.nativeXray, singBox: singBox}
	}
	if options.subscription {
		validator := request.SemanticValidators.Subscription.(*validatingSeams)
		validator.subscriptionBundle = append([]byte(nil), options.subscriptionBundle...)
		bundle, bundleErr := validator.subscriptionPublicationBundle()
		if bundleErr != nil {
			t.Fatal(bundleErr)
		}
		digest := sha256.Sum256(bundle)
		validator.planSHA256 = fmt.Sprintf("%x", digest)
		reviewed, reviewedErr := NewReviewedInputs(PlanIdentity(validator.planIdentity), validator.planSHA256, request.ReviewedInputs.managed)
		if reviewedErr != nil {
			t.Fatal(reviewedErr)
		}
		request.ReviewedInputs = reviewed
		request.SubscriptionPublication = validator
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
	} else if mutation == systemchanges.CompleteRemovalMutation && options.startingStatus == systemchanges.RecoveryRequired {
		starting.Status, observed.Status, observed.RecoveryCause = systemchanges.RecoveryRequired, systemchanges.RecoveryRequired, systemchanges.StateLineageUnprovable
	}
	owner := systemchanges.ConnectionProfilesModule
	if options.subscription {
		owner = systemchanges.SubscriptionModule
	}
	step, err := systemchanges.NewStep(owner, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	steps := append([]systemchanges.Step{step}, options.extraSteps...)
	if options.reclamation != nil {
		prelude, preludeErr := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareTunnelCreate, AccountID: "account-123", TunnelName: "sbxr-main"})
		if preludeErr != nil {
			t.Fatal(preludeErr)
		}
		steps = append([]systemchanges.Step{prelude}, steps...)
	}
	if len(options.steps) > 0 {
		steps = append([]systemchanges.Step(nil), options.steps...)
	}
	var typedRemoval systemchanges.TypedRemovalConfirmation
	var permanentRemoval systemchanges.PermanentRemovalSelection
	if mutation == systemchanges.CompleteRemovalMutation {
		console := ownerconsole.New(controlledOwnerRemovalObserver{})
		review, reviewErr := console.StartRemovalReview("removal-review-0008")
		typed, typedErr := console.RecordTypedPhrase(review)
		selected, selectedErr := console.SelectPermanentRemoval(review, typed)
		if reviewErr != nil || typedErr != nil || selectedErr != nil {
			t.Fatalf("complete removal review: %v, %v, %v", reviewErr, typedErr, selectedErr)
		}
		typedRemoval, permanentRemoval = typed, selected
		steps = options.extraSteps
		if len(steps) == 0 {
			for _, resource := range []struct {
				category systemchanges.RemovalResource
				id       string
			}{{systemchanges.FirewallTableResource, "inet-sbxr"}, {systemchanges.PublicListenerResource, "listener-xray"}, {systemchanges.PublicServiceResource, "service-xray"}} {
				authority, authorityErr := networkpolicy.NewRemoval(controlledPublicRemovalObserver{}).ProveRemovalResource("removal-review-0008", string(resource.category), resource.id)
				step, stepErr := systemchanges.NewPublicExposureRemovalStep(selected, authority)
				if authorityErr != nil || stepErr != nil {
					t.Fatalf("public removal step: %v, %v", authorityErr, stepErr)
				}
				steps = append(steps, step)
			}
			for _, resource := range []struct {
				category systemchanges.RemovalResource
				id       string
			}{{systemchanges.CloudflareRouteResource, "route-xhttp"}, {systemchanges.CloudflareDNSRecordResource, "dns-xhttp"}, {systemchanges.CloudflareDNSRecordResource, "dns-websocket"}, {systemchanges.CloudflareDNSRecordResource, "dns-direct-ipv4"}, {systemchanges.CloudflareTunnelResource, "tunnel-xhttp"}} {
				authority, authorityErr := cloudflaretunnel.NewRemoval(controlledRemovalObserver{}).ProveRemovalResource("removal-review-0008", string(resource.category), resource.id)
				step, stepErr := systemchanges.NewCloudflareRemovalStep(selected, authority)
				if authorityErr != nil || stepErr != nil {
					t.Fatalf("external removal step: %v, %v", authorityErr, stepErr)
				}
				steps = append(steps, step)
			}
		}
	}
	spec := systemchanges.ChangeSetSpec{
		Identity: identity, Mutation: mutation, OutcomeOwner: owner,
		StartingState: starting, TargetStateSHA256: target,
		Plan:          systemchanges.PlanBinding{Identity: planIdentity, SHA256: planSHA256, VolatileSHA256: testSHA('2')},
		PreparedState: prepared, TypedRemovalConfirmation: typedRemoval, PermanentRemovalSelection: permanentRemoval, Steps: steps,
		Reclamation: options.reclamation,
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
		systemchanges.RotationMutation, systemchanges.CertificateChangeMutation, systemchanges.UpdateMutation, systemchanges.CertificateRenewalMutation, systemchanges.CompleteRemovalMutation,
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

func TestCompleteRemovalDurablyCrossesIrreversibleBoundaryBeforePermanentCloudflareDeletion(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed}
	result := systemchanges.New(adapter).Apply(changeSet)
	joined := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.AwaitingTokenRevocation || result.RestoredStatus != "" || result.NothingChanged || result.Finding != nil || strings.Contains(joined, string(systemchanges.StatePublicationStarted)) || strings.Contains(joined, string(systemchanges.Complete)) || !strings.Contains(joined, string(systemchanges.OwnedExternalDeletionVerified)) || !strings.Contains(joined, string(systemchanges.IrreversibleRemovalStarted)) || adapter.recovery == nil {
		t.Fatalf("reversible Complete removal = %+v; events=%v", result, adapter.events)
	}
	public := strings.LastIndex(joined, "execute "+string(systemchanges.RemoveOwnedPublicExposure))
	irreversible := strings.Index(joined, string(systemchanges.IrreversibleRemovalStarted))
	route := strings.Index(joined, "execute "+string(systemchanges.DeleteOwnedCloudflareResource))
	dns := strings.Index(joined, "delete "+string(systemchanges.CloudflareDNSRecordsPhase))
	tunnel := strings.Index(joined, "delete "+string(systemchanges.CloudflareTunnelPhase))
	if public < 0 || route < public || irreversible < route || dns < irreversible || tunnel < dns {
		t.Fatalf("permanent provider deletion crossed the checkpoint early: %v", adapter.events)
	}
	wantLimits := []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"}
	if strings.Join(result.UnremovableTraces, ",") != strings.Join(wantLimits, ",") {
		t.Fatalf("Complete removal limits = %v, want %v", result.UnremovableTraces, wantLimits)
	}
}

func TestCompleteRemovalKeepsTunnelRouteChangeRollbackSafeUntilCheckpoint(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed, failStep: 4}
	result := systemchanges.New(adapter).Apply(changeSet)
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.Managed || strings.Contains(events, string(systemchanges.IrreversibleRemovalStarted)) || !strings.Contains(events, "reverse") {
		t.Fatalf("Cloudflare route failure = %+v; events=%v", result, adapter.events)
	}
}

func TestCompleteRemovalRefusesTheIrreversibleCheckpointUntilLocalDeletionIsReady(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed, removalReadyErr: errors.New("controlled ownership evidence failure")}
	result := systemchanges.New(adapter).Apply(changeSet)
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.Managed || strings.Contains(events, string(systemchanges.IrreversibleRemovalStarted)) || !strings.Contains(events, "verify irreversible removal ready") || !strings.Contains(events, "reverse") {
		t.Fatalf("unready irreversible removal = %+v; events=%v", result, adapter.events)
	}
}

func TestCompleteRemovalFailureAfterTheIrreversibleBoundaryResumesForward(t *testing.T) {
	for _, status := range []systemchanges.InstallationStatus{systemchanges.Managed, systemchanges.RecoveryRequired} {
		t.Run(string(status), func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: status, stepTimeout: time.Second})
			adapter := &systemChangesAdapter{observation: observed}
			result := systemchanges.New(adapter).Apply(changeSet)
			if result.Outcome != systemchanges.AwaitingTokenRevocation {
				t.Fatalf("pre-checkpoint removal = %+v; events=%v", result, adapter.events)
			}
			adapter.tokenRevoked = true
			result = systemchanges.New(adapter).Recover()
			if result.Outcome != systemchanges.RemovalForwardOnly || adapter.recovery == nil || !adapter.recovery.IrreversibleRemovalStarted || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
				t.Fatalf("post-checkpoint failure = %+v; recovery=%+v events=%v", result, adapter.recovery, adapter.events)
			}
			adapter.finalAbsent = true
			result = systemchanges.New(adapter).Recover()
			if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
				t.Fatalf("forward removal restart = %+v; events=%v", result, adapter.events)
			}
		})
	}
}

func TestCompleteRemovalForwardFailureNamesTheLastDurableCheckpointWithoutSecrets(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed, failRemoval: systemchanges.UnitsPhase, removalErr: errors.New("SECRET-MARKER controlled unit deletion failure")}
	if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("irreversible handoff = %+v", result)
	}
	adapter.tokenRevoked = true
	result := systemchanges.New(adapter).Recover()
	encoded, err := json.Marshal(result)
	if err != nil || result.Outcome != systemchanges.RemovalForwardOnly || result.Finding == nil || result.Finding.Found != string(systemchanges.ReleasesDeleted) || bytes.Contains(encoded, []byte("SECRET-MARKER")) {
		t.Fatalf("typed forward-only failure = %+v; json=%s; err=%v", result, encoded, err)
	}
}

func TestCompleteRemovalFinalAbsenceFailureNamesOnlyTheLastDurableCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name        string
		finalAbsent bool
		failRecord  systemchanges.DurableCheckpoint
	}{{name: "absence-unproved"}, {name: "absence-record-unproved", finalAbsent: true, failRecord: systemchanges.FinalRemovalAbsenceVerified}} {
		t.Run(test.name, func(t *testing.T) {
			_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
			adapter := &systemChangesAdapter{observation: observed, finalAbsent: test.finalAbsent, failRecord: test.failRecord}
			if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
				t.Fatalf("irreversible handoff = %+v", result)
			}
			adapter.tokenRevoked = true
			result := systemchanges.New(adapter).Recover()
			if result.Outcome != systemchanges.RemovalForwardOnly || result.Finding == nil || result.Finding.Found != string(systemchanges.OwnedFirewallStateDeleted) || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
				t.Fatalf("final absence failure = %+v; events=%v", result, adapter.events)
			}
		})
	}
}

func TestCompleteRemovalContinuesForwardOnlyInItsFixedDeletionOrder(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed}
	cancellation := systemchanges.NewCancellation()
	if result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("Complete removal handoff = %+v", result)
	}
	cancellation.Request()
	adapter.tokenRevoked, adapter.finalAbsent = true, true
	result := systemchanges.New(adapter).Recover()
	want := []string{
		"verify revoked Cloudflare token",
		"delete local State",
		"delete Infrastructure Secrets",
		"delete certificates",
		"delete transaction material",
		"delete releases",
		"delete units",
		"delete identities",
		"delete listeners",
		"delete prepared artifacts",
		"delete owned firewall state",
		"verify final removal absence",
		"finalize removal journal and recovery runner",
	}
	joined := strings.Join(adapter.events, ",")
	for _, event := range want {
		if !strings.Contains(joined, event) {
			t.Fatalf("forward-only Complete removal omitted %q: result=%+v events=%v", event, result, adapter.events)
		}
	}
	if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || strings.Contains(joined, "reverse") || strings.Contains(joined, "restore durable State") {
		t.Fatalf("forward-only Complete removal = %+v; events=%v", result, adapter.events)
	}
}

func TestIrreversibleCompleteRemovalRefusesAnAutomaticRollbackRequest(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed}
	if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("Complete removal handoff = %+v", result)
	}
	adapter.observation = systemchanges.Observation{
		Status: systemchanges.RecoveryRequired, CurrentChangeSet: "change-0008", LastChangeSet: "change-0007", Checkpoint: systemchanges.PreparedCheckpoint,
		TotalSteps: len(completeRemovalIDs), Lock: systemchanges.LockReleased, RollbackAvailable: true, RecoveryCause: systemchanges.ForwardCheckpointUnprovable,
	}
	result := systemchanges.New(adapter).RetryAutomaticRollback()
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.AwaitingTokenRevocation || strings.Contains(events, "reverse") || strings.Contains(events, "restore durable State") {
		t.Fatalf("rollback request after irreversibility = %+v; events=%v", result, adapter.events)
	}
}

func TestCompleteRemovalWaitsForVerifiedRevocationBeforeDeletingTheLocalToken(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed}
	if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("irreversible handoff = %+v", result)
	}
	result := systemchanges.New(adapter).Recover()
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.AwaitingTokenRevocation || !strings.Contains(events, "delete "+string(systemchanges.CloudflareDNSRecordsPhase)) || !strings.Contains(events, "delete "+string(systemchanges.CloudflareTunnelPhase)) || strings.Contains(events, "delete "+string(systemchanges.LocalStatePhase)) || strings.Contains(events, "reverse") {
		t.Fatalf("unrevoked-token continuation = %+v; events=%v", result, adapter.events)
	}
}

func TestCompleteRemovalResumesForwardAfterEveryIrreversibleCheckpointDeath(t *testing.T) {
	checkpoints := []systemchanges.DurableCheckpoint{
		systemchanges.OwnedDNSRecordsDeleted, systemchanges.OwnedTunnelDeleted, systemchanges.OwnedExternalDeletionVerified,
		systemchanges.TokenRevocationVerified, systemchanges.PackageHoldsRemoved, systemchanges.LocalStateDeleted, systemchanges.SecretsDeleted,
		systemchanges.CertificatesDeleted, systemchanges.TransactionMaterialDeleted, systemchanges.ReleasesDeleted,
		systemchanges.UnitsDeleted, systemchanges.IdentitiesDeleted, systemchanges.ListenersDeleted,
		systemchanges.PreparedArtifactsDeleted, systemchanges.OwnedFirewallStateDeleted, systemchanges.FinalRemovalAbsenceVerified,
	}
	for _, checkpoint := range checkpoints {
		for _, side := range []string{"before", "after"} {
			t.Run(side+"_"+string(checkpoint), func(t *testing.T) {
				_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
				adapter := &systemChangesAdapter{observation: observed, finalAbsent: true}
				if side == "before" {
					adapter.crashBefore = checkpoint
				} else {
					adapter.crashAfter = checkpoint
				}
				remoteCheckpoint := checkpoint == systemchanges.OwnedDNSRecordsDeleted || checkpoint == systemchanges.OwnedTunnelDeleted || checkpoint == systemchanges.OwnedExternalDeletionVerified
				if remoteCheckpoint {
					func() {
						defer func() { _ = recover() }()
						_ = systemchanges.New(adapter).Apply(changeSet)
					}()
				} else {
					if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
						t.Fatalf("irreversible handoff = %+v", result)
					}
					adapter.tokenRevoked = true
				}
				func() {
					defer func() { _ = recover() }()
					if !adapter.crashed {
						_ = systemchanges.New(adapter).Recover()
					}
				}()
				if !adapter.crashed {
					t.Fatalf("worker did not die %s %s", side, checkpoint)
				}
				adapter.crashBefore, adapter.crashAfter = "", ""
				adapter.tokenRevoked = true
				result := systemchanges.New(adapter).Recover()
				events := strings.Join(adapter.events, ",")
				if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || strings.Contains(events, "reverse") || strings.Contains(events, "restore durable State") {
					t.Fatalf("forward recovery after %s %s = %+v; events=%v", side, checkpoint, result, adapter.events)
				}
			})
		}
	}
}

func TestCompleteRemovalResumesForwardAfterDeathAtTheIrreversibleBoundary(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed, tokenRevoked: true, finalAbsent: true, crashAfter: systemchanges.IrreversibleRemovalStarted}
	func() {
		defer func() { _ = recover() }()
		_ = systemchanges.New(adapter).Apply(changeSet)
	}()
	if !adapter.crashed || adapter.recovery == nil || adapter.recovery.LastCheckpoint != systemchanges.IrreversibleRemovalStarted {
		t.Fatalf("irreversible boundary was not durable before death: %+v", adapter.recovery)
	}
	adapter.crashAfter = ""
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
		t.Fatalf("irreversible-boundary recovery = %+v; events=%v", result, adapter.events)
	}
}

func TestCompleteRemovalFailureOrCancellationRestoresItsProvenStartingStatus(t *testing.T) {
	type stopCase struct {
		name        string
		failStep    int
		cancelAfter int
	}
	stops := []stopCase{{name: "pre-start cancellation"}}
	for step := 1; step <= 4; step++ {
		stops = append(stops, stopCase{name: fmt.Sprintf("step %d failure", step), failStep: step}, stopCase{name: fmt.Sprintf("after step %d cancellation", step), cancelAfter: step})
	}
	for _, status := range []systemchanges.InstallationStatus{systemchanges.Managed, systemchanges.RecoveryRequired} {
		for _, stop := range stops {
			t.Run(string(status)+"/"+stop.name, func(t *testing.T) {
				cancellation := systemchanges.NewCancellation()
				_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: status, stepTimeout: time.Second})
				adapter := &systemChangesAdapter{observation: observed}
				if stop.name == "pre-start cancellation" {
					cancellation.Request()
				}
				adapter.failStep = stop.failStep
				if stop.cancelAfter > 0 {
					adapter.beforeStep = func() error {
						if adapter.executeCount == stop.cancelAfter {
							cancellation.Request()
						}
						return nil
					}
				}
				result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
				joined := strings.Join(adapter.events, ",")
				if stop.name == "pre-start cancellation" {
					if result.Outcome != systemchanges.Refused || !result.NothingChanged || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-CANCELLED" || len(adapter.events) != 0 {
						t.Fatalf("%s from %s = %+v; events=%v", stop.name, status, result, adapter.events)
					}
					return
				}
				wantStatus := status
				if status == systemchanges.RecoveryRequired {
					wantStatus = systemchanges.Managed
				}
				if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != wantStatus || !strings.Contains(joined, string(systemchanges.RollbackVerified)) || strings.Contains(joined, string(systemchanges.StatePublicationStarted)) {
					t.Fatalf("%s from %s = %+v; events=%v", stop.name, status, result, adapter.events)
				}
			})
		}
	}
}

func TestCompleteRemovalCancellationAfterExternalDeletionStillRollsBack(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	cancellation := systemchanges.NewCancellation()
	adapter := &systemChangesAdapter{observation: observed, beforeCheck: cancellation.Request}
	result := systemchanges.New(adapter).ApplyWithCancellation(changeSet, cancellation)
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.Managed || strings.Contains(events, string(systemchanges.IrreversibleRemovalStarted)) || !strings.Contains(events, "reverse Restore owned Cloudflare resource") {
		t.Fatalf("post-external cancellation = %+v; events=%v", result, adapter.events)
	}
}

func TestCompleteRemovalCheckpointWriteFailureStillRollsBackExternalDeletion(t *testing.T) {
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"})
	adapter := &systemChangesAdapter{observation: observed, failRecord: systemchanges.IrreversibleRemovalStarted}
	result := systemchanges.New(adapter).Apply(changeSet)
	events := strings.Join(adapter.events, ",")
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.Managed || strings.Contains(events, string(systemchanges.IrreversibleRemovalStarted)) || !strings.Contains(events, "reverse Restore owned Cloudflare resource") {
		t.Fatalf("failed irreversible checkpoint = %+v; events=%v", result, adapter.events)
	}
}

func TestLineageUnavailableCompleteRemovalRestoresCorruptRawStateAfterRestart(t *testing.T) {
	storage := &mutableStateStorage{document: "{"}
	stateModule := New(storage)
	observation := systemchanges.Observation{
		Status: systemchanges.RecoveryRequired, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, RecoveryCause: systemchanges.StateLineageUnprovable,
		VolatileSHA256: testSHA('2'), FilesystemBytes: 20 << 30, AvailableBytes: 5 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service",
	}
	adapter := &systemChangesAdapter{observation: observation, stateRecovery: stateModule, crashAfter: systemchanges.PrePublicationHealthPassed}
	changes := systemchanges.New(adapter)
	view := (softwarelifecycle.Interface{}).ViewCompleteRemoval(changes)
	console := ownerconsole.New(controlledOwnerRemovalObserver{})
	review, err := console.StartRemovalReview("lineage-unavailable-removal-0008")
	if err != nil {
		t.Fatal(err)
	}
	public := make([]systemchanges.PublicRemovalAuthority, 0, 3)
	for category, identities := range controlledPublicRemovalInventory() {
		for _, identity := range identities {
			authority, authorityErr := networkpolicy.NewRemoval(controlledPublicRemovalObserver{}).ProveRemovalResource("lineage-unavailable-removal-0008", category, identity)
			if authorityErr != nil {
				t.Fatal(authorityErr)
			}
			public = append(public, authority)
		}
	}
	external := make([]systemchanges.CloudflareRemovalAuthority, 0, 5)
	for category, identities := range controlledCloudflareRemovalInventory() {
		for _, identity := range identities {
			authority, authorityErr := cloudflaretunnel.NewRemoval(controlledRemovalObserver{}).ProveRemovalResource("lineage-unavailable-removal-0008", category, identity)
			if authorityErr != nil {
				t.Fatal(authorityErr)
			}
			external = append(external, authority)
		}
	}
	plan, finding := softwarelifecycle.PlanCompleteRemoval(softwarelifecycle.CompleteRemovalPlanRequest{
		Candidate: view.Candidate(), Review: review, ChangeSet: "lineage-unavailable-removal-0008", PublicAuthorities: public, CloudflareAuthorities: external,
		Disk: systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
	})
	if finding != nil {
		t.Fatal(finding)
	}
	prepared, err := stateModule.PrepareUnprovenCompleteRemovalCommit(plan)
	if err != nil {
		t.Fatal(err)
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
	approval := controlledCompleteRemovalApproval{softwarelifecycle.CompleteRemovalRecheck{Candidate: rechecked, Review: review, PublicAuthorities: public, CloudflareAuthorities: external, TypedConfirmation: typed, PermanentSelection: selected}}
	func() {
		defer func() { _ = recover() }()
		_ = plan.Apply(t.Context(), softwarelifecycle.CompleteRemovalApplyRequest{Approval: approval, PreparedState: prepared, SystemChanges: changes})
	}()
	if !adapter.crashed || adapter.recovery == nil || adapter.recovery.LastCheckpoint != systemchanges.PrePublicationHealthPassed || storage.document != "{" || storage.err != nil {
		t.Fatalf("pre-checkpoint process death = crashed=%t recovery=%+v raw=%q err=%v", adapter.crashed, adapter.recovery, storage.document, storage.err)
	}
	adapter.crashAfter = ""
	adapter.observation = systemchanges.Observation{Status: systemchanges.ChangeInProgress, CurrentChangeSet: "lineage-unavailable-removal-0008", Checkpoint: systemchanges.PreparedCheckpoint, TotalSteps: 8, Lock: systemchanges.LockReleased, RollbackAvailable: true}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.RecoveryRequired || storage.document != "{" || storage.err != nil || !strings.Contains(strings.Join(adapter.events, ","), "reverse") {
		t.Fatalf("lineage-unavailable restart rollback = %+v raw=%q err=%v events=%v", result, storage.document, storage.err, adapter.events)
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
	root                  string
	executed              int
	checks                int
	agreements            int
	rollbacks             int
	waitCancel            bool
	failExecute           bool
	waitReverse           bool
	delay                 time.Duration
	started               chan struct{}
	startedFile           string
	reverseFile           string
	recoveryEvents        []string
	reversed              []systemchanges.OperationKind
	startingState         string
	services              map[string]*controlledService
	expectedMutation      systemchanges.MutationClass
	removalTokenActive    bool
	removalTokenAvailable bool
	failRemovalRecovery   bool
	removalReadyErr       error
	removedResources      map[string]bool
	unrelatedExternal     string
	irreversiblePhases    []systemchanges.IrreversibleRemovalPhase
	removalFinalized      bool
	failRemovalFinalize   int
	failRemovalPrepare    int
	preparedConfiguration string
	activeConfiguration   string
	rollbackWant          []byte
	preparedWant          []byte
}

type controlledService struct {
	owner    systemchanges.Module
	state    string
	known    bool
	running  bool
	affected bool
}

var completeRemovalIDs = []string{"inet-sbxr", "listener-xray", "service-xray", "dns-xhttp", "dns-websocket", "dns-direct-ipv4", "route-xhttp", "tunnel-xhttp"}

func allRemovalResources(host *controlledUbuntuHost, removed bool) bool {
	for _, identity := range completeRemovalIDs {
		if host.removedResources[identity] != removed {
			return false
		}
	}
	return true
}

type controlledFirewall struct {
	events        []string
	failSSH       bool
	requestCancel bool
	failReverse   bool
	failClose     bool
	temporaryOpen bool
	unrelated     string
}

func (firewall *controlledFirewall) CaptureRollback(_ systemchanges.Step, write func(io.Reader) error) error {
	firewall.events = append(firewall.events, "capture inet sbxr")
	return write(strings.NewReader("table inet sbxr { chain input { tcp dport 2222 accept } }"))
}

func (firewall *controlledFirewall) Execute(step systemchanges.Step, rollbackPath string, _ time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	change, ok := step.FirewallChange()
	if !ok {
		return systemchanges.StepEvidence{}, errors.New("missing typed firewall change")
	}
	if _, err := os.Stat(rollbackPath); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	switch change.Action {
	case systemchanges.FirewallPolicyAction:
		firewall.events = append(firewall.events, "native validate", "arm root watchdog", "apply only inet sbxr", "existing SSH responsive", "detected SSH admitted")
		if firewall.failSSH {
			return systemchanges.StepEvidence{}, errors.New("controlled SSH gate failure")
		}
	case systemchanges.HTTP01OpenAction:
		firewall.temporaryOpen = true
		firewall.events = append(firewall.events, "native validate", "arm root watchdog", "apply only inet sbxr", "existing SSH responsive", "detected SSH admitted", "record sbxr:acme-http-01")
	case systemchanges.HTTP01CloseAction:
		if !firewall.temporaryOpen {
			return systemchanges.StepEvidence{}, errors.New("temporary rule identity not present")
		}
		if firewall.failClose {
			return systemchanges.StepEvidence{}, errors.New("controlled HTTP-01 cleanup failure")
		}
		journal, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(rollbackPath)), "journal.jsonl"))
		if err != nil || !bytes.Contains(journal, []byte(`"code":"network-http01-handle-41"`)) {
			return systemchanges.StepEvidence{}, errors.New("temporary rule identity was not durable before cleanup")
		}
		firewall.temporaryOpen = false
		firewall.events = append(firewall.events, "delete only sbxr:acme-http-01", "prove TCP 80 prior policy")
	}
	if firewall.requestCancel {
		cancellation.Request()
	}
	if cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("cancelled after safe firewall checkpoint")
	}
	code := "network-policy-safe"
	if change.Action == systemchanges.HTTP01OpenAction {
		code = "network-http01-handle-41"
	} else if change.Action == systemchanges.HTTP01CloseAction {
		code = "network-http01-removed-41"
	}
	digest := sha256.Sum256([]byte(change.Action + systemchanges.FirewallAction(firewall.unrelated)))
	return systemchanges.StepEvidence{Code: code, SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (firewall *controlledFirewall) Commit(_ systemchanges.Step, evidence systemchanges.StepEvidence) error {
	if evidence.Code == "" {
		return errors.New("durable firewall evidence unavailable")
	}
	firewall.events = append(firewall.events, "durable step evidence", "cancel watchdog")
	return nil
}

func (firewall *controlledFirewall) Reverse(_ systemchanges.Step, snapshot io.Reader, _ time.Duration) (systemchanges.StepEvidence, error) {
	if firewall.failReverse {
		return systemchanges.StepEvidence{}, errors.New("controlled firewall reverse interruption")
	}
	prior, err := io.ReadAll(snapshot)
	if err != nil || !strings.Contains(string(prior), "table inet sbxr") {
		return systemchanges.StepEvidence{}, errors.New("prior inet sbxr policy unavailable")
	}
	firewall.temporaryOpen = false
	firewall.events = append(firewall.events, "restore only prior inet sbxr", "cancel watchdog")
	digest := sha256.Sum256(prior)
	return systemchanges.StepEvidence{Code: "network-policy-restored", SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (firewall *controlledFirewall) Inspect(_ systemchanges.Step, _ io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	firewall.events = append(firewall.events, "inspect exact inet sbxr effect")
	return systemchanges.StepEffectPresent, nil
}

type cleanupFailingUbuntuAdapter struct{ ubuntu.Adapter }

func (cleanupFailingUbuntuAdapter) Cleanup(systemchanges.ExecutionLease, string) error {
	return errors.New("controlled cleanup interruption")
}

type checkpointCrashingUbuntuAdapter struct {
	ubuntu.Adapter
	checkpoint systemchanges.DurableCheckpoint
	after      bool
	crashed    bool
	lock       systemchanges.Lock
}

func (adapter *checkpointCrashingUbuntuAdapter) TryLock() (systemchanges.Lock, bool, error) {
	lock, acquired, err := adapter.Adapter.TryLock()
	adapter.lock = lock
	return lock, acquired, err
}

func (adapter *checkpointCrashingUbuntuAdapter) Record(lease systemchanges.ExecutionLease, record systemchanges.CheckpointRecord) error {
	if !adapter.crashed && record.Checkpoint == adapter.checkpoint && !adapter.after {
		adapter.crashed = true
		panic("controlled worker death")
	}
	err := adapter.Adapter.Record(lease, record)
	if err == nil && !adapter.crashed && record.Checkpoint == adapter.checkpoint {
		adapter.crashed = true
		panic("controlled worker death")
	}
	return err
}

func (host *controlledUbuntuHost) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	if removal, ok := step.RemovalChange(); ok && removal.Resource == systemchanges.CloudflareRouteResource {
		token, err := cloudflaretunnel.NewManagementToken("cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		if err != nil {
			return err
		}
		return cloudflaretunnel.WriteRemovalRecovery(token, cloudflaretunnel.RemovalRecoveryAuthority{
			AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), ZoneName: "example.com", TunnelID: "11111111-1111-4111-8111-111111111111",
			DNSRecordIDs: []string{strings.Repeat("c", 32), strings.Repeat("d", 32)}, Routes: []cloudflaretunnel.Route{{Hostname: "xhttp.example.com", Service: "http://127.0.0.1:11080"}, {Service: "http_status:404"}},
		}, write)
	}
	active := host.activeConfigurationPath()
	prior, err := os.ReadFile(active)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(prior) == 0 {
		prior = []byte(`{"status":"absent"}`)
	}
	return write(bytes.NewReader(prior))
}

func (host *controlledUbuntuHost) LoadRemovalRecovery(source io.Reader) error {
	if host.failRemovalRecovery {
		return errors.New("controlled removal recovery authority unavailable")
	}
	_, _, err := cloudflaretunnel.ReadRemovalRecovery(source)
	if err == nil {
		host.removalTokenAvailable = true
	}
	return err
}

func (host *controlledUbuntuHost) Execute(step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
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
	wantMutation := host.expectedMutation
	if wantMutation == "" {
		wantMutation = systemchanges.SettingChangeMutation
	}
	if json.Unmarshal(manifestBytes, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Release != wantRelease || manifest.Reason != wantMutation || len(manifest.Files) < 3 {
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
	if json.Unmarshal(first, &preparedEntry) != nil || preparedEntry.Checkpoint != "Prepared" || preparedEntry.ChangeSet != "change-0008" || len(preparedEntry.PlanSHA256) != 64 || preparedEntry.State.StartingRevision != 7 || preparedEntry.State.CandidateRevision != 8 || len(preparedEntry.Steps) < 1 || preparedEntry.Steps[0]["cancellation"] != string(systemchanges.SafeCheckpointCancellation) || len(preparedEntry.Checks) != 2 || bytes.Contains(journalBytes, []byte("SECRET-MARKER")) || bytes.Contains(manifestBytes, []byte("SECRET-MARKER")) {
		return systemchanges.StepEvidence{}, errors.New("Prepared journal binding is incomplete or unsafe")
	}
	if removal, ok := step.RemovalChange(); ok {
		if removal.Action == systemchanges.CloudflareRemoval && (!host.removalTokenActive || !host.removalTokenAvailable) {
			return systemchanges.StepEvidence{}, errors.New("controlled Cloudflare token proof unavailable")
		}
		if host.removedResources == nil {
			host.removedResources = map[string]bool{}
		}
		host.removedResources[removal.ImmutableID] = true
		digest := sha256.Sum256([]byte(removal.ImmutableID))
		return systemchanges.StepEvidence{Code: "removal-verified-" + removal.ImmutableID, SHA256: fmt.Sprintf("%x", digest)}, nil
	}
	preparedConfig, err := os.ReadFile(host.preparedConfigurationPath())
	if err != nil || !json.Valid(preparedConfig) || len(host.preparedWant) > 0 && !bytes.Equal(preparedConfig, host.preparedWant) {
		return systemchanges.StepEvidence{}, errors.New("prepared native configuration is invalid")
	}
	active := host.activeConfigurationPath()
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
	if removal, ok := step.RemovalChange(); ok {
		if _, err := io.ReadAll(snapshot); err != nil {
			return systemchanges.StepEvidence{}, err
		}
		if removal.Action == systemchanges.CloudflareRemoval && (!host.removalTokenActive || !host.removalTokenAvailable) {
			return systemchanges.StepEvidence{}, errors.New("controlled Cloudflare rollback token proof unavailable")
		}
		host.removedResources[removal.ImmutableID] = false
		return systemchanges.StepEvidence{Code: "removal-restored-" + removal.ImmutableID, SHA256: testSHA('b')}, nil
	}
	active := host.activeConfigurationPath()
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

func (host *controlledUbuntuHost) preparedConfigurationPath() string {
	if host.preparedConfiguration != "" {
		return filepath.Join(host.root, "var/lib/sbxr/transactions/change-0008", host.preparedConfiguration)
	}
	return filepath.Join(host.root, "var/lib/sbxr/transactions/change-0008/prepared/subscription.json")
}

func (host *controlledUbuntuHost) activeConfigurationPath() string {
	if host.activeConfiguration != "" {
		return filepath.Join(host.root, host.activeConfiguration)
	}
	return filepath.Join(host.root, "run/sbxr/active-subscription.json")
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
	if removal, ok := step.RemovalChange(); ok {
		if host.removedResources[removal.ImmutableID] {
			return systemchanges.StepEffectPresent, nil
		}
		return systemchanges.StepEffectAbsent, nil
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
		ChangeSet: "change-0008", Mutation: systemchanges.SettingChangeMutation, Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	bindControlledRecoveryState(&recovery)
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

func TestRecoveryRejectsCompleteRemovalWithoutItsDurableRemovalInventory(t *testing.T) {
	ordinary, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Mutation: systemchanges.CompleteRemovalMutation,
		Starting:        systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{ordinary}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.IrreversibleRemovalStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	adapter := &systemChangesAdapter{recovery: &recovery}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || strings.Contains(strings.Join(adapter.events, ","), "reverse") {
		t.Fatalf("forged Complete-removal recovery = %+v; events=%v", result, adapter.events)
	}
}

func TestRetryAutomaticRollbackUsesOnlyTheAuthorizedRecoveryPath(t *testing.T) {
	step, err := systemchanges.NewStep(systemchanges.SubscriptionModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	recovery := systemchanges.RecoveryTransaction{
		ChangeSet: "change-0008", Mutation: systemchanges.SettingChangeMutation, Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	bindControlledRecoveryState(&recovery)
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
		ChangeSet: "change-0008", Mutation: systemchanges.SettingChangeMutation, Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
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
		ChangeSet: "change-0008", Mutation: systemchanges.SettingChangeMutation, Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepCompleted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	bindControlledRecoveryState(&recovery)
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
		ChangeSet: "change-0008", Mutation: systemchanges.SettingChangeMutation, Starting: systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 7, SHA256: testSHA('7')},
		StartingRelease: systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256},
		OutcomeOwner:    systemchanges.ConnectionProfilesModule, Steps: []systemchanges.Step{step}, AttemptedSteps: 1,
		LastCheckpoint: systemchanges.StepStarted, Timeouts: systemchanges.Timeouts{Step: time.Second, Check: time.Second},
	}
	bindControlledRecoveryState(&recovery)
	adapter := &systemChangesAdapter{recovery: &recovery, holdErr: errors.New("controlled unrelated service agreement failure")}
	result := systemchanges.New(adapter).Recover()
	if result.Outcome != systemchanges.RecoveryRequiredOutcome || result.Finding == nil || result.Finding.Owner != systemchanges.ConnectionProfilesModule || strings.Join(adapter.events, ",") != "hold public services and timers,allow proven unrelated services" {
		t.Fatalf("unproven unrelated service recovery = %+v; events=%v", result, adapter.events)
	}
}

func bindControlledRecoveryState(recovery *systemchanges.RecoveryTransaction) {
	recovery.Candidate = systemchanges.StateLineage{Status: systemchanges.Managed, Revision: recovery.Starting.Revision + 1, SHA256: testSHA('8')}
	recovery.CandidateRelease = recovery.StartingRelease
	recovery.State = systemchanges.StateTransactionBinding{
		StartingRevision: recovery.Starting.Revision, CandidateRevision: recovery.Candidate.Revision,
		StartingSHA256: recovery.Starting.SHA256, CandidateSHA256: recovery.Candidate.SHA256,
		PreparedStateSHA256: testSHA('9'), PreparedManifestSHA256: testSHA('a'), ChangeSet: recovery.ChangeSet,
		StartingRelease: recovery.StartingRelease, CandidateRelease: recovery.CandidateRelease,
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
	if active, err := os.ReadFile(host.activeConfigurationPath()); err != nil || !json.Valid(active) {
		return errors.New("active configuration agreement failed")
	}
	return nil
}

func (host *controlledUbuntuHost) VerifyRollback(agreement systemchanges.RollbackAgreement, _ time.Duration) error {
	host.rollbacks++
	wantRelease := systemchanges.ReleaseBinding{Repository: testRelease.Repository, Tag: testRelease.Tag, Commit: testRelease.Commit, ReleaseIndexSHA256: testRelease.ReleaseIndexSHA256}
	validManaged := agreement.Status == systemchanges.Managed && agreement.Release == wantRelease
	validRecoveryRequired := agreement.Status == systemchanges.RecoveryRequired && agreement.Release == (systemchanges.ReleaseBinding{})
	if (!validManaged && !validRecoveryRequired) || agreement.Revision != 7 || agreement.SHA256 == "" {
		return errors.New("rollback State agreement failed")
	}
	active := host.activeConfigurationPath()
	if len(host.rollbackWant) > 0 {
		if restored, err := os.ReadFile(active); err != nil || !bytes.Equal(restored, host.rollbackWant) {
			return errors.New("rollback active-file agreement failed")
		}
	} else if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) {
		return errors.New("rollback active-file agreement failed")
	}
	journal, err := os.ReadFile(filepath.Join(host.root, "var/lib/sbxr/transactions/change-0008/journal.jsonl"))
	if err != nil || !bytes.Contains(journal, []byte(`"checkpoint":"Rollback started"`)) || !bytes.Contains(journal, []byte(`"checkpoint":"Rollback step completed"`)) || bytes.Contains(journal, []byte("SECRET-MARKER")) {
		return errors.New("rollback journal agreement failed")
	}
	return nil
}

func (host *controlledUbuntuHost) VerifyCloudflareTokenRevoked(_ time.Duration) (bool, error) {
	host.recoveryEvents = append(host.recoveryEvents, "verify revoked Cloudflare token")
	if !host.removalTokenAvailable {
		return false, errors.New("local scoped-token copy unavailable before revocation proof")
	}
	return !host.removalTokenActive && host.removalTokenAvailable, nil
}

func (host *controlledUbuntuHost) VerifyIrreversibleRemovalReady(_ time.Duration) error {
	host.recoveryEvents = append(host.recoveryEvents, "verify irreversible removal ready")
	return host.removalReadyErr
}

func (host *controlledUbuntuHost) DeleteIrreversibleRemovalPhase(phase systemchanges.IrreversibleRemovalPhase, _ time.Duration) (systemchanges.StepEvidence, error) {
	if !slices.Contains(host.irreversiblePhases, phase) {
		host.irreversiblePhases = append(host.irreversiblePhases, phase)
	}
	if phase == systemchanges.SecretsPhase {
		host.removalTokenAvailable = false
	}
	digest := sha256.Sum256([]byte(phase))
	return systemchanges.StepEvidence{Code: "removal-phase-absent", SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (host *controlledUbuntuHost) VerifyFinalRemovalAbsence(_ time.Duration) (bool, error) {
	host.recoveryEvents = append(host.recoveryEvents, "verify final removal absence")
	want := []systemchanges.IrreversibleRemovalPhase{
		systemchanges.PackageHoldsPhase, systemchanges.LocalStatePhase, systemchanges.SecretsPhase, systemchanges.CertificatesPhase,
		systemchanges.TransactionMaterialDeletionAuthorizedPhase,
		systemchanges.ReleasesPhase, systemchanges.UnitsPhase, systemchanges.IdentitiesPhase,
		systemchanges.ListenersPhase, systemchanges.PreparedArtifactsPhase, systemchanges.OwnedFirewallStatePhase,
	}
	return slices.Equal(host.irreversiblePhases, want) && allRemovalResources(host, true) && !host.removalTokenAvailable, nil
}

func (host *controlledUbuntuHost) FinalizeRemoval(_ time.Duration) error {
	host.recoveryEvents = append(host.recoveryEvents, "finalize removal journal and recovery runner")
	if host.failRemovalFinalize > 0 {
		host.failRemovalFinalize--
		return errors.New("controlled recovery-runner removal failure")
	}
	host.removalFinalized = true
	return nil
}

func (host *controlledUbuntuHost) PrepareRemovalFinalization(_ time.Duration) error {
	host.recoveryEvents = append(host.recoveryEvents, "prepare recovery runner finalization")
	if host.failRemovalPrepare > 0 {
		host.failRemovalPrepare--
		return errors.New("controlled recovery-runner preparation failure")
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
	if _, err := adapter.Execute(systemchanges.ExecutionLease{}, "change-0008", 1, unauthorizedStep, time.Second, nil); err == nil || host.executed != 0 {
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

func TestWebSocketPostMutationFailureRestoresPriorCompleteXrayConfiguration(t *testing.T) {
	candidate := []byte(`{"inbounds":[{"listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"flow":"xtls-rprx-vision","id":"11111111-1111-4111-8111-111111111111"}],"decryption":"none"},"streamSettings":{"method":"raw","realitySettings":{"limitFallbackDownload":{"afterBytes":20971520,"burstBytesPerSec":10485760,"bytesPerSec":2097152},"limitFallbackUpload":{"afterBytes":10485760,"burstBytesPerSec":5242880,"bytesPerSec":1048576},"maxTimeDiff":0,"privateKey":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","serverNames":["edge.example.net"],"shortIds":["0123456789abcdef"],"show":false,"target":"edge.example.net:443","xver":0},"security":"reality"},"tag":"vless-reality-vision"},{"listen":"127.0.0.1","port":11080,"protocol":"vless","settings":{"clients":[{"id":"22222222-2222-4222-8222-222222222222"}],"decryption":"none"},"streamSettings":{"method":"xhttp","security":"none","xhttpSettings":{"mode":"packet-up","path":"/2222222222222222222222222222222222222222222222222222222222222222"}},"tag":"vless-xhttp"},{"listen":"127.0.0.1","port":11081,"protocol":"vless","settings":{"clients":[{"id":"33333333-3333-4333-8333-333333333333"}],"decryption":"none"},"streamSettings":{"method":"websocket","security":"none","wsSettings":{"host":"ws.example.com","path":"/4444444444444444444444444444444444444444444444444444444444444444"}},"tag":"vless-websocket"}],"log":{"access":"none","loglevel":"warning"},"outbounds":[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"blocked"}]}`)
	_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-WEBSOCKET-CONFIGURATION"}, systemChangeTestOptions{
		stepTimeout: time.Second, nativeXray: candidate,
		candidateEdit: func(desired *DesiredState) {
			desired.ConnectionProfiles.VLESSRealityVision.PrivateKey = NewInfrastructureSecret("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
			desired.ConnectionProfiles.VLESSRealityVision.PublicKey = "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ-xnTzf3_pe20"
			desired.ConnectionProfiles.VLESSRealityVision.ShortID = NewClientAccessValue("0123456789abcdef")
			desired.ConnectionProfiles.VLESSRealityVision.Target = "edge.example.net:443"
			desired.ConnectionProfiles.VLESSRealityVision.ServerName = "edge.example.net"
		},
	})
	root := t.TempDir()
	prepareLock(t, root)
	prior := []byte(`{"inbounds":[{"tag":"vless-reality-vision"}],"outbounds":[{"protocol":"freedom"}]}`)
	active := filepath.Join(root, "etc/sbxr/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(active), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, prior, 0o640); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{
		root: root, failExecute: true, preparedConfiguration: "prepared/xray.json", activeConfiguration: "etc/sbxr/xray/config.json", rollbackWant: prior, preparedWant: candidate,
	}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	result := systemchanges.New(adapter).Apply(changeSet)
	restored, err := os.ReadFile(active)
	if result.Outcome != systemchanges.RollbackSucceeded || host.executed != 1 || host.rollbacks != 1 || err != nil || !bytes.Equal(restored, prior) {
		t.Fatalf("WebSocket rollback = %+v; executed=%d rollbacks=%d restored=%s err=%v", result, host.executed, host.rollbacks, restored, err)
	}
}

func TestHysteria2PostMutationFailureRestoresPriorCompleteSingBoxConfiguration(t *testing.T) {
	candidate := []byte(`{"inbounds":[{"listen":"0.0.0.0","listen_port":443,"masquerade":{"content":"Not Found\n","headers":{"content-type":["text/plain; charset=utf-8"]},"status_code":404,"type":"string"},"tag":"hysteria2-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"hysteria2","users":[{"password":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}],"log":{"level":"warn"},"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}`)
	xray := []byte(`{"inbounds":[{"tag":"vless-reality-vision"}],"outbounds":[{"protocol":"freedom"}]}`)
	_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-HYSTERIA2-CONFIGURATION"}, systemChangeTestOptions{stepTimeout: time.Second, nativeXray: xray, nativeSingBox: candidate})
	root := t.TempDir()
	prepareLock(t, root)
	prior := []byte(`{"inbounds":[{"tag":"prior-hysteria2"}],"outbounds":[{"tag":"direct","type":"direct"}]}`)
	active := filepath.Join(root, "etc/sbxr/sing-box/config.json")
	if err := os.MkdirAll(filepath.Dir(active), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, prior, 0o640); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root, failExecute: true, preparedConfiguration: "prepared/sing-box.json", activeConfiguration: "etc/sbxr/sing-box/config.json", rollbackWant: prior, preparedWant: candidate}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	result := systemchanges.New(adapter).Apply(changeSet)
	restored, err := os.ReadFile(active)
	if result.Outcome != systemchanges.RollbackSucceeded || host.executed != 1 || host.rollbacks != 1 || err != nil || !bytes.Equal(restored, prior) {
		t.Fatalf("Hysteria2 rollback = %+v; executed=%d rollbacks=%d restored=%s err=%v", result, host.executed, host.rollbacks, restored, err)
	}
}

func TestTUICPostMutationFailureRestoresPriorCompleteSingBoxConfiguration(t *testing.T) {
	candidate := []byte(`{"inbounds":[{"listen":"0.0.0.0","listen_port":443,"masquerade":{"content":"Not Found\n","headers":{"content-type":["text/plain; charset=utf-8"]},"status_code":404,"type":"string"},"tag":"hysteria2-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"hysteria2","users":[{"password":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},{"congestion_control":"cubic","listen":"0.0.0.0","listen_port":8443,"tag":"tuic-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"tuic","users":[{"password":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","uuid":"55555555-5555-4555-8555-555555555555"}],"zero_rtt_handshake":false}],"log":{"level":"warn"},"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}`)
	xray := []byte(`{"inbounds":[{"tag":"vless-reality-vision"}],"outbounds":[{"protocol":"freedom"}]}`)
	_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-TUIC-CONFIGURATION"}, systemChangeTestOptions{stepTimeout: time.Second, nativeXray: xray, nativeSingBox: candidate})
	root := t.TempDir()
	prepareLock(t, root)
	prior := []byte(`{"inbounds":[{"tag":"prior-hysteria2"}],"outbounds":[{"tag":"direct","type":"direct"}]}`)
	active := filepath.Join(root, "etc/sbxr/sing-box/config.json")
	if err := os.MkdirAll(filepath.Dir(active), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, prior, 0o640); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root, failExecute: true, preparedConfiguration: "prepared/sing-box.json", activeConfiguration: "etc/sbxr/sing-box/config.json", rollbackWant: prior, preparedWant: candidate}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	result := systemchanges.New(adapter).Apply(changeSet)
	restored, err := os.ReadFile(active)
	if result.Outcome != systemchanges.RollbackSucceeded || host.executed != 1 || host.rollbacks != 1 || err != nil || !bytes.Equal(restored, prior) {
		t.Fatalf("TUIC rollback = %+v; executed=%d rollbacks=%d restored=%s err=%v", result, host.executed, host.rollbacks, restored, err)
	}
}

func TestAnyTLSPostMutationFailureRestoresPriorCompleteSingBoxConfiguration(t *testing.T) {
	candidate := []byte(`{"inbounds":[{"listen":"0.0.0.0","listen_port":443,"masquerade":{"content":"Not Found\n","headers":{"content-type":["text/plain; charset=utf-8"]},"status_code":404,"type":"string"},"tag":"hysteria2-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"hysteria2","users":[{"password":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},{"congestion_control":"cubic","listen":"0.0.0.0","listen_port":8443,"tag":"tuic-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"tuic","users":[{"password":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","uuid":"55555555-5555-4555-8555-555555555555"}],"zero_rtt_handshake":false},{"listen":"0.0.0.0","listen_port":9443,"tag":"anytls-in","tls":{"certificate_path":"/var/lib/sbxr/certificates/domain/current/fullchain.pem","enabled":true,"key_path":"/var/lib/sbxr/certificates/domain/current/privkey.pem","server_name":"direct.example.com"},"type":"anytls","users":[{"password":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]}],"log":{"level":"warn"},"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct"}}`)
	xray := []byte(`{"inbounds":[{"tag":"vless-reality-vision"}],"outbounds":[{"protocol":"freedom"}]}`)
	_, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CONNECTION-PROFILES-ANYTLS-CONFIGURATION"}, systemChangeTestOptions{stepTimeout: time.Second, nativeXray: xray, nativeSingBox: candidate})
	root := t.TempDir()
	prepareLock(t, root)
	prior := []byte(`{"inbounds":[{"tag":"prior-tuic"}],"outbounds":[{"tag":"direct","type":"direct"}]}`)
	active := filepath.Join(root, "etc/sbxr/sing-box/config.json")
	if err := os.MkdirAll(filepath.Dir(active), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, prior, 0o640); err != nil {
		t.Fatal(err)
	}
	host := &controlledUbuntuHost{root: root, failExecute: true, preparedConfiguration: "prepared/sing-box.json", activeConfiguration: "etc/sbxr/sing-box/config.json", rollbackWant: prior, preparedWant: candidate}
	adapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)
	result := systemchanges.New(adapter).Apply(changeSet)
	restored, err := os.ReadFile(active)
	if result.Outcome != systemchanges.RollbackSucceeded || host.executed != 1 || host.rollbacks != 1 || err != nil || !bytes.Equal(restored, prior) {
		t.Fatalf("AnyTLS rollback = %+v; executed=%d rollbacks=%d restored=%s err=%v", result, host.executed, host.rollbacks, restored, err)
	}
}

type renewalDuePolicy struct{ events *[]string }

func (policy renewalDuePolicy) Due(lineage certificatelifecycle.Lineage) bool {
	*policy.events = append(*policy.events, "due "+string(lineage))
	return true
}

func (renewalDuePolicy) Record(certificatelifecycle.Lineage, certificatelifecycle.ApplyResult) error {
	return nil
}

type renewalPlanner struct {
	events  *[]string
	changes map[certificatelifecycle.Lineage][]*systemchanges.ChangeSet
}

func (planner *renewalPlanner) BuildFresh(lineage certificatelifecycle.Lineage) (certificatelifecycle.ChangeSet, error) {
	changes := planner.changes[lineage]
	if len(changes) == 0 {
		return nil, errors.New("no fresh controlled renewal Change Set")
	}
	changeSet := changes[0]
	planner.changes[lineage] = changes[1:]
	*planner.events = append(*planner.events, "build "+changeSet.Identity())
	return changeSet, nil
}

type renewalSystemChanges struct{ changes systemchanges.Interface }

func (adapter renewalSystemChanges) ApplyFresh(build func() (certificatelifecycle.ChangeSet, error)) certificatelifecycle.ApplyResult {
	result := adapter.changes.ApplyFreshCertificateRenewal(func() (*systemchanges.ChangeSet, error) {
		changeSet, err := build()
		if err != nil {
			return nil, err
		}
		change, ok := changeSet.(*systemchanges.ChangeSet)
		if !ok {
			return nil, errors.New("controlled renewal Change Set unavailable")
		}
		return change, nil
	})
	code := ""
	if result.Finding != nil {
		code = result.Finding.Code
	}
	return certificatelifecycle.ApplyResult{
		Outcome: certificatelifecycle.ApplyOutcome(result.Outcome), PlanConsumed: result.PlanConsumed,
		QueueCreated: result.QueueCreated, RebuildPlan: result.RebuildPlan, Code: code,
	}
}

func controlledIPRenewalSteps(t *testing.T) []systemchanges.Step {
	t.Helper()
	candidate := "table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  ct state established,related accept\n  tcp dport 22 accept\n  ip daddr 192.0.2.10 tcp dport 80 accept comment \"sbxr:acme-http-01\"\n }\n}"
	open, err := systemchanges.NewHTTP01OpenStep(candidate, 22)
	if err != nil {
		t.Fatal(err)
	}
	close, err := systemchanges.NewHTTP01CloseStep()
	if err != nil {
		t.Fatal(err)
	}
	changes := []systemchanges.CertificateChange{
		{Action: systemchanges.CertificateIPStage, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/staging/sbxr-ip", Account: "disposable-staging-sbxr-ip"},
		{Action: systemchanges.CertificateIPOrder, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"},
		{Action: systemchanges.CertificateIPActivate, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", SubscriptionUnit: "sbxr-subscription.service"},
	}
	steps := []systemchanges.Step{open}
	for _, change := range changes {
		step, err := systemchanges.NewCertificateStep(change)
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, step)
	}
	return append(steps, close)
}

func controlledDomainRenewalSteps(t *testing.T) []systemchanges.Step {
	t.Helper()
	candidate := "table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  ct state established,related accept\n  tcp dport 22 accept\n  ip daddr 192.0.2.10 tcp dport 80 accept comment \"sbxr:acme-http-01\"\n }\n}"
	open, err := systemchanges.NewHTTP01OpenStep(candidate, 22)
	if err != nil {
		t.Fatal(err)
	}
	close, err := systemchanges.NewHTTP01CloseStep()
	if err != nil {
		t.Fatal(err)
	}
	changes := []systemchanges.CertificateChange{
		{Action: systemchanges.CertificateDomainStage, Identity: "direct.example.com", RequiredProfile: "tlsserver", CertName: "sbxr-domain", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/staging/sbxr-domain", Account: "disposable-staging-sbxr-domain", DestinationIP: "192.0.2.10"},
		{Action: systemchanges.CertificateDomainOrder, Identity: "direct.example.com", RequiredProfile: "tlsserver", CertName: "sbxr-domain", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production", DestinationIP: "192.0.2.10"},
		{Action: systemchanges.CertificateDomainActivate, Identity: "direct.example.com", RequiredProfile: "tlsserver", CertName: "sbxr-domain", DestinationIP: "192.0.2.10", DirectTLSRevision: 7, DirectTLSSHA256: strings.Repeat("d", 64)},
	}
	steps := []systemchanges.Step{open}
	for _, change := range changes {
		step, err := systemchanges.NewCertificateStep(change)
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, step)
	}
	return append(steps, close)
}

func TestCertificateRenewalSchedulerUsesRealOneUseSystemChangesLock(t *testing.T) {
	_, ipFirst, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CertificateRenewalMutation, systemchanges.Check{Owner: systemchanges.CertificateModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CERTIFICATE-RENEWAL"}, systemChangeTestOptions{identity: "change-8101", stepTimeout: time.Second, steps: controlledIPRenewalSteps(t)})
	_, domainFirst, _, _ := preparedSystemChangeWithOptions(t, systemchanges.CertificateRenewalMutation, systemchanges.Check{Owner: systemchanges.CertificateModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CERTIFICATE-RENEWAL"}, systemChangeTestOptions{identity: "change-8102", stepTimeout: time.Second, steps: controlledDomainRenewalSteps(t)})
	var events []string
	planner := &renewalPlanner{events: &events, changes: map[certificatelifecycle.Lineage][]*systemchanges.ChangeSet{
		certificatelifecycle.IPLineage:     {ipFirst},
		certificatelifecycle.DomainLineage: {domainFirst},
	}}
	host := &systemChangesAdapter{lockHeld: true, observation: observed}
	changes := systemchanges.New(host)
	scheduler := certificatelifecycle.NewScheduler(renewalDuePolicy{events: &events}, planner, renewalSystemChanges{changes: changes})
	first := scheduler.Run()
	host.lockHeld = false
	retry := scheduler.Run()
	if len(first) != 2 || first[0].Lineage != certificatelifecycle.IPLineage || first[0].ChangeSetID != "" || first[0].Apply.Outcome != certificatelifecycle.Deferred || first[0].Apply.PlanConsumed || !first[0].Apply.RebuildPlan || first[1].Lineage != certificatelifecycle.DomainLineage || first[1].Apply.Outcome != certificatelifecycle.Deferred || len(retry) != 2 || retry[0].ChangeSetID != ipFirst.Identity() || retry[0].Apply.Outcome != certificatelifecycle.Applied || !retry[0].Apply.PlanConsumed || retry[1].ChangeSetID != domainFirst.Identity() || retry[1].Apply.Outcome != certificatelifecycle.Applied || !retry[1].Apply.PlanConsumed {
		t.Fatalf("scheduled System Changes results = first %+v retry %+v", first, retry)
	}
	want := []string{"due IP certificate", "due Domain certificate", "due IP certificate", "build change-8101", "due Domain certificate", "build change-8102"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("serial renewal order = %v, want %v", events, want)
	}
	joined := strings.Join(host.events, ",")
	if strings.Count(joined, string(systemchanges.StatePublicationStarted)) != 2 || strings.Count(joined, string(systemchanges.Complete)) != 2 || host.recovery != nil || host.executeCount != 10 {
		t.Fatalf("renewal publication/cleanup = events %v recovery %+v steps %d", host.events, host.recovery, host.executeCount)
	}
	for _, changeSet := range []*systemchanges.ChangeSet{ipFirst, domainFirst} {
		reused := changes.Apply(changeSet)
		if reused.Finding == nil || reused.Finding.Code != "SYSTEM-CHANGES-PLAN-USED" || reused.QueueCreated {
			t.Fatalf("scheduled authority was reusable or queued: %+v", reused)
		}
	}
}

func TestUbuntuFirewallSeamPreservesSSHAndCleansOnlyExactHTTP01Rule(t *testing.T) {
	base := "table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  ct state established,related accept\n  tcp dport 2222 accept\n }\n}"
	temporary := "table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  ct state established,related accept\n  tcp dport 2222 accept\n  tcp dport 80 accept comment \"sbxr:acme-http-01\"\n }\n}"
	policy, err := systemchanges.NewFirewallPolicyStep(base, 2222)
	if err != nil {
		t.Fatal(err)
	}
	open, err := systemchanges.NewHTTP01OpenStep(temporary, 2222)
	if err != nil {
		t.Fatal(err)
	}
	closeHTTP, err := systemchanges.NewHTTP01CloseStep()
	if err != nil {
		t.Fatal(err)
	}
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-SSH-RESPONSIVE"}, policy, open, closeHTTP)
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root}
	firewall := &controlledFirewall{unrelated: "table inet unrelated remains"}
	result := systemchanges.New(ubuntu.NewAtWithFirewall(root, func() (systemchanges.Observation, error) { return observed, nil }, host, firewall)).Apply(changeSet)
	events := strings.Join(firewall.events, ",")
	for _, required := range []string{"native validate,arm root watchdog,apply only inet sbxr,existing SSH responsive,detected SSH admitted,durable step evidence,cancel watchdog", "record sbxr:acme-http-01,durable step evidence,cancel watchdog", "delete only sbxr:acme-http-01,prove TCP 80 prior policy"} {
		if !strings.Contains(events, required) {
			t.Fatalf("firewall result %+v events %q omit %q", result, events, required)
		}
	}
	if result.Outcome != systemchanges.Completed || firewall.temporaryOpen || firewall.unrelated != "table inet unrelated remains" {
		t.Fatalf("firewall success = %+v; firewall=%+v", result, firewall)
	}

	for _, test := range []struct {
		name   string
		steps  []systemchanges.Step
		change func(*controlledFirewall)
	}{
		{name: "SSH failure", steps: []systemchanges.Step{policy}, change: func(firewall *controlledFirewall) { firewall.failSSH = true }},
		{name: "explicit cancellation", steps: []systemchanges.Step{open}, change: func(firewall *controlledFirewall) { firewall.requestCancel = true }},
		{name: "HTTP-01 cleanup failure", steps: []systemchanges.Step{open, closeHTTP}, change: func(firewall *controlledFirewall) { firewall.failClose = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failedChange, _, failedObserved := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-SSH-RESPONSIVE"}, systemChangeTestOptions{extraSteps: test.steps, stepTimeout: time.Second})
			failedRoot := t.TempDir()
			prepareLock(t, failedRoot)
			failedFirewall := &controlledFirewall{unrelated: "table inet unrelated remains"}
			test.change(failedFirewall)
			failedResult := systemchanges.New(ubuntu.NewAtWithFirewall(failedRoot, func() (systemchanges.Observation, error) { return failedObserved, nil }, &controlledUbuntuHost{root: failedRoot}, failedFirewall)).ApplyWithCancellation(failedChange, systemchanges.NewCancellation())
			if failedResult.Outcome != systemchanges.RollbackSucceeded || failedFirewall.temporaryOpen || !strings.Contains(strings.Join(failedFirewall.events, ","), "restore only prior inet sbxr") || failedFirewall.unrelated != "table inet unrelated remains" {
				t.Fatalf("%s = %+v; firewall=%+v", test.name, failedResult, failedFirewall)
			}
		})
	}
}

func TestUbuntuAdapterRefusesFirewallStepWithoutNativeExecutor(t *testing.T) {
	policy := testFirewallStep(t)
	_, changeSet, _, observed := preparedSystemChangeForMutation(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-SSH-RESPONSIVE"}, policy)
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root}
	result := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)).Apply(changeSet)
	if !result.NothingChanged || result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-PREPARATION" || host.executed != 0 {
		t.Fatalf("missing native firewall executor = %+v; generic executions=%d", result, host.executed)
	}
}

func TestUbuntuAdapterReversesOnlyTypedCompleteRemovalResourcesAfterRestart(t *testing.T) {
	for _, status := range []systemchanges.InstallationStatus{systemchanges.Managed, systemchanges.RecoveryRequired} {
		for _, crash := range []struct {
			name       string
			checkpoint systemchanges.DurableCheckpoint
			after      bool
			allRemoved bool
		}{{"during-public-deletion", systemchanges.StepCompleted, false, false}, {"after-route-removal", systemchanges.PrePublicationHealthPassed, true, true}} {
			t.Run(string(status)+"/"+crash.name, func(t *testing.T) {
				stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: status, stepTimeout: time.Second})
				root := t.TempDir()
				prepareLock(t, root)
				host := &controlledUbuntuHost{
					root: root, expectedMutation: systemchanges.CompleteRemovalMutation,
					removalTokenActive: true, removalTokenAvailable: true,
					removedResources: map[string]bool{}, unrelatedExternal: "unrelated-cloudflare-resource-remains",
				}
				baseAdapter := ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)
				crashing := &checkpointCrashingUbuntuAdapter{Adapter: baseAdapter, checkpoint: crash.checkpoint, after: crash.after}
				var initial systemchanges.ApplyResult
				func() {
					defer func() { _ = recover() }()
					initial = systemchanges.New(crashing).Apply(changeSet)
				}()
				if crashing.lock != nil {
					_ = crashing.lock.Close()
				}
				removedAsExpected := !crash.allRemoved && host.removedResources[completeRemovalIDs[0]] && !host.removedResources[completeRemovalIDs[1]]
				if crash.allRemoved {
					removedAsExpected = host.removedResources["inet-sbxr"] && host.removedResources["listener-xray"] && host.removedResources["service-xray"] && host.removedResources["route-xhttp"] && !host.removedResources["dns-xhttp"] && !host.removedResources["tunnel-xhttp"]
				}
				if !crashing.crashed || !removedAsExpected || !host.removalTokenActive || !host.removalTokenAvailable || host.unrelatedExternal != "unrelated-cloudflare-resource-remains" {
					t.Fatalf("controlled pre-checkpoint death = result=%+v observation=%+v crashed=%t host=%+v", initial, observed, crashing.crashed, host)
				}
				journal, err := os.ReadFile(filepath.Join(root, "var/lib/sbxr/transactions/change-0008/journal.jsonl"))
				if err != nil || bytes.Contains(journal, []byte("CLOUDFLARE-MANAGEMENT-SECRET-MARKER")) {
					t.Fatalf("removal journal exposed credentials: %v", err)
				}
				observed.Status, observed.CurrentChangeSet, observed.RecoveryCause = systemchanges.ChangeInProgress, "change-0008", ""
				observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, len(completeRemovalIDs), true
				recovered := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)).Recover()
				wantStatus := status
				if status == systemchanges.RecoveryRequired {
					wantStatus = systemchanges.Managed
				}
				if recovered.Outcome != systemchanges.RollbackSucceeded || recovered.RestoredStatus != wantStatus || !allRemovalResources(host, false) || !host.removalTokenAvailable || host.unrelatedExternal != "unrelated-cloudflare-resource-remains" {
					t.Fatalf("controlled removal restart rollback = %+v; host=%+v", recovered, host)
				}
			})
		}
	}
}

func TestUbuntuAdapterRefusesRemovalRollbackAfterScopedTokenDisappears(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: systemchanges.Managed, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root, expectedMutation: systemchanges.CompleteRemovalMutation, removalTokenActive: true, removalTokenAvailable: true, removedResources: map[string]bool{}}
	if result := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("controlled reversible removal = %+v", result)
	}
	host.removalTokenAvailable = false
	host.failRemovalRecovery = true
	observed.Status, observed.CurrentChangeSet, observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.ChangeInProgress, "change-0008", systemchanges.PreparedCheckpoint, len(completeRemovalIDs), true
	result := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)).Recover()
	if result.Outcome != systemchanges.RemovalForwardOnly || !allRemovalResources(host, true) {
		t.Fatalf("rollback without live scoped token = %+v; resources=%v", result, host.removedResources)
	}
}

func TestUbuntuAdapterRollsBackBeforeTheIrreversibleCheckpointWhenLocalDeletionIsUnready(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: systemchanges.Managed, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root, expectedMutation: systemchanges.CompleteRemovalMutation, removalTokenActive: true, removalTokenAvailable: true, removalReadyErr: errors.New("controlled local ownership evidence failure"), removedResources: map[string]bool{}}
	result := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host, stateModule)).Apply(changeSet)
	if result.Outcome != systemchanges.RollbackSucceeded || result.RestoredStatus != systemchanges.Managed || !allRemovalResources(host, false) || !slices.Contains(host.recoveryEvents, "verify irreversible removal ready") || slices.Contains(host.recoveryEvents, "verify revoked Cloudflare token") {
		t.Fatalf("unready Ubuntu irreversible removal = %+v; host=%+v", result, host)
	}
}

func TestUbuntuAdapterCompletesForwardOnlyRemovalAfterVerifiedTokenRevocation(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: systemchanges.Managed, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root, expectedMutation: systemchanges.CompleteRemovalMutation, removalTokenActive: true, removalTokenAvailable: true, removedResources: map[string]bool{}}
	source := func() (systemchanges.Observation, error) {
		current := observed
		if slices.Contains(host.irreversiblePhases, systemchanges.LocalStatePhase) {
			current = systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, FilesystemBytes: observed.FilesystemBytes, AvailableBytes: observed.AvailableBytes, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: observed.TimeOwner}
		}
		return current, nil
	}
	if result := systemchanges.New(ubuntu.NewAt(root, source, host, stateModule)).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("irreversible handoff = %+v", result)
	}
	host.removalTokenActive = false
	observed.Status, observed.CurrentChangeSet, observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.ChangeInProgress, "change-0008", systemchanges.PreparedCheckpoint, len(completeRemovalIDs), false
	result := systemchanges.New(ubuntu.NewAt(root, source, host, stateModule)).Recover()
	transaction := filepath.Join(root, "var/lib/sbxr/transactions/change-0008")
	if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || !host.removalFinalized || host.removalTokenAvailable || !allRemovalResources(host, true) {
		t.Fatalf("forward-only Ubuntu removal = %+v; host=%+v", result, host)
	}
	if _, err := os.Stat(transaction); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final removal retained transaction material: %v", err)
	}
}

func TestUbuntuAdapterRemovalResumesForwardDeletionAfterProcessDeathAtEveryCheckpoint(t *testing.T) {
	checkpoints := []systemchanges.DurableCheckpoint{
		systemchanges.TokenRevocationVerified, systemchanges.PackageHoldsRemoved, systemchanges.LocalStateDeleted, systemchanges.SecretsDeleted,
		systemchanges.CertificatesDeleted, systemchanges.TransactionMaterialDeletionAuthorized, systemchanges.TransactionMaterialDeleted, systemchanges.ReleasesDeleted,
		systemchanges.UnitsDeleted, systemchanges.IdentitiesDeleted, systemchanges.ListenersDeleted,
		systemchanges.PreparedArtifactsDeleted, systemchanges.OwnedFirewallStateDeleted, systemchanges.FinalRemovalAbsenceVerified,
	}
	for _, checkpoint := range checkpoints {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/after=%t", checkpoint, after), func(t *testing.T) {
				stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: systemchanges.Managed, stepTimeout: time.Second})
				root := t.TempDir()
				prepareLock(t, root)
				host := &controlledUbuntuHost{root: root, expectedMutation: systemchanges.CompleteRemovalMutation, removalTokenActive: true, removalTokenAvailable: true, removedResources: map[string]bool{}}
				source := func() (systemchanges.Observation, error) {
					if slices.Contains(host.irreversiblePhases, systemchanges.LocalStatePhase) {
						return systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, FilesystemBytes: observed.FilesystemBytes, AvailableBytes: observed.AvailableBytes, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: observed.TimeOwner}, nil
					}
					return observed, nil
				}
				base := ubuntu.NewAt(root, source, host, stateModule)
				if result := systemchanges.New(base).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
					t.Fatalf("irreversible handoff = %+v", result)
				}
				host.removalTokenActive = false
				observed.Status, observed.CurrentChangeSet, observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.ChangeInProgress, "change-0008", systemchanges.PreparedCheckpoint, len(completeRemovalIDs), false
				crashing := &checkpointCrashingUbuntuAdapter{Adapter: base, checkpoint: checkpoint, after: after}
				func() {
					defer func() { _ = recover() }()
					_ = systemchanges.New(crashing).Recover()
				}()
				if crashing.lock != nil {
					_ = crashing.lock.Close()
				}
				if !crashing.crashed {
					t.Fatal("controlled recovery worker did not die")
				}
				result := systemchanges.New(ubuntu.NewAt(root, source, host, stateModule)).Recover()
				if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || !host.removalFinalized {
					t.Fatalf("final deletion recovery = %+v; host=%+v", result, host)
				}
				if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("final deletion retained recovery material: %v", err)
				}
			})
		}
	}
}

func TestUbuntuAdapterLeftoverRunnerSelfCleansAfterJournalDeletion(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: systemchanges.Managed, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root, expectedMutation: systemchanges.CompleteRemovalMutation, removalTokenActive: true, removalTokenAvailable: true, removedResources: map[string]bool{}, failRemovalFinalize: 1}
	source := func() (systemchanges.Observation, error) {
		if slices.Contains(host.irreversiblePhases, systemchanges.LocalStatePhase) {
			return systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, FilesystemBytes: observed.FilesystemBytes, AvailableBytes: observed.AvailableBytes, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: observed.TimeOwner}, nil
		}
		return observed, nil
	}
	adapter := ubuntu.NewAt(root, source, host, stateModule)
	if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("irreversible handoff = %+v", result)
	}
	host.removalTokenActive = false
	observed.Status, observed.CurrentChangeSet, observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.ChangeInProgress, "change-0008", systemchanges.PreparedCheckpoint, len(completeRemovalIDs), false
	first := systemchanges.New(adapter).Recover()
	if first.Outcome != systemchanges.RemovalForwardOnly || host.removalFinalized {
		t.Fatalf("controlled runner-removal failure = %+v; host=%+v", first, host)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal was not durably removed before runner cleanup: %v", err)
	}
	second := systemchanges.New(ubuntu.NewAt(root, source, host, stateModule)).Recover()
	if second.Outcome != systemchanges.Completed || second.RestoredStatus != systemchanges.NotInstalled || !host.removalFinalized || len(second.UnremovableTraces) != 2 {
		t.Fatalf("leftover recovery runner self-clean = %+v; host=%+v", second, host)
	}
}

func TestUbuntuAdapterLeavesOrphanRecoveryAuthorityWhenRunnerPreparationIsInterrupted(t *testing.T) {
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.CompleteRemovalMutation, systemchanges.Check{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "REMOVAL-EXTERNAL-ABSENT"}, systemChangeTestOptions{startingStatus: systemchanges.Managed, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	host := &controlledUbuntuHost{root: root, expectedMutation: systemchanges.CompleteRemovalMutation, removalTokenActive: true, removalTokenAvailable: true, removedResources: map[string]bool{}, failRemovalPrepare: 1}
	source := func() (systemchanges.Observation, error) {
		if slices.Contains(host.irreversiblePhases, systemchanges.LocalStatePhase) {
			return systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, FilesystemBytes: observed.FilesystemBytes, AvailableBytes: observed.AvailableBytes, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: observed.TimeOwner}, nil
		}
		return observed, nil
	}
	adapter := ubuntu.NewAt(root, source, host, stateModule)
	if result := systemchanges.New(adapter).Apply(changeSet); result.Outcome != systemchanges.AwaitingTokenRevocation {
		t.Fatalf("irreversible handoff = %+v", result)
	}
	host.removalTokenActive = false
	observed.Status, observed.CurrentChangeSet, observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.ChangeInProgress, "change-0008", systemchanges.PreparedCheckpoint, len(completeRemovalIDs), false
	first := systemchanges.New(adapter).Recover()
	if first.Outcome != systemchanges.RemovalForwardOnly {
		t.Fatalf("controlled runner preparation interruption = %+v", first)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions/change-0008")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolved transaction journal remained after final absence proof: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/transactions", ubuntu.FinalizingRemovalChangeSet)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("finalizing journal remained after final absence proof: %v", err)
	}
	second := systemchanges.New(ubuntu.NewAt(root, source, host, stateModule)).Recover()
	if second.Outcome != systemchanges.Completed || second.RestoredStatus != systemchanges.NotInstalled || !host.removalFinalized {
		t.Fatalf("finalizing journal recovery = %+v; host=%+v", second, host)
	}
}

func TestUbuntuAdapterKeepsOrphanRunnerWhileOwnedResourcesRemain(t *testing.T) {
	root := t.TempDir()
	prepareLock(t, root)
	observed := systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, FilesystemBytes: 1 << 30, AvailableBytes: 1 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
	host := &controlledUbuntuHost{root: root, removedResources: map[string]bool{}, removalTokenAvailable: true}
	result := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)).Recover()
	if result.Outcome != systemchanges.RemovalForwardOnly || host.removalFinalized {
		t.Fatalf("orphan runner with residual owned resources = %+v; host=%+v", result, host)
	}
}

func TestUbuntuAdapterRemovalResumesAfterDeathBetweenFinalJournalAndDirectoryDeletion(t *testing.T) {
	for _, hostile := range []bool{false, true} {
		t.Run(fmt.Sprintf("hostile=%t", hostile), func(t *testing.T) {
			root := t.TempDir()
			prepareLock(t, root)
			finalizing := filepath.Join(root, "var/lib/sbxr/transactions/removal-finalizing")
			if err := os.MkdirAll(finalizing, 0o700); err != nil {
				t.Fatal(err)
			}
			if hostile {
				if err := os.WriteFile(filepath.Join(finalizing, "unknown"), []byte("unrelated"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			removed := map[string]bool{}
			for _, identity := range completeRemovalIDs {
				removed[identity] = true
			}
			host := &controlledUbuntuHost{
				root: root, removedResources: removed,
				irreversiblePhases: []systemchanges.IrreversibleRemovalPhase{
					systemchanges.PackageHoldsPhase, systemchanges.LocalStatePhase, systemchanges.SecretsPhase, systemchanges.CertificatesPhase,
					systemchanges.TransactionMaterialDeletionAuthorizedPhase,
					systemchanges.ReleasesPhase, systemchanges.UnitsPhase, systemchanges.IdentitiesPhase,
					systemchanges.ListenersPhase, systemchanges.PreparedArtifactsPhase, systemchanges.OwnedFirewallStatePhase,
				},
			}
			observed := systemchanges.Observation{Status: systemchanges.NotInstalled, Checkpoint: systemchanges.NoCheckpoint, Lock: systemchanges.LockReleased, FilesystemBytes: 1 << 30, AvailableBytes: 1 << 30, WallTimeSynchronized: true, MonotonicClock: true, TimeOwner: "systemd-timesyncd.service"}
			result := systemchanges.New(ubuntu.NewAt(root, func() (systemchanges.Observation, error) { return observed, nil }, host)).Recover()
			if hostile {
				if result.Outcome != systemchanges.RemovalForwardOnly || host.removalFinalized {
					t.Fatalf("hostile finalizing directory = %+v; host=%+v", result, host)
				}
				return
			}
			if result.Outcome != systemchanges.Completed || result.RestoredStatus != systemchanges.NotInstalled || !host.removalFinalized || len(result.UnremovableTraces) != 2 {
				t.Fatalf("empty finalizing directory recovery = %+v; host=%+v", result, host)
			}
			if _, err := os.Stat(finalizing); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("finalizing directory remains: %v", err)
			}
		})
	}
}

func TestUbuntuFirewallRestartRepeatsOnlyItsRecordedReverse(t *testing.T) {
	policy, err := systemchanges.NewFirewallPolicyStep("table inet sbxr {\n chain input {\n  type filter hook input priority filter\n  policy drop\n  tcp dport 2200 accept\n }\n}", 2200)
	if err != nil {
		t.Fatal(err)
	}
	stateModule, changeSet, _, observed := preparedSystemChangeWithOptions(t, systemchanges.SettingChangeMutation, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-SSH-RESPONSIVE"}, systemChangeTestOptions{extraSteps: []systemchanges.Step{policy}, stepTimeout: time.Second})
	root := t.TempDir()
	prepareLock(t, root)
	interrupted := &controlledFirewall{failSSH: true, failReverse: true, unrelated: "table inet unrelated remains"}
	result := systemchanges.New(ubuntu.NewAtWithFirewall(root, func() (systemchanges.Observation, error) { return observed, nil }, &controlledUbuntuHost{root: root}, interrupted, stateModule)).Apply(changeSet)
	if result.Outcome != systemchanges.RecoveryRequiredOutcome {
		t.Fatalf("interrupted firewall rollback = %+v", result)
	}
	observed.Status, observed.CurrentChangeSet = systemchanges.ChangeInProgress, "change-0008"
	observed.Checkpoint, observed.TotalSteps, observed.RollbackAvailable = systemchanges.PreparedCheckpoint, 2, true
	freshFirewall := &controlledFirewall{unrelated: "table inet unrelated remains"}
	host := &controlledUbuntuHost{root: root, services: map[string]*controlledService{
		"network": {owner: systemchanges.NetworkPolicyModule, state: observed.StateSHA256, known: true},
	}}
	recovered := systemchanges.New(ubuntu.NewAtWithFirewall(root, func() (systemchanges.Observation, error) { return observed, nil }, host, freshFirewall, stateModule)).Recover()
	joined := strings.Join(freshFirewall.events, ",")
	if recovered.Outcome != systemchanges.RollbackSucceeded || !strings.Contains(joined, "inspect exact inet sbxr effect") || !strings.Contains(joined, "restore only prior inet sbxr") || freshFirewall.unrelated != "table inet unrelated remains" {
		t.Fatalf("firewall restart recovery = %+v; firewall=%+v", recovered, freshFirewall)
	}
}

func prepareLock(t *testing.T, root string) {
	t.Helper()
	lockPath := filepath.Join(root, "run/sbxr/system-changes.lock")
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
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
