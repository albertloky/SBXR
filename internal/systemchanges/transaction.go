package systemchanges

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync/atomic"
	"time"
)

// DurableCheckpoint names one recovery-relevant journal boundary.
type DurableCheckpoint string

const (
	Prepared                      DurableCheckpoint = "Prepared"
	StepStarted                   DurableCheckpoint = "Step started"
	StepCompleted                 DurableCheckpoint = "Step completed"
	PrePublicationHealthPassed    DurableCheckpoint = "Pre-publication health passed"
	OwnedExternalDeletionVerified DurableCheckpoint = "Owned external deletion verified"
	IrreversibleRemovalStarted    DurableCheckpoint = "Irreversible removal started"
	TokenRevocationVerified       DurableCheckpoint = "Cloudflare token revocation verified"
	RemainingExternalDeleted      DurableCheckpoint = "Remaining owned external resources deleted"
	LocalStateDeleted             DurableCheckpoint = "Local State deleted"
	SecretsDeleted                DurableCheckpoint = "Infrastructure Secrets deleted"
	CertificatesDeleted           DurableCheckpoint = "Certificates deleted"
	ServicesDeleted               DurableCheckpoint = "Services deleted"
	IdentitiesDeleted             DurableCheckpoint = "Identities deleted"
	ListenersDeleted              DurableCheckpoint = "Listeners deleted"
	FirewallRulesDeleted          DurableCheckpoint = "Firewall rules deleted"
	ReleasesDeleted               DurableCheckpoint = "Releases deleted"
	TransactionMaterialDeleted    DurableCheckpoint = "Transaction material deleted"
	FinalRemovalAbsenceVerified   DurableCheckpoint = "Final removal absence verified"
	StatePublicationStarted       DurableCheckpoint = "Desired State publication started"
	StatePublished                DurableCheckpoint = "Desired State published"
	PostPublicationHealthPassed   DurableCheckpoint = "Post-publication health passed"
	Complete                      DurableCheckpoint = "Complete"
	CancellationRequested         DurableCheckpoint = "Cancellation requested"
	RollbackStarted               DurableCheckpoint = "Rollback started"
	RollbackStepStarted           DurableCheckpoint = "Rollback step started"
	RollbackStepCompleted         DurableCheckpoint = "Rollback step completed"
	RollbackVerified              DurableCheckpoint = "Rollback verified"
	RolledBack                    DurableCheckpoint = "Rolled back"
)

type CheckpointRecord struct {
	ChangeSet     string
	Checkpoint    DurableCheckpoint
	Step          int
	Evidence      *StepEvidence
	CompletedStep *Step
}

func (record CheckpointRecord) String() string {
	if record.Step > 0 {
		return fmt.Sprintf("%s %d", record.Checkpoint, record.Step)
	}
	return string(record.Checkpoint)
}

type GatePhase string

const (
	PrePublication  GatePhase = "Pre-publication"
	PostPublication GatePhase = "Post-publication"
)

type ReleaseBinding struct {
	Repository         string `json:"repository"`
	Tag                string `json:"tag"`
	Commit             string `json:"commit"`
	ReleaseIndexSHA256 string `json:"release_index_sha256"`
}

type StateTransactionBinding struct {
	StartingRevision       uint64         `json:"starting_revision"`
	CandidateRevision      uint64         `json:"candidate_revision"`
	StartingSHA256         string         `json:"starting_sha256"`
	CandidateSHA256        string         `json:"candidate_sha256"`
	PreparedStateSHA256    string         `json:"prepared_state_sha256"`
	PreparedManifestSHA256 string         `json:"prepared_manifest_sha256"`
	ChangeSet              string         `json:"change_set"`
	StartingRelease        ReleaseBinding `json:"starting_release"`
	CandidateRelease       ReleaseBinding `json:"candidate_release"`
}

type Preparation struct {
	ChangeSet    string
	Mutation     MutationClass
	OutcomeOwner Module
	Starting     StateLineage
	PlanSHA256   string
	State        StateTransactionBinding
	Steps        []Step
	Checks       []Check
	Timeouts     Timeouts
	writeState   func(func(name string, mode uint32, source io.Reader) error) error
}

func (preparation Preparation) WriteStateArtifacts(write func(name string, mode uint32, source io.Reader) error) error {
	if preparation.writeState == nil || write == nil {
		return fmt.Errorf("state artifact handoff unavailable")
	}
	return preparation.writeState(write)
}

type Agreement struct {
	Revision               uint64         `json:"revision"`
	CandidateSHA256        string         `json:"candidate_sha256"`
	PublishedStateSHA256   string         `json:"published_state_sha256"`
	PreparedManifestSHA256 string         `json:"prepared_manifest_sha256"`
	ChangeSet              string         `json:"change_set"`
	Release                ReleaseBinding `json:"release_identity"`
}

type RollbackAgreement struct {
	Status   InstallationStatus `json:"status"`
	Revision uint64             `json:"revision"`
	SHA256   string             `json:"sha256"`
	Release  ReleaseBinding     `json:"release_identity"`
}

type StepEvidence struct {
	Code   string `json:"code"`
	SHA256 string `json:"sha256"`
}

type StepEffect string

const (
	StepEffectAbsent  StepEffect = "Absent"
	StepEffectPresent StepEffect = "Present"
)

type IrreversibleRemovalPhase string

const (
	RemainingExternalResourcesPhase IrreversibleRemovalPhase = "Remaining owned external resources"
	LocalStatePhase                 IrreversibleRemovalPhase = "local State"
	SecretsPhase                    IrreversibleRemovalPhase = "Infrastructure Secrets"
	CertificatesPhase               IrreversibleRemovalPhase = "certificates"
	ServicesPhase                   IrreversibleRemovalPhase = "services"
	IdentitiesPhase                 IrreversibleRemovalPhase = "identities"
	ListenersPhase                  IrreversibleRemovalPhase = "listeners"
	FirewallRulesPhase              IrreversibleRemovalPhase = "firewall rules"
	ReleasesPhase                   IrreversibleRemovalPhase = "releases"
	TransactionMaterialPhase        IrreversibleRemovalPhase = "transaction material"
)

var irreversibleRemovalPhases = []struct {
	phase      IrreversibleRemovalPhase
	checkpoint DurableCheckpoint
}{
	{RemainingExternalResourcesPhase, RemainingExternalDeleted},
	{LocalStatePhase, LocalStateDeleted},
	{SecretsPhase, SecretsDeleted},
	{CertificatesPhase, CertificatesDeleted},
	{ServicesPhase, ServicesDeleted},
	{IdentitiesPhase, IdentitiesDeleted},
	{ListenersPhase, ListenersDeleted},
	{FirewallRulesPhase, FirewallRulesDeleted},
	{ReleasesPhase, ReleasesDeleted},
	{TransactionMaterialPhase, TransactionMaterialDeleted},
}

// RecoveryTransaction is the secret-safe durable authority for one interrupted
// ordinary Change Set. Snapshot contents remain inside the Adapter.
type RecoveryTransaction struct {
	ChangeSet        string
	Mutation         MutationClass
	Starting         StateLineage
	StartingRelease  ReleaseBinding
	Candidate        StateLineage
	CandidateRelease ReleaseBinding
	OutcomeOwner     Module
	Steps            []Step
	AttemptedSteps   int
	RollbackStep     int
	LastCheckpoint   DurableCheckpoint
	Timeouts         Timeouts
}

type ExecutionLease struct{ authority *executionAuthority }
type executionAuthority struct {
	active   atomic.Bool
	recovery bool
}

func newExecutionLease() ExecutionLease {
	authority := &executionAuthority{}
	authority.active.Store(true)
	return ExecutionLease{authority: authority}
}
func newRecoveryLease() ExecutionLease {
	lease := newExecutionLease()
	lease.authority.recovery = true
	return lease
}
func (lease ExecutionLease) Authorized() bool {
	return lease.authority != nil && lease.authority.active.Load()
}
func (lease ExecutionLease) RecoveryAuthorized() bool {
	return lease.Authorized() && lease.authority.recovery
}
func (lease ExecutionLease) revoke() {
	if lease.authority != nil {
		lease.authority.active.Store(false)
	}
}

type leaseLock struct {
	Lock
	lease ExecutionLease
}

func (lock leaseLock) Close() error {
	lock.lease.revoke()
	return lock.Lock.Close()
}

// TransactionAdapter is the one whole-host Seam for durable work after SC-01 admission.
type TransactionAdapter interface {
	Prepare(ExecutionLease, Preparation) error
	Record(ExecutionLease, CheckpointRecord) error
	Execute(ExecutionLease, string, int, Step, time.Duration, *Cancellation) (StepEvidence, error)
	Reverse(ExecutionLease, string, int, Step, time.Duration) (StepEvidence, error)
	Check(ExecutionLease, Check, GatePhase, time.Duration) (HealthStatus, error)
	VerifyAgreement(ExecutionLease, Agreement, time.Duration) error
	VerifyRollback(ExecutionLease, RollbackAgreement, time.Duration) error
	Cleanup(lease ExecutionLease, changeSet string) error
}

type RecoveryAdapter interface {
	LoadRecovery(ExecutionLease) (RecoveryTransaction, error)
	HoldServices(ExecutionLease) error
	AllowProvenServices(ExecutionLease, RecoveryTransaction, time.Duration) error
	InspectStep(ExecutionLease, RecoveryTransaction, int, Step, time.Duration) (StepEffect, error)
	RestoreRecoveryState(ExecutionLease, RecoveryTransaction) (RollbackAgreement, error)
	VerifyStartingServices(ExecutionLease, RecoveryTransaction, time.Duration) error
}

type IrreversibleRemovalAdapter interface {
	VerifyCloudflareTokenRevoked(ExecutionLease, RecoveryTransaction, time.Duration) (bool, error)
	DeleteIrreversibleRemovalPhase(ExecutionLease, RecoveryTransaction, IrreversibleRemovalPhase, time.Duration) (StepEvidence, error)
	VerifyFinalRemovalAbsence(ExecutionLease, RecoveryTransaction, time.Duration) (Observation, error)
	FinalizeRemoval(ExecutionLease, RecoveryTransaction, time.Duration) error
}

type OrphanedRemovalAdapter interface {
	FinalizeOrphanedRemoval(ExecutionLease, Observation, time.Duration) error
}

type StateRecovery interface {
	SystemChangesRestoreDurable(lease any, binding []byte, prior, candidate io.Reader) ([]byte, error)
}

var ErrNoRecoveryTransaction = errors.New("no unfinished recovery transaction")

type statePreparedAuthority interface {
	SystemChangesConsume(lease any, planIdentity, planSHA256 string) (any, error)
}

type stateTransaction interface {
	SystemChangesBindings(lease any) ([]byte, error)
	SystemChangesWriteArtifacts(lease any, write func(name string, mode uint32, source io.Reader) error) error
	SystemChangesPublish(lease any) (any, error)
	SystemChangesRestore(lease any) ([]byte, error)
}

type stateAgreement interface {
	SystemChangesAgreement(lease any) ([]byte, error)
}

func (step Step) Owner() Module                              { return step.owner }
func (step Step) Forward() OperationKind                     { return step.forward }
func (step Step) Rollback() OperationKind                    { return step.rollback }
func (step Step) CancellationContract() CancellationContract { return step.cancel }
func (step Step) InspectionContract() InspectionContract     { return step.inspect }
func (step Step) FirewallChange() (FirewallChange, bool) {
	return step.firewall, step.firewall != (FirewallChange{})
}
func (step Step) RemovalChange() (RemovalChange, bool) {
	return step.removal, step.removal != (RemovalChange{})
}

// Recover is the private startup path for unfinished ordinary forward work.
// It never resumes the forward transaction.
func (i Interface) Recover() ApplyResult {
	adapter, transactionOK := i.adapter.(TransactionAdapter)
	recoveryAdapter, recoveryOK := i.adapter.(RecoveryAdapter)
	if !transactionOK || !recoveryOK {
		return ApplyResult{Outcome: RecoveryRequiredOutcome, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-RECOVERY-ADAPTER", Owner: StateModule, Problem: "Restart recovery is unavailable", Found: "no complete durable recovery Adapter", Required: "one private recovery runner over the production Adapter", WhyStopped: "unfinished work cannot be guessed through", NextAction: "Keep affected services stopped and use Inspect."}}
	}
	lock, acquired, err := i.adapter.TryLock()
	if err != nil || acquired && lock == nil {
		return ApplyResult{Outcome: RecoveryRequiredOutcome, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-RECOVERY-LOCK", Owner: StateModule, Problem: "Restart recovery could not acquire the kernel lock", Found: "the lock is held or unprovable", Required: "the released installation-wide kernel lock", WhyStopped: "PID or wall time never proves ownership", NextAction: "Keep affected services stopped and use Inspect."}}
	}
	if !acquired {
		result := refused("SYSTEM-CHANGES-RECOVERY-BUSY", "Restart recovery found the kernel lock held", "one active mutation owner", "the kernel-released installation-wide lock", "PID or wall time never authorizes stealing the lock", "Keep affected services stopped and use Inspect.", true)
		result.Finding.Owner = StateModule
		return result
	}
	lease := newRecoveryLease()
	defer lease.revoke()
	lock = leaseLock{Lock: lock, lease: lease}
	if err := recoveryAdapter.HoldServices(lease); err != nil {
		return finish(lock, recoveryRequired(ChangeSetSpec{OutcomeOwner: StateModule}, "SYSTEM-CHANGES-SERVICE-HOLDBACK", Prepared))
	}
	recovery, err := recoveryAdapter.LoadRecovery(lease)
	if errors.Is(err, ErrNoRecoveryTransaction) {
		observed, observeErr := i.adapter.Observe()
		if observeErr != nil || !validObservation(observed) || observed.Status != Managed && observed.Status != NotInstalled {
			return finish(lock, recoveryRequired(ChangeSetSpec{OutcomeOwner: StateModule}, "SYSTEM-CHANGES-RECOVERY-LINEAGE", Prepared))
		}
		if finalizer, ok := i.adapter.(OrphanedRemovalAdapter); ok && observed.Status == NotInstalled {
			if err := finalizer.FinalizeOrphanedRemoval(lease, observed, time.Minute); err != nil {
				return finish(lock, forwardRemovalRequired(ChangeSetSpec{OutcomeOwner: StateModule}, "SYSTEM-CHANGES-REMOVAL-RUNNER", FinalRemovalAbsenceVerified))
			}
			return finish(lock, ApplyResult{Outcome: Completed, RestoredStatus: NotInstalled, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()})
		}
		result := refused("SYSTEM-CHANGES-RECOVERY-NOT-NEEDED", "No unfinished Change Set requires restart recovery", "no durable transaction", "the last proven Desired State", "ordinary work is never invented or resumed", "Start only services proven against the current Desired State.", true)
		result.Finding.Owner = StateModule
		return finish(lock, result)
	}
	if err != nil || !validRecoveryTransaction(recovery) {
		return finish(lock, recoveryRequired(ChangeSetSpec{OutcomeOwner: StateModule}, "SYSTEM-CHANGES-RECOVERY-LINEAGE", Prepared))
	}
	recovery.Steps = append([]Step(nil), recovery.Steps...)
	spec := ChangeSetSpec{Identity: recovery.ChangeSet, Mutation: recovery.Mutation, StartingState: recovery.Starting, OutcomeOwner: recovery.OutcomeOwner, Steps: recovery.Steps, Timeouts: recovery.Timeouts}
	if recovery.Mutation == CompleteRemovalMutation && irreversibleRemovalCheckpoint(recovery.LastCheckpoint) {
		removalAdapter, ok := i.adapter.(IrreversibleRemovalAdapter)
		if !ok {
			return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-ADAPTER", recovery.LastCheckpoint))
		}
		return finish(lock, continueIrreversibleRemoval(lease, adapter, removalAdapter, recovery, spec))
	}
	if err := recoveryAdapter.AllowProvenServices(lease, recovery, recovery.Timeouts.Check); err != nil {
		return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-SERVICE-HOLDBACK", recovery.LastCheckpoint))
	}
	if recovery.LastCheckpoint == Complete {
		if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
			return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete))
		}
		return finish(lock, ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()})
	}
	if recovery.LastCheckpoint == RolledBack {
		if recoveryAdapter.VerifyStartingServices(lease, recovery, recovery.Timeouts.Check) != nil || adapter.Cleanup(lease, recovery.ChangeSet) != nil {
			return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RolledBack))
		}
		return finish(lock, recoveredRollbackResult(recovery, rollbackRestoredStatus(recovery.Starting)))
	}
	nextRollbackStep := recovery.AttemptedSteps
	if rollbackCheckpoint(recovery.LastCheckpoint) {
		nextRollbackStep = recovery.RollbackStep
	}
	for index := nextRollbackStep - 1; index >= 0; index-- {
		effect, err := recoveryAdapter.InspectStep(lease, recovery, index+1, recovery.Steps[index], recovery.Timeouts.Check)
		if err != nil || effect != StepEffectAbsent && effect != StepEffectPresent {
			return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-RECOVERY-INSPECTION", recovery.LastCheckpoint))
		}
	}
	result := rollbackRecovered(lease, adapter, recoveryAdapter, recovery, spec)
	return finish(lock, result)
}

func validRecoveryTransaction(recovery RecoveryTransaction) bool {
	if !safeIdentity(recovery.ChangeSet) || !validMutation(recovery.Mutation) || !validModule(recovery.OutcomeOwner) || len(recovery.Steps) == 0 || recovery.AttemptedSteps < 0 || recovery.AttemptedSteps > len(recovery.Steps) || recovery.Timeouts.Step <= 0 || recovery.Timeouts.Step > maxStepTimeout || recovery.Timeouts.Check <= 0 || recovery.Timeouts.Check > maxCheckTimeout {
		return false
	}
	if (recovery.Starting.Status == Managed || recovery.Starting.Status == RecoveryRequired) && (recovery.Starting.Revision == 0 || !validSHA256(recovery.Starting.SHA256) || recovery.StartingRelease == (ReleaseBinding{})) || recovery.Starting.Status == NotInstalled && (recovery.Starting.Revision != 0 || recovery.Starting.SHA256 != "" || recovery.StartingRelease != (ReleaseBinding{})) || recovery.Starting.Status != Managed && recovery.Starting.Status != RecoveryRequired && recovery.Starting.Status != NotInstalled {
		return false
	}
	removal := false
	for _, step := range recovery.Steps {
		if !validStep(step) {
			return false
		}
		removal = removal || step.removal != (RemovalChange{})
	}
	if recovery.Mutation == CompleteRemovalMutation != removal || removal && !validRemovalSteps(recovery.Steps) {
		return false
	}
	switch recovery.LastCheckpoint {
	case Prepared:
		return recovery.AttemptedSteps == 0
	case StepStarted, StepCompleted, PrePublicationHealthPassed, OwnedExternalDeletionVerified, StatePublicationStarted, StatePublished, PostPublicationHealthPassed:
		return recovery.AttemptedSteps > 0 && recovery.RollbackStep == 0
	case IrreversibleRemovalStarted, TokenRevocationVerified, RemainingExternalDeleted, LocalStateDeleted, SecretsDeleted, CertificatesDeleted, ServicesDeleted, IdentitiesDeleted, ListenersDeleted, FirewallRulesDeleted, ReleasesDeleted, TransactionMaterialDeleted, FinalRemovalAbsenceVerified:
		return recovery.Mutation == CompleteRemovalMutation && recovery.AttemptedSteps == len(recovery.Steps) && recovery.RollbackStep == 0
	case RollbackStarted:
		return recovery.RollbackStep == recovery.AttemptedSteps
	case RollbackStepStarted:
		return recovery.RollbackStep > 0 && recovery.RollbackStep <= recovery.AttemptedSteps
	case RollbackStepCompleted:
		return recovery.RollbackStep >= 0 && recovery.RollbackStep < recovery.AttemptedSteps
	case RollbackVerified, RolledBack:
		return recovery.RollbackStep == 0
	case Complete:
		return recovery.RollbackStep == 0 && recovery.Candidate.Status == Managed && recovery.Candidate.Revision == recovery.Starting.Revision+1 && validSHA256(recovery.Candidate.SHA256) && recovery.CandidateRelease != (ReleaseBinding{})
	}
	return false
}

func irreversibleRemovalCheckpoint(checkpoint DurableCheckpoint) bool {
	switch checkpoint {
	case IrreversibleRemovalStarted, TokenRevocationVerified, RemainingExternalDeleted, LocalStateDeleted, SecretsDeleted, CertificatesDeleted, ServicesDeleted, IdentitiesDeleted, ListenersDeleted, FirewallRulesDeleted, ReleasesDeleted, TransactionMaterialDeleted, FinalRemovalAbsenceVerified:
		return true
	}
	return false
}

func continueIrreversibleRemoval(lease ExecutionLease, adapter TransactionAdapter, removal IrreversibleRemovalAdapter, recovery RecoveryTransaction, spec ChangeSetSpec) ApplyResult {
	record := func(checkpoint DurableCheckpoint, evidence *StepEvidence) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: checkpoint, Evidence: evidence}) == nil
	}
	if recovery.LastCheckpoint == IrreversibleRemovalStarted {
		revoked, err := removal.VerifyCloudflareTokenRevoked(lease, recovery, recovery.Timeouts.Check)
		if err != nil {
			return forwardRemovalRequired(spec, "SYSTEM-CHANGES-TOKEN-REVOCATION", IrreversibleRemovalStarted)
		}
		if !revoked {
			return ApplyResult{Outcome: AwaitingTokenRevocation, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), UnremovableTraces: []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"}}
		}
		if !record(TokenRevocationVerified, nil) {
			return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", IrreversibleRemovalStarted)
		}
		recovery.LastCheckpoint = TokenRevocationVerified
	}
	start := 0
	for index, item := range irreversibleRemovalPhases {
		if recovery.LastCheckpoint == item.checkpoint {
			start = index + 1
		}
	}
	if recovery.LastCheckpoint != FinalRemovalAbsenceVerified {
		for _, item := range irreversibleRemovalPhases[start:] {
			evidence, err := removal.DeleteIrreversibleRemovalPhase(lease, recovery, item.phase, recovery.Timeouts.Step)
			if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !record(item.checkpoint, &evidence) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-FORWARD", item.checkpoint)
			}
			recovery.LastCheckpoint = item.checkpoint
		}
		observed, err := removal.VerifyFinalRemovalAbsence(lease, recovery, recovery.Timeouts.Check)
		if err != nil || !validObservation(observed) || observed.Status != NotInstalled || !record(FinalRemovalAbsenceVerified, nil) {
			return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-ABSENCE", FinalRemovalAbsenceVerified)
		}
	}
	if err := removal.FinalizeRemoval(lease, recovery, recovery.Timeouts.Step); err != nil {
		return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-FINALIZE", FinalRemovalAbsenceVerified)
	}
	return ApplyResult{Outcome: Completed, RestoredStatus: NotInstalled, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), UnremovableTraces: []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"}}
}

func forwardRemovalRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-FORWARD-REMOVAL", Owner: spec.OutcomeOwner, Problem: "Irreversible Complete removal must continue forward", Found: string(checkpoint), Required: "retry the exact next durable deletion from protected evidence", WhyStopped: cause, NextAction: "Keep services stopped and retry the private recovery runner."}}
}

func rollbackCheckpoint(checkpoint DurableCheckpoint) bool {
	switch checkpoint {
	case RollbackStarted, RollbackStepStarted, RollbackStepCompleted, RollbackVerified, RolledBack:
		return true
	}
	return false
}

func rollbackRecovered(lease ExecutionLease, adapter TransactionAdapter, recoveryAdapter RecoveryAdapter, recovery RecoveryTransaction, spec ChangeSetSpec) ApplyResult {
	record := func(point DurableCheckpoint, step int, evidence *StepEvidence) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: point, Step: step, Evidence: evidence}) == nil
	}
	if !rollbackCheckpoint(recovery.LastCheckpoint) && !record(RollbackStarted, 0, nil) {
		return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", recovery.LastCheckpoint)
	}
	agreement, err := recoveryAdapter.RestoreRecoveryState(lease, recovery)
	if err != nil || agreement.Release != recovery.StartingRelease {
		return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RollbackStarted)
	}
	restored, valid := rollbackResultStatus(agreement, recovery.Starting)
	if !valid {
		return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RollbackStarted)
	}
	nextRollbackStep := recovery.AttemptedSteps
	if rollbackCheckpoint(recovery.LastCheckpoint) {
		nextRollbackStep = recovery.RollbackStep
	}
	stepAlreadyStarted := recovery.LastCheckpoint == RollbackStepStarted
	for index := nextRollbackStep - 1; index >= 0; index-- {
		number := index + 1
		if !stepAlreadyStarted && !record(RollbackStepStarted, number, nil) {
			return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RollbackStepStarted)
		}
		evidence, reverseErr := adapter.Reverse(lease, recovery.ChangeSet, number, recovery.Steps[index], recovery.Timeouts.Step)
		if reverseErr != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !record(RollbackStepCompleted, number, &evidence) {
			return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RollbackStepStarted)
		}
		stepAlreadyStarted = false
	}
	if err := adapter.VerifyRollback(lease, agreement, recovery.Timeouts.Check); err != nil || recoveryAdapter.VerifyStartingServices(lease, recovery, recovery.Timeouts.Check) != nil || recovery.LastCheckpoint != RollbackVerified && !record(RollbackVerified, 0, nil) || !record(RolledBack, 0, nil) {
		return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RollbackVerified)
	}
	if err := adapter.Cleanup(lease, recovery.ChangeSet); err != nil {
		return recoveryRequired(spec, "SYSTEM-CHANGES-RESTART", RolledBack)
	}
	return recoveredRollbackResult(recovery, restored)
}

func recoveredRollbackResult(recovery RecoveryTransaction, restored InstallationStatus) ApplyResult {
	return ApplyResult{Outcome: RollbackSucceeded, RestoredStatus: restored, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-ROLLED-BACK-AFTER-RESTART", Owner: recovery.OutcomeOwner, Problem: "The interrupted Change Set was rolled back from durable evidence", Found: string(recovery.LastCheckpoint), Required: "the prior proven installation status", WhyStopped: "SYSTEM-CHANGES-RESTART", NextAction: "Start only services proven against the restored Desired State."}}
}

func (i Interface) applyPrepared(lock Lock, spec ChangeSetSpec, cancellation *Cancellation) ApplyResult {
	adapter, ok := i.adapter.(TransactionAdapter)
	if !ok {
		return finish(lock, refused("SYSTEM-CHANGES-TRANSACTION-ADAPTER", "Durable transaction execution is unavailable", "the Adapter has no transaction capability", "one protected durable transaction Adapter", "live work cannot start without recovery material", "Restore the Adapter and create a fresh Plan.", true))
	}
	lease := newExecutionLease()
	defer lease.revoke()
	lock = leaseLock{Lock: lock, lease: lease}
	prepared, ok := spec.PreparedState.(statePreparedAuthority)
	if !ok {
		return finish(lock, refused("SYSTEM-CHANGES-PREPARED-STATE", "The prepared State authority cannot be consumed", "an incomplete State handoff", "one exact one-use State authority", "live work cannot start without opaque transaction material", "Prepare State again and create a fresh Plan.", true))
	}
	material, err := prepared.SystemChangesConsume(lease, spec.Plan.Identity, spec.Plan.SHA256)
	if err != nil {
		return finish(lock, refused("SYSTEM-CHANGES-PREPARED-STATE", "The prepared State authority could not be consumed", "State refused the one-use handoff", "one fresh exact State transaction handoff", "live work has not started", "Reload State and create a fresh Plan.", true))
	}
	typeOf := reflect.TypeOf(material)
	transaction, ok := material.(stateTransaction)
	if !ok || typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/state" || typeOf.Elem().Name() != "TransactionMaterial" {
		return finish(lock, refused("SYSTEM-CHANGES-STATE-MATERIAL", "State returned invalid transaction material", "an untrusted opaque handoff", "one State-owned TransactionMaterial", "live work has not started", "Prepare State again and create a fresh Plan.", true))
	}
	binding, ok := transactionBinding(lease, transaction, spec)
	if !ok {
		return finish(lock, refused("SYSTEM-CHANGES-STATE-BINDING", "State transaction material does not match the Change Set", "a mismatched lineage, release, checksum, or identity", "the exact reviewed State transaction binding", "live work has not started", "Reload State and create a fresh Plan.", true))
	}
	preparation := Preparation{
		ChangeSet: spec.Identity, Mutation: spec.Mutation, OutcomeOwner: spec.OutcomeOwner, Starting: spec.StartingState,
		PlanSHA256: spec.Plan.SHA256, State: binding,
		Steps: append([]Step(nil), spec.Steps...), Checks: append([]Check(nil), spec.Checks...), Timeouts: spec.Timeouts,
		writeState: func(write func(name string, mode uint32, source io.Reader) error) error {
			return transaction.SystemChangesWriteArtifacts(lease, write)
		},
	}
	if err := adapter.Prepare(lease, preparation); err != nil {
		return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-PREPARATION", Prepared))
	}
	for index, step := range spec.Steps {
		if cancellation.Requested() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, index))
		}
		number := index + 1
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepStarted, Step: number}); err != nil {
			return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-JOURNAL", StepStarted))
		}
		evidence, err := adapter.Execute(lease, spec.Identity, number, step, spec.Timeouts.Step, cancellation)
		if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) {
			if cancellation.Requested() {
				return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, number))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, number, "SYSTEM-CHANGES-STEP", StepStarted))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepCompleted, Step: number, Evidence: &evidence, CompletedStep: &step}); err != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, number, "SYSTEM-CHANGES-JOURNAL", StepStarted))
		}
		if cancellation.Requested() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, number))
		}
	}
	if cancellation.Requested() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if !gatePassed(lease, adapter, spec.Checks, PrePublication, spec.Timeouts.Check) {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-HEALTH", DurableCheckpoint(PrePublication+" health")))
	}
	if cancellation.Requested() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: PrePublicationHealthPassed}); err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", StepCompleted))
	}
	if spec.Mutation == CompleteRemovalMutation {
		if cancellation.Requested() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: OwnedExternalDeletionVerified}); err != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: IrreversibleRemovalStarted}); err != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", OwnedExternalDeletionVerified))
		}
		return finish(lock, ApplyResult{Outcome: AwaitingTokenRevocation, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), UnremovableTraces: []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"}}, spec.OutcomeOwner)
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StatePublicationStarted}); err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed))
	}
	if cancellation.Requested() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	published, err := transaction.SystemChangesPublish(lease)
	if err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-PUBLICATION", StatePublicationStarted))
	}
	agreement, ok := validatedAgreement(lease, published, binding)
	if !ok {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-PUBLICATION", StatePublicationStarted))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StatePublished}); err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", StatePublicationStarted))
	}
	if cancellation.Requested() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if !gatePassed(lease, adapter, spec.Checks, PostPublication, spec.Timeouts.Check) {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-HEALTH", DurableCheckpoint(PostPublication+" health")))
	}
	if cancellation.Requested() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if err := adapter.VerifyAgreement(lease, agreement, spec.Timeouts.Check); err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-AGREEMENT", StatePublished))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: PostPublicationHealthPassed}); err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", StatePublished))
	}
	if cancellation.Requested() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: Complete}); err != nil {
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed))
	}
	if err := adapter.Cleanup(lease, spec.Identity); err != nil {
		return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete))
	}
	return finish(lock, ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}, spec.OutcomeOwner)
}

func cancelAndRollback(lease ExecutionLease, adapter TransactionAdapter, transaction stateTransaction, spec ChangeSetSpec, attempted int) ApplyResult {
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: CancellationRequested, Step: attempted}); err != nil {
		return recoveryRequired(spec, "SYSTEM-CHANGES-CANCELLATION", CancellationRequested)
	}
	return rollbackChange(lease, adapter, transaction, spec, attempted, "SYSTEM-CHANGES-CANCELLATION", CancellationRequested)
}

func rollbackChange(lease ExecutionLease, adapter TransactionAdapter, transaction stateTransaction, spec ChangeSetSpec, attempted int, cause string, checkpoint DurableCheckpoint) ApplyResult {
	record := func(point DurableCheckpoint, step int, evidence *StepEvidence) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: point, Step: step, Evidence: evidence}) == nil
	}
	if !record(RollbackStarted, 0, nil) {
		return recoveryRequired(spec, cause, checkpoint)
	}
	var agreement RollbackAgreement
	data, err := transaction.SystemChangesRestore(lease)
	if err != nil || json.Unmarshal(data, &agreement) != nil {
		return recoveryRequired(spec, cause, RollbackStarted)
	}
	restored, valid := rollbackResultStatus(agreement, spec.StartingState)
	if !valid {
		return recoveryRequired(spec, cause, RollbackStarted)
	}
	for index := attempted - 1; index >= 0; index-- {
		number := index + 1
		if !record(RollbackStepStarted, number, nil) {
			return recoveryRequired(spec, cause, RollbackStepStarted)
		}
		evidence, reverseErr := adapter.Reverse(lease, spec.Identity, number, spec.Steps[index], spec.Timeouts.Step)
		if reverseErr != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !record(RollbackStepCompleted, number, &evidence) {
			return recoveryRequired(spec, cause, RollbackStepStarted)
		}
	}
	if err := adapter.VerifyRollback(lease, agreement, spec.Timeouts.Check); err != nil || !record(RollbackVerified, 0, nil) || !record(RolledBack, 0, nil) {
		return recoveryRequired(spec, cause, RollbackVerified)
	}
	if err := adapter.Cleanup(lease, spec.Identity); err != nil {
		return recoveryRequired(spec, cause, RolledBack)
	}
	return ApplyResult{
		Outcome: RollbackSucceeded, RestoredStatus: restored, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(),
		Finding: &Finding{Code: "SYSTEM-CHANGES-ROLLED-BACK", Owner: spec.OutcomeOwner, Problem: "The Change Set stopped and its exact baseline was restored", Found: string(checkpoint), Required: "the prior proven installation status", WhyStopped: cause, NextAction: "Inspect the restored baseline and create a fresh Plan."},
	}
}

func validRollbackAgreement(agreement RollbackAgreement, starting StateLineage) bool {
	if agreement.Status != starting.Status || agreement.Revision != starting.Revision || agreement.SHA256 != starting.SHA256 {
		return false
	}
	return agreement.Status == NotInstalled && agreement.Release == (ReleaseBinding{}) || agreement.Status == Managed && agreement.Release != (ReleaseBinding{}) || agreement.Status == RecoveryRequired && agreement.Release == (ReleaseBinding{})
}

func rollbackResultStatus(agreement RollbackAgreement, starting StateLineage) (InstallationStatus, bool) {
	if validRollbackAgreement(agreement, starting) {
		return starting.Status, true
	}
	provedEarlierManaged := starting.Status == RecoveryRequired && starting.Revision > 0 && agreement.Status == Managed && agreement.Revision == starting.Revision && agreement.SHA256 == starting.SHA256 && agreement.Release != (ReleaseBinding{})
	return Managed, provedEarlierManaged
}

func rollbackRestoredStatus(starting StateLineage) InstallationStatus {
	if starting.Status == RecoveryRequired && starting.Revision > 0 {
		return Managed
	}
	return starting.Status
}

func recoveryRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{
		Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(),
		Finding: &Finding{Code: "SYSTEM-CHANGES-RECOVERY-REQUIRED", Owner: spec.OutcomeOwner, Problem: "Automatic rollback could not prove the prior baseline", Found: string(checkpoint), Required: "one complete verified reverse path", WhyStopped: cause, NextAction: "Use Inspect and the Recovery Required flow."},
	}
}

func transactionBinding(lease ExecutionLease, transaction stateTransaction, spec ChangeSetSpec) (StateTransactionBinding, bool) {
	data, err := transaction.SystemChangesBindings(lease)
	var binding StateTransactionBinding
	if err != nil || json.Unmarshal(data, &binding) != nil {
		return StateTransactionBinding{}, false
	}
	return binding, binding.ChangeSet == spec.Identity && binding.StartingRevision == spec.StartingState.Revision && binding.CandidateRevision == binding.StartingRevision+1 && binding.CandidateSHA256 == spec.TargetStateSHA256 && (binding.StartingSHA256 == spec.StartingState.SHA256 || spec.StartingState.Status == NotInstalled && binding.StartingSHA256 == "")
}

func validatedAgreement(lease ExecutionLease, value any, binding StateTransactionBinding) (Agreement, bool) {
	typeOf := reflect.TypeOf(value)
	published, ok := value.(stateAgreement)
	if !ok || typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/state" || typeOf.Elem().Name() != "PostPublicationAgreement" {
		return Agreement{}, false
	}
	data, err := published.SystemChangesAgreement(lease)
	var agreement Agreement
	if err != nil || json.Unmarshal(data, &agreement) != nil {
		return Agreement{}, false
	}
	return agreement, agreement.Revision == binding.CandidateRevision && agreement.CandidateSHA256 == binding.CandidateSHA256 && agreement.PublishedStateSHA256 == binding.PreparedStateSHA256 && agreement.PreparedManifestSHA256 == binding.PreparedManifestSHA256 && agreement.ChangeSet == binding.ChangeSet && agreement.Release == binding.CandidateRelease
}

func gatePassed(lease ExecutionLease, adapter TransactionAdapter, checks []Check, phase GatePhase, timeout time.Duration) bool {
	for _, check := range checks {
		if check.Phase != phase {
			continue
		}
		status, err := adapter.Check(lease, check, phase, timeout)
		if err != nil || check.Classification == Required && status != Healthy || check.Classification == Advisory && (status == Failed || status == Unknown || status == NeedsAttention && !check.Disclosed) {
			return false
		}
	}
	return true
}

func nothingChanged(spec ChangeSetSpec, code string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{
		Outcome: Refused, NothingChanged: true, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(),
		Finding: &Finding{Code: code, Owner: spec.OutcomeOwner, Problem: "The Change Set stopped before live work", Found: string(checkpoint), Required: "a valid durable transaction boundary", WhyStopped: "no live step started", NextAction: "Inspect incomplete transaction material and create a fresh Plan."},
	}
}
