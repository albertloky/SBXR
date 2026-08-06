package systemchanges

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync/atomic"
	"time"
)

// DurableCheckpoint names one recovery-relevant journal boundary.
type DurableCheckpoint string

const (
	Prepared                    DurableCheckpoint = "Prepared"
	StepStarted                 DurableCheckpoint = "Step started"
	StepCompleted               DurableCheckpoint = "Step completed"
	PrePublicationHealthPassed  DurableCheckpoint = "Pre-publication health passed"
	StatePublicationStarted     DurableCheckpoint = "Desired State publication started"
	StatePublished              DurableCheckpoint = "Desired State published"
	PostPublicationHealthPassed DurableCheckpoint = "Post-publication health passed"
	Complete                    DurableCheckpoint = "Complete"
	CancellationRequested       DurableCheckpoint = "Cancellation requested"
	RollbackStarted             DurableCheckpoint = "Rollback started"
	RollbackStepStarted         DurableCheckpoint = "Rollback step started"
	RollbackStepCompleted       DurableCheckpoint = "Rollback step completed"
	RollbackVerified            DurableCheckpoint = "Rollback verified"
	RolledBack                  DurableCheckpoint = "Rolled back"
)

type CheckpointRecord struct {
	ChangeSet  string
	Checkpoint DurableCheckpoint
	Step       int
	Evidence   *StepEvidence
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
	ChangeSet  string
	Mutation   MutationClass
	Starting   StateLineage
	PlanSHA256 string
	State      StateTransactionBinding
	Steps      []Step
	Checks     []Check
	writeState func(func(name string, mode uint32, source io.Reader) error) error
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

type ExecutionLease struct{ authority *executionAuthority }
type executionAuthority struct{ active atomic.Bool }

func newExecutionLease() ExecutionLease {
	authority := &executionAuthority{}
	authority.active.Store(true)
	return ExecutionLease{authority: authority}
}
func (lease ExecutionLease) Authorized() bool {
	return lease.authority != nil && lease.authority.active.Load()
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
	Execute(ExecutionLease, Step, time.Duration, *Cancellation) (StepEvidence, error)
	Reverse(ExecutionLease, string, int, Step, time.Duration) (StepEvidence, error)
	Check(ExecutionLease, Check, GatePhase, time.Duration) (HealthStatus, error)
	VerifyAgreement(ExecutionLease, Agreement, time.Duration) error
	VerifyRollback(ExecutionLease, RollbackAgreement, time.Duration) error
	Cleanup(lease ExecutionLease, changeSet string) error
}

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
		ChangeSet: spec.Identity, Mutation: spec.Mutation, Starting: spec.StartingState,
		PlanSHA256: spec.Plan.SHA256, State: binding,
		Steps: append([]Step(nil), spec.Steps...), Checks: append([]Check(nil), spec.Checks...),
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
		evidence, err := adapter.Execute(lease, step, spec.Timeouts.Step, cancellation)
		if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) {
			if cancellation.Requested() {
				return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, number))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, number, "SYSTEM-CHANGES-STEP", StepStarted))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepCompleted, Step: number, Evidence: &evidence}); err != nil {
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
	data, err := transaction.SystemChangesRestore(lease)
	var agreement RollbackAgreement
	if err != nil || json.Unmarshal(data, &agreement) != nil || !validRollbackAgreement(agreement, spec.StartingState) {
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
		Outcome: RollbackSucceeded, RestoredStatus: spec.StartingState.Status, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(),
		Finding: &Finding{Code: "SYSTEM-CHANGES-ROLLED-BACK", Owner: spec.OutcomeOwner, Problem: "The Change Set stopped and its exact baseline was restored", Found: string(checkpoint), Required: "the prior proven installation status", WhyStopped: cause, NextAction: "Inspect the restored baseline and create a fresh Plan."},
	}
}

func validRollbackAgreement(agreement RollbackAgreement, starting StateLineage) bool {
	if agreement.Status != starting.Status || agreement.Revision != starting.Revision || agreement.SHA256 != starting.SHA256 {
		return false
	}
	return agreement.Status == NotInstalled && agreement.Release == (ReleaseBinding{}) || agreement.Status == Managed && agreement.Release != (ReleaseBinding{})
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
