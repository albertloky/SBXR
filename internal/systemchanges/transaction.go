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
	Execute(ExecutionLease, Step, time.Duration) (StepEvidence, error)
	Check(ExecutionLease, Check, GatePhase, time.Duration) (HealthStatus, error)
	VerifyAgreement(ExecutionLease, Agreement) error
	Cleanup(lease ExecutionLease, changeSet string) error
}

type statePreparedAuthority interface {
	SystemChangesConsume(lease any, planIdentity, planSHA256 string) (any, error)
}

type stateTransaction interface {
	SystemChangesBindings(lease any) ([]byte, error)
	SystemChangesWriteArtifacts(lease any, write func(name string, mode uint32, source io.Reader) error) error
	SystemChangesPublish(lease any) (any, error)
}

type stateAgreement interface {
	SystemChangesAgreement(lease any) ([]byte, error)
}

func (step Step) Owner() Module           { return step.owner }
func (step Step) Forward() OperationKind  { return step.forward }
func (step Step) Rollback() OperationKind { return step.rollback }

func (i Interface) applyPrepared(lock Lock, spec ChangeSetSpec) ApplyResult {
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
		return finish(lock, executionStopped("SYSTEM-CHANGES-PREPARATION", Prepared, true))
	}
	for index, step := range spec.Steps {
		number := index + 1
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepStarted, Step: number}); err != nil {
			return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", StepStarted, true))
		}
		evidence, err := adapter.Execute(lease, step, spec.Timeouts.Step)
		if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) {
			return finish(lock, executionStopped("SYSTEM-CHANGES-STEP", StepStarted, false))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepCompleted, Step: number, Evidence: &evidence}); err != nil {
			return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", StepCompleted, false))
		}
	}
	if result := runGate(lease, adapter, spec.Checks, PrePublication, spec.Timeouts.Check); result != nil {
		return finish(lock, *result)
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: PrePublicationHealthPassed}); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed, false))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StatePublicationStarted}); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", StatePublicationStarted, false))
	}
	published, err := transaction.SystemChangesPublish(lease)
	if err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-PUBLICATION", StatePublicationStarted, false))
	}
	agreement, ok := validatedAgreement(lease, published, binding)
	if !ok {
		return finish(lock, executionStopped("SYSTEM-CHANGES-PUBLICATION", StatePublicationStarted, false))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StatePublished}); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", StatePublished, false))
	}
	if result := runGate(lease, adapter, spec.Checks, PostPublication, spec.Timeouts.Check); result != nil {
		return finish(lock, *result)
	}
	if err := adapter.VerifyAgreement(lease, agreement); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-AGREEMENT", StatePublished, false))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: PostPublicationHealthPassed}); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed, false))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: Complete}); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-JOURNAL", Complete, false))
	}
	if err := adapter.Cleanup(lease, spec.Identity); err != nil {
		return finish(lock, executionStopped("SYSTEM-CHANGES-CLEANUP", Complete, false))
	}
	return finish(lock, ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()})
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

func runGate(lease ExecutionLease, adapter TransactionAdapter, checks []Check, phase GatePhase, timeout time.Duration) *ApplyResult {
	for _, check := range checks {
		if check.Phase != phase {
			continue
		}
		status, err := adapter.Check(lease, check, phase, timeout)
		if err != nil || check.Classification == Required && status != Healthy || check.Classification == Advisory && (status == Failed || status == Unknown || status == NeedsAttention && !check.Disclosed) {
			result := executionStopped("SYSTEM-CHANGES-HEALTH", DurableCheckpoint(phase+" health"), false)
			return &result
		}
	}
	return nil
}

func executionStopped(code string, checkpoint DurableCheckpoint, nothingChanged bool) ApplyResult {
	return ApplyResult{
		Outcome: Incomplete, NothingChanged: nothingChanged, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(),
		Finding: &Finding{Code: code, Problem: "The Change Set did not reach durable Complete", Found: string(checkpoint), Required: "automatic rollback or durable cleanup in the next System Changes slice", WhyStopped: "success is never claimed before Complete", NextAction: "Inspect the active Change Set."},
	}
}
