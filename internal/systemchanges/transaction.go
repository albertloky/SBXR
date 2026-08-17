package systemchanges

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
)

// DurableCheckpoint names one recovery-relevant journal boundary.
type DurableCheckpoint string

const (
	Prepared                                      DurableCheckpoint = "Prepared"
	StepStarted                                   DurableCheckpoint = "Step started"
	StepCompleted                                 DurableCheckpoint = "Step completed"
	StateFinalized                                DurableCheckpoint = "Deferred State finalized"
	PrePublicationHealthPassed                    DurableCheckpoint = "Pre-publication health passed"
	OwnedExternalDeletionVerified                 DurableCheckpoint = "Owned external deletion verified"
	IrreversibleRemovalStarted                    DurableCheckpoint = "Irreversible removal started"
	OwnedDNSRecordsDeleted                        DurableCheckpoint = "Owned Cloudflare DNS records deleted"
	OwnedTunnelDeleted                            DurableCheckpoint = "Owned Cloudflare Tunnel deleted"
	ManagementTokenDeletionStarted                DurableCheckpoint = "Cloudflare management token deletion started"
	IrreversibleRunTokenRotationStarted           DurableCheckpoint = "Irreversible run-token rotation started"
	ManagementTokenCandidateIntentPrepared        DurableCheckpoint = "Management-token candidate intent prepared"
	ManagementTokenCandidatePrepared              DurableCheckpoint = "Management-token candidate prepared"
	ManagementTokenCandidateCleanupRequired       DurableCheckpoint = "Management-token candidate cleanup required"
	IrreversibleManagementTokenReplacementStarted DurableCheckpoint = "Irreversible management-token replacement started"
	ManagementTokenRollbackDeleted                DurableCheckpoint = "Management-token Rollback Snapshot deleted"
	IrreversibleCloudflareSetupStarted            DurableCheckpoint = "Irreversible Cloudflare setup started"
	CloudflareSetupRollbackDeleted                DurableCheckpoint = "Cloudflare setup Rollback Snapshot deleted"
	IrreversibleReclamationStarted                DurableCheckpoint = "Irreversible reclamation started"
	ReclamationProcessStopped                     DurableCheckpoint = "Reclamation process stopped"
	ReclamationTargetDeleted                      DurableCheckpoint = "Reclamation target deleted"
	PackageHoldsRemoved                           DurableCheckpoint = "SBXR package holds removed"
	TokenRevocationVerified                       DurableCheckpoint = "Cloudflare management token deletion verified"
	LocalStateDeleted                             DurableCheckpoint = "Local State deleted"
	SecretsDeleted                                DurableCheckpoint = "Infrastructure Secrets deleted"
	CertificatesDeleted                           DurableCheckpoint = "Certificates deleted"
	TransactionMaterialDeletionAuthorized         DurableCheckpoint = "Transaction material deletion authorized"
	TransactionMaterialDeleted                    DurableCheckpoint = "Transaction material deleted"
	ReleasesDeleted                               DurableCheckpoint = "Releases deleted"
	UnitsDeleted                                  DurableCheckpoint = "Units deleted"
	IdentitiesDeleted                             DurableCheckpoint = "Identities deleted"
	ListenersDeleted                              DurableCheckpoint = "Listeners deleted"
	PreparedArtifactsDeleted                      DurableCheckpoint = "Prepared artifacts deleted"
	OwnedFirewallStateDeleted                     DurableCheckpoint = "Owned firewall state deleted"
	FinalRemovalAbsenceVerified                   DurableCheckpoint = "Final removal absence verified"
	StatePublicationStarted                       DurableCheckpoint = "Desired State publication started"
	StatePublished                                DurableCheckpoint = "Desired State published"
	PostPublicationHealthPassed                   DurableCheckpoint = "Post-publication health passed"
	Complete                                      DurableCheckpoint = "Complete"
	CancellationRequested                         DurableCheckpoint = "Cancellation requested"
	RollbackStarted                               DurableCheckpoint = "Rollback started"
	RollbackStepStarted                           DurableCheckpoint = "Rollback step started"
	RollbackStepCompleted                         DurableCheckpoint = "Rollback step completed"
	RollbackVerified                              DurableCheckpoint = "Rollback verified"
	RolledBack                                    DurableCheckpoint = "Rolled back"
)

type CheckpointRecord struct {
	ChangeSet     string
	Checkpoint    DurableCheckpoint
	Step          int
	Evidence      *StepEvidence
	CompletedStep *Step
	State         *StateTransactionBinding
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
	LineageUnavailable     bool                             `json:"lineage_unavailable,omitempty"`
	RawStatePresent        bool                             `json:"raw_state_present,omitempty"`
	StartingRevision       uint64                           `json:"starting_revision"`
	CandidateRevision      uint64                           `json:"candidate_revision"`
	StartingSHA256         string                           `json:"starting_sha256"`
	CandidateSHA256        string                           `json:"candidate_sha256"`
	PreparedStateSHA256    string                           `json:"prepared_state_sha256"`
	PreparedManifestSHA256 string                           `json:"prepared_manifest_sha256"`
	ConnectionProfiles     ConnectionProfilesRuntimeBinding `json:"connection_profiles,omitempty"`
	ChangeSet              string                           `json:"change_set"`
	StartingRelease        ReleaseBinding                   `json:"starting_release"`
	CandidateRelease       ReleaseBinding                   `json:"candidate_release"`
}

// ConnectionProfilesRuntimeBinding identifies the exact reviewed runtime bytes.
type ConnectionProfilesRuntimeBinding struct {
	XraySHA256    string `json:"xray_sha256,omitempty"`
	SingBoxSHA256 string `json:"sing_box_sha256,omitempty"`
}

type Preparation struct {
	ChangeSet          string
	Mutation           MutationClass
	OutcomeOwner       Module
	Starting           StateLineage
	PlanSHA256         string
	State              StateTransactionBinding
	Steps              []Step
	Checks             []Check
	Timeouts           Timeouts
	Reclamation        *ReclamationTarget
	writeState         func(func(name string, mode uint32, source io.Reader) error) error
	sshIdentity        string
	SSHAgreementSHA256 string
}

func (Preparation) String() string   { return "System Changes Preparation: redacted" }
func (Preparation) GoString() string { return "System Changes Preparation: redacted" }
func (Preparation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("System Changes Preparation JSON unavailable")
}

func (preparation Preparation) WriteStateArtifacts(write func(name string, mode uint32, source io.Reader) error) error {
	if preparation.writeState == nil || write == nil {
		return fmt.Errorf("state artifact handoff unavailable")
	}
	return preparation.writeState(write)
}

func (preparation Preparation) WriteSSHPreservation(write func(source io.Reader) error) error {
	if preparation.sshIdentity == "" || write == nil {
		return errors.New("SSH Preservation material unavailable")
	}
	return write(strings.NewReader(preparation.sshIdentity))
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
	Code         string `json:"code"`
	SHA256       string `json:"sha256"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

type StepEffect string

const (
	StepEffectAbsent  StepEffect = "Absent"
	StepEffectPresent StepEffect = "Present"
)

type IrreversibleRemovalPhase string

const (
	CloudflareDNSRecordsPhase                  IrreversibleRemovalPhase = "owned Cloudflare DNS records"
	CloudflareTunnelPhase                      IrreversibleRemovalPhase = "owned Cloudflare Tunnel"
	LocalStatePhase                            IrreversibleRemovalPhase = "local State"
	PackageHoldsPhase                          IrreversibleRemovalPhase = "SBXR package holds"
	SecretsPhase                               IrreversibleRemovalPhase = "Infrastructure Secrets"
	CertificatesPhase                          IrreversibleRemovalPhase = "certificates"
	TransactionMaterialDeletionAuthorizedPhase IrreversibleRemovalPhase = "transaction material deletion authorization"
	TransactionMaterialPhase                   IrreversibleRemovalPhase = "transaction material"
	ReleasesPhase                              IrreversibleRemovalPhase = "releases"
	UnitsPhase                                 IrreversibleRemovalPhase = "units"
	IdentitiesPhase                            IrreversibleRemovalPhase = "identities"
	ListenersPhase                             IrreversibleRemovalPhase = "listeners"
	PreparedArtifactsPhase                     IrreversibleRemovalPhase = "prepared artifacts"
	OwnedFirewallStatePhase                    IrreversibleRemovalPhase = "owned firewall state"
)

var irreversibleRemovalPhases = []struct {
	phase      IrreversibleRemovalPhase
	checkpoint DurableCheckpoint
}{
	{PackageHoldsPhase, PackageHoldsRemoved},
	{LocalStatePhase, LocalStateDeleted},
	{SecretsPhase, SecretsDeleted},
	{CertificatesPhase, CertificatesDeleted},
	{TransactionMaterialDeletionAuthorizedPhase, TransactionMaterialDeletionAuthorized},
	{TransactionMaterialPhase, TransactionMaterialDeleted},
	{ReleasesPhase, ReleasesDeleted},
	{UnitsPhase, UnitsDeleted},
	{IdentitiesPhase, IdentitiesDeleted},
	{ListenersPhase, ListenersDeleted},
	{PreparedArtifactsPhase, PreparedArtifactsDeleted},
	{OwnedFirewallStatePhase, OwnedFirewallStateDeleted},
}

var irreversibleRemoteRemovalPhases = []struct {
	phase      IrreversibleRemovalPhase
	checkpoint DurableCheckpoint
}{
	{CloudflareDNSRecordsPhase, OwnedDNSRecordsDeleted},
	{CloudflareTunnelPhase, OwnedTunnelDeleted},
}

// RecoveryTransaction is the secret-safe durable authority for one interrupted
// ordinary Change Set. Snapshot contents remain inside the Adapter.
type RecoveryTransaction struct {
	ChangeSet                          string
	Mutation                           MutationClass
	Starting                           StateLineage
	StartingRelease                    ReleaseBinding
	Candidate                          StateLineage
	CandidateRelease                   ReleaseBinding
	State                              StateTransactionBinding
	OutcomeOwner                       Module
	Steps                              []Step
	Checks                             []Check
	AttemptedSteps                     int
	RollbackStep                       int
	LastCheckpoint                     DurableCheckpoint
	Timeouts                           Timeouts
	PriorRunTokenSHA256                string
	IrreversibleRemovalStarted         bool
	IrreversibleReclamationStarted     bool
	IrreversibleCloudflareSetupStarted bool
	Reclamation                        *ReclamationTarget
	SSHPreservationSHA256              string
	ManagementTokenID                  string
}

// PendingChangeSet is the secret-safe identity needed to select one recovery
// owner. Journal entries, rollback material, and Adapter details stay private.
type PendingChangeSet struct {
	Identity                          string
	Kind                              MutationClass
	StartingStatus                    InstallationStatus
	StartingRevision                  uint64
	StartingRelease, CandidateRelease ReleaseBinding
	ForwardOnly                       bool
	ForwardFirewallPending            bool
	SSHPreservationTracked            bool
	Checkpoint                        DurableCheckpoint
	CompletedSteps, TotalSteps        int
}

// PendingChangeSetReader is System Changes' read-only startup seam.
type PendingChangeSetReader interface {
	PendingChangeSet() (PendingChangeSet, bool, error)
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

type SSHPreservationAdapter interface {
	VerifySSHPreservation(ExecutionLease, string, string, SSHPreservationPhase, time.Duration) error
}

type RecoverySSHPreservationAdapter interface {
	AppendRecoverySSHPreservation(ExecutionLease, string, string, string) error
}

type SSHPreservationPhase string

const (
	BeforeFirewallReplacement SSHPreservationPhase = "Before firewall replacement"
	AfterFirewallReplacement  SSHPreservationPhase = "After firewall replacement"
)

type RecoveryAdapter interface {
	LoadRecovery(ExecutionLease) (RecoveryTransaction, error)
	HoldServices(ExecutionLease) error
	AllowProvenServices(ExecutionLease, RecoveryTransaction, time.Duration) error
	InspectStep(ExecutionLease, RecoveryTransaction, int, Step, time.Duration) (StepEffect, error)
	RestoreRecoveryState(ExecutionLease, RecoveryTransaction) (RollbackAgreement, error)
	VerifyStartingServices(ExecutionLease, RecoveryTransaction, time.Duration) error
}

type IrreversibleRemovalAdapter interface {
	VerifyIrreversibleRemovalReady(ExecutionLease, string, time.Duration) error
	PrepareCloudflareManagementTokenDeletion(ExecutionLease, RecoveryTransaction, time.Duration) (StepEvidence, error)
	DeleteAndVerifyCloudflareManagementToken(ExecutionLease, RecoveryTransaction, time.Duration) error
	DeleteIrreversibleRemovalPhase(ExecutionLease, RecoveryTransaction, IrreversibleRemovalPhase, time.Duration) (StepEvidence, error)
	VerifyFinalRemovalAbsence(ExecutionLease, RecoveryTransaction, time.Duration) (Observation, error)
	FinalizeRemoval(ExecutionLease, RecoveryTransaction, time.Duration) error
}

// RunTokenRotationAdapter is the narrow durable seam for the one forward-only
// Cloudflare credential transition. State material remains opaque.
type RunTokenRotationAdapter interface {
	StartRunTokenRotation(ExecutionLease, string) (checkpointCrossed bool, err error)
	FinalizeRunTokenRotation(ExecutionLease, RecoveryTransaction, time.Duration) (material any, binding StateTransactionBinding, changed bool, err error)
	LoadRunTokenRotationState(ExecutionLease, RecoveryTransaction) (any, error)
}

type ManagementTokenRotationAdapter interface {
	PrepareManagementTokenRotation(ExecutionLease, string, time.Duration) (cleanupRequired bool, err error)
	RequireManagementTokenCandidateCleanup(ExecutionLease, string) error
	CleanupManagementTokenCandidate(ExecutionLease, string, time.Duration) error
	StartManagementTokenRotation(ExecutionLease, string, time.Duration) (checkpointCrossed bool, err error)
	DeleteManagementTokenRollback(ExecutionLease, string) error
	FinalizeManagementTokenRotation(ExecutionLease, RecoveryTransaction, time.Duration) (material any, binding StateTransactionBinding, evidence StepEvidence, err error)
	LoadManagementTokenRotationState(ExecutionLease, RecoveryTransaction) (any, error)
}

type ForwardReclamationAdapter interface {
	ForwardChangeAdapter
	VerifyReclamationReady(ExecutionLease, string, ReclamationTarget, time.Duration) error
	StopReclamationProcess(ExecutionLease, ReclamationTarget, time.Duration) (StepEvidence, error)
	DeleteReclamationTarget(ExecutionLease, string, ReclamationTarget, time.Duration) (StepEvidence, error)
	InspectReclamationTarget(ExecutionLease, string, ReclamationTarget, time.Duration) (StepEffect, error)
}

type ForwardChangeAdapter interface {
	LoadForwardChangeState(ExecutionLease, RecoveryTransaction) (any, error)
	LoadForwardChangeEvidence(ExecutionLease, RecoveryTransaction) ([]StepEvidence, error)
}

type CloudflareSetupBoundaryAdapter interface {
	ForwardChangeAdapter
	DeleteCloudflareSetupRollback(ExecutionLease, string) error
}

type OrphanedRemovalAdapter interface {
	FinalizeOrphanedRemoval(ExecutionLease, Observation, time.Duration) error
}

type StateRecovery interface {
	SystemChangesRestoreDurable(lease any, binding []byte, prior, candidate io.Reader) ([]byte, error)
	SystemChangesFinalizeRunTokenRotation(lease any, binding []byte, candidate io.Reader, source any) (any, error)
	SystemChangesLoadRunTokenRotation(lease any, binding []byte, candidate, manifests io.Reader) (any, error)
	SystemChangesFinalizeManagementTokenRotation(lease any, binding []byte, candidate io.Reader, source any) (any, error)
	SystemChangesLoadManagementTokenRotation(lease any, binding []byte, candidate, manifests io.Reader) (any, error)
	SystemChangesLoadForwardChange(lease any, binding []byte, candidate, manifests io.Reader) (any, error)
}

var ErrNoRecoveryTransaction = errors.New("no unfinished recovery transaction")

type statePreparedAuthority interface {
	SystemChangesConsume(lease any, planIdentity, planSHA256 string) (any, error)
}

type stateTransaction interface {
	SystemChangesBindings(lease any) ([]byte, error)
	SystemChangesWriteArtifacts(lease any, write func(name string, mode uint32, source io.Reader) error) error
	SystemChangesPublish(lease any) (any, error)
	SystemChangesPublishedAgreement(lease any) (any, error)
	SystemChangesRestore(lease any) ([]byte, error)
	SystemChangesDeferred(lease any) bool
	SystemChangesFinalizeCloudflare(lease any, evidence []byte) ([]byte, error)
}

type DeferredStateAdapter interface {
	ReplaceStateArtifacts(ExecutionLease, string, StateTransactionBinding, func(func(name string, mode uint32, source io.Reader) error) error) error
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
func (step Step) CloudflareChange() (CloudflareChange, bool) {
	return step.cloudflare, step.cloudflare.Action != ""
}
func (step Step) CertificateChange() (CertificateChange, bool) {
	return step.certificate, step.certificate.Action != ""
}

// Recover is the private startup path for unfinished ordinary forward work.
// It never resumes the forward transaction.
func (i Interface) Recover() ApplyResult {
	return i.recover(RecoverySSHIdentityAuthority{}, SSHPreservationAuthority{})
}

// RecoverWithSSHPreservation records one freshly proved direct SSH identity
// for this recovery attempt. Saved recovery material never creates authority.
func (i Interface) RecoverWithSSHPreservation(authority SSHPreservationAuthority) ApplyResult {
	return i.recover(RecoverySSHIdentityAuthority{}, authority)
}

func (i Interface) RecoverWithSSHRecovery(identity RecoverySSHIdentityAuthority, proof SSHPreservationAuthority) ApplyResult {
	return i.recover(identity, proof)
}

func (i Interface) recover(identityAuthority RecoverySSHIdentityAuthority, authority SSHPreservationAuthority) ApplyResult {
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
			return finish(lock, ApplyResult{Outcome: Completed, RestoredStatus: NotInstalled, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), UnremovableTraces: removalLimits()})
		}
		result := refused("SYSTEM-CHANGES-RECOVERY-NOT-NEEDED", "No unfinished Change Set requires restart recovery", "no durable transaction", "the last proven Desired State", "ordinary work is never invented or resumed", "Start only services proven against the current Desired State.", true)
		result.Finding.Owner = StateModule
		return finish(lock, result)
	}
	if err != nil || !validRecoveryTransaction(recovery) {
		return finish(lock, recoveryRequired(ChangeSetSpec{OutcomeOwner: StateModule}, "SYSTEM-CHANGES-RECOVERY-LINEAGE", Prepared))
	}
	recovery.Steps = append([]Step(nil), recovery.Steps...)
	sshIdentity, sshSHA256, freshSSH := authority.consume()
	recoveryIdentity, recoverySHA256, hasRecoveryIdentity := identityAuthority.consume()
	if !hasRecoveryIdentity && freshSSH {
		recoveryIdentity, recoverySHA256, hasRecoveryIdentity = sshIdentity, sshSHA256, true
	}
	if hasRecoveryIdentity {
		appender, ok := i.adapter.(RecoverySSHPreservationAdapter)
		if !ok || appender.AppendRecoverySSHPreservation(lease, recovery.ChangeSet, recoveryIdentity, recoverySHA256) != nil {
			freshSSH = false
		} else if freshSSH && sshSHA256 == recoverySHA256 {
			recovery.SSHPreservationSHA256 = sshSHA256
		} else {
			freshSSH = false
		}
	}
	spec := ChangeSetSpec{Identity: recovery.ChangeSet, Mutation: recovery.Mutation, StartingState: recovery.Starting, OutcomeOwner: recovery.OutcomeOwner, Steps: recovery.Steps, Checks: recovery.Checks, Timeouts: recovery.Timeouts}
	if recovery.Mutation == CompleteRemovalMutation && recovery.IrreversibleRemovalStarted {
		removalAdapter, ok := i.adapter.(IrreversibleRemovalAdapter)
		if !ok {
			return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-ADAPTER", recovery.LastCheckpoint))
		}
		return finish(lock, continueIrreversibleRemoval(lease, adapter, removalAdapter, recovery, spec))
	}
	if recovery.Mutation == RotationMutation && (runTokenRotationCheckpoint(recovery.LastCheckpoint) || managementTokenRotationChange(spec) && (recovery.LastCheckpoint == Prepared || recovery.LastCheckpoint == ManagementTokenCandidateIntentPrepared || recovery.LastCheckpoint == ManagementTokenCandidatePrepared || recovery.LastCheckpoint == ManagementTokenCandidateCleanupRequired)) {
		if managementTokenRotationChange(spec) {
			rotationAdapter, ok := i.adapter.(ManagementTokenRotationAdapter)
			if !ok {
				return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-ADAPTER", recovery.LastCheckpoint))
			}
			if recovery.LastCheckpoint == Prepared || recovery.LastCheckpoint == ManagementTokenCandidateIntentPrepared {
				cleanup, err := rotationAdapter.PrepareManagementTokenRotation(lease, recovery.ChangeSet, recovery.Timeouts.Step)
				if cleanup {
					return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP", ManagementTokenCandidateCleanupRequired))
				}
				if err != nil {
					return finish(lock, rollbackRecovered(lease, adapter, recoveryAdapter, recovery, spec))
				}
				recovery.LastCheckpoint = ManagementTokenCandidatePrepared
			}
			if recovery.LastCheckpoint == ManagementTokenCandidateCleanupRequired {
				if rotationAdapter.CleanupManagementTokenCandidate(lease, recovery.ChangeSet, recovery.Timeouts.Step) != nil {
					return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP", recovery.LastCheckpoint))
				}
				return finish(lock, rollbackRecovered(lease, adapter, recoveryAdapter, recovery, spec))
			}
			if recovery.LastCheckpoint == ManagementTokenCandidatePrepared {
				crossed, err := rotationAdapter.StartManagementTokenRotation(lease, recovery.ChangeSet, recovery.Timeouts.Step)
				if err != nil {
					if crossed {
						return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CHECKPOINT", IrreversibleManagementTokenReplacementStarted))
					}
					if rotationAdapter.RequireManagementTokenCandidateCleanup(lease, recovery.ChangeSet) != nil || rotationAdapter.CleanupManagementTokenCandidate(lease, recovery.ChangeSet, recovery.Timeouts.Step) != nil {
						return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP", ManagementTokenCandidateCleanupRequired))
					}
					return finish(lock, rollbackRecovered(lease, adapter, recoveryAdapter, recovery, spec))
				}
				recovery.LastCheckpoint = IrreversibleManagementTokenReplacementStarted
			}
			return finish(lock, continueManagementTokenRotation(lease, adapter, rotationAdapter, recovery, spec))
		}
		rotationAdapter, ok := i.adapter.(RunTokenRotationAdapter)
		if !ok {
			return finish(lock, forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-ADAPTER", recovery.LastCheckpoint))
		}
		return finish(lock, continueRunTokenRotation(lease, adapter, rotationAdapter, recovery, spec))
	}
	if recovery.Mutation == CloudflareProfileSetupMutation && recovery.IrreversibleCloudflareSetupStarted {
		boundary, ok := i.adapter.(CloudflareSetupBoundaryAdapter)
		if !ok {
			return finish(lock, forwardCloudflareSetupRequired(spec, "SYSTEM-CHANGES-CLOUDFLARE-SETUP-ADAPTER", recovery.LastCheckpoint))
		}
		if recovery.LastCheckpoint == IrreversibleCloudflareSetupStarted {
			if boundary.DeleteCloudflareSetupRollback(lease, recovery.ChangeSet) != nil || adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: CloudflareSetupRollbackDeleted}) != nil {
				return finish(lock, forwardCloudflareSetupRequired(spec, "SYSTEM-CHANGES-CLOUDFLARE-SETUP-SNAPSHOT", IrreversibleCloudflareSetupStarted))
			}
			recovery.LastCheckpoint = CloudflareSetupRollbackDeleted
		}
		return finish(lock, continueForwardChange(lease, adapter, boundary, recovery, spec, freshSSH))
	}
	if recovery.Reclamation != nil && recovery.IrreversibleReclamationStarted {
		forward, ok := i.adapter.(ForwardReclamationAdapter)
		if !ok {
			return finish(lock, forwardReclamationRequired(spec, "SYSTEM-CHANGES-RECLAMATION-ADAPTER", recovery.LastCheckpoint))
		}
		return finish(lock, continueForwardChange(lease, adapter, forward, recovery, spec, freshSSH))
	}
	if err := recoveryAdapter.AllowProvenServices(lease, recovery, recovery.Timeouts.Check); err != nil {
		return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-SERVICE-HOLDBACK", recovery.LastCheckpoint))
	}
	if recovery.LastCheckpoint == Complete {
		if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
			return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete))
		}
		return finish(lock, ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), SSHPreservationSHA256: recovery.SSHPreservationSHA256})
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
	if !safeIdentity(recovery.ChangeSet) || !validMutation(recovery.Mutation) || !validOutcomeOwner(recovery.OutcomeOwner) || len(recovery.Steps) == 0 || recovery.AttemptedSteps < 0 || recovery.AttemptedSteps > len(recovery.Steps) || recovery.Timeouts.Step <= 0 || recovery.Timeouts.Step > maxStepTimeout || recovery.Timeouts.Check <= 0 || recovery.Timeouts.Check > maxCheckTimeout {
		return false
	}
	unprovenRemoval := recovery.State.LineageUnavailable
	if !validRecoveryStateBinding(recovery) {
		return false
	}
	if !unprovenRemoval && (recovery.Starting.Status == Managed || recovery.Starting.Status == RecoveryRequired) && (recovery.Starting.Revision == 0 || !validSHA256(recovery.Starting.SHA256) || recovery.StartingRelease == (ReleaseBinding{})) || recovery.Starting.Status == NotInstalled && (recovery.Starting.Revision != 0 || recovery.Starting.SHA256 != "" || recovery.StartingRelease != (ReleaseBinding{})) || recovery.Starting.Status != Managed && recovery.Starting.Status != RecoveryRequired && recovery.Starting.Status != NotInstalled {
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
	if recovery.Mutation == RotationMutation && runTokenRotationCheckpoint(recovery.LastCheckpoint) {
		spec := ChangeSetSpec{Mutation: recovery.Mutation, Steps: recovery.Steps}
		if managementTokenRotationChange(spec) {
			if !validManagementTokenRotationChecks(recovery.Checks) {
				return false
			}
		} else if !validRunTokenRecoveryChecks(recovery.Checks) {
			return false
		}
	}
	if recovery.Reclamation != nil && (recovery.Mutation != InstallationMutation || recovery.Starting.Status != NotInstalled || !validReclamationTarget(*recovery.Reclamation) || recovery.RollbackStep != 0) {
		return false
	}
	if recovery.IrreversibleReclamationStarted {
		prelude := reclamationPreludeSteps(recovery.Steps)
		if recovery.Reclamation == nil || !irreversibleReclamationCheckpoint(recovery.LastCheckpoint) || recovery.AttemptedSteps < prelude || recovery.AttemptedSteps > len(recovery.Steps) {
			return false
		}
		if (recovery.LastCheckpoint == IrreversibleReclamationStarted || recovery.LastCheckpoint == ReclamationProcessStopped || recovery.LastCheckpoint == ReclamationTargetDeleted) && recovery.AttemptedSteps != prelude {
			return false
		}
	}
	if recovery.IrreversibleRemovalStarted {
		first := firstIrreversibleRemoteRemovalStep(recovery.Steps)
		attempted := first
		if first < 0 {
			attempted = len(recovery.Steps)
		}
		return recovery.Mutation == CompleteRemovalMutation && first != 0 && recovery.AttemptedSteps == attempted && recovery.RollbackStep == 0 && IsIrreversibleRemovalCheckpoint(recovery.LastCheckpoint)
	}
	if recovery.IrreversibleCloudflareSetupStarted {
		if recovery.Mutation != CloudflareProfileSetupMutation || recovery.RollbackStep != 0 || !irreversibleCloudflareSetupCheckpoint(recovery.LastCheckpoint) {
			return false
		}
		switch recovery.LastCheckpoint {
		case IrreversibleCloudflareSetupStarted, CloudflareSetupRollbackDeleted:
			return recovery.AttemptedSteps == 0
		case StateFinalized:
			return recovery.AttemptedSteps >= 0 && recovery.AttemptedSteps <= len(recovery.Steps)
		case StepStarted, StepCompleted, PrePublicationHealthPassed, StatePublicationStarted, StatePublished, PostPublicationHealthPassed:
			return recovery.AttemptedSteps > 0
		case Complete:
			return recovery.AttemptedSteps == len(recovery.Steps)
		}
		return false
	}
	switch recovery.LastCheckpoint {
	case Prepared:
		return recovery.AttemptedSteps == 0
	case IrreversibleRunTokenRotationStarted:
		return recovery.Mutation == RotationMutation && recovery.AttemptedSteps == 0 && validSHA256(recovery.PriorRunTokenSHA256)
	case ManagementTokenCandidateIntentPrepared, ManagementTokenCandidatePrepared, ManagementTokenCandidateCleanupRequired:
		return recovery.Mutation == RotationMutation && recovery.AttemptedSteps == 0 && managementTokenRotationChange(ChangeSetSpec{Mutation: recovery.Mutation, Steps: recovery.Steps})
	case IrreversibleManagementTokenReplacementStarted:
		return recovery.Mutation == RotationMutation && recovery.AttemptedSteps == 0 && managementTokenRotationChange(ChangeSetSpec{Mutation: recovery.Mutation, Steps: recovery.Steps})
	case ManagementTokenRollbackDeleted:
		return recovery.Mutation == RotationMutation && recovery.AttemptedSteps == 1 && managementTokenRotationChange(ChangeSetSpec{Mutation: recovery.Mutation, Steps: recovery.Steps})
	case IrreversibleReclamationStarted, ReclamationProcessStopped, ReclamationTargetDeleted:
		return recovery.IrreversibleReclamationStarted
	case StateFinalized:
		return recovery.Mutation == RotationMutation && recovery.AttemptedSteps == 0 || recovery.Reclamation != nil && !recovery.IrreversibleReclamationStarted && recovery.AttemptedSteps == reclamationPreludeSteps(recovery.Steps)
	case StepStarted, StepCompleted, PrePublicationHealthPassed, StatePublicationStarted, StatePublished, PostPublicationHealthPassed:
		return recovery.AttemptedSteps > 0 && recovery.RollbackStep == 0
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

func irreversibleCloudflareSetupCheckpoint(checkpoint DurableCheckpoint) bool {
	switch checkpoint {
	case IrreversibleCloudflareSetupStarted, CloudflareSetupRollbackDeleted, StateFinalized, StepStarted, StepCompleted, PrePublicationHealthPassed, StatePublicationStarted, StatePublished, PostPublicationHealthPassed, Complete:
		return true
	}
	return false
}

func validRecoveryStateBinding(recovery RecoveryTransaction) bool {
	binding := recovery.State
	if binding.ChangeSet != recovery.ChangeSet || !validSHA256(binding.PreparedStateSHA256) || !validSHA256(binding.PreparedManifestSHA256) {
		return false
	}
	if binding.LineageUnavailable {
		return recovery.Mutation == CompleteRemovalMutation && recovery.Starting.Status == RecoveryRequired && recovery.Starting.Revision == 0 && recovery.Starting.SHA256 == "" && recovery.StartingRelease == (ReleaseBinding{}) && binding.StartingRevision == 0 && binding.CandidateRevision == 0 && binding.StartingSHA256 == "" && binding.CandidateSHA256 == "" && binding.StartingRelease == (ReleaseBinding{}) && binding.CandidateRelease == (ReleaseBinding{})
	}
	return binding.StartingRevision == recovery.Starting.Revision && binding.StartingSHA256 == recovery.Starting.SHA256 && binding.StartingRelease == recovery.StartingRelease && binding.CandidateRevision == binding.StartingRevision+1 && validSHA256(binding.CandidateSHA256) && binding.CandidateRelease != (ReleaseBinding{}) && recovery.Candidate.Revision == binding.CandidateRevision && recovery.Candidate.SHA256 == binding.CandidateSHA256 && recovery.CandidateRelease == binding.CandidateRelease
}

func validRunTokenRecoveryChecks(checks []Check) bool {
	if len(checks) != 2 {
		return false
	}
	for index, phase := range []GatePhase{PrePublication, PostPublication} {
		check := checks[index]
		if !validCheck(check) || check.Owner != CloudflareModule || check.Phase != phase || check.Classification != Required || check.Status != Healthy || check.Code != "CLOUDFLARE-WHOLE-TUNNEL" {
			return false
		}
	}
	return true
}

func validManagementTokenRotationChecks(checks []Check) bool {
	if len(checks) != 2 {
		return false
	}
	for index, phase := range []GatePhase{PrePublication, PostPublication} {
		check := checks[index]
		if !validCheck(check) || check.Owner != CloudflareModule || check.Phase != phase || check.Classification != Required || check.Status != Healthy || check.Code != "CLOUDFLARE-MANAGEMENT-TOKEN-REPLACED" {
			return false
		}
	}
	return true
}

func runTokenRotationCheckpoint(checkpoint DurableCheckpoint) bool {
	switch checkpoint {
	case IrreversibleRunTokenRotationStarted, ManagementTokenCandidatePrepared, ManagementTokenCandidateCleanupRequired, IrreversibleManagementTokenReplacementStarted, ManagementTokenRollbackDeleted, StateFinalized, StepStarted, StepCompleted, PrePublicationHealthPassed, StatePublicationStarted, StatePublished, PostPublicationHealthPassed, Complete:
		return true
	}
	return false
}

func managementTokenRotationChange(spec ChangeSetSpec) bool {
	if spec.Mutation != RotationMutation || len(spec.Steps) != 1 {
		return false
	}
	change, ok := spec.Steps[0].CloudflareChange()
	return ok && change.Action == CloudflareManagementTokenActivate
}

func continueManagementTokenRotation(lease ExecutionLease, adapter TransactionAdapter, rotation ManagementTokenRotationAdapter, recovery RecoveryTransaction, spec ChangeSetSpec) ApplyResult {
	record := func(point DurableCheckpoint, step int, evidence *StepEvidence, binding *StateTransactionBinding) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: point, Step: step, Evidence: evidence, State: binding}) == nil
	}
	var transaction stateTransaction
	if recovery.LastCheckpoint == Complete {
		if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete)
		}
		return ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}
	}
	if recovery.LastCheckpoint == IrreversibleManagementTokenReplacementStarted {
		material, binding, evidence, err := rotation.FinalizeManagementTokenRotation(lease, recovery, recovery.Timeouts.Step)
		var ok bool
		transaction, ok = material.(stateTransaction)
		if err != nil || !ok || binding.ChangeSet != recovery.ChangeSet || binding.StartingRevision != recovery.Starting.Revision || binding.CandidateRevision != recovery.Candidate.Revision || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !record(StateFinalized, 0, nil, &binding) || !record(StepStarted, 1, nil, nil) || !record(StepCompleted, 1, &evidence, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-FINALIZE", recovery.LastCheckpoint)
		}
		recovery.LastCheckpoint = StepCompleted
		recovery.Candidate.SHA256 = binding.CandidateSHA256
		recovery.State = binding
	} else {
		material, err := rotation.LoadManagementTokenRotationState(lease, recovery)
		var ok bool
		transaction, ok = material.(stateTransaction)
		if err != nil || !ok {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-STATE", recovery.LastCheckpoint)
		}
	}
	if recovery.LastCheckpoint == StateFinalized {
		change, _ := recovery.Steps[0].CloudflareChange()
		digest := sha256.Sum256([]byte("management-token-revoked\x00" + change.ManagementTokenID))
		evidence := StepEvidence{Code: "cloudflare-management-token-revoked", SHA256: hex.EncodeToString(digest[:]), ResourceID: change.ManagementTokenID}
		if !record(StepStarted, 1, nil, nil) || !record(StepCompleted, 1, &evidence, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-JOURNAL", StateFinalized)
		}
		recovery.LastCheckpoint = StepCompleted
	}
	if recovery.LastCheckpoint == StepCompleted {
		if rotation.DeleteManagementTokenRollback(lease, recovery.ChangeSet) != nil || !record(ManagementTokenRollbackDeleted, 0, nil, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-SNAPSHOT", StepCompleted)
		}
		recovery.LastCheckpoint = ManagementTokenRollbackDeleted
	}
	if recovery.LastCheckpoint == ManagementTokenRollbackDeleted {
		if !gatePassed(lease, adapter, spec.Checks, PrePublication, recovery.Timeouts.Check) || !record(PrePublicationHealthPassed, 0, nil, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-HEALTH", StepCompleted)
		}
		recovery.LastCheckpoint = PrePublicationHealthPassed
	}
	if recovery.LastCheckpoint == PrePublicationHealthPassed {
		if !record(StatePublicationStarted, 0, nil, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed)
		}
		recovery.LastCheckpoint = StatePublicationStarted
	}
	published, err := transaction.SystemChangesPublish(lease)
	agreement, ok := validatedAgreement(lease, published, recovery.State)
	if err != nil || !ok {
		return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-PUBLICATION", recovery.LastCheckpoint)
	}
	if recovery.LastCheckpoint == StatePublicationStarted {
		if !record(StatePublished, 0, nil, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-JOURNAL", StatePublicationStarted)
		}
		recovery.LastCheckpoint = StatePublished
	}
	if recovery.LastCheckpoint == StatePublished {
		if !gatePassed(lease, adapter, spec.Checks, PostPublication, recovery.Timeouts.Check) || adapter.VerifyAgreement(lease, agreement, recovery.Timeouts.Check) != nil || !record(PostPublicationHealthPassed, 0, nil, nil) {
			return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-AGREEMENT", StatePublished)
		}
		recovery.LastCheckpoint = PostPublicationHealthPassed
	}
	if recovery.LastCheckpoint == PostPublicationHealthPassed && !record(Complete, 0, nil, nil) {
		return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed)
	}
	if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
		return forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete)
	}
	return ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}
}

func forwardManagementTokenRotationRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-FORWARD-MANAGEMENT-TOKEN-ROTATION", Owner: spec.OutcomeOwner, Problem: "management-token rotation must continue forward", Found: string(checkpoint), Required: "resume the exact candidate and publish its protected authority", WhyStopped: cause, NextAction: "Retry the private recovery runner."}}
}

func continueRunTokenRotation(lease ExecutionLease, adapter TransactionAdapter, rotation RunTokenRotationAdapter, recovery RecoveryTransaction, spec ChangeSetSpec) ApplyResult {
	record := func(point DurableCheckpoint, step int, evidence *StepEvidence, binding *StateTransactionBinding) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: point, Step: step, Evidence: evidence, State: binding}) == nil
	}
	var transaction stateTransaction
	if recovery.LastCheckpoint == Complete {
		if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete)
		}
		return ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}
	}
	if recovery.LastCheckpoint == IrreversibleRunTokenRotationStarted {
		material, binding, changed, err := rotation.FinalizeRunTokenRotation(lease, recovery, recovery.Timeouts.Step)
		if err != nil {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-FETCH", recovery.LastCheckpoint)
		}
		if !changed {
			return ApplyResult{Outcome: AwaitingRunTokenRotation, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}
		}
		var ok bool
		transaction, ok = material.(stateTransaction)
		if !ok || binding.ChangeSet != recovery.ChangeSet || binding.StartingRevision != recovery.Starting.Revision || binding.CandidateRevision != recovery.Candidate.Revision || !record(StateFinalized, 0, nil, &binding) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-STATE", StateFinalized)
		}
		recovery.LastCheckpoint = StateFinalized
		recovery.Candidate.SHA256 = binding.CandidateSHA256
		recovery.State = binding
	} else {
		material, err := rotation.LoadRunTokenRotationState(lease, recovery)
		var ok bool
		transaction, ok = material.(stateTransaction)
		if err != nil || !ok {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-STATE", recovery.LastCheckpoint)
		}
	}
	step := recovery.Steps[0]
	if recovery.LastCheckpoint == StateFinalized || recovery.LastCheckpoint == StepStarted {
		if recovery.LastCheckpoint == StateFinalized && !record(StepStarted, 1, nil, nil) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-JOURNAL", StepStarted)
		}
		evidence, err := adapter.Execute(lease, recovery.ChangeSet, 1, step, recovery.Timeouts.Step, nil)
		if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !record(StepCompleted, 1, &evidence, nil) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-RESTART", StepStarted)
		}
		recovery.LastCheckpoint = StepCompleted
	}
	if recovery.LastCheckpoint == StepCompleted {
		if !gatePassed(lease, adapter, spec.Checks, PrePublication, recovery.Timeouts.Check) || !record(PrePublicationHealthPassed, 0, nil, nil) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-HEALTH", StepCompleted)
		}
		recovery.LastCheckpoint = PrePublicationHealthPassed
	}
	if recovery.LastCheckpoint == PrePublicationHealthPassed {
		if !record(StatePublicationStarted, 0, nil, nil) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed)
		}
		recovery.LastCheckpoint = StatePublicationStarted
	}
	var agreement Agreement
	if recovery.LastCheckpoint == StatePublicationStarted {
		published, err := transaction.SystemChangesPublish(lease)
		var ok bool
		agreement, ok = validatedAgreement(lease, published, recovery.State)
		if err != nil || !ok || !record(StatePublished, 0, nil, nil) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-PUBLICATION", StatePublicationStarted)
		}
		recovery.LastCheckpoint = StatePublished
	} else {
		published, err := transaction.SystemChangesPublish(lease)
		var ok bool
		agreement, ok = validatedAgreement(lease, published, recovery.State)
		if err != nil || !ok {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-PUBLICATION", recovery.LastCheckpoint)
		}
	}
	if recovery.LastCheckpoint == StatePublished {
		if !gatePassed(lease, adapter, spec.Checks, PostPublication, recovery.Timeouts.Check) || adapter.VerifyAgreement(lease, agreement, recovery.Timeouts.Check) != nil || !record(PostPublicationHealthPassed, 0, nil, nil) {
			return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-AGREEMENT", StatePublished)
		}
		recovery.LastCheckpoint = PostPublicationHealthPassed
	}
	if recovery.LastCheckpoint == PostPublicationHealthPassed && !record(Complete, 0, nil, nil) {
		return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed)
	}
	if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
		return forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete)
	}
	return ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}
}

func forwardRunTokenRotationRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-FORWARD-RUN-TOKEN-ROTATION", Owner: spec.OutcomeOwner, Problem: "Tunnel run-token rotation must continue forward", Found: string(checkpoint), Required: "resume the exact next unproved phase with the new protected token", WhyStopped: cause, NextAction: "Keep cloudflared stopped if it cannot be proved and retry the private recovery runner."}}
}

func irreversibleReclamationCheckpoint(checkpoint DurableCheckpoint) bool {
	switch checkpoint {
	case IrreversibleReclamationStarted, ReclamationProcessStopped, ReclamationTargetDeleted, StateFinalized, StepStarted, StepCompleted, PrePublicationHealthPassed, StatePublicationStarted, StatePublished, PostPublicationHealthPassed, Complete:
		return true
	}
	return false
}

func reclamationPreludeSteps(steps []Step) int {
	count := 0
	for _, step := range steps {
		if step.Owner() != CloudflareModule || step.Forward() == ActivatePreparedConfiguration {
			break
		}
		count++
	}
	return count
}

func finalizeDeferredState(lease ExecutionLease, adapter TransactionAdapter, transaction stateTransaction, changeSet string, binding StateTransactionBinding, evidence []StepEvidence, attempted int) (StateTransactionBinding, string, DurableCheckpoint, bool) {
	deferred, ok := adapter.(DeferredStateAdapter)
	evidenceJSON, marshalErr := json.Marshal(evidence)
	bindingJSON, finalizeErr := transaction.SystemChangesFinalizeCloudflare(lease, evidenceJSON)
	var final StateTransactionBinding
	if !ok || marshalErr != nil || finalizeErr != nil || json.Unmarshal(bindingJSON, &final) != nil || final.ChangeSet != binding.ChangeSet || final.StartingRevision != binding.StartingRevision || final.CandidateRevision != binding.CandidateRevision || final.StartingSHA256 != binding.StartingSHA256 {
		return StateTransactionBinding{}, "SYSTEM-CHANGES-STATE-FINALIZATION", StepCompleted, false
	}
	if deferred.ReplaceStateArtifacts(lease, changeSet, final, func(write func(name string, mode uint32, source io.Reader) error) error {
		return transaction.SystemChangesWriteArtifacts(lease, write)
	}) != nil {
		return StateTransactionBinding{}, "SYSTEM-CHANGES-STATE-FINALIZATION", StepCompleted, false
	}
	if adapter.Record(lease, CheckpointRecord{ChangeSet: changeSet, Checkpoint: StateFinalized, Step: attempted, State: &final}) != nil {
		return StateTransactionBinding{}, "SYSTEM-CHANGES-JOURNAL", StateFinalized, false
	}
	return final, "", "", true
}

func continueForwardChange(lease ExecutionLease, adapter TransactionAdapter, forward ForwardChangeAdapter, recovery RecoveryTransaction, spec ChangeSetSpec, freshSSH bool) ApplyResult {
	failure := func(cause string, checkpoint DurableCheckpoint) ApplyResult {
		if recovery.Mutation == CloudflareProfileSetupMutation {
			return forwardCloudflareSetupRequired(spec, cause, checkpoint)
		}
		return forwardReclamationRequired(spec, cause, checkpoint)
	}
	record := func(point DurableCheckpoint, step int, evidence *StepEvidence) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: point, Step: step, Evidence: evidence}) == nil
	}
	if recovery.LastCheckpoint == Complete {
		if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
			return failure("SYSTEM-CHANGES-CLEANUP", Complete)
		}
		return ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}
	}
	material, err := forward.LoadForwardChangeState(lease, recovery)
	transaction, ok := material.(stateTransaction)
	if err != nil || !ok {
		return failure("SYSTEM-CHANGES-FORWARD-STATE", recovery.LastCheckpoint)
	}
	evidenceByStep, err := forward.LoadForwardChangeEvidence(lease, recovery)
	if err != nil || len(evidenceByStep) != len(recovery.Steps) {
		return failure("SYSTEM-CHANGES-FORWARD-EVIDENCE", recovery.LastCheckpoint)
	}
	finalizeState := func(attempted int) *ApplyResult {
		if !transaction.SystemChangesDeferred(lease) || recovery.LastCheckpoint == StateFinalized {
			return nil
		}
		binding, cause, checkpoint, ok := finalizeDeferredState(lease, adapter, transaction, recovery.ChangeSet, recovery.State, evidenceByStep, attempted)
		if !ok {
			result := failure(cause, checkpoint)
			return &result
		}
		recovery.State, recovery.LastCheckpoint = binding, StateFinalized
		return nil
	}
	if recovery.LastCheckpoint == IrreversibleReclamationStarted {
		reclamation, ok := forward.(ForwardReclamationAdapter)
		if !ok {
			return failure("SYSTEM-CHANGES-RECLAMATION-ADAPTER", recovery.LastCheckpoint)
		}
		evidence, err := reclamation.StopReclamationProcess(lease, *recovery.Reclamation, recovery.Timeouts.Step)
		if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !record(ReclamationProcessStopped, recovery.AttemptedSteps, &evidence) {
			return failure("SYSTEM-CHANGES-RECLAMATION-PROCESS", IrreversibleReclamationStarted)
		}
		recovery.LastCheckpoint = ReclamationProcessStopped
	}
	if recovery.LastCheckpoint == ReclamationProcessStopped {
		reclamation, ok := forward.(ForwardReclamationAdapter)
		if !ok {
			return failure("SYSTEM-CHANGES-RECLAMATION-ADAPTER", recovery.LastCheckpoint)
		}
		effect, err := reclamation.InspectReclamationTarget(lease, recovery.ChangeSet, *recovery.Reclamation, recovery.Timeouts.Check)
		if err != nil {
			return failure("SYSTEM-CHANGES-RECLAMATION-INSPECTION", ReclamationProcessStopped)
		}
		var evidence StepEvidence
		if effect == StepEffectPresent {
			evidence, err = reclamation.DeleteReclamationTarget(lease, recovery.ChangeSet, *recovery.Reclamation, recovery.Timeouts.Step)
		} else if effect == StepEffectAbsent {
			digest := sha256.Sum256([]byte(recovery.Reclamation.Kind + "\x00" + recovery.Reclamation.Path + "\x00" + recovery.Reclamation.SHA256))
			evidence = StepEvidence{Code: "reclamation-target-deleted", SHA256: hex.EncodeToString(digest[:])}
		} else {
			err = errors.New("unknown reclamation target effect")
		}
		if err != nil || !record(ReclamationTargetDeleted, recovery.AttemptedSteps, &evidence) {
			return failure("SYSTEM-CHANGES-RECLAMATION-DELETE", IrreversibleReclamationStarted)
		}
		recovery.LastCheckpoint = ReclamationTargetDeleted
	}
	if recovery.LastCheckpoint == ReclamationTargetDeleted || recovery.LastCheckpoint == CloudflareSetupRollbackDeleted || recovery.LastCheckpoint == StepStarted || recovery.LastCheckpoint == StepCompleted || recovery.LastCheckpoint == StateFinalized {
		next := recovery.AttemptedSteps + 1
		if recovery.LastCheckpoint == StepStarted {
			next = recovery.AttemptedSteps
		}
		for number := next; number <= len(recovery.Steps); number++ {
			step := recovery.Steps[number-1]
			if step.Owner() == CloudflareModule && step.Forward() == ActivatePreparedConfiguration {
				if result := finalizeState(number - 1); result != nil {
					return *result
				}
			}
			sshAdapter, hasSSHAdapter := adapter.(SSHPreservationAdapter)
			if isFirewallReplacement(step) && (!freshSSH || !hasSSHAdapter || sshAdapter.VerifySSHPreservation(lease, recovery.ChangeSet, recovery.SSHPreservationSHA256, BeforeFirewallReplacement, recovery.Timeouts.Check) != nil) {
				return failure("SYSTEM-CHANGES-SSH-PRESERVATION", recovery.LastCheckpoint)
			}
			if !(recovery.LastCheckpoint == StepStarted && number == recovery.AttemptedSteps) && !record(StepStarted, number, nil) {
				return failure("SYSTEM-CHANGES-JOURNAL", StepStarted)
			}
			evidence, err := adapter.Execute(lease, recovery.ChangeSet, number, step, recovery.Timeouts.Step, nil)
			if err == nil && isFirewallReplacement(step) {
				err = sshAdapter.VerifySSHPreservation(lease, recovery.ChangeSet, recovery.SSHPreservationSHA256, AfterFirewallReplacement, recovery.Timeouts.Check)
			}
			if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !validCloudflareEvidence(step, number, evidence, evidenceByStep) || adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: StepCompleted, Step: number, Evidence: &evidence, CompletedStep: &step}) != nil {
				return failure("SYSTEM-CHANGES-FORWARD-STEP", StepStarted)
			}
			evidenceByStep[number-1] = evidence
			recovery.LastCheckpoint, recovery.AttemptedSteps = StepCompleted, number
		}
		if result := finalizeState(len(recovery.Steps)); result != nil {
			return *result
		}
		if !gatePassed(lease, adapter, recovery.Checks, PrePublication, recovery.Timeouts.Check) || !record(PrePublicationHealthPassed, 0, nil) {
			return failure("SYSTEM-CHANGES-FORWARD-HEALTH", StepCompleted)
		}
		recovery.LastCheckpoint = PrePublicationHealthPassed
	}
	if recovery.LastCheckpoint == PrePublicationHealthPassed {
		if !record(StatePublicationStarted, 0, nil) {
			return failure("SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed)
		}
		recovery.LastCheckpoint = StatePublicationStarted
	}
	var published any
	if recovery.LastCheckpoint == StatePublicationStarted {
		published, err = transaction.SystemChangesPublish(lease)
	} else {
		published, err = transaction.SystemChangesPublishedAgreement(lease)
	}
	agreement, agreementOK := validatedAgreement(lease, published, recovery.State)
	if err != nil || !agreementOK {
		return failure("SYSTEM-CHANGES-FORWARD-PUBLICATION", recovery.LastCheckpoint)
	}
	if recovery.LastCheckpoint == StatePublicationStarted {
		if !record(StatePublished, 0, nil) {
			return failure("SYSTEM-CHANGES-JOURNAL", StatePublicationStarted)
		}
		recovery.LastCheckpoint = StatePublished
	}
	if recovery.LastCheckpoint == StatePublished {
		if !gatePassed(lease, adapter, recovery.Checks, PostPublication, recovery.Timeouts.Check) || adapter.VerifyAgreement(lease, agreement, recovery.Timeouts.Check) != nil || !record(PostPublicationHealthPassed, 0, nil) {
			return failure("SYSTEM-CHANGES-FORWARD-AGREEMENT", StatePublished)
		}
		recovery.LastCheckpoint = PostPublicationHealthPassed
	}
	if recovery.LastCheckpoint == PostPublicationHealthPassed && !record(Complete, 0, nil) {
		return failure("SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed)
	}
	if adapter.Cleanup(lease, recovery.ChangeSet) != nil {
		return failure("SYSTEM-CHANGES-CLEANUP", Complete)
	}
	return ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), SSHPreservationSHA256: recovery.SSHPreservationSHA256}
}

func NextIrreversibleRemovalCheckpoint(checkpoint DurableCheckpoint) (DurableCheckpoint, bool) {
	if checkpoint == IrreversibleRemovalStarted {
		return OwnedDNSRecordsDeleted, true
	}
	if checkpoint == OwnedDNSRecordsDeleted {
		return OwnedTunnelDeleted, true
	}
	if checkpoint == OwnedTunnelDeleted {
		return OwnedExternalDeletionVerified, true
	}
	if checkpoint == OwnedExternalDeletionVerified {
		return ManagementTokenDeletionStarted, true
	}
	if checkpoint == ManagementTokenDeletionStarted {
		return TokenRevocationVerified, true
	}
	if checkpoint == TokenRevocationVerified {
		return irreversibleRemovalPhases[0].checkpoint, true
	}
	for index, item := range irreversibleRemovalPhases {
		if checkpoint != item.checkpoint {
			continue
		}
		if index+1 < len(irreversibleRemovalPhases) {
			return irreversibleRemovalPhases[index+1].checkpoint, true
		}
		return FinalRemovalAbsenceVerified, true
	}
	return "", checkpoint == FinalRemovalAbsenceVerified
}

func IsIrreversibleRemovalCheckpoint(checkpoint DurableCheckpoint) bool {
	if checkpoint == IrreversibleRemovalStarted {
		return true
	}
	_, ok := NextIrreversibleRemovalCheckpoint(checkpoint)
	return ok
}

func continueIrreversibleRemoval(lease ExecutionLease, adapter TransactionAdapter, removal IrreversibleRemovalAdapter, recovery RecoveryTransaction, spec ChangeSetSpec) ApplyResult {
	record := func(checkpoint DurableCheckpoint, step int, evidence *StepEvidence) bool {
		return adapter.Record(lease, CheckpointRecord{ChangeSet: recovery.ChangeSet, Checkpoint: checkpoint, Step: step, Evidence: evidence}) == nil
	}
	first := firstIrreversibleRemoteRemovalStep(recovery.Steps)
	if first >= 0 {
		remoteStart := 0
		for index, item := range irreversibleRemoteRemovalPhases {
			if recovery.LastCheckpoint == item.checkpoint {
				remoteStart = index + 1
			}
		}
		if recovery.LastCheckpoint != OwnedExternalDeletionVerified && recovery.LastCheckpoint != ManagementTokenDeletionStarted && recovery.LastCheckpoint != TokenRevocationVerified && !slicesContainRemovalCheckpoint(irreversibleRemovalPhases, recovery.LastCheckpoint) && recovery.LastCheckpoint != FinalRemovalAbsenceVerified {
			for _, item := range irreversibleRemoteRemovalPhases[remoteStart:] {
				evidence, err := removal.DeleteIrreversibleRemovalPhase(lease, recovery, item.phase, recovery.Timeouts.Step)
				if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) {
					return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-FORWARD", recovery.LastCheckpoint)
				}
				if !record(item.checkpoint, 0, &evidence) {
					return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", recovery.LastCheckpoint)
				}
				recovery.LastCheckpoint = item.checkpoint
			}
			if !record(OwnedExternalDeletionVerified, 0, nil) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", recovery.LastCheckpoint)
			}
			recovery.LastCheckpoint = OwnedExternalDeletionVerified
		}
		if recovery.LastCheckpoint == OwnedExternalDeletionVerified {
			evidence, err := removal.PrepareCloudflareManagementTokenDeletion(lease, recovery, recovery.Timeouts.Check)
			if err != nil || !validManagementTokenDeletionEvidence(evidence) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-TOKEN-IDENTITY", IrreversibleRemovalStarted)
			}
			if !record(ManagementTokenDeletionStarted, 0, &evidence) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", IrreversibleRemovalStarted)
			}
			recovery.LastCheckpoint = ManagementTokenDeletionStarted
			recovery.ManagementTokenID = evidence.ResourceID
		}
		if recovery.LastCheckpoint == ManagementTokenDeletionStarted {
			if err := removal.DeleteAndVerifyCloudflareManagementToken(lease, recovery, recovery.Timeouts.Check); err != nil {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-TOKEN-DELETION", IrreversibleRemovalStarted)
			}
			if !record(TokenRevocationVerified, 0, nil) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", IrreversibleRemovalStarted)
			}
			recovery.LastCheckpoint = TokenRevocationVerified
		}
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
			if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-FORWARD", recovery.LastCheckpoint)
			}
			if !record(item.checkpoint, 0, &evidence) {
				return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", recovery.LastCheckpoint)
			}
			recovery.LastCheckpoint = item.checkpoint
		}
		observed, err := removal.VerifyFinalRemovalAbsence(lease, recovery, recovery.Timeouts.Check)
		if err != nil || !validObservation(observed) || observed.Status != NotInstalled {
			return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-ABSENCE", recovery.LastCheckpoint)
		}
		if !record(FinalRemovalAbsenceVerified, 0, nil) {
			return forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", recovery.LastCheckpoint)
		}
		recovery.LastCheckpoint = FinalRemovalAbsenceVerified
	}
	if err := removal.FinalizeRemoval(lease, recovery, recovery.Timeouts.Step); err != nil {
		return forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-FINALIZE", FinalRemovalAbsenceVerified)
	}
	return ApplyResult{Outcome: Completed, RestoredStatus: NotInstalled, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), UnremovableTraces: removalLimits()}
}

func removalLimits() []string {
	return []string{"Certificate Transparency entries cannot be erased", "DNS caches cannot be erased"}
}

func firstIrreversibleRemoteRemovalStep(steps []Step) int {
	for index, step := range steps {
		change, ok := step.RemovalChange()
		if ok && change.Action == CloudflareRemoval && (change.Resource == CloudflareDNSRecordResource || change.Resource == CloudflareTunnelResource) {
			return index
		}
	}
	return -1
}

func slicesContainRemovalCheckpoint(phases []struct {
	phase      IrreversibleRemovalPhase
	checkpoint DurableCheckpoint
}, checkpoint DurableCheckpoint) bool {
	for _, phase := range phases {
		if phase.checkpoint == checkpoint {
			return true
		}
	}
	return false
}

func validManagementTokenDeletionEvidence(evidence StepEvidence) bool {
	digest := sha256.Sum256([]byte(evidence.ResourceID))
	return safeIdentity(evidence.Code) && validSHA256(evidence.SHA256) && evidence.ResourceType == "cloudflare-management-token" && safeIdentity(evidence.ResourceID) && evidence.SHA256 == hex.EncodeToString(digest[:])
}

func forwardRemovalRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{Outcome: RemovalForwardOnly, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-FORWARD-REMOVAL", Owner: spec.OutcomeOwner, Problem: "Irreversible Complete removal must continue forward", Found: string(checkpoint), Required: "retry the exact next durable deletion from protected evidence", WhyStopped: cause, NextAction: "Keep services stopped and retry the private recovery runner."}}
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
	return ApplyResult{Outcome: RollbackSucceeded, RestoredStatus: restored, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), SSHPreservationSHA256: recovery.SSHPreservationSHA256, Finding: &Finding{Code: "SYSTEM-CHANGES-ROLLED-BACK-AFTER-RESTART", Owner: recovery.OutcomeOwner, Problem: "The interrupted Change Set was rolled back from durable evidence", Found: string(recovery.LastCheckpoint), Required: "the prior proven installation status", WhyStopped: "SYSTEM-CHANGES-RESTART", NextAction: "Start only services proven against the restored Desired State."}}
}

func (i Interface) applyPrepared(lock Lock, spec ChangeSetSpec, cancellation *Cancellation) ApplyResult {
	adapter, ok := i.adapter.(TransactionAdapter)
	if !ok {
		return finish(lock, refused("SYSTEM-CHANGES-TRANSACTION-ADAPTER", "Durable transaction execution is unavailable", "the Adapter has no transaction capability", "one protected durable transaction Adapter", "live work cannot start without recovery material", "Restore the Adapter and create a fresh Plan.", true))
	}
	sshIdentity, sshSHA256, sshProtected := spec.SSHPreservation.consume()
	spec.sshPreservationSHA256 = sshSHA256
	needsSSHProtection := (spec.Mutation == InstallationMutation || spec.Mutation == SettingChangeMutation || spec.Mutation == CloudflareProfileSetupMutation) && containsFirewallStep(spec.Steps)
	sshAdapter, hasSSHAdapter := adapter.(SSHPreservationAdapter)
	if needsSSHProtection && (!sshProtected || !hasSSHAdapter) {
		return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-SSH-PRESERVATION", Prepared))
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
	var reclamation *ReclamationTarget
	if spec.Reclamation != nil {
		if cloudflareAuthority, ok := spec.Reclamation.(interface {
			SystemChangesCloudflareReclamation() (string, []string, []string, []string, [][]string, bool)
			SystemChangesCloudflareReclamationAvailable() bool
		}); ok && cloudflareAuthority.SystemChangesCloudflareReclamationAvailable() {
			review, kinds, ids, names, routeRows, valid := cloudflareAuthority.SystemChangesCloudflareReclamation()
			target := ReclamationTarget{Kind: "cloudflare", ReviewSHA256: review, PolicyVersion: 1, Cloudflare: &CloudflareReclamationTarget{}}
			if !valid || len(kinds) == 0 || len(ids) != len(kinds) || len(names) != len(kinds) || len(routeRows) != len(kinds) {
				return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
			}
			for index := range kinds {
				conflict := CloudflareReclamationConflict{Kind: kinds[index], ID: ids[index], Name: names[index]}
				for _, row := range routeRows[index] {
					hostname, origin, found := strings.Cut(row, "\x00")
					if !found {
						return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
					}
					conflict.Routes = append(conflict.Routes, CloudflareRoute{Hostname: hostname, Origin: origin})
				}
				target.Cloudflare.Conflicts = append(target.Cloudflare.Conflicts, conflict)
			}
			if !validReclamationTarget(target) {
				return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
			}
			reclamation = &target
		} else {
			dockerReview, service, executable, executableSHA256, dockerPID, firewallSHA256, firewallObjects, dockerPackages, dockerVersions, controlSHA256, dockerOwnedPaths, runtimePackages, runtimeVersions, runtimeOwnedPaths, preserved, preservedPaths, preservedSHA256, dockerValid := "", "", "", "", "", "", []string(nil), []string(nil), []string(nil), []string(nil), [][]string(nil), []string(nil), []string(nil), [][]string(nil), []string(nil), []string(nil), []string(nil), false
			if dockerAuthority, ok := spec.Reclamation.(interface {
				SystemChangesDockerReclamation() (string, string, string, string, string, string, []string, []string, []string, []string, [][]string, []string, []string, [][]string, []string, []string, []string, bool)
				SystemChangesDockerReclamationAvailable() bool
			}); ok && dockerAuthority.SystemChangesDockerReclamationAvailable() {
				dockerReview, service, executable, executableSHA256, dockerPID, firewallSHA256, firewallObjects, dockerPackages, dockerVersions, controlSHA256, dockerOwnedPaths, runtimePackages, runtimeVersions, runtimeOwnedPaths, preserved, preservedPaths, preservedSHA256, dockerValid = dockerAuthority.SystemChangesDockerReclamation()
			}
			if dockerValid {
				target := ReclamationTarget{Kind: "docker", ReviewSHA256: dockerReview, PolicyVersion: 1, Docker: &DockerReclamationTarget{Service: service, Executable: executable, ExecutableSHA256: executableSHA256, ProcessID: dockerPID, FirewallSHA256: firewallSHA256, FirewallObjects: append([]string(nil), firewallObjects...), PreservedData: append([]string(nil), preserved...), PreservedPaths: append([]string(nil), preservedPaths...), PreservedSHA256: append([]string(nil), preservedSHA256...)}}
				for index := range runtimePackages {
					if index >= len(runtimeVersions) || index >= len(runtimeOwnedPaths) {
						return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
					}
					target.Docker.RuntimePackages = append(target.Docker.RuntimePackages, ReclamationPackageTarget{Package: runtimePackages[index], PackageVersion: runtimeVersions[index], OwnedPaths: append([]string(nil), runtimeOwnedPaths[index]...)})
				}
				for index := range dockerPackages {
					if index >= len(dockerVersions) || index >= len(controlSHA256) || index >= len(dockerOwnedPaths) {
						return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
					}
					target.Packages = append(target.Packages, ReclamationPackageTarget{Package: dockerPackages[index], PackageVersion: dockerVersions[index], ControlSHA256: controlSHA256[index], OwnedPaths: append([]string(nil), dockerOwnedPaths[index]...)})
				}
				if !validReclamationTarget(target) {
					return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
				}
				reclamation = &target
			} else if firewallAuthority, ok := spec.Reclamation.(interface {
				SystemChangesFirewallReclamation() (string, string, string, string, string, string, string, string, string, string, []string, []string, bool)
				SystemChangesFirewallReclamationAvailable() bool
			}); ok && firewallAuthority.SystemChangesFirewallReclamationAvailable() {
				review, manager, prior, outbound, candidate, service, listener, session, keysPath, keys, objects, outboundObjects, valid := firewallAuthority.SystemChangesFirewallReclamation()
				target := ReclamationTarget{Kind: "firewall", ReviewSHA256: review, PolicyVersion: 1, Firewall: &FirewallReclamationTarget{Manager: manager, PriorSHA256: prior, OutboundSHA256: outbound, Candidate: candidate, Service: service, Listener: listener, SessionSHA256: session, AuthorizedKeysPath: keysPath, AuthorizedKeysSHA256: keys, Objects: append([]string(nil), objects...), OutboundObjects: append([]string(nil), outboundObjects...)}}
				if !valid || !validReclamationTarget(target) {
					return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
				}
				reclamation = &target
			} else {
				policyVersion, review, kinds, paths, digests, interpreters, processIDs, packages, packageVersions, ownedPaths, identityNames, identityKinds, valid := spec.Reclamation.SystemChangesReclamation()
				if !valid || len(kinds) == 0 || len(paths) != len(kinds) || len(digests) != len(kinds) || len(interpreters) != len(kinds) || len(processIDs) != len(kinds) || len(packages) != len(kinds) || len(packageVersions) != len(kinds) || len(ownedPaths) != len(kinds) || len(identityNames) != len(kinds) || len(identityKinds) != len(kinds) {
					return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
				}
				identities := func(index int) []ReclamationIdentity {
					if len(identityNames[index]) != len(identityKinds[index]) {
						return nil
					}
					result := make([]ReclamationIdentity, len(identityNames[index]))
					for identity := range result {
						result[identity] = ReclamationIdentity{Name: identityNames[index][identity], Kind: identityKinds[index][identity]}
					}
					return result
				}
				target := ReclamationTarget{Kind: kinds[0], Path: paths[0], SHA256: digests[0], Interpreter: interpreters[0], ProcessID: processIDs[0], ReviewSHA256: review, Package: packages[0], PackageVersion: packageVersions[0], PolicyVersion: policyVersion, Identities: identities(0)}
				if len(kinds) > 1 {
					target = ReclamationTarget{Kind: "package-purge-set", ReviewSHA256: review, PolicyVersion: policyVersion}
					for index := range kinds {
						if kinds[index] != "package-purge" {
							return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
						}
						target.Packages = append(target.Packages, ReclamationPackageTarget{Path: paths[index], SHA256: digests[index], ProcessID: processIDs[index], Package: packages[index], PackageVersion: packageVersions[index], OwnedPaths: append([]string(nil), ownedPaths[index]...), Identities: identities(index)})
					}
				} else if len(ownedPaths) == 1 {
					target.OwnedPaths = append([]string(nil), ownedPaths[0]...)
				}
				if !validReclamationTarget(target) {
					return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-RECLAMATION-STALE", Prepared))
				}
				reclamation = &target
			}
		}
	}
	if !needsSSHProtection {
		sshIdentity, sshSHA256, sshProtected = "", "", false
	}
	preparation := Preparation{
		ChangeSet: spec.Identity, Mutation: spec.Mutation, OutcomeOwner: spec.OutcomeOwner, Starting: spec.StartingState,
		PlanSHA256: spec.Plan.SHA256, State: binding,
		Steps: append([]Step(nil), spec.Steps...), Checks: append([]Check(nil), spec.Checks...), Timeouts: spec.Timeouts, Reclamation: reclamation,
		sshIdentity: sshIdentity, SSHAgreementSHA256: sshSHA256,
		writeState: func(write func(name string, mode uint32, source io.Reader) error) error {
			return transaction.SystemChangesWriteArtifacts(lease, write)
		},
	}
	if err := adapter.Prepare(lease, preparation); err != nil {
		return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-PREPARATION", Prepared))
	}
	irreversibleReclamation := false
	irreversibleCloudflareSetup := false
	var reclamationForward ForwardReclamationAdapter
	if reclamation != nil {
		var ok bool
		reclamationForward, ok = adapter.(ForwardReclamationAdapter)
		if !ok {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-RECLAMATION-ADAPTER", Prepared))
		}
	}
	if managementTokenRotationChange(spec) {
		rotation, ok := adapter.(ManagementTokenRotationAdapter)
		if !ok {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-ADAPTER", Prepared))
		}
		cleanup, err := rotation.PrepareManagementTokenRotation(lease, spec.Identity, spec.Timeouts.Step)
		if cleanup {
			return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP", ManagementTokenCandidateCleanupRequired))
		}
		if err != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-PREPARATION", Prepared))
		}
		if cancellation.Requested() {
			if rotation.RequireManagementTokenCandidateCleanup(lease, spec.Identity) != nil {
				return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP-CHECKPOINT", ManagementTokenCandidatePrepared))
			}
			if rotation.CleanupManagementTokenCandidate(lease, spec.Identity, spec.Timeouts.Step) != nil {
				return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP", ManagementTokenCandidateCleanupRequired))
			}
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, 0))
		}
		crossed, err := rotation.StartManagementTokenRotation(lease, spec.Identity, spec.Timeouts.Step)
		if err != nil {
			if crossed {
				return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CHECKPOINT", IrreversibleManagementTokenReplacementStarted))
			}
			if rotation.RequireManagementTokenCandidateCleanup(lease, spec.Identity) != nil || rotation.CleanupManagementTokenCandidate(lease, spec.Identity, spec.Timeouts.Step) != nil {
				return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CLEANUP", ManagementTokenCandidateCleanupRequired))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-CHECKPOINT", Prepared))
		}
		recoveryAdapter, ok := adapter.(RecoveryAdapter)
		if !ok {
			return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-RECOVERY", IrreversibleManagementTokenReplacementStarted))
		}
		recovery, err := recoveryAdapter.LoadRecovery(lease)
		if err != nil || !validRecoveryTransaction(recovery) {
			return finish(lock, forwardManagementTokenRotationRequired(spec, "SYSTEM-CHANGES-MANAGEMENT-TOKEN-RECOVERY", IrreversibleManagementTokenReplacementStarted))
		}
		return finish(lock, continueManagementTokenRotation(lease, adapter, rotation, recovery, spec), spec.OutcomeOwner)
	}
	if runTokenRotationChange(spec) {
		rotation, ok := adapter.(RunTokenRotationAdapter)
		if !ok {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-RUN-TOKEN-ADAPTER", Prepared))
		}
		if cancellation.Requested() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, 0))
		}
		crossed, err := rotation.StartRunTokenRotation(lease, spec.Identity)
		if err != nil {
			if crossed {
				return finish(lock, forwardRunTokenRotationRequired(spec, "SYSTEM-CHANGES-RUN-TOKEN-CHECKPOINT", IrreversibleRunTokenRotationStarted))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-RUN-TOKEN-CHECKPOINT", Prepared))
		}
		return finish(lock, ApplyResult{Outcome: AwaitingRunTokenRotation, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence()}, spec.OutcomeOwner)
	}
	if spec.Mutation == CloudflareProfileSetupMutation {
		boundary, ok := adapter.(CloudflareSetupBoundaryAdapter)
		if !ok {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-CLOUDFLARE-SETUP-ADAPTER", Prepared))
		}
		confirmed := spec.CloudflareSetupConfirmation(CloudflareSetupConfirmationRequest{ChangeSet: spec.Identity, StartingRevision: spec.StartingState.Revision})
		if cancellation.Requested() || !confirmed {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, 0))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: IrreversibleCloudflareSetupStarted}); err != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-CLOUDFLARE-SETUP-CHECKPOINT", Prepared))
		}
		irreversibleCloudflareSetup = true
		if boundary.DeleteCloudflareSetupRollback(lease, spec.Identity) != nil {
			return finish(lock, forwardCloudflareSetupRequired(spec, "SYSTEM-CHANGES-CLOUDFLARE-SETUP-SNAPSHOT", IrreversibleCloudflareSetupStarted))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: CloudflareSetupRollbackDeleted}); err != nil {
			return finish(lock, forwardCloudflareSetupRequired(spec, "SYSTEM-CHANGES-CLOUDFLARE-SETUP-JOURNAL", IrreversibleCloudflareSetupStarted))
		}
	}
	forwardOnly := func() bool { return irreversibleReclamation || irreversibleCloudflareSetup }
	forwardFailure := func(cause string, checkpoint DurableCheckpoint) ApplyResult {
		if irreversibleCloudflareSetup {
			return forwardCloudflareSetupRequired(spec, cause, checkpoint)
		}
		return forwardReclamationRequired(spec, cause, checkpoint)
	}
	evidenceByStep := make([]StepEvidence, len(spec.Steps))
	finalized := false
	finalizeState := func(attempted int) *ApplyResult {
		if finalized || !transaction.SystemChangesDeferred(lease) {
			return nil
		}
		finalBinding, cause, checkpoint, ok := finalizeDeferredState(lease, adapter, transaction, spec.Identity, binding, evidenceByStep, attempted)
		if !ok {
			if forwardOnly() {
				result := finish(lock, forwardFailure(cause, checkpoint))
				return &result
			}
			result := finish(lock, rollbackChange(lease, adapter, transaction, spec, attempted, cause, checkpoint))
			return &result
		}
		binding = finalBinding
		finalized = true
		return nil
	}
	irreversibleRemoval := false
	attemptedSteps := len(spec.Steps)
	reclamationBoundary := 0
	if reclamation != nil {
		reclamationBoundary = reclamationPreludeSteps(spec.Steps)
		if reclamation.Kind == "cloudflare" {
			reclamationBoundary = 0
		}
		if reclamationBoundary < 0 || reclamationBoundary >= attemptedSteps || reclamation.Kind != "cloudflare" && reclamationBoundary < 1 {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-RECLAMATION-STEPS", Prepared))
		}
	}
	if spec.Mutation == CompleteRemovalMutation {
		firstRemote := firstIrreversibleRemoteRemovalStep(spec.Steps)
		if firstRemote == 0 {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, 0, "SYSTEM-CHANGES-REMOVAL-STEPS", Prepared))
		}
		if firstRemote > 0 {
			attemptedSteps = firstRemote
		}
	}
	for index, step := range spec.Steps[:attemptedSteps] {
		if cancellation.Requested() && !irreversibleRemoval && !forwardOnly() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, index))
		}
		if reclamation != nil && index == reclamationBoundary {
			if reclamation.Kind != "cloudflare" {
				if result := finalizeState(index); result != nil {
					return *result
				}
			}
			if cancellation.Requested() {
				return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, index))
			}
			if reclamationForward.VerifyReclamationReady(lease, spec.Identity, *reclamation, spec.Timeouts.Check) != nil {
				return finish(lock, rollbackChange(lease, adapter, transaction, spec, index, "SYSTEM-CHANGES-RECLAMATION-RECHECK", StateFinalized))
			}
			if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: IrreversibleReclamationStarted, Step: index}); err != nil {
				return finish(lock, rollbackChange(lease, adapter, transaction, spec, index, "SYSTEM-CHANGES-RECLAMATION-CHECKPOINT", StateFinalized))
			}
			irreversibleReclamation = true
			processEvidence, err := reclamationForward.StopReclamationProcess(lease, *reclamation, spec.Timeouts.Step)
			if err != nil || !safeIdentity(processEvidence.Code) || !validSHA256(processEvidence.SHA256) || adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: ReclamationProcessStopped, Step: index, Evidence: &processEvidence}) != nil {
				return finish(lock, forwardReclamationRequired(spec, "SYSTEM-CHANGES-RECLAMATION-PROCESS", IrreversibleReclamationStarted))
			}
			evidence, err := reclamationForward.DeleteReclamationTarget(lease, spec.Identity, *reclamation, spec.Timeouts.Step)
			if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: ReclamationTargetDeleted, Step: index, Evidence: &evidence}) != nil {
				return finish(lock, forwardReclamationRequired(spec, "SYSTEM-CHANGES-RECLAMATION-DELETE", IrreversibleReclamationStarted))
			}
		}
		number := index + 1
		if step.Owner() == CloudflareModule && step.Forward() == ActivatePreparedConfiguration {
			if result := finalizeState(index); result != nil {
				return *result
			}
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepStarted, Step: number}); err != nil {
			if forwardOnly() {
				return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", StepStarted))
			}
			if irreversibleRemoval {
				return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", StepStarted))
			}
			return finish(lock, nothingChanged(spec, "SYSTEM-CHANGES-JOURNAL", StepStarted))
		}
		if isFirewallReplacement(step) && needsSSHProtection && sshAdapter.VerifySSHPreservation(lease, spec.Identity, sshSHA256, BeforeFirewallReplacement, spec.Timeouts.Check) != nil {
			if forwardOnly() {
				return finish(lock, forwardFailure("SYSTEM-CHANGES-SSH-PRESERVATION", StepStarted))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, index, "SYSTEM-CHANGES-SSH-PRESERVATION", StepStarted))
		}
		executionCancellation := cancellation
		if forwardOnly() {
			executionCancellation = nil
		}
		evidence, err := adapter.Execute(lease, spec.Identity, number, step, spec.Timeouts.Step, executionCancellation)
		if err == nil {
			if isFirewallReplacement(step) && needsSSHProtection {
				err = sshAdapter.VerifySSHPreservation(lease, spec.Identity, sshSHA256, AfterFirewallReplacement, spec.Timeouts.Check)
			}
		}
		if err != nil || !safeIdentity(evidence.Code) || !validSHA256(evidence.SHA256) || !validCloudflareEvidence(step, number, evidence, evidenceByStep) {
			if irreversibleRemoval || forwardOnly() {
				if forwardOnly() {
					return finish(lock, forwardFailure("SYSTEM-CHANGES-FORWARD-STEP", StepStarted))
				}
				return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-CLOUDFLARE-DELETION", StepStarted))
			}
			if cancellation.Requested() {
				return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, number))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, number, "SYSTEM-CHANGES-STEP", StepStarted))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StepCompleted, Step: number, Evidence: &evidence, CompletedStep: &step}); err != nil {
			if irreversibleRemoval || forwardOnly() {
				if forwardOnly() {
					return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", StepCompleted))
				}
				return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", StepCompleted))
			}
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, number, "SYSTEM-CHANGES-JOURNAL", StepStarted))
		}
		evidenceByStep[index] = evidence
		if cancellation.Requested() && !irreversibleRemoval && !forwardOnly() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, number))
		}
	}
	if cancellation.Requested() && !irreversibleRemoval && !forwardOnly() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, attemptedSteps))
	}
	if result := finalizeState(attemptedSteps); result != nil {
		return *result
	}
	if !gatePassed(lease, adapter, spec.Checks, PrePublication, spec.Timeouts.Check) {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-FORWARD-HEALTH", StepCompleted))
		}
		if irreversibleRemoval {
			return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-REMOVAL-HEALTH", StepCompleted))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, attemptedSteps, "SYSTEM-CHANGES-HEALTH", DurableCheckpoint(PrePublication+" health")))
	}
	if cancellation.Requested() && !irreversibleRemoval && !forwardOnly() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, attemptedSteps))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: PrePublicationHealthPassed}); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed))
		}
		if irreversibleRemoval {
			return finish(lock, forwardRemovalRequired(spec, "SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, attemptedSteps, "SYSTEM-CHANGES-JOURNAL", StepCompleted))
	}
	if spec.Mutation == CompleteRemovalMutation {
		if cancellation.Requested() {
			return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, attemptedSteps))
		}
		removal, ok := adapter.(IrreversibleRemovalAdapter)
		if !ok || removal.VerifyIrreversibleRemovalReady(lease, spec.Identity, spec.Timeouts.Check) != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, attemptedSteps, "SYSTEM-CHANGES-REMOVAL-READINESS", PrePublicationHealthPassed))
		}
		if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: IrreversibleRemovalStarted}); err != nil {
			return finish(lock, rollbackChange(lease, adapter, transaction, spec, attemptedSteps, "SYSTEM-CHANGES-REMOVAL-CHECKPOINT", PrePublicationHealthPassed))
		}
		irreversibleRemoval = true
		recovery := RecoveryTransaction{ChangeSet: spec.Identity, Mutation: spec.Mutation, Starting: spec.StartingState, StartingRelease: binding.StartingRelease, Candidate: StateLineage{Status: Managed, Revision: binding.CandidateRevision, SHA256: binding.CandidateSHA256}, CandidateRelease: binding.CandidateRelease, State: binding, OutcomeOwner: spec.OutcomeOwner, Steps: append([]Step(nil), spec.Steps...), Checks: append([]Check(nil), spec.Checks...), AttemptedSteps: attemptedSteps, LastCheckpoint: IrreversibleRemovalStarted, Timeouts: spec.Timeouts, IrreversibleRemovalStarted: true}
		return finish(lock, continueIrreversibleRemoval(lease, adapter, removal, recovery, spec), spec.OutcomeOwner)
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StatePublicationStarted}); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", PrePublicationHealthPassed))
	}
	if cancellation.Requested() && !forwardOnly() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	published, err := transaction.SystemChangesPublish(lease)
	if err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-FORWARD-PUBLICATION", StatePublicationStarted))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-PUBLICATION", StatePublicationStarted))
	}
	agreement, ok := validatedAgreement(lease, published, binding)
	if !ok {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-FORWARD-PUBLICATION", StatePublicationStarted))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-PUBLICATION", StatePublicationStarted))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: StatePublished}); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", StatePublicationStarted))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", StatePublicationStarted))
	}
	if cancellation.Requested() && !forwardOnly() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if !gatePassed(lease, adapter, spec.Checks, PostPublication, spec.Timeouts.Check) {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-FORWARD-HEALTH", StatePublished))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-HEALTH", DurableCheckpoint(PostPublication+" health")))
	}
	if cancellation.Requested() && !forwardOnly() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if err := adapter.VerifyAgreement(lease, agreement, spec.Timeouts.Check); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-FORWARD-AGREEMENT", StatePublished))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-AGREEMENT", StatePublished))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: PostPublicationHealthPassed}); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", StatePublished))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", StatePublished))
	}
	if cancellation.Requested() && !forwardOnly() {
		return finish(lock, cancelAndRollback(lease, adapter, transaction, spec, len(spec.Steps)))
	}
	if err := adapter.Record(lease, CheckpointRecord{ChangeSet: spec.Identity, Checkpoint: Complete}); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed))
		}
		return finish(lock, rollbackChange(lease, adapter, transaction, spec, len(spec.Steps), "SYSTEM-CHANGES-JOURNAL", PostPublicationHealthPassed))
	}
	if err := adapter.Cleanup(lease, spec.Identity); err != nil {
		if forwardOnly() {
			return finish(lock, forwardFailure("SYSTEM-CHANGES-CLEANUP", Complete))
		}
		return finish(lock, recoveryRequired(spec, "SYSTEM-CHANGES-CLEANUP", Complete))
	}
	return finish(lock, ApplyResult{Outcome: Completed, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), SSHPreservationSHA256: spec.sshPreservationSHA256}, spec.OutcomeOwner)
}

func containsFirewallStep(steps []Step) bool {
	for _, step := range steps {
		if isFirewallReplacement(step) {
			return true
		}
	}
	return false
}

func isFirewallReplacement(step Step) bool {
	change, ok := step.FirewallChange()
	return ok && change.Action == FirewallPolicyAction
}

func forwardReclamationRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-FORWARD-RECLAMATION", Owner: spec.OutcomeOwner, Problem: "Irreversible reclamation must continue forward to Managed", Found: string(checkpoint), Required: "resume the exact next unproved installation effect from protected evidence", WhyStopped: cause, NextAction: "Keep affected services stopped and retry the private recovery runner."}}
}

func forwardCloudflareSetupRequired(spec ChangeSetSpec, cause string, checkpoint DurableCheckpoint) ApplyResult {
	return ApplyResult{Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-FORWARD-CLOUDFLARE-SETUP", Owner: spec.OutcomeOwner, Problem: "Irreversible Cloudflare Profile Setup must continue forward to Managed", Found: string(checkpoint), Required: "resume the exact next unproved setup effect from protected evidence", WhyStopped: cause, NextAction: "Keep affected services stopped and retry the private recovery runner."}}
}

func runTokenRotationChange(spec ChangeSetSpec) bool {
	return spec.Mutation == RotationMutation && len(spec.Steps) == 1 && spec.Steps[0].forward == RotateCloudflaredRunToken
}

func validCloudflareEvidence(step Step, number int, evidence StepEvidence, prior []StepEvidence) bool {
	change, cloudflare := step.CloudflareChange()
	if !cloudflare {
		return evidence.ResourceType == "" && evidence.ResourceID == ""
	}
	if change.TunnelIDFromStep > 0 {
		index := change.TunnelIDFromStep - 1
		if change.TunnelIDFromStep >= number || index >= len(prior) || prior[index].ResourceType != string(CloudflareTunnelResource) || !safeIdentity(prior[index].ResourceID) {
			return false
		}
	}
	switch change.Action {
	case CloudflareTunnelCreate:
		return evidence.ResourceType == string(CloudflareTunnelResource) && safeIdentity(evidence.ResourceID)
	case CloudflareDNSDelete:
		return evidence.ResourceType == string(CloudflareDNSRecordResource) && evidence.ResourceID == change.DNSRecordID
	case CloudflareDNSCreate, CloudflareDNSRepair:
		return evidence.ResourceType == string(CloudflareDNSRecordResource) && safeIdentity(evidence.ResourceID)
	case CloudflareRoutesDelete:
		return evidence.ResourceType == string(CloudflareRouteResource) && evidence.ResourceID == change.TunnelID
	case CloudflareRoutesPut:
		return evidence.ResourceType == string(CloudflareRouteResource) && safeIdentity(evidence.ResourceID)
	case CloudflareTunnelDelete:
		return evidence.ResourceType == string(CloudflareTunnelResource) && evidence.ResourceID == change.TunnelID
	case CloudflaredActivate:
		return evidence.ResourceType == "" && evidence.ResourceID == ""
	case CloudflareRunTokenActivate:
		return evidence.ResourceType == "" && evidence.ResourceID == ""
	case CloudflareManagementTokenActivate:
		return evidence.ResourceType == "" && evidence.ResourceID == change.ManagementTokenID
	}
	return false
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
		SSHPreservationSHA256: spec.sshPreservationSHA256,
		Finding:               &Finding{Code: "SYSTEM-CHANGES-ROLLED-BACK", Owner: spec.OutcomeOwner, Problem: "The Change Set stopped and its exact baseline was restored", Found: string(checkpoint), Required: "the prior proven installation status", WhyStopped: cause, NextAction: "Inspect the restored baseline and create a fresh Plan."},
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
	unproven := spec.Mutation == CompleteRemovalMutation && spec.StartingState.Status == RecoveryRequired && spec.StartingState.Revision == 0 && spec.StartingState.SHA256 == ""
	if unproven {
		return binding, binding.LineageUnavailable && binding.ChangeSet == spec.Identity && binding.StartingRevision == 0 && binding.CandidateRevision == 0 && binding.StartingSHA256 == "" && binding.CandidateSHA256 == "" && binding.StartingRelease == (ReleaseBinding{}) && binding.CandidateRelease == (ReleaseBinding{})
	}
	return binding, !binding.LineageUnavailable && binding.ChangeSet == spec.Identity && binding.StartingRevision == spec.StartingState.Revision && binding.CandidateRevision == binding.StartingRevision+1 && binding.CandidateSHA256 == spec.TargetStateSHA256 && (binding.StartingSHA256 == spec.StartingState.SHA256 || spec.StartingState.Status == NotInstalled && binding.StartingSHA256 == "")
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
