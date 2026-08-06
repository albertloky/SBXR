// Package systemchanges owns SBXR's single installation-wide mutation boundary.
package systemchanges

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

type InstallationStatus string

const (
	NotInstalled     InstallationStatus = "Not installed"
	Managed          InstallationStatus = "Managed"
	ChangeInProgress InstallationStatus = "Change in progress"
	RecoveryRequired InstallationStatus = "Recovery Required"
)

type Checkpoint string

const (
	NoCheckpoint       Checkpoint = "None"
	PreparedCheckpoint Checkpoint = "Prepared"
)

type LockState string

const (
	LockReleased LockState = "Released"
	LockHeld     LockState = "Held"
)

type Action string

const (
	InspectAction         Action = "Inspect"
	ApplyAction           Action = "Apply"
	RetryRollbackAction   Action = "Retry automatic rollback"
	DiagnosticsAction     Action = "Read-only diagnostics"
	ForwardRepairAction   Action = "Create forward-repair Plan"
	CheckAgainAction      Action = "Check again"
	BackAction            Action = "Back"
	CompleteRemovalAction Action = "Complete removal"
)

type RecoveryCause string

const (
	StateLineageUnprovable      RecoveryCause = "Current State lineage unprovable"
	SnapshotUnprovable          RecoveryCause = "Rollback Snapshot integrity unprovable"
	JournalUnprovable           RecoveryCause = "Recovery journal integrity unprovable"
	ForwardCheckpointUnprovable RecoveryCause = "Forward checkpoint unprovable"
	RollbackStepUnprovable      RecoveryCause = "Rollback step unprovable"
	PriorAgreementUnprovable    RecoveryCause = "Prior-State agreement unprovable"
	CurrentStateDrift           RecoveryCause = "Valid current State has drift"
	MissingSecrets              RecoveryCause = "Required secrets are missing"
	ReplacementVPS              RecoveryCause = "VPS is replaced or unavailable"
	OlderRevision               RecoveryCause = "An older completed revision was requested"
	OwnerRegret                 RecoveryCause = "Owner requested a prior configuration"
)

type Observation struct {
	Status                 InstallationStatus
	CurrentChangeSet       string
	LastChangeSet          string
	Checkpoint             Checkpoint
	CompletedSteps         int
	TotalSteps             int
	Lock                   LockState
	RollbackAvailable      bool
	ForwardRepairAvailable bool
	RecoveryCause          RecoveryCause
	StateRevision          uint64
	StateSHA256            string
	VolatileSHA256         string
	FilesystemBytes        uint64
	AvailableBytes         uint64
	WallTimeSynchronized   bool
	MonotonicClock         bool
	TimeOwner              string
}

type Inspection struct {
	Status                 InstallationStatus `json:"status"`
	CurrentChangeSet       string             `json:"current_change_set,omitempty"`
	LastChangeSet          string             `json:"last_change_set,omitempty"`
	Checkpoint             Checkpoint         `json:"checkpoint"`
	CompletedSteps         int                `json:"completed_steps"`
	TotalSteps             int                `json:"total_steps"`
	Lock                   LockState          `json:"lock"`
	RollbackAvailable      bool               `json:"rollback_available"`
	ForwardRepairAvailable bool               `json:"forward_repair_available"`
	RecoveryCause          RecoveryCause      `json:"recovery_cause,omitempty"`
	AllowedActions         []Action           `json:"allowed_actions"`
	Correction             *Correction        `json:"correction,omitempty"`
	ActivityPolicies       []ActivityPolicy   `json:"activity_policies"`
	Findings               []Finding          `json:"findings,omitempty"`
}

type Correction struct {
	Source            CorrectionSource `json:"source"`
	SBXROption        Action           `json:"sbxr_option,omitempty"`
	FreshPlanRequired bool             `json:"fresh_plan_required"`
	OwnerWorkPlan     []string         `json:"owner_work_plan,omitempty"`
	CheckAgain        string           `json:"check_again"`
	Back              string           `json:"back"`
}

type CorrectionSource string

const (
	SBXROwnedCorrection CorrectionSource = "SBXR-owned correction"
	ExternalCorrection  CorrectionSource = "External or Owner-controlled fault"
)

type Activity string

const (
	ScheduledHealthActivity     Activity = "Scheduled health check"
	UpdateDiscoveryActivity     Activity = "Update discovery"
	ReleaseVerificationActivity Activity = "Release verification"
	CertificateRenewalActivity  Activity = "Automatic certificate renewal"
)

type ActivityDecision string

const (
	ActivityAllowed           ActivityDecision = "Allowed"
	ActivityDeferred          ActivityDecision = "Deferred"
	ActivityDeferredAndReplan ActivityDecision = "Deferred; rebuild observations and Plan"
)

type ActivityPolicy struct {
	Activity Activity         `json:"activity"`
	Decision ActivityDecision `json:"decision"`
}

type Finding struct {
	Code       string `json:"code"`
	Owner      Module `json:"owner,omitempty"`
	Problem    string `json:"problem"`
	Found      string `json:"found"`
	Required   string `json:"required"`
	WhyStopped string `json:"why_stopped"`
	NextAction string `json:"next_action"`
}

func (finding *Finding) Error() string {
	return fmt.Sprintf("%s: %s; found %s; required %s; %s; next: %s", finding.Code, finding.Problem, finding.Found, finding.Required, finding.WhyStopped, finding.NextAction)
}

type Lock interface{ Close() error }

type Adapter interface {
	Observe() (Observation, error)
	TryLock() (Lock, bool, error)
}

type Interface struct{ adapter Adapter }

func New(adapter Adapter) Interface { return Interface{adapter: adapter} }

type Cancellation struct{ requested atomic.Bool }

func NewCancellation() *Cancellation { return &Cancellation{} }
func (c *Cancellation) Request() {
	if c != nil {
		c.requested.Store(true)
	}
}
func (c *Cancellation) Requested() bool { return c != nil && c.requested.Load() }

func (i Interface) Inspect() Inspection {
	if i.adapter == nil {
		return recoveryInspection(Finding{Code: "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE", Problem: "System Changes inspection is unavailable", Found: "no Ubuntu host Adapter", Required: "one read-only Ubuntu host Adapter", WhyStopped: "transaction safety cannot be proven", NextAction: "Restore the Adapter and check again."})
	}
	observed, err := i.adapter.Observe()
	if err != nil || !validObservation(observed) {
		return recoveryInspection(Finding{Code: "SYSTEM-CHANGES-INSPECTION-UNPROVABLE", Problem: "Transaction status cannot be proven", Found: "incomplete or inconsistent typed facts", Required: "one exact State lineage, checkpoint, progress, and kernel-lock observation", WhyStopped: "SBXR never guesses transaction ownership or progress", NextAction: "Use the Recovery Required flow."})
	}
	return Inspection{
		Status: observed.Status, CurrentChangeSet: observed.CurrentChangeSet, LastChangeSet: observed.LastChangeSet,
		Checkpoint: observed.Checkpoint, CompletedSteps: observed.CompletedSteps, TotalSteps: observed.TotalSteps,
		Lock: observed.Lock, RollbackAvailable: observed.RollbackAvailable, ForwardRepairAvailable: observed.ForwardRepairAvailable, RecoveryCause: observed.RecoveryCause,
		AllowedActions: allowedActions(observed), Correction: recoveryCorrection(observed), ActivityPolicies: activityPolicies(observed.Status, observed.Lock),
	}
}

func (i Interface) CheckAgain() Inspection { return i.Inspect() }

func (i Interface) RetryAutomaticRollback() ApplyResult {
	inspection := i.Inspect()
	if inspection.Status != RecoveryRequired || !inspection.RollbackAvailable {
		return refused("SYSTEM-CHANGES-ROLLBACK-NOT-AVAILABLE", "Automatic rollback is not available", string(inspection.RecoveryCause), "valid unfinished transaction material", "recovery never invents or selects rollback material", "Use a safe action offered by Inspect or go Back.", false)
	}
	return i.Recover()
}

func validObservation(observed Observation) bool {
	if observed.Status != NotInstalled && observed.Status != Managed && observed.Status != ChangeInProgress && observed.Status != RecoveryRequired || observed.Lock != LockReleased && observed.Lock != LockHeld || observed.CompletedSteps < 0 || observed.TotalSteps < observed.CompletedSteps || observed.RollbackAvailable && observed.ForwardRepairAvailable {
		return false
	}
	if observed.CurrentChangeSet != "" && !safeIdentity(observed.CurrentChangeSet) || observed.LastChangeSet != "" && !safeIdentity(observed.LastChangeSet) || observed.Checkpoint != NoCheckpoint && observed.Checkpoint != PreparedCheckpoint {
		return false
	}
	if observed.Status == ChangeInProgress && observed.CurrentChangeSet == "" || observed.Status == Managed && observed.LastChangeSet == "" || observed.Status == NotInstalled && (observed.CurrentChangeSet != "" || observed.LastChangeSet != "" || observed.RollbackAvailable) {
		return false
	}
	if (observed.Status == NotInstalled || observed.Status == Managed) && (observed.Checkpoint != NoCheckpoint || observed.CompletedSteps != 0 || observed.TotalSteps != 0) || (observed.Status == ChangeInProgress || observed.Status == RecoveryRequired) && observed.CurrentChangeSet != "" && (observed.Checkpoint == NoCheckpoint || observed.TotalSteps == 0) {
		return false
	}
	if observed.Status != RecoveryRequired {
		return observed.RecoveryCause == "" && !observed.ForwardRepairAvailable
	}
	if !validRecoveryCause(observed.RecoveryCause) || observed.RollbackAvailable && (!rollbackEligibleCause(observed.RecoveryCause) || observed.CurrentChangeSet == "" || observed.Checkpoint != PreparedCheckpoint || observed.TotalSteps == 0) {
		return false
	}
	if observed.ForwardRepairAvailable {
		return observed.RecoveryCause == CurrentStateDrift && observed.CurrentChangeSet == "" && observed.LastChangeSet != "" && observed.Checkpoint == NoCheckpoint && observed.TotalSteps == 0 && observed.StateRevision > 0 && validSHA256(observed.StateSHA256)
	}
	return observed.RecoveryCause != CurrentStateDrift
}

func rollbackEligibleCause(cause RecoveryCause) bool {
	return cause == ForwardCheckpointUnprovable || cause == RollbackStepUnprovable || cause == PriorAgreementUnprovable
}

func allowedActions(observed Observation) []Action {
	switch observed.Status {
	case NotInstalled, Managed:
		return []Action{InspectAction, ApplyAction}
	case RecoveryRequired:
		actions := []Action{InspectAction, DiagnosticsAction}
		if observed.RollbackAvailable {
			actions = append(actions, RetryRollbackAction)
		} else if observed.ForwardRepairAvailable {
			actions = append(actions, ForwardRepairAction)
		}
		return append(actions, CheckAgainAction, BackAction, CompleteRemovalAction)
	default:
		return []Action{InspectAction}
	}
}

func recoveryInspection(finding Finding) Inspection {
	observed := Observation{Status: RecoveryRequired, Checkpoint: NoCheckpoint, Lock: LockReleased, RecoveryCause: StateLineageUnprovable}
	return Inspection{Status: RecoveryRequired, Checkpoint: NoCheckpoint, Lock: LockReleased, RecoveryCause: observed.RecoveryCause, AllowedActions: allowedActions(observed), Correction: recoveryCorrection(observed), ActivityPolicies: activityPolicies(RecoveryRequired, LockReleased), Findings: []Finding{finding}}
}

func validRecoveryCause(cause RecoveryCause) bool {
	switch cause {
	case StateLineageUnprovable, SnapshotUnprovable, JournalUnprovable, ForwardCheckpointUnprovable, RollbackStepUnprovable, PriorAgreementUnprovable, CurrentStateDrift, MissingSecrets, ReplacementVPS, OlderRevision, OwnerRegret:
		return true
	}
	return false
}

func recoveryCorrection(observed Observation) *Correction {
	if observed.Status != RecoveryRequired {
		return nil
	}
	correction := &Correction{CheckAgain: "Repeat read-only State and transaction inspection.", Back: "Return without changing State, services, or transaction evidence."}
	if observed.RollbackAvailable {
		correction.Source = SBXROwnedCorrection
		correction.SBXROption = RetryRollbackAction
		return correction
	}
	if observed.ForwardRepairAvailable {
		correction.Source = SBXROwnedCorrection
		correction.SBXROption = ForwardRepairAction
		correction.FreshPlanRequired = true
		return correction
	}
	correction.Source = ExternalCorrection
	correction.OwnerWorkPlan = externalRecoveryPlan(observed.RecoveryCause)
	return correction
}

func externalRecoveryPlan(cause RecoveryCause) []string {
	first := "Preserve the secret-safe evidence and do not start unproven services."
	switch cause {
	case MissingSecrets:
		first = "Supply new Owner-held secrets; SBXR cannot reconstruct lost secrets."
	case ReplacementVPS:
		first = "Prepare a Clean replacement VPS; transaction evidence does not transfer between servers."
	case OlderRevision:
		first = "Prepare current Owner-held inputs; SBXR does not restore an older revision."
	case OwnerRegret:
		first = "Choose the new intended configuration; SBXR does not turn transaction recovery into historical restore."
	}
	return []string{
		first,
		"Separately confirm Complete removal.",
		"Rebuild from a Clean VPS with current Owner-held inputs.",
	}
}

func activityPolicies(status InstallationStatus, lock LockState) []ActivityPolicy {
	health, renewal := ActivityAllowed, ActivityAllowed
	if status == ChangeInProgress || status == RecoveryRequired || lock == LockHeld {
		health, renewal = ActivityDeferred, ActivityDeferredAndReplan
	}
	return []ActivityPolicy{
		{ScheduledHealthActivity, health},
		{UpdateDiscoveryActivity, ActivityAllowed},
		{ReleaseVerificationActivity, ActivityAllowed},
		{CertificateRenewalActivity, renewal},
	}
}

type MutationClass string

const (
	InstallationMutation       MutationClass = "Installation"
	RepairMutation             MutationClass = "Repair"
	SettingChangeMutation      MutationClass = "Setting change"
	RotationMutation           MutationClass = "Rotation"
	UpdateMutation             MutationClass = "Update"
	CertificateRenewalMutation MutationClass = "Automatic certificate renewal"
	CompleteRemovalMutation    MutationClass = "Complete removal"
)

type Module string

const (
	ConnectionProfilesModule Module = "Connection Profiles"
	SubscriptionModule       Module = "Subscription Publication"
	CloudflareModule         Module = "Cloudflare Tunnel"
	CertificateModule        Module = "Certificate Lifecycle"
	SoftwareModule           Module = "Software Lifecycle"
	NetworkPolicyModule      Module = "Network Policy"
	HealthDiagnosticsModule  Module = "Health and Diagnostics"
	StateModule              Module = "State"
)

type OperationKind string

type CancellationContract string
type InspectionContract string

const SafeCheckpointCancellation CancellationContract = "Wait for declared safe checkpoint"
const InspectBeforeIdempotentReverse InspectionContract = "Inspect effect before idempotent reverse"

const (
	ActivatePreparedConfiguration OperationKind = "Activate prepared configuration"
	RestorePriorConfiguration     OperationKind = "Restore prior configuration"
	ApplyApprovedNetworkPolicy    OperationKind = "Apply approved Network Policy"
	RestorePriorNetworkPolicy     OperationKind = "Restore prior Network Policy"
)

type Step struct {
	owner    Module
	forward  OperationKind
	rollback OperationKind
	cancel   CancellationContract
	inspect  InspectionContract
}

func NewStep(owner Module, forward, rollback OperationKind) (Step, error) {
	if !validModule(owner) || !validOperation(forward) || !validOperation(rollback) || forward == rollback {
		return Step{}, &Finding{Code: "SYSTEM-CHANGES-STEP-INVALID", Problem: "A typed change or rollback instruction is invalid", Found: "an unsupported owner or operation", Required: "one owning Module plus distinct allowed forward and rollback operations", WhyStopped: "System Changes never accepts arbitrary commands, paths, services, or root operations", NextAction: "Rebuild the Change Set through the owning Module."}
	}
	return Step{owner: owner, forward: forward, rollback: rollback, cancel: SafeCheckpointCancellation, inspect: InspectBeforeIdempotentReverse}, nil
}

type Classification string

const (
	Required Classification = "Required"
	Advisory Classification = "Advisory"
)

type HealthStatus string

const (
	Healthy        HealthStatus = "Healthy"
	NeedsAttention HealthStatus = "Needs attention"
	Failed         HealthStatus = "Failed"
	Unknown        HealthStatus = "Unknown"
)

type CheckScope string

const (
	ServerSideCheck   CheckScope = "Server-side"
	ClientDeviceCheck CheckScope = "Client device"
)

type Check struct {
	Owner          Module         `json:"owner"`
	Scope          CheckScope     `json:"scope"`
	Phase          GatePhase      `json:"phase"`
	Classification Classification `json:"classification"`
	Status         HealthStatus   `json:"status"`
	Code           string         `json:"code"`
	Disclosed      bool           `json:"disclosed"`
}

type StateLineage struct {
	Status   InstallationStatus `json:"status"`
	Revision uint64             `json:"revision"`
	SHA256   string             `json:"sha256"`
}

type PlanBinding struct {
	Identity       string
	SHA256         string
	VolatileSHA256 string
}

type PreparedStateCommit interface {
	SystemChangesPreparedState() (changeSet string, revision uint64, startingSHA256, candidateSHA256, planIdentity, planSHA256 string, valid bool)
	SystemChangesConsume(lease any, planIdentity, planSHA256 string) (any, error)
}

type Timeouts struct {
	Step  time.Duration
	Check time.Duration
}

type DiskRequirement struct {
	PreparationBytes uint64
	TemporaryBytes   uint64
	SnapshotBytes    uint64
	JournalBytes     uint64
	RollbackBytes    uint64
	OverheadBytes    uint64
}

func (requirement DiskRequirement) total() (uint64, bool) {
	total := uint64(0)
	for _, value := range []uint64{requirement.PreparationBytes, requirement.TemporaryBytes, requirement.SnapshotBytes, requirement.JournalBytes, requirement.RollbackBytes, requirement.OverheadBytes} {
		var carry uint64
		total, carry = bits.Add64(total, value, 0)
		if carry != 0 {
			return 0, false
		}
	}
	return total, true
}

const (
	maxStepTimeout  = 24 * time.Hour
	maxCheckTimeout = time.Hour
)

type ChangeSetSpec struct {
	Identity          string
	Mutation          MutationClass
	OutcomeOwner      Module
	StartingState     StateLineage
	TargetStateSHA256 string
	Plan              PlanBinding
	PreparedState     PreparedStateCommit
	Steps             []Step
	Checks            []Check
	Timeouts          Timeouts
	Disk              DiskRequirement
}

type ChangeSet struct {
	spec ChangeSetSpec
	used *planAuthority
}

type planAuthority struct{ used atomic.Bool }

// ponytail: process-lifetime interning is enough before Plans gain durable ownership.
var planAuthorities sync.Map

type EvidenceRules struct {
	SecretSafeOnly bool `json:"secret_safe_only"`
	RawOutput      bool `json:"raw_output"`
	Commands       bool `json:"commands"`
}

func NewChangeSet(spec ChangeSetSpec) (*ChangeSet, error) {
	reserved, diskValid := spec.Disk.total()
	const largestFloor = ^uint64(0) / 10
	if !safeIdentity(spec.Identity) || !validMutation(spec.Mutation) || !validModule(spec.OutcomeOwner) || !validStartingState(spec.StartingState, spec.Mutation) || !validSHA256(spec.TargetStateSHA256) || !safeIdentity(spec.Plan.Identity) || !validSHA256(spec.Plan.SHA256) || !validSHA256(spec.Plan.VolatileSHA256) || spec.PreparedState == nil || len(spec.Steps) == 0 || len(spec.Checks) == 0 || spec.Timeouts.Step <= 0 || spec.Timeouts.Step > maxStepTimeout || spec.Timeouts.Check <= 0 || spec.Timeouts.Check > maxCheckTimeout || spec.Disk.PreparationBytes == 0 || spec.Disk.TemporaryBytes == 0 || spec.Disk.SnapshotBytes == 0 || spec.Disk.JournalBytes == 0 || spec.Disk.RollbackBytes == 0 || spec.Disk.OverheadBytes == 0 || !diskValid || reserved > ^uint64(0)-largestFloor {
		return nil, &Finding{Code: "SYSTEM-CHANGES-CHANGE-SET-INVALID", Problem: "The Change Set is incomplete or untyped", Found: "a missing or invalid typed transaction input", Required: "one opaque prepared State commit, exact lineage and Plan checksums, typed steps and rollback, checks, disk reservation, and bounded timeouts", WhyStopped: "System Changes never accepts an arbitrary mutation surface", NextAction: "Rebuild and review the Change Set through its owning Module."}
	}
	for _, step := range spec.Steps {
		if !validStep(step) {
			return nil, &Finding{Code: "SYSTEM-CHANGES-STEP-INVALID", Problem: "A transaction step is untyped", Found: "a missing owner, reverse operation, or safe-cancellation contract", Required: "one exact Module-owned forward and reverse pair", WhyStopped: "automatic rollback cannot guess how to reverse work", NextAction: "Rebuild the Change Set through its owning Modules."}
		}
	}
	var requiredPre, requiredPost bool
	for _, check := range spec.Checks {
		if !validCheck(check) {
			return nil, &Finding{Code: "SYSTEM-CHANGES-CHECK-INVALID", Problem: "A transaction check is untyped", Found: "an unsupported owner, classification, status, or code", Required: "one typed Required or Advisory check", WhyStopped: "System Changes cannot reinterpret a Module result", NextAction: "Rebuild the check through its owning Module."}
		}
		requiredPre = requiredPre || check.Classification == Required && check.Phase == PrePublication
		requiredPost = requiredPost || check.Classification == Required && check.Phase == PostPublication
	}
	if !requiredPre || !requiredPost {
		return nil, &Finding{Code: "SYSTEM-CHANGES-CHECK-INVALID", Problem: "The transaction health gates are incomplete", Found: "no Required check for both publication phases", Required: "at least one Required Server-side check before and after publication", WhyStopped: "State cannot publish or Complete without exact phase-specific health proof", NextAction: "Rebuild the checks through their owning Modules."}
	}
	spec.Steps = append([]Step(nil), spec.Steps...)
	spec.Checks = append([]Check(nil), spec.Checks...)
	authority, _ := planAuthorities.LoadOrStore(spec.Plan.Identity, &planAuthority{})
	return &ChangeSet{spec: spec, used: authority.(*planAuthority)}, nil
}

type ApplyOutcome string

const (
	Completed               ApplyOutcome = "Completed"
	RollbackSucceeded       ApplyOutcome = "Rollback succeeded"
	RecoveryRequiredOutcome ApplyOutcome = "Recovery Required"
	Refused                 ApplyOutcome = "Refused"
	Deferred                ApplyOutcome = "Deferred"
)

type ApplyResult struct {
	Outcome                ApplyOutcome       `json:"outcome"`
	RestoredStatus         InstallationStatus `json:"restored_status,omitempty"`
	NothingChanged         bool               `json:"nothing_changed"`
	PlanConsumed           bool               `json:"plan_consumed"`
	UsesMonotonicDurations bool               `json:"uses_monotonic_durations"`
	QueueCreated           bool               `json:"queue_created"`
	RebuildPlan            bool               `json:"rebuild_plan"`
	Evidence               EvidenceRules      `json:"evidence_rules"`
	Finding                *Finding           `json:"finding,omitempty"`
}

func (i Interface) Apply(changeSet *ChangeSet) ApplyResult {
	return i.apply(changeSet, nil)
}

func (i Interface) ApplyWithCancellation(changeSet *ChangeSet, cancellation *Cancellation) ApplyResult {
	return i.apply(changeSet, cancellation)
}

func (i Interface) apply(changeSet *ChangeSet, cancellation *Cancellation) ApplyResult {
	if changeSet == nil {
		return refused("SYSTEM-CHANGES-CHANGE-SET-REQUIRED", "Apply received no typed Change Set", "untyped or missing input", "one Change Set created by NewChangeSet", "direct mutation is forbidden", "Create and review a fresh Plan.", false)
	}
	if changeSet.used == nil || !changeSet.used.used.CompareAndSwap(false, true) {
		return refused("SYSTEM-CHANGES-PLAN-USED", "The one-use Plan authority was already consumed", "a repeated Apply attempt", "one fresh reviewed Plan", "every outcome burns its authority", "Create and review a fresh Plan.", true)
	}
	if cancellation.Requested() {
		return refused("SYSTEM-CHANGES-CANCELLED", "The Change Set was cancelled before Apply", "an explicit cancellation before approval entered live work", "no mutation", "cancellation before start changes nothing", "Create and review a fresh Plan.", true)
	}
	if i.adapter == nil {
		return refused("SYSTEM-CHANGES-ADAPTER-UNAVAILABLE", "The Ubuntu host Adapter is unavailable", "no Adapter", "one production Adapter", "mutation safety cannot be proven", "Restore the Adapter and plan again.", true)
	}
	lock, acquired, err := i.adapter.TryLock()
	if err != nil || acquired && lock == nil {
		return refused("SYSTEM-CHANGES-LOCK-UNPROVABLE", "The installation-wide kernel lock could not be proven", "the lock Adapter returned an error or no lock handle", "one verified protected kernel lock", "unsafe lock infrastructure is not ordinary contention", "Repair the lock path and create a fresh Plan.", true)
	}
	if !acquired {
		result := refused("SYSTEM-CHANGES-BUSY", "Another mutation owns the installation-wide kernel lock", "the kernel lock is held", "the one lock released by its owning worker", "System Changes never queues, steals, force-unlocks, or guesses from a PID or wall time", "Inspect the active Change Set and plan again after the lock clears.", true)
		if changeSet.spec.Mutation == CertificateRenewalMutation {
			result.Outcome = Deferred
			result.RebuildPlan = true
		}
		return result
	}
	observed, err := i.adapter.Observe()
	if err != nil || !validObservation(observed) {
		return finish(lock, refused("SYSTEM-CHANGES-INSPECTION-UNPROVABLE", "Fresh pre-mutation inspection failed", "incomplete transaction facts", "one exact fresh inspection under the kernel lock", "SBXR never guesses current State or host facts", "Check again and create a fresh Plan.", true))
	}
	spec := changeSet.spec
	forwardRepair := observed.Status == RecoveryRequired && observed.ForwardRepairAvailable && spec.Mutation == RepairMutation && spec.StartingState.Status == Managed
	completeRemoval := observed.Status == RecoveryRequired && spec.Mutation == CompleteRemovalMutation && spec.StartingState.Status == RecoveryRequired
	if observed.Status == RecoveryRequired && !forwardRepair && !completeRemoval {
		return finish(lock, refused("SYSTEM-CHANGES-RECOVERY-BLOCKED", "Normal mutation is blocked in Recovery Required", string(observed.RecoveryCause), "Retry automatic rollback, a fresh valid-current-State forward-repair Plan, or separately confirmed Complete removal", "Recovery Required never permits ordinary mutation or evidence bypass", "Use one action offered by Inspect or go Back.", true))
	}
	statusMatches := observed.Status == spec.StartingState.Status || forwardRepair
	if !statusMatches || observed.StateRevision != spec.StartingState.Revision || observed.StateSHA256 != spec.StartingState.SHA256 || observed.VolatileSHA256 != spec.Plan.VolatileSHA256 {
		return finish(lock, refused("SYSTEM-CHANGES-STALE", "The reviewed State lineage or volatile binding changed", fmt.Sprintf("status=%s revision=%d state_match=%t binding_match=%t", observed.Status, observed.StateRevision, observed.StateSHA256 == spec.StartingState.SHA256, observed.VolatileSHA256 == spec.Plan.VolatileSHA256), "the exact reviewed lineage and every volatile binding", "stale approval cannot authorize mutation", "Reload observations and create a fresh Plan.", true))
	}
	if spec.TargetStateSHA256 == spec.StartingState.SHA256 {
		return finish(lock, refused("SYSTEM-CHANGES-NO-OP", "The Change Set would not change Desired State", "the starting and target checksums are identical", "one actual reviewed change", "a no-op must not create transaction material", "Return without applying and plan only when intent changes.", true))
	}
	reserved, _ := spec.Disk.total()
	floor := observed.FilesystemBytes / 10
	if floor < 1<<30 {
		floor = 1 << 30
	}
	required := reserved + floor
	if observed.AvailableBytes < required {
		return finish(lock, refused("SYSTEM-CHANGES-DISK", "The fixed transaction disk gate failed", fmt.Sprintf("%d bytes available", observed.AvailableBytes), fmt.Sprintf("%d bytes available", required), "rollback space and the fixed safety floor must exist before mutation", "Remove only proven-safe incomplete temporary SBXR files or add disk space, then plan again.", true))
	}
	if !observed.WallTimeSynchronized || !observed.MonotonicClock {
		next := "Correct time through the existing owner, then create a fresh Plan."
		if observed.Status == NotInstalled && observed.TimeOwner == "" {
			next = "Review enabling systemd-timesyncd, then create a fresh Plan."
		}
		return finish(lock, refused("SYSTEM-CHANGES-TIME", "Transaction time prerequisites failed", fmt.Sprintf("wall_time_synchronized=%t monotonic_clock=%t owner=%s", observed.WallTimeSynchronized, observed.MonotonicClock, observed.TimeOwner), "plausibly synchronized wall time and monotonic duration measurement", "certificate, release, timeout, and durable evidence decisions need trustworthy time", next, true))
	}
	for _, check := range spec.Checks {
		if check.Classification == Required && check.Status != Healthy || check.Classification == Advisory && (check.Status == Failed || check.Status == Unknown || check.Status == NeedsAttention && !check.Disclosed) {
			return finish(lock, refused("SYSTEM-CHANGES-CHECK", "A Module-owned pre-mutation check did not pass", fmt.Sprintf("%s %s %s", check.Classification, check.Code, check.Status), "every Required check Healthy and every Advisory concern safe and disclosed", "System Changes enforces the result without reinterpreting its domain meaning", "Correct the owning Module finding and create a fresh Plan.", true))
		}
	}
	if !validPreparedState(spec) {
		return finish(lock, refused("SYSTEM-CHANGES-PREPARED-STATE", "The prepared State authority is invalid or unrelated", "a caller-made or mismatched authority", "one State-issued commit bound to this Change Set, candidate revision, and target checksum", "only State may prepare Desired State publication material", "Prepare State again and create a fresh Plan.", true))
	}
	return i.applyPrepared(lock, spec, cancellation)
}

func validPreparedState(spec ChangeSetSpec) bool {
	typeOf := reflect.TypeOf(spec.PreparedState)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/state" || typeOf.Elem().Name() != "PreparedCommit" {
		return false
	}
	changeSet, revision, startingSHA256, checksum, planIdentity, planSHA256, valid := spec.PreparedState.SystemChangesPreparedState()
	return valid && changeSet == spec.Identity && revision == spec.StartingState.Revision+1 && startingSHA256 == spec.StartingState.SHA256 && checksum == spec.TargetStateSHA256 && planIdentity == spec.Plan.Identity && planSHA256 == spec.Plan.SHA256
}

func finish(lock Lock, result ApplyResult, owner ...Module) ApplyResult {
	if err := lock.Close(); err != nil {
		outcomeOwner := Module("")
		if result.Finding != nil {
			outcomeOwner = result.Finding.Owner
		}
		if len(owner) > 0 {
			outcomeOwner = owner[0]
		}
		if result.NothingChanged {
			stopped := refused("SYSTEM-CHANGES-LOCK-RELEASE", "The installation-wide kernel lock release could not be proven", "the lock close returned an error", "one confirmed kernel-lock release", "transaction ownership is uncertain", "Inspect the transaction and use the Recovery Required flow.", true)
			stopped.Finding.Owner = outcomeOwner
			return stopped
		}
		return ApplyResult{Outcome: RecoveryRequiredOutcome, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: "SYSTEM-CHANGES-LOCK-RELEASE", Owner: outcomeOwner, Problem: "The installation-wide kernel lock release could not be proven", Found: "the lock close returned an error after transaction work", Required: "one confirmed kernel-lock release and durable resolution", WhyStopped: "changed work can never be reported as nothing changed", NextAction: "Inspect the transaction and use the Recovery Required flow."}}
	}
	return result
}

func refused(code, problem, found, required, why, next string, consumed bool) ApplyResult {
	return ApplyResult{Outcome: Refused, NothingChanged: true, PlanConsumed: consumed, UsesMonotonicDurations: true, Evidence: safeEvidence(), Finding: &Finding{Code: code, Problem: problem, Found: found, Required: required, WhyStopped: why, NextAction: next}}
}

func safeEvidence() EvidenceRules { return EvidenceRules{SecretSafeOnly: true} }

func validStartingState(lineage StateLineage, mutation MutationClass) bool {
	if lineage.Status == NotInstalled && lineage.Revision == 0 && lineage.SHA256 == "" {
		return mutation == InstallationMutation
	}
	if lineage.Status == Managed && lineage.Revision > 0 && validSHA256(lineage.SHA256) {
		return mutation != InstallationMutation
	}
	return mutation == CompleteRemovalMutation && lineage.Status == RecoveryRequired && (lineage.Revision == 0 && lineage.SHA256 == "" || lineage.Revision > 0 && validSHA256(lineage.SHA256))
}

func validMutation(mutation MutationClass) bool {
	switch mutation {
	case InstallationMutation, RepairMutation, SettingChangeMutation, RotationMutation, UpdateMutation, CertificateRenewalMutation, CompleteRemovalMutation:
		return true
	}
	return false
}

func validModule(module Module) bool {
	switch module {
	case ConnectionProfilesModule, SubscriptionModule, CloudflareModule, CertificateModule, SoftwareModule, NetworkPolicyModule, HealthDiagnosticsModule, StateModule:
		return true
	}
	return false
}

func validOperation(operation OperationKind) bool {
	switch operation {
	case ActivatePreparedConfiguration, RestorePriorConfiguration, ApplyApprovedNetworkPolicy, RestorePriorNetworkPolicy:
		return true
	}
	return false
}

func validStep(step Step) bool {
	return validModule(step.owner) && validOperation(step.forward) && validOperation(step.rollback) && step.forward != step.rollback && step.cancel == SafeCheckpointCancellation && step.inspect == InspectBeforeIdempotentReverse
}

func validCheck(check Check) bool {
	return validModule(check.Owner) && check.Scope == ServerSideCheck && (check.Phase == PrePublication || check.Phase == PostPublication) && (check.Classification == Required || check.Classification == Advisory) && (check.Status == Healthy || check.Status == NeedsAttention || check.Status == Failed || check.Status == Unknown) && safeIdentity(check.Code)
}

func safeIdentity(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
