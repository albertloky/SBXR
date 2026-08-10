// Package systemchanges owns SBXR's single installation-wide mutation boundary.
package systemchanges

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net/mail"
	"net/netip"
	"reflect"
	"slices"
	"strings"
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

// InstallationHealthInspection is the unforgeable read-only lineage handoff
// consumed by Health and Diagnostics.
type InstallationHealthInspection struct {
	inspection Inspection
}

type InstallationHealthFacts struct {
	Status                 InstallationStatus
	CurrentChangeSet       string
	CompletedSteps         int
	TotalSteps             int
	RollbackAvailable      bool
	ForwardRepairAvailable bool
	RecoveryCause          RecoveryCause
}

// InstallationFacts returns a copy of facts already validated by Inspect.
func (facts InstallationHealthInspection) InstallationFacts() (InstallationHealthFacts, bool) {
	if facts.inspection.Status == "" {
		return InstallationHealthFacts{}, false
	}
	return InstallationHealthFacts{
		Status: facts.inspection.Status, CurrentChangeSet: facts.inspection.CurrentChangeSet,
		CompletedSteps: facts.inspection.CompletedSteps, TotalSteps: facts.inspection.TotalSteps,
		RollbackAvailable: facts.inspection.RollbackAvailable, ForwardRepairAvailable: facts.inspection.ForwardRepairAvailable,
		RecoveryCause: facts.inspection.RecoveryCause,
	}, true
}

// ManagedAuthority is a fresh, non-renderable proof that normal post-Managed
// work may run against one exact Desired State revision.
type ManagedAuthority struct {
	cell *statusAuthority
}

type ForwardRepairAuthority struct {
	cell *statusAuthority
}

type CompleteRemovalAuthority struct {
	cell *completeRemovalAuthorityCell
}

type FreshInstallationAuthority struct {
	cell  *statusAuthority
	proof FreshInstallationProof
	used  *atomic.Bool
}

type FreshInstallationProof interface {
	SystemChangesFreshInstallation() bool
}

type completeRemovalAuthorityCell struct {
	adapter                Adapter
	status                 InstallationStatus
	revision               uint64
	sha256, volatileSHA256 string
	used                   atomic.Bool
}

type statusAuthority struct {
	adapter        Adapter
	revision       uint64
	sha256         string
	volatileSHA256 string
	used           atomic.Bool
}

func (ForwardRepairAuthority) String() string   { return "Forward repair authority: redacted" }
func (ForwardRepairAuthority) GoString() string { return "Forward repair authority: redacted" }
func (ForwardRepairAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Forward repair authority cannot be rendered")
}
func (authority ForwardRepairAuthority) ConnectionProfilesForwardRepair() (uint64, string, bool) {
	return authority.consume()
}

func (authority ForwardRepairAuthority) SoftwareLifecycleRepairReview() (uint64, string, string, bool) {
	if authority.cell == nil || authority.cell.used.Load() || authority.cell.revision == 0 || !validSHA256(authority.cell.sha256) || !validSHA256(authority.cell.volatileSHA256) {
		return 0, "", "", false
	}
	return authority.cell.revision, authority.cell.sha256, authority.cell.volatileSHA256, true
}

func (authority ForwardRepairAuthority) SoftwareLifecycleForwardRepair() (uint64, string, string, bool) {
	if authority.cell == nil || !authority.cell.used.CompareAndSwap(false, true) {
		return 0, "", "", false
	}
	observed, err := authority.cell.adapter.Observe()
	valid := err == nil && validObservation(observed) && observed.Status == RecoveryRequired && observed.Lock == LockReleased && observed.RecoveryCause == CurrentStateDrift && observed.ForwardRepairAvailable && observed.StateRevision == authority.cell.revision && observed.StateSHA256 == authority.cell.sha256 && observed.VolatileSHA256 == authority.cell.volatileSHA256 && validSHA256(observed.VolatileSHA256)
	return authority.cell.revision, authority.cell.sha256, authority.cell.volatileSHA256, valid
}

func (CompleteRemovalAuthority) String() string   { return "Complete removal authority: redacted" }
func (CompleteRemovalAuthority) GoString() string { return "Complete removal authority: redacted" }
func (CompleteRemovalAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Complete removal authority cannot be rendered")
}
func (authority CompleteRemovalAuthority) SoftwareLifecycleCompleteRemovalReview() (InstallationStatus, uint64, string, string, bool) {
	if authority.cell == nil || authority.cell.used.Load() || !completeRemovalLineage(authority.cell.status, authority.cell.revision, authority.cell.sha256) || !validSHA256(authority.cell.volatileSHA256) {
		return "", 0, "", "", false
	}
	return authority.cell.status, authority.cell.revision, authority.cell.sha256, authority.cell.volatileSHA256, true
}
func (authority CompleteRemovalAuthority) SoftwareLifecycleCompleteRemoval() (InstallationStatus, uint64, string, string, bool) {
	if authority.cell == nil || !authority.cell.used.CompareAndSwap(false, true) {
		return "", 0, "", "", false
	}
	observed, err := authority.cell.adapter.Observe()
	valid := err == nil && completeRemovalObservation(observed) && observed.Status == authority.cell.status && observed.StateRevision == authority.cell.revision && observed.StateSHA256 == authority.cell.sha256 && observed.VolatileSHA256 == authority.cell.volatileSHA256
	return authority.cell.status, authority.cell.revision, authority.cell.sha256, authority.cell.volatileSHA256, valid
}

func (FreshInstallationAuthority) String() string   { return "Fresh installation authority: redacted" }
func (FreshInstallationAuthority) GoString() string { return "Fresh installation authority: redacted" }
func (FreshInstallationAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Fresh installation authority cannot be rendered")
}
func (authority FreshInstallationAuthority) ConnectionProfilesFreshInstallation() bool {
	return authority.consumeFreshInstallation()
}

func (authority FreshInstallationAuthority) CertificateLifecycleFreshInstallation() bool {
	return authority.consumeFreshInstallation()
}

func (authority FreshInstallationAuthority) SystemChangesFreshInstallation() bool {
	return authority.consumeFreshInstallation()
}

func (authority FreshInstallationAuthority) consumeFreshInstallation() bool {
	if authority.proof != nil {
		return authority.used != nil && authority.used.CompareAndSwap(false, true) && authority.proof.SystemChangesFreshInstallation()
	}
	if authority.cell == nil || !authority.cell.used.CompareAndSwap(false, true) {
		return false
	}
	observed, err := authority.cell.adapter.Observe()
	return err == nil && validObservation(observed) && observed.Status == NotInstalled && observed.Lock == LockReleased
}

// NewFreshInstallationAuthority accepts only Network Policy's one-use Clean
// VPS proof. No host path is created until an approved Change Set starts.
func NewFreshInstallationAuthority(proof FreshInstallationProof) FreshInstallationAuthority {
	typeOf := reflect.TypeOf(proof)
	if typeOf == nil || typeOf.Kind() != reflect.Struct || typeOf.PkgPath() != "github.com/albertloky/SBXR/internal/networkpolicy" || typeOf.Name() != "FreshInstallationProof" {
		return FreshInstallationAuthority{}
	}
	return FreshInstallationAuthority{proof: proof, used: &atomic.Bool{}}
}

func (ManagedAuthority) String() string   { return "Managed authority: redacted" }
func (ManagedAuthority) GoString() string { return "Managed authority: redacted" }
func (ManagedAuthority) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Managed authority cannot be rendered")
}

func (authority ManagedAuthority) ConnectionProfilesManaged() (uint64, string, bool) {
	return authority.consume()
}

func (authority ManagedAuthority) consume() (uint64, string, bool) {
	if authority.cell == nil || !authority.cell.used.CompareAndSwap(false, true) {
		return 0, "", false
	}
	observed, err := authority.cell.adapter.Observe()
	valid := err == nil && validObservation(observed) && observed.Status == Managed && observed.Lock == LockReleased && observed.StateRevision == authority.cell.revision && observed.StateSHA256 == authority.cell.sha256
	return authority.cell.revision, authority.cell.sha256, valid
}

func (authority ForwardRepairAuthority) consume() (uint64, string, bool) {
	if authority.cell == nil || !authority.cell.used.CompareAndSwap(false, true) {
		return 0, "", false
	}
	observed, err := authority.cell.adapter.Observe()
	valid := err == nil && validObservation(observed) && observed.Status == RecoveryRequired && observed.Lock == LockReleased && observed.RecoveryCause == CurrentStateDrift && observed.ForwardRepairAvailable && observed.StateRevision == authority.cell.revision && observed.StateSHA256 == authority.cell.sha256
	return authority.cell.revision, authority.cell.sha256, valid
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

func (i Interface) InstallationHealthInspection() InstallationHealthInspection {
	return InstallationHealthInspection{inspection: i.Inspect()}
}

func (i Interface) ManagedAuthority() ManagedAuthority {
	if i.adapter == nil {
		return ManagedAuthority{}
	}
	observed, err := i.adapter.Observe()
	if err != nil || !validObservation(observed) || observed.Status != Managed || observed.Lock != LockReleased || observed.StateRevision == 0 || !validSHA256(observed.StateSHA256) {
		return ManagedAuthority{}
	}
	return ManagedAuthority{cell: &statusAuthority{adapter: i.adapter, revision: observed.StateRevision, sha256: observed.StateSHA256}}
}

func (i Interface) ForwardRepairAuthority() ForwardRepairAuthority {
	if i.adapter == nil {
		return ForwardRepairAuthority{}
	}
	observed, err := i.adapter.Observe()
	if err != nil || !validObservation(observed) || observed.Status != RecoveryRequired || observed.Lock != LockReleased || observed.RecoveryCause != CurrentStateDrift || !observed.ForwardRepairAvailable || observed.StateRevision == 0 || !validSHA256(observed.StateSHA256) {
		return ForwardRepairAuthority{}
	}
	return ForwardRepairAuthority{cell: &statusAuthority{adapter: i.adapter, revision: observed.StateRevision, sha256: observed.StateSHA256, volatileSHA256: observed.VolatileSHA256}}
}

func (i Interface) CompleteRemovalAuthority() CompleteRemovalAuthority {
	if i.adapter == nil {
		return CompleteRemovalAuthority{}
	}
	observed, err := i.adapter.Observe()
	if err != nil || !completeRemovalObservation(observed) {
		return CompleteRemovalAuthority{}
	}
	return CompleteRemovalAuthority{cell: &completeRemovalAuthorityCell{adapter: i.adapter, status: observed.Status, revision: observed.StateRevision, sha256: observed.StateSHA256, volatileSHA256: observed.VolatileSHA256}}
}

func completeRemovalObservation(observed Observation) bool {
	return observed.Lock == LockReleased && completeRemovalBaseline(observed)
}

func completeRemovalBaseline(observed Observation) bool {
	if !validObservation(observed) || !validSHA256(observed.VolatileSHA256) || !completeRemovalLineage(observed.Status, observed.StateRevision, observed.StateSHA256) {
		return false
	}
	return observed.Status != RecoveryRequired || observed.CurrentChangeSet == "" && observed.Checkpoint == NoCheckpoint && observed.CompletedSteps == 0 && observed.TotalSteps == 0 && !observed.RollbackAvailable
}

func completeRemovalLineage(status InstallationStatus, revision uint64, sha256 string) bool {
	return status == Managed && revision > 0 && validSHA256(sha256) || status == RecoveryRequired && (revision > 0 && validSHA256(sha256) || revision == 0 && sha256 == "")
}

func (i Interface) FreshInstallationAuthority() FreshInstallationAuthority {
	if i.adapter == nil {
		return FreshInstallationAuthority{}
	}
	observed, err := i.adapter.Observe()
	if err != nil || !validObservation(observed) || observed.Status != NotInstalled || observed.Lock != LockReleased {
		return FreshInstallationAuthority{}
	}
	return FreshInstallationAuthority{cell: &statusAuthority{adapter: i.adapter}}
}

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
	ActivatePreparedConfiguration   OperationKind = "Activate prepared configuration"
	RestorePriorConfiguration       OperationKind = "Restore prior configuration"
	ApplyApprovedNetworkPolicy      OperationKind = "Apply approved Network Policy"
	OpenApprovedHTTP01              OperationKind = "Open approved HTTP-01 rule"
	CloseRecordedHTTP01             OperationKind = "Close recorded HTTP-01 rule"
	RestorePriorNetworkPolicy       OperationKind = "Restore prior Network Policy"
	RemoveOwnedPublicExposure       OperationKind = "Remove owned public exposure"
	RestoreOwnedPublicExposure      OperationKind = "Restore owned public exposure"
	DeleteOwnedCloudflareResource   OperationKind = "Delete owned Cloudflare resource"
	RestoreOwnedCloudflareResource  OperationKind = "Restore owned Cloudflare resource"
	CreateCloudflareResource        OperationKind = "Create Cloudflare resource"
	DeleteCreatedCloudflareResource OperationKind = "Delete created Cloudflare resource"
	ConfigureCloudflareTunnel       OperationKind = "Configure Cloudflare Tunnel"
	RestoreCloudflareTunnel         OperationKind = "Restore Cloudflare Tunnel"
	ConfigureCloudflareDNS          OperationKind = "Configure owned Cloudflare DNS"
	RestoreCloudflareDNS            OperationKind = "Restore owned Cloudflare DNS"
	ActivateCloudflaredService      OperationKind = "Activate cloudflared service"
	RotateCloudflaredRunToken       OperationKind = "Rotate cloudflared run token"
	RestoreCloudflaredService       OperationKind = "Restore cloudflared service"
	StageCertificateCandidate       OperationKind = "Stage certificate candidate"
	DiscardCertificateCandidate     OperationKind = "Discard certificate candidate"
	OrderCertificateCandidate       OperationKind = "Order certificate candidate"
	PreserveCertificateLineage      OperationKind = "Preserve certificate lineage"
	ActivateCertificateServingPair  OperationKind = "Activate certificate serving pair"
	RestoreCertificateServingPair   OperationKind = "Restore certificate serving pair"
)

type CertificateAction string

const (
	CertificateIPStage        CertificateAction = "ip-stage"
	CertificateIPOrder        CertificateAction = "ip-order"
	CertificateIPActivate     CertificateAction = "ip-activate"
	CertificateDomainStage    CertificateAction = "domain-stage"
	CertificateDomainOrder    CertificateAction = "domain-order"
	CertificateDomainActivate CertificateAction = "domain-activate"
)

// CertificateChange is the fixed, command-free contract for one certificate
// lineage. Private key material never crosses this boundary.
type CertificateChange struct {
	Action            CertificateAction `json:"action"`
	Identity          string            `json:"identity"`
	RequiredProfile   string            `json:"required_profile"`
	CertName          string            `json:"cert_name"`
	OwnerEmail        string            `json:"owner_email,omitempty"`
	ConfigDirectory   string            `json:"config_directory,omitempty"`
	Account           string            `json:"account,omitempty"`
	SubscriptionUnit  string            `json:"subscription_unit,omitempty"`
	DestinationIP     string            `json:"destination_ip,omitempty"`
	DirectTLSRevision uint64            `json:"direct_tls_revision,omitempty"`
	DirectTLSSHA256   string            `json:"direct_tls_sha256,omitempty"`
}

type CloudflareAction string

const (
	CloudflareTunnelCreate     CloudflareAction = "tunnel-create"
	CloudflareRoutesPut        CloudflareAction = "routes-put"
	CloudflareDNSCreate        CloudflareAction = "dns-create"
	CloudflareDNSRepair        CloudflareAction = "dns-repair"
	CloudflaredActivate        CloudflareAction = "service-activate"
	CloudflareRunTokenActivate CloudflareAction = "run-token-activate"
)

type CloudflareRoute struct {
	Hostname string `json:"hostname,omitempty"`
	Origin   string `json:"origin"`
}

// CloudflareChange is a secret-free provider contract. Unknown provider IDs
// refer to the earlier step whose evidence must already be durable.
type CloudflareChange struct {
	Action               CloudflareAction  `json:"action"`
	AccountID            string            `json:"account_id"`
	ZoneID               string            `json:"zone_id,omitempty"`
	TunnelID             string            `json:"tunnel_id,omitempty"`
	TunnelIDFromStep     int               `json:"tunnel_id_from_step,omitempty"`
	TunnelName           string            `json:"tunnel_name,omitempty"`
	Hostname             string            `json:"hostname,omitempty"`
	DNSRecordID          string            `json:"dns_record_id,omitempty"`
	RecordType           string            `json:"record_type,omitempty"`
	Content              string            `json:"content,omitempty"`
	Routes               []CloudflareRoute `json:"routes,omitempty"`
	XHTTPDNSRecordID     string            `json:"xhttp_dns_record_id,omitempty"`
	WebSocketDNSRecordID string            `json:"websocket_dns_record_id,omitempty"`
	DirectIPv4RecordID   string            `json:"direct_ipv4_record_id,omitempty"`
	DirectIPv6RecordID   string            `json:"direct_ipv6_record_id,omitempty"`
	DirectHostname       string            `json:"direct_hostname,omitempty"`
	PublicIPv4           string            `json:"public_ipv4,omitempty"`
	PublicIPv6           string            `json:"public_ipv6,omitempty"`
}

type FirewallAction string

const (
	FirewallPolicyAction FirewallAction = "policy"
	HTTP01OpenAction     FirewallAction = "http-01-open"
	HTTP01CloseAction    FirewallAction = "http-01-close"
)

const http01Identity = "sbxr:acme-http-01"

type FirewallChange struct {
	Action                FirewallAction `json:"action"`
	Candidate             string         `json:"candidate,omitempty"`
	SSHPort               uint16         `json:"ssh_port,omitempty"`
	TemporaryRuleIdentity string         `json:"temporary_rule_identity,omitempty"`
}

type HTTP01Authority interface {
	SystemChangesHTTP01() (candidate string, sshPort uint16, revision uint64, selectedIP, digest string, valid bool)
}

type DirectTLSAuthority interface {
	SystemChangesDirectTLS() (revision uint64, destinationIP, hostname, digest string, valid bool)
}

func NewDirectTLSChecks(authority DirectTLSAuthority) (uint64, string, string, string, []Check, error) {
	if !trustedAuthority(authority, "github.com/albertloky/SBXR/internal/connectionprofiles", "DirectTLSContribution") {
		return 0, "", "", "", nil, errors.New("Connection Profiles Direct TLS authority unavailable")
	}
	revision, destinationIP, hostname, digest, valid := authority.SystemChangesDirectTLS()
	address, addressErr := netip.ParseAddr(destinationIP)
	if !valid || revision == 0 || addressErr != nil || !address.IsGlobalUnicast() || !validCertificateHostname(hostname) || !validSHA256(digest) {
		return 0, "", "", "", nil, errors.New("Connection Profiles Direct TLS contribution invalid")
	}
	checks := []Check{
		{Owner: ConnectionProfilesModule, Scope: ServerSideCheck, Phase: PostPublication, Classification: Required, Status: Healthy, Code: "CONNECTION-PROFILES-HYSTERIA2-DIRECT-TLS"},
		{Owner: ConnectionProfilesModule, Scope: ServerSideCheck, Phase: PostPublication, Classification: Required, Status: Healthy, Code: "CONNECTION-PROFILES-TUIC-DIRECT-TLS"},
		{Owner: ConnectionProfilesModule, Scope: ServerSideCheck, Phase: PostPublication, Classification: Required, Status: Healthy, Code: "CONNECTION-PROFILES-ANYTLS-DIRECT-TLS"},
	}
	return revision, destinationIP, hostname, digest, checks, nil
}

func NewHTTP01Steps(authority HTTP01Authority) (Step, Step, string, string, uint64, error) {
	if !trustedAuthority(authority, "github.com/albertloky/SBXR/internal/networkpolicy", "HTTP01Contribution") {
		return Step{}, Step{}, "", "", 0, errors.New("Network Policy HTTP-01 authority unavailable")
	}
	candidate, sshPort, revision, selectedIP, digest, valid := authority.SystemChangesHTTP01()
	address, addressErr := netip.ParseAddr(selectedIP)
	exactRule := fmt.Sprintf("daddr %s tcp dport 80 accept comment \"%s\"", selectedIP, http01Identity)
	open, openErr := NewHTTP01OpenStep(candidate, sshPort)
	close, closeErr := NewHTTP01CloseStep()
	if !valid || revision == 0 || addressErr != nil || !address.IsGlobalUnicast() || !validSHA256(digest) || strings.Count(candidate, `comment "`+http01Identity+`"`) != 1 || !strings.Contains(candidate, exactRule) || openErr != nil || closeErr != nil {
		return Step{}, Step{}, "", "", 0, errors.New("Network Policy HTTP-01 contribution invalid")
	}
	return open, close, selectedIP, digest, revision, nil
}

type RemovalAction string
type RemovalResource string

const (
	PublicExposureRemoval RemovalAction = "public-exposure"
	CloudflareRemoval     RemovalAction = "cloudflare-resource"

	FirewallTableResource       RemovalResource = "firewall-table"
	PublicListenerResource      RemovalResource = "public-listener"
	PublicServiceResource       RemovalResource = "public-service"
	CloudflareDNSRecordResource RemovalResource = "cloudflare-dns-record"
	CloudflareRouteResource     RemovalResource = "cloudflare-route"
	CloudflareTunnelResource    RemovalResource = "cloudflare-tunnel"
)

type RemovalChange struct {
	Action                   RemovalAction   `json:"action"`
	Resource                 RemovalResource `json:"resource"`
	ImmutableID              string          `json:"immutable_id"`
	ReviewID                 string          `json:"review_id"`
	CloudflareTokenActive    bool            `json:"cloudflare_token_active,omitempty"`
	CloudflareTokenAvailable bool            `json:"cloudflare_token_available,omitempty"`
	InventorySHA256          string          `json:"inventory_sha256"`
}

type Step struct {
	owner       Module
	forward     OperationKind
	rollback    OperationKind
	cancel      CancellationContract
	inspect     InspectionContract
	firewall    FirewallChange
	removal     RemovalChange
	cloudflare  CloudflareChange
	certificate CertificateChange
}

func NewCertificateStep(change CertificateChange) (Step, error) {
	forward, rollback := StageCertificateCandidate, DiscardCertificateCandidate
	switch change.Action {
	case CertificateIPOrder, CertificateDomainOrder:
		forward, rollback = OrderCertificateCandidate, PreserveCertificateLineage
	case CertificateIPActivate, CertificateDomainActivate:
		forward, rollback = ActivateCertificateServingPair, RestoreCertificateServingPair
	}
	step := Step{owner: CertificateModule, forward: forward, rollback: rollback, cancel: SafeCheckpointCancellation, inspect: InspectBeforeIdempotentReverse, certificate: change}
	if !validStep(step) {
		return Step{}, &Finding{Code: "SYSTEM-CHANGES-CERTIFICATE-STEP", Problem: "A certificate transaction step is invalid", Found: "an incomplete certificate contract", Required: "one exact fixed-lineage staging, production, or serving activation action", WhyStopped: "System Changes never accepts certificate commands, arbitrary identities, or private key material", NextAction: "Rebuild the Change Set through Certificate Lifecycle."}
	}
	return step, nil
}

func NewCloudflareStep(change CloudflareChange) (Step, error) {
	forward, rollback := CreateCloudflareResource, DeleteCreatedCloudflareResource
	switch change.Action {
	case CloudflareRoutesPut:
		forward, rollback = ConfigureCloudflareTunnel, RestoreCloudflareTunnel
	case CloudflareDNSRepair:
		forward, rollback = ConfigureCloudflareDNS, RestoreCloudflareDNS
	case CloudflaredActivate:
		forward, rollback = ActivateCloudflaredService, RestoreCloudflaredService
	case CloudflareRunTokenActivate:
		forward, rollback = RotateCloudflaredRunToken, RestoreCloudflaredService
	}
	step := Step{owner: CloudflareModule, forward: forward, rollback: rollback, cancel: SafeCheckpointCancellation, inspect: InspectBeforeIdempotentReverse, cloudflare: change}
	if !validStep(step) {
		return Step{}, &Finding{Code: "SYSTEM-CHANGES-CLOUDFLARE-STEP", Problem: "A Cloudflare transaction step is invalid", Found: "an incomplete or unsafe secret-free provider contract", Required: "one exact owned Tunnel, route, DNS, or cloudflared action", WhyStopped: "System Changes never accepts provider commands, secrets, or unbound identifiers", NextAction: "Rebuild the Change Set through Cloudflare Tunnel."}
	}
	return step, nil
}

func NewStep(owner Module, forward, rollback OperationKind) (Step, error) {
	if !validModule(owner) || !validOperation(forward) || !validOperation(rollback) || forward == rollback || owner == NetworkPolicyModule || networkOperation(forward) || networkOperation(rollback) || removalOperation(forward) || removalOperation(rollback) || cloudflareOperation(forward) || cloudflareOperation(rollback) || certificateOperation(forward) || certificateOperation(rollback) {
		return Step{}, &Finding{Code: "SYSTEM-CHANGES-STEP-INVALID", Problem: "A typed change or rollback instruction is invalid", Found: "an unsupported owner or operation", Required: "one owning Module plus distinct allowed forward and rollback operations", WhyStopped: "System Changes never accepts arbitrary commands, paths, services, or root operations", NextAction: "Rebuild the Change Set through the owning Module."}
	}
	return Step{owner: owner, forward: forward, rollback: rollback, cancel: SafeCheckpointCancellation, inspect: InspectBeforeIdempotentReverse}, nil
}

func NewFirewallPolicyStep(candidate string, sshPort uint16) (Step, error) {
	return newFirewallStep(ApplyApprovedNetworkPolicy, FirewallPolicyAction, candidate, sshPort)
}

func NewHTTP01OpenStep(candidate string, sshPort uint16) (Step, error) {
	return newFirewallStep(OpenApprovedHTTP01, HTTP01OpenAction, candidate, sshPort)
}

func NewHTTP01CloseStep() (Step, error) {
	return newFirewallStep(CloseRecordedHTTP01, HTTP01CloseAction, "", 0)
}

func NewPublicExposureRemovalStep(selection PermanentRemovalSelection, authority PublicRemovalAuthority) (Step, error) {
	review, valid := validPermanentRemovalSelection(selection)
	authorityReview, resource, immutableID, inventory, proved := validPublicRemovalAuthority(authority)
	inventorySHA256, inventoryValid := removalInventoryDigest(inventory, publicRemovalCategories)
	if !valid || !proved || authorityReview != review || !inventoryValid || !inventoryContains(inventory, resource, immutableID) {
		return Step{}, invalidRemovalStep()
	}
	return newRemovalStep(NetworkPolicyModule, RemoveOwnedPublicExposure, RestoreOwnedPublicExposure, RemovalChange{Action: PublicExposureRemoval, Resource: RemovalResource(resource), ImmutableID: immutableID, ReviewID: review, InventorySHA256: inventorySHA256})
}

func NewCloudflareRemovalStep(selection PermanentRemovalSelection, authority CloudflareRemovalAuthority) (Step, error) {
	review, selected := validPermanentRemovalSelection(selection)
	authorityReview, resource, immutableID, inventory, tokenActive, tokenAvailable, proved := validCloudflareRemovalAuthority(authority)
	inventorySHA256, inventoryValid := removalInventoryDigest(inventory, cloudflareRemovalCategories)
	change := RemovalChange{Action: CloudflareRemoval, Resource: RemovalResource(resource), ImmutableID: immutableID, ReviewID: review, CloudflareTokenActive: tokenActive, CloudflareTokenAvailable: tokenAvailable, InventorySHA256: inventorySHA256}
	if !selected || !proved || authorityReview != review || !inventoryValid || !inventoryContains(inventory, resource, immutableID) {
		return Step{}, invalidRemovalStep()
	}
	return newRemovalStep(CloudflareModule, DeleteOwnedCloudflareResource, RestoreOwnedCloudflareResource, change)
}

func invalidRemovalStep() error {
	return &Finding{Code: "SYSTEM-CHANGES-REMOVAL-STEP", Problem: "A reversible Complete removal step is invalid", Found: "an unproved resource identity, owner, reviewed category, or live Cloudflare token authority", Required: "one owning-Module proof bound to the reviewed removal and immutable identity", WhyStopped: "Complete removal cannot guess ownership or discard rollback authority", NextAction: "Rebuild the removal Plan from fresh owning-Module observations."}
}

func newRemovalStep(owner Module, forward, rollback OperationKind, removal RemovalChange) (Step, error) {
	step := Step{owner: owner, forward: forward, rollback: rollback, cancel: SafeCheckpointCancellation, inspect: InspectBeforeIdempotentReverse, removal: removal}
	if !validStep(step) {
		return Step{}, invalidRemovalStep()
	}
	return step, nil
}

// RestoreRemovalStep reconstructs only a previously journaled removal contract
// while System Changes holds its private restart-recovery lease.
func RestoreRemovalStep(lease ExecutionLease, removal RemovalChange) (Step, error) {
	if !lease.RecoveryAuthorized() {
		return Step{}, invalidRemovalStep()
	}
	switch removal.Action {
	case PublicExposureRemoval:
		return newRemovalStep(NetworkPolicyModule, RemoveOwnedPublicExposure, RestoreOwnedPublicExposure, removal)
	case CloudflareRemoval:
		return newRemovalStep(CloudflareModule, DeleteOwnedCloudflareResource, RestoreOwnedCloudflareResource, removal)
	default:
		return Step{}, invalidRemovalStep()
	}
}

func newFirewallStep(forward OperationKind, action FirewallAction, candidate string, sshPort uint16) (Step, error) {
	contract := FirewallChange{Action: action, Candidate: candidate, SSHPort: sshPort}
	if action == HTTP01OpenAction || action == HTTP01CloseAction {
		contract.TemporaryRuleIdentity = http01Identity
	}
	step := Step{owner: NetworkPolicyModule, forward: forward, rollback: RestorePriorNetworkPolicy, cancel: SafeCheckpointCancellation, inspect: InspectBeforeIdempotentReverse, firewall: contract}
	if !validStep(step) {
		return Step{}, &Finding{Code: "SYSTEM-CHANGES-STEP-INVALID", Problem: "A Network Policy change is invalid", Found: "an incomplete or unsafe firewall contract", Required: "one exact inet sbxr candidate, detected SSH port, and typed temporary-rule action", WhyStopped: "System Changes never accepts arbitrary nftables work", NextAction: "Rebuild the Change Set through Network Policy."}
	}
	return step, nil
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

type TypedRemovalConfirmation interface {
	SystemChangesTypedRemovalConfirmation() (review, phrase string, valid bool)
}

type PermanentRemovalSelection interface {
	SystemChangesPermanentRemovalSelection() (review string, valid bool)
}

type CloudflareRemovalProof struct {
	ReviewID, ImmutableID       string
	Resource                    RemovalResource
	Inventory                   map[string][]string
	TokenActive, TokenAvailable bool
	Valid                       bool
}

type CloudflareRemovalAuthority interface {
	SystemChangesCloudflareRemovalAuthority() CloudflareRemovalProof
}

type PublicRemovalAuthority interface {
	SystemChangesPublicRemovalAuthority() (review, resource, immutableID string, inventory map[string][]string, valid bool)
}

var publicRemovalCategories = []string{string(FirewallTableResource), string(PublicListenerResource), string(PublicServiceResource)}
var cloudflareRemovalCategories = []string{string(CloudflareDNSRecordResource), string(CloudflareRouteResource), string(CloudflareTunnelResource)}

func validTypedRemovalConfirmation(confirmation TypedRemovalConfirmation) (review, phrase string, valid bool) {
	if !trustedAuthority(confirmation, "github.com/albertloky/SBXR/internal/ownerconsole", "TypedRemovalConfirmation") {
		return "", "", false
	}
	review, phrase, valid = confirmation.SystemChangesTypedRemovalConfirmation()
	return review, phrase, valid && safeIdentity(review) && phrase == "COMPLETE REMOVAL"
}

func validPermanentRemovalSelection(selection PermanentRemovalSelection) (review string, valid bool) {
	if !trustedAuthority(selection, "github.com/albertloky/SBXR/internal/ownerconsole", "PermanentRemovalSelection") {
		return "", false
	}
	review, valid = selection.SystemChangesPermanentRemovalSelection()
	return review, valid && safeIdentity(review)
}

func validCloudflareRemovalAuthority(authority CloudflareRemovalAuthority) (review, resource, immutableID string, inventory map[string][]string, tokenActive, tokenAvailable, valid bool) {
	if !trustedAuthority(authority, "github.com/albertloky/SBXR/internal/cloudflaretunnel", "RemovalAuthority") {
		return "", "", "", nil, false, false, false
	}
	proof := authority.SystemChangesCloudflareRemovalAuthority()
	review, resource, immutableID, inventory, tokenActive, tokenAvailable, valid = proof.ReviewID, string(proof.Resource), proof.ImmutableID, proof.Inventory, proof.TokenActive, proof.TokenAvailable, proof.Valid
	return review, resource, immutableID, inventory, tokenActive, tokenAvailable, valid && safeIdentity(review) && safeIdentity(immutableID) && tokenActive && tokenAvailable
}

func validPublicRemovalAuthority(authority PublicRemovalAuthority) (review, resource, immutableID string, inventory map[string][]string, valid bool) {
	if !trustedAuthority(authority, "github.com/albertloky/SBXR/internal/networkpolicy", "RemovalAuthority") {
		return "", "", "", nil, false
	}
	review, resource, immutableID, inventory, valid = authority.SystemChangesPublicRemovalAuthority()
	return review, resource, immutableID, inventory, valid && safeIdentity(review) && safeIdentity(immutableID)
}

func inventoryContains(inventory map[string][]string, category, identity string) bool {
	return slices.Contains(inventory[category], identity)
}

func removalInventoryDigest(inventory map[string][]string, allowed []string) (string, bool) {
	if len(inventory) != len(allowed) {
		return "", false
	}
	entries := make([]string, 0)
	for _, category := range allowed {
		identities, exists := inventory[category]
		if !exists {
			return "", false
		}
		identities = append([]string(nil), identities...)
		slices.Sort(identities)
		for index, identity := range identities {
			if !safeIdentity(identity) || index > 0 && identity == identities[index-1] {
				return "", false
			}
			entries = append(entries, category+"="+identity+"\n")
		}
	}
	digest := sha256.Sum256([]byte(strings.Join(entries, "")))
	return hex.EncodeToString(digest[:]), true
}

func trustedAuthority(value any, packagePath, name string) bool {
	typeOf := reflect.TypeOf(value)
	return typeOf != nil && typeOf.Kind() == reflect.Struct && typeOf.PkgPath() == packagePath && typeOf.Name() == name
}

func removalStepsMatchReview(steps []Step, review string) bool {
	if !safeIdentity(review) {
		return false
	}
	for _, step := range steps {
		if step.removal.ReviewID != review {
			return false
		}
	}
	return true
}

type PreparedStateCommit interface {
	SystemChangesPreparedState() (changeSet string, revision uint64, startingSHA256, candidateSHA256, planIdentity, planSHA256 string, valid bool)
	SystemChangesConsume(lease any, planIdentity, planSHA256 string) (any, error)
}

type CertificateRenewalPreparedState interface {
	PreparedStateCommit
	SystemChangesIPCertificateRenewal() bool
	SystemChangesDomainCertificateRenewal() bool
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
	Identity                  string
	Mutation                  MutationClass
	OutcomeOwner              Module
	StartingState             StateLineage
	TargetStateSHA256         string
	Plan                      PlanBinding
	PreparedState             PreparedStateCommit
	TypedRemovalConfirmation  TypedRemovalConfirmation
	PermanentRemovalSelection PermanentRemovalSelection
	Steps                     []Step
	Checks                    []Check
	Timeouts                  Timeouts
	Disk                      DiskRequirement
}

type ChangeSet struct {
	spec ChangeSetSpec
	used *planAuthority
}

func (changeSet *ChangeSet) Identity() string {
	if changeSet == nil {
		return ""
	}
	return changeSet.spec.Identity
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
	confirmationReview, _, typed := validTypedRemovalConfirmation(spec.TypedRemovalConfirmation)
	selectionReview, selected := validPermanentRemovalSelection(spec.PermanentRemovalSelection)
	confirmedRemoval := spec.Mutation == CompleteRemovalMutation && typed && selected && confirmationReview == selectionReview
	validRemoval := validRemovalSteps(spec.Steps)
	if !safeIdentity(spec.Identity) || !validMutation(spec.Mutation) || !validModule(spec.OutcomeOwner) || !validStartingState(spec.StartingState, spec.Mutation) || !validTargetState(spec) || !safeIdentity(spec.Plan.Identity) || !validSHA256(spec.Plan.SHA256) || !validSHA256(spec.Plan.VolatileSHA256) || spec.PreparedState == nil || len(spec.Steps) == 0 || len(spec.Checks) == 0 || spec.Timeouts.Step <= 0 || spec.Timeouts.Step > maxStepTimeout || spec.Timeouts.Check <= 0 || spec.Timeouts.Check > maxCheckTimeout || spec.Disk.PreparationBytes == 0 || spec.Disk.TemporaryBytes == 0 || spec.Disk.SnapshotBytes == 0 || spec.Disk.JournalBytes == 0 || spec.Disk.RollbackBytes == 0 || spec.Disk.OverheadBytes == 0 || !diskValid || reserved > ^uint64(0)-largestFloor || spec.Mutation == CompleteRemovalMutation != confirmedRemoval || spec.Mutation == CompleteRemovalMutation != validRemoval || spec.Mutation == CompleteRemovalMutation && !removalStepsMatchReview(spec.Steps, selectionReview) || spec.Mutation != CompleteRemovalMutation && (spec.TypedRemovalConfirmation != nil || spec.PermanentRemovalSelection != nil) {
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
	Completed                ApplyOutcome = "Completed"
	RollbackSucceeded        ApplyOutcome = "Rollback succeeded"
	RecoveryRequiredOutcome  ApplyOutcome = "Recovery Required"
	Refused                  ApplyOutcome = "Refused"
	Deferred                 ApplyOutcome = "Deferred"
	AwaitingTokenRevocation  ApplyOutcome = "Awaiting Cloudflare token revocation"
	RemovalForwardOnly       ApplyOutcome = "Removal remains forward-only"
	AwaitingRunTokenRotation ApplyOutcome = "Awaiting Owner Tunnel run-token rotation"
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
	UnremovableTraces      []string           `json:"unremovable_traces,omitempty"`
}

func (i Interface) Apply(changeSet *ChangeSet) ApplyResult {
	return i.apply(changeSet, nil)
}

func (i Interface) ApplyWithCancellation(changeSet *ChangeSet, cancellation *Cancellation) ApplyResult {
	return i.apply(changeSet, cancellation)
}

// ApplyFreshCertificateRenewal obtains the global lock before asking the
// Certificate Lifecycle composition root for one fresh renewal Change Set.
func (i Interface) ApplyFreshCertificateRenewal(build func() (*ChangeSet, error)) ApplyResult {
	if i.adapter == nil {
		return refused("SYSTEM-CHANGES-ADAPTER-UNAVAILABLE", "The Ubuntu host Adapter is unavailable", "no Adapter", "one production Adapter", "mutation safety cannot be proven", "Restore the Adapter and plan again.", false)
	}
	lock, acquired, err := i.adapter.TryLock()
	if err != nil || acquired && lock == nil {
		return refused("SYSTEM-CHANGES-LOCK-UNPROVABLE", "The installation-wide kernel lock could not be proven", "the lock Adapter returned an error or no lock handle", "one verified protected kernel lock", "unsafe lock infrastructure is not ordinary contention", "Repair the lock path and create a fresh Plan.", false)
	}
	if !acquired {
		result := refused("SYSTEM-CHANGES-BUSY", "Another mutation owns the installation-wide kernel lock", "the kernel lock is held", "the one lock released by its owning worker", "System Changes never queues, steals, force-unlocks, or guesses from a PID or wall time", "Recheck the renewal retry policy after the lock clears.", false)
		result.Outcome = Deferred
		result.RebuildPlan = true
		return result
	}
	if build == nil {
		return finish(lock, refused("SYSTEM-CHANGES-RENEWAL-PLAN", "The renewal Plan builder is unavailable", "no Certificate Lifecycle planner", "one fresh revision-bound renewal Change Set", "unattended mutation needs fresh authority after lock acquisition", "Restore Certificate Lifecycle and try again.", false))
	}
	changeSet, err := build()
	if err != nil || changeSet == nil {
		return finish(lock, refused("SYSTEM-CHANGES-RENEWAL-PLAN", "A fresh renewal Plan could not be built", "the locked planning result was missing, invalid, or outside certificate renewal", "one fresh revision-bound certificate-renewal Change Set", "the global lock cannot authorize a caller-made or broader mutation", "Rebuild observations and try again.", false))
	}
	if result, stopped := consumeApplyAuthority(changeSet, nil); stopped {
		return finish(lock, result)
	}
	if changeSet.spec.Mutation != CertificateRenewalMutation {
		return finish(lock, refused("SYSTEM-CHANGES-RENEWAL-PLAN", "The fresh Plan is outside certificate renewal", "the locked planner returned another mutation class", "one fresh revision-bound certificate-renewal Change Set", "the global lock cannot expand standing authority", "Create a fresh reviewed Plan.", true))
	}
	return i.applyLocked(changeSet, nil, lock)
}

func (i Interface) apply(changeSet *ChangeSet, cancellation *Cancellation) ApplyResult {
	if result, stopped := consumeApplyAuthority(changeSet, cancellation); stopped {
		return result
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
	return i.applyLocked(changeSet, cancellation, lock)
}

func consumeApplyAuthority(changeSet *ChangeSet, cancellation *Cancellation) (ApplyResult, bool) {
	if changeSet == nil {
		return refused("SYSTEM-CHANGES-CHANGE-SET-REQUIRED", "Apply received no typed Change Set", "untyped or missing input", "one Change Set created by NewChangeSet", "direct mutation is forbidden", "Create and review a fresh Plan.", false), true
	}
	if changeSet.used == nil || !changeSet.used.used.CompareAndSwap(false, true) {
		return refused("SYSTEM-CHANGES-PLAN-USED", "The one-use Plan authority was already consumed", "a repeated Apply attempt", "one fresh reviewed Plan", "every outcome burns its authority", "Create and review a fresh Plan.", true), true
	}
	if cancellation.Requested() {
		return refused("SYSTEM-CHANGES-CANCELLED", "The Change Set was cancelled before Apply", "an explicit cancellation before approval entered live work", "no mutation", "cancellation before start changes nothing", "Create and review a fresh Plan.", true), true
	}
	return ApplyResult{}, false
}

func (i Interface) applyLocked(changeSet *ChangeSet, cancellation *Cancellation, lock Lock) ApplyResult {
	observed, err := i.adapter.Observe()
	if err != nil || !validObservation(observed) {
		return finish(lock, refused("SYSTEM-CHANGES-INSPECTION-UNPROVABLE", "Fresh pre-mutation inspection failed", "incomplete transaction facts", "one exact fresh inspection under the kernel lock", "SBXR never guesses current State or host facts", "Check again and create a fresh Plan.", true))
	}
	spec := changeSet.spec
	forwardRepair := observed.Status == RecoveryRequired && observed.ForwardRepairAvailable && spec.Mutation == RepairMutation && spec.StartingState.Status == Managed
	completeRemoval := observed.Status == RecoveryRequired && spec.Mutation == CompleteRemovalMutation && spec.StartingState.Status == RecoveryRequired && completeRemovalBaseline(observed)
	if observed.Status == RecoveryRequired && !forwardRepair && !completeRemoval {
		return finish(lock, refused("SYSTEM-CHANGES-RECOVERY-BLOCKED", "Normal mutation is blocked in Recovery Required", string(observed.RecoveryCause), "Retry automatic rollback, a fresh valid-current-State forward-repair Plan, or separately confirmed Complete removal", "Recovery Required never permits ordinary mutation or evidence bypass", "Use one action offered by Inspect or go Back.", true))
	}
	statusMatches := observed.Status == spec.StartingState.Status || forwardRepair
	if !statusMatches || observed.StateRevision != spec.StartingState.Revision || observed.StateSHA256 != spec.StartingState.SHA256 || observed.VolatileSHA256 != spec.Plan.VolatileSHA256 {
		return finish(lock, refused("SYSTEM-CHANGES-STALE", "The reviewed State lineage or volatile binding changed", fmt.Sprintf("status=%s revision=%d state_match=%t binding_match=%t", observed.Status, observed.StateRevision, observed.StateSHA256 == spec.StartingState.SHA256, observed.VolatileSHA256 == spec.Plan.VolatileSHA256), "the exact reviewed lineage and every volatile binding", "stale approval cannot authorize mutation", "Reload observations and create a fresh Plan.", true))
	}
	if spec.TargetStateSHA256 == spec.StartingState.SHA256 && spec.Mutation != RotationMutation && spec.Mutation != RepairMutation && spec.Mutation != CompleteRemovalMutation {
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
	if spec.Mutation == CompleteRemovalMutation && spec.StartingState.Status == RecoveryRequired && spec.StartingState.Revision == 0 && spec.StartingState.SHA256 == "" {
		unproven, ok := spec.PreparedState.(interface{ SystemChangesRemovalLineageUnavailable() bool })
		return ok && unproven.SystemChangesRemovalLineageUnavailable() && valid && changeSet == spec.Identity && revision == 0 && startingSHA256 == "" && checksum == "" && planIdentity == spec.Plan.Identity && planSHA256 == spec.Plan.SHA256
	}
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
	return mutation == CompleteRemovalMutation && completeRemovalLineage(lineage.Status, lineage.Revision, lineage.SHA256)
}

func validTargetState(spec ChangeSetSpec) bool {
	if spec.Mutation == CompleteRemovalMutation && spec.StartingState.Status == RecoveryRequired && spec.StartingState.Revision == 0 && spec.StartingState.SHA256 == "" {
		return spec.TargetStateSHA256 == ""
	}
	return validSHA256(spec.TargetStateSHA256)
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
	case ActivatePreparedConfiguration, RestorePriorConfiguration, ApplyApprovedNetworkPolicy, OpenApprovedHTTP01, CloseRecordedHTTP01, RestorePriorNetworkPolicy, RemoveOwnedPublicExposure, RestoreOwnedPublicExposure, DeleteOwnedCloudflareResource, RestoreOwnedCloudflareResource, CreateCloudflareResource, DeleteCreatedCloudflareResource, ConfigureCloudflareTunnel, RestoreCloudflareTunnel, ConfigureCloudflareDNS, RestoreCloudflareDNS, ActivateCloudflaredService, RotateCloudflaredRunToken, RestoreCloudflaredService, StageCertificateCandidate, DiscardCertificateCandidate, OrderCertificateCandidate, PreserveCertificateLineage, ActivateCertificateServingPair, RestoreCertificateServingPair:
		return true
	}
	return false
}

func validStep(step Step) bool {
	base := validModule(step.owner) && validOperation(step.forward) && validOperation(step.rollback) && step.forward != step.rollback && step.cancel == SafeCheckpointCancellation && step.inspect == InspectBeforeIdempotentReverse
	if !base {
		return false
	}
	if step.removal != (RemovalChange{}) || removalOperation(step.forward) || removalOperation(step.rollback) {
		return step.firewall == (FirewallChange{}) && step.cloudflare.Action == "" && step.certificate.Action == "" && validRemovalContract(step)
	}
	if step.cloudflare.Action != "" || cloudflareOperation(step.forward) || cloudflareOperation(step.rollback) {
		return step.firewall == (FirewallChange{}) && step.removal == (RemovalChange{}) && step.certificate.Action == "" && validCloudflareContract(step)
	}
	if step.certificate.Action != "" || certificateOperation(step.forward) || certificateOperation(step.rollback) {
		return step.firewall == (FirewallChange{}) && step.removal == (RemovalChange{}) && step.cloudflare.Action == "" && validCertificateContract(step)
	}
	if step.owner == NetworkPolicyModule || networkOperation(step.forward) || networkOperation(step.rollback) {
		return step.owner == NetworkPolicyModule && step.rollback == RestorePriorNetworkPolicy && step.certificate.Action == "" && validFirewallContract(step.firewall, step.forward)
	}
	return step.firewall == (FirewallChange{}) && step.removal == (RemovalChange{}) && step.cloudflare.Action == "" && step.certificate.Action == ""
}

func certificateOperation(operation OperationKind) bool {
	return operation == StageCertificateCandidate || operation == DiscardCertificateCandidate || operation == OrderCertificateCandidate || operation == PreserveCertificateLineage || operation == ActivateCertificateServingPair || operation == RestoreCertificateServingPair
}

func validCertificateContract(step Step) bool {
	change := step.certificate
	address, addressErr := netip.ParseAddr(change.Identity)
	destination, destinationErr := netip.ParseAddr(change.DestinationIP)
	email, emailErr := mail.ParseAddress(change.OwnerEmail)
	ipBase := step.owner == CertificateModule && addressErr == nil && address.IsGlobalUnicast() && change.RequiredProfile == "shortlived" && change.CertName == "sbxr-ip" && change.DestinationIP == "" && change.DirectTLSRevision == 0 && change.DirectTLSSHA256 == ""
	domainBase := step.owner == CertificateModule && validCertificateHostname(change.Identity) && destinationErr == nil && destination.IsGlobalUnicast() && change.RequiredProfile == "tlsserver" && change.CertName == "sbxr-domain" && change.SubscriptionUnit == ""
	switch change.Action {
	case CertificateIPStage:
		return ipBase && step.forward == StageCertificateCandidate && step.rollback == DiscardCertificateCandidate && emailErr == nil && email.Address == change.OwnerEmail && email.Name == "" && change.ConfigDirectory == "/var/lib/sbxr/certbot/staging/sbxr-ip" && change.Account == "disposable-staging-sbxr-ip" && change.SubscriptionUnit == ""
	case CertificateIPOrder:
		return ipBase && step.forward == OrderCertificateCandidate && step.rollback == PreserveCertificateLineage && emailErr == nil && email.Address == change.OwnerEmail && email.Name == "" && change.ConfigDirectory == "/var/lib/sbxr/certbot/production" && change.Account == "production" && change.SubscriptionUnit == ""
	case CertificateIPActivate:
		return ipBase && step.forward == ActivateCertificateServingPair && step.rollback == RestoreCertificateServingPair && change.OwnerEmail == "" && change.ConfigDirectory == "" && change.Account == "" && change.SubscriptionUnit == "sbxr-subscription.service"
	case CertificateDomainStage:
		return domainBase && change.DirectTLSRevision == 0 && change.DirectTLSSHA256 == "" && step.forward == StageCertificateCandidate && step.rollback == DiscardCertificateCandidate && emailErr == nil && email.Address == change.OwnerEmail && email.Name == "" && change.ConfigDirectory == "/var/lib/sbxr/certbot/staging/sbxr-domain" && change.Account == "disposable-staging-sbxr-domain"
	case CertificateDomainOrder:
		return domainBase && change.DirectTLSRevision == 0 && change.DirectTLSSHA256 == "" && step.forward == OrderCertificateCandidate && step.rollback == PreserveCertificateLineage && emailErr == nil && email.Address == change.OwnerEmail && email.Name == "" && change.ConfigDirectory == "/var/lib/sbxr/certbot/production" && change.Account == "production"
	case CertificateDomainActivate:
		return domainBase && change.DirectTLSRevision > 0 && validSHA256(change.DirectTLSSHA256) && step.forward == ActivateCertificateServingPair && step.rollback == RestoreCertificateServingPair && change.OwnerEmail == "" && change.ConfigDirectory == "" && change.Account == ""
	}
	return false
}

func validCertificateHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 || strings.ToLower(hostname) != hostname {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func cloudflareOperation(operation OperationKind) bool {
	return operation == CreateCloudflareResource || operation == DeleteCreatedCloudflareResource || operation == ConfigureCloudflareTunnel || operation == RestoreCloudflareTunnel || operation == ConfigureCloudflareDNS || operation == RestoreCloudflareDNS || operation == ActivateCloudflaredService || operation == RotateCloudflaredRunToken || operation == RestoreCloudflaredService
}

func validCloudflareContract(step Step) bool {
	change := step.cloudflare
	if step.owner != CloudflareModule || !safeIdentity(change.AccountID) || change.TunnelID != "" && !safeIdentity(change.TunnelID) || change.TunnelIDFromStep < 0 || change.TunnelID != "" && change.TunnelIDFromStep != 0 {
		return false
	}
	validTunnel := change.TunnelID != "" || change.TunnelIDFromStep > 0
	switch change.Action {
	case CloudflareTunnelCreate:
		return step.forward == CreateCloudflareResource && step.rollback == DeleteCreatedCloudflareResource && change.ZoneID == "" && change.TunnelID == "" && change.TunnelIDFromStep == 0 && safeIdentity(change.TunnelName) && change.Hostname == "" && len(change.Routes) == 0
	case CloudflareRoutesPut:
		if step.forward != ConfigureCloudflareTunnel || step.rollback != RestoreCloudflareTunnel || !validTunnel || len(change.Routes) < 1 || change.Routes[len(change.Routes)-1] != (CloudflareRoute{Origin: "http_status:404"}) {
			return false
		}
		for index, route := range change.Routes {
			if index == len(change.Routes)-1 {
				continue
			}
			if route.Hostname == "" || route.Origin != "http://127.0.0.1:11080" && route.Origin != "http://127.0.0.1:11081" {
				return false
			}
		}
		return true
	case CloudflareDNSCreate:
		validType := change.RecordType == "CNAME" && validTunnel || (change.RecordType == "A" || change.RecordType == "AAAA") && change.Content != ""
		return step.forward == CreateCloudflareResource && step.rollback == DeleteCreatedCloudflareResource && safeIdentity(change.ZoneID) && change.Hostname != "" && validType && len(change.Routes) == 0
	case CloudflareDNSRepair:
		validType := change.RecordType == "CNAME" && change.Content != "" || (change.RecordType == "A" || change.RecordType == "AAAA") && change.Content != ""
		return step.forward == ConfigureCloudflareDNS && step.rollback == RestoreCloudflareDNS && safeIdentity(change.ZoneID) && safeIdentity(change.DNSRecordID) && change.Hostname != "" && validType && len(change.Routes) == 0
	case CloudflaredActivate:
		return step.forward == ActivateCloudflaredService && step.rollback == RestoreCloudflaredService && validTunnel && change.ZoneID == "" && change.Hostname == "" && len(change.Routes) == 0
	case CloudflareRunTokenActivate:
		if step.forward != RotateCloudflaredRunToken || step.rollback != RestoreCloudflaredService || !validTunnel || !safeIdentity(change.ZoneID) || !safeIdentity(change.XHTTPDNSRecordID) || !safeIdentity(change.WebSocketDNSRecordID) || change.DirectHostname == "" || len(change.Routes) != 3 || change.Routes[2] != (CloudflareRoute{Origin: "http_status:404"}) {
			return false
		}
		return (change.DirectIPv4RecordID == "") == (change.PublicIPv4 == "") && (change.DirectIPv6RecordID == "") == (change.PublicIPv6 == "") && (change.DirectIPv4RecordID == "" || safeIdentity(change.DirectIPv4RecordID)) && (change.DirectIPv6RecordID == "" || safeIdentity(change.DirectIPv6RecordID))
	}
	return false
}

func removalOperation(operation OperationKind) bool {
	return operation == RemoveOwnedPublicExposure || operation == RestoreOwnedPublicExposure || operation == DeleteOwnedCloudflareResource || operation == RestoreOwnedCloudflareResource
}

func validRemovalContract(step Step) bool {
	change := step.removal
	if !safeIdentity(change.ImmutableID) || !safeIdentity(change.ReviewID) || !validSHA256(change.InventorySHA256) {
		return false
	}
	switch change.Action {
	case PublicExposureRemoval:
		validResource := change.Resource == FirewallTableResource || change.Resource == PublicListenerResource || change.Resource == PublicServiceResource
		return validResource && step.owner == NetworkPolicyModule && step.forward == RemoveOwnedPublicExposure && step.rollback == RestoreOwnedPublicExposure && !change.CloudflareTokenActive && !change.CloudflareTokenAvailable
	case CloudflareRemoval:
		validResource := change.Resource == CloudflareDNSRecordResource || change.Resource == CloudflareRouteResource || change.Resource == CloudflareTunnelResource
		return validResource && step.owner == CloudflareModule && step.forward == DeleteOwnedCloudflareResource && step.rollback == RestoreOwnedCloudflareResource && change.CloudflareTokenActive && change.CloudflareTokenAvailable
	}
	return false
}

func validRemovalSteps(steps []Step) bool {
	publicInventory := map[string][]string{string(FirewallTableResource): {}, string(PublicListenerResource): {}, string(PublicServiceResource): {}}
	cloudflareInventory := map[string][]string{string(CloudflareDNSRecordResource): {}, string(CloudflareRouteResource): {}, string(CloudflareTunnelResource): {}}
	publicDigest, cloudflareDigest := "", ""
	externalStarted := false
	for _, step := range steps {
		change, ok := step.RemovalChange()
		if !ok {
			return false
		}
		if change.Action == PublicExposureRemoval {
			if externalStarted {
				return false
			}
			if publicDigest != "" && publicDigest != change.InventorySHA256 {
				return false
			}
			publicDigest = change.InventorySHA256
			publicInventory[string(change.Resource)] = append(publicInventory[string(change.Resource)], change.ImmutableID)
		} else if change.Action == CloudflareRemoval {
			externalStarted = true
			if cloudflareDigest != "" && cloudflareDigest != change.InventorySHA256 {
				return false
			}
			cloudflareDigest = change.InventorySHA256
			cloudflareInventory[string(change.Resource)] = append(cloudflareInventory[string(change.Resource)], change.ImmutableID)
		} else {
			return false
		}
	}
	actualPublic, publicValid := removalInventoryDigest(publicInventory, publicRemovalCategories)
	actualCloudflare, cloudflareValid := removalInventoryDigest(cloudflareInventory, cloudflareRemovalCategories)
	return publicValid && cloudflareValid && publicDigest != "" && cloudflareDigest != "" && actualPublic == publicDigest && actualCloudflare == cloudflareDigest
}

func networkOperation(operation OperationKind) bool {
	return operation == ApplyApprovedNetworkPolicy || operation == OpenApprovedHTTP01 || operation == CloseRecordedHTTP01 || operation == RestorePriorNetworkPolicy
}

func validFirewallContract(contract FirewallChange, operation OperationKind) bool {
	if contract.Action == HTTP01CloseAction {
		return operation == CloseRecordedHTTP01 && contract.Candidate == "" && contract.SSHPort == 0 && contract.TemporaryRuleIdentity == http01Identity
	}
	if contract.SSHPort == 0 || operation == ApplyApprovedNetworkPolicy && contract.Action != FirewallPolicyAction || operation == OpenApprovedHTTP01 && contract.Action != HTTP01OpenAction || !safeFirewallCandidate(contract.Candidate, contract.SSHPort) {
		return false
	}
	hasHTTP01 := strings.Count(contract.Candidate, `comment "`+http01Identity+`"`) == 1 && strings.Contains(contract.Candidate, `tcp dport 80 accept comment "`+http01Identity+`"`)
	return contract.Action == HTTP01OpenAction && contract.TemporaryRuleIdentity == http01Identity && hasHTTP01 || contract.Action == FirewallPolicyAction && contract.TemporaryRuleIdentity == "" && !strings.Contains(contract.Candidate, http01Identity)
}

func safeFirewallCandidate(candidate string, sshPort uint16) bool {
	if len(candidate) == 0 || len(candidate) > 64<<10 {
		return false
	}
	tokens := strings.Fields(strings.ToLower(candidate))
	if len(tokens) < 4 || tokens[0] != "table" || tokens[1] != "inet" || tokens[2] != "sbxr" || tokens[3] != "{" {
		return false
	}
	tables := 0
	for _, token := range tokens {
		token = strings.Trim(token, ";")
		if token == "table" {
			tables++
		}
		switch token {
		case "add", "insert", "replace", "delete", "destroy", "flush", "rename", "include", "define", "redefine":
			return false
		}
	}
	return tables == 1 && containsTCPPort(tokens, sshPort)
}

func containsTCPPort(tokens []string, port uint16) bool {
	want := fmt.Sprint(port)
	for index := 0; index+2 < len(tokens); index++ {
		if tokens[index] != "tcp" || tokens[index+1] != "dport" {
			continue
		}
		if strings.Trim(tokens[index+2], "{},;") == want {
			return true
		}
		if tokens[index+2] != "{" {
			continue
		}
		for cursor := index + 3; cursor < len(tokens) && tokens[cursor] != "}"; cursor++ {
			if strings.Trim(tokens[cursor], "{},;") == want {
				return true
			}
		}
	}
	return false
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
