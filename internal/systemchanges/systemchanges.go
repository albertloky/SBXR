// Package systemchanges owns SBXR's single installation-wide mutation boundary.
package systemchanges

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
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
	ActivatePreparedConfiguration  OperationKind = "Activate prepared configuration"
	RestorePriorConfiguration      OperationKind = "Restore prior configuration"
	ApplyApprovedNetworkPolicy     OperationKind = "Apply approved Network Policy"
	OpenApprovedHTTP01             OperationKind = "Open approved HTTP-01 rule"
	CloseRecordedHTTP01            OperationKind = "Close recorded HTTP-01 rule"
	RestorePriorNetworkPolicy      OperationKind = "Restore prior Network Policy"
	RemoveOwnedPublicExposure      OperationKind = "Remove owned public exposure"
	RestoreOwnedPublicExposure     OperationKind = "Restore owned public exposure"
	DeleteOwnedCloudflareResource  OperationKind = "Delete owned Cloudflare resource"
	RestoreOwnedCloudflareResource OperationKind = "Restore owned Cloudflare resource"
)

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
	owner    Module
	forward  OperationKind
	rollback OperationKind
	cancel   CancellationContract
	inspect  InspectionContract
	firewall FirewallChange
	removal  RemovalChange
}

func NewStep(owner Module, forward, rollback OperationKind) (Step, error) {
	if !validModule(owner) || !validOperation(forward) || !validOperation(rollback) || forward == rollback || owner == NetworkPolicyModule || networkOperation(forward) || networkOperation(rollback) || removalOperation(forward) || removalOperation(rollback) {
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
	review, categories, valid := validPermanentRemovalSelection(selection)
	authorityReview, resource, immutableID, inventory, proved := validPublicRemovalAuthority(authority)
	inventorySHA256, inventoryValid := removalInventoryDigest(inventory, publicRemovalCategories)
	if !valid || !proved || authorityReview != review || !inventoryValid || !inventoryContains(inventory, resource, immutableID) || !slices.Contains(categories, resource) {
		return Step{}, invalidRemovalStep()
	}
	return newRemovalStep(NetworkPolicyModule, RemoveOwnedPublicExposure, RestoreOwnedPublicExposure, RemovalChange{Action: PublicExposureRemoval, Resource: RemovalResource(resource), ImmutableID: immutableID, ReviewID: review, InventorySHA256: inventorySHA256})
}

func NewCloudflareRemovalStep(selection PermanentRemovalSelection, authority CloudflareRemovalAuthority) (Step, error) {
	review, categories, selected := validPermanentRemovalSelection(selection)
	authorityReview, resource, immutableID, inventory, tokenActive, tokenAvailable, proved := validCloudflareRemovalAuthority(authority)
	inventorySHA256, inventoryValid := removalInventoryDigest(inventory, cloudflareRemovalCategories)
	change := RemovalChange{Action: CloudflareRemoval, Resource: RemovalResource(resource), ImmutableID: immutableID, ReviewID: review, CloudflareTokenActive: tokenActive, CloudflareTokenAvailable: tokenAvailable, InventorySHA256: inventorySHA256}
	if !selected || !proved || authorityReview != review || !inventoryValid || !inventoryContains(inventory, resource, immutableID) || !slices.Contains(categories, resource) {
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
	SystemChangesPermanentRemovalSelection() (review string, categories []string, valid bool)
}

type CloudflareRemovalAuthority interface {
	SystemChangesCloudflareRemovalAuthority() (review, resource, immutableID string, inventory map[string][]string, tokenActive, tokenAvailable, valid bool)
}

type PublicRemovalAuthority interface {
	SystemChangesPublicRemovalAuthority() (review, resource, immutableID string, inventory map[string][]string, valid bool)
}

var completeRemovalCategories = []string{
	string(FirewallTableResource),
	string(PublicListenerResource),
	string(PublicServiceResource),
	string(CloudflareDNSRecordResource),
	string(CloudflareRouteResource),
	string(CloudflareTunnelResource),
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

func validPermanentRemovalSelection(selection PermanentRemovalSelection) (review string, categories []string, valid bool) {
	if !trustedAuthority(selection, "github.com/albertloky/SBXR/internal/ownerconsole", "PermanentRemovalSelection") {
		return "", nil, false
	}
	review, categories, valid = selection.SystemChangesPermanentRemovalSelection()
	got := append([]string(nil), categories...)
	want := append([]string(nil), completeRemovalCategories...)
	slices.Sort(got)
	slices.Sort(want)
	return review, categories, valid && safeIdentity(review) && slices.Equal(got, want)
}

func validCloudflareRemovalAuthority(authority CloudflareRemovalAuthority) (review, resource, immutableID string, inventory map[string][]string, tokenActive, tokenAvailable, valid bool) {
	if !trustedAuthority(authority, "github.com/albertloky/SBXR/internal/cloudflaretunnel", "RemovalAuthority") {
		return "", "", "", nil, false, false, false
	}
	review, resource, immutableID, inventory, tokenActive, tokenAvailable, valid = authority.SystemChangesCloudflareRemovalAuthority()
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
	selectionReview, _, selected := validPermanentRemovalSelection(spec.PermanentRemovalSelection)
	confirmedRemoval := spec.Mutation == CompleteRemovalMutation && typed && selected && confirmationReview == selectionReview
	validRemoval := validRemovalSteps(spec.Steps)
	if !safeIdentity(spec.Identity) || !validMutation(spec.Mutation) || !validModule(spec.OutcomeOwner) || !validStartingState(spec.StartingState, spec.Mutation) || !validSHA256(spec.TargetStateSHA256) || !safeIdentity(spec.Plan.Identity) || !validSHA256(spec.Plan.SHA256) || !validSHA256(spec.Plan.VolatileSHA256) || spec.PreparedState == nil || len(spec.Steps) == 0 || len(spec.Checks) == 0 || spec.Timeouts.Step <= 0 || spec.Timeouts.Step > maxStepTimeout || spec.Timeouts.Check <= 0 || spec.Timeouts.Check > maxCheckTimeout || spec.Disk.PreparationBytes == 0 || spec.Disk.TemporaryBytes == 0 || spec.Disk.SnapshotBytes == 0 || spec.Disk.JournalBytes == 0 || spec.Disk.RollbackBytes == 0 || spec.Disk.OverheadBytes == 0 || !diskValid || reserved > ^uint64(0)-largestFloor || spec.Mutation == CompleteRemovalMutation != confirmedRemoval || spec.Mutation == CompleteRemovalMutation != validRemoval || spec.Mutation == CompleteRemovalMutation && !removalStepsMatchReview(spec.Steps, selectionReview) || spec.Mutation != CompleteRemovalMutation && (spec.TypedRemovalConfirmation != nil || spec.PermanentRemovalSelection != nil) {
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
	AwaitingTokenRevocation ApplyOutcome = "Awaiting Cloudflare token revocation"
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
	return mutation == CompleteRemovalMutation && lineage.Status == RecoveryRequired && lineage.Revision > 0 && validSHA256(lineage.SHA256)
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
	case ActivatePreparedConfiguration, RestorePriorConfiguration, ApplyApprovedNetworkPolicy, OpenApprovedHTTP01, CloseRecordedHTTP01, RestorePriorNetworkPolicy, RemoveOwnedPublicExposure, RestoreOwnedPublicExposure, DeleteOwnedCloudflareResource, RestoreOwnedCloudflareResource:
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
		return step.firewall == (FirewallChange{}) && validRemovalContract(step)
	}
	if step.owner == NetworkPolicyModule || networkOperation(step.forward) || networkOperation(step.rollback) {
		return step.owner == NetworkPolicyModule && step.rollback == RestorePriorNetworkPolicy && validFirewallContract(step.firewall, step.forward)
	}
	return step.firewall == (FirewallChange{}) && step.removal == (RemovalChange{})
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
	return tables == 1 && strings.Contains(strings.Join(tokens, " "), fmt.Sprintf("tcp dport %d", sshPort))
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
