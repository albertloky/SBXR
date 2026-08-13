// Package installation owns the reviewed transition from Not installed to Managed.
package installation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const ReclamationPhrase = "RECLAIM THIS VPS"

type Draft struct {
	Tag, CloudflareAccountID, CloudflareZoneID, CloudflareToken string
	RealityTarget, RealityServerName                            string
	Architecture                                                softwarelifecycle.Architecture
	Installation                                                softwarelifecycle.InstallationDraft
}

type Dependencies struct {
	ReleaseCandidate  func(context.Context, string, softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error)
	Stage             func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
	Network           func(networkpolicy.Request) networkpolicy.Result
	Cloudflare        func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult
	CloudflareAPI     cloudflaretunnel.MutationAPI
	Inventory         cloudflaretunnel.MutationPlanner
	Entropy           io.Reader
	Launch            func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error)
	Recover           func(context.Context, systemchanges.PendingChangeSet) error
	Pending           systemchanges.PendingChangeSetReader
	WriteReceipt      func(string, softwarelifecycle.ReleaseIdentity, string) error
	RemoveReceipt     func() error
	ObserveState      func() (systemchanges.Observation, error)
	LoadManaged       func() (systemchanges.Observation, state.ReleaseIdentity, error)
	ProveSubscription func(context.Context, string, uint16) error
}

func (dependencies Dependencies) validate() error {
	if dependencies.ReleaseCandidate == nil || dependencies.Stage == nil || dependencies.Network == nil || dependencies.Cloudflare == nil || dependencies.CloudflareAPI == nil || dependencies.Inventory == nil || dependencies.Entropy == nil || dependencies.Launch == nil || dependencies.Recover == nil || dependencies.Pending == nil || dependencies.WriteReceipt == nil || dependencies.RemoveReceipt == nil || dependencies.ObserveState == nil || dependencies.LoadManaged == nil || dependencies.ProveSubscription == nil {
		return errors.New("Installation dependencies unavailable")
	}
	return nil
}

type InvalidInput struct{ Field, Problem string }

type Correction struct {
	Problem, Found, Required, WhyStopped, InputLabel, Evidence string
	FixWithSBXR                                                bool
	OwnerSteps                                                 []string
	Selections                                                 []Selection
}

type Selection struct{ Identity, Label string }

type Plan struct {
	Identity, DesiredStateSHA256                        string
	DesiredStateRevision                                uint64
	LineageUnavailable, ReclamationConfirmed            bool
	RelevantChecksums, VerifiedExternalInputs, Effects  []string
	RequiredChecks, AdvisoryChecks                      []string
	ObservedState, Interruption, Cancellation, Rollback string
	ReclamationDigest                                   string
}

type ReviewResult struct {
	Invalid     *InvalidInput
	Correction  *Correction
	Reclamation *Plan
	Plan        *Plan
	Approval    Approval
	Health      *ReviewedHealth
}

type ReviewedHealth struct {
	Installation healthdiagnostics.InstallationSummary
	Network      healthdiagnostics.HealthStatus
}

type ReclamationConfirmation struct{ Identity, Digest, Phrase string }

type Approval struct{ cell *approvalCell }
type approvalCell struct {
	used    atomic.Bool
	owner   *Interface
	request softwareubuntu.InstallHandoffRequest
	built   *builtInstall
}

func (Approval) String() string   { return "Installation Approval: redacted" }
func (Approval) GoString() string { return "Installation Approval: redacted" }
func (Approval) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Installation Approval cannot be rendered")
}

type OperationIdentity string
type ApplyKind uint8

const (
	ApplyStarted ApplyKind = iota + 1
	ApplyRefused
	CancellationRequested
)

type ApplyResult struct {
	Kind      ApplyKind
	Operation OperationIdentity
	Reason    string
}

type OperationStatus uint8

const (
	OperationActive OperationStatus = iota + 1
	Completed
	RolledBack
	RecoveryRequired
)

type Operation struct {
	Identity                   OperationIdentity
	Status                     OperationStatus
	CompletedSteps, TotalSteps uint16
	Checkpoint, Explanation    string
}

type Interface struct {
	dependencies Dependencies
	mu           sync.Mutex
	reclamation  *networkpolicy.ReclamationPlan
	request      softwareubuntu.InstallHandoffRequest
	approval     *approvalCell
	operation    Operation
	cancel       chan struct{}
	cancelled    bool
}

func New(dependencies Dependencies) (*Interface, error) {
	if err := dependencies.validate(); err != nil {
		return nil, err
	}
	return &Interface{dependencies: dependencies}, nil
}

func (*Interface) String() string   { return "Installation Module: protected" }
func (*Interface) GoString() string { return "Installation Module: protected" }

func (module *Interface) Review(ctx context.Context, draft Draft) ReviewResult {
	module.mu.Lock()
	module.approval, module.reclamation, module.request = nil, nil, softwareubuntu.InstallHandoffRequest{}
	module.mu.Unlock()
	if invalid := validateDraft(draft); invalid != nil {
		return ReviewResult{Invalid: invalid}
	}
	handoff, err := module.dependencies.ReleaseCandidate(ctx, draft.Tag, draft.Architecture)
	if err != nil {
		return correction(errors.New("the exact release could not be verified and staged"))
	}
	session, entropy := make([]byte, 32), make([]byte, 32)
	if _, err := io.ReadFull(module.dependencies.Entropy, session); err != nil {
		return correction(errors.New("installation identity generation failed"))
	}
	if _, err := io.ReadFull(module.dependencies.Entropy, entropy); err != nil {
		return correction(errors.New("installation entropy generation failed"))
	}
	request := softwareubuntu.InstallHandoffRequest{Schema: 1, Session: hex.EncodeToString(session), Tag: draft.Tag, Architecture: draft.Architecture, Draft: draft.Installation, CloudflareAccountID: draft.CloudflareAccountID, CloudflareZoneID: draft.CloudflareZoneID, CloudflareToken: draft.CloudflareToken, RealityTarget: draft.RealityTarget, RealityServerName: draft.RealityServerName, Entropy: entropy, Candidate: handoff}
	built, err := module.build(ctx, request)
	if err != nil {
		var reclaim *reclamationReviewError
		if errors.As(err, &reclaim) && reclaim.plan != nil {
			plan := reclamationPlan(reclaim.plan, false)
			if plan == nil {
				return reclamationCorrection()
			}
			module.mu.Lock()
			module.request, module.reclamation = request, reclaim.plan
			module.mu.Unlock()
			return ReviewResult{Reclamation: plan}
		}
		return correction(err)
	}
	module.mu.Lock()
	module.request, module.reclamation = softwareubuntu.InstallHandoffRequest{}, nil
	module.mu.Unlock()
	return module.finalReview(built, request, nil)
}

func (module *Interface) ConfirmReclamation(ctx context.Context, confirmation ReclamationConfirmation) ReviewResult {
	module.mu.Lock()
	reclamation, request := module.reclamation, module.request
	module.approval, module.reclamation, module.request = nil, nil, softwareubuntu.InstallHandoffRequest{}
	module.mu.Unlock()
	identity := ""
	if reclamation != nil && len(reclamation.Digest) == 64 {
		identity = "reclaim-vps-" + reclamation.Digest[:16]
	}
	if reclamation == nil || confirmation.Identity != identity || confirmation.Digest != reclamation.Digest || confirmation.Phrase != ReclamationPhrase {
		return ReviewResult{Invalid: &InvalidInput{Field: "reclamation-confirmation", Problem: "The exact current reclamation review and confirmation are required."}}
	}
	request.ReviewedReclamationSHA256 = reclamation.Digest
	built, err := module.build(ctx, request)
	if err != nil {
		return correction(err)
	}
	return module.finalReview(built, request, reclamation)
}

func (module *Interface) build(ctx context.Context, request softwareubuntu.InstallHandoffRequest) (*builtInstall, error) {
	return buildInstallWith(ctx, request, buildDependencies{stage: module.dependencies.Stage, network: module.dependencies.Network, cloudflare: module.dependencies.Cloudflare, random: newInstallEntropyReader(request.Entropy), cloudflareAPI: module.dependencies.CloudflareAPI, inventory: module.dependencies.Inventory})
}

func (module *Interface) finalReview(built *builtInstall, request softwareubuntu.InstallHandoffRequest, reclamation *networkpolicy.ReclamationPlan) ReviewResult {
	if built == nil || built.plan == nil {
		return correction(errors.New("complete install Plan unavailable"))
	}
	request.ReviewedPlanSHA256 = built.plan.SHA256()
	plan := finalPlan(built, request, reclamation)
	if plan == nil {
		return correction(errors.New("complete install Plan presentation unavailable"))
	}
	cell := &approvalCell{owner: module, request: request, built: built}
	module.mu.Lock()
	module.approval = cell
	module.mu.Unlock()
	return ReviewResult{Plan: plan, Approval: Approval{cell: cell}, Health: &ReviewedHealth{Installation: built.health, Network: healthdiagnostics.HealthStatus(built.wiring.network.Outcome)}}
}

func (module *Interface) Apply(_ context.Context, approval Approval) ApplyResult {
	if approval.cell == nil || approval.cell.owner != module || !approval.cell.used.CompareAndSwap(false, true) {
		return ApplyResult{Kind: ApplyRefused, Reason: "A fresh exact Installation Approval is required."}
	}
	module.mu.Lock()
	if module.approval != approval.cell {
		module.mu.Unlock()
		return ApplyResult{Kind: ApplyRefused, Reason: "A fresh exact Installation Approval is required."}
	}
	module.approval = nil
	if module.operation.Status == OperationActive {
		module.mu.Unlock()
		return ApplyResult{Kind: ApplyRefused, Reason: "One Installation operation is already active."}
	}
	request, built := approval.cell.request, approval.cell.built
	if built == nil || len(request.Session) < 16 {
		module.mu.Unlock()
		return ApplyResult{Kind: ApplyRefused, Reason: "The approved Installation facts are incomplete."}
	}
	operation := OperationIdentity("install-" + request.Session[:16])
	total := uint16(built.totalSteps)
	module.operation = Operation{Identity: operation, Status: OperationActive, TotalSteps: total, Checkpoint: "Awaiting verified sudo handoff", Explanation: "The reviewed installation is running."}
	module.cancel, module.cancelled = make(chan struct{}), false
	cancellation, launch := module.cancel, module.dependencies.Launch
	module.mu.Unlock()
	go func() {
		terminal, err := launch(context.Background(), request, cancellation)
		module.mu.Lock()
		defer module.mu.Unlock()
		switch {
		case err == nil && terminal == softwareubuntu.InstallCompleted:
			module.operation = Operation{Identity: operation, Status: Completed, CompletedSteps: total, TotalSteps: total, Checkpoint: "Complete", Explanation: "Desired State revision 1 and all required agreement checks passed."}
		case err == nil && terminal == softwareubuntu.InstallRolledBack:
			module.operation = Operation{Identity: operation, Status: RolledBack, TotalSteps: total, Checkpoint: "Rolled back", Explanation: "The privileged process proved rollback to Not installed."}
		default:
			module.operation = Operation{Identity: operation, Status: RecoveryRequired, TotalSteps: total, Checkpoint: "Installation stopped", Explanation: "The privileged installation did not prove Complete; inspect the durable recovery result."}
		}
	}()
	return ApplyResult{Kind: ApplyStarted, Operation: operation, Reason: "The exact reviewed installation Plan started."}
}

func (module *Interface) Inspect(_ context.Context, identity OperationIdentity) (Operation, error) {
	module.mu.Lock()
	defer module.mu.Unlock()
	if identity == "" || module.operation.Identity != identity {
		return Operation{}, errors.New("unknown or stale Installation Operation Identity")
	}
	return module.operation, nil
}

func (module *Interface) RequestCancellation(_ context.Context, identity OperationIdentity) ApplyResult {
	module.mu.Lock()
	defer module.mu.Unlock()
	if identity == "" || module.operation.Identity != identity || module.operation.Status != OperationActive || module.cancel == nil {
		return ApplyResult{Kind: ApplyRefused, Reason: "Cancellation requires the exact active Installation Operation Identity."}
	}
	if !module.cancelled {
		close(module.cancel)
		module.cancelled = true
	}
	return ApplyResult{Kind: CancellationRequested, Operation: identity, Reason: "Cancellation will roll back at the next declared safe checkpoint."}
}

func (module *Interface) Recover(ctx context.Context, pending systemchanges.PendingChangeSet) error {
	if pending.Kind != systemchanges.InstallationMutation || pending.Identity == "" {
		return errors.New("Installation recovery requires one proven unfinished initial Installation")
	}
	return module.dependencies.Recover(ctx, pending)
}

func validateDraft(draft Draft) *InvalidInput {
	values := []struct{ field, value string }{{"release-tag", draft.Tag}, {"domain", draft.Installation.Domain}, {"owner-email", draft.Installation.OwnerEmail}, {"public-ipv4", draft.Installation.PublicIPv4}, {"primary-address", draft.Installation.PrimaryAddress}, {"cloudflare-account", draft.CloudflareAccountID}, {"cloudflare-zone", draft.CloudflareZoneID}, {"cloudflare-token", draft.CloudflareToken}, {"reality-target", draft.RealityTarget}, {"reality-server-name", draft.RealityServerName}}
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			return &InvalidInput{Field: value.field, Problem: "A required Installation value is missing."}
		}
	}
	if draft.Architecture == "" || draft.Installation.SSHPort == 0 || draft.Installation.RealityPort == 0 || draft.Installation.Hysteria2Port == 0 || draft.Installation.TUICPort == 0 || draft.Installation.AnyTLSPort == 0 || draft.Installation.SubscriptionPort == 0 {
		return &InvalidInput{Field: "ports-or-architecture", Problem: "The Architecture and every required port must be valid."}
	}
	return nil
}

func correction(err error) ReviewResult {
	return ReviewResult{Correction: &Correction{Problem: "The installation Plan could not be built", Found: "One required release, provider, network, or installation input did not pass", Required: "Correct the named input or external fact, then check again", WhyStopped: "SBXR never continues with an incomplete or changed installation Plan", FixWithSBXR: true, InputLabel: "Corrected value", Evidence: "INSTALL-PLAN-REFUSED: " + err.Error()}}
}

func reclamationCorrection() ReviewResult {
	return ReviewResult{Correction: &Correction{Problem: "The exact reclamation Plan is too large to display", Found: "More than 64 safe effect rows are required", Required: "Remove unsupported or unrelated firewall complexity, then check again", WhyStopped: "SBXR never hides or truncates destructive Plan facts", OwnerSteps: []string{"Simplify the existing firewall policy or reimage the VPS, then run the check again."}, Selections: []Selection{{Identity: "firewall-simplified", Label: "The firewall policy is now simpler"}}, Evidence: "INSTALL-RECLAMATION-PLAN-TOO-LARGE"}}
}

func finalPlan(built *builtInstall, request softwareubuntu.InstallHandoffRequest, reclamation *networkpolicy.ReclamationPlan) *Plan {
	summary := built.plan.Summary()
	plan := &Plan{Identity: built.plan.Identity(), DesiredStateRevision: 1, DesiredStateSHA256: built.desiredSHA256, RelevantChecksums: []string{"Plan SHA-256 " + built.plan.SHA256()}, ObservedState: "Proven Clean VPS baseline: Not installed", VerifiedExternalInputs: []string{"Verified release " + summary.ReleaseIdentity.Tag, "Scoped Cloudflare account and zone authority", "Fresh Network Policy observations"}, Effects: installPlanEffects(), RequiredChecks: []string{"Pre-publication module health", "Desired State agreement", "Post-publication HTTPS, Tunnel, certificate, profile, unit, timer, and permission agreement"}, AdvisoryChecks: []string{"Direct DNS is pending only until the reviewed Cloudflare steps create it"}, Interruption: summary.Interruption, Cancellation: summary.Cancellation, Rollback: summary.Rollback}
	if reclamation == nil {
		return plan
	}
	effects, ok := reclamationPlanEffects(reclamation, 64-len(plan.Effects))
	if !ok || reclamation.Digest != request.ReviewedReclamationSHA256 {
		return nil
	}
	plan.RelevantChecksums = []string{"Plan SHA-256 " + built.plan.SHA256(), "Reclamation facts SHA-256 " + reclamation.Digest}
	plan.ObservedState = "Reclaimable VPS: exact reviewed conflict followed by revision-one installation"
	plan.VerifiedExternalInputs = []string{"Verified release " + summary.ReleaseIdentity.Tag, "Fresh Network Policy reclamation review"}
	plan.Effects = append(effects, plan.Effects...)
	plan.RequiredChecks = []string{"Fresh privileged reclamation proof", "Managed State and exact candidate agreement"}
	plan.AdvisoryChecks = nil
	plan.Interruption = "Before Irreversible reclamation started, cancellation rolls back; afterward recovery continues forward to Managed"
	plan.Cancellation = "Unavailable after Irreversible reclamation started"
	plan.Rollback = "No rollback exists after permanent reclamation starts"
	plan.ReclamationDigest, plan.ReclamationConfirmed = reclamation.Digest, true
	return plan
}

func reclamationPlan(plan *networkpolicy.ReclamationPlan, confirmed bool) *Plan {
	if plan == nil || len(plan.Digest) != 64 {
		return nil
	}
	effects, ok := reclamationPlanEffects(plan, 64)
	if !ok {
		return nil
	}
	if len(effects) == 0 {
		effects = []string{"Review the exact detected conflicts; change nothing"}
	}
	return &Plan{Identity: "reclaim-vps-" + plan.Digest[:16], LineageUnavailable: true, RelevantChecksums: []string{"Reclamation facts SHA-256 " + plan.Digest}, ObservedState: "Reclaimable VPS: exact read-only conflict facts", VerifiedExternalInputs: []string{"Fresh Network Policy host and conflict observations", "Protected Host Foundation version 1"}, Effects: effects, RequiredChecks: []string{"Fresh privileged recheck must match this exact digest before any later reclamation"}, AdvisoryChecks: []string{"Review-only confirmation grants no mutation authority"}, Interruption: plan.Interruption, Cancellation: plan.Cancellation, Rollback: plan.Rollback, ReclamationDigest: plan.Digest, ReclamationConfirmed: confirmed}
}

func installPlanEffects() []string {
	return []string{"Install the exact verified release and managed units", "Create six Connection Profiles and one HTTPS subscription", "Create one Cloudflare Tunnel and exact DNS records", "Issue and activate the IP and domain certificate lineages", "Publish Desired State revision 1 exactly once"}
}

func reclamationPlanEffects(plan *networkpolicy.ReclamationPlan, limit int) ([]string, bool) {
	if plan == nil {
		return nil, false
	}
	values := append(append(append([]string(nil), plan.Targets...), plan.Preservation...), plan.PermanentWarnings...)
	var effects []string
	for _, value := range values {
		for _, line := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
			for line != "" {
				end := min(len(line), 320)
				for end > 0 && end < len(line) && line[end]&0xc0 == 0x80 {
					end--
				}
				if end == 0 {
					return nil, false
				}
				effects, line = append(effects, line[:end]), line[end:]
				if len(effects) > limit {
					return nil, false
				}
			}
		}
	}
	return effects, true
}

func DefaultEntropy() io.Reader { return rand.Reader }

var _ fmt.Stringer = Approval{}
