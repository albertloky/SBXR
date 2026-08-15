// Package installation owns the reviewed transition from Not installed to Managed.
package installation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const ReclamationPhrase = "RECLAIM THIS VPS"

type Draft struct {
	SubmittedField, SubmittedValue                              string
	Tag, CloudflareAccountID, CloudflareZoneID, CloudflareToken string
	RealityTarget, RealityServerName                            string
	Architecture                                                softwarelifecycle.Architecture
	Installation                                                softwarelifecycle.InstallationDraft
	discard                                                     bool
}

func DiscardDraft() Draft { return Draft{discard: true} }

type Dependencies struct {
	Preflight           func() networkpolicy.InstallationPreflightResult
	RunningRelease      func() (RunningRelease, error)
	ReviewRealityTarget func(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview
	ReleaseCandidate    func(context.Context, string, softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error)
	Stage               func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
	Network             func(networkpolicy.Request) networkpolicy.Result
	Cloudflare          func(context.Context, cloudflaretunnel.PlanRequest) cloudflaretunnel.PlanResult
	CloudflareAPI       cloudflaretunnel.MutationAPI
	Inventory           cloudflaretunnel.MutationPlanner
	Entropy             io.Reader
	Launch              func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error)
	Recover             func(context.Context, systemchanges.PendingChangeSet) error
	Pending             systemchanges.PendingChangeSetReader
	WriteReceipt        func(string, softwarelifecycle.ReleaseIdentity, string) error
	RemoveReceipt       func() error
	ObserveState        func() (systemchanges.Observation, error)
	LoadManaged         func() (systemchanges.Observation, state.ReleaseIdentity, error)
	ProveSubscription   func(context.Context, string, uint16) error
}

func (dependencies Dependencies) validate() error {
	if dependencies.Preflight == nil || dependencies.RunningRelease == nil || dependencies.ReviewRealityTarget == nil || dependencies.ReleaseCandidate == nil || dependencies.Stage == nil || dependencies.Network == nil || dependencies.Cloudflare == nil || dependencies.CloudflareAPI == nil || dependencies.Inventory == nil || dependencies.Entropy == nil || dependencies.Launch == nil || dependencies.Recover == nil || dependencies.Pending == nil || dependencies.WriteReceipt == nil || dependencies.RemoveReceipt == nil || dependencies.ObserveState == nil || dependencies.LoadManaged == nil || dependencies.ProveSubscription == nil {
		return errors.New("Installation dependencies unavailable")
	}
	return nil
}

type RunningRelease struct {
	Tag          string
	Architecture softwarelifecycle.Architecture
}

type ReviewFact struct{ Label, Value string }

type FieldSensitivity uint8

const PublicInformation FieldSensitivity = 1

type FieldHelp struct {
	Purpose, AcceptedFormat, Example, URL string
	Instructions, CommonMistakes          []string
	Sensitivity                           FieldSensitivity
}

type InvalidInput struct {
	Field, Value, Problem string
	Detected              bool
	Facts                 []ReviewFact
	Help                  FieldHelp
}

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
	dependencies   Dependencies
	mu             sync.Mutex
	draft          Draft
	reclamation    *networkpolicy.ReclamationPlan
	request        softwareubuntu.InstallHandoffRequest
	approval       *approvalCell
	operation      Operation
	cancel         chan struct{}
	cancelled      bool
	nextField      int
	initialized    bool
	reviewFacts    []ReviewFact
	detectedIPv4   bool
	ipv4Candidates []string
}

func New(dependencies Dependencies) (*Interface, error) {
	if err := dependencies.validate(); err != nil {
		return nil, err
	}
	return &Interface{dependencies: dependencies, draft: initialDraft()}, nil
}

func (*Interface) String() string   { return "Installation Module: protected" }
func (*Interface) GoString() string { return "Installation Module: protected" }

func (module *Interface) Review(ctx context.Context, draft Draft) ReviewResult {
	module.mu.Lock()
	if draft.discard {
		module.resetDraft()
	}
	if !module.initialized {
		if correction := module.initializeDraft(); correction != nil {
			module.mu.Unlock()
			return ReviewResult{Correction: correction}
		}
	}
	if draft.SubmittedField != "" {
		if module.nextField >= len(draftFields) || draft.SubmittedField != draftFields[module.nextField] {
			field := draftFields[min(module.nextField, len(draftFields)-1)]
			result := module.invalidDraftField(module.draft, field, "Submit the current Installation field before continuing.")
			module.mu.Unlock()
			return ReviewResult{Invalid: result}
		}
		value := draft.SubmittedValue
		if value == "" {
			value = draftFieldValue(draft, draft.SubmittedField)
		}
		if strings.TrimSpace(value) == "" {
			invalid := &InvalidInput{Field: draft.SubmittedField, Problem: "A required Installation value is missing."}
			module.attachReviewFacts(invalid)
			module.mu.Unlock()
			return ReviewResult{Invalid: invalid}
		}
		candidate, err := updateDraftField(module.draft, draft.SubmittedField, value)
		if err != nil {
			invalid := &InvalidInput{Field: draft.SubmittedField, Value: value, Problem: err.Error()}
			module.attachReviewFacts(invalid)
			module.mu.Unlock()
			return ReviewResult{Invalid: invalid}
		}
		if invalid := validateDraftField(candidate, draft.SubmittedField); invalid != nil {
			module.attachReviewFacts(invalid)
			module.mu.Unlock()
			return ReviewResult{Invalid: invalid}
		}
		if draft.SubmittedField == "reality-target" {
			if invalid := module.reviewRealityTarget(ctx, candidate); invalid != nil {
				module.mu.Unlock()
				return ReviewResult{Invalid: invalid}
			}
		}
		module.draft, module.nextField = candidate, module.nextField+1
		if validateDraft(candidate) == nil {
			module.nextField = len(draftFields)
		}
	} else if draft != (Draft{}) {
		module.draft = mergeDraft(module.draft, draft)
		if invalid := validateDraft(module.draft); invalid != nil {
			module.nextField = draftFieldIndex(invalid.Field)
		} else if invalid := module.reviewRealityTarget(ctx, module.draft); invalid != nil {
			module.nextField = draftFieldIndex(invalid.Field)
			module.mu.Unlock()
			return ReviewResult{Invalid: invalid}
		} else {
			module.nextField = len(draftFields)
		}
	}
	draft = module.draft
	module.approval, module.reclamation, module.request = nil, nil, softwareubuntu.InstallHandoffRequest{}
	if module.nextField < len(draftFields) {
		invalid := module.invalidDraftField(draft, draftFields[module.nextField], "Submit this Installation field to continue.")
		module.mu.Unlock()
		return ReviewResult{Invalid: invalid}
	}
	module.mu.Unlock()
	if invalid := validateDraft(draft); invalid != nil {
		module.mu.Lock()
		module.attachReviewFacts(invalid)
		module.mu.Unlock()
		return ReviewResult{Invalid: invalid}
	}
	handoff, err := module.dependencies.ReleaseCandidate(ctx, draft.Tag, draft.Architecture)
	if err != nil {
		return ReviewResult{Correction: &Correction{Problem: "The verified running release could not be staged", Found: "the running Release Identity is no longer available as the exact Installation candidate", Required: "the same verified running release must remain available", WhyStopped: "Installation never asks the Owner to replace the running Release Identity", OwnerSteps: []string{"Check the release connection, then check again. If the exact release is unavailable, restart through the current qualified Pasteable Install Command."}, Evidence: "INSTALL-RUNNING-RELEASE-UNAVAILABLE"}}
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

func (module *Interface) initializeDraft() *Correction {
	preflight := module.dependencies.Preflight()
	if preflight.Failure != nil {
		failure := preflight.Failure
		return &Correction{Problem: failure.Problem, Found: failure.Found, Required: failure.Required, WhyStopped: failure.WhyStopped, OwnerSteps: append([]string(nil), failure.Fix.OwnerChecklist...), Evidence: failure.Code}
	}
	release, err := module.dependencies.RunningRelease()
	if err != nil || release.Tag == "" || release.Architecture == "" || preflight.ActiveSSHPort == 0 {
		return &Correction{Problem: "The verified running Installation facts are unavailable", Found: "the running Release Identity or active SSH port could not be proved", Required: "one verified running release and one proven active SSH session", WhyStopped: "Installation never asks the Owner to re-enter facts that SBXR must prove", OwnerSteps: []string{"Restart Installation through the verified Pasteable Install Command after SSH access is restored."}, Evidence: "INSTALL-RUNTIME-FACTS-UNPROVED"}
	}
	module.draft.Tag, module.draft.Architecture, module.draft.Installation.SSHPort = release.Tag, release.Architecture, preflight.ActiveSSHPort
	module.ipv4Candidates = append([]string(nil), preflight.UsablePublicIPv4...)
	if len(preflight.UsablePublicIPv4) == 1 {
		module.draft.Installation.PublicIPv4 = preflight.UsablePublicIPv4[0]
		module.draft.Installation.PrimaryAddress = preflight.UsablePublicIPv4[0]
		module.detectedIPv4 = true
	}
	module.reviewFacts = []ReviewFact{{Label: "Running release tag", Value: release.Tag}, {Label: "Active SSH port", Value: fmt.Sprint(preflight.ActiveSSHPort)}}
	module.initialized = true
	return nil
}

func (module *Interface) resetDraft() {
	module.draft, module.nextField, module.initialized = initialDraft(), 0, false
	module.reviewFacts, module.detectedIPv4, module.ipv4Candidates = nil, false, nil
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
	module.draft = Draft{}
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
	module.operation = Operation{Identity: operation, Status: OperationActive, TotalSteps: total, Checkpoint: "Awaiting fresh root recheck", Explanation: "The reviewed installation is running."}
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

func mergeDraft(current, update Draft) Draft {
	if update.discard {
		return initialDraft()
	}
	if update.Installation.PublicIPv4 != "" {
		current.Installation.PublicIPv4 = update.Installation.PublicIPv4
		current.Installation.PrimaryAddress = update.Installation.PublicIPv4
	}
	if update.RealityTarget != "" {
		host, port, err := net.SplitHostPort(update.RealityTarget)
		if err == nil && port == "443" {
			current.RealityTarget, current.RealityServerName = update.RealityTarget, host
		} else {
			current.RealityTarget, current.RealityServerName = net.JoinHostPort(update.RealityTarget, "443"), update.RealityTarget
		}
	}
	for target, value := range map[*string]string{
		&current.CloudflareAccountID:     update.CloudflareAccountID,
		&current.CloudflareZoneID:        update.CloudflareZoneID,
		&current.CloudflareToken:         update.CloudflareToken,
		&current.Installation.Domain:     update.Installation.Domain,
		&current.Installation.OwnerEmail: update.Installation.OwnerEmail,
		&current.Installation.PublicIPv6: update.Installation.PublicIPv6,
	} {
		if value != "" {
			*target = value
		}
	}
	for target, value := range map[*uint16]uint16{
		&current.Installation.RealityPort:      update.Installation.RealityPort,
		&current.Installation.Hysteria2Port:    update.Installation.Hysteria2Port,
		&current.Installation.TUICPort:         update.Installation.TUICPort,
		&current.Installation.AnyTLSPort:       update.Installation.AnyTLSPort,
		&current.Installation.SubscriptionPort: update.Installation.SubscriptionPort,
	} {
		if value != 0 {
			*target = value
		}
	}
	return current
}

func updateDraftField(current Draft, field, value string) (Draft, error) {
	port := func() (uint16, error) {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil || parsed == 0 {
			return 0, errors.New("The Installation port is invalid.")
		}
		return uint16(parsed), nil
	}
	var err error
	switch field {
	case "domain":
		current.Installation.Domain = value
	case "owner-email":
		current.Installation.OwnerEmail = value
	case "public-ipv4":
		current.Installation.PublicIPv4 = value
		current.Installation.PrimaryAddress = value
	case "reality-port":
		current.Installation.RealityPort, err = port()
	case "hysteria2-port":
		current.Installation.Hysteria2Port, err = port()
	case "tuic-port":
		current.Installation.TUICPort, err = port()
	case "anytls-port":
		current.Installation.AnyTLSPort, err = port()
	case "subscription-port":
		current.Installation.SubscriptionPort, err = port()
	case "cloudflare-account":
		current.CloudflareAccountID = value
	case "cloudflare-zone":
		current.CloudflareZoneID = value
	case "cloudflare-token":
		current.CloudflareToken = value
	case "reality-target":
		current.RealityTarget, current.RealityServerName = net.JoinHostPort(value, "443"), value
	default:
		return current, errors.New("The Installation field is unknown.")
	}
	return current, err
}

var (
	draftFields = []string{"domain", "owner-email", "public-ipv4", "reality-port", "hysteria2-port", "tuic-port", "anytls-port", "subscription-port", "cloudflare-account", "cloudflare-zone", "cloudflare-token", "reality-target"}
	draftDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	draftID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	draftTag    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

var domainHelp = FieldHelp{
	Purpose:        "Choose the public domain that SBXR will use for its managed hostnames.",
	Instructions:   []string{"Enter a domain that you own and can manage in Cloudflare."},
	AcceptedFormat: "Lowercase DNS name without a scheme, path, port, or trailing dot.",
	CommonMistakes: []string{"Do not enter https://, a URL path, a port, or a domain that you do not control."},
	Example:        "vpn.example",
	URL:            "https://developers.cloudflare.com/fundamentals/manage-domains/add-site/",
	Sensitivity:    PublicInformation,
}

func initialDraft() Draft {
	return Draft{Installation: softwarelifecycle.InstallationDraft{RealityPort: 443, Hysteria2Port: 443, TUICPort: 8443, AnyTLSPort: 9443, SubscriptionPort: 10443}}
}

func draftFieldIndex(field string) int {
	for index, candidate := range draftFields {
		if candidate == field {
			return index
		}
	}
	return 0
}

func (module *Interface) invalidDraftField(draft Draft, field, problem string) *InvalidInput {
	invalid := &InvalidInput{Field: field, Value: draftFieldValue(draft, field), Problem: problem}
	module.attachReviewFacts(invalid)
	return invalid
}

func (module *Interface) attachReviewFacts(invalid *InvalidInput) {
	invalid.Facts = append([]ReviewFact(nil), module.reviewFacts...)
	if invalid.Field == "domain" {
		invalid.Help = domainHelp
		invalid.Help.Instructions = append([]string(nil), domainHelp.Instructions...)
		invalid.Help.CommonMistakes = append([]string(nil), domainHelp.CommonMistakes...)
	}
	if invalid.Field == "public-ipv4" {
		invalid.Detected = module.detectedIPv4
		if !module.detectedIPv4 {
			invalid.Facts = append(invalid.Facts, ReviewFact{Label: "Public IPv4 guidance", Value: "Find the public IPv4 in the VPS provider network details, then enter the final address here."})
			if len(module.ipv4Candidates) > 1 {
				invalid.Facts = append(invalid.Facts, ReviewFact{Label: "Detected Public IPv4 candidates", Value: strings.Join(module.ipv4Candidates, ", ")})
			}
		}
	}
}

func draftFieldValue(draft Draft, field string) string {
	switch field {
	case "domain":
		return draft.Installation.Domain
	case "owner-email":
		return draft.Installation.OwnerEmail
	case "public-ipv4":
		return draft.Installation.PublicIPv4
	case "reality-port":
		return portText(draft.Installation.RealityPort)
	case "hysteria2-port":
		return portText(draft.Installation.Hysteria2Port)
	case "tuic-port":
		return portText(draft.Installation.TUICPort)
	case "anytls-port":
		return portText(draft.Installation.AnyTLSPort)
	case "subscription-port":
		return portText(draft.Installation.SubscriptionPort)
	case "cloudflare-account":
		return draft.CloudflareAccountID
	case "cloudflare-zone":
		return draft.CloudflareZoneID
	case "cloudflare-token":
		return draft.CloudflareToken
	case "reality-target":
		return draft.RealityServerName
	default:
		return ""
	}
}

func portText(port uint16) string {
	if port == 0 {
		return ""
	}
	return strconv.Itoa(int(port))
}

func validateDraftField(draft Draft, field string) *InvalidInput {
	value := draftFieldValue(draft, field)
	invalid := func(problem string) *InvalidInput { return &InvalidInput{Field: field, Value: value, Problem: problem} }
	if strings.TrimSpace(value) == "" {
		return invalid("A required Installation value is missing.")
	}
	switch field {
	case "domain":
		if value == domainHelp.Example {
			return invalid("The Domain is a tutorial example and cannot become Desired State.")
		}
		if !draftDomain.MatchString(value) {
			return invalid("The Domain is invalid.")
		}
	case "owner-email":
		address, err := mail.ParseAddress(value)
		if err != nil || address.Name != "" || address.Address != value {
			return invalid("The Owner email is invalid.")
		}
	case "public-ipv4":
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || !networkpolicy.UsablePublicAddress(value) {
			return invalid("The Public IPv4 is invalid.")
		}
	case "cloudflare-account", "cloudflare-zone":
		if !draftID.MatchString(value) {
			return invalid("The Cloudflare identifier is invalid.")
		}
	case "cloudflare-token":
		if _, err := cloudflaretunnel.NewManagementToken(value); err != nil {
			return invalid("The Cloudflare Account API Token is invalid.")
		}
	}
	return nil
}

func (module *Interface) reviewRealityTarget(ctx context.Context, draft Draft) *InvalidInput {
	target := connectionprofiles.RealityTarget{Address: draft.RealityTarget, ServerName: draft.RealityServerName}
	review := module.dependencies.ReviewRealityTarget(ctx, target)
	if review.Target.Address == target.Address && review.Target.ServerName == target.ServerName && review.Health.Outcome == connectionprofiles.Healthy {
		return nil
	}
	invalid := &InvalidInput{Field: "reality-target", Value: draft.RealityServerName, Problem: review.Health.Problem}
	module.attachReviewFacts(invalid)
	flow := review.Health.CorrectionFlow()
	guidance := flow.OwnerWork
	if guidance == "" {
		guidance = flow.FixWithSBXR
	}
	if guidance != "" {
		invalid.Facts = append(invalid.Facts, ReviewFact{Label: "REALITY target correction", Value: guidance})
	}
	if review.Health.Code != "" {
		invalid.Facts = append(invalid.Facts, ReviewFact{Label: "REALITY target evidence", Value: review.Health.Code})
	}
	return invalid
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
	if identity == "" && module.operation.Status != OperationActive {
		module.resetDraft()
		module.approval, module.reclamation, module.request = nil, nil, softwareubuntu.InstallHandoffRequest{}
		return ApplyResult{Kind: CancellationRequested, Reason: "The unfinished Installation input was discarded."}
	}
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
	if !draftTag.MatchString(draft.Tag) || draft.Architecture == "" || draft.Installation.SSHPort == 0 {
		return &InvalidInput{Field: "domain", Problem: "The verified running Release Identity or active SSH port is invalid."}
	}
	for _, field := range draftFields {
		if invalid := validateDraftField(draft, field); invalid != nil {
			return invalid
		}
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
	plan.Effects = append(plan.Effects, fmt.Sprintf("Use SSH %d/TCP, REALITY %d/TCP, Hysteria2 %d/UDP, TUIC %d/UDP, AnyTLS %d/TCP, and Subscription HTTPS %d/TCP", request.Draft.SSHPort, request.Draft.RealityPort, request.Draft.Hysteria2Port, request.Draft.TUICPort, request.Draft.AnyTLSPort, request.Draft.SubscriptionPort))
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
	return []string{
		"Install the exact verified release and managed units",
		"Run xray.service, sing-box.service, cloudflared.service, and sbxr-subscription.service as root:root without separate Linux identities",
		"Retain NoNewPrivileges=true, ProtectHome=true, ProtectSystem=strict, AmbientCapabilities=CAP_NET_BIND_SERVICE, and CapabilityBoundingSet=CAP_NET_BIND_SERVICE for Xray and sing-box",
		"Retain NoNewPrivileges=true, ProtectHome=true, ProtectSystem=strict, and PrivateTmp=true for cloudflared",
		"Retain UMask=0027, NoNewPrivileges=true, PrivateTmp=true, ProtectHome=true, ProtectSystem=strict, PrivateDevices=true, ProtectControlGroups=true, ProtectKernelModules=true, ProtectKernelTunables=true, ProtectProc=invisible, and ProcSubset=pid for Subscription Serving",
		"Retain RestrictAddressFamilies=AF_INET AF_INET6, RestrictSUIDSGID=true, LockPersonality=true, MemoryDenyWriteExecute=true, LimitCORE=0, TemporaryFileSystem=/:ro, BindReadOnlyPaths=/usr/local/bin/sbxr, BindReadOnlyPaths=/var/lib/sbxr/subscriptions/current, BindReadOnlyPaths=/var/lib/sbxr/certificates/ip/current, and BindReadOnlyPaths=/etc/ssl/certs/ca-certificates.crt for Subscription Serving",
		"Store runtime service configuration, proxy credentials, subscription material, the Cloudflare Tunnel run token, and TLS private keys as root:root 0644",
		"Every local Linux identity can read the runtime proxy credentials, subscription material, Cloudflare Tunnel run token, and TLS private keys",
		"Create six Connection Profiles and one HTTPS subscription",
		"Create one Cloudflare Tunnel and exact DNS records",
		"Issue and activate the IP and domain certificate lineages",
		"Publish Desired State revision 1 exactly once",
	}
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
