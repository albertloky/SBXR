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

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const ReclamationPhrase = "RECLAIM THIS VPS"

type ConfirmationGuidance struct {
	Title string
	Lines []string
}

func ReclamationConfirmationGuidance() ConfirmationGuidance {
	return ConfirmationGuidance{Title: "RECLAIM THIS VPS HELP", Lines: []string{
		"RECLAIM THIS VPS authorizes only the conflicts in this exact reviewed Plan.",
		"Reclamation Boundary: without autoremove, delete only freshly re-proved conflict files, scripts, and identities.",
		"May replace inbound firewall and Docker; preserves SSH, outbound traffic, images, volumes, and application data.",
		"Protected Host Foundation preserves the OS, package tools, current shell, SSH access, and recovery dependencies.",
		"Before Irreversible Reclamation Started, return changes nothing; after it, only forward recovery to Managed remains.",
		"Help does not confirm RECLAIM THIS VPS, approve the reviewed Plan, or start Apply.",
	}}
}

type Draft struct {
	SubmittedField, SubmittedValue   string
	Tag                              string
	RealityTarget, RealityServerName string
	Architecture                     softwarelifecycle.Architecture
	Installation                     softwarelifecycle.InstallationDraft
	discard                          bool
}

func DiscardDraft() Draft { return Draft{discard: true} }

type Dependencies struct {
	Preflight                func() networkpolicy.InstallationPreflightResult
	RunningRelease           func() (RunningRelease, error)
	RecommendedRealityTarget string
	ReviewRealityTarget      func(context.Context, connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview
	ReleaseCandidate         func(context.Context, string, softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error)
	Stage                    func(context.Context, softwarelifecycle.StageRequest) (softwarelifecycle.StagedRelease, error)
	Network                  func(networkpolicy.Request) networkpolicy.Result
	Entropy                  io.Reader
	Launch                   func(context.Context, softwareubuntu.InstallHandoffRequest, <-chan struct{}) (softwareubuntu.InstallApplyOutcome, error)
	Recover                  func(context.Context, systemchanges.PendingChangeSet) error
	Pending                  systemchanges.PendingChangeSetReader
	WriteReceipt             func(string, softwarelifecycle.ReleaseIdentity, string) error
	RemoveReceipt            func() error
	ObserveState             func() (systemchanges.Observation, error)
	LoadManaged              func() (systemchanges.Observation, state.ReleaseIdentity, error)
	ProveSubscription        func(context.Context, string, uint16) error
}

func (dependencies Dependencies) validate() error {
	if dependencies.Preflight == nil || dependencies.RunningRelease == nil || dependencies.ReviewRealityTarget == nil || dependencies.ReleaseCandidate == nil || dependencies.Stage == nil || dependencies.Network == nil || dependencies.Entropy == nil || dependencies.Launch == nil || dependencies.Recover == nil || dependencies.Pending == nil || dependencies.WriteReceipt == nil || dependencies.RemoveReceipt == nil || dependencies.ObserveState == nil || dependencies.LoadManaged == nil || dependencies.ProveSubscription == nil {
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

const (
	PublicInformation FieldSensitivity = iota + 1
	PersonalInformation
	InfrastructureSecret
)

type FieldHelp struct {
	Purpose, AcceptedFormat, Recovery, Example, URL string
	Instructions, CommonMistakes                    []string
	Sensitivity                                     FieldSensitivity
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
	SSHFailureCause                                            networkpolicy.SSHPreservationFailureCause
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
	ConfirmationHelp                                    ConfirmationGuidance
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
	dependencies        Dependencies
	mu                  sync.Mutex
	draft               Draft
	reclamation         *networkpolicy.ReclamationPlan
	request             softwareubuntu.InstallHandoffRequest
	approval            *approvalCell
	operation           Operation
	cancel              chan struct{}
	cancelled           bool
	nextField           int
	fields              []string
	initialized         bool
	reviewFacts         []ReviewFact
	ipv4Candidates      []string
	ipv6Candidates      []string
	sshProof            networkpolicy.SSHPreservationProof
	reclamationSSHProof networkpolicy.SSHPreservationProof
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
	realityReviewed := false
	if draft.discard {
		module.resetDraft()
	}
	if !module.initialized {
		if correction := module.initializeDraft(ctx); correction != nil {
			module.mu.Unlock()
			return ReviewResult{Correction: correction}
		}
	}
	if draft.SubmittedField != "" {
		if module.nextField >= len(module.fields) || draft.SubmittedField != module.fields[module.nextField] {
			field := module.fields[min(module.nextField, len(module.fields)-1)]
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
			realityReviewed = true
		}
		module.draft, module.nextField = candidate, module.nextField+1
	} else if draft != (Draft{}) {
		module.draft = mergeDraft(module.draft, draft)
		if invalid := validateDraft(module.draft); invalid != nil {
			module.nextField = module.draftFieldIndex(invalid.Field)
		} else {
			module.nextField = len(module.fields)
		}
	}
	if module.nextField >= len(module.fields) {
		if invalid := validateDraft(module.draft); invalid != nil {
			module.nextField = module.draftFieldIndex(invalid.Field)
			module.attachReviewFacts(invalid)
			module.mu.Unlock()
			return ReviewResult{Invalid: invalid}
		}
		if !realityReviewed {
			if invalid := module.reviewRealityTarget(ctx, module.draft); invalid != nil {
				module.nextField = module.draftFieldIndex(invalid.Field)
				module.mu.Unlock()
				return ReviewResult{Invalid: invalid}
			}
		}
	}
	draft, sshProof := module.draft, module.sshProof
	module.approval, module.reclamation, module.request = nil, nil, softwareubuntu.InstallHandoffRequest{}
	if module.nextField < len(module.fields) {
		invalid := module.invalidDraftField(draft, module.fields[module.nextField], "Submit this Installation field to continue.")
		module.mu.Unlock()
		return ReviewResult{Invalid: invalid}
	}
	module.mu.Unlock()
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
	request := softwareubuntu.InstallHandoffRequest{Schema: 1, Session: hex.EncodeToString(session), Tag: draft.Tag, Architecture: draft.Architecture, Draft: draft.Installation, RealityTarget: draft.RealityTarget, RealityServerName: draft.RealityServerName, Entropy: entropy, Candidate: handoff}
	built, err := module.build(ctx, request, sshProof)
	if err != nil {
		var reclaim *reclamationReviewError
		if errors.As(err, &reclaim) && reclaim.plan != nil {
			plan := reclamationPlan(reclaim.plan, false)
			if plan == nil {
				return reclamationCorrection()
			}
			module.mu.Lock()
			module.request, module.reclamation, module.reclamationSSHProof = request, reclaim.plan, sshProof
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

func (module *Interface) initializeDraft(ctx context.Context) *Correction {
	preflight := module.dependencies.Preflight()
	if preflight.Failure != nil {
		failure := preflight.Failure
		return &Correction{Problem: failure.Problem, Found: failure.Found, Required: failure.Required, WhyStopped: failure.WhyStopped, OwnerSteps: append([]string(nil), failure.Fix.OwnerChecklist...), Evidence: failure.Code, SSHFailureCause: preflight.SSHFailureCause}
	}
	release, err := module.dependencies.RunningRelease()
	if err != nil || release.Tag == "" || release.Architecture == "" || preflight.ActiveSSHPort == 0 {
		return &Correction{Problem: "The verified running Installation facts are unavailable", Found: "the running Release Identity or active SSH port could not be proved", Required: "one verified running release and one proven active SSH session", WhyStopped: "Installation never asks the Owner to re-enter facts that SBXR must prove", OwnerSteps: []string{"Restart Installation through the verified Pasteable Install Command after SSH access is restored."}, Evidence: "INSTALL-RUNTIME-FACTS-UNPROVED"}
	}
	module.draft.Tag, module.draft.Architecture, module.draft.Installation.SSHPort = release.Tag, release.Architecture, preflight.ActiveSSHPort
	module.sshProof = preflight.SSHPreservationProof()
	module.ipv4Candidates = append([]string(nil), preflight.UsablePublicIPv4...)
	module.ipv6Candidates = append([]string(nil), preflight.UsablePublicIPv6...)
	if len(preflight.UsablePublicIPv4) > 1 || len(preflight.UsablePublicIPv6) > 1 || len(preflight.UsablePublicIPv4)+len(preflight.UsablePublicIPv6) == 0 {
		return &Correction{Problem: "The public address selection is ambiguous", Found: "Installation did not prove exactly zero or one usable address in each family", Required: "one usable public IPv4, one usable public IPv6, or one of each", WhyStopped: "Installation cannot ask for an address outside the conditional primary-address contract", OwnerSteps: []string{"Remove unused public addresses or correct the VPS network assignment, then use Check again."}, Evidence: "INSTALL-PUBLIC-ADDRESS-AMBIGUOUS"}
	}
	if len(preflight.UsablePublicIPv4) == 1 {
		module.draft.Installation.PublicIPv4 = preflight.UsablePublicIPv4[0]
	}
	if len(preflight.UsablePublicIPv6) == 1 {
		module.draft.Installation.PublicIPv6 = preflight.UsablePublicIPv6[0]
	}
	module.reviewFacts = []ReviewFact{{Label: "Running release tag", Value: release.Tag}, {Label: "Active SSH port", Value: fmt.Sprint(preflight.ActiveSSHPort)}}
	module.fields = []string{"owner-email", "subscriber-agreement"}
	if module.draft.Installation.PublicIPv4 != "" && module.draft.Installation.PublicIPv6 != "" {
		module.fields = append(module.fields, "primary-address")
	} else if module.draft.Installation.PublicIPv4 != "" {
		module.draft.Installation.PrimaryAddress = module.draft.Installation.PublicIPv4
	} else {
		module.draft.Installation.PrimaryAddress = module.draft.Installation.PublicIPv6
	}
	if preflight.RealityPortReplacementRequired {
		module.fields = append(module.fields, "reality-port")
	}
	if preflight.SubscriptionReplacementRequired {
		module.fields = append(module.fields, "subscription-port")
	}
	if recommended := module.dependencies.RecommendedRealityTarget; recommended != "" {
		target := connectionprofiles.RealityTarget{Address: net.JoinHostPort(recommended, "443"), ServerName: recommended}
		review := module.dependencies.ReviewRealityTarget(ctx, target)
		if review.Target.Address == target.Address && review.Target.ServerName == target.ServerName && review.Health.Outcome == connectionprofiles.Healthy {
			module.draft.RealityTarget, module.draft.RealityServerName = target.Address, target.ServerName
		} else {
			module.fields = append(module.fields, "reality-target")
		}
	} else {
		module.fields = append(module.fields, "reality-target")
	}
	module.initialized = true
	return nil
}

func (module *Interface) resetDraft() {
	module.draft, module.nextField, module.initialized = initialDraft(), 0, false
	module.reviewFacts, module.ipv4Candidates, module.ipv6Candidates = nil, nil, nil
	module.fields = nil
	module.sshProof = networkpolicy.SSHPreservationProof{}
	module.reclamationSSHProof = networkpolicy.SSHPreservationProof{}
}

func (module *Interface) ConfirmReclamation(ctx context.Context, confirmation ReclamationConfirmation) ReviewResult {
	module.mu.Lock()
	reclamation, request, sshProof := module.reclamation, module.request, module.reclamationSSHProof
	module.approval, module.reclamation, module.request, module.reclamationSSHProof = nil, nil, softwareubuntu.InstallHandoffRequest{}, networkpolicy.SSHPreservationProof{}
	module.mu.Unlock()
	identity := ""
	if reclamation != nil && len(reclamation.Digest) == 64 {
		identity = "reclaim-vps-" + reclamation.Digest[:16]
	}
	if reclamation == nil || confirmation.Identity != identity || confirmation.Digest != reclamation.Digest || confirmation.Phrase != ReclamationPhrase {
		return ReviewResult{Invalid: &InvalidInput{Field: "reclamation-confirmation", Problem: "The exact current reclamation review and confirmation are required."}}
	}
	request.ReviewedReclamationSHA256 = reclamation.Digest
	built, err := module.build(ctx, request, sshProof)
	if err != nil {
		return correction(err)
	}
	return module.finalReview(built, request, reclamation)
}

func (module *Interface) build(ctx context.Context, request softwareubuntu.InstallHandoffRequest, sshProof networkpolicy.SSHPreservationProof) (*builtInstall, error) {
	return buildInstallWith(ctx, request, buildDependencies{stage: module.dependencies.Stage, network: module.dependencies.Network, random: newInstallEntropyReader(request.Entropy), sshProof: sshProof})
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
		&current.Installation.OwnerEmail: update.Installation.OwnerEmail,
		&current.Installation.PublicIPv6: update.Installation.PublicIPv6,
	} {
		if value != "" {
			*target = value
		}
	}
	for target, value := range map[*uint16]uint16{
		&current.Installation.RealityPort:      update.Installation.RealityPort,
		&current.Installation.SubscriptionPort: update.Installation.SubscriptionPort,
	} {
		if value != 0 {
			*target = value
		}
	}
	current.Installation.SubscriberAgreementReviewed = current.Installation.SubscriberAgreementReviewed || update.Installation.SubscriberAgreementReviewed
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
	case "owner-email":
		current.Installation.OwnerEmail = value
	case "subscriber-agreement":
		if value != "accepted" {
			return current, errors.New("The ACME subscriber agreement must be accepted.")
		}
		current.Installation.SubscriberAgreementReviewed = true
	case "primary-address":
		current.Installation.PrimaryAddress = value
	case "reality-port":
		current.Installation.RealityPort, err = port()
	case "subscription-port":
		current.Installation.SubscriptionPort, err = port()
	case "reality-target":
		current.RealityTarget, current.RealityServerName = net.JoinHostPort(value, "443"), value
	default:
		return current, errors.New("The Installation field is unknown.")
	}
	return current, err
}

var (
	revisionOneDraftFields = []string{"owner-email", "subscriber-agreement", "primary-address", "reality-port", "subscription-port", "reality-target"}
	draftDomain            = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	draftTag               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

var installationFieldHelp = map[string]FieldHelp{
	"owner-email": {
		Purpose:        "Register and recover the ACME account.",
		Instructions:   []string{"Enter one address you monitor."},
		AcceptedFormat: "local-part@domain; no spaces.",
		CommonMistakes: []string{"No name or multiple addresses."},
		Recovery:       "Correct it; prior values remain.",
		Example:        "owner@sbxr.example",
		URL:            "https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-command-line-options",
		Sensitivity:    PersonalInformation,
	},
	"subscriber-agreement": {
		Purpose:        "Record acceptance of the ACME subscriber agreement.",
		Instructions:   []string{"Enter accepted only after you review the agreement."},
		AcceptedFormat: "accepted",
		CommonMistakes: []string{"Do not continue before review."},
		Recovery:       "Review the agreement, then enter accepted.",
		URL:            "https://letsencrypt.org/repository/",
		Sensitivity:    PublicInformation,
	},
	"primary-address": {
		Purpose:        "Select the primary subscription address when both public address families are available.",
		Instructions:   []string{"Enter one of the two detected public addresses."},
		AcceptedFormat: "The detected public IPv4 or IPv6 address.",
		CommonMistakes: []string{"No private, special-use, or different address."},
		Recovery:       "Use one exact detected public address.",
		Example:        "192.0.2.10",
		URL:            "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml",
		Sensitivity:    PublicInformation,
	},
	"reality-port":      portFieldHelp("REALITY", "TCP", "10444"),
	"subscription-port": portFieldHelp("Subscription HTTPS", "TCP", "10448"),
	"reality-target": {
		Purpose:        "Choose the REALITY Vision HTTPS target.",
		Instructions:   []string{"Enter an ordinary external host."},
		AcceptedFormat: "Lowercase DNS hostname only.",
		CommonMistakes: []string{"No URL, port, or blocked host."},
		Recovery:       "Replace it; SBXR probes again.",
		Example:        "target.example",
		URL:            "https://xtls.github.io/en/config/transport.html#realityobject",
		Sensitivity:    PublicInformation,
	},
}

func portFieldHelp(profile, transport, example string) FieldHelp {
	return FieldHelp{
		Purpose:        fmt.Sprintf("Choose the %s %s port.", profile, transport),
		Instructions:   []string{"Keep the default if available."},
		AcceptedFormat: "Decimal integer from 1 to 65535.",
		CommonMistakes: []string{"No text, sign, space, or zero."},
		Recovery:       fmt.Sprintf("Use a valid %s port.", profile),
		Example:        example,
		URL:            "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml",
		Sensitivity:    PublicInformation,
	}
}

func initialDraft() Draft {
	return Draft{Installation: softwarelifecycle.InstallationDraft{RealityPort: 443, SubscriptionPort: 10443}}
}

func (module *Interface) draftFieldIndex(field string) int {
	for index, candidate := range module.fields {
		if candidate == field {
			return index
		}
	}
	module.fields = append(module.fields, field)
	return len(module.fields) - 1
}

func (module *Interface) invalidDraftField(draft Draft, field, problem string) *InvalidInput {
	invalid := &InvalidInput{Field: field, Value: draftFieldValue(draft, field), Problem: problem}
	module.attachReviewFacts(invalid)
	return invalid
}

func (module *Interface) attachReviewFacts(invalid *InvalidInput) {
	invalid.Facts = append([]ReviewFact(nil), module.reviewFacts...)
	if module.draft.Installation.PrimaryAddress != "" {
		invalid.Facts = append(invalid.Facts, ReviewFact{Label: "Primary subscription address", Value: module.draft.Installation.PrimaryAddress})
	}
	if module.draft.RealityServerName != "" {
		invalid.Facts = append(invalid.Facts, ReviewFact{Label: "REALITY server name", Value: module.draft.RealityServerName})
	}
	if help, ok := fieldHelp(invalid.Field); ok {
		invalid.Help = help
		invalid.Help.Instructions = append([]string(nil), help.Instructions...)
		invalid.Help.CommonMistakes = append([]string(nil), help.CommonMistakes...)
	}
	if invalid.Field == "primary-address" {
		candidates := append(append([]string(nil), module.ipv4Candidates...), module.ipv6Candidates...)
		invalid.Facts = append(invalid.Facts, ReviewFact{Label: "Detected primary-address candidates", Value: strings.Join(candidates, ", ")})
	}
}

func fieldHelp(field string) (FieldHelp, bool) {
	help, ok := installationFieldHelp[field]
	return help, ok
}

func draftFieldValue(draft Draft, field string) string {
	switch field {
	case "owner-email":
		return draft.Installation.OwnerEmail
	case "subscriber-agreement":
		if draft.Installation.SubscriberAgreementReviewed {
			return "accepted"
		}
		return ""
	case "primary-address":
		return draft.Installation.PrimaryAddress
	case "reality-port":
		return portText(draft.Installation.RealityPort)
	case "subscription-port":
		return portText(draft.Installation.SubscriptionPort)
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
	if nonProductionExampleValue(field, value) {
		return invalid("The submitted value is a tutorial example and cannot become Desired State.")
	}
	switch field {
	case "owner-email":
		address, err := mail.ParseAddress(value)
		if err != nil || address.Name != "" || address.Address != value {
			return invalid("The Owner email is invalid.")
		}
	case "primary-address":
		_, err := netip.ParseAddr(value)
		if err != nil || !networkpolicy.UsablePublicAddress(value) || value != draft.Installation.PublicIPv4 && value != draft.Installation.PublicIPv6 {
			return invalid("The primary subscription address is invalid.")
		}
	case "subscriber-agreement":
		if value != "accepted" {
			return invalid("The ACME subscriber agreement must be accepted.")
		}
	case "reality-target":
		if !validDraftHostname(value) {
			return invalid("The REALITY target hostname is invalid.")
		}
	}
	return nil
}

func nonProductionExampleValue(field, value string) bool {
	for helpField := range installationFieldHelp {
		help, _ := fieldHelp(helpField)
		if value == help.Example {
			return true
		}
	}
	name := value
	if field == "owner-email" {
		if at := strings.LastIndexByte(value, '@'); at >= 0 {
			name = value[at+1:]
		}
	}
	if field != "owner-email" && field != "reality-target" {
		return false
	}
	name = strings.ToLower(name)
	return name == "placeholder" || name == "your-domain" || name == "your-hostname" || strings.HasSuffix(name, ".example")
}

func validDraftHostname(value string) bool {
	if !draftDomain.MatchString(value) || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
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
		return &InvalidInput{Field: "owner-email", Problem: "The verified running Release Identity or active SSH port is invalid."}
	}
	for _, field := range revisionOneDraftFields {
		if invalid := validateDraftField(draft, field); invalid != nil {
			return invalid
		}
	}
	return nil
}

func correction(err error) ReviewResult {
	var refusal *networkPolicyRefusal
	if errors.As(err, &refusal) {
		finding := refusal.finding
		steps := append([]string(nil), finding.Fix.OwnerChecklist...)
		if finding.Fix.SBXROption != "" {
			steps = append([]string{finding.Fix.SBXROption}, steps...)
		}
		return ReviewResult{Correction: &Correction{Problem: finding.Problem, Found: finding.Found, Required: finding.Required, WhyStopped: finding.WhyStopped, FixWithSBXR: finding.Fix.SBXROption != "", OwnerSteps: steps, Evidence: "INSTALL-PLAN-REFUSED; " + finding.Evidence}}
	}
	return ReviewResult{Correction: &Correction{Problem: "The installation Plan could not be built", Found: "One required release, network, or installation input did not pass", Required: "Correct the named input or external fact, then check again", WhyStopped: "SBXR never continues with an incomplete or changed installation Plan", OwnerSteps: []string{"Restore the required external fact, then use Check again for a fresh Installation review."}, Evidence: "INSTALL-PLAN-REFUSED"}}
}

func reclamationCorrection() ReviewResult {
	return ReviewResult{Correction: &Correction{Problem: "The exact reclamation Plan is too large to display", Found: "More than 64 safe effect rows are required", Required: "Remove unsupported or unrelated firewall complexity, then check again", WhyStopped: "SBXR never hides or truncates destructive Plan facts", OwnerSteps: []string{"Simplify the existing firewall policy or reimage the VPS, then run the check again."}, Selections: []Selection{{Identity: "firewall-simplified", Label: "The firewall policy is now simpler"}}, Evidence: "INSTALL-RECLAMATION-PLAN-TOO-LARGE"}}
}

func finalPlan(built *builtInstall, request softwareubuntu.InstallHandoffRequest, reclamation *networkpolicy.ReclamationPlan) *Plan {
	summary := built.plan.Summary()
	plan := &Plan{Identity: built.plan.Identity(), DesiredStateRevision: 1, DesiredStateSHA256: built.desiredSHA256, RelevantChecksums: []string{"Plan SHA-256 " + built.plan.SHA256()}, ObservedState: "Proven Clean VPS baseline: Not installed", VerifiedExternalInputs: []string{"Verified release " + summary.ReleaseIdentity.Tag, "Direct SSH Preservation Proof", "Fresh Network Policy observations"}, Effects: installPlanEffects(), RequiredChecks: []string{"Pre-publication Module health", "Desired State agreement", "Post-publication VLESS REALITY Vision, sbxr-ip, Subscription HTTPS, nftables, temporary TCP 80 cleanup, unit, timer, and permission agreement"}, Interruption: summary.Interruption, Cancellation: summary.Cancellation, Rollback: summary.Rollback}
	plan.Effects = append(plan.Effects, fmt.Sprintf("Use SSH %d/TCP, VLESS REALITY Vision %d/TCP, and Subscription HTTPS %d/TCP", request.Draft.SSHPort, request.Draft.RealityPort, request.Draft.SubscriptionPort))
	plan.Effects = append(plan.Effects, fmt.Sprintf("Use %s as the Primary subscription address and REALITY target %s with server name %s", request.Draft.PrimaryAddress, request.RealityTarget, request.RealityServerName))
	if reclamation == nil {
		return plan
	}
	effects, ok := reclamationPlanEffects(reclamation, 64-len(plan.Effects))
	if !ok || reclamation.Digest != request.ReviewedReclamationSHA256 {
		return nil
	}
	plan.RelevantChecksums = []string{"Plan SHA-256 " + built.plan.SHA256(), "Reclamation facts SHA-256 " + reclamation.Digest}
	plan.ObservedState = "Reclaimable VPS: exact reviewed conflict followed by revision-one installation"
	plan.VerifiedExternalInputs = append(plan.VerifiedExternalInputs, "Fresh Network Policy reclamation review")
	plan.Effects = append(effects, plan.Effects...)
	plan.RequiredChecks = append([]string{"Fresh privileged reclamation proof"}, plan.RequiredChecks...)
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
	return &Plan{Identity: "reclaim-vps-" + plan.Digest[:16], LineageUnavailable: true, RelevantChecksums: []string{"Reclamation facts SHA-256 " + plan.Digest}, ObservedState: "Reclaimable VPS: exact read-only conflict facts", VerifiedExternalInputs: []string{"Fresh Network Policy host and conflict observations", "Protected Host Foundation version 1"}, Effects: effects, RequiredChecks: []string{"Fresh privileged recheck must match this exact digest before any later reclamation"}, AdvisoryChecks: []string{"Review-only confirmation grants no mutation authority"}, Interruption: plan.Interruption, Cancellation: plan.Cancellation, Rollback: plan.Rollback, ReclamationDigest: plan.Digest, ReclamationConfirmed: confirmed, ConfirmationHelp: ReclamationConfirmationGuidance()}
}

func installPlanEffects() []string {
	return []string{
		"Install the exact verified release and complete managed unit set",
		"Run only xray.service and sbxr-subscription.service; keep sing-box.service and cloudflared.service disabled and inactive",
		"Enable sbxr-recovery.service and the certificate-renewal, health-check, and update-check timers",
		"Retain NoNewPrivileges=true, ProtectHome=true, ProtectSystem=strict, AmbientCapabilities=CAP_NET_BIND_SERVICE, and CapabilityBoundingSet=CAP_NET_BIND_SERVICE for Xray",
		"Retain UMask=0027, NoNewPrivileges=true, PrivateTmp=true, ProtectHome=true, ProtectSystem=strict, PrivateDevices=true, ProtectControlGroups=true, ProtectKernelModules=true, ProtectKernelTunables=true, ProtectProc=invisible, and ProcSubset=pid for Subscription Serving",
		"Retain RestrictAddressFamilies=AF_INET AF_INET6, RestrictSUIDSGID=true, LockPersonality=true, MemoryDenyWriteExecute=true, LimitCORE=0, TemporaryFileSystem=/:ro, BindReadOnlyPaths=/usr/local/bin/sbxr, BindReadOnlyPaths=/var/lib/sbxr/subscriptions/current, BindReadOnlyPaths=/var/lib/sbxr/certificates/ip/current, and BindReadOnlyPaths=/etc/ssl/certs/ca-certificates.crt for Subscription Serving",
		"Store runtime service configuration, VLESS REALITY Vision credentials, subscription material, and the IP TLS private key under the fixed root-owned runtime paths",
		"Create VLESS REALITY Vision Enabled and keep the other five Connection Profiles Not set up without placeholders",
		"Publish exactly VLESS REALITY Vision where compatible and name all five omitted Not set up profiles",
		"Issue and activate only the sbxr-ip certificate lineage and remove the exact temporary TCP 80 rule on every outcome",
		"Leave all Cloudflare credentials, identifiers, resources, routes, DNS, Tunnel, and domain-certificate facts unchanged and absent",
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
