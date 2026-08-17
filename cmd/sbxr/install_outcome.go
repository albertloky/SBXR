package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	networkubuntu "github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwaregithub "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	servingubuntu "github.com/albertloky/SBXR/internal/subscriptionserving/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type installOutcome struct {
	mu                sync.Mutex
	module            *installation.Interface
	construction      error
	approval          installation.Approval
	plan              ownerconsole.PlanIdentity
	reclamationDigest string
	operation         installation.OperationIdentity
	reviewedHealth    *installation.ReviewedHealth
}

func (*installOutcome) String() string   { return "Clean VPS installation outcome: protected" }
func (*installOutcome) GoString() string { return "Clean VPS installation outcome: protected" }

var installFields = []ownerconsole.EditingField{
	{Identity: "domain", Label: "Domain", Required: true},
	{Identity: "owner-email", Label: "Owner email", Required: true},
	{Identity: "public-ipv4", Label: "Public IPv4", Required: true},
	{Identity: "reality-port", Label: "REALITY port", Required: true},
	{Identity: "hysteria2-port", Label: "Hysteria2 port", Required: true},
	{Identity: "tuic-port", Label: "TUIC port", Required: true},
	{Identity: "anytls-port", Label: "AnyTLS port", Required: true},
	{Identity: "subscription-port", Label: "Subscription HTTPS port", Required: true},
	{Identity: "cloudflare-account", Label: "Cloudflare account ID", Required: true},
	{Identity: "cloudflare-zone", Label: "Cloudflare zone ID", Required: true},
	{Identity: "cloudflare-token", Label: "Dedicated Broad Cloudflare User API Token", Required: true},
	{Identity: "reality-target", Label: "REALITY target hostname", Required: true},
}

func newInstallOutcome() *installOutcome {
	module, err := newInstallationModule()
	return &installOutcome{module: module, construction: err}
}

func newInstallationModule() (*installation.Interface, error) {
	return newInstallationModuleWith(readOwnVersion, nil)
}

func newInstallationModuleWith(releaseSource func() (versionReport, error), preflightSource func() networkpolicy.InstallationPreflightResult) (*installation.Interface, error) {
	stager := softwareubuntu.NewStager()
	lifecycle := softwarelifecycle.New(softwaregithub.New(), softwarelifecycle.VerifierQualification{Version: softwaregithub.Version, SigningFingerprint: softwaregithub.SigningFingerprint}, time.Now, stager)
	network := networkpolicy.New(networkubuntu.New())
	if preflightSource == nil {
		preflightSource = func() networkpolicy.InstallationPreflightResult {
			return network.InstallationPreflight(os.Getenv("SBXR_SSH_CONNECTION"))
		}
	}
	api := cloudflaretunnel.NewProductionAPI()
	cloudflare := cloudflaretunnel.New(api, cloudflaretunnel.SystemClock{})
	releaseCandidate := func(ctx context.Context, tag string, architecture softwarelifecycle.Architecture) (softwarelifecycle.InstallCandidateHandoff, error) {
		view := lifecycle.View(ctx, softwarelifecycle.ViewRequest{Tag: tag, Architecture: architecture, InstallationStatus: softwarelifecycle.NotInstalled})
		candidate := view.InstallCandidate()
		handoff, valid := candidate.InstallHandoff()
		if view.Refusal != nil || !valid {
			return softwarelifecycle.InstallCandidateHandoff{}, errors.New("the exact release could not be verified and staged")
		}
		return handoff, nil
	}
	return installation.New(installation.Dependencies{
		Preflight: preflightSource,
		ReviewRealityTarget: func(ctx context.Context, target connectionprofiles.RealityTarget) connectionprofiles.RealityTargetReview {
			unavailable := func() connectionprofiles.RealityTargetReview {
				return connectionprofiles.RealityTargetReview{Target: target, Health: connectionprofiles.Health{Module: "Connection Profiles", Profile: "VLESS REALITY Vision", Outcome: connectionprofiles.Failed, Code: "CONNECTION-PROFILES-REALITY-HOST", Problem: "The authenticated Xray target probe is unavailable", Found: "the exact running release candidate could not supply Xray", Required: "one authenticated staged Xray candidate", WhyStopped: "Connection Profiles never substitutes an unrelated system Xray", NextActions: []string{"Check again", "Back"}, BlockerOwner: connectionprofiles.SBXROwnedBlocker, BlockerAction: "Check the release connection, then submit this hostname again."}}
			}
			report, err := releaseSource()
			if err != nil {
				return unavailable()
			}
			handoff, err := releaseCandidate(ctx, report.Build.Tag, report.Architecture)
			if err != nil {
				return unavailable()
			}
			candidate, err := softwarelifecycle.RebuildInstallCandidate(ctx, handoff, stager)
			if err != nil {
				return unavailable()
			}
			host, err := profilesubuntu.NewCandidateHost(candidate)
			if err != nil {
				return unavailable()
			}
			return connectionprofiles.New(host).ReviewRealityTarget(ctx, target)
		},
		RunningRelease: func() (installation.RunningRelease, error) {
			report, err := releaseSource()
			return installation.RunningRelease{Tag: report.Build.Tag, Architecture: report.Architecture}, err
		},
		ReleaseCandidate: releaseCandidate, Stage: stager.Stage, Network: network.Evaluate, Cloudflare: cloudflare.Plan, CloudflareAPI: api, Inventory: api,
		Entropy: installation.DefaultEntropy(), Launch: softwareubuntu.LaunchInstallApplyWithCancellation,
		Recover: func(_ context.Context, pending systemchanges.PendingChangeSet) error {
			return runProvenRecovery(pending)
		},
		Pending: productionPendingChangeSetReader(), WriteReceipt: writeInstallRecoveryReceipt, RemoveReceipt: removeInstallRecoveryReceipt,
		ObserveState: installRecoveryObservation, LoadManaged: managedLoadEvidence, ProveSubscription: proveInstalledSubscription,
	})
}

func (outcome *installOutcome) ViewDiagnostics(ctx context.Context) ownerconsole.DiagnosticsPresentation {
	installationSummary := healthdiagnostics.InstallationSummary{}
	facts := systemchanges.InstallationHealthFacts{}
	statuses := map[healthdiagnostics.Module]healthdiagnostics.HealthStatus{}
	outcome.mu.Lock()
	if outcome.reviewedHealth != nil {
		installationSummary = outcome.reviewedHealth.Installation
		facts.Status = systemchanges.NotInstalled
		statuses[healthdiagnostics.NetworkPolicyModule] = outcome.reviewedHealth.Network
	}
	outcome.mu.Unlock()
	result := healthdiagnostics.New(nil).Check(ctx, installationSummary, scheduledInspections(facts, statuses, healthdiagnostics.CapabilityInspection{})...)
	services := make([]ownerconsole.ServiceHealthPresentation, 0, 10)
	for _, unit := range healthDiagnosticUnits() {
		services = append(services, ownerconsole.ServiceHealthPresentation{Service: unit, Status: ownerconsole.HealthUnknown})
	}
	presentation, _ := diagnosticsPresentation(result, nil, services)
	return presentation
}

func (*installOutcome) CreateSupportBundle(context.Context, ownerconsole.BundleReplacement) ownerconsole.SupportBundleResult {
	return ownerconsole.SupportBundleResult{Code: "HEALTH-DIAGNOSTICS-BUNDLE-RELEASE"}
}

func (outcome *installOutcome) Review(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	module, construction := outcome.module, outcome.construction
	outcome.mu.Unlock()
	if construction != nil || module == nil {
		return installCorrection(errors.New("Installation Module construction failed"))
	}
	review := module.Review(ctx, installation.Draft{})
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	return outcome.presentReview(review)
}

func (outcome *installOutcome) Edit(ctx context.Context, input ownerconsole.EditingInput) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	module := outcome.module
	outcome.approval, outcome.plan = installation.Approval{}, ""
	outcome.reviewedHealth = nil
	outcome.mu.Unlock()
	if module == nil {
		return installCorrection(errors.New("Installation Module construction failed"))
	}
	review := module.Review(ctx, installation.Draft{SubmittedField: input.Field, SubmittedValue: input.Text})
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	return outcome.presentReview(review)
}

func (outcome *installOutcome) presentReview(review installation.ReviewResult) ownerconsole.ChangeReview {
	if review.Plan == nil {
		outcome.reviewedHealth = nil
	}
	if review.Invalid != nil {
		for _, field := range installFields {
			if field.Identity == review.Invalid.Field {
				if review.Invalid.Detected {
					field.Label += " (detected)"
				}
				if review.Invalid.Value != "" {
					field.Value = review.Invalid.Value
				}
				facts := make([]ownerconsole.EditingFact, len(review.Invalid.Facts))
				for index, fact := range review.Invalid.Facts {
					facts[index] = ownerconsole.EditingFact{Label: fact.Label, Value: fact.Value}
				}
				help := review.Invalid.Help
				return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Clean VPS installation", Facts: facts, Field: field, Help: ownerconsole.EditingHelp{Purpose: help.Purpose, Instructions: append([]string(nil), help.Instructions...), AcceptedFormat: help.AcceptedFormat, CommonMistakes: append([]string(nil), help.CommonMistakes...), Recovery: help.Recovery, Example: help.Example, URL: help.URL, Sensitivity: ownerconsole.EditingSensitivity(help.Sensitivity)}}}
			}
		}
		return installCorrection(errors.New(review.Invalid.Problem))
	}
	if review.Correction != nil {
		return ownerCorrection(review.Correction)
	}
	plan := review.Plan
	if plan == nil {
		plan = review.Reclamation
	}
	if plan == nil {
		return installCorrection(errors.New("Installation review unavailable"))
	}
	if review.Plan != nil {
		outcome.approval, outcome.plan = review.Approval, ownerconsole.PlanIdentity(plan.Identity)
		outcome.reclamationDigest = ""
		outcome.reviewedHealth = review.Health
	}
	if review.Reclamation != nil {
		outcome.reclamationDigest = plan.ReclamationDigest
	}
	return ownerconsole.ChangeReview{Plan: ownerPlan(plan)}
}

func ownerPlan(plan *installation.Plan) *ownerconsole.PlanPresentation {
	if plan == nil {
		return nil
	}
	help := ownerconsole.ConfirmationHelp{}
	if plan.ReclamationDigest != "" && !plan.ReclamationConfirmed {
		help = ownerconsole.ConfirmationHelp{Title: plan.ConfirmationHelp.Title, Lines: append([]string(nil), plan.ConfirmationHelp.Lines...)}
	}
	return &ownerconsole.PlanPresentation{Identity: ownerconsole.PlanIdentity(plan.Identity), DesiredStateRevision: plan.DesiredStateRevision, DesiredStateSHA256: plan.DesiredStateSHA256, LineageUnavailable: plan.LineageUnavailable, RelevantChecksums: append([]string(nil), plan.RelevantChecksums...), ObservedState: plan.ObservedState, VerifiedExternalInputs: append([]string(nil), plan.VerifiedExternalInputs...), Effects: append([]string(nil), plan.Effects...), RequiredChecks: append([]string(nil), plan.RequiredChecks...), AdvisoryChecks: append([]string(nil), plan.AdvisoryChecks...), Interruption: plan.Interruption, Cancellation: plan.Cancellation, Rollback: plan.Rollback, ReclamationDigest: plan.ReclamationDigest, ReclamationConfirmed: plan.ReclamationConfirmed, ConfirmationHelp: help}
}

func ownerCorrection(value *installation.Correction) ownerconsole.ChangeReview {
	selections := make([]ownerconsole.CorrectionSelection, len(value.Selections))
	for index, selection := range value.Selections {
		selections[index] = ownerconsole.CorrectionSelection{Identity: selection.Identity, Label: selection.Label}
	}
	hideCheckAgain := value.SSHFailureCause != "" && !sshObservationTemporary(value.SSHFailureCause)
	return ownerconsole.ChangeReview{Correction: &ownerconsole.CorrectionPresentation{Problem: value.Problem, Found: value.Found, Required: value.Required, WhyStopped: value.WhyStopped, FixWithSBXR: value.FixWithSBXR, HideCheckAgain: hideCheckAgain, OwnerSteps: append([]string(nil), value.OwnerSteps...), InputLabel: value.InputLabel, Selections: selections, Evidence: value.Evidence}}
}

func (outcome *installOutcome) ConfirmReclamation(ctx context.Context, identity ownerconsole.PlanIdentity, approval ownerconsole.ReclamationApproval) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	digest := outcome.reclamationDigest
	outcome.reclamationDigest = ""
	if digest == "" || !approval.NetworkPolicyReclamationApproval(identity, digest) {
		return installCorrection(errors.New("the exact current reclamation review and confirmation are required"))
	}
	return outcome.presentReview(outcome.module.ConfirmReclamation(ctx, installation.ReclamationConfirmation{Identity: string(identity), Digest: digest, Phrase: installation.ReclamationPhrase}))
}

func (outcome *installOutcome) Apply(ctx context.Context, identity ownerconsole.PlanIdentity) ownerconsole.ChangeResult {
	outcome.mu.Lock()
	if identity != outcome.plan {
		outcome.mu.Unlock()
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed installation Plan is unavailable."}
	}
	approval := outcome.approval
	result := outcome.module.Apply(ctx, approval)
	outcome.approval, outcome.plan = installation.Approval{}, ""
	if result.Kind == installation.ApplyStarted {
		outcome.operation = result.Operation
	}
	outcome.mu.Unlock()
	if result.Kind != installation.ApplyStarted {
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: result.Reason}
	}
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangeStarted, OperationID: ownerconsole.OperationIdentity(result.Operation), Explanation: result.Reason}
}

func (outcome *installOutcome) Inspect(ctx context.Context) ownerconsole.DurableChangeSet {
	outcome.mu.Lock()
	identity := outcome.operation
	outcome.mu.Unlock()
	if identity == "" {
		return ownerconsole.DurableChangeSet{}
	}
	operation, err := outcome.module.Inspect(ctx, identity)
	if err != nil {
		return ownerconsole.DurableChangeSet{}
	}
	kind := map[installation.OperationStatus]ownerconsole.ChangeSetStatus{installation.OperationActive: ownerconsole.ChangeSetActive, installation.Completed: ownerconsole.ChangeSetSucceeded, installation.RolledBack: ownerconsole.ChangeSetRolledBack, installation.RecoveryRequired: ownerconsole.ChangeSetRecoveryRequired}[operation.Status]
	return ownerconsole.DurableChangeSet{Kind: kind, OperationID: ownerconsole.OperationIdentity(operation.Identity), CompletedSteps: operation.CompletedSteps, TotalSteps: operation.TotalSteps, Checkpoint: operation.Checkpoint, Explanation: operation.Explanation}
}

func (outcome *installOutcome) RequestCancellation(ctx context.Context, identity ownerconsole.OperationIdentity) ownerconsole.ChangeResult {
	result := outcome.module.RequestCancellation(ctx, installation.OperationIdentity(identity))
	if result.Kind != installation.CancellationRequested {
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: result.Reason}
	}
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangeCancellationRequested, OperationID: identity, Explanation: result.Reason}
}

func (outcome *installOutcome) Fix(ctx context.Context, _ ownerconsole.CorrectionInput) ownerconsole.ChangeReview {
	return outcome.Review(ctx)
}
func (outcome *installOutcome) CheckAgain(ctx context.Context) ownerconsole.ChangeReview {
	return outcome.Review(ctx)
}

func (outcome *installOutcome) Back(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	outcome.approval, outcome.plan = installation.Approval{}, ""
	outcome.reclamationDigest = ""
	outcome.reviewedHealth = nil
	module := outcome.module
	outcome.mu.Unlock()
	if module == nil {
		return installCorrection(errors.New("Installation Module construction failed"))
	}
	review := module.Review(ctx, installation.DiscardDraft())
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	return outcome.presentReview(review)
}

func installCorrection(err error) ownerconsole.ChangeReview {
	return ownerconsole.ChangeReview{Correction: &ownerconsole.CorrectionPresentation{Problem: "The installation Plan could not be built", Found: "One required release, provider, network, or installation input did not pass", Required: "Correct the named input or external fact, then check again", WhyStopped: "SBXR never continues with an incomplete or changed installation Plan", OwnerSteps: []string{"Restore the required external fact, then use Check again for a fresh Installation review."}, Evidence: "INSTALL-PLAN-REFUSED: " + err.Error()}}
}

func proveInstalledSubscription(ctx context.Context, address string, port uint16) error {
	if result := servingubuntu.New().Inspect(ctx); result.Status != subscriptionserving.Healthy {
		return errors.New("Subscription Serving runtime health proof failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(address, fmt.Sprint(port))+"/", nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func trimVersion(version string) string { return strings.TrimPrefix(version, "v") }

type installClock struct{}

func (installClock) Now() time.Time { return time.Now() }

type installSingBoxValidator struct{ host profilesubuntu.CandidateHost }

func (validator installSingBoxValidator) ValidateSingBox(ctx context.Context, document io.Reader) error {
	return validator.host.ValidateSingBox(ctx, "1.13.16", document)
}
