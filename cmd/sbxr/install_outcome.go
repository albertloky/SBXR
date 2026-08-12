package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwaregithub "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type installOutcome struct {
	mu          sync.Mutex
	values      map[string]string
	request     softwareubuntu.InstallHandoffRequest
	built       *builtInstall
	reclamation *networkpolicy.ReclamationPlan
	change      ownerconsole.DurableChangeSet
	cancel      chan struct{}
	cancelled   bool
}

func (*installOutcome) String() string   { return "Clean VPS installation outcome: protected" }
func (*installOutcome) GoString() string { return "Clean VPS installation outcome: protected" }

func (outcome *installOutcome) ViewDiagnostics(ctx context.Context) ownerconsole.DiagnosticsPresentation {
	outcome.mu.Lock()
	built := outcome.built
	outcome.mu.Unlock()
	var installation healthdiagnostics.InstallationSummary
	var facts systemchanges.InstallationHealthFacts
	statuses := map[healthdiagnostics.Module]healthdiagnostics.HealthStatus{}
	if built != nil {
		installation = built.health
		facts.Status = systemchanges.NotInstalled
		statuses[healthdiagnostics.NetworkPolicyModule] = healthdiagnostics.HealthStatus(built.wiring.network.Outcome)
	}
	result := healthdiagnostics.New(nil).Check(ctx, installation, scheduledInspections(facts, statuses)...)
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

var installFields = []ownerconsole.EditingField{
	{Identity: "release-tag", Label: "Release tag", Required: true},
	{Identity: "domain", Label: "Domain", Required: true},
	{Identity: "owner-email", Label: "Owner email", Required: true},
	{Identity: "public-ipv4", Label: "Public IPv4", Required: true},
	{Identity: "primary-address", Label: "Primary subscription address", Required: true},
	{Identity: "ssh-port", Label: "SSH port", Value: "22", Required: true},
	{Identity: "reality-port", Label: "REALITY port", Value: "443", Required: true},
	{Identity: "hysteria2-port", Label: "Hysteria2 port", Value: "443", Required: true},
	{Identity: "tuic-port", Label: "TUIC port", Value: "8443", Required: true},
	{Identity: "anytls-port", Label: "AnyTLS port", Value: "9443", Required: true},
	{Identity: "subscription-port", Label: "Subscription HTTPS port", Value: "10443", Required: true},
	{Identity: "cloudflare-account", Label: "Cloudflare account ID", Required: true},
	{Identity: "cloudflare-zone", Label: "Cloudflare zone ID", Required: true},
	{Identity: "cloudflare-token", Label: "Cloudflare scoped token", Required: true},
	{Identity: "reality-target", Label: "REALITY target host:443", Required: true},
	{Identity: "reality-server-name", Label: "REALITY server name", Required: true},
}

func newInstallOutcome() *installOutcome { return &installOutcome{values: map[string]string{}} }

func (outcome *installOutcome) Review(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	for _, field := range installFields {
		if outcome.values[field.Identity] == "" {
			if field.Identity == "cloudflare-token" {
				field.Value = ""
			}
			return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Clean VPS installation", Field: field}}
		}
	}
	if outcome.built == nil {
		if err := outcome.build(ctx); err != nil {
			return installCorrection(err)
		}
	}
	if outcome.reclamation != nil {
		return reclamationReview(outcome.reclamation, false)
	}
	summary := outcome.built.plan.Summary()
	return ownerconsole.ChangeReview{Plan: &ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(outcome.built.plan.Identity()), DesiredStateRevision: 1, DesiredStateSHA256: outcome.built.desiredSHA256,
		RelevantChecksums: []string{"Plan SHA-256 " + outcome.built.plan.SHA256()}, ObservedState: "Proven Clean VPS baseline: Not installed",
		VerifiedExternalInputs: []string{"Verified release " + summary.ReleaseIdentity.Tag, "Scoped Cloudflare account and zone authority", "Fresh Network Policy observations"},
		Effects:                []string{"Install the exact verified release and managed units", "Create six Connection Profiles and one HTTPS subscription", "Create one Cloudflare Tunnel and exact DNS records", "Issue and activate the IP and domain certificate lineages", "Publish Desired State revision 1 exactly once"},
		RequiredChecks:         []string{"Pre-publication module health", "Desired State agreement", "Post-publication HTTPS, Tunnel, certificate, profile, unit, timer, and permission agreement"},
		AdvisoryChecks:         []string{"Direct DNS is pending only until the reviewed Cloudflare steps create it"},
		Interruption:           summary.Interruption, Cancellation: summary.Cancellation, Rollback: summary.Rollback,
	}}
}

func (outcome *installOutcome) Edit(ctx context.Context, input ownerconsole.EditingInput) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	known := false
	for _, field := range installFields {
		if field.Identity == input.Field {
			known = true
			break
		}
	}
	if known && input.Text != "" {
		outcome.values[input.Field] = input.Text
		outcome.built = nil
	}
	outcome.mu.Unlock()
	return outcome.Review(ctx)
}

func (outcome *installOutcome) Apply(ctx context.Context, identity ownerconsole.PlanIdentity) ownerconsole.ChangeResult {
	outcome.mu.Lock()
	if outcome.built == nil || identity != ownerconsole.PlanIdentity(outcome.built.plan.Identity()) || outcome.change.Kind == ownerconsole.ChangeSetActive {
		outcome.mu.Unlock()
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed installation Plan is unavailable."}
	}
	request := outcome.request
	request.ReviewedPlanSHA256 = outcome.built.plan.SHA256()
	operation := ownerconsole.OperationIdentity("install-" + request.Session[:16])
	totalSteps := uint16(outcome.built.totalSteps)
	outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetActive, OperationID: operation, TotalSteps: totalSteps, Checkpoint: "Awaiting verified sudo handoff", Explanation: "The reviewed installation is running."}
	outcome.cancel, outcome.cancelled = make(chan struct{}), false
	cancellation := outcome.cancel
	outcome.mu.Unlock()
	go func() {
		terminal, err := softwareubuntu.LaunchInstallApplyWithCancellation(context.Background(), request, cancellation)
		outcome.mu.Lock()
		defer outcome.mu.Unlock()
		if err == nil && terminal == softwareubuntu.InstallCompleted {
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetSucceeded, OperationID: operation, CompletedSteps: totalSteps, TotalSteps: totalSteps, Checkpoint: "Complete", Explanation: "Desired State revision 1 and all required agreement checks passed."}
			return
		}
		if err == nil && terminal == softwareubuntu.InstallRolledBack {
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRolledBack, OperationID: operation, TotalSteps: totalSteps, Checkpoint: "Rolled back", Explanation: "The privileged process proved rollback to Not installed."}
			return
		}
		outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, TotalSteps: totalSteps, Checkpoint: "Installation stopped", Explanation: "The privileged installation did not prove Complete; inspect the durable recovery result."}
	}()
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangeStarted, OperationID: operation, Explanation: "The exact reviewed installation Plan started."}
}

func (outcome *installOutcome) ConfirmReclamation(ctx context.Context, identity ownerconsole.PlanIdentity, approval ownerconsole.ReclamationApproval) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	if outcome.reclamation == nil || !approval.NetworkPolicyReclamationApproval(identity, outcome.reclamation.Digest) {
		outcome.mu.Unlock()
		return ownerconsole.ChangeReview{}
	}
	outcome.request.ReviewedReclamationSHA256 = outcome.reclamation.Digest
	request := outcome.request
	outcome.mu.Unlock()
	built, err := buildInstall(ctx, request)
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	if err != nil {
		return installCorrection(err)
	}
	outcome.request, outcome.built = request, built
	outcome.reclamation = nil
	summary := built.plan.Summary()
	return ownerconsole.ChangeReview{Plan: &ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(built.plan.Identity()), DesiredStateRevision: 1, DesiredStateSHA256: built.desiredSHA256,
		RelevantChecksums: []string{"Plan SHA-256 " + built.plan.SHA256(), "Reclamation facts SHA-256 " + request.ReviewedReclamationSHA256}, ObservedState: "Reclaimable VPS: exact reviewed conflict followed by revision-one installation",
		VerifiedExternalInputs: []string{"Verified release " + summary.ReleaseIdentity.Tag, "Fresh Network Policy reclamation review"},
		Effects:                []string{"Permanently remove the exact reviewed conflict after the durable irreversible checkpoint", "Install SBXR and publish Desired State revision 1"},
		RequiredChecks:         []string{"Fresh privileged reclamation proof", "Managed State and exact candidate agreement"},
		Interruption:           "Before Irreversible reclamation started, cancellation rolls back; afterward recovery continues forward to Managed", Cancellation: "Unavailable after Irreversible reclamation started", Rollback: "No rollback exists after permanent reclamation starts",
		ReclamationDigest: request.ReviewedReclamationSHA256, ReclamationConfirmed: true,
	}}
}

func (outcome *installOutcome) Inspect(context.Context) ownerconsole.DurableChangeSet {
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	return outcome.change
}

func (outcome *installOutcome) Fix(ctx context.Context, _ ownerconsole.CorrectionInput) ownerconsole.ChangeReview {
	return outcome.Review(ctx)
}
func (outcome *installOutcome) CheckAgain(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	outcome.built, outcome.reclamation = nil, nil
	outcome.mu.Unlock()
	return outcome.Review(ctx)
}
func (outcome *installOutcome) Back(context.Context) ownerconsole.ChangeReview {
	return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Clean VPS installation", Field: installFields[0]}}
}
func (outcome *installOutcome) RequestCancellation(_ context.Context, operation ownerconsole.OperationIdentity) ownerconsole.ChangeResult {
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	if outcome.change.Kind != ownerconsole.ChangeSetActive || outcome.change.OperationID != operation || outcome.cancel == nil {
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "Cancellation is accepted only by the active privileged Change Set."}
	}
	if !outcome.cancelled {
		close(outcome.cancel)
		outcome.cancelled = true
	}
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangeCancellationRequested, OperationID: operation, Explanation: "Cancellation will roll back at the next declared safe checkpoint."}
}

func (outcome *installOutcome) build(ctx context.Context) error {
	port := func(name string) (uint16, error) {
		value, err := strconv.ParseUint(outcome.values[name], 10, 16)
		return uint16(value), err
	}
	ssh, err1 := port("ssh-port")
	reality, err2 := port("reality-port")
	hysteria2, err3 := port("hysteria2-port")
	tuic, err4 := port("tuic-port")
	anyTLS, err5 := port("anytls-port")
	subscription, err6 := port("subscription-port")
	if errors.Join(err1, err2, err3, err4, err5, err6) != nil {
		return errors.New("one or more ports are invalid")
	}
	architecture := softwarelifecycle.Architecture(runtime.GOARCH)
	lifecycle := softwarelifecycle.New(softwaregithub.New(), softwarelifecycle.VerifierQualification{Version: softwaregithub.Version, SigningFingerprint: softwaregithub.SigningFingerprint}, time.Now, softwareubuntu.NewStager())
	view := lifecycle.View(ctx, softwarelifecycle.ViewRequest{Tag: outcome.values["release-tag"], Architecture: architecture, InstallationStatus: softwarelifecycle.NotInstalled})
	candidate := view.InstallCandidate()
	handoff, valid := candidate.InstallHandoff()
	if view.Refusal != nil || !valid {
		return errors.New("the exact release could not be verified and staged")
	}
	sessionBytes, entropy := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		return errors.New("installation identity generation failed")
	}
	if _, err := rand.Read(entropy); err != nil {
		return errors.New("installation entropy generation failed")
	}
	request := softwareubuntu.InstallHandoffRequest{
		Schema: 1, Session: hex.EncodeToString(sessionBytes), Tag: outcome.values["release-tag"], Architecture: architecture,
		Draft:               softwarelifecycle.InstallationDraft{Domain: outcome.values["domain"], OwnerEmail: outcome.values["owner-email"], PublicIPv4: outcome.values["public-ipv4"], PrimaryAddress: outcome.values["primary-address"], SSHPort: ssh, RealityPort: reality, Hysteria2Port: hysteria2, TUICPort: tuic, AnyTLSPort: anyTLS, SubscriptionPort: subscription},
		CloudflareAccountID: outcome.values["cloudflare-account"], CloudflareZoneID: outcome.values["cloudflare-zone"], CloudflareToken: outcome.values["cloudflare-token"],
		RealityTarget: outcome.values["reality-target"], RealityServerName: outcome.values["reality-server-name"], Entropy: entropy, Candidate: handoff,
	}
	built, err := buildInstall(ctx, request)
	if err != nil {
		var review *reclamationReviewError
		if errors.As(err, &review) && review.plan != nil {
			outcome.request, outcome.reclamation = request, review.plan
			return nil
		}
		return err
	}
	outcome.request, outcome.built = request, built
	return nil
}

func reclamationReview(plan *networkpolicy.ReclamationPlan, confirmed bool) ownerconsole.ChangeReview {
	if plan == nil || len(plan.Digest) != 64 {
		return ownerconsole.ChangeReview{}
	}
	effects := append([]string(nil), plan.Targets...)
	effects = append(effects, plan.Preservation...)
	effects = append(effects, plan.PermanentWarnings...)
	effects = slices.DeleteFunc(effects, func(value string) bool { return value == "" || len(value) > 320 })
	if len(effects) == 0 {
		effects = []string{"Review the exact detected conflicts; change nothing"}
	}
	return ownerconsole.ChangeReview{Plan: &ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity("reclaim-vps-" + plan.Digest[:16]), LineageUnavailable: true,
		RelevantChecksums: []string{"Reclamation facts SHA-256 " + plan.Digest}, ObservedState: "Reclaimable VPS: exact read-only conflict facts",
		VerifiedExternalInputs: []string{"Fresh Network Policy host and conflict observations", "Protected Host Foundation version 1"},
		Effects:                effects, RequiredChecks: []string{"Fresh privileged recheck must match this exact digest before any later reclamation"}, AdvisoryChecks: []string{"Review-only confirmation grants no mutation authority"},
		Interruption: plan.Interruption, Cancellation: plan.Cancellation, Rollback: plan.Rollback,
		ReclamationDigest: plan.Digest, ReclamationConfirmed: confirmed,
	}}
}

func installCorrection(err error) ownerconsole.ChangeReview {
	return ownerconsole.ChangeReview{Correction: &ownerconsole.CorrectionPresentation{Problem: "The installation Plan could not be built", Found: "One required release, provider, network, or installation input did not pass", Required: "Correct the named input or external fact, then check again", WhyStopped: "SBXR never continues with an incomplete or changed installation Plan", FixWithSBXR: true, InputLabel: "Corrected value", Evidence: "INSTALL-PLAN-REFUSED: " + err.Error()}}
}
