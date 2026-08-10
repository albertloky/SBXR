package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/ownerconsole"
)

type clientAccessOutcome struct {
	mu             sync.Mutex
	session        *clientAccessHandoffSession
	request        clientAccessHandoffRequest
	change         ownerconsole.DurableChangeSet
	presentation   clientAccessPresentation
	loaded         bool
	providerAction managedProviderAction
	providerEmail  string
	providerAgree  bool
}

func (*clientAccessOutcome) String() string   { return "Managed Client Access outcome: protected" }
func (*clientAccessOutcome) GoString() string { return "Managed Client Access outcome: protected" }

func (outcome *clientAccessOutcome) load(ctx context.Context) clientAccessPresentation {
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	if !outcome.loaded {
		outcome.presentation = loadClientAccessPresentation(ctx)
		outcome.loaded = outcome.presentation.Installation != 0
	}
	return outcome.presentation
}

func (outcome *clientAccessOutcome) Startup(ctx context.Context) ownerconsole.StartupPresentation {
	presentation := outcome.load(ctx)
	return ownerconsole.StartupPresentation{Status: presentation.Installation, Access: presentation.Access, Recovery: presentation.Recovery}
}

func (outcome *clientAccessOutcome) ViewRecovery(ctx context.Context) ownerconsole.RecoveryPresentation {
	return outcome.load(ctx).Recovery
}

func (outcome *clientAccessOutcome) RetryAutomaticRollback(ctx context.Context) ownerconsole.DurableChangeSet {
	return ownerRecovery{changeSet: outcome.load(ctx).Recovery.ChangeSet}.RetryAutomaticRollback(ctx)
}

func (outcome *clientAccessOutcome) ReviewCurrentStateRepair(ctx context.Context) ownerconsole.ChangeReview {
	return ownerRecovery{}.ReviewCurrentStateRepair(ctx)
}

func (outcome *clientAccessOutcome) Access(ctx context.Context) ownerconsole.AccessPresentation {
	return outcome.load(ctx).Access
}
func (outcome *clientAccessOutcome) ViewProfiles(ctx context.Context) ownerconsole.ProfilesPresentation {
	return outcome.load(ctx).Profiles
}

func (outcome *clientAccessOutcome) ViewCloudflare(ctx context.Context) ownerconsole.CloudflarePresentation {
	return outcome.load(ctx).Cloudflare
}

func (outcome *clientAccessOutcome) ViewCertificates(ctx context.Context) ownerconsole.CertificatesPresentation {
	return outcome.load(ctx).Certificates
}

func (*clientAccessOutcome) ViewDiagnostics(ctx context.Context) ownerconsole.DiagnosticsPresentation {
	return loadDiagnosticsPresentation(ctx)
}

func (*clientAccessOutcome) CreateSupportBundle(ctx context.Context, replacement ownerconsole.BundleReplacement) ownerconsole.SupportBundleResult {
	return createSupportBundle(ctx, replacement)
}

func (outcome *clientAccessOutcome) ReviewProfileChange(ctx context.Context, request ownerconsole.ProfileChangeRequest) ownerconsole.ChangeReview {
	action := map[ownerconsole.ProfileChange]clientAccessAction{ownerconsole.RotateProfileCredential: clientAccessRotateProfile, ownerconsole.EnableProfile: clientAccessEnableProfile, ownerconsole.DisableProfile: clientAccessDisableProfile}[request.Change]
	if action == "" {
		return unsupportedClientAccessReview()
	}
	profiles := [...]connectionprofiles.ProfileID{connectionprofiles.VLESSRealityVisionProfileID, connectionprofiles.VLESSXHTTPProfileID, connectionprofiles.VLESSWebSocketProfileID, connectionprofiles.Hysteria2ProfileID, connectionprofiles.TUICProfileID, connectionprofiles.AnyTLSProfileID}
	if request.Profile < ownerconsole.RealityVisionProfile || request.Profile > ownerconsole.AnyTLSProfile {
		return unsupportedClientAccessReview()
	}
	return outcome.reviewAction(ctx, action, profiles[request.Profile-1])
}

func (outcome *clientAccessOutcome) ReviewClientAccessChange(ctx context.Context, change ownerconsole.ClientAccessChange) ownerconsole.ChangeReview {
	action := map[ownerconsole.ClientAccessChange]clientAccessAction{ownerconsole.RotateEveryProfileCredential: clientAccessRotateAllProfiles, ownerconsole.RotateSubscriptionToken: clientAccessRotateSubscription, ownerconsole.RevokeAllClientAccess: clientAccessRevokeAll}[change]
	if action == "" {
		return unsupportedClientAccessReview()
	}
	return outcome.reviewAction(ctx, action, "")
}

func (outcome *clientAccessOutcome) ActOnCloudflare(ctx context.Context, request ownerconsole.CloudflareRequest) ownerconsole.CloudflareResponse {
	if request.Action == ownerconsole.CheckCurrentManagementToken || request.Action == ownerconsole.WaitAnotherTenMinutes {
		outcome.mu.Lock()
		outcome.loaded = false
		outcome.mu.Unlock()
		presentation := outcome.ViewCloudflare(ctx)
		return ownerconsole.CloudflareResponse{Presentation: &presentation}
	}
	action := map[ownerconsole.CloudflareAction]managedProviderAction{
		ownerconsole.VerifyInitialManagementToken:     managedCloudflareReplace,
		ownerconsole.VerifyReplacementManagementToken: managedCloudflareReplace,
		ownerconsole.ReviewManagementTokenRemoval:     managedCloudflareRemove,
		ownerconsole.ReviewTunnelRunTokenRotation:     managedCloudflareRotate,
	}[request.Action]
	if action == "" {
		return ownerconsole.CloudflareResponse{}
	}
	outcome.mu.Lock()
	outcome.providerAction = action
	outcome.providerEmail, outcome.providerAgree = "", false
	outcome.mu.Unlock()
	review := outcome.reviewProviderAction(ctx, action, request.Token, "", false)
	return ownerconsole.CloudflareResponse{Review: &review}
}

func (outcome *clientAccessOutcome) ReviewCertificateChange(ctx context.Context, change ownerconsole.CertificateChange) ownerconsole.ChangeReview {
	action := map[ownerconsole.CertificateChange]managedProviderAction{
		ownerconsole.IssueIPCertificate: managedCertificateIP, ownerconsole.RenewIPCertificate: managedCertificateIP,
		ownerconsole.IssueDirectTLSCertificate: managedCertificateDomain, ownerconsole.RenewDirectTLSCertificate: managedCertificateDomain,
	}[change]
	if action == "" {
		return unsupportedClientAccessReview()
	}
	outcome.mu.Lock()
	outcome.providerAction, outcome.providerEmail, outcome.providerAgree = action, "", false
	outcome.mu.Unlock()
	return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Certificate issuance or renewal", Field: ownerconsole.EditingField{Identity: "owner-email", Label: "Owner email", Required: true}}}
}

func (outcome *clientAccessOutcome) reviewAction(ctx context.Context, action clientAccessAction, profile connectionprofiles.ProfileID) ownerconsole.ChangeReview {
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	request := clientAccessHandoffRequest{Schema: 1, Mode: "change", Action: action, Profile: string(profile), ChangeSet: "client-access-" + hex.EncodeToString(identity)}
	session, err := launchClientAccessReview(ctx, request)
	if err != nil {
		return clientAccessCorrection(err.Error())
	}
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request = session, request
	outcome.mu.Unlock()
	prior.discard()
	effects := clientAccessEffects(action, profile)
	return ownerconsole.ChangeReview{Plan: &ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(session.review.Identity), DesiredStateRevision: session.review.CandidateRevision, DesiredStateSHA256: session.review.DesiredStateSHA256,
		RelevantChecksums: []string{"Client Access Plan SHA-256 " + session.review.SHA256, "Reviewed volatile state SHA-256 " + session.review.VolatileSHA256}, ObservedState: "Proven Managed Desired State revision " + uintText(session.review.StartingRevision),
		VerifiedExternalInputs: []string{"Current core configuration and listeners", "Current atomic subscription publication", "Current Cloudflare Tunnel routes when affected"},
		Effects:                effects, RequiredChecks: []string{"Native core validation and activation", "Atomic publication and old-token refusal", "Serving, listener, health, State, and post-publication agreement"},
		AdvisoryChecks: []string{"No dual-credential grace or unsupported representation substitution"}, Interruption: "Closing the terminal does not cancel the independent durable Change Set.", Cancellation: "Cancellation is unavailable after this privileged Change Set starts.", Rollback: "Every completed effect restores the complete prior Managed revision or reports Recovery Required when proof is impossible.",
	}}
}

func (outcome *clientAccessOutcome) reviewProviderAction(ctx context.Context, action managedProviderAction, token, email string, agreement bool) ownerconsole.ChangeReview {
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	request := clientAccessHandoffRequest{Schema: 1, Mode: "provider", ProviderAction: action, ChangeSet: "provider-" + hex.EncodeToString(identity), Token: token, OwnerEmail: email, Agreement: agreement}
	session, err := launchClientAccessReview(ctx, request)
	if err != nil {
		return clientAccessCorrection(err.Error())
	}
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request = session, request
	outcome.mu.Unlock()
	prior.discard()
	return ownerconsole.ChangeReview{Plan: &ownerconsole.PlanPresentation{
		Identity: ownerconsole.PlanIdentity(session.review.Identity), DesiredStateRevision: session.review.CandidateRevision, DesiredStateSHA256: session.review.DesiredStateSHA256,
		RelevantChecksums: []string{"Plan SHA-256 " + session.review.SHA256, "Reviewed volatile state SHA-256 " + session.review.VolatileSHA256}, ObservedState: "Proven Managed Desired State revision " + uintText(session.review.StartingRevision),
		VerifiedExternalInputs: providerExternalInputs(action), Effects: providerEffects(action),
		RequiredChecks: []string{"Exact provider or ACME ownership", "Temporary port 80 cleanup when used", "Service activation, State publication, and post-publication agreement"},
		AdvisoryChecks: []string{"No DNS-01 or CAA creation"}, Interruption: "Closing the terminal does not cancel the independent durable Change Set.", Cancellation: "Cancellation is unavailable after this privileged Change Set starts.", Rollback: "The complete prior Managed revision and active serving pointer are restored, or Recovery Required is reported when proof is impossible.",
	}}
}

func providerExternalInputs(action managedProviderAction) []string {
	if action == managedCertificateIP || action == managedCertificateDomain {
		return []string{"Current authoritative Direct DNS and effective CAA", "Current managed firewall and exact HTTP-01 authority", "Current Certbot and certificate lineage observation"}
	}
	return []string{"Current scoped Cloudflare account and zone authority", "Committed immutable Tunnel and DNS identifiers", "Current two-route and local-origin agreement"}
}

func providerEffects(action managedProviderAction) []string {
	switch action {
	case managedCloudflareReplace:
		return []string{"Replace only the stored Cloudflare management token at publication", "Keep provider resources and the prior token active until publication"}
	case managedCloudflareRemove:
		return []string{"Deliberately remove Cloudflare management authority", "Mark every dependent provider behavior unmanaged"}
	case managedCloudflareRotate:
		return []string{"Enter the durable genuine run-token rotation checkpoint", "Activate only the changed run token and re-prove both Tunnel routes"}
	case managedCertificateDomain:
		return []string{"Issue or renew sbxr-domain through staging then production HTTP-01", "Switch one shared pointer and restart sing-box", "Re-prove Hysteria2, TUIC, and AnyTLS separately"}
	default:
		return []string{"Issue or renew sbxr-ip through staging then production HTTP-01", "Switch one Subscription Serving pointer and reload or restart its service", "Prove normal-trust HTTPS for the selected IP"}
	}
}

func (outcome *clientAccessOutcome) Review(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	request := outcome.request
	outcome.mu.Unlock()
	if !validClientAccessHandoff(request) {
		return unsupportedClientAccessReview()
	}
	if request.Mode == "provider" {
		return outcome.reviewProviderAction(ctx, request.ProviderAction, request.Token, request.OwnerEmail, request.Agreement)
	}
	if request.Mode != "change" {
		return unsupportedClientAccessReview()
	}
	return outcome.reviewAction(ctx, request.Action, connectionprofiles.ProfileID(request.Profile))
}

func clientAccessEffects(action clientAccessAction, profile connectionprofiles.ProfileID) []string {
	switch action {
	case clientAccessRotateSubscription:
		return []string{"Replace only the subscription token", "Keep all six profile credentials unchanged", "Republish every representation atomically and refuse the old token"}
	case clientAccessRevokeAll:
		return []string{"Replace all six profile credentials and the subscription token", "Republish every representation atomically", "Refuse every prior Client Access value with no grace period"}
	case clientAccessRotateAllProfiles:
		return []string{"Replace all six profile credentials together", "Keep the subscription token unchanged", "Republish every representation atomically"}
	case clientAccessEnableProfile:
		return []string{"Enable " + string(profile), "Activate its selected listener and publication", "Update firewall and Cloudflare route when required"}
	case clientAccessDisableProfile:
		return []string{"Disable " + string(profile), "Close its listener and omit its publication", "Remove firewall and Cloudflare route material when required"}
	default:
		return []string{"Replace only the selected " + string(profile) + " credential", "Keep every other credential and the subscription token unchanged", "Republish every representation atomically"}
	}
}

func (outcome *clientAccessOutcome) Apply(_ context.Context, identity ownerconsole.PlanIdentity) ownerconsole.ChangeResult {
	outcome.mu.Lock()
	if outcome.session == nil || identity != ownerconsole.PlanIdentity(outcome.session.review.Identity) || outcome.change.Kind == ownerconsole.ChangeSetActive {
		outcome.mu.Unlock()
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed Client Access Plan is unavailable."}
	}
	session := outcome.session
	operation := ownerconsole.OperationIdentity(outcome.request.ChangeSet)
	total := session.review.TotalSteps
	outcome.request.Token, outcome.request.OwnerEmail = "", ""
	outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetActive, OperationID: operation, TotalSteps: total, Checkpoint: "Privileged Change Set running", Explanation: "The exact reviewed Client Access change is running."}
	outcome.mu.Unlock()
	go func() {
		terminal, err := session.apply()
		outcome.mu.Lock()
		defer outcome.mu.Unlock()
		switch {
		case err == nil && terminal == 'C':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetSucceeded, OperationID: operation, CompletedSteps: total, TotalSteps: total, Checkpoint: "Complete", Explanation: "The new Managed revision and every required agreement check passed."}
			outcome.loaded = false
		case err == nil && terminal == 'R':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRolledBack, OperationID: operation, TotalSteps: total, Checkpoint: "Rolled back", Explanation: "The complete prior Managed revision was restored."}
		case err == nil && terminal == 'A':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, TotalSteps: total, Checkpoint: "Awaiting Owner Rotate token", Explanation: "Select Rotate token for the committed Tunnel in Cloudflare, then continue the exact forward-only recovery. Rollback is no longer available."}
			outcome.loaded = false
		default:
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, TotalSteps: total, Checkpoint: "Recovery Required", Explanation: "The privileged process could not prove Complete or full rollback."}
		}
	}()
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangeStarted, OperationID: operation, Explanation: "The exact reviewed Client Access Change Set started."}
}

func (outcome *clientAccessOutcome) Inspect(context.Context) ownerconsole.DurableChangeSet {
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	return outcome.change
}
func (outcome *clientAccessOutcome) Fix(context.Context, ownerconsole.CorrectionInput) ownerconsole.ChangeReview {
	return unsupportedClientAccessReview()
}
func (outcome *clientAccessOutcome) CheckAgain(context.Context) ownerconsole.ChangeReview {
	return unsupportedClientAccessReview()
}
func (outcome *clientAccessOutcome) Back(context.Context) ownerconsole.ChangeReview {
	return unsupportedClientAccessReview()
}
func (outcome *clientAccessOutcome) Edit(ctx context.Context, input ownerconsole.EditingInput) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	action := outcome.providerAction
	if action != managedCertificateIP && action != managedCertificateDomain {
		outcome.mu.Unlock()
		return unsupportedClientAccessReview()
	}
	switch input.Field {
	case "owner-email":
		outcome.providerEmail = input.Text
		outcome.mu.Unlock()
		return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Certificate issuance or renewal", Field: ownerconsole.EditingField{Identity: "subscriber-agreement", Label: "Type AGREE after reviewing the subscriber agreement", Required: true}}}
	case "subscriber-agreement":
		outcome.providerAgree = input.Text == "AGREE"
		email, agreed := outcome.providerEmail, outcome.providerAgree
		outcome.mu.Unlock()
		if !agreed {
			return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Certificate issuance or renewal", Field: ownerconsole.EditingField{Identity: "subscriber-agreement", Label: "Type AGREE after reviewing the subscriber agreement", Required: true}}}
		}
		return outcome.reviewProviderAction(ctx, action, "", email, true)
	default:
		outcome.mu.Unlock()
		return unsupportedClientAccessReview()
	}
}
func (outcome *clientAccessOutcome) RequestCancellation(context.Context, ownerconsole.OperationIdentity) ownerconsole.ChangeResult {
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "Cancellation is unavailable after this privileged Client Access Change Set starts."}
}
func (outcome *clientAccessOutcome) ValidateProfile(context.Context, ownerconsole.AccessProfileID) ownerconsole.ProfileValidation {
	return ownerconsole.ProfileValidation{}
}
func (*clientAccessOutcome) RunLiveProfileCheck(context.Context) <-chan ownerconsole.LiveProfileCheckPresentation {
	channel := make(chan ownerconsole.LiveProfileCheckPresentation)
	close(channel)
	return channel
}

func unsupportedClientAccessReview() ownerconsole.ChangeReview {
	return clientAccessCorrection("This action belongs to a later integrated slice")
}
func clientAccessCorrection(found string) ownerconsole.ChangeReview {
	return ownerconsole.ChangeReview{Correction: &ownerconsole.CorrectionPresentation{Problem: "The Client Access Plan could not be prepared", Found: found, Required: "One fresh proven Managed revision and the exact supported Client Access action", WhyStopped: "SBXR never guesses privileged or secret-bearing inputs", FixWithSBXR: true, Selections: []ownerconsole.CorrectionSelection{{Identity: "back", Label: "Back"}}, Evidence: "CLIENT-ACCESS-PLAN-REFUSED"}}
}
func uintText(value uint64) string { return strconv.FormatUint(value, 10) }
