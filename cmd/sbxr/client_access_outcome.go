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
	mu           sync.Mutex
	session      *clientAccessHandoffSession
	request      clientAccessHandoffRequest
	change       ownerconsole.DurableChangeSet
	presentation clientAccessPresentation
	loaded       bool
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

func (outcome *clientAccessOutcome) Review(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	request := outcome.request
	outcome.mu.Unlock()
	if !validClientAccessHandoff(request) || request.Mode != "change" {
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
func (outcome *clientAccessOutcome) Edit(context.Context, ownerconsole.EditingInput) ownerconsole.ChangeReview {
	return unsupportedClientAccessReview()
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
