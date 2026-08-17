package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflareprofilesetup"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type clientAccessOutcome struct {
	mu                                     sync.Mutex
	setup                                  *cloudflareprofilesetup.Interface
	session                                *clientAccessHandoffSession
	request                                clientAccessHandoffRequest
	change                                 ownerconsole.DurableChangeSet
	presentation                           clientAccessPresentation
	loaded                                 bool
	providerAction                         managedProviderAction
	providerEmail                          string
	providerAgree                          bool
	lifecycleLoad                          func(context.Context) (softwarelifecycle.VerifiedRelease, softwarelifecycle.ViewResult, error)
	lifecycleView                          ownerconsole.LifecyclePresentation
	lifecycleInstalled, lifecycleCandidate softwarelifecycle.VerifiedRelease
	softwareReview                         *deferredSoftwareReview
	repairReview                           *deferredRepairReview
	removalReview                          *deferredRemovalReview
	softwareLaunch                         func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error)
	providerLaunch                         func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error)
	recoveryRetry                          func(context.Context, string) (systemchanges.InstallationStatus, error)
	removalPoll                            time.Duration
	sshPreflight                           func(clientAccessAction) *networkpolicy.SSHPreservationFailure
	clientAccessLaunch                     func(context.Context, clientAccessHandoffRequest) (*clientAccessHandoffSession, error)
	sshCorrectionAction                    clientAccessAction
	sshCorrectionProfile                   connectionprofiles.ProfileID
}

type deferredSoftwareReview struct {
	identity ownerconsole.PlanIdentity
	view     ownerconsole.LifecyclePresentation
}
type deferredRepairReview struct{ identity ownerconsole.PlanIdentity }
type deferredRemovalReview struct{ identity ownerconsole.PlanIdentity }

func (outcome *clientAccessOutcome) ViewCompleteRemoval(ctx context.Context) ownerconsole.CompleteRemovalPresentation {
	if outcome == nil {
		return ownerconsole.CompleteRemovalPresentation{}
	}
	outcome.mu.Lock()
	change := outcome.change
	mode := outcome.request.Mode
	outcome.mu.Unlock()
	facts := outcome.load(ctx)
	if facts.Removal.Kind != 0 && change.Kind == ownerconsole.NoChangeSet {
		return ownerCompleteRemovalPresentation(facts.Removal)
	}
	start := facts.Installation
	startingRevision := facts.StateRevision
	if facts.Removal.Kind != 0 {
		start, startingRevision = facts.Removal.StartingStatus, facts.Removal.StartingRevision
	}
	if start != ownerconsole.InstallationManaged && start != ownerconsole.InstallationRecoveryRequired {
		return ownerconsole.CompleteRemovalPresentation{}
	}
	presentation := ownerconsole.CompleteRemovalPresentation{Kind: ownerconsole.CompleteRemovalReviewAvailable, StartingStatus: start, StartingRevision: startingRevision, Checkpoint: ownerconsole.RemovalBeforeIrreversibleCheckpoint, TokenPhase: ownerconsole.RemovalTokenAvailable}
	if change.Kind == ownerconsole.ChangeSetActive && mode == "removal-apply" {
		presentation.Kind = ownerconsole.CompleteRemovalRollbackCapable
		presentation.Progress = ownerconsole.CompleteRemovalProgress{OperationID: change.OperationID, CompletedSteps: change.CompletedSteps, TotalSteps: change.TotalSteps}
	} else if change.Kind == ownerconsole.ChangeSetRecoveryRequired && mode == "removal-apply" {
		presentation.Kind = ownerconsole.CompleteRemovalRollbackCapable
		presentation.Progress = ownerconsole.CompleteRemovalProgress{OperationID: change.OperationID, CompletedSteps: change.CompletedSteps, TotalSteps: change.TotalSteps}
		if change.Checkpoint == "Provider deletion in progress" || change.Checkpoint == "Awaiting Owner token revocation" {
			presentation.Kind, presentation.Checkpoint, presentation.TokenPhase = ownerconsole.CompleteRemovalForwardOnly, ownerconsole.RemovalIrreversibleStarted, ownerconsole.RemovalProviderDeletionInProgress
			presentation.Progress.CompletedSteps = 4
		}
		if change.Checkpoint == "Awaiting Owner token revocation" {
			presentation.TokenPhase = ownerconsole.RemovalTokenAwaitingOwnerRevocation
			presentation.Progress.CompletedSteps = 7
		}
	} else if change.Kind == ownerconsole.ChangeSetRolledBack && mode == "removal-apply" {
		presentation.Kind, presentation.RestoredStatus, presentation.RestoredRevision, presentation.CancellationProof = ownerconsole.CompleteRemovalCancelled, start, startingRevision, ownerconsole.RemovalRestoredExactStart
	} else if change.Kind == ownerconsole.ChangeSetSucceeded && mode == "removal-apply" {
		presentation.Kind, presentation.FinalStatus, presentation.Checkpoint, presentation.TokenPhase, presentation.NoRecoveryMaterial = ownerconsole.CompleteRemovalSucceeded, ownerconsole.InstallationNotInstalled, ownerconsole.RemovalProvenComplete, ownerconsole.RemovalLocalTokenDeleted, true
		presentation.Progress = ownerconsole.CompleteRemovalProgress{OperationID: change.OperationID, CompletedSteps: change.TotalSteps, TotalSteps: change.TotalSteps}
	}
	return ownerCompleteRemovalPresentation(presentation)
}

func (outcome *clientAccessOutcome) CheckCompleteRemoval(ctx context.Context, operation ownerconsole.OperationIdentity) ownerconsole.CompleteRemovalPresentation {
	presentation := outcome.ViewCompleteRemoval(ctx)
	if presentation.Kind != ownerconsole.CompleteRemovalForwardOnly || presentation.TokenPhase != ownerconsole.RemovalTokenAwaitingOwnerRevocation || presentation.Progress.OperationID != operation {
		return ownerconsole.CompleteRemovalPresentation{}
	}
	outcome.advanceCompleteRemoval(ctx, presentation)
	return outcome.ViewCompleteRemoval(ctx)
}

func (outcome *clientAccessOutcome) WatchCompleteRemoval(ctx context.Context) <-chan ownerconsole.CompleteRemovalPresentation {
	updates := make(chan ownerconsole.CompleteRemovalPresentation, 1)
	go func() {
		defer close(updates)
		for {
			presentation := outcome.ViewCompleteRemoval(ctx)
			select {
			case updates <- presentation:
			case <-ctx.Done():
				return
			}
			if presentation.TokenPhase == ownerconsole.RemovalTokenAwaitingOwnerRevocation {
				return
			}
			if presentation.Kind != ownerconsole.CompleteRemovalRollbackCapable && presentation.Kind != ownerconsole.CompleteRemovalForwardOnly {
				return
			}
			delay := 250 * time.Millisecond
			if presentation.Kind == ownerconsole.CompleteRemovalForwardOnly {
				delay = outcome.removalPoll
				if delay <= 0 {
					delay = 10 * time.Second
				}
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			if presentation.Kind == ownerconsole.CompleteRemovalRollbackCapable || presentation.Kind == ownerconsole.CompleteRemovalForwardOnly {
				outcome.advanceCompleteRemoval(ctx, presentation)
			}
		}
	}()
	return updates
}

func (outcome *clientAccessOutcome) advanceCompleteRemoval(ctx context.Context, presentation ownerconsole.CompleteRemovalPresentation) {
	retry := outcome.recoveryRetry
	if retry == nil {
		retry = retryClientAccessRecovery
	}
	status, err := retry(ctx, string(presentation.Progress.OperationID))
	if err != nil {
		return
	}
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	outcome.request.Mode = "removal-apply"
	switch status {
	case systemchanges.NotInstalled:
		outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetSucceeded, OperationID: presentation.Progress.OperationID, CompletedSteps: presentation.Progress.TotalSteps, TotalSteps: presentation.Progress.TotalSteps, Checkpoint: "Not installed", Explanation: "Complete removal proved Not installed with no retained recovery material."}
	case systemchanges.Managed:
		outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRolledBack, OperationID: presentation.Progress.OperationID, Checkpoint: "Rolled back", Explanation: "Automatic recovery restored the exact Managed starting revision."}
	case "":
		outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: presentation.Progress.OperationID, CompletedSteps: 7, TotalSteps: presentation.Progress.TotalSteps, Checkpoint: "Awaiting Owner token revocation", Explanation: "Cloudflare resources are deleted. Revoke the exact Dedicated Broad User API Token, then continue the exact forward-only Complete removal."}
	}
}

func (outcome *clientAccessOutcome) ReviewCompleteRemoval(ctx context.Context, approval ownerconsole.CompleteRemovalApproval) ownerconsole.ChangeReview {
	if !approval.OwnerConsoleCompleteRemovalApproval() {
		return clientAccessCorrection("Both Complete removal confirmations are required")
	}
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	facts := outcome.load(ctx)
	request := clientAccessHandoffRequest{Schema: 1, Mode: "removal-review", ChangeSet: "complete-removal-" + hex.EncodeToString(identity)}
	launch := outcome.softwareLaunch
	if launch == nil {
		launch = launchClientAccessReview
	}
	session, err := launch(ctx, request)
	if err != nil || session.review.StartingRevision != facts.StateRevision {
		session.discard()
		if facts.Installation == ownerconsole.InstallationRecoveryRequired {
			return ownerconsole.ChangeReview{Correction: &ownerconsole.CorrectionPresentation{
				Problem:    "Complete removal cannot prove the Cloudflare resources owned by this installation",
				Found:      "Desired State lineage or scoped Cloudflare authority is unavailable",
				Required:   "Exact immutable Tunnel and DNS record IDs plus the active Dedicated Broad User API Token",
				WhyStopped: "SBXR will not treat corrupt raw State or same-named provider resources as ownership proof",
				OwnerSteps: []string{"Use Diagnostics to preserve safe evidence", "Remove only independently verified provider resources", "Rebuild SBXR on a clean VPS"},
				Selections: []ownerconsole.CorrectionSelection{{Identity: "back", Label: "Back"}},
				Evidence:   "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-OWNERSHIP-UNPROVED",
			}}
		}
		return clientAccessCorrection("The privileged Complete removal Plan did not match the reviewed installation")
	}
	request.Mode = "removal-apply"
	request.ReviewedPlanIdentity, request.ReviewedPlanSHA256 = session.review.Identity, session.review.SHA256
	reviewIdentity := ownerconsole.PlanIdentity(session.review.Identity)
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request, outcome.removalReview = nil, request, &deferredRemovalReview{identity: reviewIdentity}
	outcome.softwareReview, outcome.repairReview = nil, nil
	outcome.mu.Unlock()
	prior.discard()
	return ownerconsole.ChangeReview{Plan: &session.review.Plan}
}

func (outcome *clientAccessOutcome) CancelCompleteRemoval(ctx context.Context, operation ownerconsole.OperationIdentity) ownerconsole.CompleteRemovalPresentation {
	_ = outcome.RequestCancellation(ctx, operation)
	return outcome.ViewCompleteRemoval(ctx)
}

func (outcome *clientAccessOutcome) ViewLifecycle(ctx context.Context) ownerconsole.LifecyclePresentation {
	if outcome == nil {
		return ownerconsole.LifecyclePresentation{}
	}
	if outcome.lifecycleLoad == nil {
		return outcome.load(ctx).Lifecycle
	}
	installed, view, err := outcome.lifecycleLoad(ctx)
	if err != nil || view.VerifiedCandidate == nil || len(view.PermittedActions) != 1 {
		return ownerconsole.LifecyclePresentation{}
	}
	presentation := softwareLifecyclePresentation(installed, view)
	outcome.mu.Lock()
	outcome.lifecycleView = presentation
	outcome.lifecycleInstalled, outcome.lifecycleCandidate = installed, *view.VerifiedCandidate
	outcome.mu.Unlock()
	return presentation
}

func softwareLifecyclePresentation(installed softwarelifecycle.VerifiedRelease, view softwarelifecycle.ViewResult) ownerconsole.LifecyclePresentation {
	if view.VerifiedCandidate == nil || len(view.PermittedActions) != 1 {
		return ownerconsole.LifecyclePresentation{}
	}
	change := map[softwarelifecycle.Action]ownerconsole.LifecycleChange{softwarelifecycle.ReviewUpdate: ownerconsole.ReviewUpdate, softwarelifecycle.ReviewDowngrade: ownerconsole.ReviewDowngrade}[view.PermittedActions[0]]
	if change == 0 {
		return ownerconsole.LifecyclePresentation{}
	}
	migration := view.MigrationSummary
	if migration == "" {
		migration = "No State schema migration"
	}
	return ownerconsole.LifecyclePresentation{
		Change: change, Installed: releaseIdentityPresentation(installed), Candidate: releaseIdentityPresentation(*view.VerifiedCandidate),
		FreshlyVerified: true, CompatibleWithDesiredState: view.UpdateEligible || view.DowngradeCompatible, DiscoveryCannotApply: true, DowngradeSelectionAvailable: true,
		AuthenticatedSequence: "download, verify release index and assets, stage, approve, switch, and verify agreement",
		Migrations:            []string{migration}, RegeneratedRepresentations: []string{"raw", "base64", "v2rayN", "Shadowrocket", "Karing", "Mihomo", "sing-box"},
		AffectedServices: []string{"cloudflared.service", "sbxr-subscription.service", "sing-box.service", "xray.service"},
		RequiredChecks:   []string{"SOFTWARE-LIFECYCLE-UPDATE-STAGED", "SOFTWARE-LIFECYCLE-UPDATE-AGREEMENT", "State and publication agreement"},
		AdvisoryChecks:   []string{"Outside-client and provider acceptance remains pending until performed"},
		Interruption:     "brief controlled restart of only affected services", Cancellation: "Back before Apply changes nothing; after start, cancellation waits for a safe checkpoint", Rollback: "automatic exact prior-release rollback from the one transaction snapshot",
	}
}

func releaseIdentityPresentation(release softwarelifecycle.VerifiedRelease) ownerconsole.ReleaseIdentityPresentation {
	return ownerconsole.ReleaseIdentityPresentation{Repository: release.Identity.Repository, Tag: release.Identity.Tag, Commit: release.Identity.Commit, IndexSHA256: release.Identity.IndexSHA256, Sequence: release.Sequence}
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

func (outcome *clientAccessOutcome) RetryAutomaticRollback(ctx context.Context) ownerconsole.RecoveryRetryResult {
	presentation := outcome.load(ctx).Recovery
	return ownerRecovery{
		changeSet: presentation.ChangeSet, forwardOnly: presentation.Kind == ownerconsole.RecoveryForwardOnly,
		completeRemoval:       presentation.CauseCode == "SYSTEM-CHANGES-COMPLETE-REMOVAL-FORWARD",
		installationForward:   presentation.InstallationForward,
		needsRunTokenRotation: presentation.Evidence == "IRREVERSIBLE-RUN-TOKEN-ROTATION-STARTED" && strings.Contains(presentation.Guidance, "Select Rotate token"),
	}.RetryAutomaticRollback(ctx)
}

func (outcome *clientAccessOutcome) ReviewCurrentStateRepair(ctx context.Context) ownerconsole.ChangeReview {
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	facts := outcome.load(ctx)
	request := clientAccessHandoffRequest{Schema: 1, Mode: "software-review", SoftwareAction: "repair", ChangeSet: "repair-" + hex.EncodeToString(identity)}
	launch := outcome.softwareLaunch
	if launch == nil {
		launch = launchClientAccessReview
	}
	session, err := launch(ctx, request)
	if err != nil {
		return clientAccessCorrection(err.Error())
	}
	if session.review.StartingRevision != facts.StateRevision || session.review.VolatileSHA256 != facts.Repair.VolatileSHA256 {
		return clientAccessCorrection("The privileged repair Plan did not match the reviewed Managed facts")
	}
	request.Mode = "software-apply"
	request.ReviewedPlanIdentity, request.ReviewedPlanSHA256 = session.review.Identity, session.review.SHA256
	reviewIdentity := ownerconsole.PlanIdentity(session.review.Identity)
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request = nil, request
	outcome.softwareReview, outcome.repairReview = nil, &deferredRepairReview{identity: reviewIdentity}
	outcome.removalReview = nil
	outcome.mu.Unlock()
	prior.discard()
	return ownerconsole.ChangeReview{Plan: &session.review.Plan}
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

func (outcome *clientAccessOutcome) ReviewLifecycleChange(ctx context.Context, change ownerconsole.LifecycleChange) ownerconsole.ChangeReview {
	if change == ownerconsole.ReviewDowngrade {
		outcome.mu.Lock()
		outcome.request = clientAccessHandoffRequest{Schema: 1, Mode: "software-review", SoftwareAction: "downgrade"}
		outcome.mu.Unlock()
		return downgradeEditing("", "")
	}
	if change != ownerconsole.ReviewUpdate {
		return unsupportedClientAccessReview()
	}
	return outcome.reviewSoftwareChange(ctx, softwareUpdate, "")
}

func (outcome *clientAccessOutcome) reviewSoftwareChange(ctx context.Context, action softwareChangeAction, tag string) ownerconsole.ChangeReview {
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	facts := outcome.load(ctx)
	view := outcome.ViewLifecycle(ctx)
	want := ownerconsole.ReviewUpdate
	if action == softwareDowngrade {
		want = ownerconsole.ReviewDowngrade
	}
	selectedTag := view.Candidate.Tag
	if action == softwareDowngrade {
		selectedTag = tag
	}
	if selectedTag == "" || action == softwareUpdate && view.Change != want {
		if action == softwareDowngrade {
			return downgradeEditing(tag, "SBXR could not prove this tag is an older compatible release. Choose another official tag or try again.")
		}
		return clientAccessCorrection("Fresh Software Lifecycle selection is unavailable")
	}
	request := clientAccessHandoffRequest{Schema: 1, Mode: "software-review", SoftwareAction: string(action), ReleaseTag: selectedTag, ChangeSet: string(action) + "-" + hex.EncodeToString(identity)}
	launch := outcome.softwareLaunch
	if launch == nil {
		launch = launchClientAccessReview
	}
	session, err := launch(ctx, request)
	if err != nil {
		if action == softwareDowngrade {
			return downgradeEditing(tag, "SBXR could not prove this tag is an older compatible release. Choose another official tag or try again.")
		}
		return clientAccessCorrection(err.Error())
	}
	selected := view.Candidate
	if action == softwareDowngrade {
		selected = ownerconsole.ReleaseIdentityPresentation{Repository: softwarelifecycle.Repository, Tag: session.review.CandidateTag, Commit: session.review.CandidateCommit, IndexSHA256: session.review.CandidateIndexSHA256}
		view = ownerconsole.LifecyclePresentation{Change: ownerconsole.ReviewDowngrade, Candidate: selected}
	}
	if session.review.StartingRevision != facts.StateRevision || session.review.CandidateRevision != facts.StateRevision+1 || session.review.CandidateTag != selected.Tag || session.review.CandidateCommit != selected.Commit || session.review.CandidateIndexSHA256 != selected.IndexSHA256 {
		return clientAccessCorrection("The privileged Software Lifecycle Plan did not match the selected release")
	}
	reviewIdentity := ownerconsole.PlanIdentity(session.review.Identity)
	request.Mode = "software-apply"
	request.ReviewedPlanIdentity, request.ReviewedPlanSHA256 = session.review.Identity, session.review.SHA256
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request = nil, request
	outcome.softwareReview = &deferredSoftwareReview{identity: reviewIdentity, view: view}
	outcome.repairReview = nil
	outcome.removalReview = nil
	outcome.mu.Unlock()
	prior.discard()
	return ownerconsole.ChangeReview{Plan: &session.review.Plan}
}

func (outcome *clientAccessOutcome) ActOnCloudflare(ctx context.Context, request ownerconsole.CloudflareRequest) ownerconsole.CloudflareResponse {
	if request.Action == ownerconsole.VerifyInitialManagementToken && !request.DedicatedBroadPolicyConfirmed {
		return ownerconsole.CloudflareResponse{}
	}
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
		ownerconsole.ReviewManagementTokenRotation:    managedCloudflareRotateManagement,
		ownerconsole.ReviewTunnelRunTokenRotation:     managedCloudflareRotate,
	}[request.Action]
	if action == "" {
		return ownerconsole.CloudflareResponse{}
	}
	outcome.mu.Lock()
	outcome.providerAction = action
	outcome.providerEmail, outcome.providerAgree = "", false
	outcome.mu.Unlock()
	review := outcome.reviewProviderAction(ctx, action, request.Token, "", false, request.DedicatedBroadPolicyConfirmed)
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
	return certificateEditing("owner-email", "", "")
}

func downgradeEditing(value, feedback string) ownerconsole.ChangeReview {
	guidance := softwarelifecycle.DowngradeInputGuidance()
	return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Select compatible downgrade", Field: ownerconsole.EditingField{Identity: "release-tag", Label: "Exact immutable release tag", Value: value, Required: true}, Feedback: feedback, Help: ownerconsole.EditingHelp{Purpose: guidance.Purpose, Instructions: guidance.Instructions, AcceptedFormat: guidance.AcceptedFormat, CommonMistakes: guidance.CommonMistakes, Recovery: guidance.Recovery, Example: guidance.Example, URL: guidance.URL, Sensitivity: ownerconsole.PublicInformation}}}
}

func certificateEditing(field, value, feedback string) ownerconsole.ChangeReview {
	guidance := certificatelifecycle.OwnerEmailInputGuidance()
	label, sensitivity := "Owner email", ownerconsole.PersonalInformation
	facts := []ownerconsole.EditingFact(nil)
	if field == "subscriber-agreement" {
		guidance = certificatelifecycle.SubscriberAgreementInputGuidance()
		label, sensitivity = "Type AGREE after reviewing the subscriber agreement", ownerconsole.PublicInformation
		facts = []ownerconsole.EditingFact{{Label: "Let's Encrypt Policy and Legal Repository", Value: guidance.URL}}
	}
	return ownerconsole.ChangeReview{Editing: &ownerconsole.EditingPresentation{Title: "Certificate issuance or renewal", Facts: facts, Field: ownerconsole.EditingField{Identity: field, Label: label, Value: value, Required: true}, Feedback: feedback, Help: ownerconsole.EditingHelp{Purpose: guidance.Purpose, Instructions: guidance.Instructions, AcceptedFormat: guidance.AcceptedFormat, CommonMistakes: guidance.CommonMistakes, Recovery: guidance.Recovery, Example: guidance.Example, URL: guidance.URL, Sensitivity: sensitivity}}}
}

func (outcome *clientAccessOutcome) reviewAction(ctx context.Context, action clientAccessAction, profile connectionprofiles.ProfileID) ownerconsole.ChangeReview {
	if clientAccessChangesFirewall(action) {
		preflight := outcome.sshPreflight
		if preflight == nil {
			preflight = func(action clientAccessAction) *networkpolicy.SSHPreservationFailure {
				_, failure := managedClientAccessSSHPreservation(action)
				return failure
			}
		}
		if failure := preflight(action); failure != nil {
			outcome.mu.Lock()
			outcome.sshCorrectionAction, outcome.sshCorrectionProfile = action, profile
			outcome.mu.Unlock()
			return clientAccessSSHCorrection(failure.Cause)
		}
	}
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	request := clientAccessHandoffRequest{Schema: 1, Mode: "change", Action: action, Profile: string(profile), ChangeSet: "client-access-" + hex.EncodeToString(identity)}
	launch := outcome.clientAccessLaunch
	if launch == nil {
		launch = launchClientAccessReview
	}
	session, err := launch(ctx, request)
	if err != nil {
		var sshFailure *sshPreservationFailureError
		if errors.As(err, &sshFailure) {
			outcome.mu.Lock()
			outcome.sshCorrectionAction, outcome.sshCorrectionProfile = action, profile
			outcome.mu.Unlock()
			return clientAccessSSHCorrection(sshFailure.Cause)
		}
		return clientAccessCorrection(err.Error())
	}
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request = session, request
	outcome.sshCorrectionAction, outcome.sshCorrectionProfile = "", ""
	outcome.softwareReview = nil
	outcome.repairReview = nil
	outcome.removalReview = nil
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

func (outcome *clientAccessOutcome) reviewProviderAction(ctx context.Context, action managedProviderAction, token, email string, agreement, broadPolicyConfirmed bool) ownerconsole.ChangeReview {
	identity := make([]byte, 12)
	if _, err := rand.Read(identity); err != nil {
		return clientAccessCorrection("Change Set identity generation failed")
	}
	request := clientAccessHandoffRequest{Schema: 1, Mode: "provider", ProviderAction: action, ChangeSet: "provider-" + hex.EncodeToString(identity), Token: token, OwnerEmail: email, Agreement: agreement, DedicatedBroadPolicyConfirmed: broadPolicyConfirmed}
	launch := outcome.providerLaunch
	if launch == nil {
		launch = launchClientAccessReview
	}
	session, err := launch(ctx, request)
	if err != nil {
		return clientAccessCorrection(err.Error())
	}
	outcome.mu.Lock()
	prior := outcome.session
	outcome.session, outcome.request = session, request
	outcome.softwareReview = nil
	outcome.repairReview = nil
	outcome.removalReview = nil
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
	case managedCloudflareRotateManagement:
		return []string{"Create and prove one transaction-bound management-token candidate", "Revoke the old token only after the durable irreversible checkpoint"}
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
		return outcome.reviewProviderAction(ctx, request.ProviderAction, request.Token, request.OwnerEmail, request.Agreement, request.DedicatedBroadPolicyConfirmed)
	}
	if (request.Mode == "software-review" || request.Mode == "software-apply") && request.SoftwareAction != "view" {
		if request.SoftwareAction == "repair" {
			return outcome.ReviewCurrentStateRepair(ctx)
		}
		return outcome.reviewSoftwareChange(ctx, softwareChangeAction(request.SoftwareAction), request.ReleaseTag)
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

func (outcome *clientAccessOutcome) Apply(ctx context.Context, identity ownerconsole.PlanIdentity) ownerconsole.ChangeResult {
	outcome.mu.Lock()
	if outcome.change.Kind == ownerconsole.ChangeSetActive {
		outcome.mu.Unlock()
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed Client Access Plan is unavailable."}
	}
	if outcome.session == nil && outcome.repairReview != nil && identity == outcome.repairReview.identity {
		request, facts := outcome.request, outcome.presentation
		launch := outcome.softwareLaunch
		if launch == nil {
			launch = launchClientAccessReview
		}
		outcome.mu.Unlock()
		session, err := launch(ctx, request)
		if err != nil || session.review.Identity != request.ReviewedPlanIdentity || session.review.SHA256 != request.ReviewedPlanSHA256 || session.review.StartingRevision != facts.StateRevision || session.review.VolatileSHA256 != facts.Repair.VolatileSHA256 {
			session.discard()
			return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The approved current-State repair changed during privileged recheck."}
		}
		outcome.mu.Lock()
		if outcome.session != nil || outcome.repairReview == nil || outcome.repairReview.identity != identity || outcome.change.Kind == ownerconsole.ChangeSetActive {
			outcome.mu.Unlock()
			session.discard()
			return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed current-State repair is unavailable."}
		}
		outcome.session = session
	}
	if outcome.session == nil && outcome.softwareReview != nil && identity == outcome.softwareReview.identity {
		request, reviewed, facts := outcome.request, outcome.softwareReview.view, outcome.presentation
		launch := outcome.softwareLaunch
		if launch == nil {
			launch = launchClientAccessReview
		}
		outcome.mu.Unlock()
		session, err := launch(ctx, request)
		if err != nil || session.review.Identity != request.ReviewedPlanIdentity || session.review.SHA256 != request.ReviewedPlanSHA256 || session.review.StartingRevision != facts.StateRevision || session.review.CandidateRevision != facts.StateRevision+1 || session.review.CandidateTag != reviewed.Candidate.Tag || session.review.CandidateCommit != reviewed.Candidate.Commit || session.review.CandidateIndexSHA256 != reviewed.Candidate.IndexSHA256 {
			session.discard()
			return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The approved Software Lifecycle Plan changed during privileged recheck."}
		}
		outcome.mu.Lock()
		if outcome.session != nil || outcome.softwareReview == nil || outcome.softwareReview.identity != identity || outcome.change.Kind == ownerconsole.ChangeSetActive {
			outcome.mu.Unlock()
			session.discard()
			return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed Software Lifecycle Plan is unavailable."}
		}
		outcome.session = session
	}
	if outcome.session == nil && outcome.removalReview != nil && identity == outcome.removalReview.identity {
		request, facts := outcome.request, outcome.presentation
		launch := outcome.softwareLaunch
		if launch == nil {
			launch = launchClientAccessReview
		}
		outcome.mu.Unlock()
		session, err := launch(ctx, request)
		if err != nil || session.review.Identity != request.ReviewedPlanIdentity || session.review.SHA256 != request.ReviewedPlanSHA256 || session.review.StartingRevision != facts.StateRevision {
			session.discard()
			return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The approved Complete removal Plan changed during privileged recheck."}
		}
		outcome.mu.Lock()
		if outcome.session != nil || outcome.removalReview == nil || outcome.removalReview.identity != identity || outcome.change.Kind == ownerconsole.ChangeSetActive {
			outcome.mu.Unlock()
			session.discard()
			return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed Complete removal Plan is unavailable."}
		}
		outcome.session = session
		outcome.session.removalApproved = true
	}
	validIdentity := outcome.softwareReview != nil && identity == outcome.softwareReview.identity || outcome.repairReview != nil && identity == outcome.repairReview.identity || outcome.removalReview != nil && identity == outcome.removalReview.identity || outcome.softwareReview == nil && outcome.repairReview == nil && outcome.removalReview == nil && outcome.session != nil && identity == ownerconsole.PlanIdentity(outcome.session.review.Identity)
	if outcome.session == nil || !validIdentity {
		outcome.mu.Unlock()
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "The exact reviewed Client Access Plan is unavailable."}
	}
	session := outcome.session
	operation := ownerconsole.OperationIdentity(outcome.request.ChangeSet)
	total := session.review.TotalSteps
	removal := outcome.request.Mode == "removal-apply"
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
			if !removal {
				outcome.loaded = false
			}
		case err == nil && terminal == 'R':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRolledBack, OperationID: operation, TotalSteps: total, Checkpoint: "Rolled back", Explanation: "The complete prior Managed revision was restored."}
		case err == nil && terminal == 'A':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, TotalSteps: total, Checkpoint: "Awaiting Owner Rotate token", Explanation: "Select Rotate token for the committed Tunnel in Cloudflare, then continue the exact forward-only recovery. Rollback is no longer available."}
			outcome.loaded = false
		case err == nil && terminal == 'D':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, TotalSteps: total, Checkpoint: "Awaiting Owner token revocation", Explanation: "Cloudflare resources are deleted. Revoke the exact Dedicated Broad User API Token, then continue the exact forward-only Complete removal. Back and Cancel are unavailable."}
		case err == nil && terminal == 'P':
			outcome.change = ownerconsole.DurableChangeSet{Kind: ownerconsole.ChangeSetRecoveryRequired, OperationID: operation, TotalSteps: total, Checkpoint: "Provider deletion in progress", Explanation: "Complete removal is forward-only. Keep the Dedicated Broad User API Token active while SBXR retries the exact next Cloudflare deletion."}
		default:
			outcome.loaded = false
			outcome.change = ownerconsole.DurableChangeSet{}
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
func (outcome *clientAccessOutcome) CheckAgain(ctx context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	action, profile := outcome.sshCorrectionAction, outcome.sshCorrectionProfile
	outcome.mu.Unlock()
	if !clientAccessChangesFirewall(action) {
		return unsupportedClientAccessReview()
	}
	return outcome.reviewAction(ctx, action, profile)
}
func (outcome *clientAccessOutcome) Back(context.Context) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	outcome.sshCorrectionAction, outcome.sshCorrectionProfile = "", ""
	outcome.mu.Unlock()
	return ownerconsole.ChangeReview{}
}
func (outcome *clientAccessOutcome) Edit(ctx context.Context, input ownerconsole.EditingInput) ownerconsole.ChangeReview {
	outcome.mu.Lock()
	if outcome.request.Mode == "software-review" && outcome.request.SoftwareAction == "downgrade" && input.Field == "release-tag" {
		outcome.mu.Unlock()
		if !softwarelifecycle.ValidDowngradeTag(input.Text) {
			return downgradeEditing(input.Text, "Enter one exact immutable release tag in vX.Y.Z form.")
		}
		return outcome.reviewSoftwareChange(ctx, softwareDowngrade, input.Text)
	}
	action := outcome.providerAction
	if action != managedCertificateIP && action != managedCertificateDomain {
		outcome.mu.Unlock()
		return unsupportedClientAccessReview()
	}
	switch input.Field {
	case "owner-email":
		if !certificatelifecycle.ValidOwnerEmail(input.Text) {
			outcome.mu.Unlock()
			return certificateEditing("owner-email", input.Text, "Enter one exact local-part@domain email address without a display name or spaces.")
		}
		outcome.providerEmail = input.Text
		outcome.mu.Unlock()
		return certificateEditing("subscriber-agreement", "", "")
	case "subscriber-agreement":
		outcome.providerAgree = input.Text == "AGREE"
		email, agreed := outcome.providerEmail, outcome.providerAgree
		outcome.mu.Unlock()
		if !agreed {
			return certificateEditing("subscriber-agreement", input.Text, "Type exact uppercase AGREE only after you review the current agreement.")
		}
		return outcome.reviewProviderAction(ctx, action, "", email, true, false)
	default:
		outcome.mu.Unlock()
		return unsupportedClientAccessReview()
	}
}
func (outcome *clientAccessOutcome) RequestCancellation(_ context.Context, operation ownerconsole.OperationIdentity) ownerconsole.ChangeResult {
	outcome.mu.Lock()
	software := (outcome.request.Mode == "software-apply" || outcome.request.Mode == "removal-apply") && outcome.change.Kind == ownerconsole.ChangeSetActive && outcome.change.OperationID == operation
	session := outcome.session
	outcome.mu.Unlock()
	if !software || session.cancel() != nil {
		return ownerconsole.ChangeResult{Kind: ownerconsole.ChangePlanRejected, Explanation: "Cancellation is unavailable at this Change Set checkpoint."}
	}
	return ownerconsole.ChangeResult{Kind: ownerconsole.ChangeCancellationRequested, OperationID: operation, Explanation: "Cancellation will restore the exact prior Managed release and State at the next safe checkpoint."}
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

func clientAccessSSHCorrection(cause networkpolicy.SSHPreservationFailureCause) ownerconsole.ChangeReview {
	found := "the direct SSH launch identity is missing or invalid"
	steps := []string{"Exit and restart SBXR through one direct SSH session."}
	if cause == networkpolicy.SSHOriginalSessionLost {
		found = "the original direct SSH session is no longer established"
	} else if sshObservationTemporary(cause) {
		found = "the SSH service, listener, or established-session observation is temporarily unavailable"
		steps = []string{"Use Check again for a fresh read-only observation, or select Back."}
	}
	return ownerconsole.ChangeReview{Correction: &ownerconsole.CorrectionPresentation{
		Problem: "The Client Access firewall change could not prove the original direct SSH session", Found: found,
		Required: "fresh SSH Preservation Proof for the exact launch session", WhyStopped: "Managed Client Access cannot preserve a different or unproved SSH session",
		HideCheckAgain: !sshObservationTemporary(cause), OwnerSteps: steps, Evidence: "CLIENT-ACCESS-PLAN-REFUSED",
	}}
}
func uintText(value uint64) string { return strconv.FormatUint(value, 10) }
