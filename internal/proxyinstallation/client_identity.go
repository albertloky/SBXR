package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type clientIdentityHost interface {
	PlanProxyStartupIntegration() (hostadapter.ProxyStartupAuthority, hostadapter.Observation)
	ClientIdentityPreparationIdle() hostadapter.Observation
	PrepareClientIdentityTarget([]byte, string) bool
	PublishProxyStartupIntegration(hostadapter.ProxyStartupAuthority) bool
	ReloadProxyStartupIntegration(context.Context) bool
	VerifyProxyStartupIntegration(context.Context, hostadapter.ProxyStartupAuthority) bool
	StopProxyForClientIdentityRotation(context.Context) bool
	ProxyQuiescentForClientIdentityRotation(context.Context) bool
	PublishClientIdentityConfiguration(string, string) bool
	StartProxyForClientIdentityRotation(context.Context, string) bool
	RemoveClientIdentityTarget(string, string) bool
	RestoreClientIdentityRotation(context.Context, string, string, *hostadapter.ProxyStartupAuthority) bool
	InspectClientIdentityRotation(string, string, string, *hostadapter.ProxyStartupAuthority, bool, bool, bool) hostadapter.Observation
	RemoveProxyStartupIntegration(context.Context, hostadapter.ProxyStartupAuthority) bool
}

type proxyStartHost interface {
	ReadOwnership(string) ([]byte, error)
	ReadConfiguration(context.Context, hostadapter.SetupSpec, string) ([]byte, error)
	MutationInProgress(string) (bool, bool)
	VerifyProxyStartupIntegration(context.Context, hostadapter.ProxyStartupAuthority) bool
	ConsumeProxyStartAuthorization(string) bool
}

// AuthorizeProxyStart is the fixed private ExecCondition route. It never
// creates authority or chooses a recovery direction.
func AuthorizeProxyStart(ctx context.Context, lifecycle softwarelifecycle.Interface) bool {
	return authorizeProxyStart(ctx, lifecycle, hostadapter.New())
}

func authorizeProxyStart(ctx context.Context, lifecycle softwarelifecycle.Interface, host proxyStartHost) bool {
	status := lifecycle.Status(ctx)
	body, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	record, ok := decodeOwnership(body)
	if err != nil || !ok || status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || record.Phase != runningPhase || record.Direction != noDirection || record.Startup == nil || !host.VerifyProxyStartupIntegration(ctx, *record.Startup) {
		return false
	}
	if _, err := host.ReadConfiguration(ctx, hostSetupSpec, record.ConfigurationSHA256); err != nil {
		return false
	}
	if record.ClientRotation == nil {
		return true
	}
	policy, _, known := clientIdentityPolicy(record.ClientRotation.Checkpoint)
	if !known {
		return false
	}
	if policy.ordinaryStart {
		return record.ConfigurationSHA256 == record.ClientRotation.Source
	}
	held, valid := host.MutationInProgress(hostSetupSpec.LockPath)
	if !held || !valid {
		return false
	}
	selected := record.ClientRotation.Source
	if record.ClientRotation.Direction == "forward" {
		selected = record.ClientRotation.Target
	}
	return record.ConfigurationSHA256 == selected && host.ConsumeProxyStartAuthorization(selected)
}

func clientIdentityRotationPlan() []string {
	return []string{
		"Action: Rotate Client Identity",
		"Replace only the VLESS UUID. Preserve the endpoint, destination, REALITY key pair, short ID, package identity, and resource provenance.",
		"Existing proxy sessions will disconnect during cutover. New sessions cannot use the revoked Client Identity.",
		"The Subscription Capability is Not enabled; this action will not enable it and the same Subscription Link remains unchanged.",
		"A failed replacement after revocation can cause an extended outage. Finish only the prepared replacement; never restore the revoked identity.",
		"After completion, use the separately confirmed Show client configuration fallback. No secret is displayed automatically.",
		"A leaked Subscription Link can obtain a replacement identity when serving is enabled. Rotate a leaked Subscription Link before rotating the Client Identity.",
	}
}

func (module *installedInterface) prepareClientIdentityFinishReview(ctx context.Context, action Action, review Review, record ownershipRecord, body []byte, installed softwarelifecycle.ReleaseIdentity) Review {
	host, ok := module.host.(clientIdentityHost)
	targetRequired, startupRequired := clientRotationRequirements(record.ClientRotation.Checkpoint)
	accepted := ok && host.InspectClientIdentityRotation(record.ClientRotation.Source, record.ClientRotation.Target, record.ConfigurationSHA256, record.Startup, targetRequired, startupRequired, record.ClientRotation.Direction == "forward").Accepted
	review.Status = ChangeIncomplete
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	review.ProxyTraffic = CannotBeVerified
	if runningAccepted(running) {
		review.ProxyTraffic = ProvedWorking
	}
	review.LegalActions = []Action{FinishClientIdentityAction, ViewDetailsAction, CompleteRemovalAction}
	review.Result = Result{Status: ChangeIncomplete, Message: "Client Identity rotation needs safe cleanup or completion.", Code: StatusChangeIncomplete}
	review.Details = append(ownedDetails(installed, true, ChangeIncomplete, record, running, "Available"), "Client Identity rotation direction: "+record.ClientRotation.Direction)
	if !accepted {
		review.Status = ProblemDetected
		review.LegalActions = []Action{ViewDetailsAction}
		review.Result = refused(ProblemDetected, "Client Identity rotation authority", "Restore the exact protected source, target, startup, and Ownership Record facts, then inspect again.")
		return review
	}
	if action == StatusAction || action == ViewDetailsAction {
		return review
	}
	if action == CompleteRemovalAction {
		surface := module.host.Inspect(ctx, slices.Clone(footprint))
		removal := module.host.InspectRemoval(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
		if !inspectionAccepted(surface) || !removalAccepted(removal) {
			review.Result = refused(ChangeIncomplete, "Complete removal preflight", removalCorrection(removal))
			return review
		}
		return module.prepareRemoval(review, installed, &record, body, surface, removal)
	}
	if action != FinishClientIdentityAction {
		review.Result = refused(ChangeIncomplete, "Legal action", "Choose Finish Client Identity rotation, View details, or Complete removal.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: action, status: ChangeIncomplete, release: installed, record: slices.Clone(body)}
	review.Prepared = &PreparedAction{token: token}
	direction := "clean up the unused target and restore only the proved unchanged source"
	policy, _, _ := clientIdentityPolicy(record.ClientRotation.Checkpoint)
	remaining := []string{"prove the unchanged source"}
	if policy.targetRequired {
		remaining = append(remaining, "remove the unused target")
	}
	if policy.startupRequired {
		remaining = append(remaining, "verify and retain the startup integration, or remove only the recorded incomplete integration")
	}
	remaining = append(remaining, "clear rotation authority")
	if record.ClientRotation.Direction == "forward" {
		direction = "finish only the prepared target; the revoked source can never be restored"
		remaining = slices.Clone(record.ClientRotation.Effects[len(record.ClientRotation.Completed):])
	}
	review.Plan = []string{"Action: Finish Client Identity rotation", "Selected direction: " + direction + ".", "Remaining effects: " + strings.Join(remaining, ", ") + ".", "Proxy traffic availability: " + string(review.ProxyTraffic) + ".", "Subscription serving availability: " + string(ProvedStopped) + ".", "Subscription Capability remains Not enabled.", "No Client Configuration is displayed automatically."}
	return review
}

func (module *installedInterface) finishClientIdentityRotation(ctx context.Context, authority preparedReview, progress ProgressReporter) Result {
	host, ok := module.host.(clientIdentityHost)
	if !ok {
		return clientIdentityFailed("Client Identity rotation Adapter", "Use a qualified release with complete recovery support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(ChangeIncomplete, "SBXR mutation lock", "Wait for active SBXR work, then review Finish Client Identity rotation again.")
	}
	defer lock.Release()
	installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
	current, readErr := module.readOwnership()
	record, valid := decodeOwnership(current)
	targetRequired, startupRequired := false, false
	if record.ClientRotation != nil {
		targetRequired, startupRequired = clientRotationRequirements(record.ClientRotation.Checkpoint)
	}
	forward := record.ClientRotation != nil && record.ClientRotation.Direction == "forward"
	if readErr != nil || !valid || !bytes.Equal(current, authority.record) || record.ClientRotation == nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !host.InspectClientIdentityRotation(record.ClientRotation.Source, record.ClientRotation.Target, record.ConfigurationSHA256, record.Startup, targetRequired, startupRequired, forward).Accepted {
		return refused(ChangeIncomplete, "Prepared Action facts", "Restore the reviewed durable rotation authority, then review again.")
	}
	if record.ClientRotation.Direction == "cleanup" {
		report(progress, "Cleaning up Client Identity rotation")
		if !host.RestoreClientIdentityRotation(context.WithoutCancel(ctx), record.ClientRotation.Source, record.ClientRotation.Target, record.Startup) {
			return clientIdentityIncomplete("Source restoration", "Restore only the proved unchanged source and remove the unused target.")
		}
		running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ClientRotation.Source, record.PublicIPv4)
		if !runningAccepted(running) {
			return clientIdentityIncomplete("Source traffic verification", "Restore and prove the unchanged source proxy traffic before finishing cleanup.")
		}
		if record.Startup != nil && !host.VerifyProxyStartupIntegration(context.WithoutCancel(ctx), *record.Startup) {
			if !host.RemoveProxyStartupIntegration(context.WithoutCancel(ctx), *record.Startup) {
				return clientIdentityIncomplete("Startup integration cleanup", "Remove only the recorded incomplete startup integration, then finish cleanup.")
			}
			record.Startup = nil
		}
		record.ClientRotation = nil
		updateSubscriptionResources(&record, authority.release)
		if _, ok := module.publishClientIdentityCheckpoint(record, current); !ok {
			return clientIdentityIncomplete("Rotation cleanup checkpoint", "Inspect durable authority before retrying.")
		}
		return Result{Status: Running, SubscriptionStatus: SubscriptionNotEnabled, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedStopped, Message: "Client Identity rotation was cancelled and its preparation was cleaned up. The previous Client Identity remains authoritative.", Code: ClientIdentityRotationCleanedUp}
	}
	result := module.completeClientIdentityRotation(ctx, host, authority.release, record, current, progress)
	if result.Code == ClientIdentityRotated {
		result.Code = ClientIdentityRotationFinished
		result.Message = "The interrupted Client Identity rotation was completed."
	}
	return result
}

func clientRotationRequirements(checkpoint clientIdentityRotationCheckpoint) (bool, bool) {
	policy, _, ok := clientIdentityPolicy(checkpoint)
	return ok && policy.targetRequired, ok && policy.startupRequired
}

func (module *installedInterface) rotateClientIdentity(ctx context.Context, authority preparedReview, progress ProgressReporter) Result {
	host, ok := module.host.(clientIdentityHost)
	if !ok {
		return clientIdentityFailed("Client Identity rotation Adapter", "Use a qualified release with complete Client Identity rotation support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work, then review Rotate Client Identity again.")
	}
	defer lock.Release()
	report(progress, "Checking Client Identity rotation safety")
	installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
	current, readErr := module.readOwnership()
	record, valid := decodeOwnership(current)
	running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	absence := module.host.InspectSubscriptionAbsence(context.WithoutCancel(ctx))
	preflight := module.host.PreflightSubscription(context.WithoutCancel(ctx), record.PublicIPv4)
	targetDigest := sha256.Sum256(authority.target)
	idle := host.ClientIdentityPreparationIdle()
	if readErr != nil || !valid || !bytes.Equal(current, authority.record) || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !compatibleOwnership(record, authority.release) || !reflect.DeepEqual(running, authority.running) || !runningAccepted(running) || !absence.Observed || !absence.Accepted || !preflight.PackageLocks.Observed || !preflight.PackageLocks.Accepted || !preflight.RenewalIdle.Observed || !preflight.RenewalIdle.Accepted || !idle.Observed || !idle.Accepted || authority.startup == nil || len(authority.target) == 0 {
		return refused(Running, "Prepared Action facts", "Restore the reviewed Running proxy, subscription absence, idle exclusion, and startup facts, then review again.")
	}
	operationID := make([]byte, 16)
	if _, err := rand.Read(operationID); err != nil {
		return clientIdentityFailed("Rotation operation generation", "Review Rotate Client Identity again.")
	}
	if record.Schema == 1 {
		record.Schema = 2
		record.Resources = recordResources(record, false)
		record.ResourceCreatingReleases = make([]softwarelifecycle.ReleaseIdentity, len(record.Resources))
		for i := range record.ResourceCreatingReleases {
			record.ResourceCreatingReleases[i] = authority.release
		}
	}
	record.ClientRotation = &clientIdentityRotation{OperationID: hex.EncodeToString(operationID), Direction: "cleanup", Effects: slices.Clone(clientIdentityRotationEffects), Completed: []string{}, Source: record.ConfigurationSHA256, Target: hex.EncodeToString(targetDigest[:]), Checkpoint: clientRotationAuthorized}
	record.Startup = authority.startup
	updateSubscriptionResources(&record, authority.release)
	current, ok = module.publishClientIdentityCheckpoint(record, current)
	if !ok {
		return clientIdentityIncomplete("Rotation authority", "Inspect the durable Ownership Record before retrying.")
	}
	report(progress, "Preparing replacement Client Identity")
	if !host.PrepareClientIdentityTarget(authority.target, record.ClientRotation.Target) {
		return clientIdentityIncomplete("Replacement preparation", "Use Finish Client Identity rotation to clean up the proved unused replacement.")
	}
	current, record, ok = module.advanceClientIdentity(record, current, clientRotationTargetPrepared)
	if !ok {
		return clientIdentityIncomplete("Replacement preparation checkpoint", "Inspect durable authority before retrying.")
	}
	return module.completeClientIdentityRotation(ctx, host, authority.release, record, current, progress)
}

func (module *installedInterface) completeClientIdentityRotation(ctx context.Context, host clientIdentityHost, release softwarelifecycle.ReleaseIdentity, record ownershipRecord, current []byte, progress ProgressReporter) Result {
	checkpoint := record.ClientRotation.Checkpoint
	policy, _, known := clientIdentityPolicy(checkpoint)
	if !known || policy.verifyRoute && !host.VerifyProxyStartupIntegration(context.WithoutCancel(ctx), *record.Startup) {
		return clientIdentityIncomplete("Effective startup route", "Restore and freshly verify the exact recorded startup integration, then finish the rotation.")
	}
	advance := func(next clientIdentityRotationCheckpoint) bool {
		var ok bool
		current, record, ok = module.advanceClientIdentity(record, current, next)
		checkpoint = record.ClientRotation.Checkpoint
		return ok
	}
	if checkpoint == clientRotationTargetPrepared {
		report(progress, "Preparing Client Identity startup protection")
		if !host.PublishProxyStartupIntegration(*record.Startup) {
			return clientIdentityIncomplete("Startup integration publication", "Use Finish Client Identity rotation after restoring the exact owned startup path.")
		}
		if !advance(clientRotationIntegrationPublished) {
			return clientIdentityIncomplete("Startup integration checkpoint", "Inspect durable authority before retrying.")
		}
	}
	if checkpoint == clientRotationIntegrationPublished {
		if !host.ReloadProxyStartupIntegration(context.WithoutCancel(ctx)) || !advance(clientRotationReloaded) {
			return clientIdentityIncomplete("systemd reload", "Use Finish Client Identity rotation to reload and verify the recorded startup integration.")
		}
	}
	if checkpoint == clientRotationReloaded {
		if !host.VerifyProxyStartupIntegration(context.WithoutCancel(ctx), *record.Startup) || !advance(clientRotationRouteVerified) {
			return clientIdentityIncomplete("Effective startup route", "Restore the exact recorded startup integration, then finish the rotation.")
		}
	}
	if checkpoint == clientRotationRouteVerified && !advance(clientRotationGated) {
		return clientIdentityIncomplete("Cutover gate", "Inspect durable authority before retrying.")
	}
	if checkpoint == clientRotationGated {
		report(progress, "Stopping old Client Identity access")
		if !host.StopProxyForClientIdentityRotation(context.WithoutCancel(ctx)) || !advance(clientRotationStopped) {
			return clientIdentityIncomplete("Source proxy stop", "Use Finish Client Identity rotation to restore the source before revocation.")
		}
	}
	if checkpoint == clientRotationStopped {
		if !host.ProxyQuiescentForClientIdentityRotation(context.WithoutCancel(ctx)) || !advance(clientRotationQuiescent) {
			return clientIdentityIncomplete("Old-session quiescence", "Prove the owned process group and descendants are empty, then finish the rotation.")
		}
	}
	if checkpoint == clientRotationQuiescent {
		report(progress, "Committing Client Identity revocation")
		record.ClientRotation.Direction = "forward"
		if !advance(clientRotationRevoked) {
			return clientIdentityIncomplete("Durable revocation", "Inspect authority; never restore or regenerate the selected replacement.")
		}
	}
	if checkpoint == clientRotationRevoked {
		if !host.PublishClientIdentityConfiguration(record.ClientRotation.Source, record.ClientRotation.Target) {
			return clientIdentityIncomplete("Target configuration publication", "Use Finish Client Identity rotation to publish only the prepared target.")
		}
		record.ConfigurationSHA256 = record.ClientRotation.Target
		updateSubscriptionResources(&record, release)
		if !advance(clientRotationTargetPublished) {
			return clientIdentityIncomplete("Target publication checkpoint", "Inspect authority; never restore the revoked source.")
		}
	}
	if checkpoint == clientRotationTargetPublished {
		report(progress, "Activating replacement Client Identity")
		if !host.StartProxyForClientIdentityRotation(context.WithoutCancel(ctx), record.ClientRotation.Target) || !advance(clientRotationTargetStarted) {
			return clientIdentityIncomplete("Replacement proxy start", "Leave the proxy stopped and use Finish Client Identity rotation again.")
		}
	}
	report(progress, "Finishing Client Identity rotation")
	report(progress, "Verifying Client Identity rotation result")
	running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	if !runningAccepted(running) || !host.RemoveClientIdentityTarget(record.ClientRotation.Source, record.ClientRotation.Target) {
		return clientIdentityIncomplete("Replacement proxy verification", "Correct the prepared target runtime, then use Finish Client Identity rotation.")
	}
	record.ClientRotation = nil
	updateSubscriptionResources(&record, release)
	if _, ok := module.publishClientIdentityCheckpoint(record, current); !ok {
		return clientIdentityIncomplete("Rotation completion checkpoint", "Inspect durable authority before retrying.")
	}
	return Result{Status: Running, SubscriptionStatus: SubscriptionNotEnabled, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedStopped, Message: "Client Identity was rotated. Refresh the Subscription Link or use Show client configuration.", Code: ClientIdentityRotated}
}

func (module *installedInterface) advanceClientIdentity(record ownershipRecord, current []byte, checkpoint clientIdentityRotationCheckpoint) ([]byte, ownershipRecord, bool) {
	index := slices.Index(clientIdentityRotationEffects, effectForClientCheckpoint(checkpoint))
	if index < 0 {
		return current, record, false
	}
	record.ClientRotation.Checkpoint = checkpoint
	record.ClientRotation.Completed = slices.Clone(clientIdentityRotationEffects[:index+1])
	next, ok := module.publishClientIdentityCheckpoint(record, current)
	return next, record, ok
}

func effectForClientCheckpoint(checkpoint clientIdentityRotationCheckpoint) string {
	policy, _, _ := clientIdentityPolicy(checkpoint)
	return policy.effect
}

func (module *installedInterface) publishClientIdentityCheckpoint(record ownershipRecord, current []byte) ([]byte, bool) {
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err == nil {
		return next, true
	}
	published, err := module.readOwnership()
	_, ok := decodeOwnership(published)
	return published, err == nil && ok && bytes.Equal(published, next) && module.host.SyncOwnership(hostSetupSpec.OwnershipPath, published) == nil
}

func clientIdentityIncomplete(failed, correction string) Result {
	return Result{Status: ChangeIncomplete, SubscriptionStatus: SubscriptionNotEnabled, ProxyTraffic: CannotBeVerified, SubscriptionServing: ProvedStopped, Message: "Client Identity rotation did not complete. Use Finish Client Identity rotation.", Code: ClientIdentityRotationNeedsFinish, FailedCheck: failed, Correction: correction}
}

func clientIdentityFailed(failed, correction string) Result {
	return Result{Status: Running, SubscriptionStatus: SubscriptionNotEnabled, ProxyTraffic: CannotBeVerified, SubscriptionServing: ProvedStopped, Message: "Client Identity rotation failed. Follow the correction before retrying.", Code: ClientIdentityRotationFailed, FailedCheck: failed, Correction: correction}
}
