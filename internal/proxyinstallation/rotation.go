package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"slices"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type subscriptionRotationHost interface {
	PrepareSubscriptionRotation(hostadapter.SubscriptionRotationInput) bool
	StopSubscriptionRotation(context.Context, hostadapter.SubscriptionRotationInput) bool
	PublishSubscriptionRotation(hostadapter.SubscriptionRotationInput) bool
	RestoreSubscriptionRotation(context.Context, hostadapter.SubscriptionRotationInput) bool
	RemoveSubscriptionRotation(context.Context, hostadapter.SubscriptionRotationInput, *hostadapter.ServingExclusion) bool
	SubscriptionRotationStagingEmpty() bool
	ActivatePreparedSubscription(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) bool
	InspectPreparedSubscription(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) hostadapter.Observation
	ReadSubscriptionLink(hostadapter.ServingAuthority, string) ([]byte, bool)
	ServingPublicIPv4(context.Context, string) bool
}

func (module *installedInterface) prepareSubscriptionRotationReview(ctx context.Context, review Review, inspection hostadapter.CertificateActivationInspection) Review {
	body, err := module.readOwnership()
	record, ok := decodeOwnership(body)
	host, supported := module.host.(subscriptionRotationHost)
	if err != nil || !ok || !supported || record.Serving == nil || record.Renewal == nil || record.Rotation != nil || !inspection.Observed || inspection.Published != *record.Serving || !host.ServingPublicIPv4(ctx, record.PublicIPv4) {
		review.Prepared = nil
		review.Result = refused(Running, "Subscription rotation authority", "Restore one freshly verified current Subscription Link generation and recorded public IPv4, then review again.")
		return review
	}
	if link, accepted := host.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !accepted || len(link) == 0 {
		review.Prepared = nil
		review.Result = refused(Running, "Current Subscription Link generation", "Restore agreement among the credential, serving state, Link ID, and Ownership Record, then review again.")
		return review
	}
	status := module.lifecycle.Status(ctx)
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || !runningAccepted(running) {
		review.Prepared = nil
		review.Result = refused(Running, "Compatible idle installation", "Restore the exact compatible installation and working proxy, then review again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Prepared = nil
		review.Result = refused(Running, "Prepared Action generation", "Review Rotate subscription link again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: RotateSubscriptionLinkAction, status: Running, release: *status.Installed, record: slices.Clone(body), running: running, activation: inspection}
	review.Prepared = &PreparedAction{token: token}
	review.Plan = []string{
		"Action: Rotate subscription link",
		"Prepare exactly one replacement while the current link remains authoritative; preserve the current generation if preparation fails.",
		"Stop the old link before commitment and prove no old process or accepted request remains; there is no overlap.",
		"Replace the old link in Karing after success. Link rotation does not revoke proxy credentials already copied from the artifact.",
		"Keep the Proxy Profile, Client Identity, proxy connection fields, and proxy traffic unchanged.",
	}
	return review
}

func (module *installedInterface) rotateSubscriptionLink(ctx context.Context, authority preparedReview, progress ProgressReporter) Result {
	host, ok := module.host.(subscriptionRotationHost)
	if !ok {
		return refused(Running, "Subscription rotation Adapter", "Use a qualified release with complete rotation support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work, then review Rotate subscription link again.")
	}
	defer lock.Release()
	current, err := module.readOwnership()
	record, valid := decodeOwnership(current)
	installed := module.statusUnderMutationLock(ctx, lock)
	if ctx.Err() != nil || err != nil || !valid || !bytes.Equal(current, authority.record) || record.Serving == nil || record.Renewal == nil || record.Rotation != nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !compatibleOwnership(record, authority.release) {
		return refused(Running, "Prepared Action facts", "Review Rotate subscription link again after restoring every changed authority fact.")
	}
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	if !reflect.DeepEqual(running, authority.running) || !runningAccepted(running) || !host.ServingPublicIPv4(ctx, record.PublicIPv4) {
		return refused(Running, "Prepared Action facts", "Restore the reviewed proxy, public IPv4, and current Subscription Link generation, then review again.")
	}
	if link, accepted := host.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !accepted || len(link) == 0 {
		return refused(Running, "Current Subscription Link generation", "Restore the exact reviewed link generation, then review again.")
	}
	activationHost, ok := module.host.(certificateActivationHost)
	if !ok || !reflect.DeepEqual(activationHost.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving), authority.activation) || authority.activation.Published != *record.Serving {
		return refused(Running, "Prepared Action facts", "Review Rotate subscription link again after restoring the reviewed published, accepted, and loaded certificate facts.")
	}
	replacement := make([]byte, 32)
	linkID, operationID := make([]byte, 16), make([]byte, 16)
	if _, err := rand.Read(replacement); err != nil {
		return refused(Running, "Subscription Link Credential generation", "Review Rotate subscription link again.")
	}
	if _, err := rand.Read(linkID); err != nil {
		return refused(Running, "Subscription Link ID generation", "Review Rotate subscription link again.")
	}
	if _, err := rand.Read(operationID); err != nil {
		return refused(Running, "Subscription rotation operation generation", "Review Rotate subscription link again.")
	}
	credential := []byte(base64.RawURLEncoding.EncodeToString(replacement))
	digest := sha256.Sum256(credential)
	target := *record.Serving
	target.LinkID, target.CredentialSHA256 = hex.EncodeToString(linkID), hex.EncodeToString(digest[:])
	operation := subscriptionRotation{OperationID: hex.EncodeToString(operationID), Kind: "rotate subscription link", Direction: "cleanup", Effects: slices.Clone(subscriptionRotationEffects), Source: *record.Serving, Target: target, Checkpoint: rotationTargetAuthorized}
	record.Rotation = &operation
	updateSubscriptionResources(&record, authority.release)
	var published bool
	current, published = module.publishSubscriptionRotationCheckpoint(record, current)
	if !published {
		return subscriptionRotationIncomplete("Replacement generation authority", "Inspect the durable Ownership Record before retrying.")
	}
	input := hostadapter.SubscriptionRotationInput{Source: operation.Source, Target: operation.Target, Renewal: *record.Renewal, Credential: credential}
	report(progress, "Preparing subscription credential")
	if !host.PrepareSubscriptionRotation(input) {
		return subscriptionRotationIncomplete("Replacement Subscription Link preparation", "Use Finish subscription change to restore the old generation and remove unused target material.")
	}
	operation.Checkpoint, operation.Completed = rotationStopAuthorized, []string{"target prepared"}
	record.Rotation = &operation
	current, published = module.publishSubscriptionRotationCheckpoint(record, current)
	if !published {
		return subscriptionRotationIncomplete("Old generation stop authority", "Inspect the durable Ownership Record before retrying.")
	}
	report(progress, "Activating subscription")
	if !host.StopSubscriptionRotation(context.WithoutCancel(ctx), input) {
		return subscriptionRotationIncomplete("Old accepted-request quiescence", "Use Finish subscription change to restore the proved old generation.")
	}
	operation.Checkpoint, operation.Direction, operation.Completed = rotationCommitted, "forward", []string{"target prepared", "source stopped"}
	record.Serving, record.Rotation = &target, &operation
	updateSubscriptionResources(&record, authority.release)
	current, published = module.publishSubscriptionRotationCheckpoint(record, current)
	if !published {
		return subscriptionRotationIncomplete("Replacement selection commitment", "Inspect durable authority; never restore or regenerate the selected replacement.")
	}
	return module.completeSubscriptionRotation(ctx, host, authority.release, record, current, input, progress)
}

func (module *installedInterface) publishSubscriptionRotationCheckpoint(record ownershipRecord, current []byte) ([]byte, bool) {
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err == nil {
		return next, true
	}
	published, err := module.readOwnership()
	_, ok := decodeOwnership(published)
	return published, err == nil && ok && bytes.Equal(published, next) && module.host.SyncOwnership(hostSetupSpec.OwnershipPath, published) == nil
}

func (module *installedInterface) prepareSubscriptionRotationFinishReview(ctx context.Context, review Review, record ownershipRecord, body []byte) Review {
	status := module.lifecycle.Status(ctx)
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || !runningAccepted(running) {
		review.Prepared = nil
		review.Result = refused(Running, "Subscription rotation recovery authority", "Restore the compatible installation and working proxy, then review again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: FinishSubscriptionChangeAction, status: Running, release: *status.Installed, record: slices.Clone(body), running: running}
	review.Prepared = &PreparedAction{token: token}
	direction := "restore the proved old generation and remove the unused replacement"
	if record.Rotation.Checkpoint == rotationCommitted {
		direction = "complete only the durably selected replacement; never restore or generate another generation"
	}
	review.Plan = []string{"Action: Finish subscription change", "Interrupted operation: Subscription Link rotation.", "Selected direction: " + direction + ".", "Keep the Proxy Profile, Client Identity, and proxy traffic unchanged."}
	return review
}

func (module *installedInterface) currentSubscriptionRotation(authority preparedReview) (ownershipRecord, []byte, bool) {
	body, err := module.readOwnership()
	record, ok := decodeOwnership(body)
	return record, body, err == nil && ok && record.Rotation != nil && bytes.Equal(body, authority.record)
}

func (module *installedInterface) finishSubscriptionRotation(ctx context.Context, authority preparedReview, record ownershipRecord, current []byte, progress ProgressReporter) Result {
	host, ok := module.host.(subscriptionRotationHost)
	if !ok || record.Renewal == nil {
		return subscriptionRotationIncomplete("Subscription rotation Adapter", "Use a qualified release with complete rotation recovery support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work, then review Finish subscription change again.")
	}
	defer lock.Release()
	installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
	fresh, readErr := module.readOwnership()
	freshRecord, valid := decodeOwnership(fresh)
	if readErr != nil || !valid || !bytes.Equal(fresh, current) || freshRecord.Rotation == nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release {
		return refused(Running, "Prepared Action facts", "Restore the reviewed installation, then review Finish subscription change again.")
	}
	running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, fresh, freshRecord.ConfigurationSHA256, freshRecord.PublicIPv4)
	if !reflect.DeepEqual(running, authority.running) || !runningAccepted(running) || !host.ServingPublicIPv4(context.WithoutCancel(ctx), freshRecord.PublicIPv4) {
		return refused(Running, "Prepared Action facts", "Restore the reviewed proxy, public IPv4, and rotation authority, then review again.")
	}
	record = freshRecord
	input := hostadapter.SubscriptionRotationInput{Source: record.Rotation.Source, Target: record.Rotation.Target, Renewal: *record.Renewal}
	if record.Rotation.Checkpoint != rotationCommitted {
		report(progress, "Cleaning up subscription change")
		if !host.RestoreSubscriptionRotation(context.WithoutCancel(ctx), input) {
			return subscriptionRotationIncomplete("Old generation restoration", "Restore the exact source generation and remove only the recorded unused target.")
		}
		record.Rotation = nil
		updateSubscriptionResources(&record, authority.release)
		if _, ok := module.publishSubscriptionRotationCheckpoint(record, current); !ok {
			return subscriptionRotationIncomplete("Rotation cleanup checkpoint", "Inspect durable authority before retrying.")
		}
		report(progress, "Verifying subscription result")
		return Result{Status: Running, SubscriptionStatus: SubscriptionAvailable, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedWorking, Message: "The unfinished subscription change was cleaned up.", Code: SubscriptionChangeCleanedUp}
	}
	credentialLink, ok := host.ReadSubscriptionLink(record.Rotation.Target, record.PublicIPv4)
	if ok {
		_, credential, found := bytes.Cut(credentialLink, []byte("/s/"))
		if found {
			input.Credential = credential
		}
	}
	return module.completeSubscriptionRotation(ctx, host, authority.release, record, current, input, progress)
}

func (module *installedInterface) completeSubscriptionRotation(ctx context.Context, host subscriptionRotationHost, release softwarelifecycle.ReleaseIdentity, record ownershipRecord, current []byte, input hostadapter.SubscriptionRotationInput, progress ProgressReporter) Result {
	if !host.PublishSubscriptionRotation(input) || !host.SubscriptionRotationStagingEmpty() || !host.ActivatePreparedSubscription(context.WithoutCancel(ctx), input.Target, input.Renewal) {
		return subscriptionRotationIncomplete("Replacement Subscription Serving activation", "Use Finish subscription change to complete only the selected replacement.")
	}
	inspection := host.InspectPreparedSubscription(context.WithoutCancel(ctx), input.Target, input.Renewal)
	if !inspection.Observed || !inspection.Accepted {
		return subscriptionRotationIncomplete("Replacement Subscription Serving verification", "Correct the owned listener or serving material, then use Finish subscription change again.")
	}
	record.Rotation, record.SubscriptionCompromised = nil, false
	updateSubscriptionResources(&record, release)
	if _, ok := module.publishSubscriptionRotationCheckpoint(record, current); !ok {
		return subscriptionRotationIncomplete("Rotation completion checkpoint", "Inspect durable authority before retrying.")
	}
	report(progress, "Verifying subscription result")
	link, ok := host.ReadSubscriptionLink(input.Target, record.PublicIPv4)
	if !ok {
		return Result{Status: Running, SubscriptionStatus: SubscriptionAvailable, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedWorking, Message: "The subscription change completed, but link display did not complete. Use View details.", Code: SubscriptionLinkDisplayIncomplete}
	}
	if progress != nil {
		progress(Progress{SubscriptionLink: slices.Clone(link)})
	}
	return Result{Status: Running, SubscriptionStatus: SubscriptionAvailable, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedWorking, Message: "The subscription link was rotated. Replace the old link in Karing.", Code: SubscriptionLinkRotated}
}

func subscriptionRotationIncomplete(failed, correction string) Result {
	return Result{Status: Running, SubscriptionStatus: SubscriptionChangeIncomplete, ProxyTraffic: ProvedWorking, Message: "The subscription change did not complete. Use Finish subscription change.", Code: SubscriptionChangeNeedsCompletion, FailedCheck: failed, Correction: correction}
}
