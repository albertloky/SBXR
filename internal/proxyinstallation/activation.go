package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type certificateActivationHost interface {
	InspectCertificateActivation(context.Context, hostadapter.RenewalAuthority, hostadapter.ServingAuthority) hostadapter.CertificateActivationInspection
	ActivateServing(context.Context, hostadapter.RenewalAuthority, hostadapter.ServingAuthority) bool
}

func compatibleCertificateTarget(source, target hostadapter.ServingAuthority) bool {
	return source.Valid() && target.Valid() && source.LinkID == target.LinkID && source.CredentialSHA256 == target.CredentialSHA256 && (target == source || target.CertificateGeneration > source.CertificateGeneration)
}

func (module *installedInterface) inspectSubscription(ctx context.Context) (SubscriptionStatus, hostadapter.CertificateActivationInspection) {
	if module.host == nil {
		return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
	}
	body, err := module.readOwnership()
	if errors.Is(err, os.ErrNotExist) {
		if staged, stagedErr := module.host.ReadOwnership(hostSetupSpec.OwnershipNextPath); !errors.Is(stagedErr, os.ErrNotExist) || len(staged) != 0 {
			return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
		}
		fact := module.host.InspectSubscriptionAbsence(ctx)
		if fact.Observed && fact.Accepted {
			return SubscriptionNotEnabled, hostadapter.CertificateActivationInspection{}
		}
		return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
	}
	record, valid := decodeOwnership(body)
	if err != nil || !valid {
		return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
	}
	if staged, stagedErr := module.host.ReadOwnership(hostSetupSpec.OwnershipNextPath); !errors.Is(stagedErr, os.ErrNotExist) || len(staged) != 0 {
		return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
	}
	if record.Enablement != nil {
		return SubscriptionChangeIncomplete, hostadapter.CertificateActivationInspection{}
	}
	if record.Rotation != nil {
		return SubscriptionChangeIncomplete, hostadapter.CertificateActivationInspection{}
	}
	if record.Serving == nil {
		fact := module.host.InspectSubscriptionAbsence(ctx)
		if fact.Observed && fact.Accepted {
			return SubscriptionNotEnabled, hostadapter.CertificateActivationInspection{}
		}
		return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
	}
	activationHost, ok := module.host.(certificateActivationHost)
	renewalHost, renewalOK := module.host.(renewalHost)
	if !ok || !renewalOK || record.Renewal == nil {
		return SubscriptionProblemDetected, hostadapter.CertificateActivationInspection{}
	}
	renewal := renewalHost.InspectRenewal(*record.Renewal)
	if renewal.State == hostadapter.RenewalAttemptLive {
		return SubscriptionChangeInProgress, hostadapter.CertificateActivationInspection{}
	}
	inspection := activationHost.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
	if !inspection.Observed || !inspection.Accepted || !compatibleCertificateTarget(*record.Serving, inspection.Published) {
		return SubscriptionProblemDetected, inspection
	}
	if record.Activation != nil {
		if record.Activation.Target != inspection.Published && !compatibleCertificateTarget(record.Activation.Target, inspection.Published) {
			return SubscriptionProblemDetected, inspection
		}
		return SubscriptionChangeIncomplete, inspection
	}
	if inspection.Published != *record.Serving {
		return SubscriptionChangeIncomplete, inspection
	}
	if inspection.Loaded != *record.Serving {
		return SubscriptionProblemDetected, inspection
	}
	if !renewalHealthyForAccepted(renewal, *record.Serving) {
		return SubscriptionProblemDetected, inspection
	}
	if record.SubscriptionCompromised {
		return SubscriptionProblemDetected, inspection
	}
	return SubscriptionAvailable, inspection
}

func renewalHealthyForAccepted(inspection hostadapter.RenewalInspection, accepted hostadapter.ServingAuthority) bool {
	if inspection.State == hostadapter.RenewalAttemptHealthy {
		return true
	}
	if inspection.State != hostadapter.RenewalAttemptFailed || !inspection.Observed {
		return false
	}
	unresolved, sawFailure := false, false
	for _, attempt := range inspection.Evidence.Attempts {
		if attempt.Completion == nil {
			return false
		}
		if attempt.Completion.ExitCode != 0 || attempt.Completion.OwnedOutcome == "incomplete" {
			unresolved, sawFailure = true, true
			continue
		}
		prefix := "../../archive/sbxr-subscription/cert"
		generation, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(attempt.Completion.LineageAfter, prefix), ".pem"))
		if unresolved && err == nil && attempt.Completion.OwnedOutcome == "renewed" && attempt.DeployHook != nil && attempt.DeployHook.Outcome == "succeeded" && attempt.PostHook != nil && attempt.PostHook.Outcome == "succeeded" && attempt.Completion.LineageAfter == prefix+strconv.Itoa(generation)+".pem" && generation == accepted.CertificateGeneration {
			unresolved = false
		}
	}
	return sawFailure && !unresolved
}

func (module *installedInterface) prepareCertificateActivationReview(ctx context.Context, review Review, inspection hostadapter.CertificateActivationInspection) Review {
	if module.lifecycle == nil {
		review.Result = refused(review.Status, "Installed SBXR", "Restore a verified Ready Software Lifecycle state, then review again.")
		return review
	}
	body, err := module.readOwnership()
	record, valid := decodeOwnership(body)
	status := module.lifecycle.Status(ctx)
	if err != nil || !valid || record.Serving == nil || record.Renewal == nil || status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || !compatibleCertificateTarget(*record.Serving, inspection.Published) {
		review.Result = refused(review.Status, "Certificate activation authority", "Restore the exact owned lineage and one consistent published replacement, then review again.")
		return review
	}
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if !runningAccepted(running) {
		review.Result = refused(review.Status, "Working proxy", "Restore the independently managed proxy, then review Finish subscription change again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(review.Status, "Prepared Action generation", "Review Finish subscription change again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: FinishSubscriptionChangeAction, status: review.Status, release: *status.Installed, record: slices.Clone(body), running: running, activation: inspection}
	review.Prepared = &PreparedAction{token: token}
	link := "unverified"
	if inspection.Loaded.Valid() {
		link = "proved usable"
	} else if inspection.Observed {
		link = "unavailable"
	}
	if record.Activation != nil && record.Activation.Checkpoint == activationTargetAccepted && record.Activation.Target == inspection.Published {
		review.Plan = []string{
			"Action: Finish subscription change",
			"Interrupted operation: accepted certificate generation " + strconv.Itoa(inspection.Published.CertificateGeneration) + " still has its completion checkpoint.",
			"Selected direction: verify the loaded accepted generation and clear only the completed activation marker.",
			"Resources affected: the Ownership Record only; sbxr-subscription.service, the published Certbot certificate files, and four live links stay unchanged.",
			"Existing Subscription Link: " + link + "; its identity stays unchanged.",
			"Do not restart Subscription Serving; verify its selected state, certificate, process, service, owned listener, and local HTTPS behavior.",
			"Keep the Subscription Link, Proxy Profile, Client Identity, and working proxy unchanged.",
			"Local HTTPS checks do not prove public reachability or Karing acceptance.",
		}
	} else {
		runtimeEffect := "Restart only Subscription Serving and verify its selected state, certificate, process, service, owned listener, and local HTTPS behavior."
		if inspection.Loaded == inspection.Published {
			runtimeEffect = "Do not restart Subscription Serving; record acceptance and verify its selected state, certificate, process, service, owned listener, and local HTTPS behavior."
		}
		review.Plan = []string{
			"Action: Finish subscription change",
			"Interrupted operation: certificate activation from accepted generation " + strconv.Itoa(record.Serving.CertificateGeneration) + " to published generation " + strconv.Itoa(inspection.Published.CertificateGeneration) + ".",
			"Selected direction: finish forward activation of the exact published generation for the owned sbxr-subscription lineage.",
			"Resources affected: the Ownership Record and sbxr-subscription.service; the published Certbot certificate files and four live links stay unchanged.",
			"Existing Subscription Link: " + link + "; its identity stays unchanged.",
			runtimeEffect,
			"Keep the Subscription Link, Proxy Profile, Client Identity, and working proxy unchanged.",
			"Local HTTPS checks do not prove public reachability or Karing acceptance.",
		}
	}
	return review
}

func subscriptionActivationIncomplete(failed, correction string) Result {
	return Result{Status: Running, Message: "The subscription change did not complete. Use Finish subscription change.", Code: SubscriptionChangeNeedsCompletion, FailedCheck: failed, Correction: correction}
}

func (module *installedInterface) executeCertificateActivation(ctx context.Context, authority preparedReview, progress ProgressReporter) Result {
	host, ok := module.host.(certificateActivationHost)
	if !ok {
		return refused(Running, "Certificate activation Adapter", "Use a qualified release with protected certificate activation support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work, then review Finish subscription change again.")
	}
	defer lock.Release()
	current, err := module.readOwnership()
	record, valid := decodeOwnership(current)
	installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
	if err != nil || !valid || !bytes.Equal(current, authority.record) || record.Serving == nil || record.Renewal == nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !compatibleOwnership(record, authority.release) {
		return refused(Running, "Prepared Action facts", "Restore the exact reviewed installation and certificate authority, then review again.")
	}
	running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	inspection := host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, *record.Serving)
	if ctx.Err() != nil || !runningAccepted(running) || !reflect.DeepEqual(running, authority.running) || !inspection.Observed || !inspection.Accepted || !compatibleCertificateTarget(*record.Serving, inspection.Published) || authority.activation.Published != inspection.Published {
		return refused(Running, "Prepared Action facts", "Restore the exact reviewed proxy and one consistent published certificate generation, then review again.")
	}
	target := inspection.Published
	operation := certificateActivation{Source: *record.Serving, Target: target, Checkpoint: activationTargetRecorded}
	if record.Activation != nil && record.Activation.Target == target {
		operation = *record.Activation
	}
	if record.Activation == nil || *record.Activation != operation {
		record.Activation = &operation
		next := ownershipBytes(record)
		if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
			published, readErr := module.readOwnership()
			proved, decoded := decodeOwnership(published)
			if readErr != nil || !decoded || proved.Activation == nil || *proved.Activation != operation || module.host.SyncOwnership(hostSetupSpec.OwnershipPath, published) != nil {
				return subscriptionActivationIncomplete("Certificate activation authority", "Inspect the durable Ownership Record before retrying.")
			}
			record, current = proved, published
		} else {
			current = next
		}
	}
	if module.host.SyncOwnership(hostSetupSpec.OwnershipPath, current) != nil {
		return subscriptionActivationIncomplete("Certificate activation authority", "Restore durable Ownership Record storage before retrying.")
	}
	report(progress, "Finishing subscription change")
	inspection = host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, *record.Serving)
	if inspection.Published != target || !inspection.Accepted {
		return subscriptionActivationIncomplete("Published certificate generation", "Restore the exact recorded valid replacement or diagnose a newer concurrent publication.")
	}
	if operation.Checkpoint == activationTargetRecorded && inspection.Loaded != target {
		report(progress, "Activating subscription")
		if ctx.Err() != nil || !host.ActivateServing(context.WithoutCancel(ctx), *record.Renewal, target) {
			return subscriptionActivationIncomplete("Subscription Serving activation", "Restore the owned service and use Finish subscription change again.")
		}
	}
	report(progress, "Verifying subscription result")
	inspection = host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, *record.Serving)
	if !inspection.Observed || !inspection.Accepted || inspection.Published != target || inspection.Loaded != target {
		return subscriptionActivationIncomplete("Loaded certificate generation", "Restore the owned listener and local HTTPS behavior, then use Finish subscription change again.")
	}
	if operation.Checkpoint == activationTargetRecorded {
		record.Serving = &target
		operation.Checkpoint = activationTargetAccepted
		record.Activation = &operation
		record.Resources = recordResources(record, false)
		if len(record.ResourceCreatingReleases) != len(record.Resources) {
			creators := make([]softwarelifecycle.ReleaseIdentity, len(record.Resources))
			for index := range creators {
				creators[index] = record.Release
			}
			record.ResourceCreatingReleases = creators
		}
		next := ownershipBytes(record)
		if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
			published, readErr := module.readOwnership()
			proved, decoded := decodeOwnership(published)
			if readErr != nil || !decoded || proved.Activation == nil || *proved.Activation != operation || proved.Serving == nil || *proved.Serving != target || module.host.SyncOwnership(hostSetupSpec.OwnershipPath, published) != nil {
				return subscriptionActivationIncomplete("Accepted certificate checkpoint", "Inspect the durable Ownership Record, then use Finish subscription change.")
			}
			current, record = published, proved
		} else {
			current = next
		}
	}
	record.Activation = nil
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
		published, readErr := module.readOwnership()
		proved, decoded := decodeOwnership(published)
		if readErr != nil || !decoded || proved.Activation != nil || proved.Serving == nil || *proved.Serving != target || module.host.SyncOwnership(hostSetupSpec.OwnershipPath, published) != nil {
			return Result{Status: Running, SubscriptionStatus: SubscriptionProblemDetected, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedWorking, Message: "A subscription problem was detected. View details before continuing.", Code: SubscriptionStatusProblemDetected, FailedCheck: "Certificate activation cleanup durability", Correction: "Restore reliable Ownership Record storage, then inspect again. Do not assume Finish subscription change is available."}
		}
	}
	return Result{Status: Running, Message: "The interrupted subscription change was completed.", Code: SubscriptionChangeFinished}
}

func (module *installedInterface) reviewPublishedCertificateActivation(ctx context.Context) Review {
	module.mu.Lock()
	defer module.mu.Unlock()
	review := module.review(ctx, StatusAction)
	body, err := module.readOwnership()
	record, valid := decodeOwnership(body)
	host, ok := module.host.(certificateActivationHost)
	if err != nil || !valid || !ok || record.Serving == nil || record.Renewal == nil {
		return review
	}
	inspection := host.InspectCertificateActivation(ctx, *record.Renewal, *record.Serving)
	if !inspection.Observed || !inspection.Accepted || inspection.Published == *record.Serving || !compatibleCertificateTarget(*record.Serving, inspection.Published) {
		return review
	}
	review.SubscriptionStatus = SubscriptionChangeIncomplete
	return module.prepareCertificateActivationReview(ctx, review, inspection)
}
