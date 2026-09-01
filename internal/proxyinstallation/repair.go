package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"slices"
	"strconv"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type subscriptionRepairHost interface {
	certificateActivationHost
	renewalHost
	RepairSubscriptionCertificate(context.Context, hostadapter.RenewalAuthority) bool
	ResolveRenewalFailure(hostadapter.RenewalAuthority, hostadapter.ServingAuthority) bool
}

func (module *installedInterface) repairDiagnosis(ctx context.Context, record ownershipRecord, activation hostadapter.CertificateActivationInspection) (subscriptionRepairCorrection, hostadapter.RenewalInspection, bool) {
	host, ok := module.host.(subscriptionRepairHost)
	if !ok || record.Serving == nil || record.Renewal == nil || record.Repair != nil || !activation.Observed || !activation.Accepted || activation.Published != *record.Serving {
		return "", hostadapter.RenewalInspection{}, false
	}
	renewal := host.InspectRenewal(*record.Renewal)
	if activation.Loaded == *record.Serving && (renewal.State == hostadapter.RenewalAttemptFailed || renewal.State == hostadapter.RenewalAttemptAbandoned) {
		return repairCertificate, renewal, true
	}
	if activation.Loaded != *record.Serving && renewal.State == hostadapter.RenewalAttemptHealthy && renewal.Observed && renewal.Accepted {
		return repairRuntime, renewal, true
	}
	return "", renewal, false
}

func (module *installedInterface) prepareSubscriptionRepairReview(ctx context.Context, review Review, activation hostadapter.CertificateActivationInspection) Review {
	body, err := module.readOwnership()
	record, valid := decodeOwnership(body)
	if err != nil || !valid || record.Serving == nil || record.Renewal == nil {
		review.Result = refused(Running, "Subscription repair authority", "Restore one consistent owned subscription generation, then review again.")
		return review
	}
	correction, renewal, diagnosed := module.repairDiagnosis(ctx, record, activation)
	status := module.lifecycle.Status(ctx)
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if !diagnosed || status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || !runningAccepted(running) {
		review.Result = refused(Running, "Diagnosed subscription correction", "Restore the exact owned subscription and working proxy, then inspect the fault again. Healthy capability, public-IP drift, unknown authority, and combined faults cannot be repaired here.")
		return review
	}
	if host, ok := module.host.(interface {
		ReadSubscriptionLink(hostadapter.ServingAuthority, string) ([]byte, bool)
	}); !ok {
		review.Result = refused(Running, "Subscription Link agreement", "Use a qualified release with protected Subscription Link inspection.")
		return review
	} else if link, accepted := host.ReadSubscriptionLink(*record.Serving, record.PublicIPv4); !accepted || len(link) == 0 {
		review.Result = refused(Running, "Subscription Link agreement", "Restore agreement among the credential, serving state, Link ID, and Ownership Record, then review again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(Running, "Prepared Action generation", "Review Repair subscription again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: RepairSubscriptionAction, status: Running, release: *status.Installed, record: slices.Clone(body), running: running, activation: activation, renewal: renewal, repair: correction}
	review.Prepared = &PreparedAction{token: token}
	review.Plan = subscriptionRepairPlan(correction, *record.Serving)
	return review
}

func subscriptionRepairPlan(correction subscriptionRepairCorrection, source hostadapter.ServingAuthority) []string {
	if correction == repairCertificate {
		return []string{
			"Action: Repair subscription",
			"Diagnosed fault: the managed sbxr-subscription renewal attempt failed or its outcome is unknown.",
			"Exact correction: make one Owner-driven managed Certbot replacement attempt for only the owned sbxr-subscription lineage, then activate only a valid published replacement.",
			"Network needs: Let's Encrypt standalone HTTP-01 needs public TCP 80 and the existing provider-firewall allowance; local checks cannot prove outside reachability.",
			"Subscription Serving can be interrupted only while a valid replacement is activated; unrelated shared Certbot renewal remains excluded during this attempt.",
			"Keep the Subscription Link, Proxy Profile, Client Identity, credential values, and proxy traffic unchanged.",
			"Before commitment, discard only the unused repair authority. After commitment, finish only this selected certificate correction.",
		}
	}
	return []string{
		"Action: Repair subscription",
		"Diagnosed fault: the owned Subscription Serving runtime does not present accepted certificate generation " + strconv.Itoa(source.CertificateGeneration) + ".",
		"Exact correction: restart only the owned Subscription Serving runtime and verify its selected state, certificate, service, process, listener, and local HTTPS behavior.",
		"Subscription Serving is interrupted during the restart; no network access is required for the correction.",
		"Keep the Subscription Link, Proxy Profile, Client Identity, credential values, and proxy traffic unchanged.",
		"Before commitment, discard only the unused repair authority. After commitment, finish only this selected runtime correction.",
	}
}

func (module *installedInterface) prepareSubscriptionRepairFinishReview(ctx context.Context, review Review, record ownershipRecord, body []byte) Review {
	if record.Repair == nil || record.Serving == nil || record.Renewal == nil || module.lifecycle == nil {
		review.Result = refused(Running, "Subscription repair authority", "Restore the exact durable repair authority, then inspect again.")
		return review
	}
	status := module.lifecycle.Status(ctx)
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || !runningAccepted(running) {
		review.Result = refused(Running, "Compatible idle installation", "Restore the exact compatible installation and working proxy, then review Finish subscription change again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(Running, "Prepared Action generation", "Review Finish subscription change again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: FinishSubscriptionChangeAction, status: Running, release: *status.Installed, record: slices.Clone(body), running: running, repair: record.Repair.Correction}
	review.Prepared = &PreparedAction{token: token}
	direction := "finish forward only the selected exact correction"
	remaining := "apply the correction, verify the current generation, and clear the completed repair authority"
	if record.Repair.Checkpoint == repairPrepared {
		direction = "clean up unused preparation"
		remaining = "remove only the unused repair authority; do not restart serving or invoke Certbot"
	}
	review.Plan = append([]string{
		"Action: Finish subscription change",
		"Interrupted operation: Repair subscription for " + string(record.Repair.Correction) + ".",
		"Selected direction: " + direction + ".",
		"Remaining effects: " + remaining + ".",
		"Existing Subscription Link: unverified by this recovery review; its identity stays unchanged.",
	}, subscriptionRepairPlan(record.Repair.Correction, record.Repair.Source)[3:]...)
	return review
}

func subscriptionRepairIncomplete(failed, correction string) Result {
	return Result{Status: Running, ProxyTraffic: ProvedWorking, Message: "The subscription change did not complete. Use Finish subscription change.", Code: SubscriptionChangeNeedsCompletion, FailedCheck: failed, Correction: correction}
}

func (module *installedInterface) currentRepair(authority preparedReview) (ownershipRecord, []byte, bool) {
	body, err := module.readOwnership()
	record, ok := decodeOwnership(body)
	return record, body, err == nil && ok && record.Repair != nil && bytes.Equal(body, authority.record)
}

func (module *installedInterface) publishSubscriptionRepairCheckpoint(record ownershipRecord, current []byte) ([]byte, bool) {
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err == nil {
		return next, true
	}
	published, err := module.readOwnership()
	proved, ok := decodeOwnership(published)
	if err != nil || !ok || !bytes.Equal(ownershipBytes(proved), ownershipBytes(record)) || module.host.SyncOwnership(hostSetupSpec.OwnershipPath, published) != nil {
		return current, false
	}
	return published, true
}

func (module *installedInterface) executeSubscriptionRepair(ctx context.Context, authority preparedReview, progress ProgressReporter) Result {
	host, ok := module.host.(subscriptionRepairHost)
	if !ok {
		return refused(Running, "Subscription repair Adapter", "Use a qualified release with complete subscription repair support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work, then review the repair action again.")
	}
	defer lock.Release()
	ctx = hostadapter.RuntimeStartContext(ctx, lock)
	current, err := module.readOwnership()
	record, valid := decodeOwnership(current)
	installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
	if err != nil || !valid || !bytes.Equal(current, authority.record) || record.Serving == nil || record.Renewal == nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !compatibleOwnership(record, authority.release) {
		return refused(Running, "Prepared Action facts", "Restore the exact reviewed installation and subscription authority, then review again.")
	}
	running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	if !runningAccepted(running) || !reflect.DeepEqual(running, authority.running) {
		return refused(Running, "Prepared Action facts", "Restore the exact reviewed working proxy, then review again.")
	}
	finishing := authority.action == FinishSubscriptionChangeAction
	if record.Repair == nil {
		activation := host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, *record.Serving)
		correction, renewal, diagnosed := module.repairDiagnosis(context.WithoutCancel(ctx), record, activation)
		if ctx.Err() != nil || !diagnosed || correction != authority.repair || !reflect.DeepEqual(activation, authority.activation) || !reflect.DeepEqual(renewal, authority.renewal) {
			return refused(Running, "Prepared Action facts", "Review Repair subscription again after restoring every diagnosed certificate, runtime, and renewal fact.")
		}
		operationID := make([]byte, 16)
		if _, err := rand.Read(operationID); err != nil {
			return refused(Running, "Repair operation generation", "Review Repair subscription again.")
		}
		effects := []string{"restart owned serving runtime"}
		if correction == repairCertificate {
			effects = []string{"renew owned certificate", "activate published certificate", "resolve renewal evidence"}
		}
		record.Repair = &subscriptionRepair{OperationID: hex.EncodeToString(operationID), Kind: "repair subscription", Direction: "cleanup", Correction: correction, Effects: effects, Checkpoint: repairPrepared, Source: *record.Serving}
		current, ok = module.publishSubscriptionRepairCheckpoint(record, current)
		if !ok {
			return subscriptionRepairIncomplete("Repair preparation authority", "Inspect the durable Ownership Record before retrying.")
		}
		record, _ = decodeOwnership(current)
	}
	if record.Repair.Checkpoint == repairPrepared {
		if finishing {
			record.Repair = nil
			if _, ok := module.publishSubscriptionRepairCheckpoint(record, current); !ok {
				return subscriptionRepairIncomplete("Repair preparation cleanup", "Restore durable Ownership Record storage, then use Finish subscription change again.")
			}
			report(progress, "Cleaning up subscription change")
			return Result{Status: Running, Message: "The unfinished subscription change was cleaned up.", Code: SubscriptionChangeCleanedUp}
		}
		record.Repair.Checkpoint = repairCommitted
		record.Repair.Direction = "forward"
		current, ok = module.publishSubscriptionRepairCheckpoint(record, current)
		if !ok {
			return subscriptionRepairIncomplete("Repair commitment", "Use Finish subscription change to clean the unused preparation or finish the proved correction.")
		}
		record, _ = decodeOwnership(current)
	}
	if finishing {
		report(progress, "Finishing subscription change")
	} else {
		report(progress, "Checking subscription safety")
	}
	if record.Repair.Checkpoint == repairCommitted {
		if record.Repair.Correction == repairCertificate {
			report(progress, "Renewing subscription certificate")
			inspection := host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, record.Repair.Source)
			if !inspection.Observed || !inspection.Accepted || inspection.Published == record.Repair.Source {
				if ctx.Err() != nil || !host.RepairSubscriptionCertificate(context.WithoutCancel(ctx), *record.Renewal) {
					return subscriptionRepairIncomplete("Owned certificate replacement", "Correct public TCP 80, the provider firewall, or the exact owned Certbot lineage, then use Finish subscription change again.")
				}
				inspection = host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, record.Repair.Source)
			}
			if !inspection.Observed || !inspection.Accepted || !compatibleCertificateTarget(record.Repair.Source, inspection.Published) || inspection.Published == record.Repair.Source {
				return subscriptionRepairIncomplete("Published replacement certificate", "Restore one valid owned replacement generation, then use Finish subscription change again.")
			}
			target := inspection.Published
			record.Repair.Target = &target
			record.Repair.Completed = []string{"certificate published"}
			updateSubscriptionResources(&record, authority.release)
			current, ok = module.publishSubscriptionRepairCheckpoint(record, current)
			if !ok {
				return subscriptionRepairIncomplete("Replacement activation authority", "Inspect the durable Ownership Record before restarting Subscription Serving.")
			}
			record, _ = decodeOwnership(current)
		} else {
			target := record.Repair.Source
			record.Repair.Target = &target
			current, ok = module.publishSubscriptionRepairCheckpoint(record, current)
			if !ok {
				return subscriptionRepairIncomplete("Runtime correction authority", "Inspect the durable Ownership Record before restarting Subscription Serving.")
			}
			record, _ = decodeOwnership(current)
		}
	}
	renewalExclusion, acquired := host.AcquireRenewalExclusion(*record.Renewal)
	if !acquired {
		return subscriptionRepairIncomplete("Renewal exclusion", "Wait for the exact managed renewal attempt and evidence writer to become idle, then use Finish subscription change again.")
	}
	defer renewalExclusion.Release()
	if record.Repair.Checkpoint == repairCommitted {
		report(progress, "Repairing subscription serving")
		inspection := host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, record.Repair.Source)
		if record.Repair.Target == nil || inspection.Published != *record.Repair.Target || inspection.Loaded != *record.Repair.Target {
			if record.Repair.Target == nil || ctx.Err() != nil || !host.ActivateServing(context.WithoutCancel(ctx), *record.Renewal, *record.Repair.Target) {
				return subscriptionRepairIncomplete("Subscription Serving correction", "Restore the exact owned service and use Finish subscription change again.")
			}
		}
		report(progress, "Verifying subscription result")
		inspection = host.InspectCertificateActivation(context.WithoutCancel(ctx), *record.Renewal, record.Repair.Source)
		if !inspection.Observed || !inspection.Accepted || record.Repair.Target == nil || inspection.Published != *record.Repair.Target || inspection.Loaded != *record.Repair.Target {
			return subscriptionRepairIncomplete("Subscription repair verification", "Restore the exact selected certificate, service, listener, and local HTTPS behavior, then use Finish subscription change again.")
		}
		record.Serving = record.Repair.Target
		record.Repair.Checkpoint = repairAccepted
		record.Repair.Completed = slices.Clone(record.Repair.Effects)
		updateSubscriptionResources(&record, authority.release)
		current, ok = module.publishSubscriptionRepairCheckpoint(record, current)
		if !ok {
			return subscriptionRepairIncomplete("Accepted repair checkpoint", "Inspect the durable Ownership Record, then use Finish subscription change again.")
		}
		record, _ = decodeOwnership(current)
	}
	renewalExclusion.Release()
	if record.Repair.Correction == repairCertificate && !host.ResolveRenewalFailure(*record.Renewal, *record.Serving) {
		return subscriptionRepairIncomplete("Renewal outcome accounting", "Preserve the repaired generation and restore protected renewal evidence storage, then use Finish subscription change again.")
	}
	record.Repair = nil
	updateSubscriptionResources(&record, authority.release)
	if _, ok := module.publishSubscriptionRepairCheckpoint(record, current); !ok {
		return Result{Status: Running, SubscriptionStatus: SubscriptionProblemDetected, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedWorking, Message: "A subscription problem was detected. View details before continuing.", Code: SubscriptionStatusProblemDetected, FailedCheck: "Repair completion durability", Correction: "Restore reliable Ownership Record storage, then inspect again."}
	}
	if finishing {
		return Result{Status: Running, Message: "The interrupted subscription change was completed.", Code: SubscriptionChangeFinished}
	}
	return Result{Status: Running, Message: "Subscription repair completed and passed local checks.", Code: SubscriptionRepaired}
}
