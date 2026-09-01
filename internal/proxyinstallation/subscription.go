package proxyinstallation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type subscriptionEnablementHost interface {
	PrepareSubscription(context.Context, hostadapter.SubscriptionEnableInput) hostadapter.SubscriptionEnableResult
	ActivatePreparedSubscription(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) bool
	InspectPreparedSubscription(context.Context, hostadapter.ServingAuthority, hostadapter.RenewalAuthority) hostadapter.Observation
	CleanupPreparedSubscription(context.Context, hostadapter.SubscriptionCleanupInput) bool
}

func (module *installedInterface) subscriptionAdmission(ctx context.Context, facts hostadapter.SubscriptionPreflight) (string, string) {
	if ctx.Err() != nil {
		return "Managed termination", "Review Enable subscription again after the current process stops."
	}
	if _, err := module.host.ReadOwnership(hostSetupSpec.OwnershipNextPath); !errors.Is(err, os.ErrNotExist) {
		return "Pending ownership publication", "Inspect the pending Ownership Record publication and finish its proved direction before enabling a subscription."
	}
	for _, check := range []struct {
		fact             hostadapter.Observation
		name, correction string
	}{
		{facts.TCP80, "Local TCP 80", "Free TCP 80 on the recorded IPv4 for certificate issuance and renewal, then review again. This does not prove provider-firewall access."},
		{facts.TCP8443, "Local TCP 8443", "Free TCP 8443 on the recorded IPv4, then review again. No alternative subscription port is permitted."},
		{facts.Clock, "Synchronized clock", "Restore synchronized host time before certificate issuance."},
		{facts.PackageLocks, "Ubuntu package locks", "Wait for APT and dpkg to finish, then review again."},
		{facts.RenewalIdle, "Shared Certbot admission", "Wait for shared Certbot work and managed writers to finish; do not terminate them."},
		{facts.Dependencies, "Subscription dependencies", "Restore inspectable snapd and official Certbot snap 5.4+ or prove their absence; APT Certbot and active or unknown snap changes are unsupported. Inspect conflicts without deleting unproved resources."},
		{facts.Firewall, "Local firewall", "Restore readable iptables filter rules and resolve conflicting sbxr-subscription contributions before review; preserve unrelated rules."},
	} {
		if !check.fact.Observed || !check.fact.Accepted {
			return check.name, check.correction
		}
	}
	return "", ""
}

func (module *installedInterface) enableSubscription(ctx context.Context, authority preparedReview, progress ProgressReporter) Result {
	host, ok := module.host.(subscriptionEnablementHost)
	if !ok {
		return refused(Running, "Subscription Host Adapter", "Use a qualified release with complete subscription enablement support.")
	}
	lock, busy, err := module.host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work and restore the existing safe mutation lock before reviewing again.")
	}
	defer lock.Release()
	packageLocks, packageBusy, packageErr := module.host.AcquirePackageLocks()
	if packageErr != nil || packageBusy {
		return refused(Running, "Ubuntu package locks", "Wait for APT and dpkg to finish, then review Enable subscription again.")
	}
	defer packageLocks.Release()
	current, err := module.readOwnership()
	record, valid := decodeOwnership(current)
	installed := module.statusUnderMutationLock(ctx, lock)
	if ctx.Err() != nil || err != nil || !valid || !bytes.Equal(current, authority.record) || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !compatibleOwnership(record, authority.release) || module.subscriptionStatus(ctx) != SubscriptionNotEnabled {
		return refused(Running, "Prepared Action facts", "Review Enable subscription again after restoring the exact reviewed installation and subscription absence.")
	}
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	facts := module.host.PreflightSubscription(ctx, record.PublicIPv4)
	if failed, correction := module.subscriptionAdmission(ctx, facts); failed != "" {
		return refused(Running, failed, correction)
	}
	if !runningAccepted(running) || !reflect.DeepEqual(running, authority.running) || facts != authority.subscription {
		return refused(Running, "Prepared Action facts", "Review Enable subscription again after restoring every changed proxy or subscription safety fact.")
	}
	report(progress, "Checking subscription safety")
	credential := make([]byte, 32)
	linkID, recorderID := make([]byte, 16), make([]byte, 16)
	if _, err := rand.Read(credential); err != nil {
		return refused(Running, "Subscription Link Credential generation", "Review Enable subscription again.")
	}
	if _, err := rand.Read(linkID); err != nil {
		return refused(Running, "Subscription Link ID generation", "Review Enable subscription again.")
	}
	if _, err := rand.Read(recorderID); err != nil {
		return refused(Running, "Renewal recorder ID generation", "Review Enable subscription again.")
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(credential))
	digest := sha256.Sum256(encoded)
	resources := hostadapter.SubscriptionResourcesForEnablement(record.PublicIPv4, authority.subscription)
	enablement := subscriptionEnablement{LinkID: hex.EncodeToString(linkID), CredentialSHA256: hex.EncodeToString(digest[:]), RecorderID: hex.EncodeToString(recorderID), Resources: &resources}
	if record.Schema == 1 {
		record.Schema = 2
	}
	record.Enablement = &enablement
	updateSubscriptionResources(&record, authority.release)
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
		return subscriptionEnablementIncomplete("Enablement authority", "Inspect the durable Ownership Record before retrying.")
	}
	current = next
	var input hostadapter.SubscriptionEnableInput
	input = hostadapter.SubscriptionEnableInput{
		PublicIPv4: record.PublicIPv4,
		Credential: encoded,
		Serving:    hostadapter.ServingAuthority{LinkID: enablement.LinkID, CredentialSHA256: enablement.CredentialSHA256},
		Renewal:    hostadapter.RenewalAuthority{RecorderID: enablement.RecorderID, Lineage: "sbxr-subscription", PublicIPv4: record.PublicIPv4, Invocation: hostadapter.OfficialRenewalInvocation},
		Resources:  resources,
		Report:     func(phase string) { report(progress, phase) },
		Authorize: func(checkpoint int, serving *hostadapter.ServingAuthority) bool {
			if checkpoint != enablement.Checkpoint+1 || checkpoint >= hostadapter.SubscriptionServingCheckpoint && serving == nil || checkpoint < hostadapter.SubscriptionServingCheckpoint && serving != nil {
				return false
			}
			enablement.Checkpoint = checkpoint
			if serving != nil {
				enablement.Serving, enablement.Renewal = serving, &input.Renewal
			}
			record.Enablement = &enablement
			updateSubscriptionResources(&record, authority.release)
			next = ownershipBytes(record)
			if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
				return false
			}
			current = next
			return true
		},
	}
	prepared := host.PrepareSubscription(context.WithoutCancel(ctx), input)
	if !prepared.Prepared || !prepared.Serving.Valid() || !prepared.Renewal.Valid() || prepared.Resources != resources || prepared.Serving.LinkID != enablement.LinkID || prepared.Serving.CredentialSHA256 != enablement.CredentialSHA256 || prepared.Renewal != input.Renewal {
		return subscriptionEnablementIncomplete("Subscription preparation", "Use Finish subscription change to clean the proved provisional generation.")
	}
	enablement.Serving, enablement.Renewal, enablement.Resources = &prepared.Serving, &prepared.Renewal, &prepared.Resources
	record.Enablement = &enablement
	updateSubscriptionResources(&record, authority.release)
	next = ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
		return subscriptionEnablementIncomplete("Prepared generation checkpoint", "Use Finish subscription change to inspect the proved provisional generation.")
	}
	current = next
	report(progress, "Activating subscription")
	enablement.Checkpoint = hostadapter.SubscriptionActivationCheckpoint
	record.Enablement = &enablement
	updateSubscriptionResources(&record, authority.release)
	next = ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
		return subscriptionEnablementIncomplete("Activation authority", "Use Finish subscription change to clean the proved provisional generation.")
	}
	current = next
	if !host.ActivatePreparedSubscription(context.WithoutCancel(ctx), prepared.Serving, prepared.Renewal) {
		return subscriptionEnablementIncomplete("Provisional Subscription Serving activation", "Use Finish subscription change to clean the proved provisional generation.")
	}
	verified := host.InspectPreparedSubscription(context.WithoutCancel(ctx), prepared.Serving, prepared.Renewal)
	report(progress, "Verifying subscription result")
	proxy := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	if ctx.Err() != nil || !verified.Observed || !verified.Accepted || !runningAccepted(proxy) {
		return subscriptionEnablementIncomplete("Provisional subscription verification", "Use Finish subscription change after correcting the exact local certificate, service, listener, or HTTPS fault.")
	}
	record.Serving, record.Renewal, record.SubscriptionResources, record.Enablement = &prepared.Serving, &prepared.Renewal, &prepared.Resources, nil
	updateSubscriptionResources(&record, authority.release)
	next = ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
		committed, readErr := module.readOwnership()
		if readErr != nil || !bytes.Equal(committed, next) || module.host.SyncOwnership(hostSetupSpec.OwnershipPath, committed) != nil {
			return subscriptionEnablementIncomplete("Enabled generation commitment", "Use Finish subscription change to inspect and commit the same proved generation.")
		}
	}
	if progress != nil {
		progress(Progress{SubscriptionLink: []byte("https://" + record.PublicIPv4 + ":8443/s/" + string(encoded))})
	}
	return Result{Status: Running, SubscriptionStatus: SubscriptionAvailable, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedWorking, Message: "Subscription was enabled and passed local checks. Import the link in Karing.", Code: SubscriptionEnabled}
}

func subscriptionEnablementIncomplete(failed, correction string) Result {
	return Result{Status: Running, SubscriptionStatus: SubscriptionChangeIncomplete, ProxyTraffic: ProvedWorking, Message: "The subscription change did not complete. Use Finish subscription change.", Code: SubscriptionChangeNeedsCompletion, FailedCheck: failed, Correction: correction}
}

func (module *installedInterface) prepareEnablementCleanupReview(ctx context.Context, review Review, record ownershipRecord, body []byte) Review {
	if module.lifecycle == nil || record.Enablement == nil {
		return review
	}
	status := module.lifecycle.Status(ctx)
	running := module.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if status.State != softwarelifecycle.Ready || status.Installed == nil || !compatibleOwnership(record, *status.Installed) || !runningAccepted(running) {
		review.Result = refused(review.Status, "Enablement cleanup authority", "Restore the exact reviewed installation and working proxy, then review again.")
		return review
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		review.Result = refused(review.Status, "Prepared Action generation", "Review Finish subscription change again.")
		return review
	}
	module.prepared[token] = preparedReview{generation: module.generation, action: FinishSubscriptionChangeAction, status: Running, release: *status.Installed, record: bytes.Clone(body), running: running}
	review.Prepared = &PreparedAction{token: token}
	review.Plan = []string{
		"Action: Finish subscription change",
		"Interrupted operation: subscription enablement before commitment.",
		"Selected direction: stop provisional serving and clean only the proved created generation.",
		"Preserve the Proxy Profile, Client Identity, working proxy, shared ACME account, and dependencies without proved exclusive use.",
		"Prove the subscription capability absent before clearing the unfinished operation.",
	}
	return review
}

func (module *installedInterface) currentEnablement(authority preparedReview) (ownershipRecord, []byte, bool) {
	body, err := module.readOwnership()
	record, ok := decodeOwnership(body)
	return record, body, err == nil && ok && record.Enablement != nil && bytes.Equal(body, authority.record)
}

func (module *installedInterface) executeEnablementCleanup(ctx context.Context, authority preparedReview, record ownershipRecord, current []byte, progress ProgressReporter) Result {
	host, ok := module.host.(subscriptionEnablementHost)
	if !ok {
		return subscriptionEnablementIncomplete("Subscription cleanup Adapter", "Use a qualified release with complete cleanup support.")
	}
	lock, busy, err := module.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work, then review Finish subscription change again.")
	}
	defer lock.Release()
	installed := module.statusUnderMutationLock(context.WithoutCancel(ctx), lock)
	running := module.host.InspectRunning(context.WithoutCancel(ctx), hostSetupSpec, aptSourceBody, current, record.ConfigurationSHA256, record.PublicIPv4)
	if ctx.Err() != nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || *installed.Installed != authority.release || !bytes.Equal(current, authority.record) || !reflect.DeepEqual(running, authority.running) {
		return refused(Running, "Prepared Action facts", "Restore the exact reviewed installation and unfinished enablement, then review again.")
	}
	e := record.Enablement
	report(progress, "Cleaning up subscription change")
	if !host.CleanupPreparedSubscription(context.WithoutCancel(ctx), hostadapter.SubscriptionCleanupInput{Checkpoint: e.Checkpoint, LinkID: e.LinkID, CredentialSHA256: e.CredentialSHA256, RecorderID: e.RecorderID, Serving: e.Serving, Renewal: e.Renewal, Resources: e.Resources}) {
		return subscriptionEnablementIncomplete("Provisional subscription cleanup", "Correct the exact owned residue, then use Finish subscription change again.")
	}
	record.Enablement = nil
	updateSubscriptionResources(&record, authority.release)
	next := ownershipBytes(record)
	if err := module.host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, current, next); err != nil {
		return subscriptionEnablementIncomplete("Enablement cleanup checkpoint", "Inspect the durable Ownership Record, then use Finish subscription change again.")
	}
	report(progress, "Verifying subscription result")
	return Result{Status: Running, SubscriptionStatus: SubscriptionNotEnabled, ProxyTraffic: ProvedWorking, SubscriptionServing: ProvedStopped, Message: "The unfinished subscription change was cleaned up.", Code: SubscriptionChangeCleanedUp}
}

func updateSubscriptionResources(record *ownershipRecord, creator softwarelifecycle.ReleaseIdentity) {
	previous := make(map[string]softwarelifecycle.ReleaseIdentity, len(record.Resources))
	for index, resource := range record.Resources {
		resource = subscriptionResourceIdentity(resource)
		previous[resource] = record.Release
		if index < len(record.ResourceCreatingReleases) {
			previous[resource] = record.ResourceCreatingReleases[index]
		}
	}
	record.Resources = recordResources(*record, false)
	record.ResourceCreatingReleases = make([]softwarelifecycle.ReleaseIdentity, len(record.Resources))
	for index, resource := range record.Resources {
		record.ResourceCreatingReleases[index] = creator
		if release, ok := previous[subscriptionResourceIdentity(resource)]; ok {
			record.ResourceCreatingReleases[index] = release
		}
	}
}

func subscriptionResourceIdentity(resource string) string {
	return strings.ReplaceAll(strings.ReplaceAll(resource, "schema-1", "schema"), "schema-2", "schema")
}

func subscriptionPlan(ipv4 string, facts hostadapter.SubscriptionPreflight) []string {
	snapd, certbot := "Install missing snapd", "install missing official Certbot snap 5.4+"
	if facts.SnapdInstalled {
		snapd = "Reuse compatible snapd"
	}
	if facts.CertbotInstalled {
		certbot = "reuse compatible official Certbot snap 5.4+"
	}
	return []string{
		"Action: Enable subscription",
		"Proxy status: Running; Subscription status: Not enabled.",
		"Use recorded public IPv4 " + ipv4 + " with fixed TCP 8443 for trusted HTTPS; keep the proxy on TCP 443 unchanged.",
		"Use TCP 80 for standalone HTTP-01 certificate issuance and renewal, with no permanent TCP 80 listener.",
		"Create two owned iptables filter INPUT ACCEPT rules: IPv4 destination " + ipv4 + "/32, protocol tcp, destination ports 80 and 8443 respectively, comment sbxr-subscription. Keep them while enabled; preserve unrelated rules and remove only the exact owned contributions during Complete removal.",
		"The Owner must allow provider-firewall TCP 80 and 8443 for the enabled lifetime. SBXR cannot inspect or change provider policy.",
		snapd + "; " + certbot + ". Record creation or reuse; reuse a compatible Let's Encrypt ACME account or create one, retaining it as shared infrastructure.",
		"Create the dedicated sbxr-subscription lineage with a Let's Encrypt shortlived IP certificate; retain canonical certificate and private-key protection.",
		"Use official Certbot scheduled renewal only, with owned deploy/post hooks and a renewal recorder. Recorder-start failure blocks the shared scheduled child and can delay unrelated lineages.",
		"Create owned Subscription Serving state, protected /var/lib/sbxr/subscription-token, and sbxr-subscription.service; disclose one reusable Subscription Link only after commitment and local verification.",
		"Preserve the Proxy Profile, Client Identity, and working proxy traffic. Before enablement commitment, clean up only proved created preparation; afterward finish the same generation forward.",
		"Local bind and HTTPS checks do not prove outside reachability, provider-firewall policy, or live Karing acceptance.",
	}
}
