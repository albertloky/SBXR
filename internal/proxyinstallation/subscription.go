package proxyinstallation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

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

func (module *installedInterface) refuseSubscriptionExecution(ctx context.Context, authority preparedReview) Result {
	lock, busy, err := module.host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	if err != nil || busy {
		return refused(Running, "SBXR mutation lock", "Wait for active SBXR work and restore the existing safe mutation lock before reviewing again.")
	}
	defer lock.Release()
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
	return refused(Running, "Enable subscription unavailable", "Enable subscription is unavailable in this release. Use a qualified release with complete enablement support; this attempt made no changes.")
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
		"Enable subscription is unavailable in this release. Even y refuses without changes; the following effects describe complete enablement.",
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
