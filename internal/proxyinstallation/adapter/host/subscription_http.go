package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"
)

// PreflightHTTPSubscription does not inspect or acquire shared Certbot state.
// The HTTP endpoint needs only its fixed listener and exact owned firewall rule.
func (a Adapter) PreflightHTTPSubscription(ctx context.Context, ipv4 string) SubscriptionPreflight {
	facts := SubscriptionPreflight{HTTP: true}
	ip := net.ParseIP(ipv4)
	if ctx.Err() != nil || ip == nil || ip.To4() == nil || ip.String() != ipv4 {
		return facts
	}
	bind := a.subscriptionBind
	if bind == nil {
		bind = subscriptionTCPAvailable
	}
	facts.TCP8443 = observation(bind(ipv4, "8443"), true)
	// Client Identity rotation still needs package exclusion, independently of
	// subscription enablement. HTTP has no shared renewal writer to exclude.
	if a.packageLocksAvailable != nil {
		facts.PackageLocks = observation(a.packageLocksAvailable(), true)
	}
	facts.RenewalIdle = observation(true, true)
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	rules, code, observed := run(ctx, "iptables-save", "-t", "filter")
	var stable []string
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasPrefix(line, "#") {
			stable = append(stable, firewallChainCounters.ReplaceAllString(line, "${1}[0:0]"))
		}
	}
	rules = strings.Join(stable, "\n")
	facts.Firewall = observation(code == 0 && strings.Contains(rules, "*filter\n") && strings.Contains(rules, ":INPUT ") && strings.Contains(rules, "\nCOMMIT") && !strings.Contains(rules, "sbxr-subscription"), observed && code == 0)
	facts.FirewallIdentity = digest([]byte(rules))
	return facts
}

func httpSubscriptionFirewallUnit(ipv4 string) string {
	unit := subscriptionFirewallUnit(ipv4)
	var lines []string
	for _, line := range strings.Split(unit, "\n") {
		if !strings.Contains(line, "--dport 80 ") {
			lines = append(lines, strings.ReplaceAll(line, " snap.certbot.renew.service", ""))
		}
	}
	return strings.Join(lines, "\n")
}

func subscriptionResourceUnit(authority SubscriptionResourceAuthority) string {
	if authority.HTTP {
		return httpSubscriptionFirewallUnit(authority.PublicIPv4)
	}
	return subscriptionFirewallUnit(authority.PublicIPv4)
}

func (a Adapter) exactHTTPSubscriptionFirewall(ipv4 string) bool {
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	body, code, observed := run(context.Background(), "iptables-save", "-t", "filter")
	want := "-A INPUT -d " + ipv4 + "/32 -p tcp -m tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT"
	return observed && code == 0 && strings.Count(body, want) == 1 && strings.Count(body, "--comment sbxr-subscription") == 1
}

func (a Adapter) prepareHTTPSubscription(ctx context.Context, input SubscriptionEnableInput) SubscriptionEnableResult {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(input.Credential))
	facts := a.PreflightHTTPSubscription(ctx, input.PublicIPv4)
	resources := SubscriptionResourcesForEnablement(input.PublicIPv4, facts)
	if err != nil || len(input.Credential) != 43 || len(decoded) != 32 || !input.Serving.HTTP || !input.Serving.Valid() || input.Serving.CredentialSHA256 != digest(input.Credential) || input.Renewal != (RenewalAuthority{}) || !facts.TCP8443.Accepted || !facts.Firewall.Accepted || input.Resources != resources || !resources.Valid() {
		return SubscriptionEnableResult{}
	}
	serving := input.Serving
	authorize := func(checkpoint int, selected *ServingAuthority) bool {
		return input.Authorize != nil && input.Authorize(checkpoint, selected)
	}
	failed := SubscriptionEnableResult{Resources: resources}
	if input.Report != nil {
		input.Report("Preparing HTTP subscription resources")
	}
	if !authorize(1, nil) || !a.publishSubscriptionFile(SubscriptionFirewallUnitPath, []byte(subscriptionResourceUnit(resources)), 0644) || !authorize(2, nil) || !a.subscriptionPreparationCommand(ctx, "systemctl", "daemon-reload") || !authorize(3, nil) || !a.subscriptionPreparationCommand(ctx, "systemctl", "enable", "--now", "sbxr-subscription-firewall.service") || !a.exactHTTPSubscriptionFirewall(input.PublicIPv4) || !authorize(8, &serving) || !a.prepareServingStaging() || !authorize(9, &serving) {
		return failed
	}
	credential := append(bytes.Clone(input.Credential), '\n')
	state := servingStateBytes(serving)
	if !a.publishSubscriptionFile(SubscriptionCandidateTokenPath, credential, 0600) || !authorize(10, &serving) || !a.publishSubscriptionFile(SubscriptionCandidateStatePath, state, 0600) || !authorize(11, &serving) || !a.publishSubscriptionFile(ServingTokenPath, credential, 0600) || !authorize(12, &serving) || !a.publishSubscriptionFile(ServingStatePath, state, 0600) || !authorize(13, &serving) || !a.publishSubscriptionFile(ServingUnitPath, []byte(ServingUnit), 0644) || !authorize(14, &serving) || !a.removeFile(SubscriptionCandidateTokenPath).OK || !authorize(15, &serving) || !a.removeFile(SubscriptionCandidateStatePath).OK || !a.servingDirectory(ServingStagingPath, nil, false) || !authorize(22, &serving) || !a.subscriptionPreparationCommand(ctx, "systemctl", "daemon-reload") {
		return failed
	}
	return SubscriptionEnableResult{Serving: serving, Resources: resources, Prepared: true}
}

func (a Adapter) activateHTTPSubscription(ctx context.Context, serving ServingAuthority, ipv4 string) bool {
	if !serving.HTTP || !a.safelyAbsent(ServingStatePath+".sbxr-next") || !a.inspectServingFilesWithState(serving, serving, false, false, false, true).Accepted || !a.exactHTTPSubscriptionFirewall(ipv4) {
		return false
	}
	probe := RenewalAuthority{PublicIPv4: ipv4} // Transport context, never persisted renewal authority.
	if loaded, observed := a.loadedServingAuthority(ctx, probe, serving, serving); observed && loaded == serving {
		return true
	}
	return a.runtimeStart(ctx, ServingRole, func() bool { return a.servingCommand(ctx, "enable", "--now", "sbxr-subscription.service") }) && a.waitLoadedServingAuthority(ctx, probe, serving)
}

func (a Adapter) removeHTTPServingRuntime(ctx context.Context, serving ServingAuthority, _ *ServingExclusion) bool {
	if !serving.HTTP || !a.InspectServingFiles(serving, true).Accepted {
		return false
	}
	if !a.safelyAbsent(ServingUnitPath) && !a.servingCommand(ctx, "disable", "--now", "sbxr-subscription.service") || !a.ServingQuiescent() {
		return false
	}
	for _, path := range []string{ServingTokenPath, ServingStatePath, ServingStagingPath, ServingUnitWantsPath, ServingUnitPath} {
		if !a.removeFile(path).OK {
			return false
		}
	}
	return a.servingCommand(ctx, "daemon-reload") && a.ServingQuiescent()
}

func (a Adapter) cleanupHTTPSubscription(ctx context.Context, input SubscriptionCleanupInput) bool {
	if input.Resources == nil || !input.Resources.HTTP || !input.Resources.Valid() || input.Renewal != nil {
		return false
	}
	serving := ServingAuthority{HTTP: true, LinkID: input.LinkID, CredentialSHA256: input.CredentialSHA256}
	if !serving.Valid() || input.Serving != nil && *input.Serving != serving {
		return false
	}
	// No adoption or removal of any Certbot lineage, hook, evidence or dependency.
	credential := []byte(nil)
	for _, path := range []string{ServingTokenPath, SubscriptionCandidateTokenPath, SubscriptionCandidateTokenPath + ".sbxr-next"} {
		body, err := a.protectedServingFile(path, 0600, "")
		if err == nil {
			if len(body) != 44 || body[43] != '\n' || digest(body[:43]) != input.CredentialSHA256 {
				return false
			}
			credential = body
		} else if !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	for _, file := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{{SubscriptionCandidateTokenPath, credential, 0600}, {SubscriptionCandidateStatePath, servingStateBytes(serving), 0600}, {ServingTokenPath, credential, 0600}, {ServingStatePath, servingStateBytes(serving), 0600}, {ServingUnitPath, []byte(ServingUnit), 0644}} {
		if !a.removeSubscriptionPublication(file.path, file.body, file.mode) {
			return false
		}
	}
	return a.removeSubscriptionCandidates(&serving, input.CredentialSHA256) && a.removeHTTPServingRuntime(ctx, serving, nil) && a.RemoveSubscriptionResources(ctx, *input.Resources, &serving) && a.ServingRuntimeAbsent(serving)
}
