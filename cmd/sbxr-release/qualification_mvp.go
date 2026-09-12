package main

import (
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// A policy identifier distinguishes the reduced scope from historical attempts;
// it adds no evidence envelope, prerequisite or product behavior.
func mvpLiveAttempt(attempt v3QualificationAttempt) bool {
	return attempt.Support != nil && attempt.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair && attempt.EvidencePolicy == softwarelifecycle.MVPLiveEvidencePolicy
}

func mvpLiveChecks(id string) []string {
	checks := map[string]string{
		"mvp-install":      "packaged-install reviewed-setup outside-proxy-traffic menu-status-and-lifecycle ssh-access-preserved",
		"mvp-subscription": "trusted-outside-https one-correct-subscription-node wrong-token-refused private-files-and-logs-protected karing-import fresh-karing-node-latency manual-refresh selected-connection-preserved",
		"mvp-credentials":  "old-established-session-terminated old-proxy-credential-refused replacement-proxy-traffic same-link-refreshed-identity old-link-refused replacement-link-usable proxy-identity-unchanged-by-link-rotation fresh-karing-replacement-latency",
		"mvp-renewal":      "official-renewal-route certificate-replaced accepted-activation outside-trusted-tls proxy-traffic-preserved",
		"mvp-removal":      "restart-preserves-access reviewed-complete-removal owned-resources-absent outside-access-refused unrelated-resources-preserved test-client-and-secret-cleanup ssh-access-preserved",
	}
	return strings.Fields(checks[id])
}
