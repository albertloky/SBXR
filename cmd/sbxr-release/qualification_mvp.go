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

func mvpRecurringAttempt(attempt v3QualificationAttempt) bool {
	return attempt.Support != nil && attempt.Support.Scope == softwarelifecycle.RecurringSubscriptionUpgrade && attempt.EvidencePolicy == softwarelifecycle.MVPRecurringEvidencePolicy
}

func ordinaryLiveAttempt(attempt v3QualificationAttempt) bool {
	return mvpLiveAttempt(attempt) || mvpRecurringAttempt(attempt)
}

func mvpRecurringScenarios(sources []v3QualificationSource) []string {
	var ids []string
	for _, source := range sources {
		// Rollback leaves the exact source available for the normal update.
		for _, suffix := range []string{"precommit", "upgrade", "postcommit"} {
			ids = append(ids, "source-"+source.ReleaseIdentity.Tag+"-"+suffix)
		}
	}
	return append(ids, strings.Fields(softwarelifecycle.MVPLiveScenarios)...)
}

func mvpUpgradeChecks(id string) []string {
	if !strings.HasPrefix(id, "source-") {
		return nil
	}
	checks := strings.Fields("exact-source-and-candidate actual-source-packaged-updater source-record-schema-proved both-releases-understand-recovery reviewed-update-confirmation admission-exclusion creation-provenance-preserved no-ownership-migration proxy-not-restarted both-credentials-unchanged subscription-link-unchanged outside-proxy-traffic outside-trusted-https ssh-access-preserved private-files-and-logs-protected no-helper-or-intermediate-release")
	switch {
	case strings.HasSuffix(id, "-precommit"):
		return append(checks, strings.Fields("observed-precommit-interruption actual-source-packaged-recovery prior-exact-restoration source-installed-record-restored no-transaction-residue")...)
	case strings.HasSuffix(id, "-postcommit"):
		return append(checks, strings.Fields("observed-postcommit-interruption candidate-forward-runtime-completion candidate-installed-record-proved serving-only-restart no-transaction-residue")...)
	case strings.HasSuffix(id, "-upgrade"):
		return append(checks, strings.Fields("candidate-installed-record-proved serving-only-restart no-transaction-residue")...)
	}
	return nil
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
