package main

import (
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// A policy identifier distinguishes the reduced scope from historical attempts;
// it adds no evidence envelope, prerequisite or product behavior.
func mvpLiveAttempt(attempt v3QualificationAttempt) bool {
	if attempt.Support == nil {
		return false
	}
	if attempt.Support.Scope == softwarelifecycle.SubscriptionCleanInstallOnly {
		return attempt.EvidencePolicy == softwarelifecycle.MVPHTTPEvidencePolicy
	}
	return attempt.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair && (attempt.EvidencePolicy == softwarelifecycle.MVPLiveEvidencePolicy || attempt.EvidencePolicy == softwarelifecycle.MVPHTTPEvidencePolicy)
}

func mvpRecurringAttempt(attempt v3QualificationAttempt) bool {
	return attempt.Support != nil && attempt.Support.Scope == softwarelifecycle.RecurringSubscriptionUpgrade && (attempt.EvidencePolicy == softwarelifecycle.MVPRecurringEvidencePolicy || attempt.EvidencePolicy == softwarelifecycle.MVPHTTPRecurringEvidencePolicy)
}

func httpLiveAttempt(attempt v3QualificationAttempt) bool {
	return attempt.EvidencePolicy == softwarelifecycle.MVPHTTPEvidencePolicy || attempt.EvidencePolicy == softwarelifecycle.MVPHTTPRecurringEvidencePolicy
}

func ordinaryJourneys(attempt v3QualificationAttempt) []string {
	if httpLiveAttempt(attempt) {
		return strings.Fields(softwarelifecycle.MVPHTTPScenarios)
	}
	return strings.Fields(softwarelifecycle.MVPLiveScenarios)
}

func validProxyProfile(attempt v3QualificationAttempt) bool {
	if attempt.ProxyProfile == "" {
		return true
	}
	// Historical scopes and evidence reuse cannot qualify the new tunnel route.
	return attempt.ProxyProfile == "vless-vmess" && attempt.Schema == "sbxr-v3-qualification-attempt-v3" &&
		attempt.Support != nil && validSupportDeclaration(*attempt.Support) && attempt.Support.Scope == softwarelifecycle.SubscriptionCleanInstallOnly &&
		attempt.EvidencePolicy == softwarelifecycle.MVPHTTPEvidencePolicy && attempt.Sources != nil && len(attempt.Sources) == 0 &&
		attempt.OwnerException == "" && attempt.LateConfirmationReview == nil && attempt.Live89CorrectionReview == nil && attempt.AutomatedOnlyScenarios == nil
}

func ordinaryChecks(attempt v3QualificationAttempt, id string) []string {
	if !validProxyProfile(attempt) {
		return nil
	}
	if !httpLiveAttempt(attempt) {
		if strings.HasPrefix(id, "source-") {
			return mvpUpgradeChecks(id)
		}
		return mvpLiveChecks(id)
	}
	if strings.HasPrefix(id, "source-") {
		checks := mvpUpgradeChecks(id)
		for i, check := range checks {
			if strings.HasSuffix(id, "-precommit") {
				if check == "outside-trusted-https" {
					checks[i] = "outside-subscription-transport-preserved"
				}
				continue
			}
			switch check {
			case "no-ownership-migration":
				checks[i] = "updater-ownership-preserved-until-cleanup"
			case "subscription-link-unchanged":
				checks[i] = "subscription-address-port-path-token-preserved"
			case "outside-trusted-https":
				checks[i] = "outside-authenticated-http"
			}
		}
		if !strings.HasSuffix(id, "-precommit") {
			checks = append(checks, strings.Fields("mandatory-http-handoff-completed retained-certificate-bytes-and-provenance-preserved owned-renewal-and-http80-retired existing-client-profile-refreshed-with-settings-preserved no-migration-ca-operation no-migration-authority-residue")...)
		}
		return checks
	}
	if id == "mvp-renewal" {
		return nil
	}
	checks := mvpLiveChecks(id)
	if id == "mvp-serving" {
		checks = strings.Fields("serving-restart-preserves-link current-artifact-after-restart outside-authenticated-http no-certificate-or-renewal-resources proxy-traffic-preserved")
	}
	if id == "mvp-subscription" {
		checks[0] = "outside-authenticated-http"
		checks = append(checks, "no-certificate-or-renewal-resources", "http-exposure-disclosed")
	}
	if attempt.ProxyProfile == "vless-vmess" {
		for i, check := range checks {
			if check == "one-correct-subscription-node" {
				checks[i] = "exact-vless-reality-and-vmess-websocket-nodes"
			}
		}
		extra := map[string]string{
			"mvp-install":      "outside-vless-reality-traffic outside-vmess-websocket-traffic dedicated-connector-running",
			"mvp-subscription": "fresh-karing-vless-node-latency fresh-karing-vmess-node-latency",
			"mvp-credentials":  "vless-old-established-session-terminated vmess-old-established-session-terminated vless-old-credential-refused vmess-old-credential-refused vless-replacement-proxy-traffic vmess-replacement-proxy-traffic same-link-refreshed-both-identities rotated-link-refreshed-both-identities both-identities-unchanged-by-link-rotation fresh-karing-vless-replacement-latency fresh-karing-vmess-replacement-latency",
			"mvp-serving":      "vless-traffic-preserved vmess-traffic-preserved dedicated-connector-preserved",
			"mvp-removal":      "restart-preserves-vless-access restart-preserves-vmess-access owned-connector-absent outside-vless-access-refused outside-vmess-access-refused tunnel-prerequisites-preserved",
		}
		checks = append(checks, strings.Fields(extra[id])...)
	}
	return checks
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
