package github

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Release support is authenticated by the release-index digest. Qualification
// must repeat that exact declaration, binding its source scenarios to evidence.
func qualifiedReleaseSupport(body string, release softwarelifecycle.LatestRelease) bool {
	hasRecordLine := func(prefix string) bool {
		return strings.HasPrefix(body, prefix) || strings.Contains(body, "\n"+prefix)
	}
	latency := release.Support != nil && release.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair
	policy, policyOK := uniqueRecordValue(body, "Evidence policy: ")
	latency = latency && policyOK && policy == softwarelifecycle.RepairKaringLatencyEvidencePolicy
	if latency {
		coverage, coverageOK := uniqueRecordValue(body, "Karing connectivity evidence: ")
		excluded, excludedOK := uniqueRecordValue(body, "Karing checks not performed: ")
		if !coverageOK || coverage != softwarelifecycle.RepairKaringConnectivityEvidence || !excludedOK || excluded != softwarelifecycle.RepairKaringChecksNotPerformed {
			return false
		}
	} else if hasRecordLine("Karing connectivity evidence: ") || hasRecordLine("Karing checks not performed: ") {
		return false
	}
	if release.Support == nil {
		return !hasRecordLine("Evidence policy: ") && !hasRecordLine("Automated-only scenarios (not live): ") && !hasRecordLine("Automated-only result: ") && !hasRecordLine("Automated-only checks (not live): ")
	}
	encoded, err := json.Marshal(release.Support)
	declared, ok := uniqueRecordValue(body, "Release support: ")
	if err != nil || !ok || declared != string(encoded) {
		return false
	}
	code, ok := uniqueRecordValue(body, "Stable result code: ")
	if !ok {
		return false
	}
	automatedOnly, automatedOnlyOK := uniqueRecordValue(body, "Automated-only scenarios (not live): ")
	automatedResult, automatedResultOK := uniqueRecordValue(body, "Automated-only result: ")
	if release.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		if !policyOK || !slices.Contains([]string{softwarelifecycle.RepairEvidencePolicy, softwarelifecycle.RepairLifecycleEvidencePolicy, softwarelifecycle.RepairKaringLatencyEvidencePolicy}, policy) || !automatedOnlyOK || automatedOnly != softwarelifecycle.RepairAutomatedOnlyScenarios || !automatedResultOK || automatedResult != "Passed in native amd64/arm64 workflow" {
			return false
		}
		if policy == softwarelifecycle.RepairLifecycleEvidencePolicy || latency {
			checks, ok := uniqueRecordValue(body, "Automated-only checks (not live): ")
			if !ok || checks != softwarelifecycle.RepairAutomatedOnlyChecks {
				return false
			}
		} else if hasRecordLine("Automated-only checks (not live): ") {
			return false
		}
		for _, id := range strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios) {
			if hasRecordLine("Scenario: " + id + " ") {
				return false
			}
		}
	} else if hasRecordLine("Evidence policy: ") || hasRecordLine("Automated-only scenarios (not live): ") || hasRecordLine("Automated-only result: ") || hasRecordLine("Automated-only checks (not live): ") {
		return false
	}
	if release.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall || release.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		return code == "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION" || code == softwarelifecycle.OwnerExceptionCode && softwarelifecycle.OwnerExceptionTarget(release.Identity.Tag, release.Sequence, release.Support)
	}
	if code != "RELEASE-V3-SUBSCRIPTION-QUALIFICATION" {
		return false
	}
	for _, source := range release.Support.Sources {
		for _, suffix := range []string{"upgrade", "precommit", "postcommit"} {
			proof, ok := uniqueRecordValue(body, "Scenario: source-"+source.Tag+"-"+suffix+" ")
			fields := strings.Fields(proof)
			if !ok || len(fields) != 2 || !hashPattern.MatchString(fields[0]) || !strings.HasSuffix(fields[1], "#artifacts") || !workflowEvidencePattern.MatchString(strings.TrimSuffix(fields[1], "#artifacts")) {
				return false
			}
		}
	}
	return true
}
