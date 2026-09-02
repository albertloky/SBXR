package github

import (
	"encoding/json"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Release support is authenticated by the release-index digest. Qualification
// must repeat that exact declaration, binding its source scenarios to evidence.
func qualifiedReleaseSupport(body string, release softwarelifecycle.LatestRelease) bool {
	hasRecordLine := func(prefix string) bool {
		return strings.HasPrefix(body, prefix) || strings.Contains(body, "\n"+prefix)
	}
	if release.Support == nil {
		return !hasRecordLine("Evidence policy: ") && !hasRecordLine("Automated-only scenarios (not live): ") && !hasRecordLine("Automated-only result: ")
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
	policy, policyOK := uniqueRecordValue(body, "Evidence policy: ")
	automatedOnly, automatedOnlyOK := uniqueRecordValue(body, "Automated-only scenarios (not live): ")
	automatedResult, automatedResultOK := uniqueRecordValue(body, "Automated-only result: ")
	if release.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		if !policyOK || policy != softwarelifecycle.RepairEvidencePolicy || !automatedOnlyOK || automatedOnly != softwarelifecycle.RepairAutomatedOnlyScenarios || !automatedResultOK || automatedResult != "Passed in native amd64/arm64 workflow" {
			return false
		}
		for _, id := range strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios) {
			if hasRecordLine("Scenario: " + id + " ") {
				return false
			}
		}
	} else if hasRecordLine("Evidence policy: ") || hasRecordLine("Automated-only scenarios (not live): ") || hasRecordLine("Automated-only result: ") {
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
