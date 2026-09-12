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
	hasMVPScenario := func() bool {
		for _, id := range strings.Fields(softwarelifecycle.MVPLiveScenarios) {
			if hasRecordLine("Scenario: " + id + " ") {
				return true
			}
		}
		return false
	}
	scope := ""
	if release.Support != nil {
		scope = release.Support.Scope
	}
	latency := release.Support != nil && release.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair
	policy, policyOK := uniqueRecordValue(body, "Evidence policy: ")
	latency = latency && policyOK && slices.Contains([]string{softwarelifecycle.RepairKaringLatencyEvidencePolicy, softwarelifecycle.RepairTwoIssuanceEvidencePolicy}, policy)
	mvp := scope == softwarelifecycle.SubscriptionCleanInstallRepair && policyOK && policy == softwarelifecycle.MVPLiveEvidencePolicy
	if !mvp && (hasRecordLine("Live acceptance coverage: ") || hasMVPScenario()) {
		return false
	}
	if mvp {
		coverage, coverageOK := uniqueRecordValue(body, "Live acceptance coverage: ")
		karing, karingOK := uniqueRecordValue(body, "Karing connectivity evidence: ")
		if !coverageOK || coverage != softwarelifecycle.MVPLiveCoverage || !karingOK || karing != softwarelifecycle.MVPKaringEvidence || hasRecordLine("Karing checks not performed: ") {
			return false
		}
	} else if latency {
		coverage, coverageOK := uniqueRecordValue(body, "Karing connectivity evidence: ")
		excluded, excludedOK := uniqueRecordValue(body, "Karing checks not performed: ")
		if !coverageOK || coverage != softwarelifecycle.RepairKaringConnectivityEvidence || !excludedOK || excluded != softwarelifecycle.RepairKaringChecksNotPerformed {
			return false
		}
	} else if hasRecordLine("Live acceptance coverage: ") || hasRecordLine("Karing connectivity evidence: ") || hasRecordLine("Karing checks not performed: ") || hasMVPScenario() {
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
		if !policyOK || !slices.Contains([]string{softwarelifecycle.RepairEvidencePolicy, softwarelifecycle.RepairLifecycleEvidencePolicy, softwarelifecycle.RepairKaringLatencyEvidencePolicy, softwarelifecycle.RepairTwoIssuanceEvidencePolicy, softwarelifecycle.MVPLiveEvidencePolicy}, policy) {
			return false
		}
		if mvp {
			if hasRecordLine("Automated-only scenarios (not live): ") || hasRecordLine("Automated-only result: ") || hasRecordLine("Automated-only checks (not live): ") || !qualifiedMVPScenarios(body) {
				return false
			}
		} else if !automatedOnlyOK || automatedOnly != softwarelifecycle.RepairAutomatedOnlyScenarios || !automatedResultOK || automatedResult != "Passed in native amd64/arm64 workflow" {
			return false
		}
		if !mvp && (policy == softwarelifecycle.RepairLifecycleEvidencePolicy || latency) {
			checks, ok := uniqueRecordValue(body, "Automated-only checks (not live): ")
			if !ok || checks != softwarelifecycle.RepairAutomatedOnlyChecks {
				return false
			}
		} else if !mvp && hasRecordLine("Automated-only checks (not live): ") {
			return false
		}
		if !mvp {
			for _, id := range strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios) {
				if hasRecordLine("Scenario: " + id + " ") {
					return false
				}
			}
		}
	} else if hasRecordLine("Evidence policy: ") || hasRecordLine("Automated-only scenarios (not live): ") || hasRecordLine("Automated-only result: ") || hasRecordLine("Automated-only checks (not live): ") || hasRecordLine("Live acceptance coverage: ") || hasMVPScenario() {
		return false
	}
	if release.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall || release.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		return code == "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION" || !mvp && code == softwarelifecycle.OwnerExceptionCode && softwarelifecycle.OwnerExceptionTarget(release.Identity.Tag, release.Sequence, release.Support)
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

func qualifiedMVPScenarios(body string) bool {
	expected := map[string]bool{}
	for _, id := range strings.Fields(softwarelifecycle.MVPLiveScenarios) {
		expected[id] = true
	}
	seen := map[string]bool{}
	count := 0
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "Scenario: ") {
			continue
		}
		count++
		fields := strings.Fields(strings.TrimPrefix(line, "Scenario: "))
		if len(fields) != 3 || !expected[fields[0]] || seen[fields[0]] || !hashPattern.MatchString(fields[1]) || !strings.HasSuffix(fields[2], "#artifacts") || !workflowEvidencePattern.MatchString(strings.TrimSuffix(fields[2], "#artifacts")) {
			return false
		}
		seen[fields[0]] = true
	}
	return count == len(expected)
}
