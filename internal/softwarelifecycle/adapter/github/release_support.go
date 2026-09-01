package github

import (
	"encoding/json"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Release support is authenticated by the release-index digest. Qualification
// must repeat that exact declaration, binding its source scenarios to evidence.
func qualifiedReleaseSupport(body string, release softwarelifecycle.LatestRelease) bool {
	if release.Support == nil {
		return true
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
	if release.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall {
		return code == "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION"
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
