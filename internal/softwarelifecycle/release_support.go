package softwarelifecycle

import (
	"encoding/json"
	"io"
	"slices"
)

const (
	// ADR-0017: one Owner-approved release, never a general evidence waiver.
	OwnerExceptionCode             = "RELEASE-V3-SUBSCRIPTION-OWNER-EXCEPTION"
	OwnerExceptionID               = "owner-approved-v3.1.0-sequence-83"
	OwnerExceptionLive             = "Not performed; waived by Owner for this release"
	OwnerExceptionSecrets          = "Automated scans passed; live capture coverage not proved"
	FirstSubscriptionCleanInstall  = "first-subscription-clean-install"
	SubscriptionCleanInstallRepair = "subscription-clean-install-repair"
	RecurringSubscriptionUpgrade   = "recurring-subscription-upgrade"
	RepairEvidencePolicy           = "repair-issuance-bounded-v1"
	RepairLifecycleEvidencePolicy  = "repair-issuance-bounded-v2"
	RepairAutomatedOnlyChecks      = "lifecycle-menu/explicit-confirmation lifecycle-menu/clean-install-target-refused"
	RepairAutomatedOnlyScenarios   = "enable-precommit enable-postcommit enable-schema2-absent repair-precommit repair-postcommit activation-precommit activation-postcommit invalid-replacement recorder-start recorder-outcome recorder-stale recorder-retention recorder-death recorder-reboot remove-enable-precommit remove-enable-postcommit remove-link-precommit remove-link-postcommit remove-repair-precommit remove-repair-postcommit remove-activation-precommit remove-activation-postcommit remove-identity-precommit remove-identity-postcommit remove-death remove-reboot remove-shared-route remove-finalization remove-exact-restoration"
	// This contract includes schema-2 Update Record runtime completion and the
	// fixed ownership, package, serving, renewal and startup representations.
	SubscriptionUpdateContract = "sbxr-subscription-update-v1"
	CleanInstallCorrection     = "This release does not support this incoming update. Use the old release's reviewed Complete removal, finish any interrupted removal with its exact release, then install and set up fresh. This causes downtime, new proxy credentials, and new client setup. Do not install over remaining authority or resources."
)

func OwnerExceptionTarget(tag string, sequence uint64, support *ReleaseSupport) bool {
	return tag == "v3.1.0" && sequence == 83 && support != nil && support.valid() && support.Scope == FirstSubscriptionCleanInstall
}

type ReleaseSupport struct {
	Scope    string            `json:"scope"`
	Sources  []ReleaseIdentity `json:"sources"`
	Contract string            `json:"contract"`
}

func (support *ReleaseSupport) valid() bool {
	if support == nil || support.Contract != SubscriptionUpdateContract || support.Sources == nil || len(support.Sources) > 32 {
		return false
	}
	if support.Scope == FirstSubscriptionCleanInstall || support.Scope == SubscriptionCleanInstallRepair {
		return len(support.Sources) == 0
	}
	if support.Scope != RecurringSubscriptionUpgrade || len(support.Sources) == 0 {
		return false
	}
	seen := map[ReleaseIdentity]bool{}
	for _, source := range support.Sources {
		if !validLatestRelease(LatestRelease{Identity: source, Sequence: 1}) || seen[source] {
			return false
		}
		seen[source] = true
	}
	return true
}

func supportedUpdate(release LatestRelease, source ReleaseIdentity, required bool) bool {
	if release.Support == nil {
		return !required
	}
	return release.Support.valid() && release.Support.Scope == RecurringSubscriptionUpgrade && slices.Contains(release.Support.Sources, source)
}

// BuildSubscriptionReleaseIndex binds support into the attested index. The
// qualification gate must bind the same source set to actual packaged evidence.
func BuildSubscriptionReleaseIndex(tag, commit string, sequence uint64, assets []LatestAssetProof, support ReleaseSupport) ([]byte, error) {
	if !support.valid() {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := BuildLatestReleaseIndex(tag, commit, sequence, assets)
	if err != nil {
		return nil, err
	}
	var document latestReleaseIndex
	if json.Unmarshal(body, &document) != nil {
		return nil, io.ErrUnexpectedEOF
	}
	document.Schema, document.Support = 2, &support
	return json.Marshal(document)
}
