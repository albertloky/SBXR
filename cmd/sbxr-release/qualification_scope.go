package main

import (
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Facts are collected by the trusted workflow from every release-list page and
// the existing public verifier. They are not an Owner-supplied override.
type v3ReleaseHistory struct {
	Complete     bool                     `json:"complete"`
	PublicLatest publicLatestVerification `json:"public_latest"`
	Releases     []observedRelease        `json:"releases"`
}

func historyReleases(history *v3ReleaseHistory) []observedRelease {
	if history == nil {
		return nil
	}
	return history.Releases
}

type v3ReleaseSupport struct {
	Contract string                    `json:"contract"`
	Scope    string                    `json:"scope"`
	Sources  []decisionReleaseIdentity `json:"sources"`
}

func validSupportDeclaration(support v3ReleaseSupport) bool {
	if support.Contract != softwarelifecycle.SubscriptionUpdateContract || support.Sources == nil || len(support.Sources) > 32 {
		return false
	}
	if cleanInstallScope(support.Scope) {
		return len(support.Sources) == 0
	}
	if support.Scope != softwarelifecycle.RecurringSubscriptionUpgrade || len(support.Sources) == 0 {
		return false
	}
	seen := map[decisionReleaseIdentity]bool{}
	for _, source := range support.Sources {
		if source.Repository != softwarelifecycle.Repository || !validTag(source.Tag) || !validCommit(source.Commit) || !validSHA256(source.ReleaseIndexSHA256) || seen[source] {
			return false
		}
		seen[source] = true
	}
	return true
}

func (support v3ReleaseSupport) lifecycle() softwarelifecycle.ReleaseSupport {
	result := softwarelifecycle.ReleaseSupport{Contract: support.Contract, Scope: support.Scope, Sources: []softwarelifecycle.ReleaseIdentity{}}
	for _, source := range support.Sources {
		result.Sources = append(result.Sources, softwarelifecycle.ReleaseIdentity{Repository: source.Repository, Tag: source.Tag, Commit: source.Commit, IndexSHA256: source.ReleaseIndexSHA256})
	}
	return result
}

func subscriptionRelease(release observedRelease) bool {
	return !release.Prerelease && release.Index != nil && release.Index.Support != nil || strings.Contains(release.Body, "Stable result code: RELEASE-V3-SUBSCRIPTION-")
}

func validSubscriptionHistory(history *v3ReleaseHistory, scope string, baseline *qualificationRelease) bool {
	if history == nil || !history.Complete || len(history.Releases) == 0 || history.PublicLatest.Outcome != "accepted" || history.PublicLatest.ReleaseIdentity == nil || history.PublicLatest.Sequence == nil {
		return false
	}
	encoded, err := marshalCanonical(history)
	if err != nil || recurringSecret(encoded) {
		return false
	}
	latest := history.PublicLatest.ReleaseIdentity
	facts := qualificationFacts{Releases: history.Releases, LatestTag: &latest.Tag}
	if !validObservedFacts(facts) {
		return false
	}
	source, exists := releaseByTag(history.Releases, latest.Tag)
	if !exists || !qualifiedV3Source(source) || sourceAction(source).ReleaseIdentity != *latest || source.Index.Sequence != *history.PublicLatest.Sequence {
		return false
	}
	if baseline != nil && !reflect.DeepEqual(*baseline, historyBaseline(history)) {
		return false
	}
	switch scope {
	case softwarelifecycle.FirstSubscriptionCleanInstall:
		for _, release := range history.Releases {
			// Legacy V1 predates this product. Every later published release needs an
			// observed index; an unreadable release cannot prove absence of support.
			if !historicalV1Tag(release.Tag) && (release.Index == nil || release.Index.Schema != 1 && release.Index.Schema != 2 || release.Index.Schema == 1 && release.Index.Support != nil || release.Index.Schema == 2 && (release.Index.Support == nil || !validSupportDeclaration(*release.Index.Support))) || subscriptionRelease(release) {
				return false
			}
		}
		return true
	case softwarelifecycle.RecurringSubscriptionUpgrade:
		return subscriptionRelease(source)
	case softwarelifecycle.SubscriptionCleanInstallRepair:
		// ADR-0018 repairs this exact immutable baseline, not arbitrary future releases.
		if *latest != (decisionReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.1.0", Commit: "c0667a12ea914f2d0c86d73d52bfb8b40fea054a", ReleaseIndexSHA256: "5e9b25cf2bd5b448c0a833b6420e165bd47a207144bb63330a62e0b9dafc3cd1"}) || source.Index.Sequence != 83 {
			return false
		}
		for _, release := range history.Releases {
			if !historicalV1Tag(release.Tag) && (release.Index == nil || release.Index.Schema != 1 && release.Index.Schema != 2 || release.Index.Schema == 1 && release.Index.Support != nil || release.Index.Schema == 2 && (release.Index.Support == nil || !validSupportDeclaration(*release.Index.Support))) {
				return false
			}
			if !release.Prerelease && release.Index != nil && release.Index.Support != nil && release.Index.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
				return false
			}
		}
		return true
	}
	return false
}

func cleanInstallScope(scope string) bool {
	return scope == softwarelifecycle.FirstSubscriptionCleanInstall || scope == softwarelifecycle.SubscriptionCleanInstallRepair
}

func historyBaseline(history *v3ReleaseHistory) qualificationRelease {
	source, _ := releaseByTag(history.Releases, history.PublicLatest.ReleaseIdentity.Tag)
	action := sourceAction(source)
	return qualificationRelease{Assets: action.Assets, Commit: action.Commit, ReleaseID: action.ReleaseID, ReleaseIdentity: action.ReleaseIdentity, Sequence: action.Sequence, Tag: action.Tag}
}

func attemptVersion(attempt *v3QualificationAttempt) string {
	if attempt.Schema == "sbxr-v3-qualification-attempt-v3" {
		return "v3"
	}
	return "v2"
}

func attemptScenarios(attempt v3QualificationAttempt) []string {
	ids := requiredV3Scenarios(attempt.Sources)
	if attempt.Support != nil && attempt.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		automatedOnly := strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)
		ids = slices.DeleteFunc(ids, func(id string) bool { return slices.Contains(automatedOnly, id) })
	}
	if attempt.Support != nil && cleanInstallScope(attempt.Support.Scope) {
		index := slices.Index(ids, "update-incompatible")
		ids = append(ids[:index], append([]string{"lifecycle-menu"}, ids[index+2:]...)...)
	}
	return ids
}

func validAttemptSupport(attempt v3QualificationAttempt) bool {
	if attempt.Support == nil || !validSupportDeclaration(*attempt.Support) || attempt.Sources == nil || len(attempt.Support.Sources) != len(attempt.Sources) || !slices.Equal(attempt.RequiredScenarios, attemptScenarios(attempt)) {
		return false
	}
	if attempt.Support.Scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		if attempt.EvidencePolicy != softwarelifecycle.RepairEvidencePolicy || !slices.Equal(attempt.AutomatedOnlyScenarios, strings.Fields(softwarelifecycle.RepairAutomatedOnlyScenarios)) {
			return false
		}
	} else if attempt.EvidencePolicy != "" || attempt.AutomatedOnlyScenarios != nil {
		return false
	}
	for i, source := range attempt.Sources {
		if source.ReleaseIdentity != attempt.Support.Sources[i] {
			return false
		}
	}
	return true
}

func validAttemptIndex(attempt v3QualificationAttempt, release qualificationRelease) bool {
	if attempt.Support == nil {
		return false
	}
	var proofs []softwarelifecycle.LatestAssetProof
	for _, asset := range release.Assets {
		proofs = append(proofs, softwarelifecycle.LatestAssetProof{Name: asset.Name, Size: asset.Size, SHA256: asset.SHA256})
	}
	verified, ok := softwarelifecycle.VerifyLatestReleaseIndex(softwarelifecycle.Repository, release.Tag, release.Commit, []byte(attempt.CandidateIndex), proofs)
	return ok && verified.Sequence == release.Sequence && verified.Identity.IndexSHA256 == release.ReleaseIdentity.ReleaseIndexSHA256 && verified.Support != nil && reflect.DeepEqual(*verified.Support, attempt.Support.lifecycle())
}

func validPublicationHistory(manifest qualificationManifest, history *v3ReleaseHistory) bool {
	if manifest.Schema != "sbxr-qualification-manifest-v3" {
		return history == nil
	}
	attempt := manifest.V3Attempt
	return attempt != nil && attempt.Support != nil && attempt.Baseline != nil && validSubscriptionHistory(history, attempt.Support.Scope, attempt.Baseline)
}

func historicalV1Tag(tag string) bool {
	for patch := 0; patch <= 15; patch++ {
		if tag == "v1.0."+strconv.Itoa(patch) {
			return true
		}
	}
	return false
}
