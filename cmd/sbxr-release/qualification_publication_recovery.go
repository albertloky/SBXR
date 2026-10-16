package main

import "encoding/base64"

// The workflow verifies the burn's signature and invocation before setting these facts.
type stablePublicationRecovery struct {
	Burn                 burnedIdentity        `json:"burn"`
	BurnAttestationRunID string                `json:"burn_attestation_run_id"`
	BurnAttested         bool                  `json:"burn_attested"`
	FailedBody           string                `json:"failed_body"`
	FailureRun           stableFinalizationRun `json:"failure_run"`
}

func assessStablePublicationRecovery(facts stablePreflightFacts, manifest qualificationManifest, originalRecords map[string]string, originalBurns []burnedIdentity) (map[string]string, error) {
	recovery := facts.PublicationRecovery
	if recovery == nil {
		return nil, nil
	}
	refused := func() (map[string]string, error) { return nil, stablePreflightRefusal("publication-recovery") }
	if !currentCleanPublication(manifest) || len(facts.Releases) != 1 || manifest.V3Attempt == nil || len(manifest.V3Attempt.Sources) != 0 || len(manifest.V3Attempt.Support.Sources) != 0 || manifest.V3Attempt.OwnerException != "" || manifest.V3Attempt.LateConfirmationReview != nil || manifest.V3Attempt.Live89CorrectionReview != nil || !recovery.BurnAttested || recovery.BurnAttestationRunID != recovery.FailureRun.ID || !validStableFinalizationRun(recovery.FailureRun) {
		return refused()
	}
	release := manifest.Releases[0]
	wantedBurn := burnedIdentity{Commit: release.Commit, OriginalTag: release.Tag, QualificationRunURL: manifest.Workflow.RunURL, Reason: "prepublication-failure", RecordedAt: recovery.Burn.RecordedAt, ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Sequence: release.Sequence}
	created, createdOK := qualificationTime(facts.CandidateRun.CreatedAt)
	failed, failedOK := qualificationTime(recovery.FailureRun.CreatedAt)
	burned, burnedOK := qualificationTime(recovery.Burn.RecordedAt)
	observed, observedOK := qualificationTime(facts.ObservedAt)
	if recovery.Burn != wantedBurn || !validBurnedIdentity(recovery.Burn) || !createdOK || !failedOK || !burnedOK || !observedOK || failed.Before(created) || burned.Before(failed) || observed.Before(burned) || recovery.FailureRun.ID == manifest.Workflow.RunID || !preservedPublicationBurns(facts.BurnedIdentities, originalBurns) || collidesWithBurned(originalBurns, release.Tag, release.Sequence) {
		return refused()
	}
	if required, exact := burnRequirement(facts.BurnedIdentities, recovery.Burn); required || !exact {
		return refused()
	}
	body, ok := originalRecords[release.Tag]
	failedBody, err := buildStableFailedAcceptanceRecord(manifest, release, body, recovery.FailureRun.URL)
	if !ok || err != nil || failedBody != recovery.FailedBody {
		return refused()
	}
	canonicalBurn, err := marshalCanonical(recovery.Burn)
	if err != nil {
		return refused()
	}
	recoveredBody := body + "\nPublication recovery: original qualification and asset bytes preserved\n" +
		"Prior publication failure: " + recovery.FailureRun.URL + "\n" +
		"Preserved burn: release-burned/" + release.Tag + "\n" +
		"Preserved burn canonical SHA-256: " + documentSHA256(canonicalBurn) + "\n" +
		"Prior failed record SHA-256: " + documentSHA256([]byte(recovery.FailedBody)) + "\n" +
		"Prior failed record base64: " + base64.StdEncoding.EncodeToString([]byte(recovery.FailedBody)) + "\n"
	current := facts.Releases[0]
	if current.Draft || !current.Immutable || current.Prerelease && current.Body != recovery.FailedBody || !current.Prerelease && current.Body != recoveredBody {
		return refused()
	}
	return map[string]string{release.Tag: recoveredBody}, nil
}

func preservedPublicationBurns(current, original []burnedIdentity) bool {
	if current == nil || original == nil || !validFailureBurns(current) || !validFailureBurns(original) {
		return false
	}
	index := 0
	for _, prior := range original {
		for index < len(current) && current[index].OriginalTag < prior.OriginalTag {
			index++
		}
		if index == len(current) || current[index] != prior {
			return false
		}
	}
	return true
}
