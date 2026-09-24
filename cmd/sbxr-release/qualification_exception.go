package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func supportPointer(support *v3ReleaseSupport) *softwarelifecycle.ReleaseSupport {
	if support == nil {
		return nil
	}
	value := support.lifecycle()
	return &value
}

func exceptionProfile(manifest qualificationManifest) (softwarelifecycle.QualificationExceptionProfile, bool) {
	if manifest.Schema != "sbxr-qualification-manifest-v3" || manifest.V3Attempt == nil || manifest.SourceState != "v3-subscription-clean" || len(manifest.Releases) != 1 {
		return softwarelifecycle.QualificationExceptionProfile{}, false
	}
	r := manifest.Releases[0]
	profile, ok := softwarelifecycle.QualificationException(r.Tag, r.Sequence, supportPointer(manifest.V3Attempt.Support))
	if !ok || manifest.V3Attempt.OwnerException != profile.ID {
		return profile, false
	}
	if profile.ID == softwarelifecycle.LateConfirmationID && (!manifest.V3Attempt.LateConfirmationReview.Valid(manifest.Workflow.Commit) || !mvpLiveAttempt(*manifest.V3Attempt)) {
		return profile, false
	}
	return profile, true
}

func ownerExceptionManifest(manifest qualificationManifest) bool {
	_, ok := exceptionProfile(manifest)
	return ok
}

// This is an explicit policy decision, not fabricated live scenario evidence.
type ownerExceptionFacts struct {
	LateConfirmationSupplement json.RawMessage `json:"late_confirmation_supplement,omitempty"`
	ObservedAt                 string          `json:"observed_at"`
	QualificationBoundaryFacts json.RawMessage `json:"qualification_boundary_facts"`
	QualificationManifest      json.RawMessage `json:"qualification_manifest"`
	ManifestAttested           bool            `json:"qualification_manifest_attested"`
	Schema                     string          `json:"schema"`
	Stage                      string          `json:"stage"`
}

func evaluateOwnerException(document []byte) (acceptanceVPSResultDecision, error) {
	var facts ownerExceptionFacts
	var boundary qualificationBoundaryFacts
	if !decodeCanonical(document, &facts) || facts.Schema != qualificationFactsSchema || facts.Stage != "owner-exception-result" || !facts.ManifestAttested || recurringSecret(document) || !decodeCanonical(facts.QualificationBoundaryFacts, &boundary) {
		return acceptanceVPSResultDecision{}, errors.New("Owner exception refused")
	}
	manifest, err := evaluateQualificationBoundary(boundary)
	encoded, encodeErr := marshalCanonical(manifest)
	observed, timeOK := qualificationTime(facts.ObservedAt)
	if err != nil || encodeErr != nil || !ownerExceptionManifest(manifest) || !bytes.Equal(encoded, facts.QualificationManifest) || !timeOK {
		return acceptanceVPSResultDecision{}, errors.New("Owner exception refused")
	}
	profile, _ := exceptionProfile(manifest)
	if profile.ID == softwarelifecycle.LateConfirmationID {
		if documentSHA256(facts.LateConfirmationSupplement) != softwarelifecycle.LateConfirmationSupplement {
			return acceptanceVPSResultDecision{}, errors.New("late confirmation evidence refused")
		}
		if _, err := evaluateLateConfirmation(facts.LateConfirmationSupplement); err != nil {
			return acceptanceVPSResultDecision{}, err
		}
		if !lateConfirmationEnvironmentMatches(*manifest.V3Attempt, facts.LateConfirmationSupplement) {
			return acceptanceVPSResultDecision{}, errors.New("prior live environment mismatch")
		}
	} else if facts.LateConfirmationSupplement != nil {
		return acceptanceVPSResultDecision{}, errors.New("unexpected late confirmation supplement")
	}
	started, _ := qualificationTime(manifest.V3Attempt.StartedAt)
	if observed.Before(started) || observed.Sub(started) > 30*time.Minute {
		return acceptanceVPSResultDecision{}, errors.New("Owner exception expired")
	}
	body, err := buildRecurringAcceptanceRecord(manifest, v3RecurringResultFacts{EvaluationTime: facts.ObservedAt, DetailedEvidenceSHA256: documentSHA256(document)})
	if err != nil {
		return acceptanceVPSResultDecision{}, err
	}
	return acceptanceVPSResultDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: documentSHA256(encoded), Records: []acceptanceRecord{{Body: body, Tag: manifest.Releases[0].Tag}}, Schema: qualificationDecisionSchema, Stage: facts.Stage}, nil
}

// The new record describes the environment actually tested in r24, not a
// freshly observed host or arbitrary replacement client/package declaration.
func lateConfirmationEnvironmentMatches(attempt v3QualificationAttempt, supplement []byte) bool {
	var facts lateConfirmationFacts
	if !decodeCanonical(supplement, &facts) {
		return false
	}
	for _, evidence := range facts.Evidence {
		if evidence.Name != "signed/qualification-manifest.json" {
			continue
		}
		var prior qualificationManifest
		if json.Unmarshal([]byte(evidence.Content), &prior) != nil || prior.V3Attempt == nil {
			return false
		}
		p := prior.V3Attempt
		return attempt.Packages == p.Packages && attempt.AfterSnapRefresh == p.AfterSnapRefresh && attempt.ProxyPackage == p.ProxyPackage && attempt.Runner == p.Runner && attempt.MacOSVersion == p.MacOSVersion && attempt.MacRunnerID == p.MacRunnerID && attempt.OutsideRunnerID == p.OutsideRunnerID && attempt.VPSID == p.VPSID && attempt.VPSIdentitySHA256 == p.VPSIdentitySHA256
	}
	return false
}
