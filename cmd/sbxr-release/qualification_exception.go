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

func ownerExceptionManifest(manifest qualificationManifest) bool {
	return manifest.Schema == "sbxr-qualification-manifest-v3" && manifest.V3Attempt != nil && manifest.V3Attempt.OwnerException == softwarelifecycle.OwnerExceptionID && manifest.SourceState == "v3-subscription-clean" && len(manifest.Releases) == 1 && softwarelifecycle.OwnerExceptionTarget(manifest.Releases[0].Tag, manifest.Releases[0].Sequence, supportPointer(manifest.V3Attempt.Support))
}

// This is an explicit policy decision, not fabricated live scenario evidence.
type ownerExceptionFacts struct {
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
