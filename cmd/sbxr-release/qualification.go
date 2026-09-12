package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const (
	qualificationFactsSchema           = "sbxr-release-qualification-facts-v1"
	qualificationDecisionSchema        = "sbxr-release-qualification-decision-v1"
	candidatePreflightStage            = "candidate-preflight"
	candidateDraftConstructionStage    = "candidate-draft-construction"
	candidateDraftVerificationStage    = "candidate-draft-verification"
	qualificationBoundaryStage         = "qualification-boundary"
	acceptanceVPSResultStage           = "acceptance-vps-result"
	v3PackagedLiveResultStage          = "v3-packaged-live-result"
	candidateFailureStage              = "candidate-failure-finalization"
	candidateFailureVerificationStage  = "candidate-failure-verification"
	stablePreflightStage               = "stable-preflight"
	stablePublicationStage             = "stable-publication"
	stablePublicationVerificationStage = "stable-publication-verification"
	stableV3FinalizationStage          = "stable-v3-finalization"
	stableNoUpdateStage                = "stable-no-update"
	stableFailureStage                 = "stable-failure-finalization"
	stableFailureVerificationStage     = "stable-failure-verification"
	maxQualificationFactsBytes         = 16 << 20
)

type qualificationEnvelope struct {
	Schema string `json:"schema"`
	Stage  string `json:"stage"`
}

func runQualification(input io.Reader, output io.Writer) error {
	document, err := io.ReadAll(io.LimitReader(input, maxQualificationFactsBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxQualificationFactsBytes || softwarelifecycle.ValidateUniqueJSON(document) != nil {
		return errors.New("qualification facts refused")
	}
	var envelope qualificationEnvelope
	if json.Unmarshal(document, &envelope) != nil || envelope.Schema != qualificationFactsSchema {
		return errors.New("qualification facts refused")
	}
	var decision any
	switch envelope.Stage {
	case candidatePreflightStage:
		var facts qualificationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateCandidatePreflight(facts, document)
	case candidateDraftConstructionStage:
		var facts candidateDraftConstructionFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateCandidateDraftConstruction(facts, document)
	case candidateDraftVerificationStage:
		var facts candidateDraftVerificationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateCandidateDraftVerification(facts, document)
	case qualificationBoundaryStage:
		var facts qualificationBoundaryFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateQualificationBoundary(facts)
	case acceptanceVPSResultStage:
		var facts acceptanceVPSResultFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateAcceptanceVPSResult(facts, document)
	case v3PackagedLiveResultStage:
		decision, err = evaluateV3Result(document)
	case "v3-scenario-result":
		var facts v3RecurringResultFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateV3ScenarioResult(facts, document)
	case "v3-scenario-failure":
		var facts v3ScenarioFailureFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateV3ScenarioFailure(facts, document)
	case candidateFailureStage:
		var facts candidateFailureFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateCandidateFailure(facts, document)
	case candidateFailureVerificationStage:
		var facts candidateFailureVerificationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateCandidateFailureVerification(facts, document)
	case "owner-exception-result":
		decision, err = evaluateOwnerException(document)
	case stablePreflightStage:
		var facts stablePreflightFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStablePreflight(facts, document)
	case stablePublicationStage:
		var facts stablePublicationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStablePublication(facts, document)
	case stablePublicationVerificationStage:
		var facts stablePublicationVerificationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStablePublicationVerification(facts, document)
	case stableV3FinalizationStage:
		var facts stableV3FinalizationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStableV3Finalization(facts, document)
	case stableNoUpdateStage:
		var facts stableNoUpdateFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStableNoUpdate(facts, document)
	case stableFailureStage:
		var facts stableFailureFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStableFailure(facts, document)
	case stableFailureVerificationStage:
		var facts stableFailureVerificationFacts
		if !decodeCanonical(document, &facts) {
			return errors.New("qualification facts refused")
		}
		decision, err = evaluateStableFailureVerification(facts, document)
	default:
		return errors.New("qualification facts refused")
	}
	if err != nil {
		return err
	}
	body, err := marshalCanonical(decision)
	if err != nil {
		return errors.New("qualification decision refused")
	}
	_, err = output.Write(body)
	return err
}

func secretBearing(document []byte) bool {
	return bytes.Contains(document, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(document, []byte("BEGIN RSA PRIVATE KEY")) || bytes.Contains(document, []byte("BEGIN EC PRIVATE KEY")) || bytes.Contains(document, []byte("BEGIN OPENSSH PRIVATE KEY")) || bytes.Contains(document, []byte("Authorization: Bearer "))
}

func decodeCanonical(document []byte, value any) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	canonical, err := marshalCanonical(value)
	return err == nil && bytes.Equal(canonical, document)
}

func documentSHA256(document []byte) string {
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:])
}

func mustJSON(value any) json.RawMessage {
	body, err := marshalCanonical(value)
	if err != nil {
		panic(err)
	}
	return body
}

func marshalCanonical(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}
