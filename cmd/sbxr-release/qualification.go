package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	stablePublicationRecordStage       = "stable-publication-record-verification"
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

// Diagnostic text is fixed by the check; private parser/I/O causes stay unwrap-able.
type qualificationDiagnostic struct {
	check string
	cause error
}

func (err *qualificationDiagnostic) Error() string { return err.check }
func (err *qualificationDiagnostic) Unwrap() error { return err.cause }

func qualificationRefused(check string, cause error) error {
	return &qualificationDiagnostic{check: check, cause: cause}
}

func runQualification(input io.Reader, output io.Writer) error {
	document, err := io.ReadAll(io.LimitReader(input, maxQualificationFactsBytes+1))
	if err != nil {
		return qualificationRefused("qualification-input/read", err)
	}
	if len(document) == 0 {
		return qualificationRefused("qualification-input/empty", nil)
	}
	if len(document) > maxQualificationFactsBytes {
		return qualificationRefused(fmt.Sprintf("qualification-input/size expected<=%d observed>=%d", maxQualificationFactsBytes, len(document)), nil)
	}
	if err := softwarelifecycle.ValidateUniqueJSON(document); err != nil {
		return qualificationRefused("qualification-input/unique-json", err)
	}
	var envelope qualificationEnvelope
	if err := json.Unmarshal(document, &envelope); err != nil {
		return qualificationRefused("qualification-input/envelope", err)
	}
	if envelope.Schema != qualificationFactsSchema {
		return qualificationRefused("qualification-input/schema", nil)
	}
	var decision any
	switch envelope.Stage {
	case candidatePreflightStage:
		var facts qualificationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateCandidatePreflight(facts, document)
	case candidateDraftConstructionStage:
		var facts candidateDraftConstructionFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateCandidateDraftConstruction(facts, document)
	case candidateDraftVerificationStage:
		var facts candidateDraftVerificationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateCandidateDraftVerification(facts, document)
	case qualificationBoundaryStage:
		var facts qualificationBoundaryFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateQualificationBoundary(facts)
	case acceptanceVPSResultStage:
		var facts acceptanceVPSResultFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateAcceptanceVPSResult(facts, document)
	case v3PackagedLiveResultStage:
		decision, err = evaluateV3Result(document)
	case "v3-scenario-result":
		var facts v3RecurringResultFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateV3ScenarioResult(facts, document)
	case "v3-scenario-failure":
		var facts v3ScenarioFailureFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateV3ScenarioFailure(facts, document)
	case candidateFailureStage:
		var facts candidateFailureFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateCandidateFailure(facts, document)
	case candidateFailureVerificationStage:
		var facts candidateFailureVerificationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateCandidateFailureVerification(facts, document)
	case "owner-exception-result":
		decision, err = evaluateOwnerException(document)
	case lateConfirmationStage:
		decision, err = evaluateLateConfirmation(document)
	case live89CorrectionStage:
		decision, err = evaluateLive89Correction(document)
	case stablePreflightStage:
		var facts stablePreflightFacts
		if !decodeCanonical(document, &facts) {
			return stablePreflightRefusal("canonical-facts")
		}
		decision, err = evaluateStablePreflight(facts, document)
	case stablePublicationStage:
		var facts stablePublicationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStablePublication(facts, document)
	case stablePublicationVerificationStage:
		var facts stablePublicationVerificationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStablePublicationVerification(facts, document)
	case stablePublicationRecordStage:
		var facts stablePublicationRecordFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStablePublicationRecord(facts, document)
	case stableV3FinalizationStage:
		var facts stableV3FinalizationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStableV3Finalization(facts, document)
	case stableNoUpdateStage:
		var facts stableNoUpdateFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStableNoUpdate(facts, document)
	case stableFailureStage:
		var facts stableFailureFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStableFailure(facts, document)
	case stableFailureVerificationStage:
		var facts stableFailureVerificationFacts
		if !decodeCanonical(document, &facts) {
			return qualificationRefused(envelope.Stage+"/canonical-facts", nil)
		}
		decision, err = evaluateStableFailureVerification(facts, document)
	default:
		return qualificationRefused("qualification-input/stage", nil)
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
