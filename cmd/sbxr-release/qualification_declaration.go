package main

import (
	"errors"
	"io"
	"regexp"
	"strconv"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const qualificationDeclarationStage = "qualification-declaration"

type qualificationDeclarationFacts struct {
	Attempt   v3QualificationAttempt `json:"attempt"`
	Preflight qualificationFacts     `json:"preflight"`
}

type qualificationDeclarationDecision struct {
	FactsSHA256 string `json:"facts_sha256"`
	Outcome     string `json:"outcome"`
	Schema      string `json:"schema"`
	Stage       string `json:"stage"`
}

// runQualificationDeclaration checks the complete, still-unsigned V3 attempt
// declaration before the candidate workflow allocates build runners. Values
// derived only after the build (the candidate index and baseline binding) are
// deliberately absent from this input and remain signing-gate checks.
func runQualificationDeclaration(input io.Reader, output io.Writer) error {
	document, err := io.ReadAll(io.LimitReader(input, maxQualificationFactsBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxQualificationFactsBytes || softwarelifecycle.ValidateUniqueJSON(document) != nil {
		return errors.New("qualification declaration refused")
	}
	var facts qualificationDeclarationFacts
	if !decodeCanonical(document, &facts) {
		return errors.New("qualification declaration refused")
	}
	preflightDocument, err := marshalCanonical(facts.Preflight)
	if err != nil {
		return errors.New("qualification declaration refused")
	}
	preflightDecision, err := evaluateCandidatePreflight(facts.Preflight, preflightDocument)
	if err != nil || preflightDecision.Outcome != "accepted" || facts.Preflight.Candidate.Mode != "v3" || facts.Preflight.Candidate.EvidenceVersion != 3 || facts.Attempt.Schema != "sbxr-v3-qualification-attempt-v3" || facts.Attempt.Baseline != nil || facts.Attempt.CandidateIndex != "" {
		return errors.New("qualification declaration refused")
	}
	baseline := historyBaseline(facts.Preflight.SubscriptionHistory)
	bound := facts.Attempt
	bound.Baseline = &baseline
	if !validDeclaredAttemptID(bound.AttemptID, bound.RunAttempt) || !validV3AttemptDeclaredFields(bound, facts.Preflight) {
		return errors.New("qualification declaration refused")
	}
	decision := qualificationDeclarationDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", Schema: qualificationDecisionSchema, Stage: qualificationDeclarationStage}
	body, err := marshalCanonical(decision)
	if err != nil {
		return errors.New("qualification declaration decision refused")
	}
	_, err = output.Write(body)
	return err
}

func validDeclaredAttemptID(value string, runAttempt int) bool {
	return regexp.MustCompile(`^run-[1-9][0-9]*-attempt-` + strconv.Itoa(runAttempt) + `$`).MatchString(value)
}
