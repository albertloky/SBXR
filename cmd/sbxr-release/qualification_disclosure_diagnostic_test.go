package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDisclosureDiagnosticAdmissionCannotQualifyOrPublish(t *testing.T) {
	binary := buildReleaseTestBinary(t)
	boundary, _, evidence := mvpQualificationFixtureForSupport(t, binary, false, true, true)
	var bf qualificationBoundaryFacts
	var vf candidateDraftVerificationFacts
	var cf candidateDraftConstructionFacts
	var pre qualificationFacts
	if !decodeCanonical([]byte(boundary), &bf) || !decodeCanonical(bf.DraftVerificationFacts, &vf) || !decodeCanonical(vf.ConstructionFacts, &cf) || !decodeCanonical(cf.PreflightFacts, &pre) {
		t.Fatal("fixture chain")
	}
	a := bf.V3Attempt
	started, _ := qualificationTime(a.StartedAt)
	a.Diagnostic = &disclosureDiagnostic{StartUnix: started.Unix(), TestUntilUnix: started.Unix() + 7200, FinishUnix: started.Unix() + 10800}
	a.RequiredScenarios = []string{"mvp-install"}
	manifest, err := evaluateQualificationBoundary(bf)
	if err != nil {
		t.Fatalf("diagnostic boundary: %v", err)
	}
	if !validStableFailureManifest(manifest) {
		t.Fatal("gateway cannot carry diagnostic manifest")
	}
	declaration := *a
	declaration.Baseline, declaration.CandidateIndex = nil, ""
	var output bytes.Buffer
	if err := runQualificationDeclaration(strings.NewReader(qualificationDocument(t, qualificationDeclarationFacts{Attempt: declaration, Preflight: pre})), &output); err != nil {
		t.Fatal(err)
	}
	encoded, _ := marshalCanonical(manifest)
	document := recurringResultFixture(t, qualificationDocument(t, bf), encoded, evidence)
	assertQualificationRefused(t, binary, document, "diagnostic cannot qualify even with complete five-journey evidence")
	var facts v3RecurringResultFacts
	if !decodeCanonical([]byte(document), &facts) {
		t.Fatal("result fixture")
	}
	if _, err := recurringManifest(facts); err == nil {
		t.Fatal("diagnostic result accepted")
	}
	if currentCleanPublication(manifest) || validPublicationHistory(manifest, pre.SubscriptionHistory) {
		t.Fatal("diagnostic publication eligibility")
	}
	if _, err := buildRecurringAcceptanceRecord(manifest, facts); err == nil {
		t.Fatal("diagnostic acceptance record")
	}

	for name, mutate := range map[string]func(*v3QualificationAttempt){
		"no cleanup reserve": func(a *v3QualificationAttempt) { a.Diagnostic.TestUntilUnix = a.Diagnostic.FinishUnix },
		"extended window":    func(a *v3QualificationAttempt) { a.Diagnostic.FinishUnix++ },
		"signed after test cutoff": func(a *v3QualificationAttempt) {
			a.Diagnostic.StartUnix -= 7200
			a.Diagnostic.TestUntilUnix -= 7200
			a.Diagnostic.FinishUnix -= 7200
		},
		"overflow": func(a *v3QualificationAttempt) {
			a.Diagnostic.StartUnix = 9223372036854775800
			a.Diagnostic.FinishUnix = -9223372036854765016
		},
		"subscription journey": func(a *v3QualificationAttempt) { a.RequiredScenarios = append(a.RequiredScenarios, "mvp-subscription") },
		"Karing wait":          func(a *v3QualificationAttempt) { a.KaringResponseLimitSeconds = 3600 },
		"profile":              func(a *v3QualificationAttempt) { a.ProxyProfile = "vless-vmess" },
		"missing package":      func(a *v3QualificationAttempt) { a.Packages.Karing = v3SoftwarePackage{} },
		"exception":            func(a *v3QualificationAttempt) { a.OwnerException = "waiver" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *a
			window := *a.Diagnostic
			copy.Diagnostic = &window
			mutate(&copy)
			if validV3AttemptDeclaredFields(copy, pre) {
				t.Fatal("unsafe diagnostic accepted")
			}
		})
	}
}
