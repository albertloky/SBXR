package main

import "testing"

func automaticPublicationFixture(t *testing.T, binary string, pre map[string]any) map[string]any {
	t.Helper()
	f := mainReviewPublicationFixture(t, binary, pre)
	a := f["approval"].(map[string]any)
	a["state"], a["environments"] = "automatic", []any{}
	return f
}

func TestQualifiedPublicationNeedsNoSecondHumanApproval(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	f := automaticPublicationFixture(t, binary, mainReviewPreflightFixture(t, binary))
	out, err := runQualificationCommand(binary, qualificationDocument(t, f))
	if err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("qualified automatic publication: %v %s", err, out)
	}
	delete(f["approval"].(map[string]any), "decision_chain")
	out, err = runQualificationCommand(binary, qualificationDocument(t, f))
	if err != nil || jsonObject(t, out)["outcome"] != "pending-review" {
		t.Fatalf("automatic publication lost exact evidence binding: %v %s", err, out)
	}
}

func TestQualifiedPublicationRetryAfterMetadataWasPublished(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	pre := mainReviewPreflightFixture(t, binary)
	// An interrupted publisher already changed flags. The files and successful
	// Acceptance Record are still exactly those qualified by the original run.
	r := pre["releases"].([]any)[0].(map[string]any)
	r["draft"], r["immutable"] = false, true
	f := automaticPublicationFixture(t, binary, pre)
	o := f["observation"].(map[string]any)
	o["draft"], o["immutable"] = false, true
	out, err := runQualificationCommand(binary, qualificationDocument(t, f))
	if err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("partial publication retry: %v %s", err, out)
	}
	o["body"] = "unproved replacement record"
	assertQualificationRefused(t, binary, qualificationDocument(t, f), "retry cannot replace qualification")
}

func TestQualifiedPublicationSurvivesUnrelatedLaterBurn(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	pre := mainReviewPreflightFixture(t, binary)
	release := pre["releases"].([]any)[0].(map[string]any)
	burn := burnedIdentity{Commit: release["commit"].(string), OriginalTag: "v3.1.99", QualificationRunURL: failedRunURL("901"), Reason: "owner-abandoned", RecordedAt: "2026-09-02T00:00:00Z", ReleaseIndexSHA256: release["release_identity"].(decisionReleaseIdentity).ReleaseIndexSHA256, Sequence: 177}
	pre["burned_identities"] = []burnedIdentity{burn}
	out, err := runQualificationCommand(binary, qualificationDocument(t, pre))
	if err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("unrelated burn consumed qualified candidate: %v %s", err, out)
	}
	burn.OriginalTag = release["tag"].(string)
	pre["burned_identities"] = []burnedIdentity{burn}
	assertQualificationRefused(t, binary, qualificationDocument(t, pre), "own burn still requires authenticated recovery")
}
