package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// One approved correction of an operator's recorded facts, not a product-test
// waiver or permission to reuse any other failed workflow. The original failed
// release and burn are never candidates for publication through this stage.
const (
	live89CorrectionStage           = "live89-evidence-correction-result"
	live89CorrectionBase            = "1723e06aca91465dc687b0ac72f06a2e48f8974d"
	live89CorrectionTag             = "v3.1.90"
	live89CorrectionSequence uint64 = 168
	live89RuntimeTree               = "d1b3eddefcee885e636c6467b9c8ddbe9958592c0187a0b2fdd218013a28dc84"
	live89EvidenceSHA256            = "73e8c3930c796c899e039c5d31bf9783073b0b375496b9b2406cda6d7b4d3154"
	live89PriorRun                  = "https://github.com/albertloky/SBXR/actions/runs/37189061844"
)

type live89CorrectionReview struct {
	BaseCommit        string `json:"base_commit"`
	EvidenceSHA256    string `json:"evidence_sha256"`
	PolicyDiffSHA256  string `json:"policy_diff_sha256"`
	Reviewer          string `json:"reviewer"`
	RuntimeTreeSHA256 string `json:"runtime_tree_sha256"`
	TargetCommit      string `json:"target_commit"`
	TargetSequence    uint64 `json:"target_sequence"`
	TargetTag         string `json:"target_tag"`
}

func (r *live89CorrectionReview) valid(commit string) bool {
	return r != nil && r.BaseCommit == live89CorrectionBase && r.TargetCommit == commit && validCommit(commit) && commit != live89CorrectionBase && r.EvidenceSHA256 == live89EvidenceSHA256 && validSHA256(r.PolicyDiffSHA256) && r.Reviewer == "Codex source comparison; Owner-approved live89 recording correction" && r.RuntimeTreeSHA256 == live89RuntimeTree && r.TargetTag == live89CorrectionTag && r.TargetSequence == live89CorrectionSequence
}

func live89OriginalBurn() burnedIdentity {
	// Retain the actual published burn payload, including its actual recorded_at
	// field. It is audit history, not the time of the later Owner correction.
	return burnedIdentity{Commit: live89CorrectionBase, OriginalTag: "v3.1.89", QualificationRunURL: live89PriorRun, Reason: "post-sign-qualification-failure", RecordedAt: "2026-10-04T08:29:00Z", ReleaseIndexSHA256: "6563ba60d80bd4197eb7ac6b6ca5b207316f33f8f0162c7e4c9b2e0c9aefc240", Sequence: 167}
}

type live89Archive struct {
	Evidence []lateConfirmationEvidence `json:"evidence"`
}

type live89CorrectionFacts struct {
	ArchivedEvidence           []lateConfirmationEvidence `json:"archived_evidence"`
	ObservedAt                 string                     `json:"observed_at"`
	QualificationBoundaryFacts json.RawMessage            `json:"qualification_boundary_facts"`
	QualificationManifest      json.RawMessage            `json:"qualification_manifest"`
	ManifestAttested           bool                       `json:"qualification_manifest_attested"`
	Schema                     string                     `json:"schema"`
	Stage                      string                     `json:"stage"`
}

func live89CorrectionManifest(m qualificationManifest) bool {
	return m.Schema == "sbxr-qualification-manifest-v3" && m.Mode == "v3" && m.SourceState == "v3-subscription-clean" && len(m.Releases) == 1 && m.Releases[0].Tag == live89CorrectionTag && m.Releases[0].Sequence == live89CorrectionSequence && m.V3Attempt != nil && m.V3Attempt.Live89CorrectionReview.valid(m.Workflow.Commit)
}

func evaluateLive89Correction(document []byte) (acceptanceVPSResultDecision, error) {
	refused := func() (acceptanceVPSResultDecision, error) {
		return acceptanceVPSResultDecision{}, errors.New("live89 recording correction refused")
	}
	var facts live89CorrectionFacts
	var boundary qualificationBoundaryFacts
	if !decodeCanonical(document, &facts) || facts.Schema != qualificationFactsSchema || facts.Stage != live89CorrectionStage || !facts.ManifestAttested || recurringSecret(document) || !decodeCanonical(facts.QualificationBoundaryFacts, &boundary) {
		return refused()
	}
	m, err := evaluateQualificationBoundary(boundary)
	encoded, encodeErr := marshalCanonical(m)
	observed, timeOK := qualificationTime(facts.ObservedAt)
	if err != nil || encodeErr != nil || !bytes.Equal(encoded, facts.QualificationManifest) || !live89CorrectionManifest(m) || !timeOK {
		return refused()
	}
	started, _ := qualificationTime(m.V3Attempt.StartedAt)
	if observed.Before(started) || observed.Sub(started) > 30*time.Minute {
		return refused()
	}
	archive, archiveErr := marshalCanonical(live89Archive{Evidence: facts.ArchivedEvidence})
	if archiveErr != nil || documentSHA256(archive) != live89EvidenceSHA256 {
		return refused()
	}
	// Hash the actual archived text, including the failure, real response timing
	// and null callback. No caller approval flag or replaceable pin is accepted.
	retained := make(map[string][]byte, len(facts.ArchivedEvidence))
	for _, e := range facts.ArchivedEvidence {
		data := []byte(e.Content)
		if softwarelifecycle.ValidateUniqueJSON(data) != nil || !json.Valid(data) || recurringSecret(data) {
			return refused()
		}
		retained[e.Name] = data
	}
	var prefix v3RecurringResultFacts
	var failure v3ScenarioFailureFacts
	if !decodeCanonical(retained["m4-collector-facts.json"], &prefix) || !decodeCanonical(retained["m5-incomplete-failure-facts.json"], &failure) {
		return refused()
	}
	accepted, prefixErr := evaluateV3ScenarioResult(prefix, retained["m4-collector-facts.json"])
	failed, failureErr := evaluateV3ScenarioFailure(failure, retained["m5-incomplete-failure-facts.json"])
	acceptedBytes, _ := marshalCanonical(accepted)
	failedBytes, _ := marshalCanonical(failed)
	prior, priorErr := recurringManifest(prefix)
	if prefixErr != nil || failureErr != nil || priorErr != nil || !bytes.Equal(acceptedBytes, retained["m4-collector-decision.json"]) || !bytes.Equal(failedBytes, retained["m5-incomplete-failure-decision.json"]) || prior.Workflow.RunURL != live89PriorRun || prior.Workflow.Commit != live89CorrectionBase || len(prefix.DetailedEvidence.Scenarios) != 4 || !live89EnvironmentMatches(*m.V3Attempt, *prior.V3Attempt) {
		return refused()
	}
	body, bodyErr := buildRecurringAcceptanceRecord(m, v3RecurringResultFacts{EvaluationTime: facts.ObservedAt, DetailedEvidenceSHA256: live89EvidenceSHA256})
	if bodyErr != nil {
		return refused()
	}
	review, _ := marshalCanonical(m.V3Attempt.Live89CorrectionReview)
	disclosure := "Qualification evidence correction: Owner-approved live89 operator-recording correction\n" +
		"Correction policy: docs/adr/0029-live89-operator-recording-correction.md\n" +
		"Prior live evidence: " + live89PriorRun + "\n" +
		"Live evidence origin: All five journeys were performed with v3.1.89 / 167; accepted prior facts reused\n" +
		"Original qualification: Failed; v3.1.89 remains burned\n" +
		"Original cleanup notification: 2026-10-04T10:04:15.493836Z\n" +
		"Timely Owner reply (parent-reported approximate): 2026-10-04T10:08:51Z\n" +
		"Operator first read: 2026-10-04T10:08:59Z\n" +
		"Original short cleanup deadline: 2026-10-04T10:09:15.493836Z\n" +
		"Owner correction recorded at: 2026-10-04T10:15:18.740923+00:00\n" +
		"Original response callback: Not recorded; original unsealed removal record retained\n" +
		"Fresh live scenarios: Not performed\n" +
		"Fresh native verification: Normal amd64/arm64 candidate checks; distinct from prior live facts\n" +
		"Product payload: Exact archived executable bytes before release identity trailer; new trailer/archive/index bytes differ\n" +
		"Archival evidence SHA-256: " + live89EvidenceSHA256 + "\n" +
		"Applicability review: " + string(review) + "\n" +
		"Removal evidence format: Accepted archival bundle with Owner correction; no fabricated successful scenario JSON\n"
	for _, scenario := range prefix.DetailedEvidence.Scenarios {
		b, _ := marshalCanonical(scenario)
		disclosure += "Scenario: " + scenario.ScenarioID + " " + documentSHA256(b) + " " + m.Workflow.RunURL + "#artifacts\n"
	}
	disclosure += "Scenario: mvp-removal " + live89EvidenceSHA256 + " " + m.Workflow.RunURL + "#artifacts\n"
	body = strings.Replace(body, "```json\n", disclosure+"```json\n", 1)
	return acceptanceVPSResultDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: documentSHA256(encoded), Records: []acceptanceRecord{{Body: body, Tag: m.Releases[0].Tag}}, Schema: qualificationDecisionSchema, Stage: live89CorrectionStage}, nil
}

func live89EnvironmentMatches(a, p v3QualificationAttempt) bool {
	return a.Packages == p.Packages && a.AfterSnapRefresh == p.AfterSnapRefresh && a.ProxyPackage == p.ProxyPackage && a.Runner == p.Runner && a.MacOSVersion == p.MacOSVersion && a.MacRunnerID == p.MacRunnerID && a.OutsideRunnerID == p.OutsideRunnerID && a.VPSID == p.VPSID && a.VPSIdentitySHA256 == p.VPSIdentitySHA256 && a.KaringLatestCheckedAt == p.KaringLatestCheckedAt
}
