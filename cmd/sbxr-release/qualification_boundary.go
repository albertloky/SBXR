package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type approvalEnvironment struct {
	Name string `json:"name"`
}

type qualificationApproval struct {
	DecisionChain []decisionChainEntry  `json:"decision_chain,omitempty"`
	Environments  []approvalEnvironment `json:"environments"`
	State         string                `json:"state"`
}

type qualificationWorkflow struct {
	Commit string `json:"commit"`
	Path   string `json:"path"`
	Ref    string `json:"ref"`
	RunID  string `json:"run_id"`
	RunURL string `json:"run_url"`
}

type nativeEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type qualificationBoundaryFacts struct {
	Approval                    qualificationApproval   `json:"approval"`
	CandidateFailureStateSHA256 string                  `json:"candidate_failure_state_sha256"`
	ChecklistSHA256             string                  `json:"checklist_sha256"`
	DraftVerificationDecision   json.RawMessage         `json:"draft_verification_decision"`
	DraftVerificationFacts      json.RawMessage         `json:"draft_verification_facts"`
	NativeEvidence              []nativeEvidence        `json:"native_evidence"`
	PriorDecisionSHA256         string                  `json:"prior_decision_sha256"`
	Releases                    []verifiedDraftRelease  `json:"releases"`
	Rescue                      *qualificationRescue    `json:"rescue"`
	Schema                      string                  `json:"schema"`
	SourceState                 string                  `json:"source_state"`
	Stage                       string                  `json:"stage"`
	V3Attempt                   *v3QualificationAttempt `json:"v3_attempt,omitempty"`
	Workflow                    qualificationWorkflow   `json:"workflow"`
}

type decisionChainEntry struct {
	DecisionSHA256 string `json:"decision_sha256"`
	FactsSHA256    string `json:"facts_sha256"`
	Outcome        string `json:"outcome"`
	Stage          string `json:"stage"`
}

type qualificationRescue struct {
	DefectIssueURL    string `json:"defect_issue_url"`
	FailedNormalRunID string `json:"failed_normal_run_id"`
}

type qualificationManifest struct {
	AcceptanceVPSChecklistSHA256 string                  `json:"acceptance_vps_checklist_sha256"`
	Approval                     qualificationApproval   `json:"approval"`
	CandidateFailureStateSHA256  string                  `json:"candidate_failure_state_sha256"`
	Mode                         string                  `json:"mode"`
	NativeEvidence               []nativeEvidence        `json:"native_evidence"`
	PinnedActions                []string                `json:"pinned_actions"`
	Releases                     []qualificationRelease  `json:"releases"`
	Repository                   string                  `json:"repository"`
	Rescue                       *qualificationRescue    `json:"rescue"`
	Schema                       string                  `json:"schema"`
	SourceState                  string                  `json:"source_state"`
	V3Attempt                    *v3QualificationAttempt `json:"v3_attempt,omitempty"`
	Workflow                     qualificationWorkflow   `json:"workflow"`
}

type qualificationRelease struct {
	Assets          []decisionAsset         `json:"assets"`
	Commit          string                  `json:"commit"`
	ReleaseID       int64                   `json:"release_id"`
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
	Tag             string                  `json:"tag"`
}

func evaluateQualificationBoundary(facts qualificationBoundaryFacts) (qualificationManifest, error) {
	refused := func() (qualificationManifest, error) {
		return qualificationManifest{}, errors.New("qualification boundary refused")
	}
	if facts.Schema != qualificationFactsSchema || facts.Stage != qualificationBoundaryStage || facts.Approval.State != "approved" || len(facts.Approval.Environments) != 1 || facts.Approval.Environments[0].Name != "acceptance-vps" || !validSHA256(facts.CandidateFailureStateSHA256) || !validSHA256(facts.ChecklistSHA256) || !validSHA256(facts.PriorDecisionSHA256) || facts.NativeEvidence == nil || facts.Releases == nil {
		return refused()
	}
	var verificationFacts candidateDraftVerificationFacts
	if !decodeCanonical(facts.DraftVerificationFacts, &verificationFacts) {
		return refused()
	}
	verification, err := evaluateCandidateDraftVerification(verificationFacts, facts.DraftVerificationFacts)
	if err != nil {
		return refused()
	}
	verificationBytes, err := marshalCanonical(verification)
	if err != nil || !bytes.Equal(verificationBytes, facts.DraftVerificationDecision) || facts.PriorDecisionSHA256 != documentSHA256(facts.DraftVerificationDecision) {
		return refused()
	}
	var constructionFacts candidateDraftConstructionFacts
	if !decodeCanonical(verificationFacts.ConstructionFacts, &constructionFacts) {
		return refused()
	}
	construction, err := evaluateCandidateDraftConstruction(constructionFacts, verificationFacts.ConstructionFacts)
	if err != nil {
		return refused()
	}
	var preflightFacts qualificationFacts
	if !decodeCanonical(constructionFacts.PreflightFacts, &preflightFacts) || facts.ChecklistSHA256 != preflightFacts.ChecklistSHA256 {
		return refused()
	}
	preflight, err := verifiedPreflightDecision(constructionFacts.PreflightFacts, constructionFacts.PreflightDecision)
	if err != nil {
		return refused()
	}
	releases := append([]verifiedDraftRelease(nil), verification.VerifiedReleases...)
	for _, raw := range preflight.Actions {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &kind) != nil {
			return refused()
		}
		if kind.Type == "use-source-release" {
			var source useSourceReleaseAction
			if !decodeCanonical(raw, &source) {
				return refused()
			}
			releases = append([]verifiedDraftRelease{{Assets: source.Assets, Commit: source.Commit, Draft: source.Draft, Immutable: source.Immutable, Prerelease: source.Prerelease, ReleaseID: source.ReleaseID, ReleaseIdentity: source.ReleaseIdentity, Sequence: source.Sequence, Tag: source.Tag}}, releases...)
		}
	}
	expectedReleases := 2
	if preflightFacts.Candidate.Mode == "v3" {
		expectedReleases = 1
	}
	if len(releases) != expectedReleases || facts.Workflow.Path != ".github/workflows/candidate.yml" || facts.Workflow.Ref != softwarelifecycle.Repository+"/.github/workflows/candidate.yml@refs/heads/main" || facts.Workflow.Commit != releases[len(releases)-1].Commit || !validCommit(facts.Workflow.Commit) {
		return refused()
	}
	runID, runErr := strconv.ParseUint(facts.Workflow.RunID, 10, 64)
	if runErr != nil || runID == 0 || facts.Workflow.RunURL != "https://github.com/"+softwarelifecycle.Repository+"/actions/runs/"+facts.Workflow.RunID || !validNativeEvidence(facts.NativeEvidence, construction.Actions) {
		return refused()
	}
	var rescue *qualificationRescue
	if preflight.SourceState == "rescue" {
		if preflightFacts.Candidate.DefectIssueURL == nil || preflightFacts.Candidate.FailedNormalRunID == nil {
			return refused()
		}
		rescue = &qualificationRescue{DefectIssueURL: *preflightFacts.Candidate.DefectIssueURL, FailedNormalRunID: *preflightFacts.Candidate.FailedNormalRunID}
	}
	if facts.SourceState != preflight.SourceState || !reflect.DeepEqual(facts.Releases, releases) || (facts.Rescue == nil) != (rescue == nil) || facts.Rescue != nil && *facts.Rescue != *rescue {
		return refused()
	}
	chain := []decisionChainEntry{
		{DecisionSHA256: documentSHA256(constructionFacts.PreflightDecision), FactsSHA256: documentSHA256(constructionFacts.PreflightFacts), Outcome: preflight.Outcome, Stage: preflight.Stage},
		{DecisionSHA256: documentSHA256(verificationFacts.ConstructionDecision), FactsSHA256: documentSHA256(verificationFacts.ConstructionFacts), Outcome: construction.Outcome, Stage: construction.Stage},
		{DecisionSHA256: documentSHA256(facts.DraftVerificationDecision), FactsSHA256: documentSHA256(facts.DraftVerificationFacts), Outcome: verification.Outcome, Stage: verification.Stage},
	}
	manifestReleases := make([]qualificationRelease, len(releases))
	for index, release := range releases {
		manifestReleases[index] = qualificationRelease{Assets: release.Assets, Commit: release.Commit, ReleaseID: release.ReleaseID, ReleaseIdentity: release.ReleaseIdentity, Sequence: release.Sequence, Tag: release.Tag}
	}
	approval := facts.Approval
	approval.DecisionChain = chain
	manifestSchema := "sbxr-qualification-manifest-v1"
	if preflight.SourceState == "v3-recurring" || preflight.SourceState == "v3-subscription-clean" {
		if facts.V3Attempt == nil || !validV3Attempt(*facts.V3Attempt, preflightFacts, facts.Workflow) {
			return refused()
		}
		manifestSchema = "sbxr-qualification-manifest-v2"
		if preflightFacts.Candidate.EvidenceVersion == 3 {
			if !validAttemptIndex(*facts.V3Attempt, manifestReleases[0]) {
				return refused()
			}
			manifestSchema = "sbxr-qualification-manifest-v3"
		}
	} else if facts.V3Attempt != nil {
		return refused()
	}
	return qualificationManifest{
		AcceptanceVPSChecklistSHA256: facts.ChecklistSHA256, Approval: approval, CandidateFailureStateSHA256: facts.CandidateFailureStateSHA256,
		Mode: preflightFacts.Candidate.Mode, NativeEvidence: facts.NativeEvidence, PinnedActions: []string{"actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803", "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16", "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093", "actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661"},
		Releases: manifestReleases, Repository: softwarelifecycle.Repository, Rescue: rescue, Schema: manifestSchema, SourceState: preflight.SourceState, V3Attempt: facts.V3Attempt, Workflow: facts.Workflow,
	}, nil
}

func validNativeEvidence(evidence []nativeEvidence, actions []constructDraftAction) bool {
	expected := make([]string, 0, len(actions)*2)
	for _, action := range actions {
		for _, architecture := range []string{"amd64", "arm64"} {
			expected = append(expected, "native/native-"+action.Tag+"-"+architecture+"/evidence/native-"+architecture+".json")
		}
	}
	if len(evidence) != len(expected) {
		return false
	}
	for index, item := range evidence {
		if item.Path != expected[index] || !validSHA256(item.SHA256) {
			return false
		}
	}
	return true
}
