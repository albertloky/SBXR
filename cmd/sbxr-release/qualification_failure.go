package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type stableFinalizationRun struct {
	CreatedAt string `json:"created_at"`
	HeadSHA   string `json:"head_sha"`
	ID        string `json:"id"`
	Path      string `json:"path"`
	URL       string `json:"url"`
}

type stableFailureObservation struct {
	Assets           []decisionAsset         `json:"assets"`
	Body             string                  `json:"body"`
	Commit           string                  `json:"commit"`
	Draft            bool                    `json:"draft"`
	Immutable        bool                    `json:"immutable"`
	Prerelease       bool                    `json:"prerelease"`
	PubliclyVerified bool                    `json:"publicly_verified"`
	ReleaseID        int64                   `json:"release_id"`
	ReleaseIdentity  decisionReleaseIdentity `json:"release_identity"`
	ReleasePresent   bool                    `json:"release_present"`
	Sequence         uint64                  `json:"sequence"`
	Tag              string                  `json:"tag"`
	TagCommit        *string                 `json:"tag_commit"`
}

type stableFailureFacts struct {
	BurnedIdentities        []burnedIdentity           `json:"burned_identities"`
	CandidateCommitAncestor bool                       `json:"candidate_commit_ancestor"`
	CandidateRun            stableCandidateRun         `json:"candidate_run"`
	FinalizationRun         stableFinalizationRun      `json:"finalization_run"`
	ManifestAttested        bool                       `json:"manifest_attested"`
	Observations            []stableFailureObservation `json:"observations"`
	ObservedAt              string                     `json:"observed_at"`
	Operation               string                     `json:"operation"`
	PublicationStage        string                     `json:"publication_stage"`
	Schema                  string                     `json:"schema"`
	SignedManifest          json.RawMessage            `json:"signed_manifest"`
	Stage                   string                     `json:"stage"`
}

type finalizeStableFailureAction struct {
	Assets                  []decisionAsset         `json:"assets"`
	Body                    string                  `json:"body"`
	Burn                    burnedIdentity          `json:"burn"`
	BurnRequired            bool                    `json:"burn_required"`
	Commit                  string                  `json:"commit"`
	DeleteRelease           bool                    `json:"delete_release"`
	DeleteTag               bool                    `json:"delete_tag"`
	FactsSHA256             string                  `json:"facts_sha256"`
	ObservedAt              string                  `json:"observed_at"`
	PriorDecisionSHA256     string                  `json:"prior_decision_sha256"`
	PublishFailedPrerelease bool                    `json:"publish_failed_prerelease"`
	Reason                  string                  `json:"reason"`
	ReleaseID               int64                   `json:"release_id"`
	ReleaseIdentity         decisionReleaseIdentity `json:"release_identity"`
	Sequence                uint64                  `json:"sequence"`
	Tag                     string                  `json:"tag"`
	Type                    string                  `json:"type"`
}

type stableFailureDecision struct {
	Actions             []finalizeStableFailureAction `json:"actions"`
	FactsSHA256         string                        `json:"facts_sha256"`
	Outcome             string                        `json:"outcome"`
	PriorDecisionSHA256 string                        `json:"prior_decision_sha256"`
	Reason              string                        `json:"reason"`
	Schema              string                        `json:"schema"`
	Stage               string                        `json:"stage"`
}

type stableFailureVerificationFacts struct {
	BurnedIdentities []burnedIdentity           `json:"burned_identities"`
	FailureDecision  json.RawMessage            `json:"failure_decision"`
	FailureFacts     json.RawMessage            `json:"failure_facts"`
	Observations     []stableFailureObservation `json:"observations"`
	Schema           string                     `json:"schema"`
	Stage            string                     `json:"stage"`
}

type stableFailureVerificationDecision struct {
	Actions             []json.RawMessage `json:"actions"`
	FactsSHA256         string            `json:"facts_sha256"`
	Outcome             string            `json:"outcome"`
	PriorDecisionSHA256 string            `json:"prior_decision_sha256"`
	Schema              string            `json:"schema"`
	Stage               string            `json:"stage"`
}

type candidateFailureStages struct {
	CodexLiveAcceptance    string `json:"codex_live_acceptance"`
	IntegratedVerification string `json:"integrated_verification"`
}

type candidateFailureState struct {
	Evidence    []string                 `json:"evidence"`
	RecordedAt  string                   `json:"recorded_at"`
	Runner      string                   `json:"runner"`
	Schema      string                   `json:"schema"`
	Software    acceptanceRecordSoftware `json:"software"`
	Stages      candidateFailureStages   `json:"stages"`
	WorkflowRun string                   `json:"workflow_run"`
}

type candidateFailureObservation struct {
	Assets           []decisionAsset         `json:"assets"`
	Body             string                  `json:"body"`
	Commit           string                  `json:"commit"`
	CreatedReleaseID int64                   `json:"created_release_id"`
	Draft            bool                    `json:"draft"`
	Immutable        bool                    `json:"immutable"`
	Prerelease       bool                    `json:"prerelease"`
	ReleaseID        int64                   `json:"release_id"`
	ReleaseIdentity  decisionReleaseIdentity `json:"release_identity"`
	ReleasePresent   bool                    `json:"release_present"`
	Sequence         uint64                  `json:"sequence"`
	Tag              string                  `json:"tag"`
	TagCommit        *string                 `json:"tag_commit"`
}

type candidateFailureFacts struct {
	BurnedIdentities           []burnedIdentity              `json:"burned_identities"`
	CandidateFailureState      *candidateFailureState        `json:"candidate_failure_state"`
	ConstructionDecision       json.RawMessage               `json:"construction_decision"`
	ConstructionFacts          json.RawMessage               `json:"construction_facts"`
	Observations               []candidateFailureObservation `json:"observations"`
	ObservedAt                 string                        `json:"observed_at"`
	PriorDecisionSHA256        string                        `json:"prior_decision_sha256"`
	QualificationBoundaryFacts json.RawMessage               `json:"qualification_boundary_facts"`
	QualificationManifest      json.RawMessage               `json:"qualification_manifest"`
	Reason                     string                        `json:"reason"`
	Schema                     string                        `json:"schema"`
	Stage                      string                        `json:"stage"`
	Workflow                   qualificationWorkflow         `json:"workflow"`
}

type cleanupDraftAction struct {
	Commit              string `json:"commit"`
	DeleteRelease       bool   `json:"delete_release"`
	DeleteTag           bool   `json:"delete_tag"`
	FactsSHA256         string `json:"facts_sha256"`
	PriorDecisionSHA256 string `json:"prior_decision_sha256"`
	ReleaseID           int64  `json:"release_id"`
	Tag                 string `json:"tag"`
	Type                string `json:"type"`
}

type finalizeFailedReleaseAction struct {
	Body                string         `json:"body"`
	Burn                burnedIdentity `json:"burn"`
	BurnRequired        bool           `json:"burn_required"`
	Commit              string         `json:"commit"`
	FactsSHA256         string         `json:"facts_sha256"`
	PriorDecisionSHA256 string         `json:"prior_decision_sha256"`
	ReleaseID           int64          `json:"release_id"`
	Tag                 string         `json:"tag"`
	Type                string         `json:"type"`
}

type candidateFailureDecision struct {
	Actions             []json.RawMessage `json:"actions"`
	FactsSHA256         string            `json:"facts_sha256"`
	Outcome             string            `json:"outcome"`
	PriorDecisionSHA256 string            `json:"prior_decision_sha256"`
	Schema              string            `json:"schema"`
	Stage               string            `json:"stage"`
}

type candidateFailureVerificationFacts struct {
	BurnedIdentities []burnedIdentity              `json:"burned_identities"`
	FailureDecision  json.RawMessage               `json:"failure_decision"`
	FailureFacts     json.RawMessage               `json:"failure_facts"`
	Observations     []candidateFailureObservation `json:"observations"`
	Schema           string                        `json:"schema"`
	Stage            string                        `json:"stage"`
}

type candidateFailureVerificationDecision struct {
	Actions             []json.RawMessage `json:"actions"`
	FactsSHA256         string            `json:"facts_sha256"`
	Outcome             string            `json:"outcome"`
	PriorDecisionSHA256 string            `json:"prior_decision_sha256"`
	Schema              string            `json:"schema"`
	Stage               string            `json:"stage"`
}

func evaluateStableFailure(facts stableFailureFacts, document []byte) (stableFailureDecision, error) {
	refused := func() (stableFailureDecision, error) {
		return stableFailureDecision{}, errors.New("stable failure finalization refused")
	}
	observedAt, observedErr := time.Parse(time.RFC3339, facts.ObservedAt)
	createdAt, createdErr := time.Parse(time.RFC3339, facts.CandidateRun.CreatedAt)
	finalizationAt, finalizationErr := time.Parse(time.RFC3339, facts.FinalizationRun.CreatedAt)
	var manifest qualificationManifest
	if facts.Schema != qualificationFactsSchema || facts.Stage != stableFailureStage || !facts.ManifestAttested || facts.Observations == nil || facts.BurnedIdentities == nil || secretBearing(document) || observedErr != nil || createdErr != nil || finalizationErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || finalizationAt.Format(time.RFC3339) != facts.FinalizationRun.CreatedAt || observedAt.Before(finalizationAt) || observedAt.Before(createdAt) || !validFailureBurns(facts.BurnedIdentities) || !decodeCanonical(facts.SignedManifest, &manifest) || !validStableFailureManifest(manifest) {
		return refused()
	}
	if !facts.CandidateCommitAncestor || facts.CandidateRun != (stableCandidateRun{Conclusion: "success", CreatedAt: facts.CandidateRun.CreatedAt, Event: "workflow_dispatch", HeadSHA: manifest.Workflow.Commit, ID: manifest.Workflow.RunID, Path: manifest.Workflow.Path}) || !validStableFinalizationRun(facts.FinalizationRun) || len(facts.Observations) != len(manifest.Releases) {
		return refused()
	}
	for index := range manifest.Releases {
		if !stableFailureTargetMatches(facts.Observations[index], manifest.Releases[index]) {
			return refused()
		}
	}
	if facts.PublicationStage == "complete" {
		return refused()
	}
	reason := facts.PublicationStage
	if reason == "prepublication" {
		reason = "prepublication-failure"
	}
	if facts.Operation == "abandon" {
		reason = "owner-abandoned"
	} else if facts.Operation != "publish" {
		return refused()
	} else if observedAt.Sub(createdAt) >= 90*24*time.Hour {
		reason = "qualification-expired"
	}
	aProven := manifest.SourceState == "initial-normal" && stableFailureObservationIsQualified(facts.Observations[0], manifest.Releases[0], manifest, facts.FinalizationRun.URL)
	if manifest.SourceState == "initial-normal" && facts.Observations[0].ReleasePresent && !facts.Observations[0].Draft && facts.Observations[0].Immutable && !facts.Observations[0].Prerelease && !aProven && reason != "initial-a-public-verification-failure" {
		return refused()
	}
	if (reason == "prepublication-failure" || reason == "initial-a-public-verification-failure") && aProven {
		reason = "b-publication-or-verification-failure"
	}
	if reason != "prepublication-failure" && reason != "initial-a-public-verification-failure" && reason != "b-publication-or-verification-failure" && reason != "stable-no-update-failure" && !(reason == "v3-finalization-failure" && manifest.Mode == "v3") && reason != "qualification-expired" && reason != "owner-abandoned" {
		return refused()
	}
	indexes := []int{len(manifest.Releases) - 1}
	if manifest.SourceState == "initial-normal" && !aProven && reason != "b-publication-or-verification-failure" && reason != "stable-no-update-failure" {
		indexes = []int{0, 1}
	}
	outcome := "withdraw"
	if reason == "prepublication-failure" {
		outcome = "failed-prerelease"
	}
	factsSHA256, priorDecisionSHA256 := documentSHA256(document), documentSHA256(facts.SignedManifest)
	actions := make([]finalizeStableFailureAction, len(indexes))
	for actionIndex, releaseIndex := range indexes {
		release, observation := manifest.Releases[releaseIndex], facts.Observations[releaseIndex]
		burn := stableFailureBurn(facts.BurnedIdentities, burnedIdentity{Commit: release.Commit, OriginalTag: release.Tag, QualificationRunURL: manifest.Workflow.RunURL, Reason: reason, RecordedAt: facts.ObservedAt, ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Sequence: release.Sequence})
		burnRequired, exact := burnRequirement(facts.BurnedIdentities, burn)
		if !exact {
			return refused()
		}
		body := ""
		publishFailedPrerelease := false
		if outcome == "failed-prerelease" {
			var err error
			body, err = buildStableFailedAcceptanceRecord(manifest, release, observation.Body, facts.FinalizationRun.URL)
			if err != nil {
				return refused()
			}
			publishFailedPrerelease = observation.ReleasePresent && observation.Draft && !observation.Immutable && !observation.Prerelease
			if observation.ReleasePresent && !publishFailedPrerelease && (!observation.Immutable || !observation.Prerelease || observation.Draft || observation.Body != body) {
				return refused()
			}
		}
		actions[actionIndex] = finalizeStableFailureAction{Assets: release.Assets, Body: body, Burn: burn, BurnRequired: burnRequired, Commit: release.Commit, DeleteRelease: outcome == "withdraw" && observation.ReleasePresent, DeleteTag: outcome == "withdraw" && observation.TagCommit != nil, FactsSHA256: factsSHA256, ObservedAt: facts.ObservedAt, PriorDecisionSHA256: priorDecisionSHA256, PublishFailedPrerelease: publishFailedPrerelease, Reason: reason, ReleaseID: release.ReleaseID, ReleaseIdentity: release.ReleaseIdentity, Sequence: release.Sequence, Tag: release.Tag, Type: "finalize-stable-failure"}
	}
	return stableFailureDecision{Actions: actions, FactsSHA256: factsSHA256, Outcome: outcome, PriorDecisionSHA256: priorDecisionSHA256, Reason: reason, Schema: qualificationDecisionSchema, Stage: stableFailureStage}, nil
}

func stableFailureBurn(existing []burnedIdentity, wanted burnedIdentity) burnedIdentity {
	for _, burn := range existing {
		if burn.OriginalTag == wanted.OriginalTag || burn.Sequence == wanted.Sequence {
			candidate := wanted
			candidate.RecordedAt = burn.RecordedAt
			if burn == candidate {
				return burn
			}
		}
	}
	return wanted
}

func validStableFailureManifest(manifest qualificationManifest) bool {
	if manifest.V3Attempt != nil && manifest.V3Attempt.OwnerException != "" && !ownerExceptionManifest(manifest) {
		return false
	}
	recurring := manifest.Schema == "sbxr-qualification-manifest-v2" && manifest.Mode == "v3" && manifest.SourceState == "v3-recurring" && manifest.V3Attempt != nil && len(manifest.V3Attempt.Sources) > 0 && slices.Equal(manifest.V3Attempt.RequiredScenarios, requiredV3Scenarios(manifest.V3Attempt.Sources))
	scoped := manifest.Schema == "sbxr-qualification-manifest-v3" && manifest.Mode == "v3" && manifest.V3Attempt != nil && attemptVersion(manifest.V3Attempt) == "v3" && manifest.V3Attempt.Baseline != nil && validAttemptSupport(*manifest.V3Attempt) && len(manifest.Releases) == 1 && validAttemptIndex(*manifest.V3Attempt, manifest.Releases[0]) && ((manifest.SourceState == "v3-subscription-clean" && cleanInstallScope(manifest.V3Attempt.Support.Scope)) || (manifest.SourceState == "v3-recurring" && manifest.V3Attempt.Support.Scope == softwarelifecycle.RecurringSubscriptionUpgrade))
	v3 := manifest.Mode == "v3" && (manifest.SourceState == "v3-clean" || recurring || scoped) && len(manifest.Releases) == 1
	legacy := (manifest.Mode == "normal" || manifest.Mode == "rescue") && (manifest.SourceState == "initial-normal" || manifest.SourceState == "later-normal" || manifest.SourceState == "rescue") && len(manifest.Releases) == 2
	if !recurring && !scoped && (manifest.Schema != "sbxr-qualification-manifest-v1" || manifest.V3Attempt != nil) || manifest.Repository != softwarelifecycle.Repository || !validSHA256(manifest.AcceptanceVPSChecklistSHA256) || !validSHA256(manifest.CandidateFailureStateSHA256) || manifest.Approval.State != "approved" || len(manifest.Approval.Environments) != 1 || manifest.Approval.Environments[0].Name != "acceptance-vps" || !v3 && !legacy || len(manifest.Approval.DecisionChain) != 3 || (manifest.Mode == "rescue") != (manifest.SourceState == "rescue") || (manifest.Rescue != nil) != (manifest.SourceState == "rescue") || manifest.Workflow.Path != ".github/workflows/candidate.yml" || manifest.Workflow.Ref != softwarelifecycle.Repository+"/.github/workflows/candidate.yml@refs/heads/main" || !validCommit(manifest.Workflow.Commit) || manifest.Workflow.RunURL != failedRunURL(manifest.Workflow.RunID) {
		return false
	}
	expectedStages := []string{candidatePreflightStage, candidateDraftConstructionStage, candidateDraftVerificationStage}
	for index, entry := range manifest.Approval.DecisionChain {
		if entry.Stage != expectedStages[index] || !validSHA256(entry.DecisionSHA256) || !validSHA256(entry.FactsSHA256) || entry.Outcome != "accepted" && entry.Outcome != "actions-required" {
			return false
		}
	}
	for index, release := range manifest.Releases {
		if release.ReleaseID <= 0 || release.Sequence == 0 || (manifest.Mode == "v3" || index != 0 || manifest.SourceState == "initial-normal") && release.Commit != manifest.Workflow.Commit || release.ReleaseIdentity != (decisionReleaseIdentity{Commit: release.Commit, ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Repository: softwarelifecycle.Repository, Tag: release.Tag}) || !validSHA256(release.ReleaseIdentity.ReleaseIndexSHA256) || !validTag(release.Tag) || len(release.Assets) != 4 {
			return false
		}
		for index, asset := range release.Assets {
			if asset.Name != softwarelifecycle.LatestReleaseAssetNames()[index] || !validSHA256(asset.SHA256) || asset.Size <= 0 {
				return false
			}
		}
	}
	return v3 || manifest.Releases[0].Sequence < manifest.Releases[1].Sequence && manifest.Releases[0].Tag != manifest.Releases[1].Tag && manifest.Releases[0].ReleaseID != manifest.Releases[1].ReleaseID
}

func validStableFinalizationRun(run stableFinalizationRun) bool {
	id, err := strconv.ParseUint(run.ID, 10, 64)
	return err == nil && id > 0 && validCommit(run.HeadSHA) && run.Path == ".github/workflows/stable.yml" && run.URL == failedRunURL(run.ID)
}

func stableFailureTargetMatches(observation stableFailureObservation, release qualificationRelease) bool {
	if observation.Commit != release.Commit || observation.ReleaseID != release.ReleaseID || observation.ReleaseIdentity != release.ReleaseIdentity || observation.Sequence != release.Sequence || observation.Tag != release.Tag || observation.TagCommit != nil && *observation.TagCommit != release.Commit {
		return false
	}
	if !observation.ReleasePresent {
		return len(observation.Assets) == 0 && observation.Body == "" && !observation.Draft && !observation.Immutable && !observation.Prerelease && !observation.PubliclyVerified
	}
	return reflect.DeepEqual(observation.Assets, release.Assets) && (!observation.PubliclyVerified || !observation.Draft && observation.Immutable && !observation.Prerelease && observation.TagCommit != nil)
}

func stableFailureObservationIsQualified(observation stableFailureObservation, release qualificationRelease, manifest qualificationManifest, workflowRun string) bool {
	if !observation.PubliclyVerified || !observation.ReleasePresent || observation.Draft || !observation.Immutable || observation.Prerelease || observation.TagCommit == nil || !(strings.Contains(observation.Body, "Status: Qualified\n") || ownerExceptionManifest(manifest) && strings.Contains(observation.Body, "Status: Qualified by Owner exception\n")) {
		return false
	}
	_, err := buildStableFailedAcceptanceRecord(manifest, release, observation.Body, workflowRun)
	return err == nil
}

func buildStableFailedAcceptanceRecord(manifest qualificationManifest, release qualificationRelease, sourceBody, workflowRun string) (string, error) {
	start := strings.Index(sourceBody, "```json\n")
	end := strings.LastIndex(sourceBody, "\n```\n")
	if start < 0 || end <= start {
		return "", errors.New("qualified Acceptance Record refused")
	}
	recordBytes := []byte(sourceBody[start+8 : end])
	var source acceptanceRecordJSON
	wantedSecrets := "Passed"
	if ownerExceptionManifest(manifest) {
		wantedSecrets = softwarelifecycle.OwnerExceptionSecrets
	}
	if softwarelifecycle.ValidateUniqueJSON(recordBytes) != nil || json.Unmarshal(recordBytes, &source) != nil || (source.Schema != "sbxr-acceptance-record-v1" && !((source.Schema == "sbxr-acceptance-record-v2" || source.Schema == "sbxr-acceptance-record-v3" && manifest.Schema == "sbxr-qualification-manifest-v3") && manifest.V3Attempt != nil)) || source.ReleaseIdentity != release.ReleaseIdentity || source.Sequence != release.Sequence || !reflect.DeepEqual(source.Assets, release.Assets) || source.SecretSafeResult != wantedSecrets || source.Stages.ModuleVerification != "Passed" || source.Stages.SeamVerification != "Passed" {
		return "", errors.New("qualified Acceptance Record refused")
	}
	failedRetry := strings.Contains(sourceBody, "Status: Failed prerelease\n")
	if !failedRetry && !(strings.Contains(sourceBody, "Status: Qualified\n") || ownerExceptionManifest(manifest) && strings.Contains(sourceBody, "Status: Qualified by Owner exception\n")) {
		return "", errors.New("qualified Acceptance Record refused")
	}
	if failedRetry && (source.StableResultCode != "RELEASE-INSTALLER-UPDATER-PREPUBLICATION-FAILED" || source.WorkflowRun != workflowRun) || !failedRetry && source.WorkflowRun != manifest.Workflow.RunURL {
		return "", errors.New("qualified Acceptance Record refused")
	}
	if !failedRetry {
		var canonicalSource []byte
		var err error
		if source.StableResultCode == "RELEASE-V3-SUBSCRIPTION-QUALIFICATION" || source.StableResultCode == "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION" || source.StableResultCode == softwarelifecycle.OwnerExceptionCode && ownerExceptionManifest(manifest) {
			var recurring v3RecurringAcceptanceRecord
			if !decodeCanonical(recordBytes, &recurring) || manifest.V3Attempt == nil || !reflect.DeepEqual(recurring.Attempt, *manifest.V3Attempt) {
				return "", errors.New("qualified Acceptance Record refused")
			}
			canonicalSource, err = marshalCanonical(recurring)
			if source.StableResultCode == softwarelifecycle.OwnerExceptionCode {
				expected, buildErr := buildRecurringAcceptanceRecord(manifest, v3RecurringResultFacts{EvaluationTime: recurring.AcceptedAt, DetailedEvidenceSHA256: recurring.DetailedEvidenceSHA256})
				if buildErr != nil || expected != sourceBody {
					return "", errors.New("Owner exception record refused")
				}
			}
		} else if source.StableResultCode == "RELEASE-V3-PACKAGED-LIVE-QUALIFICATION" {
			var v3Source v3AcceptanceRecordJSON
			if json.Unmarshal(recordBytes, &v3Source) != nil {
				return "", errors.New("qualified Acceptance Record refused")
			}
			canonicalSource, err = marshalCanonical(v3Source)
		} else {
			canonicalSource, err = marshalCanonical(source)
		}
		if err != nil || !bytes.Equal(canonicalSource, recordBytes) {
			return "", errors.New("qualified Acceptance Record refused")
		}
	}
	record := struct {
		AcceptedAt        string                   `json:"accepted_at"`
		Assets            []decisionAsset          `json:"assets"`
		Evidence          []string                 `json:"evidence"`
		QualificationRole string                   `json:"qualification_role"`
		ReleaseIdentity   decisionReleaseIdentity  `json:"release_identity"`
		Runner            string                   `json:"runner"`
		Schema            string                   `json:"schema"`
		SecretSafeResult  string                   `json:"secret_safe_result"`
		Sequence          uint64                   `json:"sequence"`
		Software          acceptanceRecordSoftware `json:"software"`
		StableResultCode  string                   `json:"stable_result_code"`
		Stages            acceptanceRecordStages   `json:"stages"`
		WorkflowRun       string                   `json:"workflow_run"`
	}{
		AcceptedAt: source.AcceptedAt, Assets: source.Assets, Evidence: source.Evidence, QualificationRole: source.QualificationRole, ReleaseIdentity: source.ReleaseIdentity,
		Runner: source.Runner, Schema: source.Schema, SecretSafeResult: source.SecretSafeResult, Sequence: source.Sequence, Software: source.Software,
		StableResultCode: "RELEASE-INSTALLER-UPDATER-PREPUBLICATION-FAILED", Stages: source.Stages, WorkflowRun: workflowRun,
	}
	canonical, err := marshalCanonical(record)
	if err != nil {
		return "", err
	}
	if failedRetry && !bytes.Equal(canonical, recordBytes) {
		return "", errors.New("qualified Acceptance Record refused")
	}
	lines := []string{"# SBXR Installer-Updater Acceptance Record", "Status: Failed prerelease", "Repository: " + release.ReleaseIdentity.Repository, "Tag: " + release.Tag, "Commit: " + release.Commit, "Release index SHA-256: " + release.ReleaseIdentity.ReleaseIndexSHA256, "Sequence: " + strconv.FormatUint(release.Sequence, 10), "Workflow evidence: " + workflowRun, "Acceptance time: " + source.AcceptedAt, "Runner: " + source.Runner, "Go toolchain: " + source.Software.GoToolchain, "Public verifier: " + source.Software.PublicVerifier, "Secret-safe result: Passed", "Qualification role: " + source.QualificationRole, "Stable result code: RELEASE-INSTALLER-UPDATER-PREPUBLICATION-FAILED", "Module Verification: " + source.Stages.ModuleVerification, "Seam Verification: " + source.Stages.SeamVerification, "Integrated Verification: " + source.Stages.IntegratedVerification, "Codex Live Acceptance: " + source.Stages.CodexLiveAcceptance, "Owner Acceptance: " + source.Stages.OwnerAcceptance}
	var body strings.Builder
	for _, line := range lines {
		if line == "Secret-safe result: Passed" {
			line = "Secret-safe result: " + source.SecretSafeResult
		}
		body.WriteString(line + "\n")
	}
	for _, asset := range release.Assets {
		body.WriteString("Asset: " + asset.Name + " " + strconv.FormatInt(asset.Size, 10) + " " + asset.SHA256 + "\n")
	}
	body.WriteString("```json\n" + string(canonical) + "\n```\n")
	if failedRetry && body.String() != sourceBody {
		return "", errors.New("qualified Acceptance Record refused")
	}
	return body.String(), nil
}

func evaluateStableFailureVerification(facts stableFailureVerificationFacts, document []byte) (stableFailureVerificationDecision, error) {
	refused := func() (stableFailureVerificationDecision, error) {
		return stableFailureVerificationDecision{}, errors.New("stable failure verification refused")
	}
	if facts.Schema != qualificationFactsSchema || facts.Stage != stableFailureVerificationStage || facts.BurnedIdentities == nil || facts.Observations == nil || secretBearing(document) || !validFailureBurns(facts.BurnedIdentities) {
		return refused()
	}
	var failureFacts stableFailureFacts
	if !decodeCanonical(facts.FailureFacts, &failureFacts) {
		return refused()
	}
	failure, err := evaluateStableFailure(failureFacts, facts.FailureFacts)
	failureBytes, marshalErr := marshalCanonical(failure)
	if err != nil || marshalErr != nil || !bytes.Equal(failureBytes, facts.FailureDecision) || len(facts.Observations) != len(failure.Actions) {
		return refused()
	}
	for index, action := range failure.Actions {
		observation := facts.Observations[index]
		burnRequired, exact := burnRequirement(facts.BurnedIdentities, action.Burn)
		if burnRequired || !exact || observation.Commit != action.Commit || observation.ReleaseID != action.ReleaseID || observation.ReleaseIdentity != action.ReleaseIdentity || observation.Sequence != action.Sequence || observation.Tag != action.Tag {
			return refused()
		}
		if failure.Outcome == "withdraw" {
			if observation.ReleasePresent || observation.TagCommit != nil || len(observation.Assets) != 0 || observation.Body != "" || observation.Draft || observation.Immutable || observation.Prerelease || observation.PubliclyVerified {
				return refused()
			}
		} else if !observation.ReleasePresent || observation.TagCommit == nil || *observation.TagCommit != action.Commit || observation.Draft || !observation.Immutable || !observation.Prerelease || observation.PubliclyVerified || observation.Body != action.Body || !reflect.DeepEqual(observation.Assets, action.Assets) {
			return refused()
		}
	}
	return stableFailureVerificationDecision{Actions: []json.RawMessage{}, FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: documentSHA256(facts.FailureDecision), Schema: qualificationDecisionSchema, Stage: stableFailureVerificationStage}, nil
}

func evaluateCandidateFailureVerification(facts candidateFailureVerificationFacts, document []byte) (candidateFailureVerificationDecision, error) {
	refused := func() (candidateFailureVerificationDecision, error) {
		return candidateFailureVerificationDecision{}, errors.New("candidate failure verification refused")
	}
	if facts.Schema != qualificationFactsSchema || facts.Stage != candidateFailureVerificationStage || facts.BurnedIdentities == nil || facts.Observations == nil || secretBearing(document) || !validFailureBurns(facts.BurnedIdentities) {
		return refused()
	}
	var failureFacts candidateFailureFacts
	if !decodeCanonical(facts.FailureFacts, &failureFacts) {
		return refused()
	}
	failureDecision, err := evaluateCandidateFailure(failureFacts, facts.FailureFacts)
	if err != nil {
		return refused()
	}
	failureDecisionBytes, err := marshalCanonical(failureDecision)
	if err != nil || !bytes.Equal(failureDecisionBytes, facts.FailureDecision) || len(facts.Observations) != len(failureDecision.Actions) {
		return refused()
	}
	priorObservations := make(map[string]candidateFailureObservation, len(failureFacts.Observations))
	for _, observation := range failureFacts.Observations {
		priorObservations[observation.Tag] = observation
	}
	for index, raw := range failureDecision.Actions {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &kind) != nil {
			return refused()
		}
		observation := facts.Observations[index]
		prior, ok := priorObservations[observation.Tag]
		if !ok || !sameFailureTarget(observation, prior) {
			return refused()
		}
		switch kind.Type {
		case "cleanup-draft":
			var action cleanupDraftAction
			if !decodeCanonical(raw, &action) || observation.Tag != action.Tag || observation.ReleaseID != action.ReleaseID || observation.Commit != action.Commit || observation.ReleasePresent || observation.TagCommit != nil || len(observation.Assets) != 0 || observation.Body != "" || observation.Draft || observation.Immutable || observation.Prerelease {
				return refused()
			}
		case "finalize-failed-release":
			var action finalizeFailedReleaseAction
			if !decodeCanonical(raw, &action) {
				return refused()
			}
			burnRequired, exact := burnRequirement(facts.BurnedIdentities, action.Burn)
			if burnRequired || !exact || observation.Tag != action.Tag || observation.ReleaseID != action.ReleaseID || observation.Commit != action.Commit || !observation.ReleasePresent || observation.TagCommit == nil || *observation.TagCommit != action.Commit || observation.Draft || !observation.Immutable || !observation.Prerelease || observation.Body != action.Body || !reflect.DeepEqual(observation.Assets, prior.Assets) {
				return refused()
			}
		default:
			return refused()
		}
	}
	return candidateFailureVerificationDecision{Actions: []json.RawMessage{}, FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: documentSHA256(facts.FailureDecision), Schema: qualificationDecisionSchema, Stage: candidateFailureVerificationStage}, nil
}

func sameFailureTarget(observation, prior candidateFailureObservation) bool {
	return observation.CreatedReleaseID == prior.CreatedReleaseID && observation.ReleaseID == prior.ReleaseID && observation.Commit == prior.Commit && observation.Sequence == prior.Sequence && observation.Tag == prior.Tag && observation.ReleaseIdentity == prior.ReleaseIdentity
}

func evaluateCandidateFailure(facts candidateFailureFacts, document []byte) (candidateFailureDecision, error) {
	refused := func() (candidateFailureDecision, error) {
		return candidateFailureDecision{}, errors.New("candidate failure refused")
	}
	observedAt, timeErr := time.Parse(time.RFC3339, facts.ObservedAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != candidateFailureStage || facts.Observations == nil || facts.BurnedIdentities == nil || !validSHA256(facts.PriorDecisionSHA256) || timeErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || secretBearing(document) {
		return refused()
	}
	var constructionFacts candidateDraftConstructionFacts
	if !decodeCanonical(facts.ConstructionFacts, &constructionFacts) {
		return refused()
	}
	construction, err := evaluateCandidateDraftConstruction(constructionFacts, facts.ConstructionFacts)
	if err != nil {
		return refused()
	}
	constructionBytes, err := marshalCanonical(construction)
	if err != nil || !bytes.Equal(constructionBytes, facts.ConstructionDecision) || !validFailureBurns(facts.BurnedIdentities) || !validCandidateFailureWorkflow(facts.Workflow, construction.Actions) {
		return refused()
	}
	expected := make(map[string]constructDraftAction, len(construction.Actions))
	for _, action := range construction.Actions {
		expected[action.Tag] = action
	}
	seen := map[string]bool{}
	preBoundary := bytes.Equal(facts.QualificationManifest, []byte("null")) && bytes.Equal(facts.QualificationBoundaryFacts, []byte("null"))
	for _, observation := range facts.Observations {
		action, ok := expected[observation.Tag]
		if !ok || seen[observation.Tag] || !validFailureObservation(observation, action, !preBoundary) {
			return refused()
		}
		seen[observation.Tag] = true
	}
	decision := candidateFailureDecision{FactsSHA256: documentSHA256(document), PriorDecisionSHA256: facts.PriorDecisionSHA256, Schema: qualificationDecisionSchema, Stage: candidateFailureStage}
	if preBoundary {
		if facts.Reason != "pre-boundary-failure" || facts.CandidateFailureState != nil || facts.PriorDecisionSHA256 != documentSHA256(facts.ConstructionDecision) {
			return refused()
		}
		decision.Outcome = "cleanup"
		decision.Actions = make([]json.RawMessage, len(facts.Observations))
		for index, observation := range facts.Observations {
			if observation.ReleasePresent && (!observation.Draft || observation.Prerelease || observation.Immutable) {
				return refused()
			}
			decision.Actions[index] = mustJSON(cleanupDraftAction{Commit: observation.Commit, DeleteRelease: observation.ReleasePresent, DeleteTag: observation.TagCommit != nil, FactsSHA256: decision.FactsSHA256, PriorDecisionSHA256: decision.PriorDecisionSHA256, ReleaseID: observation.ReleaseID, Tag: observation.Tag, Type: "cleanup-draft"})
		}
		return decision, nil
	}
	if facts.Reason != "post-sign-qualification-failure" || facts.CandidateFailureState == nil || len(facts.Observations) != len(construction.Actions) {
		return refused()
	}
	var boundaryFacts qualificationBoundaryFacts
	if !decodeCanonical(facts.QualificationBoundaryFacts, &boundaryFacts) {
		return refused()
	}
	manifest, err := evaluateQualificationBoundary(boundaryFacts)
	if err != nil {
		return refused()
	}
	manifestBytes, err := marshalCanonical(manifest)
	var verificationFacts candidateDraftVerificationFacts
	if err != nil || !bytes.Equal(manifestBytes, facts.QualificationManifest) || facts.PriorDecisionSHA256 != documentSHA256(facts.QualificationManifest) || facts.CandidateFailureState.WorkflowRun != manifest.Workflow.RunURL || facts.Workflow != manifest.Workflow || !validCandidateFailureState(*facts.CandidateFailureState) || !decodeCanonical(boundaryFacts.DraftVerificationFacts, &verificationFacts) || !bytes.Equal(facts.ConstructionFacts, verificationFacts.ConstructionFacts) || !bytes.Equal(facts.ConstructionDecision, verificationFacts.ConstructionDecision) {
		return refused()
	}
	decision.Outcome = "failed-prerelease"
	decision.Actions = make([]json.RawMessage, len(facts.Observations))
	for index, observation := range facts.Observations {
		if !observation.ReleasePresent {
			return refused()
		}
		burn := burnedIdentity{Commit: observation.Commit, OriginalTag: observation.Tag, QualificationRunURL: manifest.Workflow.RunURL, Reason: facts.Reason, RecordedAt: facts.ObservedAt, ReleaseIndexSHA256: observation.ReleaseIdentity.ReleaseIndexSHA256, Sequence: observation.Sequence}
		burnRequired, ok := burnRequirement(facts.BurnedIdentities, burn)
		if !ok {
			return refused()
		}
		manifestIndex := slices.IndexFunc(manifest.Releases, func(release qualificationRelease) bool { return release.Tag == observation.Tag })
		if manifestIndex < 0 {
			return refused()
		}
		manifestRelease := manifest.Releases[manifestIndex]
		if observation.ReleaseID != manifestRelease.ReleaseID || observation.Commit != manifestRelease.Commit || observation.Sequence != manifestRelease.Sequence || observation.Tag != manifestRelease.Tag || observation.ReleaseIdentity != manifestRelease.ReleaseIdentity || !reflect.DeepEqual(observation.Assets, manifestRelease.Assets) {
			return refused()
		}
		role := "Discovered, installed, recovered, final latest release"
		if manifest.Mode == "rescue" {
			role = "Rescue direct-install and lower-sequence replacement release"
		} else if manifestIndex == 0 {
			role = "Clean-installed source release"
		}
		body, err := buildFailedAcceptanceRecord(manifest, *facts.CandidateFailureState, observation, role)
		if err != nil || !observation.Draft && (!observation.Prerelease || !observation.Immutable || observation.Body != body) {
			return refused()
		}
		decision.Actions[index] = mustJSON(finalizeFailedReleaseAction{Body: body, Burn: burn, BurnRequired: burnRequired, Commit: observation.Commit, FactsSHA256: decision.FactsSHA256, PriorDecisionSHA256: decision.PriorDecisionSHA256, ReleaseID: observation.ReleaseID, Tag: observation.Tag, Type: "finalize-failed-release"})
	}
	return decision, nil
}

func validCandidateFailureWorkflow(workflow qualificationWorkflow, actions []constructDraftAction) bool {
	runID, err := strconv.ParseUint(workflow.RunID, 10, 64)
	if err != nil || runID == 0 || workflow.Path != ".github/workflows/candidate.yml" || workflow.Ref != softwarelifecycle.Repository+"/.github/workflows/candidate.yml@refs/heads/main" || workflow.RunURL != failedRunURL(workflow.RunID) || len(actions) == 0 || !validCommit(workflow.Commit) {
		return false
	}
	for _, action := range actions {
		if action.Commit != workflow.Commit {
			return false
		}
	}
	return true
}

func validFailureObservation(observation candidateFailureObservation, action constructDraftAction, complete bool) bool {
	if observation.ReleaseID <= 0 || observation.CreatedReleaseID != observation.ReleaseID || observation.Commit != action.Commit || observation.Sequence != action.Sequence || observation.Tag != action.Tag || observation.TagCommit != nil && *observation.TagCommit != action.Commit || observation.ReleaseIdentity != action.ReleaseIdentity || complete && !reflect.DeepEqual(observation.Assets, action.Assets) || len(observation.Assets) > len(action.Assets) {
		return false
	}
	if !observation.ReleasePresent {
		return !complete && len(observation.Assets) == 0 && observation.Body == "" && !observation.Draft && !observation.Immutable && !observation.Prerelease
	}
	if !(observation.Draft && !observation.Prerelease && !observation.Immutable || !observation.Draft && observation.Prerelease && observation.Immutable) {
		return false
	}
	for index, asset := range observation.Assets {
		if index > 0 && observation.Assets[index-1].Name >= asset.Name {
			return false
		}
		targetIndex, ok := slices.BinarySearchFunc(action.Assets, asset, func(a, b decisionAsset) int { return strings.Compare(a.Name, b.Name) })
		if !ok || action.Assets[targetIndex] != asset {
			return false
		}
	}
	return true
}

func validFailureBurns(burns []burnedIdentity) bool {
	if !slices.IsSortedFunc(burns, func(a, b burnedIdentity) int { return strings.Compare(a.OriginalTag, b.OriginalTag) }) {
		return false
	}
	seenTags, seenSequences := map[string]bool{}, map[uint64]bool{}
	for _, burn := range burns {
		if !validBurnedIdentity(burn) || seenTags[burn.OriginalTag] || seenSequences[burn.Sequence] {
			return false
		}
		seenTags[burn.OriginalTag], seenSequences[burn.Sequence] = true, true
	}
	return true
}

func burnRequirement(existing []burnedIdentity, wanted burnedIdentity) (bool, bool) {
	for _, burn := range existing {
		if burn.OriginalTag == wanted.OriginalTag || burn.Sequence == wanted.Sequence {
			return false, burn == wanted
		}
	}
	return true, true
}

func validCandidateFailureState(state candidateFailureState) bool {
	recordedAt, timeErr := time.Parse(time.RFC3339, state.RecordedAt)
	allowed := func(value string) bool { return value == "Pending" || value == "Failed" || value == "Passed" }
	return state.Schema == "sbxr-candidate-failure-state-v1" && state.WorkflowRun != "" && state.Runner == "Ubuntu Server 24.04 linux/amd64" && timeErr == nil && recordedAt.Format(time.RFC3339) == state.RecordedAt && state.Evidence != nil && len(state.Evidence) > 0 && allowed(state.Stages.IntegratedVerification) && allowed(state.Stages.CodexLiveAcceptance) && (state.Software.GoToolchain == "Not started" || regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(state.Software.GoToolchain)) && regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+ [A-F0-9]{64}$`).MatchString(state.Software.PublicVerifier)
}

func buildFailedAcceptanceRecord(manifest qualificationManifest, state candidateFailureState, release candidateFailureObservation, role string) (string, error) {
	record := struct {
		AcceptedAt        string                   `json:"accepted_at"`
		Assets            []decisionAsset          `json:"assets"`
		Evidence          []string                 `json:"evidence"`
		QualificationRole string                   `json:"qualification_role"`
		ReleaseIdentity   decisionReleaseIdentity  `json:"release_identity"`
		Runner            string                   `json:"runner"`
		Schema            string                   `json:"schema"`
		SecretSafeResult  string                   `json:"secret_safe_result"`
		Sequence          uint64                   `json:"sequence"`
		Software          acceptanceRecordSoftware `json:"software"`
		StableResultCode  string                   `json:"stable_result_code"`
		Stages            acceptanceRecordStages   `json:"stages"`
		WorkflowRun       string                   `json:"workflow_run"`
	}{
		AcceptedAt: state.RecordedAt, Assets: release.Assets, Evidence: state.Evidence, QualificationRole: role, ReleaseIdentity: release.ReleaseIdentity,
		Runner: state.Runner, Schema: "sbxr-acceptance-record-v1", SecretSafeResult: "Passed", Sequence: release.Sequence, Software: state.Software,
		StableResultCode: "RELEASE-INSTALLER-UPDATER-QUALIFICATION-FAILED", Stages: acceptanceRecordStages{CodexLiveAcceptance: state.Stages.CodexLiveAcceptance, IntegratedVerification: state.Stages.IntegratedVerification, ModuleVerification: "Passed", OwnerAcceptance: "Not required", SeamVerification: "Passed"}, WorkflowRun: manifest.Workflow.RunURL,
	}
	canonical, err := marshalCanonical(record)
	if err != nil {
		return "", err
	}
	lines := []string{"# SBXR Installer-Updater Acceptance Record", "Status: Failed prerelease", "Repository: " + release.ReleaseIdentity.Repository, "Tag: " + release.Tag, "Commit: " + release.Commit, "Release index SHA-256: " + release.ReleaseIdentity.ReleaseIndexSHA256, "Sequence: " + strconv.FormatUint(release.Sequence, 10), "Workflow evidence: " + manifest.Workflow.RunURL, "Acceptance time: " + state.RecordedAt, "Runner: " + state.Runner, "Go toolchain: " + state.Software.GoToolchain, "Public verifier: " + state.Software.PublicVerifier, "Secret-safe result: Passed", "Qualification role: " + role, "Stable result code: RELEASE-INSTALLER-UPDATER-QUALIFICATION-FAILED", "Module Verification: Passed", "Seam Verification: Passed", "Integrated Verification: " + state.Stages.IntegratedVerification, "Codex Live Acceptance: " + state.Stages.CodexLiveAcceptance, "Owner Acceptance: Not required"}
	var body strings.Builder
	for _, line := range lines {
		body.WriteString(line + "\n")
	}
	for _, asset := range release.Assets {
		body.WriteString("Asset: " + asset.Name + " " + strconv.FormatInt(asset.Size, 10) + " " + asset.SHA256 + "\n")
	}
	body.WriteString("```json\n" + string(canonical) + "\n```\n")
	return body.String(), nil
}
