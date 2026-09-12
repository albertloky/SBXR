package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type stableArchiveObservation struct {
	Commit          string `json:"commit"`
	RemoteCommit    string `json:"remote_commit"`
	RemoteTagObject string `json:"remote_tag_object"`
	TagObject       string `json:"tag_object"`
	Type            string `json:"type"`
}

type stableCandidateRun struct {
	Conclusion string `json:"conclusion"`
	CreatedAt  string `json:"created_at"`
	Event      string `json:"event"`
	HeadSHA    string `json:"head_sha"`
	ID         string `json:"id"`
	Path       string `json:"path"`
}

type stableReleaseObservation struct {
	Assets          []decisionAsset         `json:"assets"`
	Body            string                  `json:"body"`
	Commit          string                  `json:"commit"`
	Draft           bool                    `json:"draft"`
	Immutable       bool                    `json:"immutable"`
	Prerelease      bool                    `json:"prerelease"`
	ReleaseID       int64                   `json:"release_id"`
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
	Tag             string                  `json:"tag"`
}

type stablePreflightFacts struct {
	AcceptanceDecision  json.RawMessage            `json:"acceptance_decision"`
	AcceptanceFacts     json.RawMessage            `json:"acceptance_facts"`
	Archive             stableArchiveObservation   `json:"archive"`
	BurnedIdentities    []burnedIdentity           `json:"burned_identities"`
	CandidateRun        stableCandidateRun         `json:"candidate_run"`
	ChecklistSHA256     string                     `json:"checklist_sha256"`
	LatestReleaseID     *int64                     `json:"latest_release_id"`
	LatestTag           *string                    `json:"latest_tag"`
	ManifestAttested    bool                       `json:"manifest_attested"`
	ObservedAt          string                     `json:"observed_at"`
	Releases            []stableReleaseObservation `json:"releases"`
	RemoteMain          string                     `json:"remote_main"`
	Schema              string                     `json:"schema"`
	SignedManifest      json.RawMessage            `json:"signed_manifest"`
	Stage               string                     `json:"stage"`
	SubscriptionHistory *v3ReleaseHistory          `json:"subscription_history,omitempty"`
}

type publishStableReleaseAction struct {
	Assets              []decisionAsset         `json:"assets"`
	Body                string                  `json:"body"`
	Commit              string                  `json:"commit"`
	Draft               bool                    `json:"draft"`
	FactsSHA256         string                  `json:"facts_sha256"`
	FailureReason       string                  `json:"failure_reason"`
	Immutable           bool                    `json:"immutable"`
	Latest              bool                    `json:"latest"`
	ObservedAt          string                  `json:"observed_at"`
	Prerelease          bool                    `json:"prerelease"`
	PriorDecisionSHA256 string                  `json:"prior_decision_sha256"`
	ReleaseID           int64                   `json:"release_id"`
	ReleaseIdentity     decisionReleaseIdentity `json:"release_identity"`
	Sequence            uint64                  `json:"sequence"`
	Tag                 string                  `json:"tag"`
	Type                string                  `json:"type"`
}

type stablePublicationDecision struct {
	Actions             []publishStableReleaseAction `json:"actions"`
	FactsSHA256         string                       `json:"facts_sha256"`
	Outcome             string                       `json:"outcome"`
	PriorDecisionSHA256 string                       `json:"prior_decision_sha256"`
	Schema              string                       `json:"schema"`
	Stage               string                       `json:"stage"`
}

type stableReleaseAttestation struct {
	Commit        string `json:"commit"`
	Count         int    `json:"count"`
	Initiator     string `json:"initiator"`
	PredicateType string `json:"predicate_type"`
}

type stablePublicationObservation struct {
	Assets              []observedDraftAsset      `json:"assets"`
	Attestation         *stableReleaseAttestation `json:"attestation"`
	Body                string                    `json:"body"`
	Commit              string                    `json:"commit"`
	Downloads           []decisionAsset           `json:"downloads"`
	Draft               bool                      `json:"draft"`
	Immutable           bool                      `json:"immutable"`
	LatestInstallSHA256 string                    `json:"latest_install_sha256"`
	LatestReleaseID     *int64                    `json:"latest_release_id"`
	Prerelease          bool                      `json:"prerelease"`
	PublicVerification  *publicLatestVerification `json:"public_verification"`
	ReleaseID           int64                     `json:"release_id"`
	ReleaseIdentity     decisionReleaseIdentity   `json:"release_identity"`
	Sequence            uint64                    `json:"sequence"`
	Tag                 string                    `json:"tag"`
}

type stablePublicationFacts struct {
	ActionIndex               int                          `json:"action_index"`
	Approval                  qualificationApproval        `json:"approval"`
	Observation               stablePublicationObservation `json:"observation"`
	ObservedAt                string                       `json:"observed_at"`
	PreflightDecision         json.RawMessage              `json:"preflight_decision"`
	PreflightFacts            json.RawMessage              `json:"preflight_facts"`
	PriorDecisionSHA256       string                       `json:"prior_decision_sha256"`
	PriorVerificationDecision json.RawMessage              `json:"prior_verification_decision"`
	PriorVerificationFacts    json.RawMessage              `json:"prior_verification_facts"`
	Schema                    string                       `json:"schema"`
	Stage                     string                       `json:"stage"`
	SubscriptionHistory       *v3ReleaseHistory            `json:"subscription_history,omitempty"`
}

type observeStableReleaseAction struct {
	Commit              string                  `json:"commit"`
	FactsSHA256         string                  `json:"facts_sha256"`
	PriorDecisionSHA256 string                  `json:"prior_decision_sha256"`
	ReleaseID           int64                   `json:"release_id"`
	ReleaseIdentity     decisionReleaseIdentity `json:"release_identity"`
	Tag                 string                  `json:"tag"`
	Type                string                  `json:"type"`
	WaitSeconds         uint64                  `json:"wait_seconds"`
}

type stablePublicationVerificationFacts struct {
	Attempt             uint64                        `json:"attempt"`
	Observation         *stablePublicationObservation `json:"observation"`
	ObservedAt          string                        `json:"observed_at"`
	PriorDecisionSHA256 string                        `json:"prior_decision_sha256"`
	PublicationDecision json.RawMessage               `json:"publication_decision"`
	PublicationFacts    json.RawMessage               `json:"publication_facts"`
	Schema              string                        `json:"schema"`
	Stage               string                        `json:"stage"`
}

type stablePublicationVerificationDecision struct {
	Actions             []json.RawMessage `json:"actions"`
	FactsSHA256         string            `json:"facts_sha256"`
	Outcome             string            `json:"outcome"`
	PriorDecisionSHA256 string            `json:"prior_decision_sha256"`
	Schema              string            `json:"schema"`
	Stage               string            `json:"stage"`
}

type stableV3FinalizationFacts struct {
	ObservedAt                      string          `json:"observed_at"`
	PriorDecisionSHA256             string          `json:"prior_decision_sha256"`
	PublicationVerificationDecision json.RawMessage `json:"publication_verification_decision"`
	PublicationVerificationFacts    json.RawMessage `json:"publication_verification_facts"`
	Schema                          string          `json:"schema"`
	Stage                           string          `json:"stage"`
}

type stableV3FinalizationDecision struct {
	Actions             []json.RawMessage `json:"actions"`
	CompleteRemoval     string            `json:"complete_removal"`
	FactsSHA256         string            `json:"facts_sha256"`
	Outcome             string            `json:"outcome"`
	PriorDecisionSHA256 string            `json:"prior_decision_sha256"`
	PublicVerification  string            `json:"public_verification"`
	Schema              string            `json:"schema"`
	Stage               string            `json:"stage"`
	V3PackagedLive      string            `json:"v3_packaged_live"`
}

type stableInstalledRecord struct {
	Architecture       softwarelifecycle.Architecture `json:"architecture"`
	Commit             string                         `json:"commit"`
	ExecutableSHA256   string                         `json:"executable_sha256"`
	ReleaseIndexSHA256 string                         `json:"release_index_sha256"`
	Repository         string                         `json:"repository"`
	Schema             int                            `json:"schema"`
	Sequence           uint64                         `json:"sequence"`
	Tag                string                         `json:"tag"`
}

type stableNoUpdateObservation struct {
	AfterCheckSnapshotSHA256   string                       `json:"after_check_snapshot_sha256"`
	AfterInstallSnapshotSHA256 string                       `json:"after_install_snapshot_sha256"`
	AfterUpdateSnapshotSHA256  string                       `json:"after_update_snapshot_sha256"`
	BeforeSnapshotSHA256       string                       `json:"before_snapshot_sha256"`
	CheckResult                softwarelifecycle.ResultCode `json:"check_result"`
	ExecutableSHA256           string                       `json:"executable_sha256"`
	FilesystemLayoutExact      bool                         `json:"filesystem_layout_exact"`
	InstallResult              string                       `json:"install_result"`
	InstalledRecord            stableInstalledRecord        `json:"installed_record"`
	MutationLockAvailable      bool                         `json:"mutation_lock_available"`
	SnapshotsComplete          bool                         `json:"snapshots_complete"`
	SSHContinuity              bool                         `json:"ssh_continuity"`
	TransactionResidueAbsent   bool                         `json:"transaction_residue_absent"`
	UpdateResult               softwarelifecycle.ResultCode `json:"update_result"`
}

type stableNoUpdateFacts struct {
	Observation                     stableNoUpdateObservation `json:"observation"`
	ObservedAt                      string                    `json:"observed_at"`
	PriorDecisionSHA256             string                    `json:"prior_decision_sha256"`
	PublicationVerificationDecision json.RawMessage           `json:"publication_verification_decision"`
	PublicationVerificationFacts    json.RawMessage           `json:"publication_verification_facts"`
	Schema                          string                    `json:"schema"`
	Stage                           string                    `json:"stage"`
}

type stableNoUpdateDecision struct {
	Actions             []json.RawMessage       `json:"actions"`
	FactsSHA256         string                  `json:"facts_sha256"`
	Outcome             string                  `json:"outcome"`
	PriorDecisionSHA256 string                  `json:"prior_decision_sha256"`
	PublicVerification  string                  `json:"public_verification"`
	ReleaseIdentity     decisionReleaseIdentity `json:"release_identity"`
	Schema              string                  `json:"schema"`
	Sequence            uint64                  `json:"sequence"`
	StableNoUpdate      string                  `json:"stable_no_update"`
	Stage               string                  `json:"stage"`
}

func evaluateStablePreflight(facts stablePreflightFacts, document []byte) (stablePublicationDecision, error) {
	refused := func() (stablePublicationDecision, error) {
		return stablePublicationDecision{}, errors.New("stable preflight refused")
	}
	observedAt, observedErr := time.Parse(time.RFC3339, facts.ObservedAt)
	createdAt, createdErr := time.Parse(time.RFC3339, facts.CandidateRun.CreatedAt)
	age := observedAt.Sub(createdAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != stablePreflightStage || !facts.ManifestAttested || facts.BurnedIdentities == nil || facts.Releases == nil || secretBearing(document) || observedErr != nil || createdErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || createdAt.Format(time.RFC3339) != facts.CandidateRun.CreatedAt || age < 0 || age >= 90*24*time.Hour || !validSHA256(facts.ChecklistSHA256) || !validCommit(facts.RemoteMain) || !validFailureBurns(facts.BurnedIdentities) {
		return refused()
	}
	var envelope qualificationEnvelope
	if json.Unmarshal(facts.AcceptanceFacts, &envelope) != nil {
		return refused()
	}
	var records []acceptanceRecord
	var boundaryDocument json.RawMessage
	switch envelope.Stage {
	case acceptanceVPSResultStage:
		var acceptanceFacts acceptanceVPSResultFacts
		if !decodeCanonical(facts.AcceptanceFacts, &acceptanceFacts) {
			return refused()
		}
		acceptance, err := evaluateAcceptanceVPSResult(acceptanceFacts, facts.AcceptanceFacts)
		acceptanceBytes, marshalErr := marshalCanonical(acceptance)
		if err != nil || marshalErr != nil || !bytes.Equal(acceptanceBytes, facts.AcceptanceDecision) {
			return refused()
		}
		records, boundaryDocument = acceptance.Records, acceptanceFacts.QualificationBoundaryFacts
	case v3PackagedLiveResultStage, "owner-exception-result":
		var acceptanceFacts struct {
			QualificationBoundaryFacts json.RawMessage `json:"qualification_boundary_facts"`
		}
		if json.Unmarshal(facts.AcceptanceFacts, &acceptanceFacts) != nil {
			return refused()
		}
		acceptance, err := evaluateV3Result(facts.AcceptanceFacts)
		acceptanceBytes, marshalErr := marshalCanonical(acceptance)
		if err != nil || marshalErr != nil || !bytes.Equal(acceptanceBytes, facts.AcceptanceDecision) {
			return refused()
		}
		records, boundaryDocument = acceptance.Records, acceptanceFacts.QualificationBoundaryFacts
	default:
		return refused()
	}
	var boundaryFacts qualificationBoundaryFacts
	if !decodeCanonical(boundaryDocument, &boundaryFacts) {
		return refused()
	}
	manifest, err := evaluateQualificationBoundary(boundaryFacts)
	manifestBytes, manifestBytesErr := marshalCanonical(manifest)
	if err != nil || manifestBytesErr != nil || !bytes.Equal(facts.SignedManifest, manifestBytes) || facts.ChecklistSHA256 != manifest.AcceptanceVPSChecklistSHA256 || facts.RemoteMain != manifest.Workflow.Commit || facts.CandidateRun != (stableCandidateRun{Conclusion: "success", CreatedAt: facts.CandidateRun.CreatedAt, Event: "workflow_dispatch", HeadSHA: manifest.Workflow.Commit, ID: manifest.Workflow.RunID, Path: manifest.Workflow.Path}) {
		return refused()
	}
	var verificationFacts candidateDraftVerificationFacts
	if !decodeCanonical(boundaryFacts.DraftVerificationFacts, &verificationFacts) {
		return refused()
	}
	var constructionFacts candidateDraftConstructionFacts
	if !decodeCanonical(verificationFacts.ConstructionFacts, &constructionFacts) {
		return refused()
	}
	var preflightFacts qualificationFacts
	if !decodeCanonical(constructionFacts.PreflightFacts, &preflightFacts) || facts.Archive != (stableArchiveObservation{Commit: preflightFacts.ArchiveCommit, RemoteCommit: preflightFacts.ArchiveRemoteCommit, RemoteTagObject: preflightFacts.ArchiveRemoteTagObject, TagObject: preflightFacts.ArchiveTagObject, Type: preflightFacts.ArchiveType}) || !reflect.DeepEqual(facts.LatestTag, preflightFacts.LatestTag) || !reflect.DeepEqual(facts.BurnedIdentities, preflightFacts.BurnedIdentities) {
		return refused()
	}
	if !validPublicationHistory(manifest, facts.SubscriptionHistory) {
		return refused()
	}
	var expectedLatestReleaseID *int64
	if preflightFacts.LatestTag != nil {
		release, exists := releaseByTag(preflightFacts.Releases, *preflightFacts.LatestTag)
		if !exists {
			return refused()
		}
		expectedLatestReleaseID = &release.ID
	}
	if !reflect.DeepEqual(facts.LatestReleaseID, expectedLatestReleaseID) {
		return refused()
	}
	preflight, err := verifiedPreflightDecision(constructionFacts.PreflightFacts, constructionFacts.PreflightDecision)
	expectedReleases := 2
	if manifest.Mode == "v3" {
		expectedReleases = 1
	}
	if err != nil || preflight.SourceState != manifest.SourceState || len(manifest.Releases) != expectedReleases || len(facts.Releases) != expectedReleases || len(records) != expectedReleases {
		return refused()
	}
	recordsByTag := make(map[string]string, len(records))
	for _, record := range records {
		if _, exists := recordsByTag[record.Tag]; exists {
			return refused()
		}
		recordsByTag[record.Tag] = record.Body
	}
	for index, release := range manifest.Releases {
		observed := facts.Releases[index]
		if observed.Tag != release.Tag || observed.Sequence != release.Sequence || observed.Commit != release.Commit || observed.ReleaseID != release.ReleaseID || observed.ReleaseIdentity != release.ReleaseIdentity || !reflect.DeepEqual(observed.Assets, release.Assets) {
			return refused()
		}
		if manifest.Mode == "v3" || index == 1 || manifest.SourceState == "initial-normal" {
			if !observed.Draft || observed.Immutable || observed.Prerelease || observed.Body != recordsByTag[release.Tag] {
				return refused()
			}
		} else {
			source, exists := releaseByTag(preflightFacts.Releases, release.Tag)
			if !exists || observed.Draft || !observed.Immutable || observed.Prerelease != (manifest.SourceState == "rescue") || observed.Body != source.Body {
				return refused()
			}
		}
	}
	indexes := []int{len(manifest.Releases) - 1}
	if manifest.SourceState == "initial-normal" {
		indexes = []int{0, 1}
	}
	factsSHA256, priorDecisionSHA256 := documentSHA256(document), documentSHA256(facts.AcceptanceDecision)
	actions := make([]publishStableReleaseAction, len(indexes))
	for index, releaseIndex := range indexes {
		release := manifest.Releases[releaseIndex]
		failureReason := "b-publication-or-verification-failure"
		if releaseIndex == 0 {
			failureReason = "initial-a-public-verification-failure"
		}
		if manifest.Mode == "v3" {
			failureReason = "v3-publication-or-verification-failure"
		}
		actions[index] = publishStableReleaseAction{Assets: release.Assets, Body: recordsByTag[release.Tag], Commit: release.Commit, Draft: false, FactsSHA256: factsSHA256, FailureReason: failureReason, Immutable: true, Latest: true, ObservedAt: facts.ObservedAt, Prerelease: false, PriorDecisionSHA256: priorDecisionSHA256, ReleaseID: release.ReleaseID, ReleaseIdentity: release.ReleaseIdentity, Sequence: release.Sequence, Tag: release.Tag, Type: "publish-stable-release"}
	}
	return stablePublicationDecision{Actions: actions, FactsSHA256: factsSHA256, Outcome: "actions-required", PriorDecisionSHA256: priorDecisionSHA256, Schema: qualificationDecisionSchema, Stage: stablePreflightStage}, nil
}

func evaluateStablePublication(facts stablePublicationFacts, document []byte) (stablePublicationDecision, error) {
	refused := func() (stablePublicationDecision, error) {
		return stablePublicationDecision{}, errors.New("stable publication refused")
	}
	observedAt, timeErr := time.Parse(time.RFC3339, facts.ObservedAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != stablePublicationStage || facts.ActionIndex < 0 || facts.Approval.State != "approved" || len(facts.Approval.Environments) != 1 || facts.Approval.Environments[0].Name != "stable-publication" || timeErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || secretBearing(document) {
		return refused()
	}
	preflight, preflightFacts, err := verifiedStablePreflight(facts.PreflightFacts, facts.PreflightDecision)
	if err != nil || facts.ActionIndex >= len(preflight.Actions) {
		return refused()
	}
	var manifest qualificationManifest
	if !decodeCanonical(preflightFacts.SignedManifest, &manifest) || !validPublicationHistory(manifest, facts.SubscriptionHistory) {
		return refused()
	}
	priorDecisionSHA256 := documentSHA256(facts.PreflightDecision)
	expectedLatestReleaseID := preflightFacts.LatestReleaseID
	if facts.ActionIndex == 0 {
		if !bytes.Equal(facts.PriorVerificationFacts, []byte("null")) || !bytes.Equal(facts.PriorVerificationDecision, []byte("null")) {
			return refused()
		}
	} else {
		var priorFacts stablePublicationVerificationFacts
		if !decodeCanonical(facts.PriorVerificationFacts, &priorFacts) {
			return refused()
		}
		prior, err := evaluateStablePublicationVerification(priorFacts, facts.PriorVerificationFacts)
		priorBytes, marshalErr := marshalCanonical(prior)
		var priorPublicationFacts stablePublicationFacts
		if err != nil || marshalErr != nil || !bytes.Equal(priorBytes, facts.PriorVerificationDecision) || prior.Outcome != "accepted" || !decodeCanonical(priorFacts.PublicationFacts, &priorPublicationFacts) || priorPublicationFacts.ActionIndex != facts.ActionIndex-1 || !bytes.Equal(priorPublicationFacts.PreflightFacts, facts.PreflightFacts) || !bytes.Equal(priorPublicationFacts.PreflightDecision, facts.PreflightDecision) {
			return refused()
		}
		priorDecisionSHA256 = documentSHA256(facts.PriorVerificationDecision)
		value := preflight.Actions[facts.ActionIndex-1].ReleaseID
		expectedLatestReleaseID = &value
	}
	if facts.PriorDecisionSHA256 != priorDecisionSHA256 || !validStablePublicationObservation(facts.Observation, preflight.Actions[facts.ActionIndex], expectedLatestReleaseID, false) {
		return refused()
	}
	action := preflight.Actions[facts.ActionIndex]
	action.FactsSHA256 = documentSHA256(document)
	action.PriorDecisionSHA256 = priorDecisionSHA256
	action.ObservedAt = facts.ObservedAt
	return stablePublicationDecision{Actions: []publishStableReleaseAction{action}, FactsSHA256: action.FactsSHA256, Outcome: "actions-required", PriorDecisionSHA256: priorDecisionSHA256, Schema: qualificationDecisionSchema, Stage: stablePublicationStage}, nil
}

func verifiedStablePreflight(factsDocument, decisionDocument []byte) (stablePublicationDecision, stablePreflightFacts, error) {
	var facts stablePreflightFacts
	if !decodeCanonical(factsDocument, &facts) {
		return stablePublicationDecision{}, stablePreflightFacts{}, errors.New("stable publication refused")
	}
	decision, err := evaluateStablePreflight(facts, factsDocument)
	decisionBytes, marshalErr := marshalCanonical(decision)
	if err != nil || marshalErr != nil || !bytes.Equal(decisionBytes, decisionDocument) {
		return stablePublicationDecision{}, stablePreflightFacts{}, errors.New("stable publication refused")
	}
	return decision, facts, nil
}

func evaluateStablePublicationVerification(facts stablePublicationVerificationFacts, document []byte) (stablePublicationVerificationDecision, error) {
	refused := func() (stablePublicationVerificationDecision, error) {
		return stablePublicationVerificationDecision{}, errors.New("stable publication verification refused")
	}
	observedAt, observedErr := time.Parse(time.RFC3339, facts.ObservedAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != stablePublicationVerificationStage || facts.Attempt == 0 || facts.Attempt > 60 || observedErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || !validSHA256(facts.PriorDecisionSHA256) || secretBearing(document) {
		return refused()
	}
	var publicationFacts stablePublicationFacts
	if !decodeCanonical(facts.PublicationFacts, &publicationFacts) {
		return refused()
	}
	publication, err := evaluateStablePublication(publicationFacts, facts.PublicationFacts)
	publicationBytes, marshalErr := marshalCanonical(publication)
	if err != nil || marshalErr != nil || !bytes.Equal(publicationBytes, facts.PublicationDecision) || facts.PriorDecisionSHA256 != documentSHA256(facts.PublicationDecision) || len(publication.Actions) != 1 {
		return refused()
	}
	publishedAt, publishTimeErr := time.Parse(time.RFC3339, publication.Actions[0].ObservedAt)
	age := observedAt.Sub(publishedAt)
	if publishTimeErr != nil || age < 0 {
		return refused()
	}
	decision := stablePublicationVerificationDecision{Actions: []json.RawMessage{}, FactsSHA256: documentSHA256(document), PriorDecisionSHA256: facts.PriorDecisionSHA256, Schema: qualificationDecisionSchema, Stage: stablePublicationVerificationStage}
	action := publication.Actions[0]
	latestReleaseID := action.ReleaseID
	if facts.Observation != nil && age <= 5*time.Minute && validStablePublicationObservation(*facts.Observation, action, &latestReleaseID, true) {
		decision.Outcome = "accepted"
		return decision, nil
	}
	if facts.Attempt == 60 || age >= 5*time.Minute {
		decision.Outcome = "propagation-exhausted"
		return decision, nil
	}
	if facts.Observation != nil && !validStablePropagationObservation(*facts.Observation, publicationFacts.Observation, action) {
		return refused()
	}
	decision.Outcome = "propagation-pending"
	decision.Actions = []json.RawMessage{mustJSON(observeStableReleaseAction{Commit: action.Commit, FactsSHA256: decision.FactsSHA256, PriorDecisionSHA256: facts.PriorDecisionSHA256, ReleaseID: action.ReleaseID, ReleaseIdentity: action.ReleaseIdentity, Tag: action.Tag, Type: "observe-stable-release", WaitSeconds: 5})}
	return decision, nil
}

func evaluateStableV3Finalization(facts stableV3FinalizationFacts, document []byte) (stableV3FinalizationDecision, error) {
	refused := func() (stableV3FinalizationDecision, error) {
		return stableV3FinalizationDecision{}, errors.New("stable V3 finalization refused")
	}
	observedAt, observedErr := time.Parse(time.RFC3339, facts.ObservedAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != stableV3FinalizationStage || observedErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || !validSHA256(facts.PriorDecisionSHA256) || secretBearing(document) {
		return refused()
	}
	var verificationFacts stablePublicationVerificationFacts
	if !decodeCanonical(facts.PublicationVerificationFacts, &verificationFacts) {
		return refused()
	}
	verification, err := evaluateStablePublicationVerification(verificationFacts, facts.PublicationVerificationFacts)
	verificationBytes, marshalErr := marshalCanonical(verification)
	verifiedAt, verifiedAtErr := time.Parse(time.RFC3339, verificationFacts.ObservedAt)
	if err != nil || marshalErr != nil || !bytes.Equal(verificationBytes, facts.PublicationVerificationDecision) || verification.Outcome != "accepted" || facts.PriorDecisionSHA256 != documentSHA256(facts.PublicationVerificationDecision) || verifiedAtErr != nil || observedAt.Before(verifiedAt) || observedAt.Sub(verifiedAt) > 30*time.Minute {
		return refused()
	}
	var publicationFacts stablePublicationFacts
	if !decodeCanonical(verificationFacts.PublicationFacts, &publicationFacts) {
		return refused()
	}
	var preflightFacts stablePreflightFacts
	if !decodeCanonical(publicationFacts.PreflightFacts, &preflightFacts) {
		return refused()
	}
	acceptance, acceptanceErr := evaluateV3Result(preflightFacts.AcceptanceFacts)
	acceptanceBytes, acceptanceMarshalErr := marshalCanonical(acceptance)
	if acceptanceErr != nil || acceptanceMarshalErr != nil || !bytes.Equal(acceptanceBytes, preflightFacts.AcceptanceDecision) || len(acceptance.Records) != 1 {
		return refused()
	}
	live := "Passed"
	var manifest qualificationManifest
	if decodeCanonical(preflightFacts.SignedManifest, &manifest) && ownerExceptionManifest(manifest) {
		live = softwarelifecycle.OwnerExceptionLive
	}
	return stableV3FinalizationDecision{Actions: []json.RawMessage{}, CompleteRemoval: live, FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, PublicVerification: "Passed", Schema: qualificationDecisionSchema, Stage: stableV3FinalizationStage, V3PackagedLive: live}, nil
}

func evaluateStableNoUpdate(facts stableNoUpdateFacts, document []byte) (stableNoUpdateDecision, error) {
	refused := func() (stableNoUpdateDecision, error) {
		return stableNoUpdateDecision{}, errors.New("stable no-update verification refused")
	}
	observedAt, observedErr := time.Parse(time.RFC3339, facts.ObservedAt)
	observation := facts.Observation
	if facts.Schema != qualificationFactsSchema || facts.Stage != stableNoUpdateStage || observedErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || !validSHA256(facts.PriorDecisionSHA256) || secretBearing(document) ||
		!observation.FilesystemLayoutExact || !observation.MutationLockAvailable || !observation.SnapshotsComplete || !observation.SSHContinuity || !observation.TransactionResidueAbsent || observation.InstallResult != "SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT" || observation.CheckResult != softwarelifecycle.CheckAlreadyCurrent || observation.UpdateResult != softwarelifecycle.UpdateAlreadyCurrent ||
		!validSHA256(observation.BeforeSnapshotSHA256) || observation.AfterInstallSnapshotSHA256 != observation.BeforeSnapshotSHA256 || observation.AfterCheckSnapshotSHA256 != observation.BeforeSnapshotSHA256 || observation.AfterUpdateSnapshotSHA256 != observation.BeforeSnapshotSHA256 {
		return refused()
	}
	var verificationFacts stablePublicationVerificationFacts
	if !decodeCanonical(facts.PublicationVerificationFacts, &verificationFacts) {
		return refused()
	}
	verification, err := evaluateStablePublicationVerification(verificationFacts, facts.PublicationVerificationFacts)
	verificationBytes, marshalErr := marshalCanonical(verification)
	verifiedAt, verifiedAtErr := time.Parse(time.RFC3339, verificationFacts.ObservedAt)
	if err != nil || marshalErr != nil || !bytes.Equal(verificationBytes, facts.PublicationVerificationDecision) || verification.Outcome != "accepted" || facts.PriorDecisionSHA256 != documentSHA256(facts.PublicationVerificationDecision) || verifiedAtErr != nil || observedAt.Before(verifiedAt) || observedAt.Sub(verifiedAt) > 30*time.Minute {
		return refused()
	}
	var publicationFacts stablePublicationFacts
	if !decodeCanonical(verificationFacts.PublicationFacts, &publicationFacts) {
		return refused()
	}
	preflight, _, preflightErr := verifiedStablePreflight(publicationFacts.PreflightFacts, publicationFacts.PreflightDecision)
	publication, publicationErr := evaluateStablePublication(publicationFacts, verificationFacts.PublicationFacts)
	if preflightErr != nil || publicationErr != nil || len(publication.Actions) != 1 || publicationFacts.ActionIndex != len(preflight.Actions)-1 {
		return refused()
	}
	action := publication.Actions[0]
	record := observation.InstalledRecord
	if record.Schema != 1 || record.Architecture != softwarelifecycle.AMD64 || !validSHA256(observation.ExecutableSHA256) || record.ExecutableSHA256 != observation.ExecutableSHA256 || record.Sequence != action.Sequence || (decisionReleaseIdentity{Commit: record.Commit, ReleaseIndexSHA256: record.ReleaseIndexSHA256, Repository: record.Repository, Tag: record.Tag}) != action.ReleaseIdentity {
		return refused()
	}
	return stableNoUpdateDecision{Actions: []json.RawMessage{}, FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, PublicVerification: "Passed", ReleaseIdentity: action.ReleaseIdentity, Schema: qualificationDecisionSchema, Sequence: action.Sequence, StableNoUpdate: "Passed", Stage: stableNoUpdateStage}, nil
}

func validStablePublicationObservation(observation stablePublicationObservation, action publishStableReleaseAction, expectedLatestReleaseID *int64, public bool) bool {
	if !validStablePublicationTarget(observation, action) || !reflect.DeepEqual(observation.LatestReleaseID, expectedLatestReleaseID) {
		return false
	}
	if !public {
		return observation.Draft && !observation.Immutable && !observation.Prerelease && observation.Attestation == nil && observation.LatestInstallSHA256 == "" && observation.PublicVerification == nil
	}
	return !observation.Draft && observation.Immutable && observation.Prerelease == action.Prerelease && observation.LatestReleaseID != nil && *observation.LatestReleaseID == action.ReleaseID && observation.LatestInstallSHA256 == action.Assets[0].SHA256 && observation.Attestation != nil && *observation.Attestation == (stableReleaseAttestation{Commit: action.Commit, Count: 1, Initiator: "github", PredicateType: "release"}) && validPublicLatestVerification(observation.PublicVerification, action)
}

func validStablePublicationTarget(observation stablePublicationObservation, action publishStableReleaseAction) bool {
	if observation.ReleaseID != action.ReleaseID || observation.Commit != action.Commit || observation.Sequence != action.Sequence || observation.Tag != action.Tag || observation.ReleaseIdentity != action.ReleaseIdentity || observation.Body != action.Body || len(observation.Assets) != len(action.Assets) || !reflect.DeepEqual(observation.Downloads, action.Assets) {
		return false
	}
	seenAssetIDs := map[int64]bool{}
	for index, expected := range action.Assets {
		asset := observation.Assets[index]
		if asset.ID <= 0 || seenAssetIDs[asset.ID] || asset.Name != expected.Name || asset.SHA256 != expected.SHA256 || asset.Size != expected.Size {
			return false
		}
		seenAssetIDs[asset.ID] = true
	}
	return true
}

func validStablePropagationObservation(observation, prior stablePublicationObservation, action publishStableReleaseAction) bool {
	if !validStablePublicationTarget(observation, action) || observation.Prerelease {
		return false
	}
	if observation.Draft {
		return !observation.Immutable && observation.Attestation == nil && observation.LatestInstallSHA256 == "" && reflect.DeepEqual(observation.LatestReleaseID, prior.LatestReleaseID) && pendingPublicLatestVerification(observation.PublicVerification)
	}
	latestPending := reflect.DeepEqual(observation.LatestReleaseID, prior.LatestReleaseID) && observation.LatestInstallSHA256 == "" || observation.LatestReleaseID != nil && *observation.LatestReleaseID == action.ReleaseID && (observation.LatestInstallSHA256 == "" || observation.LatestInstallSHA256 == action.Assets[0].SHA256)
	attestationPending := observation.Attestation == nil || *observation.Attestation == (stableReleaseAttestation{Commit: action.Commit, Count: 0, Initiator: "", PredicateType: "release"}) || *observation.Attestation == (stableReleaseAttestation{Commit: action.Commit, Count: 1, Initiator: "github", PredicateType: "release"})
	return latestPending && attestationPending && pendingPublicLatestVerification(observation.PublicVerification)
}

func validPublicLatestVerification(verification *publicLatestVerification, action publishStableReleaseAction) bool {
	return verification != nil && verification.Outcome == "accepted" && verification.ReleaseIdentity != nil && *verification.ReleaseIdentity == action.ReleaseIdentity && verification.Sequence != nil && *verification.Sequence == action.Sequence
}

func pendingPublicLatestVerification(verification *publicLatestVerification) bool {
	if verification == nil {
		return false
	}
	switch verification.Outcome {
	case "unavailable":
		return verification.ReleaseIdentity == nil && verification.Sequence == nil
	case "accepted":
		return verification.ReleaseIdentity != nil && verification.Sequence != nil
	default:
		return false
	}
}
