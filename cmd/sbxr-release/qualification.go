package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

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

type qualificationFacts struct {
	ArchiveCommit          string            `json:"archive_commit"`
	ArchiveRemoteCommit    string            `json:"archive_remote_commit"`
	ArchiveRemoteTagObject string            `json:"archive_remote_tag_object"`
	ArchiveTagObject       string            `json:"archive_tag_object"`
	ArchiveType            string            `json:"archive_type"`
	BurnedIdentities       []burnedIdentity  `json:"burned_identities"`
	Candidate              candidateRequest  `json:"candidate"`
	ChecklistSHA256        string            `json:"checklist_sha256"`
	Commit                 string            `json:"commit"`
	DefectIssue            *defectIssue      `json:"defect_issue"`
	FailedNormalRun        *failedNormalRun  `json:"failed_normal_run"`
	LatestTag              *string           `json:"latest_tag"`
	Releases               []observedRelease `json:"releases"`
	RemoteMain             string            `json:"remote_main"`
	Schema                 string            `json:"schema"`
	Stage                  string            `json:"stage"`
	SubscriptionHistory    *v3ReleaseHistory `json:"subscription_history,omitempty"`
	Tags                   []string          `json:"tags"`
}

type burnedIdentity struct {
	Commit              string `json:"commit"`
	OriginalTag         string `json:"original_tag"`
	QualificationRunURL string `json:"qualification_run_url"`
	Reason              string `json:"reason"`
	RecordedAt          string `json:"recorded_at"`
	ReleaseIndexSHA256  string `json:"release_index_sha256"`
	Sequence            uint64 `json:"sequence"`
}

type candidateRequest struct {
	ASequence         uint64            `json:"a_sequence"`
	ATag              string            `json:"a_tag"`
	BSequence         uint64            `json:"b_sequence"`
	BTag              string            `json:"b_tag"`
	DefectIssueURL    *string           `json:"defect_issue_url"`
	EvidenceVersion   int               `json:"evidence_version,omitempty"`
	FailedNormalRunID *string           `json:"failed_normal_run_id"`
	Mode              string            `json:"mode"`
	Support           *v3ReleaseSupport `json:"support,omitempty"`
}

type defectIssue struct {
	IsPullRequest bool   `json:"is_pull_request"`
	State         string `json:"state"`
	URL           string `json:"url"`
}

type failedNormalRun struct {
	Conclusion string `json:"conclusion"`
	ID         string `json:"id"`
	Mode       string `json:"mode"`
	Path       string `json:"path"`
}

type observedAsset struct {
	Digest string `json:"digest"`
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
}

type observedIndex struct {
	Commit     string            `json:"commit"`
	Repository string            `json:"repository"`
	Schema     int               `json:"schema,omitempty"`
	Sequence   uint64            `json:"sequence"`
	SHA256     string            `json:"sha256"`
	Support    *v3ReleaseSupport `json:"support,omitempty"`
	Tag        string            `json:"tag"`
}

type observedRelease struct {
	Assets     []observedAsset `json:"assets"`
	Body       string          `json:"body"`
	Commit     string          `json:"commit"`
	Draft      bool            `json:"draft"`
	ID         int64           `json:"id"`
	Immutable  bool            `json:"immutable"`
	Index      *observedIndex  `json:"index"`
	Prerelease bool            `json:"prerelease"`
	Sequence   *uint64         `json:"sequence"`
	Tag        string          `json:"tag"`
}

type buildReleaseAction struct {
	Commit   string `json:"commit"`
	Sequence uint64 `json:"sequence"`
	Tag      string `json:"tag"`
	Type     string `json:"type"`
}

type decisionAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type decisionReleaseIdentity struct {
	Commit             string `json:"commit"`
	ReleaseIndexSHA256 string `json:"release_index_sha256"`
	Repository         string `json:"repository"`
	Tag                string `json:"tag"`
}

type useSourceReleaseAction struct {
	Assets          []decisionAsset         `json:"assets"`
	Commit          string                  `json:"commit"`
	Draft           bool                    `json:"draft"`
	Immutable       bool                    `json:"immutable"`
	Prerelease      bool                    `json:"prerelease"`
	ReleaseID       int64                   `json:"release_id"`
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
	Tag             string                  `json:"tag"`
	Type            string                  `json:"type"`
}

type qualificationDecision struct {
	Actions     []json.RawMessage `json:"actions"`
	FactsSHA256 string            `json:"facts_sha256"`
	Outcome     string            `json:"outcome"`
	Schema      string            `json:"schema"`
	SourceState string            `json:"source_state"`
	Stage       string            `json:"stage"`
}

type draftReleaseTarget struct {
	Assets          []decisionAsset         `json:"assets"`
	Commit          string                  `json:"commit"`
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
	Tag             string                  `json:"tag"`
}

type candidateDraftConstructionFacts struct {
	BuiltReleases     []draftReleaseTarget `json:"built_releases"`
	PreflightDecision json.RawMessage      `json:"preflight_decision"`
	PreflightFacts    json.RawMessage      `json:"preflight_facts"`
	Schema            string               `json:"schema"`
	Stage             string               `json:"stage"`
}

type constructDraftAction struct {
	Assets              []decisionAsset         `json:"assets"`
	Body                string                  `json:"body"`
	Commit              string                  `json:"commit"`
	Draft               bool                    `json:"draft"`
	FactsSHA256         string                  `json:"facts_sha256"`
	Immutable           bool                    `json:"immutable"`
	Name                string                  `json:"name"`
	Prerelease          bool                    `json:"prerelease"`
	PriorDecisionSHA256 string                  `json:"prior_decision_sha256"`
	ReleaseIdentity     decisionReleaseIdentity `json:"release_identity"`
	Sequence            uint64                  `json:"sequence"`
	Tag                 string                  `json:"tag"`
	Type                string                  `json:"type"`
}

type candidateDraftConstructionDecision struct {
	Actions             []constructDraftAction `json:"actions"`
	FactsSHA256         string                 `json:"facts_sha256"`
	Outcome             string                 `json:"outcome"`
	PriorDecisionSHA256 string                 `json:"prior_decision_sha256"`
	Schema              string                 `json:"schema"`
	Stage               string                 `json:"stage"`
}

type observedDraftAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type observedDraftDownload struct {
	Authenticated bool   `json:"authenticated"`
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
}

type observedDraft struct {
	Assets           []observedDraftAsset    `json:"assets"`
	Commit           string                  `json:"commit"`
	CreatedReleaseID int64                   `json:"created_release_id"`
	Downloads        []observedDraftDownload `json:"downloads"`
	Draft            bool                    `json:"draft"`
	Immutable        bool                    `json:"immutable"`
	Prerelease       bool                    `json:"prerelease"`
	ReleaseID        int64                   `json:"release_id"`
	ReleaseIdentity  decisionReleaseIdentity `json:"release_identity"`
	Sequence         uint64                  `json:"sequence"`
	Tag              string                  `json:"tag"`
}

type candidateDraftVerificationFacts struct {
	ConstructionDecision json.RawMessage `json:"construction_decision"`
	ConstructionFacts    json.RawMessage `json:"construction_facts"`
	Observations         []observedDraft `json:"observations"`
	Schema               string          `json:"schema"`
	Stage                string          `json:"stage"`
}

type verifiedDraftRelease struct {
	Assets          []decisionAsset         `json:"assets"`
	Commit          string                  `json:"commit"`
	Draft           bool                    `json:"draft"`
	Immutable       bool                    `json:"immutable"`
	Prerelease      bool                    `json:"prerelease"`
	ReleaseID       int64                   `json:"release_id"`
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
	Tag             string                  `json:"tag"`
}

type candidateDraftVerificationDecision struct {
	Actions             []json.RawMessage      `json:"actions"`
	FactsSHA256         string                 `json:"facts_sha256"`
	Outcome             string                 `json:"outcome"`
	PriorDecisionSHA256 string                 `json:"prior_decision_sha256"`
	Schema              string                 `json:"schema"`
	Stage               string                 `json:"stage"`
	VerifiedReleases    []verifiedDraftRelease `json:"verified_releases"`
}

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

type acceptanceVPSRunner struct {
	Architecture    string `json:"architecture"`
	GoToolchain     string `json:"go_toolchain"`
	OperatingSystem string `json:"operating_system"`
	PublicVerifier  string `json:"public_verifier"`
}

type acceptanceVPSRelease struct {
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
}

type acceptanceVPSJourney struct {
	A                           acceptanceVPSRelease `json:"a"`
	ActivatedRollback           json.RawMessage      `json:"activated_rollback"`
	B                           acceptanceVPSRelease `json:"b"`
	CheckInvalidation           json.RawMessage      `json:"check_invalidation"`
	CleanInstall                bool                 `json:"clean_install"`
	CommittedForwardRecovery    json.RawMessage      `json:"committed_forward_recovery"`
	ConcurrencyRefusal          json.RawMessage      `json:"concurrency_refusal"`
	LowerSequenceReplacement    json.RawMessage      `json:"lower_sequence_replacement"`
	MenuCheck                   json.RawMessage      `json:"menu_check"`
	Mode                        string               `json:"mode"`
	ObservedAt                  string               `json:"observed_at"`
	PreparedRollback            json.RawMessage      `json:"prepared_rollback"`
	ProductionUpdate            json.RawMessage      `json:"production_update"`
	QualificationManifestSHA256 string               `json:"qualification_manifest_sha256"`
	Schema                      string               `json:"schema"`
	SecretSafe                  bool                 `json:"secret_safe"`
	SSHContinuity               bool                 `json:"ssh_continuity"`
}

type acceptanceVPSResultFacts struct {
	EvaluationTime                string                 `json:"evaluation_time"`
	GitHubRoutingRestored         bool                   `json:"github_routing_restored"`
	Journey                       acceptanceVPSJourney   `json:"journey"`
	ObservedAt                    string                 `json:"observed_at"`
	PriorDecisionSHA256           string                 `json:"prior_decision_sha256"`
	QualificationBoundaryFacts    json.RawMessage        `json:"qualification_boundary_facts"`
	QualificationManifest         json.RawMessage        `json:"qualification_manifest"`
	QualificationManifestAttested bool                   `json:"qualification_manifest_attested"`
	Releases                      []qualificationRelease `json:"releases"`
	Runner                        acceptanceVPSRunner    `json:"runner"`
	Schema                        string                 `json:"schema"`
	Stage                         string                 `json:"stage"`
}

type acceptanceRecordSoftware struct {
	GoToolchain    string `json:"go_toolchain"`
	PublicVerifier string `json:"public_verifier"`
}

type acceptanceRecordStages struct {
	CodexLiveAcceptance    string `json:"codex_live_acceptance"`
	IntegratedVerification string `json:"integrated_verification"`
	ModuleVerification     string `json:"module_verification"`
	OwnerAcceptance        string `json:"owner_acceptance"`
	SeamVerification       string `json:"seam_verification"`
}

type acceptanceRecordJSON struct {
	AcceptedAt        string                   `json:"accepted_at"`
	Assets            []decisionAsset          `json:"assets"`
	Evidence          []string                 `json:"evidence"`
	Journey           acceptanceVPSJourney     `json:"journey"`
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
}

type acceptanceRecord struct {
	Body string `json:"body"`
	Tag  string `json:"tag"`
}

type acceptanceVPSResultDecision struct {
	FactsSHA256         string             `json:"facts_sha256"`
	Outcome             string             `json:"outcome"`
	PriorDecisionSHA256 string             `json:"prior_decision_sha256"`
	Records             []acceptanceRecord `json:"records"`
	Schema              string             `json:"schema"`
	Stage               string             `json:"stage"`
}

type v3PackageIdentity struct {
	Architecture     string `json:"architecture"`
	Name             string `json:"name"`
	Repository       string `json:"repository"`
	SHA256           string `json:"sha256"`
	SigningKeySHA256 string `json:"signing_key_sha256"`
	Size             int64  `json:"size"`
	Version          string `json:"version"`
}

type v3UninterruptedEvidence struct {
	CleanInstallation       bool   `json:"clean_installation"`
	DetailsComplete         bool   `json:"details_complete"`
	DisclosureBounded       bool   `json:"disclosure_bounded"`
	EgressMatched           bool   `json:"egress_matched"`
	FinalAbsenceComplete    bool   `json:"final_absence_complete"`
	InstalledIdentity       bool   `json:"installed_identity"`
	NotSetUp                bool   `json:"not_set_up"`
	OutsideRoutesDiffer     bool   `json:"outside_routes_differ"`
	RemovalResult           string `json:"removal_result"`
	RunnerConfigurationGone bool   `json:"runner_configuration_absent"`
	RunnerFileMode          string `json:"runner_file_mode"`
	RunnerListenerAbsent    bool   `json:"runner_listener_absent"`
	RunnerMemoryBacked      bool   `json:"runner_memory_backed"`
	RunnerProcessAbsent     bool   `json:"runner_process_absent"`
	Running                 bool   `json:"running"`
	SetupConfirmed          bool   `json:"setup_confirmed"`
	SetupResult             string `json:"setup_result"`
	SetupReviewed           bool   `json:"setup_reviewed"`
}

type v3FailureCase struct {
	FinalState      string `json:"final_state"`
	FinishingAction string `json:"finishing_action"`
	Name            string `json:"name"`
	PostDeathStatus string `json:"post_death_status"`
	TriggerEvent    string `json:"trigger_event"`
}

type v3SecretScan struct {
	ExactSecretsAbsent bool `json:"exact_secrets_absent"`
	PatternsAbsent     bool `json:"prohibited_patterns_absent"`
	RetainedEvidence   bool `json:"retained_evidence"`
	RunnerCapture      bool `json:"runner_capture"`
	VPSCapture         bool `json:"vps_capture"`
	WorkflowOutput     bool `json:"workflow_output"`
}

type v3StageTimes struct {
	AfterActivationCompletedAt  string `json:"after_activation_completed_at"`
	AfterRemovalCompletedAt     string `json:"after_removal_completed_at"`
	BeforeActivationCompletedAt string `json:"before_activation_completed_at"`
	CleanFootprintCompletedAt   string `json:"clean_footprint_completed_at"`
	CompleteRemovalCompletedAt  string `json:"complete_removal_completed_at"`
	JourneyStartedAt            string `json:"journey_started_at"`
	OwnershipDriftCompletedAt   string `json:"ownership_drift_completed_at"`
	RunnerCleanupCompletedAt    string `json:"runner_cleanup_completed_at"`
	UninterruptedCompletedAt    string `json:"uninterrupted_completed_at"`
}

type v3PackagedLiveEvidence struct {
	FailureCases                []v3FailureCase         `json:"failure_cases"`
	ObservedAt                  string                  `json:"observed_at"`
	OutsideClientPackage        v3PackageIdentity       `json:"outside_client_package"`
	ProxyPackage                v3PackageIdentity       `json:"proxy_package"`
	QualificationManifestSHA256 string                  `json:"qualification_manifest_sha256"`
	Schema                      string                  `json:"schema"`
	SecretScan                  v3SecretScan            `json:"secret_scan"`
	StageTimes                  v3StageTimes            `json:"stage_times"`
	Uninterrupted               v3UninterruptedEvidence `json:"uninterrupted"`
}

type v3PackagedLiveResultFacts struct {
	DetailedEvidence            v3PackagedLiveEvidence `json:"detailed_evidence"`
	DetailedEvidenceSHA256      string                 `json:"detailed_evidence_sha256"`
	EvaluationTime              string                 `json:"evaluation_time"`
	ObservedAt                  string                 `json:"observed_at"`
	PriorDecisionSHA256         string                 `json:"prior_decision_sha256"`
	QualificationBoundaryFacts  json.RawMessage        `json:"qualification_boundary_facts"`
	QualificationManifest       json.RawMessage        `json:"qualification_manifest"`
	QualificationManifestSigned bool                   `json:"qualification_manifest_attested"`
	Releases                    []qualificationRelease `json:"releases"`
	Runner                      acceptanceVPSRunner    `json:"runner"`
	Schema                      string                 `json:"schema"`
	Stage                       string                 `json:"stage"`
}

type v3AcceptanceRecordJSON struct {
	AcceptedAt             string                   `json:"accepted_at"`
	Assets                 []decisionAsset          `json:"assets"`
	DetailedEvidenceSHA256 string                   `json:"detailed_evidence_sha256"`
	Evidence               []string                 `json:"evidence"`
	OutsideClientPackage   v3PackageIdentity        `json:"outside_client_package"`
	ProxyPackage           v3PackageIdentity        `json:"proxy_package"`
	QualificationRole      string                   `json:"qualification_role"`
	ReleaseIdentity        decisionReleaseIdentity  `json:"release_identity"`
	Runner                 string                   `json:"runner"`
	Schema                 string                   `json:"schema"`
	SecretSafeResult       string                   `json:"secret_safe_result"`
	Sequence               uint64                   `json:"sequence"`
	Software               acceptanceRecordSoftware `json:"software"`
	StableResultCode       string                   `json:"stable_result_code"`
	Stages                 acceptanceRecordStages   `json:"stages"`
	WorkflowRun            string                   `json:"workflow_run"`
}

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
	case v3PackagedLiveResultStage:
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
	return stableV3FinalizationDecision{Actions: []json.RawMessage{}, CompleteRemoval: "Passed", FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, PublicVerification: "Passed", Schema: qualificationDecisionSchema, Stage: stableV3FinalizationStage, V3PackagedLive: "Passed"}, nil
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
	recurring := manifest.Schema == "sbxr-qualification-manifest-v2" && manifest.Mode == "v3" && manifest.SourceState == "v3-recurring" && manifest.V3Attempt != nil && len(manifest.V3Attempt.Sources) > 0 && slices.Equal(manifest.V3Attempt.RequiredScenarios, requiredV3Scenarios(manifest.V3Attempt.Sources))
	scoped := manifest.Schema == "sbxr-qualification-manifest-v3" && manifest.Mode == "v3" && manifest.V3Attempt != nil && attemptVersion(manifest.V3Attempt) == "v3" && manifest.V3Attempt.Baseline != nil && validAttemptSupport(*manifest.V3Attempt) && len(manifest.Releases) == 1 && validAttemptIndex(*manifest.V3Attempt, manifest.Releases[0]) && ((manifest.SourceState == "v3-subscription-clean" && manifest.V3Attempt.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall) || (manifest.SourceState == "v3-recurring" && manifest.V3Attempt.Support.Scope == softwarelifecycle.RecurringSubscriptionUpgrade))
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
	if !observation.PubliclyVerified || !observation.ReleasePresent || observation.Draft || !observation.Immutable || observation.Prerelease || observation.TagCommit == nil || !strings.Contains(observation.Body, "Status: Qualified\n") {
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
	if softwarelifecycle.ValidateUniqueJSON(recordBytes) != nil || json.Unmarshal(recordBytes, &source) != nil || (source.Schema != "sbxr-acceptance-record-v1" && !((source.Schema == "sbxr-acceptance-record-v2" || source.Schema == "sbxr-acceptance-record-v3" && manifest.Schema == "sbxr-qualification-manifest-v3") && manifest.V3Attempt != nil)) || source.ReleaseIdentity != release.ReleaseIdentity || source.Sequence != release.Sequence || !reflect.DeepEqual(source.Assets, release.Assets) || source.SecretSafeResult != "Passed" || source.Stages.ModuleVerification != "Passed" || source.Stages.SeamVerification != "Passed" {
		return "", errors.New("qualified Acceptance Record refused")
	}
	failedRetry := strings.Contains(sourceBody, "Status: Failed prerelease\n")
	if !failedRetry && !strings.Contains(sourceBody, "Status: Qualified\n") {
		return "", errors.New("qualified Acceptance Record refused")
	}
	if failedRetry && (source.StableResultCode != "RELEASE-INSTALLER-UPDATER-PREPUBLICATION-FAILED" || source.WorkflowRun != workflowRun) || !failedRetry && source.WorkflowRun != manifest.Workflow.RunURL {
		return "", errors.New("qualified Acceptance Record refused")
	}
	if !failedRetry {
		var canonicalSource []byte
		var err error
		if source.StableResultCode == "RELEASE-V3-SUBSCRIPTION-QUALIFICATION" || source.StableResultCode == "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION" {
			var recurring v3RecurringAcceptanceRecord
			if !decodeCanonical(recordBytes, &recurring) || manifest.V3Attempt == nil || !reflect.DeepEqual(recurring.Attempt, *manifest.V3Attempt) {
				return "", errors.New("qualified Acceptance Record refused")
			}
			canonicalSource, err = marshalCanonical(recurring)
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
		return !observation.Immutable && observation.Attestation == nil && observation.LatestInstallSHA256 == "" && reflect.DeepEqual(observation.LatestReleaseID, prior.LatestReleaseID) && pendingPublicLatestVerification(observation.PublicVerification, action, false)
	}
	latestPending := reflect.DeepEqual(observation.LatestReleaseID, prior.LatestReleaseID) && observation.LatestInstallSHA256 == "" || observation.LatestReleaseID != nil && *observation.LatestReleaseID == action.ReleaseID && (observation.LatestInstallSHA256 == "" || observation.LatestInstallSHA256 == action.Assets[0].SHA256)
	attestationPending := observation.Attestation == nil || *observation.Attestation == (stableReleaseAttestation{Commit: action.Commit, Count: 0, Initiator: "", PredicateType: "release"}) || *observation.Attestation == (stableReleaseAttestation{Commit: action.Commit, Count: 1, Initiator: "github", PredicateType: "release"})
	return latestPending && attestationPending && pendingPublicLatestVerification(observation.PublicVerification, action, observation.LatestReleaseID != nil && *observation.LatestReleaseID == action.ReleaseID)
}

func validPublicLatestVerification(verification *publicLatestVerification, action publishStableReleaseAction) bool {
	return verification != nil && verification.Outcome == "accepted" && verification.ReleaseIdentity != nil && *verification.ReleaseIdentity == action.ReleaseIdentity && verification.Sequence != nil && *verification.Sequence == action.Sequence
}

func pendingPublicLatestVerification(verification *publicLatestVerification, action publishStableReleaseAction, targetIsLatest bool) bool {
	if verification == nil {
		return false
	}
	switch verification.Outcome {
	case "unavailable":
		return verification.ReleaseIdentity == nil && verification.Sequence == nil
	case "accepted":
		return verification.ReleaseIdentity != nil && verification.Sequence != nil && (!targetIsLatest || *verification.ReleaseIdentity == action.ReleaseIdentity && *verification.Sequence == action.Sequence)
	default:
		return false
	}
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

func secretBearing(document []byte) bool {
	return bytes.Contains(document, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(document, []byte("BEGIN RSA PRIVATE KEY")) || bytes.Contains(document, []byte("BEGIN EC PRIVATE KEY")) || bytes.Contains(document, []byte("BEGIN OPENSSH PRIVATE KEY")) || bytes.Contains(document, []byte("Authorization: Bearer "))
}

func evaluateAcceptanceVPSResult(facts acceptanceVPSResultFacts, document []byte) (acceptanceVPSResultDecision, error) {
	refused := func() (acceptanceVPSResultDecision, error) {
		return acceptanceVPSResultDecision{}, errors.New("acceptance VPS result refused")
	}
	observedAt, timeErr := time.Parse(time.RFC3339, facts.ObservedAt)
	evaluationTime, evaluationTimeErr := time.Parse(time.RFC3339, facts.EvaluationTime)
	age := evaluationTime.Sub(observedAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != acceptanceVPSResultStage || !facts.GitHubRoutingRestored || !facts.QualificationManifestAttested || facts.Releases == nil || !validSHA256(facts.PriorDecisionSHA256) || timeErr != nil || evaluationTimeErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || evaluationTime.Format(time.RFC3339) != facts.EvaluationTime || age < 0 || age > 5*time.Minute || !validAcceptanceRunner(facts.Runner) || !validAcceptanceJourney(facts.Journey) {
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
	if err != nil || !bytes.Equal(manifestBytes, facts.QualificationManifest) || facts.PriorDecisionSHA256 != documentSHA256(facts.QualificationManifest) || !reflect.DeepEqual(facts.Releases, manifest.Releases) || !validAcceptanceJourneyBinding(facts, manifest) {
		return refused()
	}
	records := make([]acceptanceRecord, len(manifest.Releases))
	for index, release := range manifest.Releases {
		role := "Discovered, installed, recovered, final latest release"
		if manifest.Mode == "rescue" {
			role = "Rescue direct-install and lower-sequence replacement release"
		} else if index == 0 {
			role = "Clean-installed source release"
		}
		body, err := buildSuccessfulAcceptanceRecord(manifest, facts, release, role)
		if err != nil {
			return refused()
		}
		records[index] = acceptanceRecord{Body: body, Tag: release.Tag}
	}
	return acceptanceVPSResultDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, Records: records, Schema: qualificationDecisionSchema, Stage: acceptanceVPSResultStage}, nil
}

func evaluateV3PackagedLiveResult(facts v3PackagedLiveResultFacts, document []byte) (acceptanceVPSResultDecision, error) {
	refused := func() (acceptanceVPSResultDecision, error) {
		return acceptanceVPSResultDecision{}, errors.New("V3 packaged live result refused")
	}
	observedAt, observedErr := time.Parse(time.RFC3339, facts.ObservedAt)
	evaluationTime, evaluationErr := time.Parse(time.RFC3339, facts.EvaluationTime)
	evidenceBytes, evidenceErr := marshalCanonical(facts.DetailedEvidence)
	if facts.Schema != qualificationFactsSchema || facts.Stage != v3PackagedLiveResultStage || !facts.QualificationManifestSigned || len(facts.Releases) != 1 || !validSHA256(facts.PriorDecisionSHA256) || !validSHA256(facts.DetailedEvidenceSHA256) || observedErr != nil || evaluationErr != nil || observedAt.Format(time.RFC3339) != facts.ObservedAt || evaluationTime.Format(time.RFC3339) != facts.EvaluationTime || evaluationTime.Sub(observedAt) < 0 || evaluationTime.Sub(observedAt) > 5*time.Minute || evidenceErr != nil || facts.DetailedEvidenceSHA256 != documentSHA256(evidenceBytes) || secretBearing(document) || rawV3Secret(document) || !validAcceptanceRunner(facts.Runner) || !validV3Evidence(facts.DetailedEvidence, facts.ObservedAt, facts.PriorDecisionSHA256) {
		return refused()
	}
	var boundaryFacts qualificationBoundaryFacts
	if !decodeCanonical(facts.QualificationBoundaryFacts, &boundaryFacts) {
		return refused()
	}
	manifest, err := evaluateQualificationBoundary(boundaryFacts)
	if err != nil || manifest.Mode != "v3" || manifest.SourceState != "v3-clean" || len(manifest.Releases) != 1 {
		return refused()
	}
	manifestBytes, err := marshalCanonical(manifest)
	if err != nil || !bytes.Equal(manifestBytes, facts.QualificationManifest) || facts.PriorDecisionSHA256 != documentSHA256(facts.QualificationManifest) || !reflect.DeepEqual(facts.Releases, manifest.Releases) {
		return refused()
	}
	body, err := buildV3AcceptanceRecord(manifest, facts)
	if err != nil {
		return refused()
	}
	return acceptanceVPSResultDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, Records: []acceptanceRecord{{Body: body, Tag: manifest.Releases[0].Tag}}, Schema: qualificationDecisionSchema, Stage: v3PackagedLiveResultStage}, nil
}

func rawV3Secret(document []byte) bool {
	return regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}`).Match(document) || regexp.MustCompile(`(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:[^0-9]|$)`).Match(document)
}

func validV3Evidence(evidence v3PackagedLiveEvidence, observedAt, manifestSHA256 string) bool {
	if evidence.Schema != "sbxr-v3-packaged-live-evidence-v1" || evidence.ObservedAt != observedAt || evidence.QualificationManifestSHA256 != manifestSHA256 || evidence.ProxyPackage != expectedV3PackageIdentity() || evidence.OutsideClientPackage != expectedV3PackageIdentity() || evidence.FailureCases == nil || !validV3StageTimes(evidence.StageTimes, observedAt) {
		return false
	}
	uninterrupted := evidence.Uninterrupted
	if !uninterrupted.CleanInstallation || !uninterrupted.InstalledIdentity || !uninterrupted.NotSetUp || !uninterrupted.SetupReviewed || !uninterrupted.SetupConfirmed || uninterrupted.SetupResult != "PROXY-INSTALLATION-SETUP-COMPLETE" || !uninterrupted.Running || !uninterrupted.DetailsComplete || !uninterrupted.DisclosureBounded || !uninterrupted.OutsideRoutesDiffer || !uninterrupted.EgressMatched || !uninterrupted.RunnerMemoryBacked || uninterrupted.RunnerFileMode != "0600" || !uninterrupted.RunnerProcessAbsent || !uninterrupted.RunnerListenerAbsent || !uninterrupted.RunnerConfigurationGone || uninterrupted.RemovalResult != "SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED" || !uninterrupted.FinalAbsenceComplete {
		return false
	}
	expectedFailures := []v3FailureCase{
		{Name: "clean-footprint-refusal", TriggerEvent: "Detected mismatch: /etc/sing-box is present", PostDeathStatus: "Not set up", FinishingAction: "Remove qualification conflict", FinalState: "Not set up"},
		{Name: "before-activation-commitment", TriggerEvent: "Validate configuration", PostDeathStatus: "Setup incomplete", FinishingAction: "Finish cleanup", FinalState: "Not set up"},
		{Name: "after-activation-commitment", TriggerEvent: "Activation committed", PostDeathStatus: "Setup incomplete", FinishingAction: "Finish setup", FinalState: "Running"},
		{Name: "ownership-drift-removal-refusal", TriggerEvent: "Detected mismatch: the protected configuration identity does not match", PostDeathStatus: "Problem detected", FinishingAction: "Restore recorded metadata", FinalState: "Running"},
		{Name: "after-removal-commitment", TriggerEvent: "Removal committed", PostDeathStatus: "Removal incomplete", FinishingAction: "Finish removal", FinalState: "Not installed"},
	}
	return reflect.DeepEqual(evidence.FailureCases, expectedFailures) && evidence.SecretScan == (v3SecretScan{RetainedEvidence: true, RunnerCapture: true, VPSCapture: true, WorkflowOutput: true, ExactSecretsAbsent: true, PatternsAbsent: true})
}

func validV3StageTimes(stage v3StageTimes, observedAt string) bool {
	values := []string{stage.JourneyStartedAt, stage.CleanFootprintCompletedAt, stage.BeforeActivationCompletedAt, stage.AfterActivationCompletedAt, stage.OwnershipDriftCompletedAt, stage.AfterRemovalCompletedAt, stage.UninterruptedCompletedAt, stage.RunnerCleanupCompletedAt, stage.CompleteRemovalCompletedAt}
	parsed := make([]time.Time, len(values))
	for index, value := range values {
		var err error
		parsed[index], err = time.Parse(time.RFC3339, value)
		if err != nil || parsed[index].Format(time.RFC3339) != value || index > 0 && parsed[index].Before(parsed[index-1]) {
			return false
		}
	}
	return stage.CompleteRemovalCompletedAt == observedAt && parsed[len(parsed)-1].Sub(parsed[0]) <= 2*time.Hour
}

func expectedV3PackageIdentity() v3PackageIdentity {
	return v3PackageIdentity{Repository: "https://deb.sagernet.org/", SigningKeySHA256: "803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1", Name: "sing-box", Version: "1.13.19", Architecture: "amd64", Size: 24597120, SHA256: "fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf"}
}

func buildV3AcceptanceRecord(manifest qualificationManifest, facts v3PackagedLiveResultFacts) (string, error) {
	release := manifest.Releases[0]
	record := v3AcceptanceRecordJSON{
		AcceptedAt: facts.ObservedAt, Assets: release.Assets, DetailedEvidenceSHA256: facts.DetailedEvidenceSHA256, Evidence: []string{manifest.Workflow.RunURL + "#artifacts"}, OutsideClientPackage: facts.DetailedEvidence.OutsideClientPackage, ProxyPackage: facts.DetailedEvidence.ProxyPackage,
		QualificationRole: "Clean-installed V3 release", ReleaseIdentity: release.ReleaseIdentity, Runner: facts.Runner.OperatingSystem + " linux/" + facts.Runner.Architecture, Schema: "sbxr-acceptance-record-v1", SecretSafeResult: "Passed", Sequence: release.Sequence,
		Software: acceptanceRecordSoftware{GoToolchain: facts.Runner.GoToolchain, PublicVerifier: facts.Runner.PublicVerifier}, StableResultCode: "RELEASE-V3-PACKAGED-LIVE-QUALIFICATION",
		Stages: acceptanceRecordStages{CodexLiveAcceptance: "Passed", IntegratedVerification: "Passed on live Ubuntu Server 24.04 amd64 and outside runner", ModuleVerification: "Passed", OwnerAcceptance: "Not required", SeamVerification: "Passed"}, WorkflowRun: manifest.Workflow.RunURL,
	}
	canonical, err := marshalCanonical(record)
	if err != nil {
		return "", err
	}
	var body strings.Builder
	for _, line := range []string{"# SBXR Acceptance Record", "Status: Qualified", "Repository: " + release.ReleaseIdentity.Repository, "Tag: " + release.Tag, "Commit: " + release.Commit, "Release index SHA-256: " + release.ReleaseIdentity.ReleaseIndexSHA256, "Sequence: " + strconv.FormatUint(release.Sequence, 10), "Workflow evidence: " + record.WorkflowRun, "Acceptance time: " + record.AcceptedAt, "Runner: " + record.Runner, "Go toolchain: " + facts.Runner.GoToolchain, "Public verifier: " + facts.Runner.PublicVerifier, "Qualification role: Clean-installed V3 release", "Detailed evidence SHA-256: " + record.DetailedEvidenceSHA256, "Proxy package: sing-box 1.13.19 amd64 " + record.ProxyPackage.SHA256, "Outside-client package: sing-box 1.13.19 amd64 " + record.OutsideClientPackage.SHA256, "Secret-safe result: Passed", "Stable result code: " + record.StableResultCode, "Module Verification: Passed", "Seam Verification: Passed", "Integrated Verification: " + record.Stages.IntegratedVerification, "Codex Live Acceptance: Passed", "Owner Acceptance: Not required"} {
		body.WriteString(line + "\n")
	}
	for _, asset := range release.Assets {
		body.WriteString("Asset: " + asset.Name + " " + strconv.FormatInt(asset.Size, 10) + " " + asset.SHA256 + "\n")
	}
	body.WriteString("```json\n" + string(canonical) + "\n```\n")
	return body.String(), nil
}

func validAcceptanceJourneyBinding(facts acceptanceVPSResultFacts, manifest qualificationManifest) bool {
	if len(manifest.Releases) != 2 || facts.Journey.Mode != manifest.Mode || facts.Journey.ObservedAt != facts.ObservedAt || facts.Journey.QualificationManifestSHA256 != facts.PriorDecisionSHA256 {
		return false
	}
	a := acceptanceVPSRelease{ReleaseIdentity: manifest.Releases[0].ReleaseIdentity, Sequence: manifest.Releases[0].Sequence}
	b := acceptanceVPSRelease{ReleaseIdentity: manifest.Releases[1].ReleaseIdentity, Sequence: manifest.Releases[1].Sequence}
	return facts.Journey.A == a && facts.Journey.B == b
}

func validAcceptanceRunner(runner acceptanceVPSRunner) bool {
	return runner.OperatingSystem == "Ubuntu Server 24.04" && runner.Architecture == "amd64" && regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(runner.GoToolchain) && regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+ [A-F0-9]{64}$`).MatchString(runner.PublicVerifier)
}

func validAcceptanceJourney(journey acceptanceVPSJourney) bool {
	if journey.Schema != "sbxr-acceptance-vps-evidence-v1" || !journey.CleanInstall || !journey.SecretSafe || !journey.SSHContinuity {
		return false
	}
	trueValue := json.RawMessage("true")
	normalWaiver := json.RawMessage(`"Not required - normal authority"`)
	rescueWaiver := json.RawMessage(`"Not required - rescue authority"`)
	automated := json.RawMessage(`"Proved by native automated qualification"`)
	switch journey.Mode {
	case "normal":
		return bytes.Equal(journey.ActivatedRollback, trueValue) && bytes.Equal(journey.CheckInvalidation, trueValue) && bytes.Equal(journey.CommittedForwardRecovery, trueValue) && bytes.Equal(journey.ConcurrencyRefusal, trueValue) && bytes.Equal(journey.LowerSequenceReplacement, normalWaiver) && bytes.Equal(journey.MenuCheck, trueValue) && bytes.Equal(journey.PreparedRollback, trueValue) && bytes.Equal(journey.ProductionUpdate, trueValue)
	case "rescue":
		return bytes.Equal(journey.ActivatedRollback, rescueWaiver) && bytes.Equal(journey.CheckInvalidation, automated) && bytes.Equal(journey.CommittedForwardRecovery, rescueWaiver) && bytes.Equal(journey.ConcurrencyRefusal, automated) && bytes.Equal(journey.LowerSequenceReplacement, trueValue) && bytes.Equal(journey.MenuCheck, rescueWaiver) && bytes.Equal(journey.PreparedRollback, rescueWaiver) && bytes.Equal(journey.ProductionUpdate, rescueWaiver)
	default:
		return false
	}
}

func buildSuccessfulAcceptanceRecord(manifest qualificationManifest, facts acceptanceVPSResultFacts, release qualificationRelease, role string) (string, error) {
	code := "RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION"
	if manifest.Mode == "rescue" {
		code = "RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION"
	}
	runner := facts.Runner.OperatingSystem + " linux/" + facts.Runner.Architecture
	recordJSON := acceptanceRecordJSON{
		AcceptedAt: facts.ObservedAt, Assets: release.Assets, Evidence: []string{manifest.Workflow.RunURL + "#artifacts"}, Journey: facts.Journey, QualificationRole: role,
		ReleaseIdentity: release.ReleaseIdentity, Runner: runner, Schema: "sbxr-acceptance-record-v1", SecretSafeResult: "Passed", Sequence: release.Sequence,
		Software: acceptanceRecordSoftware{GoToolchain: facts.Runner.GoToolchain, PublicVerifier: facts.Runner.PublicVerifier}, StableResultCode: code,
		Stages: acceptanceRecordStages{CodexLiveAcceptance: "Passed", IntegratedVerification: "Passed on live Ubuntu Server 24.04 amd64", ModuleVerification: "Passed", OwnerAcceptance: "Not required", SeamVerification: "Passed"}, WorkflowRun: manifest.Workflow.RunURL,
	}
	canonical, err := marshalCanonical(recordJSON)
	if err != nil {
		return "", err
	}
	var body strings.Builder
	for _, line := range []string{
		"# SBXR Installer-Updater Acceptance Record", "Status: Qualified", "Repository: " + recordJSON.ReleaseIdentity.Repository, "Tag: " + recordJSON.ReleaseIdentity.Tag, "Commit: " + recordJSON.ReleaseIdentity.Commit,
		"Release index SHA-256: " + recordJSON.ReleaseIdentity.ReleaseIndexSHA256, "Sequence: " + strconv.FormatUint(recordJSON.Sequence, 10), "Workflow evidence: " + recordJSON.WorkflowRun,
		"Acceptance time: " + recordJSON.AcceptedAt, "Runner: " + recordJSON.Runner, "Go toolchain: " + recordJSON.Software.GoToolchain, "Public verifier: " + recordJSON.Software.PublicVerifier,
		"Secret-safe result: " + recordJSON.SecretSafeResult, "Qualification role: " + recordJSON.QualificationRole, "Stable result code: " + recordJSON.StableResultCode, "Module Verification: " + recordJSON.Stages.ModuleVerification, "Seam Verification: " + recordJSON.Stages.SeamVerification,
		"Integrated Verification: " + recordJSON.Stages.IntegratedVerification, "Codex Live Acceptance: " + recordJSON.Stages.CodexLiveAcceptance, "Owner Acceptance: " + recordJSON.Stages.OwnerAcceptance,
	} {
		body.WriteString(line + "\n")
	}
	for _, asset := range recordJSON.Assets {
		body.WriteString("Asset: " + asset.Name + " " + strconv.FormatInt(asset.Size, 10) + " " + asset.SHA256 + "\n")
	}
	if manifest.Mode == "rescue" {
		body.WriteString("Rescue defect evidence: " + manifest.Rescue.DefectIssueURL + "\nFailed normal run evidence: " + failedRunURL(manifest.Rescue.FailedNormalRunID) + "\nNormal journey waiver: Reproducible installed-source defect made the normal menu journey impossible\n")
	}
	body.WriteString("```json\n" + string(canonical) + "\n```\n")
	return body.String(), nil
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

func decodeCanonical(document []byte, value any) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false
	}
	canonical, err := marshalCanonical(value)
	return err == nil && bytes.Equal(canonical, document)
}

func evaluateCandidateDraftConstruction(facts candidateDraftConstructionFacts, document []byte) (candidateDraftConstructionDecision, error) {
	if facts.Schema != qualificationFactsSchema || facts.Stage != candidateDraftConstructionStage || facts.BuiltReleases == nil {
		return candidateDraftConstructionDecision{}, errors.New("candidate draft construction refused")
	}
	preflight, err := verifiedPreflightDecision(facts.PreflightFacts, facts.PreflightDecision)
	if err != nil {
		return candidateDraftConstructionDecision{}, err
	}
	builds, ok := preflightBuildActions(preflight)
	if !ok || len(builds) != len(facts.BuiltReleases) {
		return candidateDraftConstructionDecision{}, errors.New("candidate draft construction refused")
	}
	factsDigest := documentSHA256(document)
	priorDigest := documentSHA256(facts.PreflightDecision)
	actions := make([]constructDraftAction, len(builds))
	for index, build := range builds {
		target := facts.BuiltReleases[index]
		if target.Commit != build.Commit || target.Sequence != build.Sequence || target.Tag != build.Tag || !validDraftTarget(target) {
			return candidateDraftConstructionDecision{}, errors.New("candidate draft construction refused")
		}
		actions[index] = constructDraftAction{Assets: target.Assets, Body: "Qualification pending.", Commit: target.Commit, Draft: true, FactsSHA256: factsDigest, Name: target.Tag, PriorDecisionSHA256: priorDigest, ReleaseIdentity: target.ReleaseIdentity, Sequence: target.Sequence, Tag: target.Tag, Type: "construct-draft"}
	}
	return candidateDraftConstructionDecision{Actions: actions, FactsSHA256: factsDigest, Outcome: "actions-required", PriorDecisionSHA256: priorDigest, Schema: qualificationDecisionSchema, Stage: candidateDraftConstructionStage}, nil
}

func evaluateCandidateDraftVerification(facts candidateDraftVerificationFacts, document []byte) (candidateDraftVerificationDecision, error) {
	if facts.Schema != qualificationFactsSchema || facts.Stage != candidateDraftVerificationStage || facts.Observations == nil {
		return candidateDraftVerificationDecision{}, errors.New("candidate draft verification refused")
	}
	var constructionFacts candidateDraftConstructionFacts
	if !decodeCanonical(facts.ConstructionFacts, &constructionFacts) {
		return candidateDraftVerificationDecision{}, errors.New("candidate draft verification refused")
	}
	expected, err := evaluateCandidateDraftConstruction(constructionFacts, facts.ConstructionFacts)
	if err != nil {
		return candidateDraftVerificationDecision{}, errors.New("candidate draft verification refused")
	}
	expectedBytes, err := marshalCanonical(expected)
	if err != nil || !bytes.Equal(expectedBytes, facts.ConstructionDecision) || len(facts.Observations) != len(expected.Actions) {
		return candidateDraftVerificationDecision{}, errors.New("candidate draft verification refused")
	}
	verified := make([]verifiedDraftRelease, len(expected.Actions))
	seenReleaseIDs := map[int64]bool{}
	seenAssetIDs := map[int64]bool{}
	for index, action := range expected.Actions {
		observation := facts.Observations[index]
		if seenReleaseIDs[observation.ReleaseID] || !validDraftObservation(observation, action, seenAssetIDs) {
			return candidateDraftVerificationDecision{}, errors.New("candidate draft verification refused")
		}
		seenReleaseIDs[observation.ReleaseID] = true
		verified[index] = verifiedDraftRelease{Assets: action.Assets, Commit: action.Commit, Draft: observation.Draft, Immutable: observation.Immutable, Prerelease: observation.Prerelease, ReleaseID: observation.ReleaseID, ReleaseIdentity: action.ReleaseIdentity, Sequence: action.Sequence, Tag: action.Tag}
	}
	return candidateDraftVerificationDecision{Actions: []json.RawMessage{}, FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: documentSHA256(facts.ConstructionDecision), Schema: qualificationDecisionSchema, Stage: candidateDraftVerificationStage, VerifiedReleases: verified}, nil
}

func verifiedPreflightDecision(factsDocument, decisionDocument []byte) (qualificationDecision, error) {
	var facts qualificationFacts
	if !decodeCanonical(factsDocument, &facts) {
		return qualificationDecision{}, errors.New("candidate draft construction refused")
	}
	expected, err := evaluateCandidatePreflight(facts, factsDocument)
	if err != nil {
		return qualificationDecision{}, errors.New("candidate draft construction refused")
	}
	expectedBytes, err := marshalCanonical(expected)
	if err != nil || !bytes.Equal(expectedBytes, decisionDocument) {
		return qualificationDecision{}, errors.New("candidate draft construction refused")
	}
	return expected, nil
}

func preflightBuildActions(decision qualificationDecision) ([]buildReleaseAction, bool) {
	builds := make([]buildReleaseAction, 0, len(decision.Actions))
	for _, raw := range decision.Actions {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &kind) != nil {
			return nil, false
		}
		if kind.Type != "build-release" {
			continue
		}
		var action buildReleaseAction
		if !decodeCanonical(raw, &action) {
			return nil, false
		}
		builds = append(builds, action)
	}
	return builds, true
}

func validDraftTarget(target draftReleaseTarget) bool {
	if !validCommit(target.Commit) || target.Sequence == 0 || !validTag(target.Tag) || target.ReleaseIdentity.Repository != softwarelifecycle.Repository || target.ReleaseIdentity.Tag != target.Tag || target.ReleaseIdentity.Commit != target.Commit || !validSHA256(target.ReleaseIdentity.ReleaseIndexSHA256) || len(target.Assets) != 4 {
		return false
	}
	expected := softwarelifecycle.LatestReleaseAssetNames()
	for index, asset := range target.Assets {
		if asset.Name != expected[index] || asset.Size <= 0 || !validSHA256(asset.SHA256) || asset.Name == "release-index.json" && asset.SHA256 != target.ReleaseIdentity.ReleaseIndexSHA256 {
			return false
		}
	}
	return true
}

func validDraftObservation(observation observedDraft, action constructDraftAction, seenAssetIDs map[int64]bool) bool {
	if observation.ReleaseID <= 0 || observation.CreatedReleaseID != observation.ReleaseID || observation.Draft != action.Draft || observation.Prerelease != action.Prerelease || observation.Immutable != action.Immutable || observation.Commit != action.Commit || observation.Sequence != action.Sequence || observation.Tag != action.Tag || observation.ReleaseIdentity != action.ReleaseIdentity || len(observation.Assets) != len(action.Assets) || len(observation.Downloads) != len(action.Assets) {
		return false
	}
	for index, expected := range action.Assets {
		asset, download := observation.Assets[index], observation.Downloads[index]
		if asset.ID <= 0 || seenAssetIDs[asset.ID] || asset.Name != expected.Name || asset.Size != expected.Size || asset.SHA256 != expected.SHA256 || !download.Authenticated || download.ID != asset.ID || download.Name != asset.Name || download.Size != asset.Size || download.SHA256 != asset.SHA256 {
			return false
		}
		seenAssetIDs[asset.ID] = true
	}
	return true
}

func documentSHA256(document []byte) string {
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:])
}

func evaluateCandidatePreflight(facts qualificationFacts, document []byte) (qualificationDecision, error) {
	candidate := facts.Candidate
	if candidate.EvidenceVersion != 3 && (candidate.Support != nil || facts.SubscriptionHistory != nil) {
		return qualificationDecision{}, errors.New("historical scope override refused")
	}
	if candidate.Mode != "v3" && hasQualifiedV3(facts.Releases) {
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	if candidate.EvidenceVersion != 0 && (candidate.Mode != "v3" || candidate.EvidenceVersion != 2 && candidate.EvidenceVersion != 3) {
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	if candidate.EvidenceVersion >= 2 && recurringSecret(document) {
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	if facts.Schema != qualificationFactsSchema || facts.Stage != candidatePreflightStage ||
		!validCommit(facts.Commit) || facts.RemoteMain != facts.Commit ||
		!validCommit(facts.ArchiveCommit) || facts.ArchiveCommit != facts.ArchiveRemoteCommit ||
		!validCommit(facts.ArchiveTagObject) || facts.ArchiveTagObject != facts.ArchiveRemoteTagObject ||
		facts.ArchiveType != "tag" ||
		!validSHA256(facts.ChecklistSHA256) || facts.BurnedIdentities == nil || facts.Releases == nil || facts.Tags == nil ||
		!validObservedFacts(facts) {
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	if candidate.Mode == "v3" {
		if candidate.ATag != "" || candidate.ASequence != 0 || !validTag(candidate.BTag) || candidate.BSequence == 0 {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
	} else if !validTag(candidate.ATag) || !validTag(candidate.BTag) || candidate.ATag == candidate.BTag || candidate.ASequence == 0 || candidate.BSequence <= candidate.ASequence {
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	var actions []json.RawMessage
	var sourceState string
	switch candidate.Mode {
	case "v3":
		if candidate.DefectIssueURL != nil || candidate.FailedNormalRunID != nil || facts.DefectIssue != nil || facts.FailedNormalRun != nil || candidate.EvidenceVersion == 0 && hasQualifiedV3(facts.Releases) || tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) || candidate.BSequence != highestSequence(facts)+1 {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		sourceState = "v3-clean"
		if candidate.EvidenceVersion == 2 {
			if facts.LatestTag == nil {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			source, exists := releaseByTag(facts.Releases, *facts.LatestTag)
			if !exists || !qualifiedV3Source(source) {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			sourceState = "v3-recurring"
		}
		if candidate.EvidenceVersion == 3 {
			if candidate.Support == nil || facts.LatestTag == nil || !reflect.DeepEqual(facts.Releases, historyReleases(facts.SubscriptionHistory)) || !validSubscriptionHistory(facts.SubscriptionHistory, candidate.Support.Scope, nil) || facts.SubscriptionHistory.PublicLatest.ReleaseIdentity.Tag != *facts.LatestTag || !validSupportDeclaration(*candidate.Support) {
				return qualificationDecision{}, errors.New("subscription scope refused")
			}
			sourceState = "v3-recurring"
			if candidate.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall {
				sourceState = "v3-subscription-clean"
			}
		}
		actions = []json.RawMessage{mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
	case "normal":
		if candidate.DefectIssueURL != nil || candidate.FailedNormalRunID != nil || facts.DefectIssue != nil || facts.FailedNormalRun != nil {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		latest, hasQualifiedLatest := qualifiedLatest(facts)
		if !hasQualifiedLatest {
			if tagPresent(facts.Tags, candidate.ATag) || tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.ATag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.ASequence, "") != 0 || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.ATag, candidate.ASequence) || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			highest := highestSequence(facts)
			if candidate.ASequence != highest+1 || candidate.BSequence != candidate.ASequence+1 || highest == 16 && (candidate.ATag != "v2.0.0" || candidate.BTag != "v2.0.1") {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			sourceState = "initial-normal"
			actions = []json.RawMessage{mustJSON(buildReleaseAction{facts.Commit, candidate.ASequence, candidate.ATag, "build-release"}), mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
		} else {
			source, ok := releaseByTag(facts.Releases, candidate.ATag)
			if latest.Tag != candidate.ATag || !ok || !qualifiedStableRelease(source) || source.Index.Sequence != candidate.ASequence || tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.ASequence, "") != 1 || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.ATag, candidate.ASequence) || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			sourceState = "later-normal"
			actions = []json.RawMessage{mustJSON(sourceAction(source)), mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
		}
	case "rescue":
		source, ok := releaseByTag(facts.Releases, candidate.ATag)
		if !ok || candidate.DefectIssueURL == nil || candidate.FailedNormalRunID == nil || facts.DefectIssue == nil || facts.FailedNormalRun == nil ||
			!validRescueAuthority(candidate, *facts.DefectIssue, *facts.FailedNormalRun) || !qualifiedSourceRelease(source, true) ||
			tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.ASequence, "") != 1 || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) ||
			!exactBurnedSource(facts.BurnedIdentities, source, failedRunURL(*candidate.FailedNormalRunID)) || !strings.Contains(source.Body, failedRunURL(*candidate.FailedNormalRunID)) {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		if latest, exists := qualifiedLatest(facts); exists && strings.Contains(latest.Body, "Stable result code: RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION\n") {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		sourceState = "rescue"
		actions = []json.RawMessage{mustJSON(sourceAction(source)), mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
	default:
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	digest := sha256.Sum256(document)
	return qualificationDecision{
		Actions: actions, FactsSHA256: hex.EncodeToString(digest[:]), Outcome: "accepted", Schema: qualificationDecisionSchema, SourceState: sourceState, Stage: candidatePreflightStage,
	}, nil
}

func validObservedFacts(facts qualificationFacts) bool {
	if !slices.IsSorted(facts.Tags) || !slices.IsSortedFunc(facts.BurnedIdentities, func(a, b burnedIdentity) int { return strings.Compare(a.OriginalTag, b.OriginalTag) }) || !slices.IsSortedFunc(facts.Releases, func(a, b observedRelease) int { return cmp.Compare(a.ID, b.ID) }) {
		return false
	}
	seenTags := map[string]bool{}
	seenIDs := map[int64]bool{}
	seenBurnSequences := map[uint64]bool{}
	seenReleaseSequences := map[uint64]bool{}
	for index, tag := range facts.Tags {
		if !validTag(tag) || index > 0 && tag == facts.Tags[index-1] {
			return false
		}
	}
	for index, burned := range facts.BurnedIdentities {
		if !validBurnedIdentity(burned) || seenBurnSequences[burned.Sequence] || index > 0 && burned.OriginalTag == facts.BurnedIdentities[index-1].OriginalTag {
			return false
		}
		seenBurnSequences[burned.Sequence] = true
	}
	for _, release := range facts.Releases {
		if release.Draft || release.ID <= 0 || seenIDs[release.ID] || seenTags[release.Tag] || !validTag(release.Tag) || !validCommit(release.Commit) || !slices.IsSortedFunc(release.Assets, func(a, b observedAsset) int { return strings.Compare(a.Name, b.Name) }) {
			return false
		}
		seenIDs[release.ID], seenTags[release.Tag] = true, true
		for assetIndex, asset := range release.Assets {
			if asset.ID <= 0 || asset.Name == "" || asset.Size <= 0 || assetIndex > 0 && asset.Name == release.Assets[assetIndex-1].Name {
				return false
			}
		}
		if release.Sequence != nil && (*release.Sequence == 0 || seenReleaseSequences[*release.Sequence]) || release.Index != nil && (release.Sequence == nil || release.Index.Repository != softwarelifecycle.Repository || release.Index.Tag != release.Tag || release.Index.Commit != release.Commit || release.Index.Sequence != *release.Sequence || !validSHA256(release.Index.SHA256)) {
			return false
		}
		if release.Sequence != nil {
			seenReleaseSequences[*release.Sequence] = true
		}
	}
	if facts.LatestTag != nil && !releaseByTagExists(facts.Releases, *facts.LatestTag) {
		return false
	}
	return true
}

func qualifiedLatest(facts qualificationFacts) (observedRelease, bool) {
	if facts.LatestTag == nil {
		return observedRelease{}, false
	}
	release, exists := releaseByTag(facts.Releases, *facts.LatestTag)
	return release, exists && qualifiedStableRelease(release)
}

func highestSequence(facts qualificationFacts) uint64 {
	highest := uint64(16)
	for _, release := range facts.Releases {
		if release.Sequence != nil && *release.Sequence > highest {
			highest = *release.Sequence
		}
	}
	for _, burned := range facts.BurnedIdentities {
		if burned.Sequence > highest {
			highest = burned.Sequence
		}
	}
	return highest
}

func collidesWithBurned(burned []burnedIdentity, tag string, sequence uint64) bool {
	for _, identity := range burned {
		if identity.OriginalTag == tag || identity.Sequence == sequence {
			return true
		}
	}
	return false
}

func releaseByTag(releases []observedRelease, tag string) (observedRelease, bool) {
	for _, release := range releases {
		if release.Tag == tag {
			return release, true
		}
	}
	return observedRelease{}, false
}

func releaseByTagExists(releases []observedRelease, tag string) bool {
	_, ok := releaseByTag(releases, tag)
	return ok
}

func tagPresent(tags []string, want string) bool { return slices.Contains(tags, want) }

func sequenceUseCount(releases []observedRelease, sequence uint64, tag string) int {
	count := 0
	for _, release := range releases {
		if release.Sequence != nil && *release.Sequence == sequence && (tag == "" || release.Tag == tag) {
			count++
		}
	}
	return count
}

func qualifiedSourceRelease(release observedRelease, prerelease bool) bool {
	if release.Draft || release.Prerelease != prerelease || !release.Immutable || release.Index == nil || len(release.Assets) != 4 {
		return false
	}
	expected := softwarelifecycle.LatestReleaseAssetNames()
	for index, asset := range release.Assets {
		if asset.Name != expected[index] || !validSHA256(asset.Digest) || asset.Name == "release-index.json" && asset.Digest != release.Index.SHA256 {
			return false
		}
	}
	return true
}

func qualifiedStableRelease(release observedRelease) bool {
	if !qualifiedSourceRelease(release, false) {
		return false
	}
	required := []string{"# SBXR Installer-Updater Acceptance Record\n", "Status: Qualified\n", "Repository: " + softwarelifecycle.Repository + "\n", "Tag: " + release.Tag + "\n", "Commit: " + release.Commit + "\n", "Sequence: " + strconv.FormatUint(release.Index.Sequence, 10) + "\n", "Release index SHA-256: " + release.Index.SHA256 + "\n", "Module Verification: Passed\n", "Seam Verification: Passed\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64\n", "Codex Live Acceptance: Passed\n", "Owner Acceptance: Not required\n", "Secret-safe result: Passed\n"}
	for _, line := range required {
		if strings.Count(release.Body, line) != 1 {
			return false
		}
	}
	for _, asset := range release.Assets {
		if strings.Count(release.Body, "Asset: "+asset.Name+" "+strconv.FormatInt(asset.Size, 10)+" "+asset.Digest+"\n") != 1 {
			return false
		}
	}
	return strings.Count(release.Body, "Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\n")+strings.Count(release.Body, "Stable result code: RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION\n") == 1 &&
		oneMatch(release.Body, `(?m)^Qualification role: (Clean-installed source release|Discovered, installed, recovered, final latest release|Rescue direct-install and lower-sequence replacement release)$`) &&
		oneMatch(release.Body, `(?m)^Workflow evidence: https://github\.com/albertloky/SBXR/actions/runs/[1-9][0-9]*$`) &&
		oneMatch(release.Body, `(?m)^Runner: Ubuntu Server 24\.04 linux/amd64$`) &&
		oneMatch(release.Body, `(?m)^Go toolchain: go[0-9]+\.[0-9]+\.[0-9]+$`) &&
		oneMatch(release.Body, `(?m)^Public verifier: [0-9]+\.[0-9]+\.[0-9]+ [A-F0-9]{64}$`)
}

func hasQualifiedV3(releases []observedRelease) bool {
	for _, release := range releases {
		if qualifiedV3Source(release) {
			return true
		}
		if qualifiedSourceRelease(release, false) && strings.Count(release.Body, "# SBXR Acceptance Record\n") == 1 && strings.Count(release.Body, "Status: Qualified\n") == 1 && strings.Count(release.Body, "Stable result code: RELEASE-V3-PACKAGED-LIVE-QUALIFICATION\n") == 1 && strings.Count(release.Body, "Qualification role: Clean-installed V3 release\n") == 1 {
			return true
		}
	}
	return false
}

func oneMatch(value, pattern string) bool {
	return len(regexp.MustCompile(pattern).FindAllString(value, 2)) == 1
}

func validRescueAuthority(candidate candidateRequest, issue defectIssue, run failedNormalRun) bool {
	if candidate.DefectIssueURL == nil || candidate.FailedNormalRunID == nil || issue.URL != *candidate.DefectIssueURL || issue.State != "open" || issue.IsPullRequest || run.ID != *candidate.FailedNormalRunID || run.Path != ".github/workflows/candidate.yml" || run.Mode != "normal" || run.Conclusion == "success" || run.Conclusion == "" {
		return false
	}
	issueID := strings.TrimPrefix(issue.URL, "https://github.com/"+softwarelifecycle.Repository+"/issues/")
	runID, runErr := strconv.ParseUint(run.ID, 10, 64)
	issueNumber, issueErr := strconv.ParseUint(issueID, 10, 64)
	return runErr == nil && runID > 0 && issueErr == nil && issueNumber > 0
}

func failedRunURL(id string) string {
	return "https://github.com/" + softwarelifecycle.Repository + "/actions/runs/" + id
}

func exactBurnedSource(burned []burnedIdentity, source observedRelease, runURL string) bool {
	matches := 0
	for _, identity := range burned {
		if identity.OriginalTag == source.Tag || identity.Sequence == source.Index.Sequence {
			if identity.OriginalTag != source.Tag || identity.Sequence != source.Index.Sequence || identity.Commit != source.Commit || identity.ReleaseIndexSHA256 != source.Index.SHA256 || identity.QualificationRunURL != runURL {
				return false
			}
			matches++
		}
	}
	return matches == 1
}

func sourceAction(release observedRelease) useSourceReleaseAction {
	assets := make([]decisionAsset, len(release.Assets))
	for index, asset := range release.Assets {
		assets[index] = decisionAsset{Name: asset.Name, SHA256: asset.Digest, Size: asset.Size}
	}
	return useSourceReleaseAction{Assets: assets, Commit: release.Commit, Draft: release.Draft, Immutable: release.Immutable, Prerelease: release.Prerelease, ReleaseID: release.ID, ReleaseIdentity: decisionReleaseIdentity{Commit: release.Commit, ReleaseIndexSHA256: release.Index.SHA256, Repository: softwarelifecycle.Repository, Tag: release.Tag}, Sequence: release.Index.Sequence, Tag: release.Tag, Type: "use-source-release"}
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

func validBurnedIdentity(burned burnedIdentity) bool {
	runID := strings.TrimPrefix(burned.QualificationRunURL, "https://github.com/"+softwarelifecycle.Repository+"/actions/runs/")
	parsedRunID, runErr := strconv.ParseUint(runID, 10, 64)
	_, timeErr := time.Parse(time.RFC3339, burned.RecordedAt)
	return validTag(burned.OriginalTag) && burned.Sequence > 0 && validCommit(burned.Commit) && validSHA256(burned.ReleaseIndexSHA256) && parsedRunID > 0 && runErr == nil && timeErr == nil && burned.Reason != ""
}
