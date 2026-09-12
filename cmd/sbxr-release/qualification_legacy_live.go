package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

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
