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

type v3Observation struct {
	Check      string `json:"check"`
	ObservedAt string `json:"observed_at"`
	Result     string `json:"result"`
}

type v3ScenarioFailure struct {
	ActualResult   string               `json:"actual_result"`
	AttemptID      string               `json:"attempt_id"`
	Boundary       string               `json:"boundary"`
	Candidate      qualificationRelease `json:"candidate"`
	ExpectedResult string               `json:"expected_result"`
	HostState      string               `json:"host_state"`
	ObservedAt     string               `json:"observed_at"`
	OperationID    string               `json:"operation_id"`
	ScenarioID     string               `json:"scenario_id"`
	Schema         string               `json:"schema"`
	VPSID          string               `json:"vps_id"`
}

type v3SafetyCleanup struct {
	HostState string `json:"host_state"`
	Status    string `json:"status"`
}

type v3ScenarioFailureFacts struct {
	Failure                     v3ScenarioFailure `json:"failure"`
	QualificationBoundaryFacts  json.RawMessage   `json:"qualification_boundary_facts"`
	QualificationManifest       json.RawMessage   `json:"qualification_manifest"`
	QualificationManifestSigned bool              `json:"qualification_manifest_attested"`
	SafetyCleanup               v3SafetyCleanup   `json:"safety_cleanup"`
	Schema                      string            `json:"schema"`
	Stage                       string            `json:"stage"`
}

type v3ScenarioFailureDecision struct {
	Burn              burnedIdentity    `json:"burn"`
	BurnRequired      bool              `json:"burn_required"`
	FactsSHA256       string            `json:"facts_sha256"`
	Failure           v3ScenarioFailure `json:"failure"`
	Outcome           string            `json:"outcome"`
	SafetyCleanup     v3SafetyCleanup   `json:"safety_cleanup"`
	Schema            string            `json:"schema"`
	Stage             string            `json:"stage"`
	StopTestMutations bool              `json:"stop_test_mutations"`
}

func evaluateV3ScenarioFailure(facts v3ScenarioFailureFacts, document []byte) (v3ScenarioFailureDecision, error) {
	refused := func() (v3ScenarioFailureDecision, error) {
		return v3ScenarioFailureDecision{}, errors.New("V3 failure facts refused")
	}
	if recurringSecret(document) {
		return refused()
	}
	var boundary qualificationBoundaryFacts
	if !decodeCanonical(facts.QualificationBoundaryFacts, &boundary) {
		return refused()
	}
	manifest, err := evaluateQualificationBoundary(boundary)
	encoded, marshalErr := marshalCanonical(manifest)
	if err != nil || marshalErr != nil || !facts.QualificationManifestSigned || manifest.V3Attempt == nil || len(manifest.Releases) != 1 || !bytes.Equal(encoded, facts.QualificationManifest) || facts.Schema != qualificationFactsSchema || facts.Stage != "v3-scenario-failure" {
		return refused()
	}
	failure, attempt, release := facts.Failure, manifest.V3Attempt, manifest.Releases[0]
	observed, timeOK := qualificationTime(failure.ObservedAt)
	started, _ := qualificationTime(attempt.StartedAt)
	states := []string{"Unknown", "Not installed", "Not set up", "Running", "Problem detected", "Setup incomplete", "Change incomplete", "Removal incomplete"}
	if !timeOK || observed.Before(started) || failure.Schema != "sbxr-v3-scenario-failure-"+attemptVersion(attempt) || failure.AttemptID != attempt.AttemptID || failure.VPSID != attempt.VPSID || !reflect.DeepEqual(failure.Candidate, release) || !slices.Contains(attempt.RequiredScenarios, failure.ScenarioID) || !independentID(failure.OperationID, "operation") || failure.ExpectedResult != "expected-safety-and-final-state-proved" || !slices.Contains([]string{"unexpected-failure", "timeout", "unexplained-drift", "evidence-refused"}, failure.ActualResult) || !slices.Contains([]string{"unknown", "observed", "before-commitment", "after-commitment", "refusal"}, failure.Boundary) || !slices.Contains(states, failure.HostState) || !slices.Contains(states, facts.SafetyCleanup.HostState) || !slices.Contains([]string{"not-started", "completed", "incomplete"}, facts.SafetyCleanup.Status) {
		return refused()
	}
	burn := burnedIdentity{Commit: release.Commit, OriginalTag: release.Tag, QualificationRunURL: manifest.Workflow.RunURL, Reason: "post-sign-qualification-failure", RecordedAt: failure.ObservedAt, ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Sequence: release.Sequence}
	return v3ScenarioFailureDecision{Burn: burn, BurnRequired: true, FactsSHA256: documentSHA256(document), Failure: failure, Outcome: "failed", SafetyCleanup: facts.SafetyCleanup, Schema: qualificationDecisionSchema, Stage: facts.Stage, StopTestMutations: true}, nil
}

type v3EvidenceReference struct {
	Record v3Observation `json:"record"`
	SHA256 string        `json:"sha256"`
}

type v3ScenarioEvidence struct {
	ActualResult        string                  `json:"actual_result"`
	AttemptID           string                  `json:"attempt_id"`
	Boundary            string                  `json:"boundary"`
	Candidate           qualificationRelease    `json:"candidate"`
	CompletedAt         string                  `json:"completed_at"`
	Evidence            []v3EvidenceReference   `json:"evidence"`
	ExpectedResult      string                  `json:"expected_result"`
	FinalState          string                  `json:"final_state"`
	InitialState        string                  `json:"initial_state"`
	LinkID              string                  `json:"link_id"`
	OperationID         string                  `json:"operation_id"`
	PackagesAfter       v3QualificationPackages `json:"packages_after"`
	PackagesBefore      v3QualificationPackages `json:"packages_before"`
	PreflightAt         string                  `json:"preflight_at"`
	PriorScenarioSHA256 string                  `json:"prior_scenario_sha256"`
	RecoveryDirection   string                  `json:"recovery_direction"`
	ScenarioID          string                  `json:"scenario_id"`
	Schema              string                  `json:"schema"`
	Source              *v3QualificationSource  `json:"source"`
	StartedAt           string                  `json:"started_at"`
	ValidatedAt         string                  `json:"validated_at"`
	VPSID               string                  `json:"vps_id"`
	VPSIdentitySHA256   string                  `json:"vps_identity_sha256"`
}

type v3RecurringEvidence struct {
	AttemptID                   string               `json:"attempt_id"`
	ObservedAt                  string               `json:"observed_at"`
	QualificationManifestSHA256 string               `json:"qualification_manifest_sha256"`
	Scenarios                   []v3ScenarioEvidence `json:"scenarios"`
	Schema                      string               `json:"schema"`
}

type v3RecurringResultFacts struct {
	DetailedEvidence            v3RecurringEvidence    `json:"detailed_evidence"`
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

type v3RecurringAcceptanceRecord struct {
	AcceptedAt             string                   `json:"accepted_at"`
	Assets                 []decisionAsset          `json:"assets"`
	Attempt                v3QualificationAttempt   `json:"attempt"`
	DetailedEvidenceSHA256 string                   `json:"detailed_evidence_sha256"`
	Evidence               []string                 `json:"evidence"`
	NotApplicable          []string                 `json:"not_applicable,omitempty"`
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

func evaluateV3Result(document []byte) (acceptanceVPSResultDecision, error) {
	var stage qualificationEnvelope
	if json.Unmarshal(document, &stage) == nil && stage.Stage == "owner-exception-result" {
		return evaluateOwnerException(document)
	}
	var envelope struct {
		DetailedEvidence struct {
			Schema string `json:"schema"`
		} `json:"detailed_evidence"`
	}
	if json.Unmarshal(document, &envelope) == nil && (envelope.DetailedEvidence.Schema == "sbxr-v3-packaged-live-evidence-v2" || envelope.DetailedEvidence.Schema == "sbxr-v3-packaged-live-evidence-v3") {
		var facts v3RecurringResultFacts
		if decodeCanonical(document, &facts) {
			return evaluateRecurringV3Result(facts, document)
		}
	} else {
		var facts v3PackagedLiveResultFacts
		if decodeCanonical(document, &facts) {
			return evaluateV3PackagedLiveResult(facts, document)
		}
	}
	return acceptanceVPSResultDecision{}, errors.New("V3 packaged live result refused")
}

func recurringManifest(facts v3RecurringResultFacts) (qualificationManifest, error) {
	var boundary qualificationBoundaryFacts
	if !decodeCanonical(facts.QualificationBoundaryFacts, &boundary) {
		return qualificationManifest{}, errors.New("recurring qualification refused")
	}
	manifest, err := evaluateQualificationBoundary(boundary)
	encoded, marshalErr := marshalCanonical(manifest)
	if err != nil || marshalErr != nil || !facts.QualificationManifestSigned || (manifest.Schema != "sbxr-qualification-manifest-v2" && manifest.Schema != "sbxr-qualification-manifest-v3") || manifest.V3Attempt == nil || manifest.Mode != "v3" || (manifest.SourceState != "v3-recurring" && manifest.SourceState != "v3-subscription-clean") || len(manifest.Releases) != 1 || !bytes.Equal(encoded, facts.QualificationManifest) || facts.PriorDecisionSHA256 != documentSHA256(encoded) || !reflect.DeepEqual(facts.Releases, manifest.Releases) || facts.Runner != manifest.V3Attempt.Runner {
		return qualificationManifest{}, errors.New("recurring qualification refused")
	}
	return manifest, nil
}

func evaluateRecurringV3Result(facts v3RecurringResultFacts, document []byte) (acceptanceVPSResultDecision, error) {
	manifest, err := recurringManifest(facts)
	if err != nil || recurringSecret(document) || facts.Stage != v3PackagedLiveResultStage || !validRecurringEvidence(facts, manifest, true) {
		return acceptanceVPSResultDecision{}, errors.New("recurring V3 evidence refused")
	}
	body, err := buildRecurringAcceptanceRecord(manifest, facts)
	if err != nil {
		return acceptanceVPSResultDecision{}, err
	}
	return acceptanceVPSResultDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, Records: []acceptanceRecord{{Body: body, Tag: manifest.Releases[0].Tag}}, Schema: qualificationDecisionSchema, Stage: v3PackagedLiveResultStage}, nil
}

func evaluateV3ScenarioResult(facts v3RecurringResultFacts, document []byte) (acceptanceVPSResultDecision, error) {
	manifest, err := recurringManifest(facts)
	if err != nil || recurringSecret(document) || facts.Stage != "v3-scenario-result" || facts.EvaluationTime != facts.ObservedAt || !validRecurringEvidence(facts, manifest, false) {
		return acceptanceVPSResultDecision{}, errors.New("V3 scenario evidence refused")
	}
	return acceptanceVPSResultDecision{FactsSHA256: documentSHA256(document), Outcome: "accepted", PriorDecisionSHA256: facts.PriorDecisionSHA256, Records: []acceptanceRecord{}, Schema: qualificationDecisionSchema, Stage: facts.Stage}, nil
}

func recurringSecret(document []byte) bool {
	return secretBearing(document) || regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|vless://|https://[^"\s]+:8443/|subscription-secret-marker|profile-secret-marker`).Match(document)
}

func validRecurringEvidence(facts v3RecurringResultFacts, manifest qualificationManifest, complete bool) bool {
	evidence, attempt := facts.DetailedEvidence, manifest.V3Attempt
	encoded, err := marshalCanonical(evidence)
	observed, observedOK := qualificationTime(facts.ObservedAt)
	evaluated, evaluatedOK := qualificationTime(facts.EvaluationTime)
	if attempt == nil || facts.Schema != qualificationFactsSchema || err != nil || facts.DetailedEvidenceSHA256 != documentSHA256(encoded) || evidence.Schema != "sbxr-v3-packaged-live-evidence-"+attemptVersion(attempt) || evidence.AttemptID != attempt.AttemptID || evidence.QualificationManifestSHA256 != facts.PriorDecisionSHA256 || evidence.ObservedAt != facts.ObservedAt || !observedOK || !evaluatedOK || evaluated.Before(observed) || evaluated.Sub(observed) > 5*time.Minute || len(evidence.Scenarios) == 0 || len(evidence.Scenarios) > len(attempt.RequiredScenarios) || complete && len(evidence.Scenarios) != len(attempt.RequiredScenarios) {
		return false
	}
	previousTime, _ := qualificationTime(attempt.StartedAt)
	previousDigest, packages := facts.PriorDecisionSHA256, attempt.Packages
	operations := map[string]bool{}
	for index, scenario := range evidence.Scenarios {
		started, startOK := qualificationTime(scenario.StartedAt)
		completed, completionOK := qualificationTime(scenario.CompletedAt)
		validated, validationOK := qualificationTime(scenario.ValidatedAt)
		limit := 30 * time.Minute
		if scenario.ScenarioID == "karing-final" {
			limit = 2 * time.Hour
		}
		if !startOK || !completionOK || !validationOK || started.Before(previousTime) || completed.Before(started) || completed.Sub(started) > limit || validated.Before(completed) || validated.Sub(completed) > 5*time.Minute || validated.After(observed) || scenario.PreflightAt != scenario.StartedAt || scenario.PriorScenarioSHA256 != previousDigest || scenario.ScenarioID != attempt.RequiredScenarios[index] || scenario.Schema != "sbxr-v3-scenario-evidence-"+attemptVersion(attempt) || scenario.AttemptID != attempt.AttemptID || scenario.VPSID != attempt.VPSID || scenario.VPSIdentitySHA256 != attempt.VPSIdentitySHA256 || !reflect.DeepEqual(scenario.Candidate, manifest.Releases[0]) || !independentID(scenario.OperationID, "operation") || operations[scenario.OperationID] || scenario.LinkID != "" && !independentID(scenario.LinkID, "link") || scenario.PackagesBefore != packages {
			return false
		}
		operations[scenario.OperationID] = true
		if scenario.ScenarioID == "snap-refresh" {
			packages = attempt.AfterSnapRefresh
		}
		if scenario.PackagesAfter != packages || !validScenarioResult(scenario, attempt.Sources) {
			return false
		}
		for _, reference := range scenario.Evidence {
			record, recordErr := marshalCanonical(reference.Record)
			at, atOK := qualificationTime(reference.Record.ObservedAt)
			if recordErr != nil || reference.SHA256 != documentSHA256(record) || !atOK || at.Before(started) || at.After(completed) || reference.Record.Result != "observed" {
				return false
			}
		}
		bytes, _ := marshalCanonical(scenario)
		previousDigest, previousTime = documentSHA256(bytes), validated
	}
	last := evidence.Scenarios[len(evidence.Scenarios)-1]
	completed, _ := qualificationTime(last.CompletedAt)
	return last.ValidatedAt == facts.ObservedAt && evaluated.Sub(completed) <= 5*time.Minute
}

func validScenarioResult(scenario v3ScenarioEvidence, sources []v3QualificationSource) bool {
	id := scenario.ScenarioID
	initial, boundary, recovery, final := "Running", "observed", "none", "Running"
	if strings.Contains(id, "precommit") || id == "enable-schema2-absent" {
		boundary, recovery = "before-commitment", "rollback"
	}
	if strings.Contains(id, "postcommit") {
		boundary, recovery = "after-commitment", "forward"
	}
	if strings.HasPrefix(id, "remove-") || id == "baseline-removal" || id == "baseline-clean" || id == "karing-final" {
		final = "Not installed"
	}
	if id == "baseline-clean" {
		initial = "Not installed"
	}
	if id == "baseline-refusal" || id == "baseline-precommit" || id == "baseline-postcommit" {
		initial = "Not set up"
	}
	if id == "baseline-refusal" || id == "baseline-precommit" {
		final = "Not set up"
	}
	if id == "baseline-refusal" || id == "baseline-drift" || id == "invalid-replacement" || id == "update-incompatible" || id == "update-unlisted" {
		boundary = "refusal"
	}
	if strings.HasPrefix(id, "remove-") && (strings.HasSuffix(id, "precommit") || strings.HasSuffix(id, "postcommit")) {
		recovery = "forward"
		if strings.HasPrefix(id, "remove-identity-") {
			initial = "Change incomplete"
		}
	}
	if id == "remove-certbot" || id == "remove-writer" || id == "remove-admission-race" || id == "remove-directory-lock" {
		final, boundary = "Running", "refusal"
	}
	if id == "remove-death" || id == "remove-reboot" || id == "remove-shared-route" || id == "remove-finalization" || id == "remove-exact-restoration" || id == "baseline-removal" {
		boundary, recovery = "after-commitment", "forward"
	}
	if id == "remove-finalization" || id == "remove-exact-restoration" {
		initial = "Removal incomplete"
	}
	if id == "activation-precommit" || id == "managed-renewal" {
		recovery = "forward"
	}
	if scenario.InitialState != initial || scenario.Boundary != boundary || scenario.RecoveryDirection != recovery || scenario.FinalState != final || scenario.ExpectedResult != "expected-safety-and-final-state-proved" || scenario.ActualResult != scenario.ExpectedResult {
		return false
	}
	var source *v3QualificationSource
	for _, item := range sources {
		if strings.HasPrefix(id, "source-"+item.ReleaseIdentity.Tag+"-") {
			copy := item
			source = &copy
			break
		}
	}
	if !reflect.DeepEqual(scenario.Source, source) {
		return false
	}
	checks := requiredV3Checks(id)
	if scenario.Schema == "sbxr-v3-scenario-evidence-v3" && id == "enable-schema1" {
		checks = append(checks, strings.Fields("candidate-supported-setup-origin no-protected-state-edit no-unsupported-migration")...)
	}
	if len(checks) != len(scenario.Evidence) {
		return false
	}
	for index, check := range checks {
		if scenario.Evidence[index].Record.Check != check {
			return false
		}
	}
	return true
}

func requiredV3Checks(id string) []string {
	checks := strings.Fields(`fresh-disposable-vps-preflight unchanged-candidate-bytes initial-state-proved boundary-observed final-state-proved original-ssh-continuity capture-coverage-complete exact-secrets-absent prohibited-patterns-absent`)
	family := strings.Split(id, "-")[0]
	if family != "baseline" {
		checks = append(checks, "supported-effective-route-inspected")
	}
	switch family {
	case "enable", "link", "repair", "activation", "invalid", "managed", "recorder", "snap", "unsupported":
		checks = append(checks, "proxy-and-traffic-unchanged", "client-identity-unchanged")
		if family != "enable" && family != "link" {
			checks = append(checks, "unchanged-link")
		}
	case "identity":
		checks = append(checks, strings.Fields(`old-established-outside-session outside-target-healthy startup-publication reload effective-route source-only-before-gate ordinary-start-denied-after-gate unchanged-link-and-noncredential-fields`)...)
	case "source":
		checks = append(checks, strings.Fields(`actual-source-packaged-updater source-record-schema-proved both-releases-understand-recovery admission-exclusion creation-provenance-preserved no-ownership-migration proxy-not-restarted both-credentials-unchanged no-helper-or-intermediate-release`)...)
		switch {
		case strings.HasSuffix(id, "-precommit"):
			return append(checks, "actual-source-packaged-recovery", "prior-exact-restoration", "source-installed-record-restored")
		case strings.HasSuffix(id, "-postcommit"):
			return append(checks, "candidate-forward-runtime-completion", "serving-only-restart")
		default:
			return append(checks, "candidate-installed-record-proved", "serving-only-restart")
		}
	case "remove":
		if id != "remove-certbot" && id != "remove-writer" && id != "remove-admission-race" && id != "remove-directory-lock" {
			checks = append(checks, strings.Fields(`removal-commitment-observed writers-and-starts-excluded supported-directory-lock-acquired full-pending-provenance unrelated-resources-preserved final-state-directory-inspection one-authoritative-location all-owned-resources-absent`)...)
		}
		if strings.HasSuffix(id, "-precommit") || strings.HasSuffix(id, "-postcommit") {
			return append(checks, "idle-pending-takeover", "pending-operation-side-proved", "no-repair-or-revoked-start")
		}
	}
	extra := map[string]string{
		"lifecycle-menu":           `packaged-zero-argument-menu check-reachable update-reachable recover-reachable explicit-confirmation safe-no-update safe-no-recovery clean-install-target-refused no-replacement-on-refusal`,
		"baseline-clean":           `clean-direct-install reviewed-setup local-activation outside-proxy-traffic complete-owned-removal`,
		"baseline-refusal":         `footprint-conflict-detected setup-refused-before-mutation conflict-only-restored`,
		"baseline-precommit":       `setup-precommit-interruption cleanup-direction-proved reviewed-cleanup provisional-resources-absent`,
		"baseline-postcommit":      `setup-commitment-observed reviewed-finishing local-activation outside-proxy-traffic`,
		"baseline-drift":           `owned-metadata-drift-detected removal-refused-before-mutation exact-metadata-restored`,
		"baseline-removal":         `removal-commitment-observed interruption-observed reviewed-removal-finishing complete-owned-removal`,
		"enable-schema1":           `schema1-conversion creation-provenance-preserved enabled-generation-agreement authoritative-link-disclosed`,
		"enable-precommit":         `one-provisional-generation provisional-serving-stopped provisional-cleanup subscription-absent shared-resources-preserved no-provisional-disclosure`,
		"enable-postcommit":        `committed-generation-proved same-generation-finishing transaction-material-cleaned authoritative-link-disclosed`,
		"enable-schema2-absent":    `schema2-absent-retained no-schema-downgrade subscription-absent provisional-cleanup`,
		"link-precommit":           `one-prepared-target old-serving-quiesced old-generation-restored unused-target-removed old-link-usable no-replacement-disclosure`,
		"link-postcommit":          `one-prepared-target no-old-process-or-request-overlap target-only-finishing old-link-404 new-link-usable`,
		"repair-precommit":         `diagnosed-correction unused-preparation-cleaned correction-not-applied original-fault-retained certificate-history-not-rewound`,
		"repair-postcommit":        `diagnosed-correction exact-approved-correction-finished no-second-repair selected-generation-agreement`,
		"activation-precommit":     `canonical-publication standing-renewal-authority local-operation-not-yet-published reviewed-forward-activation accepted-activation outside-tls-presentation certificate-history-not-rewound`,
		"activation-postcommit":    `canonical-publication recorded-activation-target same-target-finishing accepted-activation outside-tls-presentation certificate-history-not-rewound`,
		"invalid-replacement":      `invalid-replacement-refused valid-loaded-certificate-preserved no-serving-restart`,
		"recorder-start":           `start-failure child-not-launched shared-route-delay-accounted`,
		"recorder-outcome":         `outcome-failure unknown-outcome-reported no-false-renewal-success`,
		"recorder-stale":           `stale-attempt stale-outcome-rejected active-attempt-not-overwritten`,
		"recorder-live":            `live-attempt live-and-abandoned-distinguished live-not-completed`,
		"recorder-retention":       `retention unresolved-fault-retained noop-and-unrelated-success-do-not-clear bounded-retention-refuses-new-child`,
		"recorder-locks":           `lock-order-contention no-evidence-lock-held-during-child-or-whole-host-wait bounded-refusal`,
		"recorder-death":           `child-and-writer-death unfinished-attempt-retained no-false-outcome`,
		"recorder-reboot":          `reboot-exclusion unfinished-attempt-retained startup-does-not-invent-outcome`,
		"identity-precommit":       `owned-process-groups-and-descendants-terminated source-restoration-only-before-revocation unused-target-removed source-traffic-restored rotation-reported-cancelled`,
		"identity-postcommit":      `owned-process-groups-and-descendants-terminated old-new-connections-refused one-target-forward-after-revocation replacement-traffic-proved`,
		"identity-unavailable":     `owned-process-groups-and-descendants-terminated old-new-connections-refused replacement-traffic-proved subscription-fault-reported-separately unavailable-subscription-fallback`,
		"identity-absent":          `owned-process-groups-and-descendants-terminated old-new-connections-refused replacement-traffic-proved subscription-remains-absent absent-subscription-fallback`,
		"update-incompatible":      `incompatible-downgrade-refused no-replacement-on-refusal`,
		"update-unlisted":          `unlisted-source-refused no-replacement-on-refusal`,
		"remove-certbot":           `active-certbot-proved removal-refused owned-resources-preserved`,
		"remove-writer":            `active-writer-proved removal-refused owned-resources-preserved`,
		"remove-admission-race":    `writer-admission-race-proved removal-refused owned-resources-preserved`,
		"remove-directory-lock":    `supported-directory-lock-held bounded-contention-refusal owned-resources-preserved`,
		"remove-death":             `writer-and-owner-death no-state-recreation reviewed-removal-finishing`,
		"remove-reboot":            `reboot-observed no-state-recreation ordinary-start-refused reviewed-removal-finishing`,
		"remove-shared-route":      `shared-route-delay-and-restoration interrupted-restoration-finished unrelated-lineages-and-accounts-preserved`,
		"remove-finalization":      `finalization-interruption unknown-residue-refused exact-authority-handoff finalization-finished`,
		"remove-exact-restoration": `exact-finishing-executable wrong-executable-refused restored-finishing-release-proved removal-finished`,
		"managed-renewal":          `supported-managed-attempt-interrupted recorder-unknown-or-failed reviewed-repair-targeted-production-replacement fault-retained-until-proof official-schedule-integration recorder-start recorder-outcome production-issuance canonical-publication accepted-activation outside-tls natural-timer-not-observed naturally-due-renewal-not-observed`,
		"snap-refresh":             `supported-snap-refresh effective-generated-route-preserved recorder-and-hooks-verified planned-package-change-only`,
		"unsupported-route":        `new-or-renamed-route-detected problem-detected accounting-gap-explicit bypass-prevention-not-claimed historical-outcomes-unknown`,
		"secret-containment":       `sandbox-cannot-read-token canonical-and-candidate-protection units-arguments-environment-safe runner-vps-mac-terminal-workflow-retained-scans qualification-secrets-and-client-processes-cleaned unrelated-data-preserved`,
		"karing-final":             `latest-official-stable-macos-package one-real-remote-profile one-vless-reality-node all-fields-and-name-match settings-preserved direct-and-proxied-traffic manual-refresh genuinely-due-five-minute-auto-refresh old-established-session-terminated owned-process-groups-and-descendants-terminated old-new-connections-refused outside-target-healthy unchanged-real-link replacement-uuid-adopted other-fields-preserved traffic-restored direct-refresh-correction-or-confirmed-fallback https-outage-preserves-node same-link-recovery complete-removal outside-access-unusable full-owned-absence temporary-secret-and-process-cleanup`,
	}
	return append(checks, strings.Fields(extra[id])...)
}

func buildRecurringAcceptanceRecord(manifest qualificationManifest, facts v3RecurringResultFacts) (string, error) {
	release, attempt := manifest.Releases[0], manifest.V3Attempt
	role, code, recordSchema := "Recurring subscription-capable V3 release", "RELEASE-V3-SUBSCRIPTION-QUALIFICATION", "sbxr-acceptance-record-v2"
	var notApplicable []string
	if attemptVersion(attempt) == "v3" {
		recordSchema = "sbxr-acceptance-record-v3"
	}
	if attempt.Support != nil && attempt.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall {
		role, code = "Clean-installed subscription-capable V3 release", "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION"
		notApplicable = []string{"incoming-source-upgrades", "two-release-update-recovery"}
	}
	status, live, integrated, owner, secretSafe, karing := "Qualified", "Passed", "Passed on live Ubuntu Server 24.04 amd64 and Karing macOS", "Not required", "Passed", "Passed"
	if ownerExceptionManifest(manifest) {
		if len(facts.DetailedEvidence.Scenarios) != 0 {
			return "", errors.New("Owner exception cannot claim live scenarios")
		}
		status, code = "Qualified by Owner exception", softwarelifecycle.OwnerExceptionCode
		live, integrated, karing = softwarelifecycle.OwnerExceptionLive, softwarelifecycle.OwnerExceptionLive, softwarelifecycle.OwnerExceptionLive
		owner, secretSafe = "One-release exception approved", softwarelifecycle.OwnerExceptionSecrets
	}
	var body strings.Builder
	for _, line := range []string{
		"# SBXR Acceptance Record", "Status: " + status, "Repository: " + release.ReleaseIdentity.Repository, "Tag: " + release.Tag, "Commit: " + release.Commit,
		"Release index SHA-256: " + release.ReleaseIdentity.ReleaseIndexSHA256, "Sequence: " + strconv.FormatUint(release.Sequence, 10), "Workflow evidence: " + manifest.Workflow.RunURL,
		"Acceptance time: " + facts.EvaluationTime, "Runner: Ubuntu Server 24.04 linux/amd64", "Go toolchain: " + attempt.Runner.GoToolchain, "Public verifier: " + attempt.Runner.PublicVerifier,
		"Qualification role: " + role, "Detailed evidence SHA-256: " + facts.DetailedEvidenceSHA256,
		"Stable result code: " + code, "Module Verification: Passed", "Seam Verification: Passed", "Integrated Verification: " + integrated, "Codex Live Acceptance: " + live, "Owner Acceptance: " + owner, "Secret-safe result: " + secretSafe, "Karing macOS: " + karing,
		"Natural timer firing and naturally due certificate renewal: Not observed",
		"Unsupported new or renamed renewal route: May execute before detection; historical outcomes unknown",
	} {
		body.WriteString(line + "\n")
	}
	if ownerExceptionManifest(manifest) {
		body.WriteString("Owner exception: " + softwarelifecycle.OwnerExceptionID + "\nLive qualification: Incomplete\nClient compatibility: static-official-evidence-passed-live-karing-pending\nWarning: Subscription and Client Identity rotation are not fully proved on a live VPS and Karing.\nPolicy: docs/adr/0017-one-release-owner-exception.md\n")
	}
	if attempt.Support != nil {
		support, _ := json.Marshal(attempt.Support.lifecycle())
		baseline, _ := marshalCanonical(attempt.Baseline)
		body.WriteString("Release support: " + string(support) + "\nStable baseline: " + string(baseline) + "\n")
		if len(notApplicable) > 0 {
			body.WriteString("Incoming source upgrades: Not applicable\nTwo-release update/recovery: Not applicable\n")
		}
	}
	for _, asset := range release.Assets {
		body.WriteString("Asset: " + asset.Name + " " + strconv.FormatInt(asset.Size, 10) + " " + asset.SHA256 + "\n")
	}
	body.WriteString("Proxy package: sing-box 1.13.19 amd64 " + attempt.ProxyPackage.SHA256 + "\n")
	body.WriteString("Karing package: karing " + attempt.Packages.Karing.Version + " " + attempt.Packages.Karing.Architecture + " " + attempt.Packages.Karing.SHA256 + "\n")
	for _, scenario := range facts.DetailedEvidence.Scenarios {
		encoded, err := marshalCanonical(scenario)
		if err != nil {
			return "", err
		}
		body.WriteString("Scenario: " + scenario.ScenarioID + " " + documentSHA256(encoded) + " " + manifest.Workflow.RunURL + "#artifacts\n")
	}
	encoded, err := marshalCanonical(v3RecurringAcceptanceRecord{
		AcceptedAt: facts.EvaluationTime, Assets: release.Assets, Attempt: *attempt, DetailedEvidenceSHA256: facts.DetailedEvidenceSHA256, Evidence: []string{manifest.Workflow.RunURL + "#artifacts"},
		NotApplicable: notApplicable, QualificationRole: role, ReleaseIdentity: release.ReleaseIdentity, Runner: "Ubuntu Server 24.04 linux/amd64", Schema: recordSchema, SecretSafeResult: secretSafe, Sequence: release.Sequence,
		Software: acceptanceRecordSoftware{GoToolchain: attempt.Runner.GoToolchain, PublicVerifier: attempt.Runner.PublicVerifier}, StableResultCode: code,
		Stages: acceptanceRecordStages{CodexLiveAcceptance: live, IntegratedVerification: integrated, ModuleVerification: "Passed", OwnerAcceptance: owner, SeamVerification: "Passed"}, WorkflowRun: manifest.Workflow.RunURL,
	})
	if err != nil {
		return "", err
	}
	body.WriteString("```json\n" + string(encoded) + "\n```\n")
	return body.String(), nil
}

type v3SoftwarePackage struct {
	Architecture string `json:"architecture"`
	Name         string `json:"name"`
	Repository   string `json:"repository"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Version      string `json:"version"`
}

type v3QualificationPackages struct {
	Certbot v3SoftwarePackage `json:"certbot"`
	Karing  v3SoftwarePackage `json:"karing"`
	Snap    v3SoftwarePackage `json:"snap"`
}

type v3QualificationSource struct {
	Assets             []decisionAsset         `json:"assets"`
	OwnershipSchema    int                     `json:"ownership_schema"`
	PublicVerification string                  `json:"public_verification"`
	ReleaseIdentity    decisionReleaseIdentity `json:"release_identity"`
	Sequence           uint64                  `json:"sequence"`
}

type v3QualificationAttempt struct {
	AfterSnapRefresh       v3QualificationPackages `json:"after_snap_refresh"`
	AttemptID              string                  `json:"attempt_id"`
	Baseline               *qualificationRelease   `json:"baseline,omitempty"`
	CandidateIndex         string                  `json:"candidate_index,omitempty"`
	KaringLatestCheckedAt  string                  `json:"karing_latest_checked_at"`
	KaringLimitSeconds     int                     `json:"karing_limit_seconds"`
	MacRunnerID            string                  `json:"mac_runner_id"`
	MacOSVersion           string                  `json:"macos_version"`
	OutsideRunnerID        string                  `json:"outside_runner_id"`
	OwnerException         string                  `json:"owner_exception,omitempty"`
	Packages               v3QualificationPackages `json:"packages"`
	ProxyPackage           v3PackageIdentity       `json:"proxy_package"`
	RequiredScenarios      []string                `json:"required_scenarios"`
	RunAttempt             int                     `json:"run_attempt"`
	Runner                 acceptanceVPSRunner     `json:"runner"`
	ScenarioLimitSeconds   int                     `json:"scenario_limit_seconds"`
	Schema                 string                  `json:"schema"`
	Sources                []v3QualificationSource `json:"sources"`
	StartedAt              string                  `json:"started_at"`
	Support                *v3ReleaseSupport       `json:"support,omitempty"`
	ValidationLimitSeconds int                     `json:"validation_limit_seconds"`
	VPSID                  string                  `json:"vps_id"`
	VPSIdentitySHA256      string                  `json:"vps_identity_sha256"`
}

func validV3Attempt(attempt v3QualificationAttempt, preflight qualificationFacts, workflow qualificationWorkflow) bool {
	if attempt.OwnerException != "" && (attempt.OwnerException != softwarelifecycle.OwnerExceptionID || attempt.Support == nil || !softwarelifecycle.OwnerExceptionTarget(preflight.Candidate.BTag, preflight.Candidate.BSequence, supportPointer(attempt.Support)) || attempt.Schema != "sbxr-v3-qualification-attempt-v3") {
		return false
	}
	started, ok := qualificationTime(attempt.StartedAt)
	checked, checkedOK := qualificationTime(attempt.KaringLatestCheckedAt)
	if !ok || !checkedOK || started.Before(checked) || started.Sub(checked) > 5*time.Minute ||
		(attempt.Schema != "sbxr-v3-qualification-attempt-v2" && attempt.Schema != "sbxr-v3-qualification-attempt-v3") || attempt.RunAttempt < 1 ||
		attempt.AttemptID != "run-"+workflow.RunID+"-attempt-"+strconv.Itoa(attempt.RunAttempt) ||
		attempt.ScenarioLimitSeconds != 1800 || attempt.KaringLimitSeconds != 7200 || attempt.ValidationLimitSeconds != 300 ||
		!validAcceptanceRunner(attempt.Runner) || attempt.Runner.GoToolchain != "go1.26.6" ||
		!independentID(attempt.VPSID, "vps") || !independentID(attempt.OutsideRunnerID, "runner") || !independentID(attempt.MacRunnerID, "mac") || !regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?$`).MatchString(attempt.MacOSVersion) || !validSHA256(attempt.VPSIdentitySHA256) ||
		attempt.ProxyPackage != expectedV3PackageIdentity() || !validV3Packages(attempt.Packages) || !validV3Packages(attempt.AfterSnapRefresh) ||
		attempt.Packages.Karing != attempt.AfterSnapRefresh.Karing || attempt.Packages.Certbot == attempt.AfterSnapRefresh.Certbot || preflight.LatestTag == nil {
		return false
	}
	if attempt.Schema == "sbxr-v3-qualification-attempt-v3" {
		if preflight.Candidate.EvidenceVersion != 3 || attempt.Support == nil || !reflect.DeepEqual(attempt.Support, preflight.Candidate.Support) || !validSubscriptionHistory(preflight.SubscriptionHistory, attempt.Support.Scope, attempt.Baseline) || attempt.Baseline == nil || !validAttemptSupport(attempt) {
			return false
		}
		if attempt.Support.Scope == softwarelifecycle.FirstSubscriptionCleanInstall {
			return true
		}
	} else if preflight.Candidate.EvidenceVersion != 2 || attempt.Support != nil || attempt.Baseline != nil || attempt.CandidateIndex != "" || len(attempt.Sources) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, source := range attempt.Sources {
		observed, exists := releaseByTag(preflight.Releases, source.ReleaseIdentity.Tag)
		if !exists || !qualifiedV3Source(observed) || attempt.Schema == "sbxr-v3-qualification-attempt-v3" && !subscriptionRelease(observed) || seen[observed.Tag] || source.OwnershipSchema != 1 && source.OwnershipSchema != 2 || source.PublicVerification != "accepted" {
			return false
		}
		action := sourceAction(observed)
		if source.ReleaseIdentity != action.ReleaseIdentity || source.Sequence != action.Sequence || !reflect.DeepEqual(source.Assets, action.Assets) {
			return false
		}
		seen[observed.Tag] = true
	}
	return seen[*preflight.LatestTag] && slices.Equal(attempt.RequiredScenarios, attemptScenarios(attempt))
}

func validV3Packages(packages v3QualificationPackages) bool {
	for _, item := range []struct {
		actual                         v3SoftwarePackage
		name, repository, architecture string
	}{
		{packages.Certbot, "certbot", "https://snapcraft.io/certbot", "amd64"},
		{packages.Snap, "snapd", "https://snapcraft.io/snapd", "amd64"},
		{packages.Karing, "karing", "https://github.com/KaringX/karing", packages.Karing.Architecture},
	} {
		p := item.actual
		if p.Name != item.name || p.Repository != item.repository || p.Architecture != item.architecture || !validSHA256(p.SHA256) || p.Size <= 0 || !regexp.MustCompile(`^[0-9]+(?:[.-][0-9]+){0,5}$`).MatchString(p.Version) {
			return false
		}
	}
	version := strings.Split(packages.Certbot.Version, ".")
	if len(version) < 2 {
		return false
	}
	major, majorErr := strconv.Atoi(version[0])
	minor, minorErr := strconv.Atoi(version[1])
	return majorErr == nil && minorErr == nil && (major > 5 || major == 5 && minor >= 4) && (packages.Karing.Architecture == "macos-arm64" || packages.Karing.Architecture == "macos-amd64")
}

func qualificationTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil && parsed.Format(time.RFC3339) == value
}

func independentID(value, kind string) bool {
	return regexp.MustCompile(`^` + kind + `-[1-9][0-9]{0,8}$`).MatchString(value)
}

func requiredV3Scenarios(sources []v3QualificationSource) []string {
	ids := strings.Fields(`baseline-clean baseline-refusal baseline-precommit baseline-postcommit baseline-drift baseline-removal
enable-schema1 enable-precommit enable-postcommit enable-schema2-absent link-precommit link-postcommit
repair-precommit repair-postcommit activation-precommit activation-postcommit invalid-replacement managed-renewal
recorder-start recorder-outcome recorder-stale recorder-live recorder-retention recorder-locks recorder-death recorder-reboot snap-refresh unsupported-route
identity-precommit identity-postcommit identity-unavailable identity-absent`)
	for _, source := range sources {
		for _, suffix := range []string{"upgrade", "precommit", "postcommit"} {
			ids = append(ids, "source-"+source.ReleaseIdentity.Tag+"-"+suffix)
		}
	}
	ids = append(ids, "update-incompatible", "update-unlisted")
	for _, operation := range []string{"enable", "link", "repair", "activation", "identity"} {
		for _, boundary := range []string{"precommit", "postcommit"} {
			ids = append(ids, "remove-"+operation+"-"+boundary)
		}
	}
	return append(ids, strings.Fields(`remove-certbot remove-writer remove-admission-race remove-directory-lock remove-death remove-reboot remove-shared-route remove-finalization remove-exact-restoration secret-containment karing-final`)...)
}

// This checks observed metadata. The workflow must also use the public verifier
// for the exact source bytes and their signed release provenance.
func qualifiedV3Source(release observedRelease) bool {
	if !qualifiedSourceRelease(release, false) {
		return false
	}
	exception := strings.Count(release.Body, "Stable result code: "+softwarelifecycle.OwnerExceptionCode+"\n") == 1
	status, live, owner, secrets := "Qualified", "Passed", "Not required", "Passed"
	if exception {
		if !softwarelifecycle.OwnerExceptionTarget(release.Tag, release.Index.Sequence, supportPointer(release.Index.Support)) || strings.Count(release.Body, "Owner exception: "+softwarelifecycle.OwnerExceptionID+"\n") != 1 || strings.Count(release.Body, "Live qualification: Incomplete\n") != 1 {
			return false
		}
		status, live, owner, secrets = "Qualified by Owner exception", softwarelifecycle.OwnerExceptionLive, "One-release exception approved", softwarelifecycle.OwnerExceptionSecrets
	}
	for _, line := range []string{
		"# SBXR Acceptance Record", "Status: " + status, "Repository: " + softwarelifecycle.Repository,
		"Tag: " + release.Tag, "Commit: " + release.Commit,
		"Sequence: " + strconv.FormatUint(release.Index.Sequence, 10), "Release index SHA-256: " + release.Index.SHA256,
		"Module Verification: Passed", "Seam Verification: Passed", "Codex Live Acceptance: " + live,
		"Owner Acceptance: " + owner, "Secret-safe result: " + secrets,
	} {
		if strings.Count(release.Body, line+"\n") != 1 {
			return false
		}
	}
	for _, asset := range release.Assets {
		if strings.Count(release.Body, "Asset: "+asset.Name+" "+strconv.FormatInt(asset.Size, 10)+" "+asset.Digest+"\n") != 1 {
			return false
		}
	}
	return (exception || oneMatch(release.Body, `(?m)^Stable result code: RELEASE-V3-(PACKAGED-LIVE|SUBSCRIPTION|SUBSCRIPTION-CLEAN-INSTALL)-QUALIFICATION$`)) &&
		oneMatch(release.Body, `(?m)^Qualification role: (Clean-installed V3 release|Recurring subscription-capable V3 release|Clean-installed subscription-capable V3 release)$`) &&
		oneMatch(release.Body, `(?m)^Workflow evidence: https://github\.com/albertloky/SBXR/actions/runs/[1-9][0-9]*$`) &&
		(exception && strings.Count(release.Body, "Integrated Verification: "+softwarelifecycle.OwnerExceptionLive+"\n") == 1 || !exception && oneMatch(release.Body, `(?m)^Integrated Verification: Passed on live Ubuntu Server 24\.04 amd64 and (outside runner|Karing macOS)$`))
}
