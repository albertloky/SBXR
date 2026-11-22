package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const (
	qualificationWindowStage  = "qualification-window"
	qualificationWindowSchema = "sbxr-qualification-window-v1"
	windowActivityReserve     = 1200
	windowRestorationReserve  = 1500
	windowTransportReserve    = 60
)

// The original manifest remains the artifact authority. This separate record
// binds the clock to a new protected run without rewriting the signed manifest.
type qualificationWindow struct {
	FinishUnix      int64                 `json:"finish_unix"`
	KaringCheckedAt string                `json:"karing_checked_at"`
	ManifestSHA256  string                `json:"manifest_sha256"`
	Origin          qualificationWorkflow `json:"origin"`
	Release         qualificationRelease  `json:"release"`
	RunAttempt      int                   `json:"run_attempt"`
	Schema          string                `json:"schema"`
	StartUnix       int64                 `json:"start_unix"`
	TestUntilUnix   int64                 `json:"test_until_unix"`
	Workflow        qualificationWorkflow `json:"workflow"`
}

// Attestation and live draft fields are observations made by the protected
// workflow. This evaluator replays and compares them; it does not verify Sigstore.
type qualificationWindowOrigin struct {
	LiveNeverStarted bool                  `json:"live_never_started"`
	ManifestAttested bool                  `json:"manifest_attested"`
	RunAttempt       int                   `json:"run_attempt"`
	SignConclusion   string                `json:"sign_conclusion"`
	SignerWorkflow   string                `json:"signer_workflow"`
	Workflow         qualificationWorkflow `json:"workflow"`
}

type qualificationWindowDraft struct {
	BurnRef    string               `json:"burn_ref"`
	Draft      bool                 `json:"draft"`
	Immutable  bool                 `json:"immutable"`
	Prerelease bool                 `json:"prerelease"`
	Release    qualificationRelease `json:"release"`
	ReleaseRef string               `json:"release_ref"`
}

type qualificationWindowFacts struct {
	Approval                   qualificationApproval     `json:"approval"`
	BurnedIdentities           []burnedIdentity          `json:"burned_identities"`
	Draft                      qualificationWindowDraft  `json:"draft"`
	ObservedAt                 string                    `json:"observed_at"`
	Origin                     qualificationWindowOrigin `json:"origin"`
	QualificationBoundaryFacts json.RawMessage           `json:"qualification_boundary_facts"`
	RunAttempt                 int                       `json:"run_attempt"`
	Schema                     string                    `json:"schema"`
	SignedManifest             json.RawMessage           `json:"signed_manifest"`
	Stage                      string                    `json:"stage"`
	Window                     qualificationWindow       `json:"window"`
	Workflow                   qualificationWorkflow     `json:"workflow"`
}

type qualificationWindowDecision struct {
	FactsSHA256 string              `json:"facts_sha256"`
	Outcome     string              `json:"outcome"`
	Schema      string              `json:"schema"`
	Stage       string              `json:"stage"`
	Window      qualificationWindow `json:"window"`
}

func evaluateQualificationWindow(facts qualificationWindowFacts, document []byte) (qualificationWindowDecision, error) {
	refused := func() (qualificationWindowDecision, error) {
		return qualificationWindowDecision{}, errors.New("fresh qualification window refused")
	}
	observed, ok := qualificationTime(facts.ObservedAt)
	if facts.Schema != qualificationFactsSchema || facts.Stage != qualificationWindowStage ||
		!ok || !validWindowWorkflow(facts.Workflow) || facts.RunAttempt != 1 ||
		facts.Approval.State != "approved" || len(facts.Approval.DecisionChain) != 0 ||
		!slices.Equal(facts.Approval.Environments, []approvalEnvironment{{Name: "acceptance-vps"}}) ||
		!facts.Origin.ManifestAttested || !facts.Origin.LiveNeverStarted || facts.Origin.SignConclusion != "success" ||
		facts.Origin.SignerWorkflow != softwarelifecycle.Repository+"/.github/workflows/candidate.yml" ||
		facts.BurnedIdentities == nil || !validFailureBurns(facts.BurnedIdentities) || secretBearing(document) {
		return refused()
	}
	var boundary qualificationBoundaryFacts
	if !decodeCanonical(facts.QualificationBoundaryFacts, &boundary) {
		return refused()
	}
	manifest, err := evaluateQualificationBoundary(boundary)
	encoded, marshalErr := marshalCanonical(manifest)
	if err != nil || marshalErr != nil || !bytes.Equal(encoded, facts.SignedManifest) ||
		!eligibleWindowManifest(manifest) || facts.Origin.Workflow != manifest.Workflow ||
		facts.Origin.RunAttempt != manifest.V3Attempt.RunAttempt {
		return refused()
	}
	release := manifest.Releases[0]
	if reservedCandidate(release.Tag, release.Sequence, release.ReleaseID) ||
		collidesWithBurned(facts.BurnedIdentities, release.Tag, release.Sequence) ||
		!facts.Draft.Draft || facts.Draft.Immutable || facts.Draft.Prerelease ||
		facts.Draft.ReleaseRef != "absent" || facts.Draft.BurnRef != "absent" ||
		!reflect.DeepEqual(facts.Draft.Release, release) {
		return refused()
	}
	w := facts.Window
	if !matchesQualificationWindow(w, manifest, encoded, facts.Workflow, facts.RunAttempt) ||
		!qualificationWindowCanStart(w, observed.Unix()) || !windowKaringCheckFresh(w, observed) {
		return refused()
	}
	return qualificationWindowDecision{
		FactsSHA256: documentSHA256(document), Outcome: "accepted", Schema: qualificationDecisionSchema,
		Stage: qualificationWindowStage, Window: w,
	}, nil
}

func validWindowWorkflow(workflow qualificationWorkflow) bool {
	runID, err := strconv.ParseUint(workflow.RunID, 10, 64)
	return err == nil && runID > 0 && strconv.FormatUint(runID, 10) == workflow.RunID &&
		validCommit(workflow.Commit) && workflow.Path == ".github/workflows/candidate.yml" &&
		workflow.Ref == softwarelifecycle.Repository+"/.github/workflows/candidate.yml@refs/heads/main" &&
		workflow.RunURL == "https://github.com/"+softwarelifecycle.Repository+"/actions/runs/"+workflow.RunID
}

func eligibleWindowManifest(manifest qualificationManifest) bool {
	if !currentCleanPublication(manifest) || !validWindowWorkflow(manifest.Workflow) {
		return false
	}
	a := manifest.V3Attempt
	return a.EvidencePolicy == softwarelifecycle.MVPHTTPEvidencePolicy &&
		slices.Equal(a.RequiredScenarios, strings.Fields(softwarelifecycle.MVPHTTPScenarios)) &&
		a.OwnerException == "" && a.Live89CorrectionReview == nil && a.LateConfirmationReview == nil &&
		a.AttendedFinishBy == "" && a.KaringResponseLimitSeconds == 0 && a.ProxyProfile == ""
}

func matchesQualificationWindow(w qualificationWindow, manifest qualificationManifest, raw []byte, workflow qualificationWorkflow, attempt int) bool {
	originStart, validStart := qualificationTime(manifest.V3Attempt.StartedAt)
	return validStart && w.Schema == qualificationWindowSchema && w.ManifestSHA256 == documentSHA256(raw) &&
		w.Origin == manifest.Workflow && w.Workflow == workflow && w.Workflow.RunID != w.Origin.RunID &&
		w.RunAttempt == 1 && w.RunAttempt == attempt && reflect.DeepEqual(w.Release, manifest.Releases[0]) &&
		w.StartUnix > originStart.Unix() && w.StartUnix > 0 &&
		w.StartUnix < w.TestUntilUnix && w.TestUntilUnix < w.FinishUnix &&
		w.FinishUnix-w.StartUnix <= 21600 && w.FinishUnix-w.TestUntilUnix >= windowRestorationReserve+windowTransportReserve
}

func windowKaringCheckFresh(window qualificationWindow, observed time.Time) bool {
	checked, ok := qualificationTime(window.KaringCheckedAt)
	return ok && checked.Unix() >= window.StartUnix && !checked.After(observed)
}

func qualificationWindowCanStart(window qualificationWindow, now int64) bool {
	return now >= window.StartUnix && now <= window.TestUntilUnix-windowActivityReserve &&
		now <= window.FinishUnix-windowTransportReserve-windowRestorationReserve-windowActivityReserve
}

// Live and attestation observations are supplied only after the workflow
// verifies the window artifact and the separate protected live deployment.
type freshQualificationEvidence struct {
	AdmittedAt          string                `json:"admitted_at"`
	Attested            bool                  `json:"attested"`
	LiveApproved        bool                  `json:"live_approved"`
	LiveJob             string                `json:"live_job"`
	RunAttempt          int                   `json:"run_attempt"`
	SignerWorkflow      string                `json:"signer_workflow"`
	TransportRestoredAt string                `json:"transport_restored_at,omitempty"`
	WindowDecision      json.RawMessage       `json:"window_decision"`
	WindowFacts         json.RawMessage       `json:"window_facts"`
	Workflow            qualificationWorkflow `json:"workflow"`
}

func freshResultWindow(facts v3RecurringResultFacts, manifest qualificationManifest, complete bool) (qualificationWindow, bool) {
	w, ok := freshQualificationBinding(facts.FreshWindow, manifest, facts.QualificationManifest, facts.QualificationBoundaryFacts)
	if !ok || documentSHA256(facts.FreshWindow.WindowDecision) != facts.PriorDecisionSHA256 {
		return qualificationWindow{}, false
	}
	fresh := facts.FreshWindow
	if complete {
		restored, restoredOK := qualificationTime(fresh.TransportRestoredAt)
		observed, observedOK := qualificationTime(facts.ObservedAt)
		evaluated, evaluatedOK := qualificationTime(facts.EvaluationTime)
		if !restoredOK || !observedOK || !evaluatedOK || restored.Before(observed) ||
			restored.After(evaluated) || restored.Unix() > w.FinishUnix {
			return qualificationWindow{}, false
		}
	} else if fresh.TransportRestoredAt != "" {
		return qualificationWindow{}, false
	}
	return w, true
}

func freshQualificationBinding(fresh *freshQualificationEvidence, manifest qualificationManifest, signedManifest, boundary []byte) (qualificationWindow, bool) {
	if fresh == nil || !fresh.Attested || !fresh.LiveApproved || fresh.LiveJob != "acceptance-vps" ||
		fresh.SignerWorkflow != softwarelifecycle.Repository+"/.github/workflows/candidate.yml" {
		return qualificationWindow{}, false
	}
	var inputs qualificationWindowFacts
	if !decodeCanonical(fresh.WindowFacts, &inputs) ||
		!bytes.Equal(inputs.SignedManifest, signedManifest) ||
		!bytes.Equal(inputs.QualificationBoundaryFacts, boundary) {
		return qualificationWindow{}, false
	}
	decision, err := evaluateQualificationWindow(inputs, fresh.WindowFacts)
	if err != nil {
		return qualificationWindow{}, false
	}
	w := decision.Window
	raw, err := marshalCanonical(decision)
	admitted, admissionOK := qualificationTime(fresh.AdmittedAt)
	minted, mintOK := qualificationTime(inputs.ObservedAt)
	if err != nil || !bytes.Equal(raw, fresh.WindowDecision) || !admissionOK || !mintOK || admitted.Before(minted) ||
		!matchesQualificationWindow(w, manifest, signedManifest, fresh.Workflow, fresh.RunAttempt) ||
		!qualificationWindowCanStart(w, admitted.Unix()) {
		return qualificationWindow{}, false
	}
	return w, true
}

func freshResultAttempt(attempt v3QualificationAttempt, fresh *freshQualificationEvidence) v3QualificationAttempt {
	attempt.AttemptID = "run-" + fresh.Workflow.RunID + "-attempt-" + strconv.Itoa(fresh.RunAttempt)
	attempt.RunAttempt = fresh.RunAttempt
	attempt.StartedAt = fresh.AdmittedAt
	var decision qualificationWindowDecision
	if decodeCanonical(fresh.WindowDecision, &decision) {
		attempt.KaringLatestCheckedAt = decision.Window.KaringCheckedAt
	}
	return attempt
}

func stableQualificationRunMatches(facts stablePreflightFacts, manifest qualificationManifest, evidence *freshQualificationEvidence, evaluatedRaw string, observed time.Time) bool {
	workflow := manifest.Workflow
	if evidence == nil {
		return facts.FreshWindow == nil && successfulQualificationRun(facts.CandidateRun, workflow)
	}
	r := facts.FreshWindow
	if r == nil || !r.WindowAttested || r.OriginSignConclusion != "success" ||
		r.AcceptanceConclusion != "success" || r.RunAttempt != 1 || r.RunAttempt != evidence.RunAttempt ||
		!successfulQualificationRun(facts.CandidateRun, evidence.Workflow) {
		return false
	}
	if r.OriginRun != (stableCandidateRun{
		Conclusion: r.OriginRun.Conclusion, CreatedAt: r.OriginRun.CreatedAt, Event: "workflow_dispatch",
		HeadSHA: workflow.Commit, ID: workflow.RunID, Path: workflow.Path,
	}) || (r.OriginRun.Conclusion != "cancelled" && r.OriginRun.Conclusion != "success") {
		return false
	}
	createdOrigin, originOK := qualificationTime(r.OriginRun.CreatedAt)
	createdLive, liveOK := qualificationTime(facts.CandidateRun.CreatedAt)
	admitted, admittedOK := qualificationTime(evidence.AdmittedAt)
	evaluated, evaluatedOK := qualificationTime(evaluatedRaw)
	if !originOK || !liveOK || !admittedOK || !evaluatedOK || observed.Before(evaluated) || !createdLive.After(createdOrigin) || createdLive.After(admitted) ||
		observed.Sub(createdOrigin) >= 90*24*time.Hour {
		return false
	}
	return r.WindowSHA256 == documentSHA256(evidence.WindowDecision)
}

func successfulQualificationRun(run stableCandidateRun, workflow qualificationWorkflow) bool {
	return run == (stableCandidateRun{
		Conclusion: "success", CreatedAt: run.CreatedAt, Event: "workflow_dispatch",
		HeadSHA: workflow.Commit, ID: workflow.RunID, Path: workflow.Path,
	})
}
