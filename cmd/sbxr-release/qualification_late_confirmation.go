package main

import (
	"encoding/json"
	"errors"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const lateConfirmationStage = "mvp-late-confirmation-supplement"
const lateConfirmationException = "owner-approved-r24-late-confirmation-2026-09-24"

// This stage accepts only the Owner-approved archival supplement. It neither
// produces an Acceptance Record nor designates a future release. Publication
// must not consume this decision as a successful candidate/live result.
type lateConfirmationFacts struct {
	Evidence    []lateConfirmationEvidence `json:"evidence"`
	ExceptionID string                     `json:"exception_id"`
	Schema      string                     `json:"schema"`
	Stage       string                     `json:"stage"`
}

type lateConfirmationEvidence struct {
	Content string `json:"content"`
	Name    string `json:"name"`
}

type lateConfirmationDecision struct {
	Activation                  string                  `json:"activation"`
	BurnRef                     string                  `json:"burn_ref"`
	CleanupPerformedAt          *string                 `json:"cleanup_performed_at"`
	ExceptionID                 string                  `json:"exception_id"`
	FactsSHA256                 string                  `json:"facts_sha256"`
	OriginalResult              string                  `json:"original_result"`
	Outcome                     string                  `json:"outcome"`
	OwnerConfirmationRecordedAt string                  `json:"owner_confirmation_recorded_at"`
	PriorManifestSHA256         string                  `json:"prior_manifest_sha256"`
	PriorRelease                decisionReleaseIdentity `json:"prior_release"`
	PriorRunAttempt             int                     `json:"prior_run_attempt"`
	PriorRunID                  string                  `json:"prior_run_id"`
	PriorSequence               uint64                  `json:"prior_sequence"`
	ReleaseEligible             bool                    `json:"release_eligible"`
	Schema                      string                  `json:"schema"`
	Stage                       string                  `json:"stage"`
}

func evaluateLateConfirmation(document []byte) (lateConfirmationDecision, error) {
	refused := func() (lateConfirmationDecision, error) {
		return lateConfirmationDecision{}, errors.New("late confirmation supplement refused")
	}
	var facts lateConfirmationFacts
	if !decodeCanonical(document, &facts) || facts.Schema != qualificationFactsSchema || facts.Stage != lateConfirmationStage || facts.ExceptionID != lateConfirmationException || len(facts.Evidence) != len(lateConfirmationEvidencePins) {
		return refused()
	}
	seen := make(map[string]bool, len(facts.Evidence))
	for _, evidence := range facts.Evidence {
		expected, exists := lateConfirmationEvidencePins[evidence.Name]
		data := []byte(evidence.Content)
		if !exists || seen[evidence.Name] || documentSHA256(data) != expected || !json.Valid(data) || softwarelifecycle.ValidateUniqueJSON(data) != nil || secretBearing(data) {
			return refused()
		}
		seen[evidence.Name] = true
	}
	// These constants describe the approved historical case, not user-supplied
	// assertions. The content pins above retain its real timing and failures.
	return lateConfirmationDecision{
		Schema: qualificationDecisionSchema, Stage: lateConfirmationStage,
		ExceptionID: lateConfirmationException, FactsSHA256: documentSHA256(document),
		Outcome:       "accepted-supplement",
		PriorRelease:  decisionReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.1.80", Commit: "1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52", ReleaseIndexSHA256: "53001e9785381a75820e0b37e53254ad869652b7f27788477fcb915533c2780b"},
		PriorSequence: 158, PriorRunID: "35965345632", PriorRunAttempt: 2,
		PriorManifestSHA256: "1d664476d96ee0cea97eef1ce91445e159d56c234f6772939e15014b792f1046",
		OriginalResult:      "failed", BurnRef: "refs/tags/release-burned/v3.1.80",
		OwnerConfirmationRecordedAt: "2026-09-24T09:26:44.001843+00:00",
		CleanupPerformedAt:          nil, ReleaseEligible: false,
		Activation: "requires-designated-fresh-target-and-target-bound-applicability-policy",
	}, nil
}

// Reviewed, secret-safe bytes for this single approved case. New evidence or a
// new target cannot be authorized by replacing runtime hashes or approval flags.
// The archived fixture is data, not a source of truth for general product policy.
var lateConfirmationEvidencePins = map[string]string{
	"signed/qualification-manifest.json":   "1d664476d96ee0cea97eef1ce91445e159d56c234f6772939e15014b792f1046",
	"01-observation.json":                  "94e78278b5c660dd9f1c955d5a54645f373f275ce3b6d2a811800341debb5e83",
	"02-observation.json":                  "469a1a430c40738e2e7d0bb6ac0c151cb7b84f73fa08de7572afdb7b0b0fbcda",
	"03-observation.json":                  "e1f78d97e8cc687f095c92ff94f9b642bdbe2ca61e57e61704ba017595ca79df",
	"04-observation.json":                  "a209d3538883741a0a10115d00beccdccead4f8c0eaa4a2c9e6a9b3dc9ac9589",
	"05-restart.receipt.json":              "c21696528a0f93029d2f4e472bc46daf015f25ed95fd283c60c28ac8ca52d297",
	"05-restart-https.json":                "fa2a01aece413e0cfdf3c4041b0653151c23994438d00aef7aded18a9b73fc53",
	"05-restart-traffic.json":              "9fb0ad350e56df1e3bccf4f4a91a337438aad0627fa66cd7415da8de0bc6f6ff",
	"05-remove.receipt.json":               "2e18d4fd17b98f7476106c49a0d605cec9f99aa5e61611cbb4f0f33714dd69ff",
	"05-preservation.json":                 "c5cd9ba85dafdba2706eb09aa274459644f64267e66283474bd54c6cf797f6ce",
	"05-outside-refused.json":              "3907fd2687e091cc6c30236a8ba7da95e5f55b35c3431beb1062377ba8d7a746",
	"05-outside-client-cleanup.json":       "8288384d5b88f4694860a61ad77038118a4f97041eac83249065a6e5241a59b9",
	"05-secret-cleanup.json":               "d9f59c093a602786ee791881bfb7d1c279d58f7660c64f0b5acb63cbfb9201d9",
	"failure-summary.json":                 "81691887607d6f1be184e8bad5b4b07953df929c68e53a83a23c428c8df11f39",
	"owner-late-cleanup-confirmation.json": "e6c6794528814810cf75c78c8c2807d2fbaf6fcc75d54256a7bb8879eade0b79",
	"failure-decision.json":                "3358ca5e8ed406e85e10005dc1a7a3fe273f6969d5d7d52f2631997b900ce3fc",
}
