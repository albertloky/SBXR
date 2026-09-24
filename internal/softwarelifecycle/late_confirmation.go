package softwarelifecycle

import (
	"encoding/json"
	"strings"
)

// One fresh target authorized for the r24 evidence exception. This is not a
// runtime option or a general relaxation of MVP qualification.
const (
	LateConfirmationID                 = "owner-approved-r24-late-confirmation-2026-09-24"
	LateConfirmationTag                = "v3.1.81"
	LateConfirmationSequence    uint64 = 159
	LateConfirmationBase               = "1878d6fb57dd3f28a4c90ce9b3b5dc009b756f52"
	LateConfirmationSupplement         = "f20a3644592f5af4e1b2927358774c8f9d8e7c4a127ceed7f7a17724157eca71"
	LateConfirmationRuntimeTree        = "c70633b317322ff495abc4b700137022fa99a2f44c8b166896db4c0ab4a05d04"
	LateConfirmationLive               = "Prior v3.1.80 live evidence reused by Owner exception; no fresh live run"
	LateConfirmationSecrets            = "Fresh automated scans passed; prior live secret checks reused"
	LateConfirmationTime               = "2026-09-24T09:26:44.001843+00:00"
	LateConfirmationPriorRun           = "https://github.com/albertloky/SBXR/actions/runs/35965345632"
)

type QualificationExceptionProfile struct {
	ID, Live, Secrets, Client, Policy string
}

func QualificationException(tag string, sequence uint64, support *ReleaseSupport) (QualificationExceptionProfile, bool) {
	if OwnerExceptionTarget(tag, sequence, support) {
		return QualificationExceptionProfile{OwnerExceptionID, OwnerExceptionLive, OwnerExceptionSecrets, "static-official-evidence-passed-live-karing-pending", "docs/adr/0017-one-release-owner-exception.md"}, true
	}
	if tag == LateConfirmationTag && sequence == LateConfirmationSequence && support != nil && support.valid() && support.Scope == SubscriptionCleanInstallRepair {
		return QualificationExceptionProfile{LateConfirmationID, LateConfirmationLive, LateConfirmationSecrets, "prior-live-karing-passed-owner-cleanup-confirmed-late", "docs/adr/0024-r24-late-confirmation-supplement.md"}, true
	}
	return QualificationExceptionProfile{}, false
}

// The source review is produced from Git by the workflow, then bound into the
// signed attempt. It is a Codex/source comparison, not an invented human signature.
type LateConfirmationReview struct {
	BaseCommit        string `json:"base_commit"`
	PolicyDiffSHA256  string `json:"policy_diff_sha256"`
	Reviewer          string `json:"reviewer"`
	RuntimeTreeSHA256 string `json:"runtime_tree_sha256"`
	SupplementSHA256  string `json:"supplement_sha256"`
	TargetCommit      string `json:"target_commit"`
	TargetSequence    uint64 `json:"target_sequence"`
	TargetTag         string `json:"target_tag"`
}

func (r *LateConfirmationReview) Valid(commit string) bool {
	return r != nil && r.BaseCommit == LateConfirmationBase && r.TargetCommit == commit && commit != r.BaseCommit && commitPatternForLate(commit, 40) && commitPatternForLate(r.PolicyDiffSHA256, 64) && r.Reviewer == "Codex source comparison; Owner-approved exception" && r.RuntimeTreeSHA256 == LateConfirmationRuntimeTree && r.SupplementSHA256 == LateConfirmationSupplement && r.TargetTag == LateConfirmationTag && r.TargetSequence == LateConfirmationSequence
}

func commitPatternForLate(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidLateConfirmationRecord(body, commit string) bool {
	value := func(prefix string) (string, bool) {
		result, count := "", 0
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, prefix) {
				result = strings.TrimPrefix(line, prefix)
				count++
			}
		}
		return result, count == 1 && result != ""
	}
	for prefix, expected := range map[string]string{
		"Prior live evidence: ":     LateConfirmationPriorRun,
		"Late Owner confirmation: ": LateConfirmationTime,
		"Supplement SHA-256: ":      LateConfirmationSupplement,
		"Original qualification: ":  "Failed; v3.1.80 remains burned",
		"Fresh live scenarios: ":    "Not performed",
		"Cleanup execution time: ":  "Unknown",
	} {
		if got, ok := value(prefix); !ok || got != expected {
			return false
		}
	}
	encoded, ok := value("Applicability review: ")
	var review LateConfirmationReview
	if !ok || ValidateUniqueJSON([]byte(encoded)) != nil || json.Unmarshal([]byte(encoded), &review) != nil || !review.Valid(commit) {
		return false
	}
	canonical, err := json.Marshal(review)
	return err == nil && string(canonical) == encoded && !strings.Contains(body, "\nScenario: ") && !strings.HasPrefix(body, "Scenario: ")
}
