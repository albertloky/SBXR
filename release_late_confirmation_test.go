package architecture_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLateConfirmationReviewGitBoundary(t *testing.T) {
	if out, err := exec.Command("python3", ".github/scripts/test_late_confirmation_review.py").CombinedOutput(); err != nil {
		t.Fatalf("real Git review: %v\n%s", err, out)
	}
}

func TestLateConfirmationWorkflowBinding(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, required := range []string{
		`python3 .github/scripts/late-confirmation-review.py "$GITHUB_SHA"`,
		`.late_confirmation_review == $review[0]`,
		`.v3_attempt.late_confirmation_review == $review[0]`,
		`late_confirmation_supplement:$supplement[0]`,
		`.records[0].tag == $tag`,
		`gh release edit "$target_tag" --draft`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("missing adapter binding %s", required)
		}
	}
	if strings.Count(workflow, `python3 .github/scripts/late-confirmation-review.py "$GITHUB_SHA"`) != 2 {
		t.Fatal("preflight and result must independently reproduce source review")
	}
	// Existing job partition keeps the exception out of VPS/CA/Karing execution.
	if !strings.Contains(workflow, `if: ${{ !fromJSON(inputs.v3_attempt || '{}').owner_exception }}`) {
		t.Fatal("exception would run live journey")
	}
	data, err = os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Prior v3.1.80 live evidence reused by Owner exception; no fresh live run") {
		t.Fatal("stable finalization mislabels evidence")
	}
}
