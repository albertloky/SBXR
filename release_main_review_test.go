package architecture_test

import (
	"os/exec"
	"testing"
)

func TestReleaseMainReviewAndPublicationPauseFixtures(t *testing.T) {
	if output, err := exec.Command("python3", ".github/scripts/test_release_main_review.py").CombinedOutput(); err != nil {
		t.Fatalf("release main review/pause fixtures: %v\n%s", err, output)
	}
}
