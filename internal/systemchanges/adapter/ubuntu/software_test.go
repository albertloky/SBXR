package ubuntu

import (
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestSoftwareLifecycleUpdateChecksUseTheAuthenticatedExecutor(t *testing.T) {
	for _, code := range []string{"SOFTWARE-LIFECYCLE-UPDATE-STAGED", "SOFTWARE-LIFECYCLE-UPDATE-AGREEMENT"} {
		if !softwareLifecycleCheck(systemchanges.Check{Owner: systemchanges.SoftwareModule, Code: code}) {
			t.Fatalf("%s did not route to Software Lifecycle", code)
		}
	}
	if softwareLifecycleCheck(systemchanges.Check{Owner: systemchanges.CloudflareModule, Code: "SOFTWARE-LIFECYCLE-UPDATE-STAGED"}) {
		t.Fatal("another Module could claim the Software Lifecycle update checker")
	}
}
