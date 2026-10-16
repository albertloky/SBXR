package architecture_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPublicationRecoveryAuthenticatesHistoricalBurnAndInvocation(t *testing.T) {
	command := exec.Command("python3", ".github/scripts/test_publication_recovery.py")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("publication recovery authentication: %v\n%s", err, out)
	}
}

func TestPublicationRecoveryPreservesAuditBeforeMetadataOnlyPromotion(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(raw)
	collect := strings.Index(workflow, "python3 .github/scripts/publication-recovery.py verified/stable-preflight-facts.json")
	decide := strings.Index(workflow, "go run ./cmd/sbxr-release qualification < verified/stable-preflight-facts.json")
	archive := strings.Index(workflow, "name: verified-stable-publication-input")
	mutate := strings.Index(workflow, "-F \"body=@verified/records/$tag.md\"")
	if !(collect > 0 && collect < decide && decide < archive && archive < mutate) {
		t.Fatal("recovery must authenticate, validate and archive original history before mutation")
	}
	publish := workflow[strings.Index(workflow, "  publish:"):strings.Index(workflow, "  finalize-failure:")]
	if !strings.Contains(publish, "attestations: read") || strings.Contains(publish, "attestations: write") || strings.Contains(publish, "id-token: write") || strings.Contains(publish, "actions/attest-build-provenance@") {
		t.Fatal("recovery unnecessarily expands publishing signing authority")
	}
}
