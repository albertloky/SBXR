package architecture_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMVPEvidenceAssemblerAndCollectorSyntax(t *testing.T) {
	if output, err := exec.Command("python3", ".github/scripts/tests/test_mvp_evidence.py").CombinedOutput(); err != nil {
		t.Fatalf("MVP evidence assembler regression: %v\n%s", err, output)
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/v3-recurring-evidence.sh").CombinedOutput(); err != nil {
		t.Fatalf("MVP collector syntax: %v\n%s", err, output)
	}
}

func TestSharedPackagedMenuDrivers(t *testing.T) {
	for _, path := range []string{
		".github/scripts/tests/test_v3_menu_session.py",
		".github/scripts/tests/test_v3_packaged_live_menu_disclosure.py",
	} {
		if output, err := exec.Command("python3", path).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", path, err, output)
		}
	}
}

func TestMVPCollectorUsesExplicitObservationAndHasNoHistoricalDrivers(t *testing.T) {
	body, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	observation := strings.Index(text, "python3 .github/scripts/v3-mvp-evidence.py")
	validation := strings.Index(text, `"$tool" qualification < "$directory/mvp-facts.json"`)
	submission := strings.Index(text, `submit_result "$1" "$2" "$3" "$manifest" "$directory/mvp-facts.json"`)
	if observation < 0 || validation < observation || submission < validation {
		t.Fatal("MVP observation is not assembled, validated, and submitted in order")
	}
	for _, obsolete := range []string{"managed-outside-request", "identity-outside", "outside-reply-baseline", "v3-operator"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("MVP collector retains historical driver %q", obsolete)
		}
	}
	if !strings.Contains(text, `.v3_attempt.evidence_policy == "mvp-live-v1"`) || !strings.Contains(text, "rm /root/sbxr-qualification-evidence/request.json") {
		t.Fatal("MVP collector does not reject old policies locally or clean its request")
	}
}
