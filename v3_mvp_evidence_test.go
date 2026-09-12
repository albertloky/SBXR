package architecture_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMVPEvidenceAssemblerAndCollectorSyntax(t *testing.T) {
	if output, err := exec.Command("python3", ".github/scripts/test_v3_mvp_evidence.py").CombinedOutput(); err != nil {
		t.Fatalf("MVP evidence assembler regression: %v\n%s", err, output)
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/v3-recurring-evidence.sh").CombinedOutput(); err != nil {
		t.Fatalf("MVP collector syntax: %v\n%s", err, output)
	}
}

func TestMVPCollectorUsesExplicitObservationAndPolicySpecificCleanup(t *testing.T) {
	body, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	observation := strings.Index(text, "python3 .github/scripts/v3-mvp-evidence.py")
	validation := strings.Index(text, `"$tool" qualification < "$directory/mvp-facts.json"`)
	submission := strings.Index(text, `submit_result "$1" "$2" "$3" "$manifest" "$directory/mvp-facts.json"`)
	historicalOffset := -1
	if submission >= 0 {
		historicalOffset = strings.Index(text[submission:], "/root/sbxr-qualification-evidence/managed-outside-request.json")
	}
	historical := historicalOffset
	if historicalOffset >= 0 {
		historical += submission
	}
	if observation < 0 || validation < observation || submission < validation || historical < submission {
		t.Fatal("MVP observation is not assembled, validated, and submitted before historical polling")
	}
	between := text[submission:historical]
	if !strings.Contains(between, `if test "$mvp_live" = true`) || !strings.Contains(between, "continue") {
		t.Fatal("MVP path can fall through into historical outside-driver polling")
	}
	cleanupStart := strings.LastIndex(text, `if test "$mvp_live" = true; then`)
	if cleanupStart < 0 {
		t.Fatal("MVP final cleanup branch missing")
	}
	cleanupEnd := strings.Index(text[cleanupStart:], "else")
	if cleanupEnd < 0 {
		t.Fatal("MVP final cleanup branch missing")
	}
	mvpCleanup := text[cleanupStart : cleanupStart+cleanupEnd]
	if !strings.Contains(mvpCleanup, "rm /root/sbxr-qualification-evidence/request.json") || strings.Contains(mvpCleanup, "outside-reply-baseline") {
		t.Fatal("MVP final cleanup depends on historical baseline replies")
	}
}
