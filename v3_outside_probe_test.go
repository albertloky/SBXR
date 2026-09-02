package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestV3OutsideProbeRequestUsesExactBytes(t *testing.T) {
	body, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := strings.Cut(string(body), `test "$#" -eq 3`)
	if !ok || !strings.Contains(prefix, "outside_request_matches()") {
		t.Fatal("missing collector request boundary")
	}
	digest := strings.Repeat("a", 64)
	valid := `{"deadline_unix":1788324000,"qualification_manifest_sha256":"` + digest + `","request_id":"probe-1","scenario_id":"baseline-clean","schema":"sbxr-v3-outside-probe-request-v1"}`
	for name, request := range map[string]string{
		"valid":          valid,
		"newline":        valid + "\n",
		"duplicate":      strings.Replace(valid, `"request_id":"probe-1"`, `"request_id":"probe-1","request_id":"probe-1"`, 1),
		"unknown":        strings.TrimSuffix(valid, "}") + `,"extra":true}`,
		"stale":          strings.Replace(valid, "1788324000", "1788323999", 1),
		"wrong scenario": strings.Replace(valid, "baseline-clean", "baseline-postcommit", 1),
		"wrong identity": strings.Replace(valid, "probe-1", "probe-2", 1),
		"wrong manifest": strings.Replace(valid, digest, strings.Repeat("b", 64), 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.json")
			if err := os.WriteFile(path, []byte(request), 0600); err != nil {
				t.Fatal(err)
			}
			command := prefix + "\noutside_request_matches \"$1\" \"$2\" \"$3\" \"$4\" \"$5\"\n"
			output, err := exec.Command("bash", "-c", command, "request-check", path, "1788324000", digest, "probe-1", "baseline-clean").CombinedOutput()
			if (err == nil) != (name == "valid") {
				t.Fatalf("acceptance mismatch: %v %s", err, output)
			}
		})
	}
}

func TestV3OutsideProbeShellRegression(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the probe requires Linux tmpfs tooling")
	}
	if output, err := exec.Command("bash", ".github/scripts/v3-outside-probe_test.sh").CombinedOutput(); err != nil {
		t.Fatalf("outside probe regression: %v\n%s", err, output)
	}
}

func TestV3OutsideProbeCollectorKeepsFailureAndCleanupBoundaries(t *testing.T) {
	body, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "remaining=$((deadline - $(date +%s)))\n      test \"$remaining\" -gt 0\n      timeout") {
		t.Fatal("probe must reject zero remaining time before timeout")
	}
	failure := strings.Index(text, "reason=failure-recorded")
	probeGate := strings.Index(text, `if test "$outside_probe_required" = true && test "$outside_probe_done" != true`)
	if failure < 0 || probeGate < failure {
		t.Fatal("probe gate hides original scenario failure")
	}
	for _, scenario := range []string{"baseline-clean", "baseline-postcommit"} {
		if !strings.Contains(text, "/root/sbxr-qualification-evidence/outside-reply-"+scenario+".json") {
			t.Fatal("final cleanup lacks exact probe reply", scenario)
		}
	}
}
