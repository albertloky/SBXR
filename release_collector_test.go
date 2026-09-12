package architecture_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRecurringV3UsesTheExistingQualificationWorkflow(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"v3_attempt:", "evidence_version:3", "v3-subscription-clean", "sbxr-qualification-manifest-v3", "subscription_history", "release-history.sh", "candidate_index", "-support release-support.json", "v3-recurring", "sbxr-qualification-manifest-v2", "v3-recurring-evidence.sh", "RELEASE-V3-SUBSCRIPTION-QUALIFICATION", "go run ./cmd/sbxr-release verify-public-latest"} {
		if !strings.Contains(string(workflow), required) {
			t.Fatalf("missing recurring workflow contract %q", required)
		}
	}
	stable, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(stable), "bash .github/scripts/release-history.sh current-release-history.json") != 2 || strings.Count(string(stable), "subscription_history:{complete:true") != 2 {
		t.Fatal("publication must recheck history before and after approval")
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/release-history.sh").CombinedOutput(); err != nil {
		t.Fatalf("history collector syntax: %v %s", err, output)
	}
	collector, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"v3-scenario-result", "v3-scenario-failure", "stop_test_mutations", "qualification <", "completed_at", "300", "7200", "STOP", "failure-recorded", "retained-failure.json", ".failure.scenario_id == $scenario"} {
		if !strings.Contains(string(collector), required) {
			t.Fatalf("missing evidence handoff contract %q", required)
		}
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/v3-recurring-evidence.sh").CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v\n%s", err, output)
	}
}

func TestRecurringCollectorPreservesScenarioInputAndLastFailureIdentity(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, loop, found := strings.Cut(string(source), "\nindex=0\n")
	header, _, hasBody := strings.Cut(loop, "  index=$((index + 1))\n")
	_, ending, hasEnd := strings.Cut(loop, "  reason=unexpected-failure\n")
	footer, _, _ := strings.Cut(ending, "\n")
	if !found || !hasBody || !hasEnd || !strings.Contains(footer, ".v3_attempt.required_scenarios[]") {
		t.Fatal("scenario loop boundaries not found")
	}
	manifest := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"v3_attempt":{"required_scenarios":["baseline-clean","baseline-refusal","karing-final"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, child := range []string{":", "cat >/dev/null"} {
		t.Run(child, func(t *testing.T) {
			// A real child consumes stdin just as ssh does; use the collector's
			// unchanged loop boundaries, without a network or live evidence.
			script := "set -euo pipefail\nmanifest=" + strconv.Quote(manifest) + "\nscenario=baseline-clean\n" + header + child + "\nprintf '%s\\n' \"$scenario\"\n" + footer + "\nprintf 'last=%s\\n' \"$scenario\"\n"
			command := exec.Command("bash", "-c", script)
			command.Stdin = strings.NewReader("ordinary child input\n")
			output, err := command.CombinedOutput()
			if err != nil || string(output) != "baseline-clean\nbaseline-refusal\nkaring-final\nlast=karing-final\n" {
				t.Fatalf("scenario loop lost input or failure identity: %v, output = %q", err, output)
			}
		})
	}
}

func TestRecurringCollectorSubmitsExactTypedFailureWithoutDiscardingStdin(t *testing.T) {
	directory := t.TempDir()
	remoteDirectory := filepath.Join(directory, "remote")
	if err := os.Mkdir(remoteDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"schema":"sbxr-qualification-manifest-v3","source_state":"v3-recurring","v3_attempt":{"attempt_id":"attempt-1"}}`)
	manifestPath := filepath.Join(directory, "qualification-manifest.json")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	facts := []byte(`{"failure":{"actual_result":"unexpected-failure","scenario_id":"baseline-postcommit"},"qualification_manifest":{"schema":"sbxr-qualification-manifest-v3","source_state":"v3-recurring","v3_attempt":{"attempt_id":"attempt-1"}},"schema":"sbxr-release-qualification-facts-v1","stage":"v3-scenario-failure"}`)
	factsPath := filepath.Join(directory, "failure-facts.json")
	if err := os.WriteFile(factsPath, facts, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := fmt.Sprintf("%x", sha256.Sum256(manifest))
	request := fmt.Sprintf(`{"deadline_unix":1,"qualification_manifest_sha256":%q,"scenario_id":"baseline-postcommit"}`, manifestDigest)
	if err := os.WriteFile(filepath.Join(remoteDirectory, "request.json"), []byte(request), 0o600); err != nil {
		t.Fatal(err)
	}

	binDirectory := filepath.Join(directory, "bin")
	if err := os.Mkdir(binDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	// Model ssh -n faithfully: it redirects stdin from /dev/null. The submit
	// path may use it to read the request, but must not use it for publication.
	fakeSSH := `#!/usr/bin/env bash
set -euo pipefail
discard_stdin=false
for argument in "$@"; do
  if test "$argument" = -n; then discard_stdin=true; fi
done
remote_command="${!#}"
remote_command="${remote_command//\/root\/sbxr-qualification-evidence/$FAKE_REMOTE_DIRECTORY}"
if test "$discard_stdin" = true; then
  exec bash -c "$remote_command" </dev/null
fi
exec bash -c "$remote_command"
`
	if err := os.WriteFile(filepath.Join(binDirectory, "ssh"), []byte(fakeSSH), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDirectory, "mv"), []byte("#!/usr/bin/env bash\nif test \"${1:-}\" = -T; then shift; fi\nexec /bin/mv \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	fakeCat := `#!/usr/bin/env bash
set -euo pipefail
if test "$#" -gt 0; then exec /bin/cat "$@"; fi
case "${FAKE_PAYLOAD_MODE:-}" in
  drop) /bin/cat >/dev/null ;;
  truncate) /bin/cat | head -c 8 ;;
  stop) /bin/cat; printf 'STOP\n' > "$FAKE_REMOTE_DIRECTORY/request.json" ;;
  *) /bin/cat ;;
esac
`
	if err := os.WriteFile(filepath.Join(binDirectory, "cat"), []byte(fakeCat), 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "ssh.key")
	knownHostsPath := filepath.Join(directory, "known_hosts")
	if err := os.WriteFile(keyPath, []byte("test key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHostsPath, []byte("test host key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runSubmit := func(payloadMode string) ([]byte, error) {
		command := exec.Command("bash", ".github/scripts/v3-recurring-evidence.sh", "submit", "example.test", keyPath, knownHostsPath, manifestPath, factsPath)
		command.Env = append(os.Environ(), "PATH="+binDirectory+":"+os.Getenv("PATH"), "FAKE_REMOTE_DIRECTORY="+remoteDirectory, "FAKE_PAYLOAD_MODE="+payloadMode)
		return command.CombinedOutput()
	}
	if output, err := runSubmit(""); err != nil {
		t.Fatalf("submit typed failure: %v\n%s", err, output)
	}
	resultPath := filepath.Join(remoteDirectory, "result.json")
	published, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(published, facts) {
		t.Fatalf("published facts changed: got %q want %q", published, facts)
	}
	if _, err := os.Stat(filepath.Join(remoteDirectory, "result.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary publication remains: %v", err)
	}
	if output, err := runSubmit(""); err == nil {
		t.Fatalf("existing result was accepted: %s", output)
	}
	stillPublished, err := os.ReadFile(resultPath)
	if err != nil || !bytes.Equal(stillPublished, facts) {
		t.Fatalf("existing result changed: %v, got %q", err, stillPublished)
	}
	if err := os.Remove(resultPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(factsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runSubmit(""); err == nil {
		t.Fatalf("empty result was accepted: %s", output)
	}
	if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
		t.Fatalf("empty result was published: %v", err)
	}
	if err := os.WriteFile(factsPath, facts, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, payloadMode := range []string{"drop", "truncate", "stop"} {
		t.Run(payloadMode, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(remoteDirectory, "request.json"), []byte(request), 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := runSubmit(payloadMode); err == nil {
				t.Fatalf("faulty transfer was accepted: %s", output)
			}
			if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
				t.Fatalf("faulty transfer was published: %v", err)
			}
			temporaryPath := filepath.Join(remoteDirectory, "result.tmp")
			if err := os.Remove(temporaryPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
	for _, invalid := range []struct {
		name  string
		facts []byte
	}{
		{name: "wrong-scenario", facts: bytes.Replace(facts, []byte("baseline-postcommit"), []byte("baseline-clean"), 1)},
		{name: "wrong-manifest", facts: bytes.Replace(facts, []byte("attempt-1"), []byte("attempt-2"), 1)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(remoteDirectory, "request.json"), []byte(request), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(factsPath, invalid.facts, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := runSubmit(""); err == nil {
				t.Fatalf("unbound facts were accepted: %s", output)
			}
			if _, err := os.Stat(resultPath); !os.IsNotExist(err) {
				t.Fatalf("unbound facts were published: %v", err)
			}
		})
	}
}
