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
	for _, required := range []string{
		"v3-scenario-result", "v3-scenario-failure", "stop_test_mutations",
		"qualification <", "completed_at", "300", "7200", "STOP",
		"failure-recorded", "retained-failure.json", ".failure.scenario_id == $scenario",
		`test ! -L /root/sbxr-qualification-evidence`,
		`test ! -L /root/sbxr-qualification-evidence/result.json`,
		`test ! -L '$mvp_observation_remote'`,
		`test ! -L /usr/local/bin/sbxr`,
		`test ! -L /var/lib/sbxr`,
	} {
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

func TestRecurringCollectorRequestPublicationPreservesUnsafePaths(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	var remoteCommand string
	for _, line := range strings.Split(string(source), "\n") {
		if !strings.Contains(line, `cat > /root/sbxr-qualification-evidence/request.json' < "$directory/request.json"`) {
			continue
		}
		start := strings.Index(line, "'")
		end := strings.LastIndex(line, `' < "$directory/request.json"`)
		if start < 0 || end <= start {
			t.Fatal("collector request command boundary changed")
		}
		remoteCommand = line[start+1 : end]
		break
	}
	if remoteCommand == "" {
		t.Fatal("collector request command not found")
	}
	for _, test := range []struct {
		name, symlink string
		targetExists  bool
		resultExists  bool
		accept        bool
	}{
		{name: "regular request", accept: true},
		{name: "existing result", resultExists: true},
		{name: "dangling result", symlink: "result.json"},
		{name: "linked result", symlink: "result.json", targetExists: true},
		{name: "dangling request", symlink: "request.json"},
		{name: "linked request", symlink: "request.json", targetExists: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			remoteRoot := t.TempDir()
			request := filepath.Join(remoteRoot, "request.json")
			result := filepath.Join(remoteRoot, "result.json")
			if err := os.WriteFile(request, []byte("original request\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if test.resultExists {
				if err := os.WriteFile(result, []byte("original result\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(remoteRoot, "foreign-target")
			link := filepath.Join(remoteRoot, test.symlink)
			if test.symlink != "" {
				if test.symlink == "request.json" {
					if err := os.Remove(request); err != nil {
						t.Fatal(err)
					}
				}
				if test.targetExists {
					if err := os.WriteFile(target, []byte("foreign sentinel\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-c", strings.ReplaceAll(remoteCommand, "/root/sbxr-qualification-evidence", remoteRoot))
			command.Stdin = strings.NewReader("new request\n")
			output, err := command.CombinedOutput()
			if (err == nil) != test.accept {
				t.Fatalf("request publication accepted = %v, error = %v, output = %s", err == nil, err, output)
			}
			if test.accept {
				assertFileBody(t, request, "new request\n")
			} else if test.symlink != "request.json" {
				assertFileBody(t, request, "original request\n")
			}
			if test.resultExists {
				assertFileBody(t, result, "original result\n")
			}
			if test.symlink != "" {
				if got, err := os.Readlink(link); err != nil || got != target {
					t.Fatalf("link changed: got %q, %v", got, err)
				}
				if test.targetExists {
					assertFileBody(t, target, "foreign sentinel\n")
				} else if _, err := os.Lstat(target); !os.IsNotExist(err) {
					t.Fatalf("dangling link target was created: %v", err)
				}
			}
		})
	}
}

func TestRecurringCollectorNeverFollowsEvidenceDirectoryForStopOrCleanup(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-recurring-evidence.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, needle, suffix string
	}{
		{name: "failure stop", needle: `printf "%s\n" STOP`, suffix: `' || true`},
		{name: "successful cleanup", needle: `rmdir /root/sbxr-qualification-evidence`, suffix: `'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var remoteCommand string
			for _, line := range strings.Split(string(source), "\n") {
				if !strings.Contains(line, test.needle) {
					continue
				}
				start := strings.Index(line, "'")
				end := strings.LastIndex(line, test.suffix)
				if start < 0 || end <= start {
					t.Fatal("collector evidence-directory command boundary changed")
				}
				remoteCommand = line[start+1 : end]
				break
			}
			if remoteCommand == "" {
				t.Fatal("collector evidence-directory command not found")
			}
			fixture := t.TempDir()
			foreign := filepath.Join(fixture, "foreign")
			if err := os.Mkdir(foreign, 0700); err != nil {
				t.Fatal(err)
			}
			request := filepath.Join(foreign, "request.json")
			if err := os.WriteFile(request, []byte("foreign sentinel\n"), 0600); err != nil {
				t.Fatal(err)
			}
			evidence := filepath.Join(fixture, "evidence")
			if err := os.Symlink(foreign, evidence); err != nil {
				t.Fatal(err)
			}
			remoteCommand = strings.ReplaceAll(remoteCommand, "/root/sbxr-qualification-evidence", evidence)
			remoteCommand = strings.ReplaceAll(remoteCommand, "/usr/local/bin/sbxr", filepath.Join(fixture, "absent-product"))
			remoteCommand = strings.ReplaceAll(remoteCommand, "/var/lib/sbxr", filepath.Join(fixture, "absent-state"))
			if output, err := exec.Command("bash", "-c", remoteCommand).CombinedOutput(); err == nil {
				t.Fatalf("symlinked evidence directory admitted: %s", output)
			}
			assertFileBody(t, request, "foreign sentinel\n")
			if target, err := os.Readlink(evidence); err != nil || target != foreign {
				t.Fatalf("evidence directory link changed: got %q, %v", target, err)
			}
		})
	}
}

func assertFileBody(t *testing.T, name, want string) {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil || string(body) != want {
		t.Fatalf("%s changed: got %q, %v", name, body, err)
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
