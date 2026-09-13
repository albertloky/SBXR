package architecture_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
)

func TestV3QualificationAcceptsTheCanonicalClientConfiguration(t *testing.T) {
	script, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "jq -e '"
	start := strings.Index(string(script), prefix+`.inbounds ==`)
	if start < 0 {
		t.Fatal("V3 qualification omitted the Client Configuration predicate")
	}
	start += len(prefix)
	end := strings.Index(string(script)[start:], `' "$client_config"`)
	if end < 0 {
		t.Fatal("V3 qualification Client Configuration predicate is malformed")
	}
	predicate := string(script)[start : start+end]
	want := `.inbounds == [{type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080}] and (.outbounds | length) == 1`
	if predicate != want {
		t.Fatalf("Client Configuration predicate = %q", predicate)
	}

	adapter := singboxadapter.New()
	identity, err := adapter.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	server, err := adapter.EncodeServerConfiguration(identity, "microsoft.com:443", "microsoft.com")
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.EncodeClientConfiguration(server, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("jq", "-e", predicate)
	command.Stdin = bytes.NewReader(client)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("live Client Configuration predicate rejected the production encoder: %v\n%s", err, output)
	}
}

func TestPackagedActionReadsItsResultNotLifecycleStatus(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "run_action() {")
	if start < 0 {
		t.Fatal("run_action function not found")
	}
	end := strings.Index(string(source)[start:], "\n}\n\nview_details() {")
	if end < 0 {
		t.Fatal("run_action function not found")
	}
	function := string(source)[start : start+end+2]
	const setup = "Code: PROXY-INSTALLATION-SETUP-COMPLETE"
	const removed = "Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED"
	const initial = "SBXR V3\n" + setup + "\nSoftware Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n0. Exit\n"
	for _, test := range []struct {
		name, after, expected string
		want                  bool
	}{
		{"setup with lifecycle status", "SBXR V3\n" + setup + "\nSoftware Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n0. Exit\n", setup, true},
		{"real refusal after prior success", "SBXR V3\nCode: PROXY-INSTALLATION-ACTION-REFUSED\nSoftware Lifecycle: Ready\nCode: SOFTWARE-LIFECYCLE-STATUS-READY\n0. Exit\n", setup, false},
		{"missing action result", "", setup, false},
		{"complete removal without another menu", removed + "\n", removed, true},
		{"refused removal", "Code: PROXY-INSTALLATION-ACTION-REFUSED\n", removed, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command("bash", "-c", "set -euo pipefail\nmenu_session_action() { printf '%s' \"$ACTION_OUTPUT\"; }\nscan_vps_capture() { return 0; }\n"+function+"\nrun_action 'Start setup' y \"$EXPECTED\"\n")
			command.Env = append(os.Environ(), "ACTION_OUTPUT="+initial+test.after, "EXPECTED="+test.expected)
			output, err := command.CombinedOutput()
			if (err == nil) != test.want {
				t.Fatalf("action success = %v, want %v; output: %s", err == nil, test.want, output)
			}
		})
	}
}

func TestPackagedInterruptionRequiresObservedEventAndForcedDeath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real process-group interruption and subreaper checks require Linux")
	}
	// Exercise the real packaged function, including timeout, signal, lock and
	// descendant behavior. Rewriting shell snippets and mocking wait/kill hid
	// the live orphan failure and no longer represents the controller seam.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-m", "unittest", "discover", "-v",
		"-s", ".github/scripts", "-p", "test_v3_packaged_live_interrupt.py")
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("packaged interruption process fixture: %v\n%s", err, output)
	}
}

func TestPackagedSigningKeyDownloadFollowsRedirectAndChecksDigest(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(source), "runner_stage=download-client-signing-key\n")
	download, _, ended := strings.Cut(rest, "runner_stage=download-client-package\n")
	if !found || !ended {
		t.Fatal("signing-key download block not found")
	}
	const key = "public signing key fixture\n"
	for _, body := range []string{key, "changed key\n"} {
		t.Run(strings.TrimSpace(body), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/gpg.key" {
					http.Redirect(w, r, "/key", http.StatusMovedPermanently)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			script := strings.NewReplacer(
				"https://sing-box.app/gpg.key", server.URL+"/gpg.key",
				"/dev/shm/sagernet.asc", filepath.Join(t.TempDir(), "sagernet.asc"),
				"803d5a2f09fe9d360008161aa2684e7f49a211d48a4116d0651b08bdd90bdea1", fmt.Sprintf("%x", sha256.Sum256([]byte(key))),
			).Replace(download)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "bash", "-c", "set -euo pipefail\n"+script).CombinedOutput()
			if (err == nil) != (body == key) {
				t.Fatalf("redirected key verification: %v, output = %s", err, output)
			}
		})
	}
}

func TestPackagedRunnerCleanupRetainsOnlyTheFixedFailedStage(t *testing.T) {
	source, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "\ncleanup() {")
	if start < 0 {
		t.Fatal("runner cleanup function not found")
	}
	start++
	end := strings.Index(string(source)[start:], "\n}\ntrap cleanup EXIT")
	if end < 0 {
		t.Fatal("runner cleanup function not found")
	}
	cleanup := string(source)[start : start+end+2]
	for _, test := range []struct {
		name       string
		exitStatus int
		wantStage  bool
	}{
		{name: "failure", exitStatus: 23, wantStage: true},
		{name: "success", wantStage: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			stageEvidence := filepath.Join(directory, "failure-evidence", "runner-stage.txt")
			workflowCapture := filepath.Join(directory, "workflow.log")
			secret := "11111111-1111-4111-8111-111111111111"
			body := "safe capture\n"
			if test.wantStage {
				body += secret + "\n"
			}
			if err := os.WriteFile(workflowCapture, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			sandboxCleanup := strings.ReplaceAll(cleanup, "/dev/shm/sagernet.asc", filepath.Join(directory, "sagernet.asc"))
			sandboxCleanup = strings.ReplaceAll(sandboxCleanup, "/dev/shm/sagernet.sources", filepath.Join(directory, "sagernet.sources"))
			sandbox := fmt.Sprintf("set -u\nclient_config=%q\nclient_root=%q\nclient_deb=%q\nclient_log=%q\nworkflow_capture=%q\nclient_uuid=%q\ndownload=\nrunner_stage=measure-proxied-route\nrunner_stage_evidence=%q\n%s\ntrap cleanup EXIT\nexit %d\n", filepath.Join(directory, "client.json"), filepath.Join(directory, "client"), filepath.Join(directory, "client.deb"), filepath.Join(directory, "client.log"), workflowCapture, secret, stageEvidence, sandboxCleanup, test.exitStatus)
			script := filepath.Join(directory, "cleanup.sh")
			if err := os.WriteFile(script, []byte(sandbox), 0o700); err != nil {
				t.Fatal(err)
			}
			output, runErr := exec.Command("bash", script).CombinedOutput()
			if (runErr != nil) != test.wantStage {
				t.Fatalf("cleanup error = %v, output = %s", runErr, output)
			}
			evidence, readErr := os.ReadFile(stageEvidence)
			if test.wantStage {
				if readErr != nil || string(evidence) != "Runner stage: measure-proxied-route\n" || strings.Contains(string(evidence), secret) {
					t.Fatalf("stage evidence = %q, %v", evidence, readErr)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("successful cleanup retained stage evidence: %q, %v", evidence, readErr)
			}
			if _, err := os.Stat(workflowCapture); !os.IsNotExist(err) {
				t.Fatalf("workflow capture remains: %v", err)
			}
		})
	}
}

func TestCandidateFailureCleanupFinishesOnlyThroughThePublicInterface(t *testing.T) {
	workflowBody, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	scriptBody, err := os.ReadFile(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	workflow, script := string(workflowBody), string(scriptBody)
	for _, required := range []string{
		"remote-failure-cleanup",
		"Finish cleanup",
		"PROXY-INSTALLATION-SETUP-CLEANED-UP",
		"Finish setup",
		"PROXY-INSTALLATION-SETUP-COMPLETE",
		"Finish removal",
		"SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED",
		"Complete removal",
		"prove_not_installed",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("packaged-live failure cleanup omitted %q", required)
		}
	}
	for _, required := range []string{`cleanup_mode='${{ inputs.mode }}'`, `if test "$cleanup_mode" = v3`, `if test -d /var/lib/sbxr; then find /var/lib/sbxr -depth -delete; fi`} {
		if !strings.Contains(workflow, required) {
			t.Errorf("candidate mode-specific failure cleanup omitted %q", required)
		}
	}
	cleanupCall := strings.Index(workflow, "remote-failure-cleanup")
	if cleanupCall < 0 {
		t.Fatal("candidate failure cleanup does not call the packaged public cleanup mode")
	}
	transportCleanup := strings.Index(workflow[cleanupCall:], "hosts.original")
	cleanupResult := strings.Index(workflow[cleanupCall:], `test "$proxy_cleanup_status" -eq 0`)
	if transportCleanup < 0 || cleanupResult < 0 || transportCleanup >= cleanupResult {
		t.Fatal("failure cleanup does not preserve the public cleanup result through qualification transport cleanup")
	}
	failureCleanup := workflow[cleanupCall : cleanupCall+cleanupResult]
	for _, forbidden := range []string{"rm -f /usr/local/bin/sbxr", "find /var/lib/sbxr -depth -delete"} {
		if strings.Contains(failureCleanup, forbidden) {
			t.Fatalf("failure cleanup bypasses public ownership with %q", forbidden)
		}
	}
}

func TestPackagedFailureCleanupHandlesEveryPublicFinishingState(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	driverSource, err := os.ReadFile(".github/scripts/v3-menu-session.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, state, behavior     string
		wantSuccess, wantRetained bool
	}{
		{"cleanup required", "cleanup", "success", true, false},
		{"setup required", "setup", "success", true, false},
		{"removal required", "removal", "success", true, false},
		{"removal output secret", "removal", "removal-secret", false, false},
		{"inspection failure", "inspection-failure", "failure", false, true},
		{"secret inspection failure", "secret-inspection", "failure", false, true},
		{"unowned mismatch", "problem", "failure", false, true},
		{"finishing failure", "cleanup", "finishing-failure", false, true},
		{"final absence failure", "not-set-up", "final-absence", false, true},
		{"absence inspection failure", "removal", "inspector-failure", false, false},
		{"unit inspection failure", "removal", "systemctl-failure", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			statePath := filepath.Join(directory, "state")
			binary := filepath.Join(directory, "sbxr")
			configuration := filepath.Join(directory, "config.json")
			sandboxScript := filepath.Join(directory, "v3-packaged-live.sh")
			sandboxDriver := filepath.Join(directory, "v3-menu-session.py")
			work := filepath.Join(directory, "work")
			bin := filepath.Join(directory, "bin")
			if err := os.MkdirAll(work, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(statePath, []byte(test.state+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fake := `#!/bin/sh
set -eu
state="$(cat "$FAKE_STATE")"
if test "$state" = inspection-failure; then exit 23; fi
if test "$state" = secret-inspection; then printf '%s\n' "$KNOWN_CLIENT_UUID"; exit 23; fi
menu() {
  printf 'SBXR V3\n'
  case "$1" in
    cleanup) printf 'Proxy status: Setup incomplete\n1. Finish cleanup\n' ;;
    setup) printf 'Proxy status: Setup incomplete\n1. Finish setup\n' ;;
    removal) printf 'Proxy status: Removal incomplete\n1. Finish removal\n' ;;
    not-set-up) printf 'Proxy status: Not set up\n1. Complete removal\n' ;;
    running) printf 'Proxy status: Running\n1. Complete removal\n' ;;
    problem) printf 'Proxy status: Problem detected\n1. View details\n' ;;
  esac
  printf '0. Exit\n'
}
menu "$state"
IFS= read -r choice || exit 24
case "$state:$choice" in
  cleanup:0|setup:0|removal:0|not-set-up:0|running:0|problem:0) exit ;;
  problem:1)
    printf 'Detected mismatch: unowned protected resource\nPress Enter to return to the menu.\n'
    IFS= read -r answer || exit 24
    menu problem
    IFS= read -r choice
    test "$choice" = 0
    ;;
  cleanup:1)
    printf 'Finish proxy cleanup? [y/N]\n'
    IFS= read -r answer || exit 24
    test "$answer" = y
    if test "$FAKE_BEHAVIOR" = finishing-failure; then printf 'Code: PROXY-INSTALLATION-ACTION-REFUSED\n'; exit; fi
    printf 'not-set-up\n' > "$FAKE_STATE"
    printf 'Code: PROXY-INSTALLATION-SETUP-CLEANED-UP\n'
    menu not-set-up
    IFS= read -r choice
    test "$choice" = 0
    ;;
  setup:1)
    printf 'Finish proxy setup? [y/N]\n'
    IFS= read -r answer || exit 24
    test "$answer" = y
    printf 'running\n' > "$FAKE_STATE"
    printf 'Code: PROXY-INSTALLATION-SETUP-COMPLETE\n'
    menu running
    IFS= read -r choice
    test "$choice" = 0
    ;;
  removal:1)
    rm -f "$0" "${FAKE_CONFIG:-}"
    if test "$FAKE_BEHAVIOR" = removal-secret; then printf '11111111-1111-4111-8111-111111111111\n'; fi
    printf 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED\n'
    ;;
  not-set-up:1|running:1)
    printf 'Type REMOVE SBXR to confirm Complete removal. Any other input cancels.\n'
    IFS= read -r answer || exit 24
    test "$answer" = 'REMOVE SBXR'
    if test "$FAKE_BEHAVIOR" != final-absence; then rm -f "$0"; fi
    printf 'Code: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED\n'
    ;;
  *) exit 24 ;;
esac
`
			if err := os.WriteFile(binary, []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sandboxDriver, driverSource, 0o700); err != nil {
				t.Fatal(err)
			}
			inspectors := map[string]string{
				"dpkg-query": "#!/bin/sh\nif test \"$FAKE_BEHAVIOR\" = inspector-failure; then exit 23; fi\nexit 1\n",
				"apt-mark":   "#!/bin/sh\nexit 0\n",
				"systemctl":  "#!/bin/sh\nif test \"$FAKE_BEHAVIOR\" = systemctl-failure; then printf 'inspection failed\\n' >&2; fi\nexit 1\n",
				"ss":         "#!/bin/sh\nexit 0\n",
				"getent":     "#!/bin/sh\nexit 2\n",
				"stat":       "#!/bin/sh\nprintf 'protected-path 700 0 0 1\\n'\n",
				"sha256sum":  "#!/bin/sh\nif test \"$#\" -eq 0; then cat >/dev/null; fi\nprintf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  -\\n'\n",
			}
			for name, body := range inspectors {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			body := strings.ReplaceAll(string(source), "/usr/local/bin/sbxr", binary)
			body = strings.ReplaceAll(body, "/etc/sing-box/config.json", configuration)
			body = strings.Replace(body, "WORK=/run/sbxr-qualification", "WORK="+work, 1)
			if err := os.WriteFile(sandboxScript, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", sandboxScript, "remote-failure-cleanup", "v3.0.10", "71", strings.Repeat("a", 40), strings.Repeat("b", 64))
			knownClientUUID := "11111111-1111-4111-8111-111111111111"
			if test.behavior == "removal-secret" {
				config := `{"inbounds":[{"tls":{"reality":{"private_key":"known-reality-private-key"}},"users":[{"uuid":"` + knownClientUUID + `"}]}]}`
				if err := os.WriteFile(configuration, []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "SBXR_EXECUTABLE="+binary, "FAKE_STATE="+statePath, "FAKE_BEHAVIOR="+test.behavior, "FAKE_CONFIG="+configuration)
			if test.behavior == "failure" && test.state == "secret-inspection" {
				command.Env = append(command.Env, "KNOWN_CLIENT_UUID="+knownClientUUID)
			}
			output, runErr := command.CombinedOutput()
			if (runErr == nil) != test.wantSuccess {
				t.Fatalf("cleanup error = %v, output = %s", runErr, output)
			}
			if test.wantRetained {
				if _, err := os.Stat(binary); err != nil {
					t.Fatalf("failed cleanup did not retain the inspected executable: %v", err)
				}
			}
			evidence, err := os.ReadFile(filepath.Join(work, "failure-cleanup-evidence.txt"))
			if err != nil || len(evidence) == 0 || strings.Contains(string(evidence), "PRIVATE KEY") || strings.Contains(string(evidence), knownClientUUID) {
				t.Fatalf("cleanup evidence = %q, %v", evidence, err)
			}
			if _, err := os.Stat(filepath.Join(work, "failure-cleanup-evidence.safe")); err != nil {
				t.Fatalf("safe cleanup evidence was not sealed: %v", err)
			}
			if test.state == "problem" && (!strings.Contains(string(evidence), "Detected mismatch: unowned protected resource") || !strings.Contains(string(evidence), "Legal finishing action: Absent") || !strings.Contains(string(evidence), "Protected inventory after:") || !strings.Contains(string(evidence), "Retention: Verified")) {
				t.Fatalf("mismatch evidence = %q", evidence)
			}
		})
	}
}
