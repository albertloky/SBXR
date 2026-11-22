package architecture_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshQualificationUsesTheExistingSigningRole(t *testing.T) {
	workflow, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	body := string(workflow)
	_, preflight, preflightFound := strings.Cut(body, "\n  preflight:\n")
	preflight, _, _ = strings.Cut(preflight, "\n  rust-native:")
	_, drafts, draftsFound := strings.Cut(body, "\n  drafts:\n")
	drafts, sign, signFound := strings.Cut(drafts, "\n  sign:\n")
	sign, _, liveFound := strings.Cut(sign, "\n  acceptance-vps:")
	if !preflightFound || !draftsFound || !signFound || !liveFound {
		t.Fatal("existing candidate roles are missing")
	}
	for _, item := range []struct{ section, expected string }{
		{preflight, "!inputs.fresh_window"},
		{drafts, "bash .github/scripts/fresh-qualification.sh prepare"},
		{sign, "bash .github/scripts/fresh-qualification.sh authorize"},
		{sign, "subject-path: fresh-window-decision.json"},
		{sign, "\n    environment: acceptance-vps\n    permissions:\n      actions: read\n      attestations: write\n      contents: read\n      id-token: write\n"},
	} {
		if !strings.Contains(item.section, item.expected) {
			t.Errorf("fresh workflow role lacks %q", item.expected)
		}
	}
}

func TestFreshQualificationWorkflowPreservesProtectedAdmissionOrder(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, live, ok := strings.Cut(string(body), "\n  acceptance-vps:\n")
	live, _, _ = strings.Cut(live, "\n  owner-exception:")
	if !ok || !strings.Contains(live, "\n    environment: acceptance-vps\n    permissions:\n      actions: read\n      attestations: read\n      contents: write\n") {
		t.Fatal("fresh acceptance must keep the protected role and existing permissions")
	}
	order := []string{
		"bash .github/scripts/fresh-qualification.sh verify-live",
		"gh attestation verify qualification-manifest.json",
		"bash .github/scripts/fresh-qualification.sh admit",
		"name: fresh-qualification-use-",
		"fresh-qualification.sh recheck-clock",
		"sha256sum /etc/machine-id",
		"mkdir -m 0700 /root/sbxr-qualification-v3",
		"bash .github/scripts/fresh-qualification.sh record-restoration",
		"gh api \"repos/$GITHUB_REPOSITORY/releases/$release_id\" --method PATCH",
	}
	for _, marker := range order {
		_, next, found := strings.Cut(live, marker)
		if !found {
			t.Fatalf("fresh workflow lacks ordered boundary %q", marker)
		}
		live = next
	}
}

func TestFreshQualificationAuthorityFixtures(t *testing.T) {
	command := exec.Command("python3", "-B", ".github/scripts/test_qualification_window_authority.py")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fresh qualification authority: %v\n%s", err, output)
	}
}

func TestFreshQualificationHostReadinessFailsClosed(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, check, found := strings.Cut(string(body), `"root@$ACCEPTANCE_VPS_HOST" 'set -eu; test "$(`)
	check, _, terminated := strings.Cut(check, `' | cut -d`)
	if !found || !terminated {
		t.Fatal("missing fresh host readiness command")
	}
	check = `set -eu; test "$(` + check
	check = strings.ReplaceAll(check, ". /etc/os-release", `ID="$TEST_ID"; VERSION_ID=24.04`)
	check = strings.ReplaceAll(check, "$(uname -m)", `$TEST_ARCH`)
	check = strings.ReplaceAll(check, "command -v strace", `test "$TEST_STRACE" = available`)
	check = strings.ReplaceAll(check, "/usr/local/bin/sbxr /var/lib/sbxr /run/sbxr-qualification /root/sbxr-qualification-v3 /root/sbxr-qualification-evidence", `"$TEST_STAGING"`)
	check = strings.ReplaceAll(check, "sha256sum /etc/machine-id", "printf 'synthetic-identity\\n'")
	for _, tc := range []struct {
		name, id, arch, strace string
		existing               bool
		want                   bool
	}{
		{"clean", "ubuntu", "x86_64", "available", false, true},
		{"wrong OS", "debian", "x86_64", "available", false, false},
		{"wrong architecture", "ubuntu", "arm64", "available", false, false},
		{"missing strace", "ubuntu", "x86_64", "missing", false, false},
		{"preexisting state", "ubuntu", "x86_64", "available", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			staging := filepath.Join(t.TempDir(), "staging")
			if tc.existing {
				if err := os.WriteFile(staging, []byte("already there"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-c", check)
			command.Env = append(os.Environ(), "TEST_ID="+tc.id, "TEST_ARCH="+tc.arch,
				"TEST_STRACE="+tc.strace, "TEST_STAGING="+staging)
			output, err := command.CombinedOutput()
			if (err == nil) != tc.want || strings.Contains(string(output), "synthetic-identity") != tc.want {
				t.Fatalf("readiness returned %v and %q, want admitted=%v", err, output, tc.want)
			}
		})
	}
}

func TestFreshQualificationStagingHasOnlyOneOwner(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/candidate.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, claim, found := strings.Cut(string(body), `"root@$ACCEPTANCE_VPS_HOST" 'test ! -e /root/sbxr-qualification-v3 && test ! -L /root/sbxr-qualification-v3 && mkdir -m 0700`)
	claim, _, terminated := strings.Cut(claim, "'\n")
	if !found || !terminated {
		t.Fatal("missing exclusive staging command")
	}
	claim = `test ! -e /root/sbxr-qualification-v3 && test ! -L /root/sbxr-qualification-v3 && mkdir -m 0700` + claim
	claim = strings.ReplaceAll(claim, "/root/sbxr-qualification-v3", `"$TEST_STAGING"`)
	claim = strings.ReplaceAll(claim, "${{ github.run_id }}-${{ github.run_attempt }}", "$TEST_OWNER")
	staging := filepath.Join(t.TempDir(), "staging")
	first := exec.Command("bash", "-c", claim)
	first.Env = append(os.Environ(), "TEST_STAGING="+staging, "TEST_OWNER=first")
	second := exec.Command("bash", "-c", claim)
	second.Env = append(os.Environ(), "TEST_STAGING="+staging, "TEST_OWNER=second")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	secondStart := second.Start()
	firstResult := first.Wait()
	if secondStart != nil {
		t.Fatal(secondStart)
	}
	secondResult := second.Wait()
	if (firstResult == nil) == (secondResult == nil) {
		t.Fatalf("expected one owner, got %v and %v", firstResult, secondResult)
	}
	winner := "first\n"
	if secondResult == nil {
		winner = "second\n"
	}
	owner, err := os.ReadFile(filepath.Join(staging, "staging-owned"))
	if err != nil || string(owner) != winner {
		t.Fatalf("staging owner %q, %v, expected %q", owner, err, winner)
	}
}

func TestStablePublicationEvidenceNamesTheQualificationRun(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/stable.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, step, found := strings.Cut(string(body), "      - name: Retain public stable evidence\n")
	step, _, _ = strings.Cut(step, "\n      - ")
	_, shell, hasShell := strings.Cut(step, "        run: |\n")
	if !found || !hasShell {
		t.Fatal("missing publication evidence step")
	}
	const origin = "https://github.com/albertloky/SBXR/actions/runs/101"
	const live = "https://github.com/albertloky/SBXR/actions/runs/102"
	for _, tc := range []struct{ name, preflight, qualification, provenance string }{
		{"single run", `{}`, origin, ""},
		{"fresh window", `{"fresh_window":{},"acceptance_facts":{"fresh_window":{"workflow":{"run_url":"` + live + `"}}}}`, live, origin},
		{"broken preflight evidence", `{`, "", ""},
		{"fresh evidence missing live run", `{"fresh_window":{}}`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"verified", "public"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range map[string]string{
				"verified/qualification-manifest.json": `{"mode":"v3","releases":[{"tag":"v3.1.1"}],"workflow":{"run_url":"` + origin + `"}}`,
				"verified/stable-preflight-facts.json": tc.preflight,
				"stable-v3-finalization-facts.json":    `{}`,
				"stable-v3-finalization-decision.json": `{"prior_decision_sha256":"synthetic","v3_packaged_live":"Passed"}`,
			} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("bash", "-c", shell)
			command.Dir = root
			command.Env = append(os.Environ(), "GITHUB_SERVER_URL=https://github.com", "GITHUB_REPOSITORY=albertloky/SBXR",
				"GITHUB_RUN_ID=103", "GITHUB_STEP_SUMMARY="+filepath.Join(root, "summary"))
			out, shellErr := command.CombinedOutput()
			raw, err := os.ReadFile(filepath.Join(root, "stable-evidence", "result.json"))
			if tc.qualification == "" {
				if shellErr == nil || !os.IsNotExist(err) {
					t.Fatalf("wrote result from invalid evidence: %v %s", shellErr, out)
				}
				return
			}
			if shellErr != nil {
				t.Fatalf("publication evidence shell: %v %s", shellErr, out)
			}
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Qualification string `json:"qualification_run"`
				Provenance    string `json:"artifact_provenance_run"`
			}
			if err := json.Unmarshal(raw, &report); err != nil || report.Qualification != tc.qualification || report.Provenance != tc.provenance {
				t.Fatalf("evidence identity = %+v, want %s and %s (%v)", report, tc.qualification, tc.provenance, err)
			}
		})
	}
}
