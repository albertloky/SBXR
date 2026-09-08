package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCandidateIdentitySurvivesFreshShell(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixture := `set -euo pipefail
cd "$1"
printf executable > sbxr
executable=$(sha256sum sbxr | cut -d' ' -f1)
commit=$(printf '%040d' 1)
index=$(printf '%064d' 2)
jq -cn --arg commit "$commit" --arg index "$index" '{mode:"v3",schema:"sbxr-qualification-manifest-v3",source_state:"v3-subscription-clean",releases:[{tag:"v3.1.50",commit:$commit,sequence:131,release_identity:{repository:"albertloky/SBXR",tag:"v3.1.50",commit:$commit,release_index_sha256:$index}}]}' > manifest
jq -cn --arg digest "$(sha256sum manifest | cut -d' ' -f1)" '{qualification_manifest_sha256:$digest}' > request
jq -cn --arg commit "$commit" --arg index "$index" --arg executable "$executable" '{repository:"albertloky/SBXR",tag:"v3.1.50",sequence:131,commit:$commit,release_index_sha256:$index,architecture:"amd64",executable_sha256:$executable}' > installed
`
	for _, mutation := range []string{"", "unset TAG SEQUENCE COMMIT INDEX", `printf changed >> manifest`, `jq '.qualification_manifest_sha256="bad"' request > next; mv next request`, `jq '.sequence=130' installed > next; mv next installed`, `jq '.tag="v3.1.49"' installed > next; mv next installed`, `printf changed >> sbxr`, `rm request`, `mv manifest actual; ln -s actual manifest`, `jq '.architecture="arm64"' installed > next; mv next installed`, `jq '.commit="bad"' installed > next; mv next installed`, `jq '.release_index_sha256="bad"' installed > next; mv next installed`, `jq '.repository="other/SBXR"' installed > next; mv next installed`} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			if out, err := exec.Command("bash", "-c", fixture, "fixture", dir).CombinedOutput(); err != nil {
				t.Fatalf("fixture: %v %s", err, out)
			}
			if mutation == "" {
				body, err := os.ReadFile(script)
				if err != nil {
					t.Fatal(err)
				}
				// Relocate only filesystem fixtures; exercise the unchanged CLI
				// dispatch without touching a real installed product or VPS.
				sandbox := strings.NewReplacer(
					"/root/sbxr-qualification-v3/qualification-manifest.json", filepath.Join(dir, "manifest"),
					"/root/sbxr-qualification-evidence/request.json", filepath.Join(dir, "request"),
					"/var/lib/sbxr/installed.json", filepath.Join(dir, "installed"),
					"/usr/local/bin/sbxr", filepath.Join(dir, "sbxr"),
				).Replace(string(body))
				entry := filepath.Join(dir, "live.sh")
				if err := os.WriteFile(entry, []byte(sandbox), 0600); err != nil {
					t.Fatal(err)
				}
				for _, args := range [][]string{{entry, "remote-exact-candidate"}, {entry, "remote-exact-candidate", "unexpected"}} {
					cmd := exec.Command("bash", args...)
					cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
					out, err := cmd.CombinedOutput()
					if (err == nil) != (len(args) == 2) {
						t.Fatalf("candidate CLI dispatch: %v %s", err, out)
					}
				}
			}
			// Every assertion runs in a new noninteractive shell with no candidate
			// exports. Stale caller values must not override the bound manifest.
			command := exec.Command("bash", "-c", `set -euo pipefail
cd "$1"
source "$2"
TAG=stale SEQUENCE=1 COMMIT=stale INDEX=stale
`+mutation+`
exact_candidate manifest request installed sbxr`, "check", dir, script)
			command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
			out, err := command.CombinedOutput()
			valid := mutation == "" || mutation == "unset TAG SEQUENCE COMMIT INDEX"
			if valid && err != nil {
				t.Fatalf("fresh-shell candidate check: %v %s", err, out)
			}
			if !valid && err == nil {
				t.Fatal("accepted mismatched candidate")
			}
			if strings.Contains(string(out), "unbound variable") {
				t.Fatalf("candidate depends on inherited state: %s", out)
			}
		})
	}
}

func TestPackagedLiveSourcePreservesCallerState(t *testing.T) {
	script, err := filepath.Abs(".github/scripts/v3-packaged-live.sh")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", `set +e +u; set +o pipefail
umask 022
WORK=caller PACKAGE_SHA256=caller PACKAGE_SIZE=caller
before_flags=$-; before_mask=$(umask)
source "$1"
test "$before_flags" = "$-" && test "$before_mask" = "$(umask)" &&
test "$WORK:$PACKAGE_SHA256:$PACKAGE_SIZE" = caller:caller:caller &&
! shopt -qo pipefail`, "source-check", script)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sourcing changed caller state: %v %s", err, out)
	}
}
