//go:build linux

package ubuntu

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestOwnerLaunchExecutesTheSameDescriptorThatPassedVerification(t *testing.T) {
	name, facts := stampedOwnerLaunchTestExecutable(t)
	executable, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	if err := verifyOwnerConsoleExecutable(executable, facts); err != nil {
		t.Fatalf("verify owner console executable: %v", err)
	}
	replacement := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, name); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("/proc/self/fd/3", "-test.run=^TestOwnerLaunchDescriptorHelper$")
	command.ExtraFiles = []*os.File{executable}
	command.Env = append(os.Environ(), "SBXR_OWNER_LAUNCH_DESCRIPTOR_HELPER=1", "SBXR_OWNER_LAUNCH_TAG="+facts.tag, "SBXR_OWNER_LAUNCH_COMMIT="+facts.commit, "SBXR_OWNER_LAUNCH_SHA256="+facts.sha256)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("same descriptor launch = %v\n%s", err, output)
	}
}

func TestOwnerLaunchDescriptorHelper(t *testing.T) {
	if os.Getenv("SBXR_OWNER_LAUNCH_DESCRIPTOR_HELPER") != "1" {
		return
	}
	facts, err := ownerLaunchFactsFromEnvironment(os.Geteuid())
	executable := os.NewFile(3, "verified-owner-console")
	if err != nil || executable == nil {
		t.Fatalf("launch facts = %v", err)
	}
	defer executable.Close()
	running, runningErr := os.Stat("/proc/self/exe")
	descriptor, descriptorErr := executable.Stat()
	if runningErr != nil || descriptorErr != nil || !os.SameFile(running, descriptor) || verifyOwnerConsoleExecutable(executable, facts) != nil {
		t.Fatal("root process did not execute the verified descriptor")
	}
}

func stampedOwnerLaunchTestExecutable(t *testing.T) (string, ownerLaunchFacts) {
	t.Helper()
	running, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(running)
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	metadata := installHandoffMetadata(t, softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: commit}, softwarelifecycle.Architecture(runtime.GOARCH))
	stamped, err := softwarelifecycle.StampPayload(body, metadata)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "sbxr")
	if err := os.WriteFile(name, stamped, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(stamped)
	return name, ownerLaunchFacts{uid: os.Geteuid(), tag: "v1.0.0", commit: commit, sha256: fmt.Sprintf("%x", digest)}
}
