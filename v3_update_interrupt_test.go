package architecture_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMVPProtectedWrapperPins(t *testing.T) {
	body, err := os.ReadFile(".github/scripts/sbxr-snapshot-recovery/with-protected-log-parent.sh")
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	for _, name := range []string{
		".github/scripts/mvp-protected-menu.sh",
		".github/scripts/mvp-update-interrupt.py",
		"internal/proxyinstallation/protected_log_parent_linux_test.go",
		"docs/acceptance/mvp-protected-log-parent-2026-09-19.md",
	} {
		caller, err := os.ReadFile(name)
		if err != nil || !strings.Contains(string(caller), digest) {
			t.Fatalf("%s does not pin the current reviewed wrapper %s: %v", name, digest, err)
		}
	}
}

func TestMVPUpdateControlSyntax(t *testing.T) {
	for _, name := range []string{"mvp-update-interrupt.py", "test_mvp_update_interrupt.py", "test_mvp_released_umask.py", "test_mvp_startup_cleanup.py"} {
		cmd := exec.Command("python3", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read())", ".github/scripts/"+name)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, output)
		}
	}
	if output, err := exec.Command("bash", "-n", ".github/scripts/mvp-protected-menu.sh").CombinedOutput(); err != nil {
		t.Fatalf("launcher syntax: %v\n%s", err, output)
	}
}

func TestMVPStartupCleanupLinuxIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("SBXR_UPDATE_CONTROL_VM") != "1" {
		t.Skip("requires explicitly marked disposable Linux VM and SBXR_UPDATE_CONTROL_VM=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_mvp_startup_cleanup.py")
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 20 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("real wrapper startup cancellation: %v\n%s", err, output)
	}
}

func TestMVPUpdateControlLinuxIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("SBXR_UPDATE_CONTROL_VM") != "1" {
		t.Skip("requires explicitly marked disposable Linux VM and SBXR_UPDATE_CONTROL_VM=1")
	}
	directory := t.TempDir()
	fixture := filepath.Join(directory, "fixture")
	build := exec.Command("go", "build", "-o", fixture, "./.github/scripts/testdata/update-interrupt-fixture")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_mvp_update_interrupt.py", fixture)
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 20 * time.Second
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "UPDATE_INTERRUPT_FIXTURE_PASSED count=18") {
		t.Fatalf("real syscall/wrapper fixture: %v\n%s", err, output)
	}
}
