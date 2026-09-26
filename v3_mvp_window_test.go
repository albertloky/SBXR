package architecture_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMVPWindowObserverContracts(t *testing.T) {
	for _, name := range []string{"test_mvp_inspect_window.py", "test_mvp_recovery_window.py"} {
		command := exec.Command("python3", ".github/scripts/"+name, "-v")
		command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("MVP window observer contracts %s: %v\n%s", name, err, output)
		}
	}
}

func TestMVPWindowObserverLinuxIntegration(t *testing.T) {
	deb := os.Getenv("SBXR_MVP_OBSERVER_DEB")
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || deb == "" {
		t.Skip("requires explicitly marked disposable amd64 VM and SBXR_MVP_OBSERVER_DEB")
	}
	fixture := filepath.Join(t.TempDir(), "window-recovery-fixture")
	build := exec.Command("go", "build", "-o", fixture, "./.github/scripts/testdata/window-recovery-fixture")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("recovery lifecycle fixture build: %v\n%s", err, output)
	}
	source := os.Getenv("SBXR_MVP_RECOVERY_SOURCE")
	if source == "" {
		source = fixture
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_mvp_inspect_window_linux.py", deb, source, fixture)
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 30 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("MVP window observer real dpkg/SSH rehearsal: %v\n%s", err, output)
	}
}
