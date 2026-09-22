package architecture_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestMVPWindowObserverContracts(t *testing.T) {
	command := exec.Command("python3", ".github/scripts/test_mvp_inspect_window.py", "-v")
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("MVP window observer contracts: %v\n%s", err, output)
	}
}

func TestMVPWindowObserverLinuxIntegration(t *testing.T) {
	deb := os.Getenv("SBXR_MVP_OBSERVER_DEB")
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || deb == "" {
		t.Skip("requires explicitly marked disposable amd64 VM and SBXR_MVP_OBSERVER_DEB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_mvp_inspect_window_linux.py", deb)
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 30 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("MVP window observer real dpkg/SSH rehearsal: %v\n%s", err, output)
	}
}
