package architecture_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestV3RealSSHBoundaries(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("isolated SSH fixture requires root Linux")
	}
	for _, tool := range []string{"python3", "unshare", "mount", "sshd", "ssh", "ssh-keygen", "jq", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("isolated SSH fixture requires %s", tool)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/tests/test_ssh_boundary.py")
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 10 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real SSH boundary regression: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "SSH_BOUNDARY_CASES_PASSED") {
		t.Fatalf("real SSH boundary fixture did not exercise its cases:\n%s", output)
	}
}
