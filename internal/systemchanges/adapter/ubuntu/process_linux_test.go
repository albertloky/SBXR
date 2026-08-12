//go:build linux

package ubuntu

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSignalReclamationProcessFreezesIdentityBeforeFinalProof(t *testing.T) {
	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	statusPath := fmt.Sprintf("/proc/%d/status", command.Process.Pid)
	verified := false
	err := signalReclamationProcess(command.Process.Pid, statusPath, time.Second, func() error {
		status, err := os.ReadFile(statusPath)
		if err != nil {
			return err
		}
		if !bytes.Contains(status, []byte("\nState:\tT")) && !bytes.Contains(status, []byte("\nState:\tt")) {
			return fmt.Errorf("process was not frozen during proof")
		}
		verified = true
		return nil
	})
	if err != nil || !verified {
		t.Fatalf("frozen pidfd signal = %v, verified=%t", err, verified)
	}
}
