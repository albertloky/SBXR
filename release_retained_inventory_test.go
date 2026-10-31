package architecture_test

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestRetainedQ205Inventory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_retained_q205.py", "-v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("retained inventory: %v\n%s", err, output)
	}
}

func TestRetainedQ206Inventory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_retained_q206.py", "-v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("retained inventory: %v\n%s", err, output)
	}
}
