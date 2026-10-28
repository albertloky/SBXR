package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Every fixture is finite and checks its private release file. The direct
// child is reaped by boundedCommandOutput; an orphaned leaf is reaped by init.
// Cleanup checks only the PID published by our leaf, never a process inventory.
func TestCommandDescendantFixture(t *testing.T) {
	if os.Getenv("SBXR_COMMAND_DESCENDANT_FIXTURE") != "1" {
		return
	}
	role, marker := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if role == "parent" || role == "exited-parent" {
		child := exec.Command(os.Args[0], "-test.run=^TestCommandDescendantFixture$", "--", "leaf", marker)
		if role == "exited-parent" {
			child.Env = append(os.Environ(), "SBXR_EXITED_PARENT_PID="+strconv.Itoa(os.Getpid()))
		}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(71)
		}
		if role == "parent" && child.Wait() != nil {
			os.Exit(74)
		}
		os.Exit(0)
	}
	if role != "leaf" {
		os.Exit(72)
	}
	// Readiness for the early-exit case must prove the leader has exited,
	// rather than merely racing its exit against cancellation.
	if parent := os.Getenv("SBXR_EXITED_PARENT_PID"); parent != "" {
		pid, err := strconv.Atoi(parent)
		if err != nil || pid <= 0 {
			os.Exit(75)
		}
		until := time.Now().Add(2 * time.Second)
		for os.Getppid() == pid {
			if time.Now().After(until) {
				os.Exit(76)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		os.Exit(73)
	}
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Stat(marker + ".release"); err == nil {
			os.Exit(0)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(0)
}

func waitOwnedLeafGone(pid int, duration time.Duration) bool {
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestCommandCancellationStopsDescendant(t *testing.T) {
	for _, role := range []string{"parent", "exited-parent"} {
		t.Run(role, func(t *testing.T) {
			for _, combined := range []bool{false, true} {
				for _, deadline := range []bool{false, true} {
					t.Run(strconv.FormatBool(combined)+"/deadline="+strconv.FormatBool(deadline), func(t *testing.T) {
						marker := filepath.Join(t.TempDir(), "leaf")
						var ctx context.Context
						var cancel context.CancelFunc
						if deadline {
							ctx, cancel = context.WithTimeout(t.Context(), time.Second)
						} else {
							ctx, cancel = context.WithCancel(t.Context())
						}
						defer cancel()
						command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCommandDescendantFixture$", "--", role, marker)
						// Keep race detection, but remove its artificial one-second
						// exit sleep so readiness measures actual leader exit.
						command.Env = append(os.Environ(), "SBXR_COMMAND_DESCENDANT_FIXTURE=1", "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
						finished := make(chan error, 1)
						done := make(chan struct{})
						go func() { defer close(done); _, err := boundedCommandOutput(command, combined); finished <- err }()
						pid := 0
						t.Cleanup(func() {
							cancel()
							if err := os.WriteFile(marker+".release", nil, 0600); err != nil {
								t.Error(err)
							}
							select {
							case <-done:
							case <-time.After(10 * time.Second):
								t.Error("fixture direct child was not reaped")
							}
							if pid != 0 && !waitOwnedLeafGone(pid, 3*time.Second) {
								t.Error("owned leaf was not reaped after cleanup")
							}
						})
						for until := time.Now().Add(750 * time.Millisecond); time.Now().Before(until); {
							if body, err := os.ReadFile(marker); err == nil {
								pid, _ = strconv.Atoi(string(body))
								if pid > 0 {
									break
								}
							}
							time.Sleep(10 * time.Millisecond)
						}
						if pid == 0 {
							cancel()
							<-finished
							t.Fatal("fixture did not become ready")
						}
						if !deadline {
							cancel()
						}
						select {
						case err := <-finished:
							if err == nil {
								t.Error("cancelled command succeeded")
							}
							if errors.Is(err, exec.ErrWaitDelay) {
								t.Error("descendant retained output pipe after cancellation")
							}
						case <-time.After(4 * time.Second):
							t.Fatal("cancelled command did not return")
						}
						if !waitOwnedLeafGone(pid, time.Second) {
							t.Error("descendant remained alive after cancelled command returned")
						}
					})
				}
			}
		})
	}
}

func TestCommandCancellationAdmission(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		command := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
		if _, err := boundedCommandOutput(command, false); !errors.Is(err, context.Canceled) || command.Process != nil {
			t.Fatalf("started cancelled command: process=%v err=%v", command.Process, err)
		}
	})
	t.Run("start failure", func(t *testing.T) {
		command := exec.CommandContext(t.Context(), filepath.Join(t.TempDir(), "absent"))
		if _, err := boundedCommandOutput(command, true); err == nil || command.Process != nil {
			t.Fatalf("missing executable: process=%v err=%v", command.Process, err)
		}
	})
	for _, attr := range []syscall.SysProcAttr{{Pgid: 1}, {Setsid: true}} {
		command := exec.CommandContext(t.Context(), "/bin/sh", "-c", "exit 0")
		command.SysProcAttr = &attr
		if _, err := boundedCommandOutput(command, false); err == nil || command.Process != nil {
			t.Fatalf("conflicting group admitted: process=%v err=%v", command.Process, err)
		}
	}
}

// The late callback must not signal a numeric process-group ID after Wait has
// released it. Also exercise immediate exits during cancellation races.
func TestCommandCancellationAfterReaping(t *testing.T) {
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		command := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
		timer := time.AfterFunc(time.Duration(i%5)*time.Millisecond, cancel)
		_, _ = boundedCommandOutput(command, false)
		timer.Stop()
		cancel()
		if command.Process != nil {
			if err := command.Cancel(); !errors.Is(err, os.ErrProcessDone) {
				t.Fatalf("late cancellation was not disabled: %v", err)
			}
		}
	}
}
