package host

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The holder inherits the runner's output descriptor but waits only for this
// fixture's release file. Cleanup waits for its acknowledgement; no PID/group
// signalling or unrelated-process discovery is needed, even after a failure.
func inheritedPipeFixture(t *testing.T, finish string) (string, string) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "holder")
	t.Cleanup(func() {
		if err := os.WriteFile(marker+".release", nil, 0600); err != nil {
			t.Error(err)
			return
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(marker + ".done"); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("fixture holder did not acknowledge cleanup")
	})
	script := `printf partial; (for i in 1 2 3 4 5 6 7 8; do [ ! -e "$1.release" ] || break; /bin/sleep 1; done; : > "$1.done") & ` + finish
	return script, marker
}

func TestCommandInheritedPipesAreBounded(t *testing.T) {
	for _, mutation := range []bool{false, true} {
		for _, exit := range []string{"exit 0", "exit 7"} {
			t.Run(strconv.FormatBool(mutation)+"/"+exit, func(t *testing.T) {
				script, marker := inheritedPipeFixture(t, exit)
				started := time.Now()
				var observed bool
				if mutation {
					result := (Adapter{}).command(t.Context(), "/bin/sh", "-c", script, "fixture", marker)
					observed = result.Observed
					if result.Fact != "" || result.OK {
						t.Fatal("incomplete mutation output retained as a fact")
					}
				} else {
					_, _, observed = commandOutput(t.Context(), "/bin/sh", "-c", script, "fixture", marker)
				}
				if elapsed := time.Since(started); elapsed >= 5*time.Second {
					t.Fatalf("inherited pipe kept runner blocked for %v", elapsed)
				}
				if observed {
					t.Fatal("incomplete output reported observed")
				}
			})
		}
	}
}

func TestCommandDeadlineBoundsInheritedPipes(t *testing.T) {
	script, marker := inheritedPipeFixture(t, "wait")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, observed := commandOutput(ctx, "/bin/sh", "-c", script, "fixture", marker)
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("deadline did not bound drain: %v", elapsed)
	}
	if observed {
		t.Fatal("cancelled command reported observed")
	}
}

// Keep the normal exit-code contract: bounded drainage is not a blanket refusal.
func TestCommandCompletedOutputPreservesExitCode(t *testing.T) {
	for _, code := range []int{0, 7} {
		body, actual, observed := commandOutput(t.Context(), "/bin/sh", "-c", "printf observed; exit "+strconv.Itoa(code))
		if !observed || actual != code || body != "observed" {
			t.Fatalf("output=%q code=%d observed=%t", body, actual, observed)
		}
		result := (Adapter{}).command(t.Context(), "/bin/sh", "-c", "printf observed; exit "+strconv.Itoa(code))
		if !result.Observed || result.Code != code || result.Fact != "observed" || result.OK != (code == 0) {
			t.Fatalf("mutation result=%+v", result)
		}
	}
}
