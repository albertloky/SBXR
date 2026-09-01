package terminal

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func lifecycleChoiceCount(lifecycle softwarelifecycle.Interface) int {
	if lifecycle == nil {
		return 0
	}
	return 3
}

func writeLifecycleResult(output io.Writer, result softwarelifecycle.Result) error {
	_, err := fmt.Fprintf(output, "Software Lifecycle: %s\nResult: %s\nCode: %s\n", result.State, result.Message, result.Code)
	return err
}

func runLifecycle(ctx context.Context, reader *bufio.Reader, output io.Writer, lifecycle softwarelifecycle.Interface, choice int) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var outputErr error
	progress := func(p softwarelifecycle.Progress) {
		if outputErr == nil {
			_, outputErr = fmt.Fprintln(output, "Progress:", p.Status)
		}
		if outputErr != nil {
			cancel()
		}
	}
	reviewed := lifecycle.Status(ctx)
	if choice != 3 {
		reviewed = lifecycle.Check(ctx, progress)
	}
	if outputErr != nil || writeLifecycleResult(output, reviewed) != nil {
		return false
	}
	if choice == 1 {
		return true
	}
	if choice == 2 && reviewed.Code != softwarelifecycle.CheckUpdateAvailable {
		return true
	}
	if choice == 3 && (reviewed.State != softwarelifecycle.RecoveryRequiredState || reviewed.RecoveryDirection == "") {
		_, err := fmt.Fprintln(output, "No recovery is available. If a change is in progress, wait for it to finish.")
		return err == nil
	}
	prompt := "Recover SBXR? [y/N]"
	if choice == 3 {
		if _, err := fmt.Fprintln(output, "Recovery direction:", reviewed.RecoveryDirection); err != nil {
			return false
		}
	}
	if choice == 2 {
		if reviewed.Latest == nil {
			return false
		}
		target := reviewed.Latest
		if _, err := fmt.Fprintf(output, "Target: %s %s %s %s\n", target.Repository, target.Tag, target.Commit, target.IndexSHA256); err != nil {
			return false
		}
		prompt = "Update SBXR? [y/N]"
	}
	if _, err := fmt.Fprintln(output, "Enabled Subscription Serving may restart with a short outage. Shared certificate renewal waits until completion. Proxy traffic and both credentials are preserved."); err != nil {
		return false
	}
	confirmation, ok := readConfirmation(reader, output, prompt)
	if !ok {
		return false
	}
	if confirmation != proxyinstallation.Approved {
		_, err := fmt.Fprintln(output, "No changes were made.")
		return err == nil
	}
	ctx = softwarelifecycle.ConfirmReview(ctx, reviewed)
	var result softwarelifecycle.Result
	if choice == 2 {
		result = lifecycle.Update(ctx, progress)
	} else {
		result = lifecycle.Recover(ctx, progress)
	}
	return outputErr == nil && writeLifecycleResult(output, result) == nil
}
