package ubuntu

import (
	"context"
	"errors"
)

// LaunchOwnerConsole admits one Owner Launch Identity and hides the complete
// authentication, candidate verification, and root-execution sequence.
func LaunchOwnerConsole(ctx context.Context) error {
	if ctx == nil {
		return errors.New("Owner Console launch refused")
	}
	return launchOwnerConsole(ctx)
}

// ServeRootOwnerConsole verifies the exact descriptor used for root execution
// before it permits the command composition root to start presentation.
func ServeRootOwnerConsole(run func() error) error {
	if run == nil {
		return errors.New("root Owner Console launch refused")
	}
	if err := verifyRootOwnerConsoleProcess(); err != nil {
		return err
	}
	return run()
}
