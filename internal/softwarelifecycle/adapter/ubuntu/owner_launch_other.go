//go:build !linux

package ubuntu

import (
	"context"
	"errors"
)

func launchOwnerConsole(context.Context) error {
	return errors.New("Owner Console launch is supported only on Linux")
}

func verifyRootOwnerConsoleProcess() error {
	return errors.New("Owner Console launch is supported only on Linux")
}
