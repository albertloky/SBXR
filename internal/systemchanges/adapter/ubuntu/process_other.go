//go:build !linux

package ubuntu

import (
	"errors"
	"time"
)

func signalReclamationProcess(int, string, time.Duration, func() error) error {
	return errors.New("pidfd process control requires Linux")
}
