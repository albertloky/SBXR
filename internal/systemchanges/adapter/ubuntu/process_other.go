//go:build !linux

package ubuntu

import "errors"

func signalReclamationProcess(int, func() error) error {
	return errors.New("pidfd process control requires Linux")
}
