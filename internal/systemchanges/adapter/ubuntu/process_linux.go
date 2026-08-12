//go:build linux

package ubuntu

import (
	"errors"
	"syscall"
)

const (
	sysPIDFDOpen       = 434
	sysPIDFDSendSignal = 424
)

func signalReclamationProcess(pid int, verify func() error) error {
	fd, _, errno := syscall.Syscall(sysPIDFDOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		return errno
	}
	defer syscall.Close(int(fd))
	if err := verify(); err != nil {
		return err
	}
	_, _, errno = syscall.Syscall6(sysPIDFDSendSignal, fd, uintptr(syscall.SIGTERM), 0, 0, 0, 0)
	if errno != 0 && !errors.Is(errno, syscall.ESRCH) {
		return errno
	}
	return nil
}
