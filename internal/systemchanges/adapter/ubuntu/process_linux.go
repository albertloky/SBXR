//go:build linux

package ubuntu

import (
	"bytes"
	"errors"
	"os"
	"syscall"
	"time"
)

const (
	sysPIDFDOpen       = 434
	sysPIDFDSendSignal = 424
)

func signalReclamationProcess(pid int, statusPath string, timeout time.Duration, verify func() error) error {
	fd, _, errno := syscall.Syscall(sysPIDFDOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		return errno
	}
	defer syscall.Close(int(fd))
	signal := func(value syscall.Signal) error {
		_, _, errno = syscall.Syscall6(sysPIDFDSendSignal, fd, uintptr(value), 0, 0, 0, 0)
		if errno != 0 && !errors.Is(errno, syscall.ESRCH) {
			return errno
		}
		return nil
	}
	if err := signal(syscall.SIGSTOP); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		status, err := os.ReadFile(statusPath)
		if err != nil {
			return err
		}
		if bytes.Contains(status, []byte("\nState:\tT")) || bytes.Contains(status, []byte("\nState:\tt")) {
			break
		}
		if !time.Now().Before(deadline) {
			_ = signal(syscall.SIGCONT)
			return errors.New("reclamation process did not stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := verify(); err != nil {
		_ = signal(syscall.SIGCONT)
		return err
	}
	if err := signal(syscall.SIGTERM); err != nil {
		_ = signal(syscall.SIGCONT)
		return err
	}
	return signal(syscall.SIGCONT)
}
