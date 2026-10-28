package host

import (
	"errors"
	"syscall"
)

// Darwin's NOTE_EXIT observes exit without reaping the child. Keep its PID
// reserved until the cancellation callback has stopped using the group ID.
func waitCommandExit(pid int) error {
	syscall.ForkLock.RLock()
	queue, err := syscall.Kqueue()
	if err == nil {
		syscall.CloseOnExec(queue)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return err
	}
	defer syscall.Close(queue)
	change := syscall.Kevent_t{Ident: uint64(pid), Filter: syscall.EVFILT_PROC, Flags: syscall.EV_ADD | syscall.EV_ONESHOT, Fflags: syscall.NOTE_EXIT}
	for {
		_, err = syscall.Kevent(queue, []syscall.Kevent_t{change}, nil, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		// An already exited, unreaped child may refuse registration. No other
		// code waits for this child, so its PID still cannot have been reused.
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			return err
		}
		break
	}
	events := make([]syscall.Kevent_t, 1)
	for {
		n, err := syscall.Kevent(queue, nil, events, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if events[0].Flags&syscall.EV_ERROR != 0 {
			return syscall.Errno(events[0].Data)
		}
		return nil
	}
}
