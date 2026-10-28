package host

import (
	"errors"
	"golang.org/x/sys/unix"
)

// WNOWAIT leaves the direct child waitable, reserving its PID until Cmd.Wait.
func waitCommandExit(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
