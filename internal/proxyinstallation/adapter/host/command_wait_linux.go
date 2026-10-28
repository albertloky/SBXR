package host

import (
	"syscall"
	"unsafe"
)

// WNOWAIT leaves the direct child waitable, reserving its PID until Cmd.Wait.
func waitCommandExit(pid int) error {
	// Linux siginfo_t occupies 128 bytes. We only need exit notification,
	// not its architecture-specific fields; uint64 storage supplies alignment
	// for both supported Linux architectures. Keep this boundary stdlib-only.
	var info [16]uint64
	const pPID = 1
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(pid), uintptr(unsafe.Pointer(&info)), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		return nil
	}
}
