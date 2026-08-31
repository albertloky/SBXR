//go:build linux

package host

import (
	"syscall"
	"unsafe"
)

func servingCapabilitiesRestricted() bool {
	header := struct {
		Version uint32
		PID     int32
	}{Version: 0x20080522}
	data := [2]struct{ Effective, Permitted, Inheritable uint32 }{}
	_, _, err := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data)), 0)
	if err != 0 || data[0].Effective != 0 || data[0].Permitted != 0 || data[0].Inheritable != 0 || data[1].Effective != 0 || data[1].Permitted != 0 || data[1].Inheritable != 0 {
		return false
	}
	value, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0) // PR_GET_NO_NEW_PRIVS
	return err == 0 && value == 1
}
