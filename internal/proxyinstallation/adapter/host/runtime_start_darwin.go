//go:build darwin

package host

import (
	"net"
	"syscall"
	"unsafe"
)

func runtimePeerUID(connection *net.UnixConn) (uint32, bool) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, false
	}
	var peer struct {
		Version, UID uint32
		NGroups      int16
		Groups       [16]uint32
	}
	size := uint32(unsafe.Sizeof(peer))
	var callErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, callErr = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, 0, 1, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&size)), 0)
	})
	return peer.UID, err == nil && callErr == 0 && peer.Version == 0
}
