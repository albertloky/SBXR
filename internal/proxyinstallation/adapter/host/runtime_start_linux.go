//go:build linux

package host

import (
	"net"
	"syscall"
)

func runtimePeerUID(connection *net.UnixConn) (uint32, bool) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, false
	}
	var peer *syscall.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || peerErr != nil || peer == nil {
		return 0, false
	}
	return peer.Uid, true
}
