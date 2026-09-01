//go:build linux

package host

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
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

func runtimePeerExecutable(connection *net.UnixConn) ([]byte, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *syscall.Ucred
	var peerErr error
	err = raw.Control(func(fd uintptr) {
		peer, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || peerErr != nil || peer == nil || peer.Pid < 1 {
		return nil, errors.New("runtime peer refused")
	}
	file, err := os.Open("/proc/" + strconv.Itoa(int(peer.Pid)) + "/exe")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 256<<20+1))
	if len(body) == 0 || len(body) > 256<<20 {
		return nil, errors.New("runtime peer oversized")
	}
	return body, err
}
