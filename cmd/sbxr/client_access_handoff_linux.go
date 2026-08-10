//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

func openCurrentClientAccessExecutable() (*os.File, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, errors.New("Client Access executable unavailable")
	}
	info, err := file.Stat()
	active, activeErr := os.Stat("/usr/local/bin/sbxr")
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || activeErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || stat.Uid != 0 || stat.Nlink != 1 || !os.SameFile(info, active) {
		file.Close()
		return nil, errors.New("Client Access executable refused")
	}
	return file, nil
}

func verifyClientAccessProcess(socket, executable *os.File) error {
	if os.Geteuid() != 0 {
		return errors.New("Client Access requires root")
	}
	socketInfo, socketErr := socket.Stat()
	executableInfo, executableErr := executable.Stat()
	runningInfo, runningErr := os.Stat("/proc/self/exe")
	activeInfo, activeErr := os.Stat("/usr/local/bin/sbxr")
	peer, peerErr := syscall.GetsockoptUcred(int(socket.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	sudoUID, uidErr := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	stat, statOK := executableInfo.Sys().(*syscall.Stat_t)
	if socketErr != nil || executableErr != nil || runningErr != nil || activeErr != nil || peerErr != nil || uidErr != nil || !statOK || stat.Uid != 0 || executableInfo.Mode().Perm() != 0o755 || sudoUID == 0 || socketInfo.Mode()&os.ModeSocket == 0 || !os.SameFile(executableInfo, runningInfo) || !os.SameFile(executableInfo, activeInfo) || peer.Uid != uint32(sudoUID) || peer.Pid <= 1 {
		return errors.New("Client Access process identity refused")
	}
	parentInfo, err := os.Stat("/proc/" + strconv.Itoa(int(peer.Pid)) + "/exe")
	if err != nil || !os.SameFile(executableInfo, parentInfo) {
		return errors.New("Client Access parent identity refused")
	}
	return nil
}

func startClientAccessProcess(_ context.Context, executable *os.File) (*os.File, func() error, error) {
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	parent := os.NewFile(uintptr(descriptors[0]), "sbxr-client-access-parent")
	child := os.NewFile(uintptr(descriptors[1]), "sbxr-client-access-child")
	command := exec.Command("/usr/bin/sudo", "--preserve-fds=3", "--", "/proc/self/fd/3", "private", "client-access")
	command.Stdin, command.Stdout, command.Stderr = child, os.Stdout, os.Stderr
	command.ExtraFiles = []*os.File{executable}
	if err := command.Start(); err != nil {
		parent.Close()
		child.Close()
		return nil, nil, err
	}
	child.Close()
	return parent, command.Wait, nil
}
