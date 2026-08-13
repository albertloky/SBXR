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
	if err != nil {
		file.Close()
		return nil, errors.New("Client Access executable refused")
	}
	active, activeErr := os.Stat("/usr/local/bin/sbxr")
	stat, ok := info.Sys().(*syscall.Stat_t)
	launchUID, launchUIDOK := rootOwnerLaunchUID()
	installed := activeErr == nil && ok && info.Mode().Perm() == 0o755 && stat.Uid == 0 && os.SameFile(info, active)
	recovery := ok && launchUIDOK && info.Mode().Perm() == 0o700 && stat.Uid == launchUID && clientAccessRecoveryMarker()
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || !installed && !recovery {
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
	launchUID, launchUIDOK := rootOwnerLaunchUID()
	stat, statOK := executableInfo.Sys().(*syscall.Stat_t)
	installed := activeErr == nil && statOK && stat.Uid == 0 && executableInfo.Mode().Perm() == 0o755 && os.SameFile(executableInfo, activeInfo)
	recovery := statOK && launchUIDOK && stat.Uid == launchUID && executableInfo.Mode().Perm() == 0o700 && clientAccessRecoveryMarker()
	if socketErr != nil || executableErr != nil || runningErr != nil || peerErr != nil || socketInfo.Mode()&os.ModeSocket == 0 || !os.SameFile(executableInfo, runningInfo) || (!installed && !recovery) || peer.Uid != 0 || peer.Pid <= 1 {
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
	command := exec.Command("/proc/self/fd/3", "private", "client-access")
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

func rootOwnerLaunchUID() (uint32, bool) {
	uid, err := strconv.ParseUint(os.Getenv("SBXR_OWNER_LAUNCH_UID"), 10, 32)
	return uint32(uid), err == nil
}
