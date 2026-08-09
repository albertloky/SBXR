//go:build linux

package ubuntu

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func openVerifiedInstallExecutable(staged softwarelifecycle.StagedRelease) (*os.File, error) {
	if staged.Architecture != softwarelifecycle.Architecture(runtime.GOARCH) {
		return nil, errors.New("install executable architecture mismatch")
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, errors.New("install executable unavailable")
	}
	info, err := executable.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		executable.Close()
		return nil, errors.New("install executable refused")
	}
	if verifyInstallExecutableCandidate(executable, staged) != nil {
		executable.Close()
		return nil, errors.New("install executable identity refused")
	}
	return executable, nil
}

func verifyInstallApplyProcess(socket, executable *os.File) error {
	if os.Geteuid() != 0 {
		return errors.New("privileged install requires root")
	}
	socketInfo, socketErr := socket.Stat()
	executableInfo, executableErr := executable.Stat()
	runningInfo, runningErr := os.Stat("/proc/self/exe")
	if socketErr != nil || executableErr != nil || runningErr != nil || socketInfo.Mode()&os.ModeSocket == 0 || !executableInfo.Mode().IsRegular() || executableInfo.Mode().Perm()&0o022 != 0 || executableInfo.Sys().(*syscall.Stat_t).Nlink != 1 || !os.SameFile(executableInfo, runningInfo) {
		return errors.New("privileged install descriptors refused")
	}
	peer, err := syscall.GetsockoptUcred(int(socket.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	sudoUID, uidErr := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || uidErr != nil || sudoUID == 0 || peer.Uid != uint32(sudoUID) || peer.Pid <= 1 {
		return errors.New("privileged install peer refused")
	}
	parentInfo, err := os.Stat("/proc/" + strconv.Itoa(int(peer.Pid)) + "/exe")
	if err != nil || !os.SameFile(executableInfo, parentInfo) {
		return errors.New("privileged install executable mismatch")
	}
	return nil
}
