//go:build linux

package ubuntu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type ownerLaunchFacts struct {
	uid                    int
	tag, commit, sha256    string
	installedReentryMarker string
	sshConnection          string
}

func launchOwnerConsole(ctx context.Context) error {
	facts, err := ownerLaunchFactsFromEnvironment(os.Geteuid())
	if err != nil {
		return err
	}
	executable, err := openOwnerConsoleExecutable(facts)
	if err != nil {
		return err
	}
	defer executable.Close()

	rootEnvironment := []string{"-i", "HOME=/root", "USER=root", "LOGNAME=root", "TERM=" + os.Getenv("TERM"), "LANG=C.UTF-8", "PATH=/usr/bin:/bin", "SBXR_OWNER_LAUNCH_UID=" + strconv.Itoa(facts.uid), "SBXR_OWNER_LAUNCH_TAG=" + facts.tag, "SBXR_OWNER_LAUNCH_COMMIT=" + facts.commit, "SBXR_OWNER_LAUNCH_SHA256=" + facts.sha256}
	if facts.sshConnection != "" {
		rootEnvironment = append(rootEnvironment, "SBXR_SSH_CONNECTION="+facts.sshConnection)
	}
	if facts.installedReentryMarker != "" {
		rootEnvironment = append(rootEnvironment, "SBXR_INSTALLED_REENTRY=1")
	}
	rootEnvironment = append(rootEnvironment, fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), executable.Fd()), "private", "root-owner-console")
	arguments := append([]string{"--", "/usr/bin/env"}, rootEnvironment...)
	command := exec.CommandContext(ctx, "/usr/bin/sudo", arguments...)
	if facts.uid == 0 {
		command = exec.CommandContext(ctx, "/usr/bin/env", rootEnvironment...)
	}
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func openOwnerConsoleExecutable(facts ownerLaunchFacts) (*os.File, error) {
	name, err := os.Executable()
	if err != nil {
		return nil, errors.New("Owner Console candidate unavailable")
	}
	descriptor, err := syscall.Open(name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("Owner Console candidate unavailable")
	}
	executable := os.NewFile(uintptr(descriptor), "verified-owner-console")
	opened, openedErr := executable.Stat()
	running, runningErr := os.Stat("/proc/self/exe")
	if openedErr != nil || runningErr != nil || !os.SameFile(opened, running) || verifyOwnerConsoleExecutable(executable, facts) != nil {
		executable.Close()
		return nil, errors.New("Owner Console candidate refused")
	}
	return executable, nil
}

func verifyRootOwnerConsoleProcess() error {
	if os.Geteuid() != 0 {
		return errors.New("root Owner Console requires root")
	}
	uid, err := strconv.Atoi(os.Getenv("SBXR_OWNER_LAUNCH_UID"))
	if err != nil || uid < 0 {
		return errors.New("Owner Launch Identity refused")
	}
	facts, err := ownerLaunchFactsFromEnvironment(uid)
	if err != nil {
		return err
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		return errors.New("Owner Console descriptor unavailable")
	}
	defer executable.Close()
	running, err := os.Stat("/proc/self/exe")
	descriptor, descriptorErr := executable.Stat()
	if err != nil || descriptorErr != nil || !os.SameFile(running, descriptor) || verifyOwnerConsoleExecutable(executable, facts) != nil {
		return errors.New("root Owner Console descriptor refused")
	}
	return nil
}

func ownerLaunchFactsFromEnvironment(uid int) (ownerLaunchFacts, error) {
	facts := ownerLaunchFacts{uid: uid, tag: os.Getenv("SBXR_OWNER_LAUNCH_TAG"), commit: os.Getenv("SBXR_OWNER_LAUNCH_COMMIT"), sha256: os.Getenv("SBXR_OWNER_LAUNCH_SHA256"), installedReentryMarker: os.Getenv("SBXR_INSTALLED_REENTRY"), sshConnection: os.Getenv("SBXR_SSH_CONNECTION")}
	if facts.tag == "" || len(facts.commit) != 40 || len(facts.sha256) != 64 || facts.installedReentryMarker != "" && facts.installedReentryMarker != "1" {
		return ownerLaunchFacts{}, errors.New("Owner Console Release Identity refused")
	}
	for _, value := range []string{facts.commit, facts.sha256} {
		if decoded, err := hex.DecodeString(value); err != nil || hex.EncodeToString(decoded) != value {
			return ownerLaunchFacts{}, errors.New("Owner Console Release Identity refused")
		}
	}
	return facts, nil
}

func verifyOwnerConsoleExecutable(executable *os.File, facts ownerLaunchFacts) error {
	info, err := executable.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("Owner Console candidate unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("Owner Console candidate permissions refused")
	}
	ownerMode := stat.Uid == uint32(facts.uid) && info.Mode().Perm() == 0o700
	installedMode := stat.Uid == 0 && info.Mode().Perm() == 0o755
	if stat.Nlink != 1 || !ownerMode && !installedMode {
		return errors.New("Owner Console candidate permissions refused")
	}
	metadata, _, err := softwarelifecycle.ReadPayloadMetadata(executable, info.Size())
	digest := sha256.New()
	_, digestErr := io.Copy(digest, io.NewSectionReader(executable, 0, info.Size()))
	if err != nil || digestErr != nil || metadata.Build.Repository != softwarelifecycle.Repository || metadata.Build.Tag != facts.tag || metadata.Build.Commit != facts.commit || metadata.Architecture != softwarelifecycle.Architecture(runtime.GOARCH) || hex.EncodeToString(digest.Sum(nil)) != facts.sha256 {
		return errors.New("Owner Console Release Identity refused")
	}
	return nil
}
