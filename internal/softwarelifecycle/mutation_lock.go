package softwarelifecycle

import (
	"errors"
	"os"
	"syscall"
)

type MutationLockAuthority struct {
	file *os.File
	path string
	uid  uint32
}

func AcquireMutationLockAuthority(path string, uid uint32) (*MutationLockAuthority, bool, error) {
	return acquireMutationLockAuthority(path, uid, os.O_CREATE|os.O_RDWR)
}

// AcquireExistingMutationLockAuthority never creates durable state for read-only work.
func AcquireExistingMutationLockAuthority(path string, uid uint32) (*MutationLockAuthority, bool, error) {
	return acquireMutationLockAuthority(path, uid, os.O_RDONLY)
}

func acquireMutationLockAuthority(path string, uid uint32, flags int) (*MutationLockAuthority, bool, error) {
	file, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	info, err := file.Stat()
	stat, ok := mutationLockFileInfo(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uid || stat.Nlink != 1 {
		_ = file.Close()
		return nil, false, errors.New("unsafe mutation lock")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return &MutationLockAuthority{file: file, path: path, uid: uid}, false, nil
}

func (authority *MutationLockAuthority) Holds(path string) bool {
	if authority == nil || authority.file == nil || authority.path != path {
		return false
	}
	before, beforeErr := os.Lstat(path)
	opened, openedErr := authority.file.Stat()
	beforeStat, beforeOK := mutationLockFileInfo(before)
	openedStat, openedOK := mutationLockFileInfo(opened)
	if beforeErr != nil || openedErr != nil || !beforeOK || !openedOK || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || beforeStat.Uid != authority.uid || beforeStat.Nlink != 1 || beforeStat.Dev != openedStat.Dev || beforeStat.Ino != openedStat.Ino {
		return false
	}
	return syscall.Flock(int(authority.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

func (authority *MutationLockAuthority) Release() {
	if authority == nil || authority.file == nil {
		return
	}
	_ = syscall.Flock(int(authority.file.Fd()), syscall.LOCK_UN)
	_ = authority.file.Close()
	authority.file = nil
}

func mutationLockFileInfo(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
