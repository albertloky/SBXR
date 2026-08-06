// Package ubuntu supplies the System Changes Module's one host Adapter.
package ubuntu

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const lockDirectory = "run/sbxr"

type Adapter struct {
	root     string
	uid      int
	source   ObservationSource
	host     Host
	firewall FirewallExecutor
	state    systemchanges.StateRecovery
}

// ObservationSource reloads coordinated State lineage and volatile bindings.
type ObservationSource func() (systemchanges.Observation, error)

func New(source ObservationSource, host Host, state ...systemchanges.StateRecovery) Adapter {
	return Adapter{root: "/", uid: 0, source: source, host: host, firewall: NewNativeFirewall(), state: firstStateRecovery(state)}
}

// NewAt provides the production lock and host-fact seam under a controlled root.
func NewAt(root string, source ObservationSource, host Host, state ...systemchanges.StateRecovery) Adapter {
	return Adapter{root: root, uid: os.Geteuid(), source: source, host: host, state: firstStateRecovery(state)}
}

func NewAtWithFirewall(root string, source ObservationSource, host Host, firewall FirewallExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state...)
	adapter.firewall = firewall
	return adapter
}

func firstStateRecovery(states []systemchanges.StateRecovery) systemchanges.StateRecovery {
	if len(states) == 1 {
		return states[0]
	}
	return nil
}

func (a Adapter) Observe() (systemchanges.Observation, error) {
	if a.source == nil {
		return systemchanges.Observation{}, errors.New("system changes observation source unavailable")
	}
	observed, err := a.source()
	if err != nil {
		return systemchanges.Observation{}, err
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(a.root, &filesystem); err != nil {
		return systemchanges.Observation{}, err
	}
	observed.FilesystemBytes = filesystem.Blocks * uint64(filesystem.Bsize)
	observed.AvailableBytes = filesystem.Bavail * uint64(filesystem.Bsize)
	observed.MonotonicClock = true
	state, err := a.inspectLock()
	if err != nil {
		return systemchanges.Observation{}, err
	}
	observed.Lock = state
	return observed, nil
}

func (a Adapter) TryLock() (systemchanges.Lock, bool, error) {
	file, err := a.openLock()
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &kernelLock{file: file}, true, nil
}

func (a Adapter) inspectLock() (systemchanges.LockState, error) {
	file, err := a.openLock()
	if err != nil {
		return systemchanges.LockReleased, err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return systemchanges.LockHeld, nil
		}
		return systemchanges.LockReleased, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		return systemchanges.LockReleased, err
	}
	return systemchanges.LockReleased, nil
}

func (a Adapter) openLock() (*os.File, error) {
	directoryPath := filepath.Join(a.root, filepath.FromSlash(lockDirectory))
	directory, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, err
	}
	if directory.Mode()&os.ModeSymlink != 0 || !directory.IsDir() || !exactMode(directory.Mode(), 0o700) || directory.Sys().(*syscall.Stat_t).Uid != uint32(a.uid) {
		return nil, fs.ErrPermission
	}
	root, err := os.OpenRoot(directoryPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	openedDirectory, err := root.Stat(".")
	currentDirectory, currentErr := os.Lstat(directoryPath)
	if err != nil || currentErr != nil || !os.SameFile(directory, openedDirectory) || !os.SameFile(openedDirectory, currentDirectory) {
		return nil, fs.ErrPermission
	}
	info, err := root.Lstat("system-changes.lock")
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !exactMode(info.Mode(), 0o600) || info.Sys().(*syscall.Stat_t).Uid != uint32(a.uid) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, fs.ErrPermission
	}
	file, err := root.OpenFile("system-changes.lock", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	current, currentErr := root.Lstat("system-changes.lock")
	if err != nil || currentErr != nil || !os.SameFile(info, after) || !os.SameFile(after, current) {
		file.Close()
		return nil, fs.ErrPermission
	}
	return file, nil
}

func exactMode(actual, wanted os.FileMode) bool {
	const special = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return actual.Perm() == wanted && actual&special == 0
}

type kernelLock struct{ file *os.File }

func (lock *kernelLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
