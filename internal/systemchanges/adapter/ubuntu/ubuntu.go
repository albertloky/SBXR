// Package ubuntu supplies the System Changes Module's one host Adapter.
package ubuntu

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const lockDirectory = "run/sbxr"

type Adapter struct {
	root                     string
	uid                      int
	source                   ObservationSource
	host                     Host
	firewall                 FirewallExecutor
	cloudflare               CloudflareExecutor
	certificate              CertificateExecutor
	profiles                 ConnectionProfilesExecutor
	subscription             SubscriptionPublicationExecutor
	software                 SoftwareLifecycleExecutor
	state                    systemchanges.StateRecovery
	fresh                    *systemchanges.FreshInstallationAuthority
	freshLock                bool
	afterReclamationDigest   func(string)
	afterReclamationProof    func(string)
	afterPackageControlProof func(string)
	stopProcess              func(int, string, time.Duration, func() error) error
	packageCommand           func(time.Duration, string, ...string) ([]byte, error)
}

func runPackageCommand(timeout time.Duration, name string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return command.CombinedOutput()
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

// NewAtForFreshInstallation permits only the exact reviewed Clean VPS proof
// to bootstrap the installation lock after Apply starts.
func NewAtForFreshInstallation(root string, source ObservationSource, host Host, authority systemchanges.FreshInstallationAuthority, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state...)
	adapter.fresh = &authority
	adapter.freshLock = true
	return adapter
}

func NewAtWithFirewall(root string, source ObservationSource, host Host, firewall FirewallExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state...)
	adapter.firewall = firewall
	return adapter
}

func NewAtWithCloudflare(root string, source ObservationSource, host Host, cloudflare CloudflareExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state...)
	adapter.cloudflare = cloudflare
	return adapter
}

func NewAtWithCertificate(root string, source ObservationSource, host Host, firewall FirewallExecutor, certificate CertificateExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAtWithFirewall(root, source, host, firewall, state...)
	adapter.certificate = certificate
	return adapter
}

func NewAtWithCertificateAndConnectionProfiles(root string, source ObservationSource, host Host, firewall FirewallExecutor, certificate CertificateExecutor, profiles ConnectionProfilesExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAtWithCertificate(root, source, host, firewall, certificate, state...)
	adapter.profiles = profiles
	return adapter
}

func NewAtWithSubscriptionPublication(root string, source ObservationSource, host Host, subscription SubscriptionPublicationExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state...)
	adapter.subscription = subscription
	return adapter
}

func NewAtWithSoftwareLifecycle(root string, source ObservationSource, host Host, software SoftwareLifecycleExecutor, state ...systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state...)
	adapter.software = software
	return adapter
}

// NewAtForInstall wires the complete fixed executor set for the revision-1
// installation transaction.
func NewAtForInstall(root string, source ObservationSource, host Host, authority systemchanges.FreshInstallationAuthority, firewall FirewallExecutor, cloudflare CloudflareExecutor, certificate CertificateExecutor, profiles ConnectionProfilesExecutor, subscription SubscriptionPublicationExecutor, software SoftwareLifecycleExecutor, state systemchanges.StateRecovery) Adapter {
	adapter := NewAtForFreshInstallation(root, source, host, authority, state)
	adapter.firewall, adapter.cloudflare, adapter.certificate = firewall, cloudflare, certificate
	adapter.profiles, adapter.subscription, adapter.software = profiles, subscription, software
	return adapter
}

func NewAtForInstallRecovery(root string, source ObservationSource, host Host, firewall FirewallExecutor, cloudflare CloudflareExecutor, certificate CertificateExecutor, profiles ConnectionProfilesExecutor, subscription SubscriptionPublicationExecutor, software SoftwareLifecycleExecutor, state systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state)
	adapter.freshLock = true
	adapter.firewall, adapter.cloudflare, adapter.certificate = firewall, cloudflare, certificate
	adapter.profiles, adapter.subscription, adapter.software = profiles, subscription, software
	return adapter
}

// NewAtForClientAccess wires only the fixed executors used by a Managed to
// Managed Client Access Change Set.
func NewAtForClientAccess(root string, source ObservationSource, host Host, firewall FirewallExecutor, cloudflare CloudflareExecutor, profiles ConnectionProfilesExecutor, subscription SubscriptionPublicationExecutor, state systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state)
	adapter.firewall, adapter.cloudflare, adapter.profiles, adapter.subscription = firewall, cloudflare, profiles, subscription
	return adapter
}

// NewAtForManagedProvider wires the fixed provider and certificate executors
// used by Managed Cloudflare and Certificate Lifecycle Change Sets.
func NewAtForManagedProvider(root string, source ObservationSource, host Host, firewall FirewallExecutor, cloudflare CloudflareExecutor, certificate CertificateExecutor, profiles ConnectionProfilesExecutor, subscription SubscriptionPublicationExecutor, state systemchanges.StateRecovery) Adapter {
	adapter := NewAtForClientAccess(root, source, host, firewall, cloudflare, profiles, subscription, state)
	adapter.certificate = certificate
	return adapter
}

// NewAtForSoftwareChange wires the fixed executors used by a verified release
// update or compatible downgrade.
func NewAtForSoftwareChange(root string, source ObservationSource, host Host, cloudflare CloudflareExecutor, profiles ConnectionProfilesExecutor, subscription SubscriptionPublicationExecutor, software SoftwareLifecycleExecutor, state systemchanges.StateRecovery) Adapter {
	adapter := NewAt(root, source, host, state)
	adapter.cloudflare, adapter.profiles, adapter.subscription, adapter.software = cloudflare, profiles, subscription, software
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
	created := false
	if errors.Is(err, fs.ErrNotExist) && a.fresh != nil && a.fresh.SystemChangesFreshInstallation() {
		file, err = a.createFreshLock()
		created = err == nil
	}
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
	return &kernelLock{file: file, cleanup: a.freshLockCleanup(created)}, true, nil
}

func (a Adapter) inspectLock() (systemchanges.LockState, error) {
	file, err := a.openLock()
	if errors.Is(err, fs.ErrNotExist) && a.fresh != nil {
		return systemchanges.LockReleased, nil
	}
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

func (a Adapter) createFreshLock() (*os.File, error) {
	directoryPath := filepath.Join(a.root, filepath.FromSlash(lockDirectory))
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(directoryPath, "system-changes.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.Remove(directoryPath)
		return nil, err
	}
	if closeErr := file.Close(); closeErr != nil {
		_ = os.Remove(path)
		_ = os.Remove(directoryPath)
		return nil, closeErr
	}
	file, err = a.openLock()
	if err != nil {
		_ = os.Remove(path)
		_ = os.Remove(directoryPath)
	}
	return file, err
}

func (a Adapter) freshLockCleanup(created bool) func() error {
	if !created && !a.freshLock {
		return nil
	}
	return func() error {
		observed, err := a.source()
		if err != nil || observed.Status != systemchanges.NotInstalled {
			return err
		}
		path := filepath.Join(a.root, filepath.FromSlash(lockDirectory), "system-changes.lock")
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return os.Remove(filepath.Dir(path))
	}
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

type kernelLock struct {
	file    *os.File
	cleanup func() error
}

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
	if closeErr != nil {
		return closeErr
	}
	if lock.cleanup != nil {
		return lock.cleanup()
	}
	return nil
}
