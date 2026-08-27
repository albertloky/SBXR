package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const maxOwnership = 64 << 10

type SetupSpec struct {
	OwnershipPath, OwnershipNextPath, LockPath, PackageArtifactPath string
	APTKeyPath, APTKeyURL, APTKeySHA256, APTSourcePath              string
	PackageName, PackageVersion, Architecture, PackageSHA256        string
	PackageSize                                                     int
	ConfigurationPath, StatePath, Service, ServiceUnitPath          string
	User, Group, ListenerPort                                       string
}

type Operation string

const (
	InstallAPTKey            Operation = "Install APT key"
	InstallAPTSource         Operation = "Install APT source"
	MaskService              Operation = "Mask service"
	InstallPackage           Operation = "Install package"
	HoldPackage              Operation = "Hold package"
	CreateStateDirectory     Operation = "Create state directory"
	InstallConfiguration     Operation = "Install configuration"
	ValidateConfiguration    Operation = "Validate configuration"
	UnmaskService            Operation = "Unmask service"
	EnableService            Operation = "Enable service"
	StartService             Operation = "Start service"
	StopDisableService       Operation = "Stop and disable service"
	RemovePackageArtifact    Operation = "Remove package artifact"
	RemovePackageHold        Operation = "Remove package hold"
	RemovePackage            Operation = "Remove package"
	RemoveConfigurationState Operation = "Remove configuration and state"
	RemovePackageIdentity    Operation = "Remove package identity"
	RemoveAPTSource          Operation = "Remove APT source"
	RemoveAPTKey             Operation = "Remove APT key"
)

type OperationInput struct {
	Operation Operation
	Spec      SetupSpec
	Body      []byte
	SHA256    string
}

type OperationResult struct {
	OK       bool
	Fact     string
	Code     int
	Observed bool
}

type Observation struct {
	Observed bool
	Accepted bool
}

type RunningInspection struct {
	OSID, OSVersion, Architecture, PublicIPv4 string
	Host, PublicIPv4Matches                   Observation
	Ownership, TransactionFilesAbsent         Observation
	APTKey, APTSource, Package, Hold          Observation
	PackageIdentity, Configuration, State     Observation
	Validation, ServiceProvenance             Observation
	ServiceEnabled, ServiceActive, Listener   Observation
}

type RemovalInspection struct {
	RunningInspection
	PackageLocks, ConfigurationEntries, StateEntries Observation
	IdentityExclusive, ProcessExclusive, ServiceSafe Observation
}

func observation(accepted, observed bool) Observation {
	return Observation{Observed: observed, Accepted: observed && accepted}
}

type ActivationInspection struct {
	RunningInspection
	DestinationCompatible bool
	ListenerAvailable     bool
}

type MutationLock = softwarelifecycle.MutationLockAuthority

type PackageLocks struct{ files []*os.File }

var ubuntuPackageLocks = []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/cache/apt/archives/lock"}

func (locks *PackageLocks) Release() {
	if locks == nil {
		return
	}
	for _, file := range locks.files {
		_ = syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{Type: syscall.F_UNLCK, Whence: io.SeekStart})
		_ = file.Close()
	}
	locks.files = nil
}

func (adapter Adapter) AcquirePackageLocks() (*PackageLocks, bool, error) {
	locks := &PackageLocks{}
	for _, name := range ubuntuPackageLocks {
		file, err := os.OpenFile(adapter.path(name), os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			locks.Release()
			return nil, false, err
		}
		lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
		if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock); err != nil {
			_ = file.Close()
			locks.Release()
			if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EAGAIN) {
				return nil, true, nil
			}
			return nil, false, err
		}
		locks.files = append(locks.files, file)
	}
	return locks, false, nil
}

func (adapter Adapter) AcquireMutationLock(name string) (*MutationLock, bool, error) {
	path := adapter.path(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, err
	}
	return softwarelifecycle.AcquireMutationLockAuthority(path, adapter.ownerUID())
}

func (adapter Adapter) ReadOwnership(name string) ([]byte, error) {
	return adapter.readOwnedFile(name)
}

func (adapter Adapter) ReadConfiguration(ctx context.Context, spec SetupSpec, expectedDigest string) ([]byte, error) {
	group := adapter.command(ctx, "getent", "group", spec.Group)
	gid, ok := groupID(group.Fact)
	if !group.OK || !ok {
		return nil, errors.New("configuration group unavailable")
	}
	return adapter.readConfigurationFile(spec.ConfigurationPath, expectedDigest, gid)
}

func (adapter Adapter) readConfigurationFile(name, expectedDigest string, gid uint32) ([]byte, error) {
	const limit = 1 << 20
	path := adapter.path(name)
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || stat.Uid != adapter.ownerUID() || stat.Gid != gid || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("unsafe configuration")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	openedStat, openedOK := infoSys(opened)
	if err != nil || !openedOK || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return nil, errors.New("configuration changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit || digest(body) != expectedDigest {
		return nil, errors.New("configuration identity mismatch")
	}
	return body, nil
}

func (adapter Adapter) readOwnedFile(name string) ([]byte, error) {
	path := adapter.path(name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := infoSys(info)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maxOwnership {
		return nil, errors.New("unsafe ownership record")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, openedErr := file.Stat()
	openedStat, openedOK := infoSys(opened)
	if openedErr != nil || !openedOK || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return nil, errors.New("ownership record changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxOwnership+1))
	if err != nil || len(body) > maxOwnership {
		return nil, errors.New("ownership record unreadable")
	}
	return body, nil
}

func (adapter Adapter) PublishOwnership(name, nextName string, expected, next []byte) error {
	current, err := adapter.ReadOwnership(name)
	if len(expected) == 0 {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("ownership record already exists")
		}
	} else if err != nil || !bytes.Equal(current, expected) {
		return errors.New("ownership record changed")
	}
	if len(next) == 0 || len(next) > maxOwnership {
		return errors.New("ownership record refused")
	}
	directory := adapter.path(filepath.Dir(name))
	directoryInfo, err := os.Lstat(directory)
	directoryStat, directoryOK := infoSys(directoryInfo)
	if err != nil || !directoryOK || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 || directoryStat.Uid != adapter.ownerUID() {
		return errors.New("unsafe ownership directory")
	}
	temporary := adapter.path(nextName)
	if staged, stagedErr := adapter.readOwnedFile(nextName); stagedErr == nil {
		if !bytes.Equal(staged, next) || os.Rename(temporary, adapter.path(name)) != nil {
			return errors.New("ownership checkpoint refused")
		}
		return syncDirectory(directory)
	} else if !errors.Is(stagedErr, os.ErrNotExist) {
		return errors.New("ownership checkpoint unsafe")
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(next)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(next) || syncErr != nil || closeErr != nil {
		_ = os.Remove(temporary)
		return errors.New("ownership record write failed")
	}
	if err := os.Rename(temporary, adapter.path(name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(directory)
}

func (adapter Adapter) RemoveOwnership(name, nextName string, expected []byte) error {
	current, err := adapter.ReadOwnership(name)
	if err != nil || !bytes.Equal(current, expected) {
		return errors.New("ownership record changed")
	}
	stagedPresent := false
	if staged, err := adapter.readOwnedFile(nextName); err == nil {
		if !bytes.Equal(staged, expected) {
			return errors.New("ownership checkpoint changed")
		}
		stagedPresent = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(adapter.path(name)); err != nil {
		return err
	}
	if stagedPresent {
		if removeErr := os.Remove(adapter.path(nextName)); removeErr != nil {
			return removeErr
		}
	}
	return syncDirectory(adapter.path(filepath.Dir(name)))
}

func (adapter Adapter) RemoveFinalOwnership(name, nextName, finalName string, expected []byte) error {
	current, currentErr := adapter.readOwnedFile(name)
	final, finalErr := adapter.readOwnedFile(finalName)
	if currentErr == nil && finalErr == nil {
		return errors.New("multiple ownership records")
	}
	if currentErr == nil {
		if !bytes.Equal(current, expected) || !errors.Is(finalErr, os.ErrNotExist) {
			return errors.New("ownership record changed")
		}
		if staged, err := adapter.readOwnedFile(nextName); err == nil {
			if !bytes.Equal(staged, expected) || os.Remove(adapter.path(nextName)) != nil {
				return errors.New("ownership checkpoint changed")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(adapter.path(name), adapter.path(finalName)); err != nil {
			return err
		}
		if err := syncDirectory(adapter.path(filepath.Dir(finalName))); err != nil {
			return err
		}
	} else if !errors.Is(currentErr, os.ErrNotExist) || finalErr != nil || !bytes.Equal(final, expected) {
		return errors.New("ownership record changed")
	}
	directory := adapter.path(filepath.Dir(name))
	if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := adapter.path(filepath.Dir(finalName))
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := os.Remove(adapter.path(finalName)); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func (adapter Adapter) Apply(ctx context.Context, input OperationInput) OperationResult {
	spec := input.Spec
	switch input.Operation {
	case InstallAPTKey:
		body, err := adapter.download(ctx, spec.APTKeyURL, 1<<20)
		if err != nil || digest(body) != spec.APTKeySHA256 {
			return OperationResult{}
		}
		return adapter.writeFile(spec.APTKeyPath, body, 0o644)
	case InstallAPTSource:
		return adapter.writeFile(spec.APTSourcePath, input.Body, 0o644)
	case MaskService:
		return typed(adapter.command(ctx, "systemctl", "mask", spec.Service), "service masked")
	case InstallConfiguration:
		result := adapter.writeFile(spec.ConfigurationPath, input.Body, 0o640)
		if result.OK && adapter.root == "/" {
			if owner := adapter.command(ctx, "chown", "root:"+spec.Group, spec.ConfigurationPath); !owner.OK {
				return OperationResult{}
			}
		}
		return result
	case InstallPackage:
		return adapter.installPackage(ctx, spec)
	case HoldPackage:
		return typed(adapter.command(ctx, "apt-mark", "hold", spec.PackageName), "package hold applied")
	case CreateStateDirectory:
		path := adapter.path(spec.StatePath)
		if err := os.Mkdir(path, 0o755); err != nil {
			return OperationResult{}
		}
		if err := os.Chmod(path, 0o755); err != nil {
			return OperationResult{}
		}
		if adapter.root == "/" && !adapter.command(ctx, "chown", spec.User+":"+spec.Group, spec.StatePath).OK {
			return OperationResult{}
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "protected state directory created"}
	case ValidateConfiguration:
		return typed(adapter.command(ctx, spec.PackageName, "-D", spec.StatePath, "-C", filepath.Dir(spec.ConfigurationPath), "check"), "packaged configuration accepted")
	case UnmaskService:
		load := adapter.command(ctx, "systemctl", "is-enabled", spec.Service)
		if load.Fact == "not-found" || load.Fact == "disabled" {
			return OperationResult{OK: true, Fact: "service unmasked"}
		}
		return typed(adapter.command(ctx, "systemctl", "unmask", spec.Service), "service unmasked")
	case EnableService:
		return typed(adapter.command(ctx, "systemctl", "enable", spec.Service), "service enabled")
	case StartService:
		return typed(adapter.command(ctx, "systemctl", "start", spec.Service), "service started")
	case StopDisableService:
		adapter.command(ctx, "systemctl", "disable", "--now", spec.Service)
		load := adapter.command(ctx, "systemctl", "show", "--property=LoadState", "--value", spec.Service)
		enabled := adapter.command(ctx, "systemctl", "is-enabled", spec.Service)
		active := adapter.command(ctx, "systemctl", "is-active", spec.Service)
		process := adapter.command(ctx, "pgrep", "-x", spec.PackageName)
		listener := adapter.command(ctx, "ss", "-H", "-ltnp", "sport", "=", ":"+spec.ListenerPort)
		if serviceStopped(load, enabled, active, process, listener, spec.PackageName) {
			return OperationResult{OK: true, Fact: "service stopped and disabled"}
		}
		return OperationResult{}
	case RemovePackage:
		installed := adapter.command(ctx, "dpkg-query", "--show", "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}", spec.PackageName)
		if !installed.OK {
			if installed.Observed && installed.Code == 1 {
				return OperationResult{OK: true, Fact: "package absent"}
			}
			return OperationResult{}
		}
		if !exactPackageIdentity(installed.Fact, spec) {
			return OperationResult{}
		}
		holds := adapter.command(ctx, "apt-mark", "showhold")
		if !holds.Observed {
			return OperationResult{}
		}
		if slicesContains(strings.Fields(holds.Fact), spec.PackageName) && !adapter.command(ctx, "apt-mark", "unhold", spec.PackageName).OK {
			return OperationResult{}
		}
		return typed(adapter.command(ctx, "apt-get", "purge", "-y", spec.PackageName+"="+spec.PackageVersion), "package absent")
	case RemovePackageHold:
		installed := adapter.command(ctx, "dpkg-query", "--show", "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}", spec.PackageName)
		if !installed.OK {
			if installed.Observed && installed.Code == 1 {
				return OperationResult{OK: true, Fact: "package hold absent"}
			}
			return OperationResult{}
		}
		if !exactPackageIdentity(installed.Fact, spec) || !adapter.command(ctx, "apt-mark", "unhold", spec.PackageName).OK {
			return OperationResult{}
		}
		holds := adapter.command(ctx, "apt-mark", "showhold")
		if !holds.Observed || slicesContains(strings.Fields(holds.Fact), spec.PackageName) {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "package hold absent"}
	case RemovePackageArtifact:
		if !adapter.removeSafeFile(spec.PackageArtifactPath, int64(spec.PackageSize)+(1<<20)) {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "package artifact absent"}
	case RemoveConfigurationState:
		if !adapter.removeBoundFile(spec.ConfigurationPath, input.SHA256, 0o640, 1<<20) {
			return OperationResult{}
		}
		if !adapter.removeEmptyDirectory(filepath.Dir(spec.ConfigurationPath)) || !adapter.removeEmptyDirectory(spec.StatePath) {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "configuration and state absent"}
	case RemovePackageIdentity:
		user := adapter.command(ctx, "getent", "passwd", spec.User)
		group := adapter.command(ctx, "getent", "group", spec.Group)
		if !user.OK && (!user.Observed || user.Code != 2) || !group.OK && (!group.Observed || group.Code != 2) {
			return OperationResult{}
		}
		if user.OK && group.OK {
			uid, gid, accountOK := accountIDs(user.Fact)
			groupGID, groupOK := groupID(group.Fact)
			identityExclusive, identityObserved := adapter.identityExclusive(ctx, spec, uid, gid, accountOK && groupOK && gid == groupGID)
			processExclusive, processObserved := adapter.processExclusive(ctx, spec.PackageName, uid, gid, accountOK && groupOK && gid == groupGID)
			if !identityObserved || !identityExclusive || !processObserved || !processExclusive {
				return OperationResult{}
			}
		} else if user.OK || group.OK && !adapter.groupExclusive(ctx, spec, group.Fact) {
			return OperationResult{}
		}
		if user.OK && !adapter.command(ctx, "userdel", spec.User).OK {
			return OperationResult{}
		}
		if user.OK && group.OK {
			current := adapter.command(ctx, "getent", "group", spec.Group)
			if !current.OK {
				if current.Observed && current.Code == 2 {
					return OperationResult{OK: true, Fact: "package identity absent"}
				}
				return OperationResult{}
			}
			if current.Fact != group.Fact || !adapter.groupExclusive(ctx, spec, current.Fact) {
				return OperationResult{}
			}
			group = current
		}
		if group.OK && !adapter.command(ctx, "groupdel", spec.Group).OK {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "package identity absent"}
	case RemoveAPTSource:
		if !adapter.removeBoundFile(spec.APTSourcePath, input.SHA256, 0o644, 4096) {
			return OperationResult{}
		}
		if !adapter.removeBoundFile(spec.APTSourcePath+".sbxr-next", input.SHA256, 0o644, 4096) {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "APT source absent"}
	case RemoveAPTKey:
		if !adapter.removeBoundFile(spec.APTKeyPath, spec.APTKeySHA256, 0o644, 1<<20) {
			return OperationResult{}
		}
		if !adapter.removeBoundFile(spec.APTKeyPath+".sbxr-next", spec.APTKeySHA256, 0o644, 1<<20) {
			return OperationResult{}
		}
		return OperationResult{OK: true, Fact: "APT key absent"}
	default:
		return OperationResult{}
	}
}

func (adapter Adapter) groupExclusive(ctx context.Context, spec SetupSpec, fact string) bool {
	gid, ok := groupID(fact)
	if !ok {
		return false
	}
	owned := adapter.command(ctx, "find", adapter.path("/"), "-xdev", "-gid", strconv.FormatUint(uint64(gid), 10), "-print", "-quit")
	groupProcesses := adapter.command(ctx, "pgrep", "-G", strconv.FormatUint(uint64(gid), 10))
	packageProcesses := adapter.command(ctx, "pgrep", "-x", spec.PackageName)
	groupPIDs, groupObserved := pidSet(groupProcesses)
	packagePIDs, packageObserved := pidSet(packageProcesses)
	return owned.Observed && owned.OK && owned.Fact == "" && groupObserved && packageObserved && reflect.DeepEqual(groupPIDs, packagePIDs)
}

func serviceStopped(load, enabled, active, process, listener OperationResult, packageName string) bool {
	unloaded := enabled.Observed && (enabled.Fact == "disabled" || enabled.Fact == "masked") || load.Observed && load.Fact == "not-found"
	processAbsent := process.Observed && !process.OK && process.Code == 1
	listenerAbsent := listener.OK && listener.Observed && !strings.Contains(listener.Fact, packageName)
	return unloaded && active.Observed && active.Fact == "inactive" && processAbsent && listenerAbsent
}

func (adapter Adapter) InspectRunning(ctx context.Context, spec SetupSpec, sourceBody, ownership []byte, configurationDigest, publicIPv4 string) RunningInspection {
	osID, osVersion := adapter.osRelease()
	observedPublicIPv4 := adapter.publicIPv4(ctx)
	current, err := adapter.ReadOwnership(spec.OwnershipPath)
	packageResult := adapter.command(ctx, "dpkg-query", "--show", "--showformat=${Version} ${Architecture} ${db:Status-Abbrev}", spec.PackageName)
	hold := adapter.command(ctx, "apt-mark", "showhold")
	stateInfo, stateErr := os.Lstat(adapter.path(spec.StatePath))
	stateStat, stateStatOK := infoSys(stateInfo)
	user := adapter.command(ctx, "getent", "passwd", spec.User)
	group := adapter.command(ctx, "getent", "group", spec.Group)
	userUID, userGID, userIDsOK := accountIDs(user.Fact)
	groupGID, groupIDOK := groupID(group.Fact)
	validation := adapter.Apply(ctx, OperationInput{Operation: ValidateConfiguration, Spec: spec})
	provenance := adapter.command(ctx, "dpkg-query", "--search", spec.ServiceUnitPath)
	enabled := adapter.command(ctx, "systemctl", "is-enabled", spec.Service)
	active := adapter.command(ctx, "systemctl", "is-active", spec.Service)
	listener := adapter.command(ctx, "ss", "-H", "-ltnp", "sport", "=", ":"+spec.ListenerPort)
	aptKey, aptKeyObserved := adapter.boundFileInspection(spec.APTKeyPath, spec.APTKeySHA256, 0o644, 1<<20)
	aptSource, aptSourceObserved := adapter.boundFileInspection(spec.APTSourcePath, digest(sourceBody), 0o644, 4096)
	configuration, configurationObserved := adapter.boundFileGroupInspection(spec.ConfigurationPath, configurationDigest, 0o640, 1<<20, groupGID, groupIDOK)
	return RunningInspection{
		OSID: osID, OSVersion: osVersion, Architecture: adapter.architecture, PublicIPv4: observedPublicIPv4,
		Host:              observation(osID == "ubuntu" && osVersion == "24.04" && adapter.architecture == spec.Architecture, osID != "" && osVersion != "" && adapter.architecture != ""),
		PublicIPv4Matches: observation(observedPublicIPv4 == publicIPv4, observedPublicIPv4 != ""),
		Ownership:         observation(bytes.Equal(current, ownership) && err == nil, err == nil || errors.Is(err, os.ErrNotExist)),
		TransactionFilesAbsent: observation(adapter.filesAbsent(spec.OwnershipNextPath, spec.PackageArtifactPath,
			spec.APTKeyPath+".sbxr-next", spec.APTSourcePath+".sbxr-next"), adapter.pathsObserved(spec.OwnershipNextPath, spec.PackageArtifactPath, spec.APTKeyPath+".sbxr-next", spec.APTSourcePath+".sbxr-next")),
		APTKey:            observation(aptKey, aptKeyObserved),
		APTSource:         observation(aptSource, aptSourceObserved),
		Package:           observation(packageResult.OK && exactHeldPackageIdentity(packageResult.Fact, spec), packageResult.Observed),
		Hold:              observation(slicesContains(strings.Fields(hold.Fact), spec.PackageName), hold.Observed),
		PackageIdentity:   observation(user.OK && group.OK && userIDsOK && groupIDOK && userGID == groupGID, user.Observed && group.Observed),
		Configuration:     observation(configuration, configurationObserved && group.Observed),
		State:             observation(stateErr == nil && stateStatOK && stateInfo.IsDir() && stateInfo.Mode().Perm() == 0o755 && stateInfo.Mode()&os.ModeSymlink == 0 && userIDsOK && groupIDOK && stateStat.Uid == userUID && stateStat.Gid == groupGID, (stateErr == nil || errors.Is(stateErr, os.ErrNotExist)) && user.Observed && group.Observed),
		Validation:        observation(validation.OK, validation.Observed || validation.OK),
		ServiceProvenance: observation(provenance.OK && strings.HasPrefix(provenance.Fact, spec.PackageName+":"), provenance.Observed),
		ServiceEnabled:    observation(enabled.OK && enabled.Fact == "enabled", enabled.Observed),
		ServiceActive:     observation(active.OK && active.Fact == "active", active.Observed),
		Listener:          observation(listener.OK && strings.Contains(listener.Fact, spec.PackageName) && (strings.Contains(listener.Fact, publicIPv4+":"+spec.ListenerPort) || strings.Contains(listener.Fact, "*:"+spec.ListenerPort) || strings.Contains(listener.Fact, "[::]:"+spec.ListenerPort)), listener.Observed),
	}
}

func (adapter Adapter) InspectRemoval(ctx context.Context, spec SetupSpec, sourceBody, ownership []byte, configurationDigest, publicIPv4 string) RemovalInspection {
	facts := adapter.InspectRunning(ctx, spec, sourceBody, ownership, configurationDigest, publicIPv4)
	user := adapter.command(ctx, "getent", "passwd", spec.User)
	group := adapter.command(ctx, "getent", "group", spec.Group)
	uid, gid, accountOK := accountIDs(user.Fact)
	groupGID, groupOK := groupID(group.Fact)
	configurationEntries, configurationObserved := adapter.directoryContainsOnly(filepath.Dir(spec.ConfigurationPath), 0o755, adapter.ownerUID(), adapter.ownerGID(), filepath.Base(spec.ConfigurationPath))
	stateEntries, stateObserved := adapter.directoryContainsOnly(spec.StatePath, 0o755, uid, gid)
	identityExclusive, identityObserved := adapter.identityExclusive(ctx, spec, uid, gid, accountOK && groupOK && gid == groupGID)
	processExclusive, processObserved := adapter.processExclusive(ctx, spec.PackageName, uid, gid, accountOK && groupOK && gid == groupGID)
	serviceSafe, serviceObserved := adapter.serviceRemovalSafe(ctx, spec)
	return RemovalInspection{
		RunningInspection:    facts,
		PackageLocks:         observation(adapter.packageLocksAvailable(), true),
		ConfigurationEntries: observation(configurationEntries, configurationObserved),
		StateEntries:         observation(stateEntries, stateObserved),
		IdentityExclusive:    observation(identityExclusive, identityObserved),
		ProcessExclusive:     observation(processExclusive, processObserved),
		ServiceSafe:          observation(serviceSafe, serviceObserved),
	}
}

func (adapter Adapter) directoryContainsOnly(name string, mode os.FileMode, uid, gid uint32, expected ...string) (bool, bool) {
	path := adapter.path(name)
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || stat.Uid != uid || stat.Gid != gid {
		return false, err == nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, false
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	slices.Sort(names)
	slices.Sort(expected)
	return slices.Equal(names, expected), true
}

func (adapter Adapter) identityExclusive(ctx context.Context, spec SetupSpec, uid, gid uint32, valid bool) (bool, bool) {
	if !valid {
		return false, true
	}
	configuration := adapter.path(spec.ConfigurationPath)
	state := adapter.path(spec.StatePath)
	result := adapter.command(ctx, "find", adapter.path("/"), "-xdev", "(", "-uid", strconv.FormatUint(uint64(uid), 10), "-o", "-gid", strconv.FormatUint(uint64(gid), 10), ")", "!", "-path", configuration, "!", "-path", state, "!", "-path", state+string(os.PathSeparator)+"*", "-print", "-quit")
	if !result.Observed || !result.OK {
		return false, false
	}
	return result.Fact == "", true
}

func (adapter Adapter) processExclusive(ctx context.Context, packageName string, uid, gid uint32, valid bool) (bool, bool) {
	if !valid {
		return false, true
	}
	userProcesses := adapter.command(ctx, "pgrep", "-u", strconv.FormatUint(uint64(uid), 10))
	groupProcesses := adapter.command(ctx, "pgrep", "-G", strconv.FormatUint(uint64(gid), 10))
	packageProcesses := adapter.command(ctx, "pgrep", "-x", packageName)
	userPIDs, userObserved := pidSet(userProcesses)
	groupPIDs, groupObserved := pidSet(groupProcesses)
	packagePIDs, packageObserved := pidSet(packageProcesses)
	return processSetsExclusive(userPIDs, groupPIDs, packagePIDs), userObserved && groupObserved && packageObserved
}

func processSetsExclusive(userPIDs, groupPIDs, packagePIDs map[string]struct{}) bool {
	for pid := range groupPIDs {
		userPIDs[pid] = struct{}{}
	}
	return reflect.DeepEqual(userPIDs, packagePIDs)
}

func pidSet(result OperationResult) (map[string]struct{}, bool) {
	if !result.Observed || result.Code != 0 && result.Code != 1 {
		return nil, false
	}
	pids := make(map[string]struct{})
	for _, pid := range strings.Fields(result.Fact) {
		pids[pid] = struct{}{}
	}
	return pids, true
}

func (adapter Adapter) serviceRemovalSafe(ctx context.Context, spec SetupSpec) (bool, bool) {
	enabled := adapter.command(ctx, "systemctl", "is-enabled", spec.Service)
	active := adapter.command(ctx, "systemctl", "is-active", spec.Service)
	mainPID := adapter.command(ctx, "systemctl", "show", "--property=MainPID", "--value", spec.Service)
	process := adapter.command(ctx, "pgrep", "-x", spec.PackageName)
	listener := adapter.command(ctx, "ss", "-H", "-ltnp", "sport", "=", ":"+spec.ListenerPort)
	observed := enabled.Observed && active.Observed && mainPID.Observed && process.Observed && listener.Observed
	return serviceStateRemovalSafe(enabled, active, mainPID, process, listener, spec.PackageName), observed
}

func serviceStateRemovalSafe(enabled, active, mainPID, process, listener OperationResult, packageName string) bool {
	enabledKnown := enabled.OK && enabled.Fact == "enabled" || enabled.Observed && (enabled.Fact == "disabled" || enabled.Fact == "masked")
	running := active.OK && active.Fact == "active" && mainPID.OK && mainPID.Fact != "" && strings.TrimSpace(process.Fact) == mainPID.Fact && listenerOwnedOnly(listener.Fact, packageName)
	stopped := active.Observed && active.Fact == "inactive" && mainPID.Fact == "0" && !process.OK && process.Code == 1 && listener.OK && listener.Fact == ""
	return enabledKnown && (running || stopped)
}

func listenerOwnedOnly(fact, packageName string) bool {
	lines := strings.Split(strings.TrimSpace(fact), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return false
	}
	for _, line := range lines {
		if !strings.Contains(line, `(("`+packageName+`",`) {
			return false
		}
	}
	return true
}

func (adapter Adapter) pathObserved(name string) bool {
	_, err := os.Lstat(adapter.path(name))
	return err == nil || errors.Is(err, os.ErrNotExist)
}

func (adapter Adapter) pathsObserved(names ...string) bool {
	for _, name := range names {
		if !adapter.pathObserved(name) {
			return false
		}
	}
	return true
}

func exactPackageIdentity(fact string, spec SetupSpec) bool {
	fields := strings.Fields(fact)
	return len(fields) == 3 && fields[0] == spec.PackageVersion && fields[1] == spec.Architecture
}

func exactHeldPackageIdentity(fact string, spec SetupSpec) bool {
	fields := strings.Fields(fact)
	return exactPackageIdentity(fact, spec) && fields[2] == "hi"
}

func (adapter Adapter) filesAbsent(names ...string) bool {
	for _, name := range names {
		if _, err := os.Lstat(adapter.path(name)); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func (adapter Adapter) InspectActivation(ctx context.Context, spec SetupSpec, sourceBody, ownership []byte, configurationDigest, publicIPv4 string, destination Destination) ActivationInspection {
	facts := adapter.InspectRunning(ctx, spec, sourceBody, ownership, configurationDigest, publicIPv4)
	return ActivationInspection{
		RunningInspection:     facts,
		DestinationCompatible: adapter.probeDestination(ctx, destination).Compatible(),
		ListenerAvailable:     adapter.tcp443Available(publicIPv4),
	}
}

func (adapter Adapter) installPackage(ctx context.Context, spec SetupSpec) OperationResult {
	if !adapter.command(ctx, "apt-get", "update").OK {
		return OperationResult{}
	}
	directory := filepath.Dir(adapter.path(spec.PackageArtifactPath))
	packagePath := adapter.path(spec.PackageArtifactPath)
	if _, err := os.Lstat(packagePath); !errors.Is(err, os.ErrNotExist) {
		return OperationResult{}
	}
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandCtx, "apt-get", "download", spec.PackageName+"="+spec.PackageVersion)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil || len(output) > 1<<20 {
		return OperationResult{}
	}
	body, err := os.ReadFile(packagePath)
	if err != nil || len(body) != spec.PackageSize || digest(body) != spec.PackageSHA256 {
		return OperationResult{}
	}
	result := adapter.command(ctx, "dpkg", "--install", packagePath)
	if !result.OK {
		return OperationResult{}
	}
	disabled := adapter.command(ctx, "systemctl", "is-enabled", spec.Service)
	active := adapter.command(ctx, "systemctl", "is-active", spec.Service)
	if disabled.Fact != "masked" || active.Fact != "inactive" {
		return OperationResult{}
	}
	if !adapter.removeSafeFile(spec.PackageArtifactPath, int64(spec.PackageSize)+(1<<20)) {
		return OperationResult{}
	}
	return OperationResult{OK: true, Fact: "qualified package installed from verified DEB"}
}

func (adapter Adapter) writeFile(name string, body []byte, mode os.FileMode) OperationResult {
	path := adapter.path(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return OperationResult{}
	}
	temporary := path + ".sbxr-next"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return OperationResult{}
	}
	modeErr := file.Chmod(mode)
	info, statErr := file.Stat()
	if modeErr != nil || statErr != nil || info.Mode().Perm() != mode.Perm() {
		_ = file.Close()
		_ = os.Remove(temporary)
		return OperationResult{}
	}
	written, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(body) || syncErr != nil || closeErr != nil || os.Rename(temporary, path) != nil || syncDirectory(filepath.Dir(path)) != nil {
		_ = os.Remove(temporary)
		return OperationResult{}
	}
	return OperationResult{OK: true, Fact: digest(body)}
}

func (adapter Adapter) removeFile(name string) OperationResult {
	path := adapter.path(name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return OperationResult{}
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return OperationResult{}
	}
	return OperationResult{OK: true, Fact: "absent"}
}

func (adapter Adapter) removeEmptyDirectory(name string) bool {
	path := adapter.path(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return os.Remove(path) == nil && syncDirectory(filepath.Dir(path)) == nil
}

func (adapter Adapter) removeBoundFile(name, expectedDigest string, mode os.FileMode, limit int64) bool {
	if !adapter.boundFileMatches(name, expectedDigest, mode, limit) {
		if _, err := os.Lstat(adapter.path(name)); errors.Is(err, os.ErrNotExist) {
			return true
		}
		return false
	}
	path := adapter.path(name)
	return os.Remove(path) == nil && syncDirectory(filepath.Dir(path)) == nil
}

func (adapter Adapter) boundFileMatches(name, expectedDigest string, mode os.FileMode, limit int64) bool {
	matches, _ := adapter.boundFileInspection(name, expectedDigest, mode, limit)
	return matches
}

func (adapter Adapter) boundFileInspection(name, expectedDigest string, mode os.FileMode, limit int64) (bool, bool) {
	path := adapter.path(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > limit {
		return false, err == nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	return digest(body) == expectedDigest, true
}

func (adapter Adapter) boundFileMatchesGroup(name, expectedDigest string, mode os.FileMode, limit int64, gid uint32, gidOK bool) bool {
	matches, _ := adapter.boundFileGroupInspection(name, expectedDigest, mode, limit, gid, gidOK)
	return matches
}

func (adapter Adapter) boundFileGroupInspection(name, expectedDigest string, mode os.FileMode, limit int64, gid uint32, gidOK bool) (bool, bool) {
	matches, observed := adapter.boundFileInspection(name, expectedDigest, mode, limit)
	if !gidOK || !matches {
		return false, observed
	}
	info, err := os.Lstat(adapter.path(name))
	if err != nil {
		return false, false
	}
	stat, ok := infoSys(info)
	if !ok {
		return false, true
	}
	return stat.Gid == gid, true
}

func (adapter Adapter) removeSafeFile(name string, limit int64) bool {
	path := adapter.path(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > limit {
		return false
	}
	return os.Remove(path) == nil && syncDirectory(filepath.Dir(path)) == nil
}

func (adapter Adapter) command(ctx context.Context, name string, arguments ...string) OperationResult {
	commandCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, name, arguments...).CombinedOutput()
	fact := strings.TrimSpace(string(output))
	if len(fact) > 4096 {
		fact = fact[:4096]
	}
	if err == nil {
		return OperationResult{OK: true, Fact: fact, Code: 0, Observed: true}
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && commandCtx.Err() == nil {
		return OperationResult{Fact: fact, Code: exit.ExitCode(), Observed: true}
	}
	return OperationResult{Fact: fact, Code: -1}
}

func (adapter Adapter) download(ctx context.Context, url string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("download refused")
	}
	return body, nil
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (adapter Adapter) ownerUID() uint32 {
	if adapter.root == "/" {
		return 0
	}
	return uint32(os.Getuid())
}

func (adapter Adapter) ownerGID() uint32 {
	if adapter.root == "/" {
		return 0
	}
	return uint32(os.Getgid())
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func typed(result OperationResult, fact string) OperationResult {
	if !result.OK {
		return OperationResult{Code: result.Code, Observed: result.Observed}
	}
	return OperationResult{OK: true, Fact: fact, Observed: true}
}

func accountIDs(entry string) (uint32, uint32, bool) {
	fields := strings.Split(entry, ":")
	if len(fields) < 4 {
		return 0, 0, false
	}
	uid, uidErr := strconv.ParseUint(fields[2], 10, 32)
	gid, gidErr := strconv.ParseUint(fields[3], 10, 32)
	return uint32(uid), uint32(gid), uidErr == nil && gidErr == nil
}

func groupID(entry string) (uint32, bool) {
	fields := strings.Split(entry, ":")
	if len(fields) < 3 {
		return 0, false
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	return uint32(gid), err == nil
}
