package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const MutationLockProvisionRole = "--provision-mutation-lock"
const MutationLockProvisionUnitPath = "/etc/systemd/system/sbxr-mutation-lock.service"
const MutationLockProvisionWantsPath = "/etc/systemd/system/multi-user.target.wants/sbxr-mutation-lock.service"

const MutationLockProvisionUnit = `[Unit]
Description=Provision the SBXR whole-host mutation lock
DefaultDependencies=no
After=local-fs.target systemd-tmpfiles-setup.service
Before=basic.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/sbxr --provision-mutation-lock
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/run/lock
InaccessiblePaths=/run/dbus
StandardInput=null
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
`

type LockProvisioningAuthority struct {
	UnitSHA256 string `json:"unit_sha256"`
}

func NewLockProvisioningAuthority() LockProvisioningAuthority {
	return LockProvisioningAuthority{UnitSHA256: digest([]byte(MutationLockProvisionUnit))}
}

func (authority LockProvisioningAuthority) Valid() bool {
	return authority == NewLockProvisioningAuthority()
}

func (authority LockProvisioningAuthority) Resources() []string {
	return []string{
		MutationLockProvisionUnitPath + " root:root 0644 one-link sha256:" + authority.UnitSHA256,
		MutationLockProvisionUnitPath + ".sbxr-next root-owned synchronized no-replace publication",
		MutationLockProvisionWantsPath + " root-owned symlink ../sbxr-mutation-lock.service",
	}
}

func (a Adapter) mutationLockParentSafe(name string) error {
	if name != "/run/lock/sbxr.lock" {
		return errors.New("mutation lock path refused")
	}
	parent := filepath.Dir(name)
	if err := a.safeParents(parent); err != nil {
		return err
	}
	info, err := os.Lstat(a.path(parent))
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || stat.Uid != a.ownerUID() || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return &parentSafetyError{path: parent, mode: infoMode(info), err: err}
	}
	return nil
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode()
}

func (a Adapter) ProvisionMutationLock(name string) (*MutationLock, bool, error) {
	if err := a.mutationLockParentSafe(name); err != nil {
		return nil, false, err
	}
	return softwarelifecycle.ProvisionMutationLockAuthority(a.path(name), a.ownerUID())
}

func (a Adapter) InspectLockProvisioning(authority LockProvisioningAuthority) Observation {
	if !authority.Valid() {
		return observation(false, true)
	}
	parentsSafe := a.safeParents(MutationLockProvisionWantsPath) == nil
	unit, err := a.protectedServingFile(MutationLockProvisionUnitPath, 0o644, authority.UnitSHA256)
	wants, wantsErr := os.Lstat(a.path(MutationLockProvisionWantsPath))
	wantsStat, wantsOK := infoSys(wants)
	target, targetErr := os.Readlink(a.path(MutationLockProvisionWantsPath))
	stagedAbsent := a.safelyAbsent(MutationLockProvisionUnitPath + ".sbxr-next")
	observed := err == nil && wantsErr == nil && targetErr == nil && stagedAbsent
	accepted := observed && parentsSafe && string(unit) == MutationLockProvisionUnit && wantsOK && wants.Mode()&os.ModeSymlink != 0 && wantsStat.Uid == a.ownerUID() && wantsStat.Nlink == 1 && target == "../sbxr-mutation-lock.service"
	return observation(accepted, observed)
}

func (a Adapter) InstallLockProvisioning(ctx context.Context, authority LockProvisioningAuthority) bool {
	if !authority.Valid() || a.safeParents(MutationLockProvisionWantsPath) != nil {
		return false
	}
	wants := a.path(MutationLockProvisionWantsPath)
	info, wantsErr := os.Lstat(wants)
	if wantsErr == nil {
		stat, ok := infoSys(info)
		target, targetErr := os.Readlink(wants)
		if !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != a.ownerUID() || stat.Nlink != 1 || targetErr != nil || target != "../sbxr-mutation-lock.service" {
			return false
		}
	} else if !errors.Is(wantsErr, os.ErrNotExist) {
		return false
	}
	if !a.publishSubscriptionFile(MutationLockProvisionUnitPath, []byte(MutationLockProvisionUnit), 0o644) {
		return false
	}
	if errors.Is(wantsErr, os.ErrNotExist) && (os.Symlink("../sbxr-mutation-lock.service", wants) != nil || a.syncOwnershipDirectory(a.path(filepath.Dir(MutationLockProvisionWantsPath))) != nil) {
		return false
	}
	return a.command(ctx, "systemctl", "daemon-reload").OK && a.InspectLockProvisioning(authority).Accepted
}

func (a Adapter) RemoveLockProvisioning(ctx context.Context, authority LockProvisioningAuthority) bool {
	if !authority.Valid() || a.safeParents(MutationLockProvisionWantsPath) != nil {
		return false
	}
	unit, unitErr := a.protectedServingFile(MutationLockProvisionUnitPath, 0o644, authority.UnitSHA256)
	if unitErr == nil && string(unit) != MutationLockProvisionUnit || unitErr != nil && !errors.Is(unitErr, os.ErrNotExist) {
		return false
	}
	staged, stagedErr := a.protectedServingFile(MutationLockProvisionUnitPath+".sbxr-next", 0o644, authority.UnitSHA256)
	if stagedErr == nil && string(staged) != MutationLockProvisionUnit || stagedErr != nil && !errors.Is(stagedErr, os.ErrNotExist) {
		return false
	}
	wants, wantsErr := os.Lstat(a.path(MutationLockProvisionWantsPath))
	if wantsErr == nil {
		stat, ok := infoSys(wants)
		target, targetErr := os.Readlink(a.path(MutationLockProvisionWantsPath))
		if !ok || wants.Mode()&os.ModeSymlink == 0 || stat.Uid != a.ownerUID() || stat.Nlink != 1 || targetErr != nil || target != "../sbxr-mutation-lock.service" {
			return false
		}
	} else if !errors.Is(wantsErr, os.ErrNotExist) {
		return false
	}
	if unitErr == nil && !a.command(ctx, "systemctl", "stop", "sbxr-mutation-lock.service").OK {
		return false
	}
	for _, path := range []string{MutationLockProvisionWantsPath, MutationLockProvisionUnitPath + ".sbxr-next", MutationLockProvisionUnitPath} {
		if err := os.Remove(a.path(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err := a.syncOwnershipDirectory(a.path(filepath.Dir(path))); err != nil {
			return false
		}
	}
	return a.command(ctx, "systemctl", "daemon-reload").OK && a.lockProvisioningAbsent()
}

func (a Adapter) lockProvisioningAbsent() bool {
	if a.safeParents(MutationLockProvisionWantsPath) != nil {
		return false
	}
	for _, path := range []string{MutationLockProvisionUnitPath, MutationLockProvisionUnitPath + ".sbxr-next", MutationLockProvisionWantsPath} {
		if _, err := os.Lstat(a.path(path)); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

const lockProvisioningCapability = "SBXR-MUTATION-LOCK-BOOT-PROVISIONING-V1"

func LockProvisioningCapability() string { return strings.Clone(lockProvisioningCapability) }
