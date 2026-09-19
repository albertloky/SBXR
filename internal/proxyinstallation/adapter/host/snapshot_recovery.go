//go:build linux && amd64 && sbxr_snapshot_recovery

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// These maintenance-only checks use the same admission and POSIX-lock rules as
// ordinary operations. Never reopen Certbot lock descriptors while holding them:
// closing any descriptor for a POSIX-locked inode would release that lock.
func (a Adapter) SnapshotRecoveryExclusionValid(authority RenewalAuthority, renewal *RenewalExclusion, serving *ServingExclusion) bool {
	if renewal == nil || renewal.authority != authority || renewal.admission == nil || renewal.writer == nil || !a.validServingExclusion(serving) || !a.renewalFiles(authority) || !a.renewalRoute() {
		return false
	}
	for _, file := range []*os.File{renewal.admission, renewal.writer} {
		opened, e1 := file.Stat()
		current, e2 := os.Lstat(file.Name())
		if e1 != nil || e2 != nil || !os.SameFile(opened, current) {
			return false
		}
	}
	return true
}

func (a Adapter) SnapshotRecoveryReadOnlyLocks() bool {
	for _, path := range certbotDirectoryLocks {
		if a.safeParents(path) != nil {
			return false
		}
		observed, _ := a.inspectCertbotLock(path)
		if !observed.Accepted {
			return false
		}
	}
	return true
}

// Bind service state and process identity across the state-only transaction.
// This handoff is intentionally confined to the retained failed-host shape.
func (a Adapter) SnapshotRecoveryServices(ctx context.Context, postReboot bool) (string, bool) {
	if postReboot {
		return a.snapshotRecoveryPostRebootServices(ctx)
	}
	var states []string
	for _, unit := range []string{"sing-box.service", "sbxr-subscription.service", "sbxr-subscription-firewall.service", "snap.certbot.renew.service", "snap.certbot.renew.timer"} {
		body, code, observed := commandOutput(ctx, "systemctl", "show", "--property=ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,UnitFileState", unit)
		if !observed || code != 0 {
			return "", false
		}
		fields := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return "", false
			}
			fields[k] = v
		}
		if unit == "sbxr-subscription-firewall.service" {
			if fields["ActiveState"] != "active" || fields["SubState"] != "exited" || fields["MainPID"] != "0" || fields["UnitFileState"] != "enabled" {
				return "", false
			}
			states = append(states, body)
			continue
		}
		active := "inactive"
		if unit == "sbxr-subscription.service" || unit == "snap.certbot.renew.timer" {
			active = "active"
		}
		if fields["ActiveState"] != active || active == "inactive" && fields["MainPID"] != "0" {
			return "", false
		}
		states = append(states, body)
	}
	if !a.servingExecutable(ctx).Accepted {
		return "", false
	}
	return strings.Join(states, "\n"), true
}

func (a Adapter) snapshotRecoveryPostRebootServices(ctx context.Context) (string, bool) {
	type expected struct {
		active, sub, result, code, status, unitFile string
		pid                                         bool
	}
	wants := map[string]expected{
		"sing-box.service":                   {"active", "running", "success", "0", "0", "enabled", true},
		"sbxr-subscription.service":          {"failed", "failed", "exit-code", "1", "1", "enabled", false},
		"sbxr-subscription-firewall.service": {"active", "exited", "success", "1", "0", "enabled", false},
		"snap.certbot.renew.service":         {"failed", "failed", "exit-code", "1", strconv.Itoa(RenewalRecorderRefused), "static", false},
		"snap.certbot.renew.timer":           {"active", "waiting", "success", "", "", "enabled", false},
	}
	var states []string
	for _, unit := range []string{"sing-box.service", "sbxr-subscription.service", "sbxr-subscription-firewall.service", "snap.certbot.renew.service", "snap.certbot.renew.timer"} {
		body, code, observed := commandOutput(ctx, "systemctl", "show", "--property=ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,UnitFileState,Result,ExecMainCode,ExecMainStatus", unit)
		if !observed || code != 0 {
			return "", false
		}
		fields := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
			key, value, found := strings.Cut(line, "=")
			if !found || key == "" {
				return "", false
			}
			if _, duplicate := fields[key]; duplicate {
				return "", false
			}
			fields[key] = value
		}
		want := wants[unit]
		pid, pidErr := strconv.Atoi(fields["MainPID"])
		pidOK := want.pid && pidErr == nil && pid > 0 || !want.pid && (fields["MainPID"] == "" || pidErr == nil && pid == 0)
		if fields["ActiveState"] != want.active || fields["SubState"] != want.sub || fields["Result"] != want.result || fields["UnitFileState"] != want.unitFile || !pidOK {
			return "", false
		}
		if want.code != "" && fields["ExecMainCode"] != want.code || want.status != "" && fields["ExecMainStatus"] != want.status {
			return "", false
		}
		states = append(states, body)
	}
	return strings.Join(states, "\n"), true
}

// SnapshotRecoveryWholeHostLock observes the exact runtime lock without
// creating it. An absent lock is admitted only as the pinned post-reboot input
// to apply; a retained retry lock must be the safe idle inode created below.
func (a Adapter) SnapshotRecoveryWholeHostLock(name string) (bool, bool) {
	parent := filepath.Dir(name)
	if name != "/run/lock/sbxr.lock" || a.safeParents(parent) != nil {
		return false, false
	}
	parentInfo, parentErr := os.Lstat(a.path(parent))
	parentStat, parentOwned := infoSys(parentInfo)
	if parentErr != nil || !parentOwned || !parentInfo.IsDir() || parentStat.Uid != a.ownerUID() || parentStat.Gid != a.ownerUID() || parentInfo.Mode().Perm() != 0777 || parentInfo.Mode()&os.ModeSticky == 0 {
		return false, false
	}
	info, err := os.Lstat(a.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	if err != nil || !a.snapshotRecoveryLockFileSafe(info) {
		return true, false
	}
	file, err := os.OpenFile(a.path(name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return true, false
	}
	defer file.Close()
	opened, openedErr := file.Stat()
	current, currentErr := os.Lstat(a.path(name))
	if openedErr != nil || currentErr != nil || !os.SameFile(opened, current) {
		return true, false
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true, false
	}
	return true, syscall.Flock(int(file.Fd()), syscall.LOCK_UN) == nil
}

func (a Adapter) snapshotRecoveryLockFileSafe(info os.FileInfo) bool {
	stat, ok := infoSys(info)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && stat.Uid == a.ownerUID() && stat.Gid == a.ownerUID() && stat.Nlink == 1 && info.Size() == 0
}

// SnapshotRecoveryWholeHostLockHeld closes the create/open race by binding the
// acquired descriptor to the current exact empty root-owned runtime inode.
func (a Adapter) SnapshotRecoveryWholeHostLockHeld(name string, lock *MutationLock) bool {
	if lock == nil {
		return false
	}
	parent := filepath.Dir(name)
	parentInfo, parentErr := os.Lstat(a.path(parent))
	parentStat, parentOwned := infoSys(parentInfo)
	descriptor, descriptorErr := lock.RuntimeDescriptor()
	if descriptorErr != nil {
		return false
	}
	defer descriptor.Close()
	opened, openedErr := descriptor.Stat()
	current, currentErr := os.Lstat(a.path(name))
	return parentErr == nil && parentOwned && parentInfo.IsDir() && parentStat.Uid == a.ownerUID() && parentStat.Gid == a.ownerUID() && parentInfo.Mode().Perm() == 0777 && parentInfo.Mode()&os.ModeSticky != 0 && openedErr == nil && currentErr == nil && os.SameFile(opened, current) && a.snapshotRecoveryLockFileSafe(opened) && a.snapshotRecoveryLockFileSafe(current)
}

// SnapshotRecoveryIdentity is the unlocked pre-creation check for the one
// post-reboot mode. Every fact is revalidated through lifecycle authority after
// the whole-host lock has been acquired.
func (a Adapter) SnapshotRecoveryIdentity(executableSHA256, installedSHA256, ownershipSHA256 string) bool {
	executable, executableErr := a.readInstalledUpdateExecutable()
	installed, installedErr := a.ReadOwnership("/var/lib/sbxr/installed.json")
	ownership, ownershipErr := a.ReadOwnership("/var/lib/sbxr/proxy-ownership.json")
	return executableErr == nil && installedErr == nil && ownershipErr == nil && digest(executable) == executableSHA256 && digest(installed) == installedSHA256 && digest(ownership) == ownershipSHA256
}

// SnapshotRecoveryFirewall binds the accepted resource authority to the exact
// owned unit and its two live filter rules without changing either one.
func (a Adapter) SnapshotRecoveryFirewall(authority SubscriptionResourceAuthority) bool {
	if !authority.Valid() {
		return false
	}
	unit, err := a.protectedServingFile(SubscriptionFirewallUnitPath, 0644, authority.FirewallSHA256)
	return err == nil && string(unit) == subscriptionFirewallUnit(authority.PublicIPv4) && a.exactSubscriptionFirewall(authority.PublicIPv4)
}

// Revalidate the pinned old archive even on an already-published target retry.
func (a Adapter) SnapshotRecoverySourceValid(source ServingAuthority) bool {
	if !source.Valid() || source.CertificateGeneration != 1 {
		return false
	}
	entries, err := os.ReadDir(a.path(servingArchive))
	if err != nil || len(entries) != 8 {
		return false
	}
	for _, entry := range entries {
		generation, valid := servingArchiveIdentity(entry.Name())
		if !valid || generation != 1 && generation != 2 {
			return false
		}
	}
	for i, name := range certificateNames {
		mode := os.FileMode(0644)
		if name == "privkey" {
			mode = 0600
		}
		if _, err := a.protectedServingFile(servingArchive+"/"+name+strconv.Itoa(source.CertificateGeneration)+".pem", mode, source.CertificateSHA256[i]); err != nil {
			return false
		}
	}
	return true
}
