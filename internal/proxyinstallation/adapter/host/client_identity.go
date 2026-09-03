package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const ClientIdentityTargetPath = "/var/lib/sbxr/client-identity-target.json"
const ClientIdentityConfigurationNextPath = "/etc/sing-box/.config.json.sbxr-next"
const ProxyStartupDropInDirectory = "/etc/systemd/system/sing-box.service.d"
const ProxyStartupDropInPath = ProxyStartupDropInDirectory + "/sbxr-client-identity.conf"
const ProxyStartRole = "--proxy-start-authorize"
const proxyStartAuthorizationPath = "/run/sbxr-client-identity-start"

const ProxyStartupDropIn = `[Service]
ExecCondition=/usr/local/bin/sbxr --proxy-start-authorize
`

func (authority ProxyStartupAuthority) Resources() []string {
	resources := []string{ProxyStartupDropInPath + " root:root 0644 one-link sha256:" + authority.DropInSHA256}
	if authority.DirectoryCreated {
		resources = append(resources, ProxyStartupDropInDirectory+" root:root 0755 SBXR-created empty-after-drop-in-removal")
	}
	return resources
}

func (adapter Adapter) PlanProxyStartupIntegration() (ProxyStartupAuthority, Observation) {
	_, err := adapter.protectedServingFile(ProxyStartupDropInPath, 0644, "")
	if err == nil {
		return ProxyStartupAuthority{}, observation(false, true)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ProxyStartupAuthority{}, Observation{}
	}
	authority := ProxyStartupAuthority{DropInSHA256: digest([]byte(ProxyStartupDropIn))}
	parent := adapter.path(ProxyStartupDropInDirectory)
	info, parentErr := os.Lstat(parent)
	if errors.Is(parentErr, os.ErrNotExist) {
		authority.DirectoryCreated = true
		return authority, observation(adapter.safeParents(filepath.Dir(ProxyStartupDropInDirectory)) == nil, true)
	}
	stat, ok := infoSys(info)
	return authority, observation(parentErr == nil && ok && info.IsDir() && info.Mode().Perm() == 0755 && stat.Uid == adapter.ownerUID(), parentErr == nil)
}

func (adapter Adapter) ClientIdentityPreparationIdle() Observation {
	target := adapter.observeSafeAbsence(ClientIdentityTargetPath)
	token := adapter.observeSafeAbsence(proxyStartAuthorizationPath)
	return observation(target.Accepted && token.Accepted, target.Observed && token.Observed)
}

func (adapter Adapter) observeSafeAbsence(name string) Observation {
	if adapter.safeParents(name) != nil {
		return Observation{}
	}
	_, err := os.Lstat(adapter.path(name))
	return observation(errors.Is(err, os.ErrNotExist), err == nil || errors.Is(err, os.ErrNotExist))
}

func (adapter Adapter) PrepareClientIdentityTarget(body []byte, expected string) bool {
	return len(body) > 0 && len(body) <= 1<<20 && digest(body) == expected && adapter.publishSubscriptionFile(ClientIdentityTargetPath, body, 0600)
}

func (adapter Adapter) PublishProxyStartupIntegration(authority ProxyStartupAuthority) bool {
	if !authority.Valid() || authority.DropInSHA256 != digest([]byte(ProxyStartupDropIn)) {
		return false
	}
	if _, err := os.Lstat(adapter.path(ProxyStartupDropInDirectory)); errors.Is(err, os.ErrNotExist) {
		if !authority.DirectoryCreated || adapter.safeParents(filepath.Dir(ProxyStartupDropInDirectory)) != nil || os.Mkdir(adapter.path(ProxyStartupDropInDirectory), 0755) != nil || os.Chmod(adapter.path(ProxyStartupDropInDirectory), 0755) != nil || adapter.syncOwnershipDirectory(adapter.path(filepath.Dir(ProxyStartupDropInDirectory))) != nil {
			return false
		}
	}
	return adapter.publishSubscriptionFile(ProxyStartupDropInPath, []byte(ProxyStartupDropIn), 0644)
}

func (adapter Adapter) ReloadProxyStartupIntegration(ctx context.Context) bool {
	return adapter.command(ctx, "systemctl", "daemon-reload").OK
}

func (adapter Adapter) VerifyProxyStartupIntegration(ctx context.Context, authority ProxyStartupAuthority) bool {
	body, err := adapter.protectedServingFile(ProxyStartupDropInPath, 0644, authority.DropInSHA256)
	condition := adapter.command(ctx, "systemctl", "show", "--property=ExecCondition", "--value", "sing-box.service")
	return err == nil && string(body) == ProxyStartupDropIn && condition.OK && exactProxyStartCondition(condition.Fact)
}

func exactProxyStartCondition(fact string) bool {
	const command = "/usr/local/bin/sbxr --proxy-start-authorize"
	fact = strings.TrimSpace(fact)
	if strings.Count(fact, "{") != 1 || strings.Count(fact, "}") != 1 {
		return false
	}
	path, arguments, failureRequired := false, false, false
	for _, field := range strings.Split(strings.Trim(fact, "{} "), ";") {
		field = strings.TrimSpace(field)
		switch field {
		case "path=/usr/local/bin/sbxr":
			if path {
				return false
			}
			path = true
		case "argv[]=" + command:
			if arguments {
				return false
			}
			arguments = true
		case "ignore_errors=no":
			if failureRequired {
				return false
			}
			failureRequired = true
		default:
			if strings.HasPrefix(field, "path=") || strings.HasPrefix(field, "argv[]=") || strings.HasPrefix(field, "ignore_errors=") {
				return false
			}
		}
	}
	return path && arguments && failureRequired
}

func (adapter Adapter) StopProxyForClientIdentityRotation(ctx context.Context) bool {
	killMode := adapter.command(ctx, "systemctl", "show", "--property=KillMode", "--value", "sing-box.service")
	controlGroup := adapter.command(ctx, "systemctl", "show", "--property=ControlGroup", "--value", "sing-box.service")
	return killMode.OK && strings.TrimSpace(killMode.Fact) == "control-group" && controlGroup.OK && strings.TrimSpace(controlGroup.Fact) == "/system.slice/sing-box.service" && adapter.command(ctx, "systemctl", "stop", "sing-box.service").OK
}

func (adapter Adapter) ProxyQuiescentForClientIdentityRotation(ctx context.Context) bool {
	killMode := adapter.command(ctx, "systemctl", "show", "--property=KillMode", "--value", "sing-box.service")
	active := adapter.command(ctx, "systemctl", "is-active", "sing-box.service")
	mainPID := adapter.command(ctx, "systemctl", "show", "--property=MainPID", "--value", "sing-box.service")
	controlGroup := adapter.command(ctx, "systemctl", "show", "--property=ControlGroup", "--value", "sing-box.service")
	process := adapter.command(ctx, "pgrep", "-x", "sing-box")
	listener := adapter.command(ctx, "ss", "-H", "-ltnp", "sport", "=", ":443")
	if !killMode.OK || strings.TrimSpace(killMode.Fact) != "control-group" || !controlGroup.OK || strings.TrimSpace(controlGroup.Fact) != "/system.slice/sing-box.service" || !active.Observed || active.Fact != "inactive" || !mainPID.OK || strings.TrimSpace(mainPID.Fact) != "0" || !process.Observed || process.Code != 1 || !listener.OK || strings.TrimSpace(listener.Fact) != "" {
		return false
	}
	events, err := os.ReadFile(adapter.path("/sys/fs/cgroup/system.slice/sing-box.service/cgroup.events"))
	return err == nil && len(events) <= 4096 && slicesContainsLine(string(events), "populated 0")
}

func slicesContainsLine(body, line string) bool {
	for _, current := range strings.Split(body, "\n") {
		if current == line {
			return true
		}
	}
	return false
}

func (adapter Adapter) PublishClientIdentityConfiguration(source, target string) bool {
	group := adapter.command(context.Background(), "getent", "group", "sing-box")
	gid, ok := groupID(group.Fact)
	if !group.OK || !ok {
		return false
	}
	current, currentErr := adapter.readConfigurationFile("/etc/sing-box/config.json", source, gid)
	prepared, preparedErr := adapter.protectedServingFile(ClientIdentityTargetPath, 0600, target)
	if currentErr != nil {
		if accepted, err := adapter.readConfigurationFile("/etc/sing-box/config.json", target, gid); err == nil && bytes.Equal(accepted, prepared) {
			return adapter.syncOwnershipDirectory(adapter.path("/etc/sing-box")) == nil
		}
		return false
	}
	if preparedErr != nil || len(current) == 0 {
		return false
	}
	temporary := adapter.path(ClientIdentityConfigurationNextPath)
	if _, err := os.Lstat(temporary); errors.Is(err, os.ErrNotExist) {
		file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0640)
		if err != nil {
			return false
		}
		if err := file.Chmod(0640); err != nil {
			_ = file.Close()
			return false
		}
		written, writeErr := file.Write(prepared)
		ownErr := file.Chown(int(adapter.ownerUID()), int(gid))
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || written != len(prepared) || ownErr != nil || syncErr != nil || closeErr != nil {
			_ = os.Remove(temporary)
			return false
		}
	}
	staged, stagedErr := adapter.readConfigurationFile(ClientIdentityConfigurationNextPath, target, gid)
	if stagedErr != nil || !bytes.Equal(staged, prepared) {
		return false
	}
	latest, err := adapter.readConfigurationFile("/etc/sing-box/config.json", source, gid)
	return err == nil && bytes.Equal(current, latest) && os.Rename(temporary, adapter.path("/etc/sing-box/config.json")) == nil && adapter.syncOwnershipDirectory(adapter.path("/etc/sing-box")) == nil
}

func (adapter Adapter) StartProxyForClientIdentityRotation(ctx context.Context, target string) bool {
	if !adapter.publishSubscriptionFile(proxyStartAuthorizationPath, []byte(target+"\n"), 0600) {
		return false
	}
	started := adapter.runtimeStart(ctx, ProxyStartRole, func() bool { return adapter.command(ctx, "systemctl", "start", "sing-box.service").OK })
	_ = os.Remove(adapter.path(proxyStartAuthorizationPath))
	_ = adapter.syncOwnershipDirectory(adapter.path("/run"))
	return started
}

func (adapter Adapter) ConsumeProxyStartAuthorization(target string) bool {
	body, err := adapter.protectedServingFile(proxyStartAuthorizationPath, 0600, "")
	return err == nil && string(body) == target+"\n" && os.Remove(adapter.path(proxyStartAuthorizationPath)) == nil && adapter.syncOwnershipDirectory(adapter.path("/run")) == nil
}

func (adapter Adapter) RemoveClientIdentityTarget(source, target string) bool {
	if !adapter.safelyAbsent(ClientIdentityConfigurationNextPath) {
		group := adapter.command(context.Background(), "getent", "group", "sing-box")
		gid, ok := groupID(group.Fact)
		if !group.OK || !ok {
			return false
		}
		if _, err := adapter.readConfigurationFile(ClientIdentityConfigurationNextPath, target, gid); err != nil || os.Remove(adapter.path(ClientIdentityConfigurationNextPath)) != nil {
			return false
		}
	}
	if !adapter.syncAbsentPath(ClientIdentityConfigurationNextPath) {
		return false
	}
	if body, err := adapter.protectedServingFile(proxyStartAuthorizationPath, 0600, ""); err == nil {
		value := strings.TrimSpace(string(body))
		if value != source && value != target || os.Remove(adapter.path(proxyStartAuthorizationPath)) != nil || adapter.syncOwnershipDirectory(adapter.path("/run")) != nil {
			return false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	return adapter.removeClientPublication(ClientIdentityTargetPath, 0600, target)
}

func (adapter Adapter) RestoreClientIdentityRotation(ctx context.Context, source, target string, startup *ProxyStartupAuthority) bool {
	group := adapter.command(ctx, "getent", "group", "sing-box")
	gid, ok := groupID(group.Fact)
	if !group.OK || !ok {
		return false
	}
	if _, err := adapter.readConfigurationFile("/etc/sing-box/config.json", source, gid); err != nil || !adapter.RemoveClientIdentityTarget(source, target) {
		return false
	}
	active := adapter.command(ctx, "systemctl", "is-active", "sing-box.service")
	if active.OK && active.Fact == "active" {
		return true
	}
	return adapter.StartProxyForClientIdentityRotation(ctx, source)
}

func (adapter Adapter) InspectClientIdentityRotation(source, target, canonical string, startup *ProxyStartupAuthority, targetRequired, startupRequired, forward bool) Observation {
	group := adapter.command(context.Background(), "getent", "group", "sing-box")
	gid, groupOK := groupID(group.Fact)
	canonicalBody, canonicalErr := adapter.readConfigurationFile("/etc/sing-box/config.json", canonical, gid)
	if canonicalErr != nil && forward && canonical != target {
		canonicalBody, canonicalErr = adapter.readConfigurationFile("/etc/sing-box/config.json", target, gid)
	}
	targetBody, targetErr := adapter.clientPublicationFile(ClientIdentityTargetPath, 0600, target)
	targetAccepted := targetErr == nil && len(targetBody) > 0 || (!targetRequired || !forward && canonical == source) && errors.Is(targetErr, os.ErrNotExist)
	accepted := group.OK && groupOK && canonicalErr == nil && len(canonicalBody) > 0 && targetAccepted
	if !adapter.safelyAbsent(ClientIdentityConfigurationNextPath) {
		_, err := adapter.readConfigurationFile(ClientIdentityConfigurationNextPath, target, gid)
		accepted = accepted && forward && err == nil
	}
	if startup != nil {
		body, err := adapter.clientPublicationFile(ProxyStartupDropInPath, 0644, startup.DropInSHA256)
		accepted = accepted && (err == nil && string(body) == ProxyStartupDropIn || !startupRequired && errors.Is(err, os.ErrNotExist))
	}
	return observation(accepted && (canonical == source || canonical == target), group.Observed)
}

// Removal accepts either recorded canonical digest after revocation, including
// a target rename whose following Ownership Record checkpoint did not finish.
func (adapter Adapter) InspectClientIdentityRemoval(ctx context.Context, spec SetupSpec, sourceBody, ownership []byte, source, target, ipv4 string, forward bool) RemovalInspection {
	selected := source
	if forward {
		if _, err := adapter.ReadConfiguration(ctx, spec, target); err == nil {
			selected = target
		}
	}
	facts := adapter.InspectRemoval(ctx, spec, sourceBody, ownership, selected, ipv4)
	if forward && !adapter.safelyAbsent(ClientIdentityConfigurationNextPath) {
		group := adapter.command(ctx, "getent", "group", "sing-box")
		gid, ok := groupID(group.Fact)
		_, err := adapter.readConfigurationFile(ClientIdentityConfigurationNextPath, target, gid)
		accepted, observed := adapter.directoryContainsOnly("/etc/sing-box", 0755, adapter.ownerUID(), adapter.ownerGID(), "config.json", ".config.json.sbxr-next")
		facts.ConfigurationEntries = observation(accepted && group.OK && ok && err == nil, observed && group.Observed)
	}
	return facts
}

func (adapter Adapter) RemoveProxyStartupIntegration(ctx context.Context, authority ProxyStartupAuthority) bool {
	body, err := adapter.clientPublicationFile(ProxyStartupDropInPath, 0644, authority.DropInSHA256)
	if errors.Is(err, os.ErrNotExist) {
		if authority.DirectoryCreated && !adapter.removeEmptyDirectory(ProxyStartupDropInDirectory) {
			return false
		}
		return adapter.ReloadProxyStartupIntegration(ctx)
	}
	if err != nil || string(body) != ProxyStartupDropIn || !adapter.removeClientPublication(ProxyStartupDropInPath, 0644, authority.DropInSHA256) || !adapter.ReloadProxyStartupIntegration(ctx) {
		return false
	}
	if authority.DirectoryCreated {
		return adapter.removeEmptyDirectory(ProxyStartupDropInDirectory)
	}
	return true
}
