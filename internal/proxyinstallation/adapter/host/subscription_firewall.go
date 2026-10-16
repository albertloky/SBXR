package host

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
)

// The fixed enablement link is part of the known firewall unit's authority.
// This derived footprint also applies to existing schema-1 recovery journals.
const SubscriptionFirewallWantsPath = "/etc/systemd/system/multi-user.target.wants/sbxr-subscription-firewall.service"

func (a Adapter) subscriptionFirewallFilesSafe(allowMain, allowLink bool) bool {
	const unit = "sbxr-subscription-firewall.service"
	for _, directory := range []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient"} {
		for _, suffix := range []string{unit, unit + ".d", "multi-user.target.wants/" + unit, "multi-user.target.requires/" + unit} {
			path := directory + "/" + suffix
			if path == SubscriptionFirewallUnitPath && allowMain || path == SubscriptionFirewallWantsPath && allowLink {
				continue
			}
			if _, err := os.Lstat(a.path(path)); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
	}
	if err := a.safeParents(SubscriptionFirewallUnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err := a.safeParents(SubscriptionFirewallWantsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false
	}
	return !allowLink || a.subscriptionFirewallLinkSafe()
}

func (a Adapter) subscriptionFirewallLinkSafe() bool {
	if err := a.safeParents(SubscriptionFirewallWantsPath); err != nil {
		return errors.Is(err, os.ErrNotExist) && a.safelyAbsent(SubscriptionFirewallWantsPath)
	}
	info, err := os.Lstat(a.path(SubscriptionFirewallWantsPath))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	stat, owned := infoSys(info)
	target, targetErr := os.Readlink(a.path(SubscriptionFirewallWantsPath))
	return err == nil && owned && stat.Uid == a.ownerUID() && stat.Nlink == 1 && info.Mode()&os.ModeSymlink != 0 && targetErr == nil && (target == "../sbxr-subscription-firewall.service" || target == SubscriptionFirewallUnitPath)
}

var firewallExecEntries = regexp.MustCompile(`\{[^{}]*\}`)

func exactFirewallExec(body, unit, property string) bool {
	var commands []string
	for _, line := range strings.Split(unit, "\n") {
		if command, ok := strings.CutPrefix(line, property+"="); ok {
			commands = append(commands, strings.TrimSuffix(strings.Replace(command, "/bin/sh -ec '", "/bin/sh -ec ", 1), "'"))
		}
	}
	entries := firewallExecEntries.FindAllString(body, -1)
	if len(entries) != len(commands) || strings.Trim(firewallExecEntries.ReplaceAllString(body, ""), " ;\r\n\t") != "" {
		return false
	}
	for i, entry := range entries {
		path, argv, valid := exactSystemdExecStart(entry)
		if !valid || path != "/bin/sh" || argv != commands[i] {
			return false
		}
	}
	return len(commands) > 0
}

// An absent main file permits only quiescent cache cleanup, never cached commands.
func (a Adapter) subscriptionFirewallEffective(ctx context.Context, authority SubscriptionResourceAuthority, mainAbsent bool) (safe, loaded bool) {
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	show := func(property string) (string, bool) {
		value, code, observed := run(ctx, "systemctl", "show", "--property="+property, "--value", "sbxr-subscription-firewall.service")
		return strings.TrimSpace(value), observed && code == 0
	}
	pid, pidOK := show("MainPID")
	controlPID, controlOK := show("ControlPID")
	if !pidOK || !controlOK || pid != "0" || controlPID != "0" {
		return false, false
	}
	if mainAbsent {
		active, activeOK := show("ActiveState")
		return activeOK && (active == "inactive" || active == "failed"), false
	}
	state, ok := show("LoadState")
	if !ok {
		return false, false
	}
	fragment, fragmentOK := show("FragmentPath")
	dropins, dropinsOK := show("DropInPaths")
	if !fragmentOK || !dropinsOK || dropins != "" {
		return false, false
	}
	if state != "loaded" || fragment != SubscriptionFirewallUnitPath {
		return false, false
	}
	for _, property := range []string{"ExecStart", "ExecStop"} {
		value, ok := show(property)
		if !ok || !exactFirewallExec(value, subscriptionResourceUnit(authority), property) {
			return false, false
		}
	}
	for _, property := range []string{"ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStopPost"} {
		value, ok := show(property)
		if !ok || value != "" {
			return false, false
		}
	}
	return true, true
}

func (a Adapter) removeSubscriptionFirewallLink() bool {
	return a.subscriptionFirewallLinkSafe() && a.removeFile(SubscriptionFirewallWantsPath).OK
}
