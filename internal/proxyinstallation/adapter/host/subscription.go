package host

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// SubscriptionPreflight contains read-only admission facts, not execution authority.
type SubscriptionPreflight struct {
	TCP80, TCP8443, Clock, PackageLocks, RenewalIdle, Dependencies, Firewall Observation
	SnapdInstalled, CertbotInstalled                                         bool
	DependencyIdentity, FirewallIdentity                                     string
}

func (adapter Adapter) AcquireSubscriptionReviewLock(name string) (*MutationLock, bool, error) {
	if err := adapter.safeParents(name); err != nil {
		return nil, false, err
	}
	return softwarelifecycle.AcquireExistingMutationLockAuthority(adapter.path(name), adapter.ownerUID())
}

func (adapter Adapter) PreflightSubscription(ctx context.Context, ipv4 string) SubscriptionPreflight {
	facts := SubscriptionPreflight{}
	if ctx.Err() != nil || net.ParseIP(ipv4).To4() == nil {
		return facts
	}
	command := adapter.subscriptionCommand
	if command == nil {
		command = commandOutput
	}
	bind := adapter.subscriptionBind
	if bind == nil {
		bind = subscriptionTCPAvailable
	}
	facts.TCP80 = observation(bind(ipv4, "80"), true)
	facts.TCP8443 = observation(bind(ipv4, "8443"), true)
	if adapter.clockSynchronized != nil {
		facts.Clock = observation(adapter.clockSynchronized(ctx), true)
	}
	if adapter.packageLocksAvailable != nil {
		facts.PackageLocks = observation(adapter.packageLocksAvailable(), true)
	}

	// Certbot uses these shared directory locks. Observation never creates them.
	idle := true
	for _, path := range []string{"/etc/letsencrypt/.certbot.lock", "/var/lib/letsencrypt/.certbot.lock", "/var/log/letsencrypt/.certbot.lock"} {
		if err := adapter.safeParents(path); err != nil && !os.IsNotExist(err) {
			idle = false
		}
		idle = idle && adapter.certbotLockAvailable(path)
	}
	_, code, observed := command(ctx, "pgrep", "--exact", "certbot")
	facts.RenewalIdle = observation(idle && code == 1, observed && (code == 0 || code == 1))

	// Only a known iptables filter surface can support the reviewed exact rules.
	rules, code, observed := command(ctx, "iptables-save", "-t", "filter")
	var stableRules []string
	for _, line := range strings.Split(rules, "\n") {
		if !strings.HasPrefix(line, "#") {
			stableRules = append(stableRules, line)
		}
	}
	rules = strings.Join(stableRules, "\n")
	facts.Firewall = observation(code == 0 && strings.Contains(rules, "*filter\n") && strings.Contains(rules, ":INPUT ") && strings.Contains(rules, "\nCOMMIT") && !strings.Contains(rules, "sbxr-subscription"), observed && code == 0)
	facts.FirewallIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte(rules)))

	packages, code, observed := command(ctx, "dpkg-query", "--show", "--showformat=${Package} ${db:Status-Status} ${Version}\\n", "snapd", "certbot")
	if !observed || (code != 0 && code != 1) || code == 0 && strings.TrimSpace(packages) == "" {
		return facts
	}
	for _, line := range strings.Split(strings.TrimSpace(packages), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "snapd" && fields[0] != "certbot" {
			return facts
		}
		if fields[1] == "not-installed" || fields[1] == "config-files" {
			continue
		}
		if fields[1] != "installed" || fields[0] == "certbot" {
			return facts
		}
		facts.SnapdInstalled = true
	}
	identity := packages
	if facts.SnapdInstalled {
		// Listing all installed snaps distinguishes genuine absence from a failed lookup.
		snaps, code, observed := command(ctx, "snap", "list", "--unicode=always", "--color=never")
		if !observed || code != 0 {
			return facts
		}
		lines := strings.Split(strings.TrimSpace(snaps), "\n")
		if strings.TrimSpace(snaps) != "" && strings.Join(strings.Fields(lines[0]), " ") != "Name Version Rev Tracking Publisher Notes" {
			return facts
		}
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) != 6 {
				return facts
			}
			if fields[0] != "certbot" {
				continue
			}
			version := strings.Split(fields[1], ".")
			if len(version) != 3 {
				return facts
			}
			major, e1 := strconv.Atoi(version[0])
			minor, e2 := strconv.Atoi(version[1])
			_, e3 := strconv.Atoi(version[2])
			if e1 != nil || e2 != nil || e3 != nil || major < 5 || major == 5 && minor < 4 || fields[4] != "certbot-eff✓" || fields[5] != "classic" {
				return facts
			}
			facts.CertbotInstalled = true
		}
		changes, code, observed := command(ctx, "snap", "changes")
		if !observed || code != 0 {
			return facts
		}
		changeLines := strings.Split(strings.TrimSpace(changes), "\n")
		if strings.TrimSpace(changes) != "" && strings.Join(strings.Fields(changeLines[0]), " ") != "ID Status Spawn Ready Summary" {
			return facts
		}
		for index, line := range changeLines {
			if index == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[1] != "Done" && fields[1] != "Error" && fields[1] != "Undone" {
				return facts
			}
		}
		identity += snaps
	} else {
		for _, path := range []string{"/snap/certbot", "/snap/bin/certbot", "/var/lib/snapd/snaps"} {
			if !adapter.safelyAbsent(path) {
				return facts
			}
		}
	}
	facts.DependencyIdentity = fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))
	facts.Dependencies = observation(true, true)
	return facts
}

func subscriptionTCPAvailable(ipv4, port string) bool {
	listener, err := net.Listen("tcp4", net.JoinHostPort(ipv4, port))
	if err != nil {
		return false
	}
	return listener.Close() == nil
}

func (adapter Adapter) certbotLockAvailable(name string) bool {
	path := adapter.path(name)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != adapter.ownerUID() || stat.Nlink != 1 {
		return false
	}
	// F_GETLK observes Certbot's POSIX lockf lock without creating or writing a file.
	lock := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart}
	if syscall.FcntlFlock(file.Fd(), syscall.F_GETLK, &lock) != nil || lock.Type != syscall.F_UNLCK {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && os.SameFile(info, current)
}
