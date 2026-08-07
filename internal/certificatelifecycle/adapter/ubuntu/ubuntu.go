// Package ubuntu supplies Certificate Lifecycle's read-only Certbot Adapter.
package ubuntu

import (
	"context"
	"errors"
	"io"
	"net/mail"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

const maximumOutput = 64 << 10

var certbotVersion = regexp.MustCompile(`^certbot ([0-9]+\.[0-9]+(?:\.[0-9]+)?)$`)
var directHostname = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9]?))*$`)

type Adapter struct {
	lookPath func(string) (string, error)
	readLink func(string) (string, error)
	readFile func(string) ([]byte, error)
	command  func(context.Context, string, ...string) ([]byte, error)
}

func New() Adapter { return Adapter{} }

func (adapter Adapter) Observe(ctx context.Context) (certificatelifecycle.Observation, error) {
	lookPath := adapter.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath("certbot")
	if err != nil {
		return certificatelifecycle.Observation{}, errors.New("Certbot executable unavailable")
	}
	versionOutput, err := adapter.run(ctx, path, "--version")
	if err != nil {
		return certificatelifecycle.Observation{}, errors.New("Certbot version check failed")
	}
	match := certbotVersion.FindStringSubmatch(strings.TrimSpace(string(versionOutput)))
	if match == nil {
		return certificatelifecycle.Observation{}, errors.New("Certbot version output malformed")
	}
	helpOutput, err := adapter.run(ctx, path, "certonly", "--help", "all")
	if err != nil {
		return certificatelifecycle.Observation{}, errors.New("Certbot capability check failed")
	}
	flags := map[string]bool{}
	for _, field := range strings.Fields(string(helpOutput)) {
		flags[strings.Trim(field, " ,=<>[]()")] = true
	}
	distribution := "unproved"
	readLink := adapter.readLink
	if readLink == nil {
		readLink = os.Readlink
	}
	target, _ := readLink(path)
	if path == "/snap/bin/certbot" || target == "/snap/bin/certbot" {
		distribution = "snap"
	} else if adapter.isVirtualEnvironment(path) {
		distribution = "pip-venv"
	}
	scheduler, err := adapter.observeScheduler(ctx)
	if err != nil {
		return certificatelifecycle.Observation{}, errors.New("renewal scheduler check failed")
	}
	return certificatelifecycle.Observation{Issuer: certificatelifecycle.IssuerObservation{
		Name: "Let's Encrypt", CertbotVersion: match[1], Distribution: distribution,
		SupportedDistribution: distribution == "snap" || distribution == "pip-venv",
		RequiredProfile:       flags["--required-profile"],
		IPAddress:             flags["--ip-address"],
		Staging:               flags["--staging"] && flags["--config-dir"] && flags["--work-dir"] && flags["--logs-dir"],
	}, Scheduler: scheduler}, nil
}

func (adapter Adapter) observeScheduler(ctx context.Context) (certificatelifecycle.SchedulerObservation, error) {
	enabled, err := adapter.run(ctx, "systemctl", "is-enabled", "sbxr-cert-renew.timer")
	if err != nil {
		return certificatelifecycle.SchedulerObservation{}, err
	}
	service, err := adapter.run(ctx, "systemctl", "cat", "sbxr-cert-renew.service")
	if err != nil {
		return certificatelifecycle.SchedulerObservation{}, err
	}
	timer, err := adapter.run(ctx, "systemctl", "cat", "sbxr-cert-renew.timer")
	if err != nil {
		return certificatelifecycle.SchedulerObservation{}, err
	}
	timers, err := adapter.run(ctx, "systemctl", "list-unit-files", "--type=timer", "--state=enabled", "--no-legend", "--no-pager")
	if err != nil {
		return certificatelifecycle.SchedulerObservation{}, err
	}
	serviceUnit, timerUnit := parseSystemdUnit(service), parseSystemdUnit(timer)
	execStart := serviceUnit["Service"]["ExecStart"]
	onCalendar := timerUnit["Timer"]["OnCalendar"]
	onInactive := timerUnit["Timer"]["OnUnitInactiveSec"]
	randomized := timerUnit["Timer"]["RandomizedDelaySec"]
	accuracy := timerUnit["Timer"]["AccuracySec"]
	persistent := timerUnit["Timer"]["Persistent"]
	target := timerUnit["Timer"]["Unit"]
	observation := certificatelifecycle.SchedulerObservation{
		Enabled:       strings.TrimSpace(string(enabled)) == "enabled",
		Persistent:    len(persistent) == 1 && persistent[0] == "true",
		Serial:        len(execStart) == 1 && execStart[0] == "/usr/local/bin/sbxr private certificate-renewal",
		ExactUnitPair: len(onCalendar) == 1 && onCalendar[0] == "*-*-* 00,12:00:00" && len(onInactive) == 1 && onInactive[0] == "13m" && len(accuracy) == 1 && accuracy[0] == "1s" && len(target) == 1 && target[0] == "sbxr-cert-renew.service",
		Randomized:    len(randomized) == 1 && randomized[0] == "1m",
		RunsPerDay:    0,
	}
	if len(onCalendar) == 1 && onCalendar[0] == "*-*-* 00,12:00:00" {
		observation.RunsPerDay = 2
	}
	seenOwner, competitor := false, false
	for _, line := range strings.Split(string(timers), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		seenOwner = seenOwner || name == "sbxr-cert-renew.timer"
		if name == "sbxr-cert-renew.timer" {
			continue
		}
		content, contentErr := adapter.run(ctx, "systemctl", "cat", fields[0])
		if contentErr != nil {
			return certificatelifecycle.SchedulerObservation{}, contentErr
		}
		timerDefinition := parseSystemdUnit(content)
		targets := timerDefinition["Timer"]["Unit"]
		target := strings.TrimSuffix(fields[0], ".timer") + ".service"
		if len(targets) == 1 {
			target = targets[0]
		} else if len(targets) > 1 {
			competitor = true
			continue
		}
		if !safeUnitName(target, ".service") {
			competitor = true
			continue
		}
		serviceContent, serviceErr := adapter.run(ctx, "systemctl", "cat", target)
		if serviceErr != nil {
			return certificatelifecycle.SchedulerObservation{}, serviceErr
		}
		lower := strings.ToLower(string(content) + "\n" + string(serviceContent))
		competitor = competitor || strings.Contains(lower, "certbot") || strings.Contains(lower, "certificate-renewal") || strings.Contains(lower, "sbxr-cert-renew")
	}
	observation.NoCompetingScheduler = seenOwner && !competitor
	return observation, nil
}

func safeUnitName(name, suffix string) bool {
	return strings.HasSuffix(name, suffix) && !strings.ContainsAny(name, "/\\ \t\r\n") && name != suffix
}

func parseSystemdUnit(content []byte) map[string]map[string][]string {
	parsed := map[string]map[string][]string{}
	section := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if parsed[section] == nil {
				parsed[section] = map[string][]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		parsed[section][strings.TrimSpace(key)] = append(parsed[section][strings.TrimSpace(key)], strings.TrimSpace(value))
	}
	return parsed
}

func (adapter Adapter) isVirtualEnvironment(path string) bool {
	read := adapter.readFile
	if read == nil {
		read = readSmallFile
	}
	script, err := read(path)
	if err != nil || len(script) > 4096 {
		return false
	}
	first, _, _ := strings.Cut(string(script), "\n")
	interpreter := strings.TrimPrefix(first, "#!")
	bin := filepath.Dir(path)
	if first == interpreter || !filepath.IsAbs(interpreter) || filepath.Dir(interpreter) != bin {
		return false
	}
	config, err := read(filepath.Join(filepath.Dir(bin), "pyvenv.cfg"))
	return err == nil && len(config) > 0 && len(config) <= 4096
}

func readSmallFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 4097))
}

// Arguments converts one fixed reviewed order contract into the only supported
// Certbot argv shapes. Plans contain typed facts, never raw command arguments.
func Arguments(order certificatelifecycle.OrderContract) ([]string, error) {
	address, addressErr := netip.ParseAddr(order.Identity)
	email, emailErr := mail.ParseAddress(order.OwnerEmail)
	if emailErr != nil || email.Address != order.OwnerEmail || email.Name != "" || strings.ContainsAny(order.OwnerEmail, "\r\n") {
		return nil, errors.New("reviewed Owner email unavailable")
	}
	base := []string{"certbot", "certonly"}
	if order.Staging {
		if order.ConfigDirectory != "/var/lib/sbxr/certbot/staging/"+order.CertName || order.Account != "disposable-staging-"+order.CertName {
			return nil, errors.New("staging isolation contract invalid")
		}
		base = append(base, "--staging", "--config-dir", order.ConfigDirectory, "--work-dir", "/run/sbxr/certbot/"+order.CertName, "--logs-dir", "/var/log/sbxr/certbot/"+order.CertName)
	} else if order.ConfigDirectory != "/var/lib/sbxr/certbot/production" || order.Account != "production" {
		return nil, errors.New("production isolation contract invalid")
	} else {
		base = append(base, "--config-dir", order.ConfigDirectory, "--work-dir", "/run/sbxr/certbot/production", "--logs-dir", "/var/log/sbxr/certbot/production")
	}
	base = append(base, "--standalone", "--non-interactive", "--agree-tos", "--email", order.OwnerEmail, "--required-profile", order.RequiredProfile)
	switch {
	case order.Lineage == certificatelifecycle.IPLineage && order.RequiredProfile == "shortlived" && order.CertName == "sbxr-ip" && addressErr == nil && address.IsGlobalUnicast():
		return append(base, "--ip-address", order.Identity, "--cert-name", order.CertName), nil
	case order.Lineage == certificatelifecycle.DomainLineage && order.RequiredProfile == "tlsserver" && order.CertName == "sbxr-domain" && len(order.Identity) <= 253 && directHostname.MatchString(order.Identity):
		return append(base, "--cert-name", order.CertName, "-d", order.Identity), nil
	default:
		return nil, errors.New("certificate order contract invalid")
	}
}

func (adapter Adapter) run(parent context.Context, path string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if adapter.command != nil {
		output, err := adapter.command(ctx, path, arguments...)
		if len(output) > maximumOutput {
			return nil, errors.New("command output exceeded limit")
		}
		return output, err
	}
	output := &limitedOutput{remaining: maximumOutput}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdout = output
	if err := command.Run(); err != nil {
		return nil, errors.New("command failed")
	}
	return output.data, nil
}

type limitedOutput struct {
	data      []byte
	remaining int
}

func (output *limitedOutput) Write(data []byte) (int, error) {
	if len(data) > output.remaining {
		return 0, errors.New("Certbot output exceeded limit")
	}
	output.data = append(output.data, data...)
	output.remaining -= len(data)
	return len(data), nil
}
