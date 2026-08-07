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
	return certificatelifecycle.Observation{Issuer: certificatelifecycle.IssuerObservation{
		Name: "Let's Encrypt", CertbotVersion: match[1], Distribution: distribution,
		SupportedDistribution: distribution == "snap" || distribution == "pip-venv",
		RequiredProfile:       flags["--required-profile"],
		IPAddress:             flags["--ip-address"],
		Staging:               flags["--staging"] && flags["--config-dir"] && flags["--work-dir"] && flags["--logs-dir"],
	}}, nil
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
			return nil, errors.New("Certbot output exceeded limit")
		}
		return output, err
	}
	output := &limitedOutput{remaining: maximumOutput}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdout = output
	if err := command.Run(); err != nil {
		return nil, errors.New("Certbot command failed")
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
