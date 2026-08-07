package ubuntu

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

func TestAdapterQualifiesOfficialCertbotShapeAndRedactsFailures(t *testing.T) {
	var calls []string
	adapter := Adapter{
		lookPath: func(string) (string, error) { return "/usr/local/bin/certbot", nil },
		readLink: func(string) (string, error) { return "/snap/bin/certbot", nil },
		command: func(ctx context.Context, path string, arguments ...string) ([]byte, error) {
			deadline, bounded := ctx.Deadline()
			if !bounded || time.Until(deadline) > 30*time.Second {
				return nil, errors.New("invocation was not bounded")
			}
			calls = append(calls, path+" "+strings.Join(arguments, " "))
			switch strings.Join(arguments, " ") {
			case "--version":
				return []byte("certbot 5.4.0\n"), nil
			case "certonly --help all":
				return []byte("--standalone --non-interactive --agree-tos --email --required-profile --ip-address --staging --config-dir --work-dir --logs-dir\n"), nil
			default:
				return nil, errors.New("unexpected invocation")
			}
		},
	}
	observed, err := adapter.Observe(context.Background())
	if err != nil || observed.Issuer.CertbotVersion != "5.4.0" || observed.Issuer.Distribution != "snap" || !observed.Issuer.SupportedDistribution || !observed.Issuer.RequiredProfile || !observed.Issuer.IPAddress || !observed.Issuer.Staging {
		t.Fatalf("official Certbot observation = %+v, %v", observed, err)
	}
	if fmt.Sprint(calls) != "[/usr/local/bin/certbot --version /usr/local/bin/certbot certonly --help all]" {
		t.Fatalf("bounded read-only calls = %v", calls)
	}

	adapter.command = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("RAW-CERTBOT-SECRET-MARKER"), errors.New("RAW-CERTBOT-SECRET-MARKER")
	}
	if _, err := adapter.Observe(context.Background()); err == nil || strings.Contains(err.Error(), "RAW-CERTBOT-SECRET-MARKER") {
		t.Fatalf("raw Certbot failure crossed the seam: %v", err)
	}

	adapter.command = func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if len(arguments) == 1 {
			return []byte("not official version output"), nil
		}
		return nil, nil
	}
	if _, err := adapter.Observe(context.Background()); err == nil {
		t.Fatal("malformed Certbot version was accepted")
	}
	adapter.command = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(strings.Repeat("x", maximumOutput+1)), nil
	}
	if _, err := adapter.Observe(context.Background()); err == nil {
		t.Fatal("unbounded Certbot output was accepted")
	}
}

func TestArgumentsBuildOnlyTheFourExactReviewedContracts(t *testing.T) {
	orders := []certificatelifecycle.OrderContract{
		{Lineage: certificatelifecycle.IPLineage, RequiredProfile: "shortlived", Identity: "192.0.2.10", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", Staging: true, ConfigDirectory: "/var/lib/sbxr/certbot/staging/sbxr-ip", Account: "disposable-staging-sbxr-ip"},
		{Lineage: certificatelifecycle.IPLineage, RequiredProfile: "shortlived", Identity: "192.0.2.10", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"},
		{Lineage: certificatelifecycle.DomainLineage, RequiredProfile: "tlsserver", Identity: "direct.example.com", CertName: "sbxr-domain", OwnerEmail: "owner@example.com", Staging: true, ConfigDirectory: "/var/lib/sbxr/certbot/staging/sbxr-domain", Account: "disposable-staging-sbxr-domain"},
		{Lineage: certificatelifecycle.DomainLineage, RequiredProfile: "tlsserver", Identity: "direct.example.com", CertName: "sbxr-domain", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"},
	}
	var commands [][]string
	for _, order := range orders {
		arguments, err := Arguments(order)
		if err != nil || strings.Contains(strings.Join(arguments, " "), "--preferred-profile") {
			t.Fatalf("arguments for %#v = %#v, %v", order, arguments, err)
		}
		commands = append(commands, arguments)
	}
	wantIP := []string{"certbot", "certonly", "--config-dir", "/var/lib/sbxr/certbot/production", "--work-dir", "/run/sbxr/certbot/production", "--logs-dir", "/var/log/sbxr/certbot/production", "--standalone", "--non-interactive", "--agree-tos", "--email", "owner@example.com", "--required-profile", "shortlived", "--ip-address", "192.0.2.10", "--cert-name", "sbxr-ip"}
	wantDomain := []string{"certbot", "certonly", "--config-dir", "/var/lib/sbxr/certbot/production", "--work-dir", "/run/sbxr/certbot/production", "--logs-dir", "/var/log/sbxr/certbot/production", "--standalone", "--non-interactive", "--agree-tos", "--email", "owner@example.com", "--required-profile", "tlsserver", "--cert-name", "sbxr-domain", "-d", "direct.example.com"}
	if fmt.Sprint(commands[1]) != fmt.Sprint(wantIP) || fmt.Sprint(commands[3]) != fmt.Sprint(wantDomain) {
		t.Fatalf("production contracts = %#v", commands)
	}
	for _, staging := range [][]string{commands[0], commands[2]} {
		joined := strings.Join(staging, " ")
		if !strings.Contains(joined, "--staging") || !strings.Contains(joined, "--config-dir") || !strings.Contains(joined, "--work-dir") || !strings.Contains(joined, "--logs-dir") {
			t.Fatalf("staging contract = %v", staging)
		}
	}
	changed := orders[1]
	changed.RequiredProfile = "preferred shortlived"
	if _, err := Arguments(changed); err == nil {
		t.Fatal("arbitrary profile entered Certbot arguments")
	}
}

func TestAdapterRecognizesSupportedPipVirtualEnvironment(t *testing.T) {
	adapter := Adapter{
		lookPath: func(string) (string, error) { return "/opt/certbot/bin/certbot", nil },
		readLink: func(string) (string, error) { return "", errors.New("not a symlink") },
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/opt/certbot/bin/certbot":
				return []byte("#!/opt/certbot/bin/python3\n"), nil
			case "/opt/certbot/pyvenv.cfg":
				return []byte("home = /usr/bin\n"), nil
			default:
				return nil, errors.New("unexpected path")
			}
		},
		command: func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
			if len(arguments) == 1 {
				return []byte("certbot 5.4.0\n"), nil
			}
			return []byte("--required-profile --ip-address --staging --config-dir --work-dir --logs-dir\n"), nil
		},
	}
	observed, err := adapter.Observe(t.Context())
	if err != nil || observed.Issuer.Distribution != "pip-venv" || !observed.Issuer.SupportedDistribution {
		t.Fatalf("pip virtual environment = %+v, %v", observed, err)
	}
}
