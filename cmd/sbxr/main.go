// Command sbxr is the startup and Module-wiring entry point.
package main

import (
	"context"
	"os"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	healthfilesystem "github.com/albertloky/SBXR/internal/healthdiagnostics/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		if writeVersion(os.Stdout, false) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		if writeVersion(os.Stdout, true) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "health-check" {
		history := healthdiagnostics.NewEventHistory(healthfilesystem.NewEventStorage(), nil)
		if runScheduledHealthCheck(context.Background(), history) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "install-apply" {
		if softwareubuntu.ServeInstallApply(context.Background(), prepareInstallApply) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "client-access" {
		if servePrivateClientAccess(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "recover" {
		if runInstallRecovery() != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "subscription-serve" {
		if subscriptionserving.Run(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "certificate-renewal" {
		if runCertificateRenewal(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	_ = filesystem.New()
	_ = networkpolicy.New(ubuntu.New())
	if runOwnerConsole(context.Background(), os.Stdin, os.Stdout, os.Environ()) != nil {
		os.Exit(1)
	}
}

func runOwnerConsole(ctx context.Context, input, output *os.File, environment []string) error {
	capabilities := ownerconsole.DetectTerminal(input, output, environment)
	if installedClientAccessMarker() {
		managed := &clientAccessOutcome{}
		return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Authenticator: systemAuthenticator{}, AuthenticationPolicy: ownerconsole.AuthenticateForAccess, Profiles: managed, ProfileOutcomes: managed, Cloudflare: managed, CloudflareOutcomes: managed, Certificates: managed, CertificateOutcomes: managed, StartupProvider: managed.Startup, Recovery: managed})
	}
	return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Authenticator: systemAuthenticator{}, AuthenticationPolicy: ownerconsole.DeferAuthenticationUntilApply, Outcome: newInstallOutcome()})
}

func installedClientAccessMarker() bool {
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return false
	}
	return executable.Close() == nil
}
