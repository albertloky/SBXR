// Command sbxr is the startup and Module-wiring entry point.
package main

import (
	"context"
	"errors"
	"os"
	"slices"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	healthfilesystem "github.com/albertloky/SBXR/internal/healthdiagnostics/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
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
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "update-check" {
		if runProductionScheduledUpdateCheck(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "install-apply" {
		installationModule, err := newInstallationModule()
		if err != nil || softwareubuntu.ServeInstallApply(context.Background(), func(ctx context.Context, request softwareubuntu.InstallHandoffRequest) (func() softwareubuntu.InstallApplyOutcome, error) {
			return installation.PreparePrivilegedApply(installationModule, ctx, request)
		}) != nil {
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
		if runStartupRecovery() != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "docker-purge" {
		if systemubuntu.ServeDockerPurge(os.Stdin) != nil {
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
	installed := installedClientAccessMarker()
	if slices.Contains(environment, "SBXR_INSTALLED_REENTRY=1") && !installed {
		return errors.New("installed Client Access executable changed before re-entry")
	}
	if installed || clientAccessRecoveryMarker() {
		managed := &clientAccessOutcome{}
		return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Authenticator: systemAuthenticator{}, AuthenticationPolicy: ownerconsole.AuthenticateForAccess, Profiles: managed, ProfileOutcomes: managed, Cloudflare: managed, CloudflareOutcomes: managed, Certificates: managed, CertificateOutcomes: managed, Diagnostics: managed, Lifecycle: managed, LifecycleOutcomes: managed, CompleteRemoval: managed, CompleteRemovalOutcomes: managed, StartupProvider: managed.Startup, Recovery: managed})
	}
	install := newInstallOutcome()
	return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Authenticator: systemAuthenticator{}, AuthenticationPolicy: ownerconsole.AuthenticateForAccess, Outcome: install, Diagnostics: install})
}

func installedClientAccessMarker() bool {
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return false
	}
	return executable.Close() == nil
}
