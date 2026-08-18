// Command sbxr is the startup and Module-wiring entry point.
package main

import (
	"context"
	"errors"
	"os"
	"slices"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/cloudflareprofilesetup"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	healthfilesystem "github.com/albertloky/SBXR/internal/healthdiagnostics/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	subscriptionfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func newCloudflareProfileSetupModule(network networkpolicy.Interface, cloudflare cloudflaretunnel.Interface, certificates certificatelifecycle.Interface, profiles connectionprofiles.Interface, publication subscriptionpublication.Interface, stored state.Interface, inspect func() systemchanges.Inspection, apply func(*systemchanges.ChangeSet, cloudflareprofilesetup.Execution) systemchanges.ApplyResult) (*cloudflareprofilesetup.Interface, error) {
	return cloudflareprofilesetup.New(cloudflareprofilesetup.Dependencies{
		NetworkPolicy: network.Evaluate, CloudflareTunnel: cloudflare.Plan, CertificateLifecycle: certificates.Plan,
		ConnectionProfiles: profiles.PlanRegistry, SubscriptionPublication: publication.Plan,
		State:         cloudflareprofilesetup.StateDependency{Load: stored.Load, Prepare: stored.PrepareDeferredCloudflareCommit},
		SystemChanges: cloudflareprofilesetup.SystemChangesDependency{Inspect: inspect, Apply: apply},
	})
}

func newProductionCloudflareProfileSetupModule() (*cloudflareprofilesetup.Interface, error) {
	stored := filesystem.New()
	host, err := systemubuntu.NewInstallHost("/", softwarelifecycle.ManagedUnitNames())
	if err != nil {
		return nil, err
	}
	profileHost := profilesubuntu.NewRealityHost("/")
	inspection := systemchanges.New(systemubuntu.New(installRecoveryObservation, host, stored))
	return newCloudflareProfileSetupModule(
		networkpolicy.New(ubuntu.New()),
		cloudflaretunnel.NewProduction(),
		certificatelifecycle.New(certificateubuntu.New(), installClock{}),
		connectionprofiles.New(profileHost),
		subscriptionpublication.NewIntegrated(installedSingBoxValidator{host: profileHost, version: trimVersion(softwarelifecycle.QualifiedComponentBaselines().SingBox)}),
		stored,
		inspection.Inspect,
		func(change *systemchanges.ChangeSet, execution cloudflareprofilesetup.Execution) systemchanges.ApplyResult {
			return applyProductionCloudflareProfileSetup(change, execution, stored, host)
		},
	)
}

func applyProductionCloudflareProfileSetup(change *systemchanges.ChangeSet, execution cloudflareprofilesetup.Execution, stored state.Interface, host systemubuntu.InstallHost) systemchanges.ApplyResult {
	cloudflare, err := execution.Cloudflare.Executor(cloudflaretunnel.NewProductionAPI())
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	certificate, err := certificateubuntu.NewTransactionExecutor("/opt/sbxr/releases/" + execution.ReleaseTag + "/certbot/bin/certbot")
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	subscription, err := subscriptionfilesystem.New(func(ctx context.Context, address string) error {
		return proveInstalledSubscription(ctx, address, execution.SubscriptionPort)
	})
	if err != nil {
		return systemchanges.Interface{}.Apply(nil)
	}
	observation := func() (systemchanges.Observation, error) {
		observed, err := installRecoveryObservation()
		if err != nil {
			return observed, err
		}
		observed.VolatileSHA256, err = clientAccessVolatileSHA("/")
		return observed, err
	}
	adapter := systemubuntu.NewAtForManagedProvider("/", observation, host, systemubuntu.NewNativeFirewall(), cloudflare, certificate, profilesubuntu.NewRuntimeExecutor(), subscription, stored)
	return systemchanges.New(adapter).Apply(change)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "acceptance" {
		if runPackageQualification(context.Background(), os.Args[1:], os.Stdout) != nil {
			_, _ = os.Stderr.WriteString(packageQualificationRefusal + "\n")
			os.Exit(1)
		}
		return
	}
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
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "owner-launch" {
		if softwareubuntu.LaunchOwnerConsole(context.Background()) != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "private" && os.Args[2] == "root-owner-console" {
		if softwareubuntu.ServeRootOwnerConsole(func() error {
			return runOwnerConsole(context.Background(), os.Stdin, os.Stdout, os.Environ())
		}) != nil {
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
		setup, err := newProductionCloudflareProfileSetupModule()
		if err != nil {
			return err
		}
		managed := &clientAccessOutcome{setup: setup}
		return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Scenario: ownerconsole.AuthenticatedOverview, Profiles: managed, ProfileOutcomes: managed, Cloudflare: managed, CloudflareOutcomes: managed, Certificates: managed, CertificateOutcomes: managed, Diagnostics: managed, Lifecycle: managed, LifecycleOutcomes: managed, CompleteRemoval: managed, CompleteRemovalOutcomes: managed, StartupProvider: managed.Startup, Recovery: managed})
	}
	install := newInstallOutcome()
	return ownerconsole.Run(ctx, ownerconsole.Session{Input: input, Output: output, Environment: environment, Capabilities: &capabilities, Scenario: ownerconsole.InstallationReview, Outcome: install, Diagnostics: install})
}

func installedClientAccessMarker() bool {
	executable, err := openCurrentClientAccessExecutable()
	if err != nil {
		return false
	}
	return executable.Close() == nil
}
