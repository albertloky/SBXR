package main

import (
	"context"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	networkubuntu "github.com/albertloky/SBXR/internal/networkpolicy/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func runScheduledHealthCheck(ctx context.Context, history healthdiagnostics.EventHistory) error {
	changes := systemchanges.New(systemubuntu.New(nil, nil))
	installation := healthdiagnostics.InstallationSummaryFrom(changes.InstallationHealthInspection())
	_, err := healthdiagnostics.New(nil).ScheduledCheck(ctx, history, installation, scheduledInspections()...)
	return err
}

func scheduledInspections() []healthdiagnostics.NamedInspection {
	stateModule := statefilesystem.New()
	networkModule := networkpolicy.New(networkubuntu.New())
	changes := systemchanges.New(systemubuntu.New(nil, nil))
	tunnel := cloudflaretunnel.New(nil, nil)
	certificates := certificatelifecycle.New(certificateubuntu.New(), nil)
	profiles := connectionprofiles.New(nil)
	return []healthdiagnostics.NamedInspection{
		inspection(healthdiagnostics.StateModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			result, err := stateModule.Load(state.LoadRequest{})
			if err != nil {
				return healthdiagnostics.Unknown, err
			}
			switch result.Status {
			case state.NotInstalled, state.Managed:
				return healthdiagnostics.Healthy, nil
			case state.ChangeInProgress:
				return healthdiagnostics.NeedsAttention, nil
			default:
				return healthdiagnostics.Unknown, nil
			}
		}),
		inspection(healthdiagnostics.NetworkPolicyModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			return healthdiagnostics.HealthStatus(networkModule.Evaluate(networkpolicy.Request{}).Outcome), nil
		}),
		inspection(healthdiagnostics.SystemChangesModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			result := changes.Inspect()
			if len(result.Findings) > 0 {
				return healthdiagnostics.Unknown, nil
			}
			switch result.Status {
			case systemchanges.NotInstalled, systemchanges.Managed:
				return healthdiagnostics.Healthy, nil
			case systemchanges.ChangeInProgress:
				return healthdiagnostics.NeedsAttention, nil
			case systemchanges.RecoveryRequired:
				return healthdiagnostics.Failed, nil
			default:
				return healthdiagnostics.Unknown, nil
			}
		}),
		inspection(healthdiagnostics.CloudflareTunnelModule, func(ctx context.Context) (healthdiagnostics.HealthStatus, error) {
			return healthdiagnostics.HealthStatus(tunnel.View(ctx, cloudflaretunnel.ViewRequest{}).Health.Outcome), nil
		}),
		inspection(healthdiagnostics.CertificateLifecycleModule, func(ctx context.Context) (healthdiagnostics.HealthStatus, error) {
			return healthdiagnostics.HealthStatus(certificates.View(ctx, certificatelifecycle.ViewRequest{}).Health.Outcome), nil
		}),
		inspection(healthdiagnostics.ConnectionProfilesModule, func(ctx context.Context) (healthdiagnostics.HealthStatus, error) {
			return healthdiagnostics.HealthStatus(profiles.ViewRegistry(ctx, connectionprofiles.RegistryViewRequest{}).Health.Outcome), nil
		}),
		inspection(healthdiagnostics.SubscriptionPublicationModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			if (subscriptionpublication.Interface{}).View(subscriptionpublication.ViewRequest{}).Status == subscriptionpublication.PublicationUnavailable {
				return healthdiagnostics.Unknown, nil
			}
			return healthdiagnostics.Failed, nil
		}),
		inspection(healthdiagnostics.SubscriptionServingModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			server, err := subscriptionserving.New()
			if err != nil {
				return healthdiagnostics.Unknown, err
			}
			return healthdiagnostics.HealthStatus(server.Health().Status), nil
		}),
		{Module: healthdiagnostics.HealthDiagnosticsModule, Role: healthdiagnostics.Required},
		{Module: healthdiagnostics.SoftwareLifecycleModule, Role: healthdiagnostics.Required},
		{Module: healthdiagnostics.OwnerConsoleModule, Role: healthdiagnostics.Required},
	}
}

func inspection(module healthdiagnostics.Module, inspect func(context.Context) (healthdiagnostics.HealthStatus, error)) healthdiagnostics.NamedInspection {
	return healthdiagnostics.NamedInspection{Module: module, Role: healthdiagnostics.Required, Inspect: func(ctx context.Context) (healthdiagnostics.Finding, error) {
		status, err := inspect(ctx)
		return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(module, status)}, err
	}}
}
