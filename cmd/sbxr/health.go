package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	profilesubuntu "github.com/albertloky/SBXR/internal/connectionprofiles/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	healthfilesystem "github.com/albertloky/SBXR/internal/healthdiagnostics/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	ownerubuntu "github.com/albertloky/SBXR/internal/ownerconsole/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
	statefilesystem "github.com/albertloky/SBXR/internal/state/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

func runScheduledHealthCheck(ctx context.Context, history healthdiagnostics.EventHistory) error {
	module, installation, inspections := productionHealthInputs(ctx)
	_, err := module.ScheduledCheck(ctx, history, installation, inspections...)
	return err
}

func productionHealthInputs(ctx context.Context) (healthdiagnostics.Interface, healthdiagnostics.InstallationSummary, []healthdiagnostics.NamedInspection) {
	changes := systemchanges.New(systemubuntu.New(healthObservation, nil))
	lineage := changes.InstallationHealthInspection()
	facts, _ := lineage.InstallationFacts()
	if runtime.GOOS != "linux" {
		facts = systemchanges.InstallationHealthFacts{}
	}
	statuses := map[healthdiagnostics.Module]healthdiagnostics.HealthStatus{}
	capabilities, connectionProfiles, connectionProfilesObserved := productionHealthCapabilities(ctx)
	if connectionProfilesObserved {
		statuses[healthdiagnostics.ConnectionProfilesModule] = connectionProfiles
	}
	if facts.Status == systemchanges.Managed {
		if presentation, err := managedClientAccessPresentation(ctx); err == nil {
			for module, status := range presentation.health {
				statuses[module] = status
			}
		}
		if finding, err := healthfilesystem.NewSelfInspector().Inspect(); err == nil {
			statuses[healthdiagnostics.HealthDiagnosticsModule] = finding.Status
		}
		if _, release, err := managedLoadEvidence(); err == nil {
			statuses[healthdiagnostics.SoftwareLifecycleModule] = healthdiagnostics.HealthStatus(softwareubuntu.InspectRelease("/", softwarelifecycle.ReleaseIdentity{Repository: release.Repository, Tag: release.Tag, Commit: release.Commit, IndexSHA256: release.ReleaseIndexSHA256}))
		}
		statuses[healthdiagnostics.OwnerConsoleModule] = healthdiagnostics.HealthStatus(ownerubuntu.Inspect().String())
	}
	return healthdiagnostics.New(nil), healthdiagnostics.InstallationSummaryFrom(lineage), scheduledInspections(facts, statuses, capabilities)
}

func productionHealthCapabilities(ctx context.Context) (healthdiagnostics.CapabilityInspection, healthdiagnostics.HealthStatus, bool) {
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return healthdiagnostics.CapabilityInspection{}, "", false
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return healthdiagnostics.CapabilityInspection{}, "", false
	}
	capabilities := healthCapabilities(loaded.Snapshot.Revision, loaded.Snapshot.DesiredState.ConnectionProfiles)
	if !revisionOneConnectionProfiles(loaded.Snapshot.DesiredState.ConnectionProfiles) {
		return capabilities, "", false
	}
	var status healthdiagnostics.HealthStatus
	err = module.WithManagedConnectionProfileSecrets(loaded, func(snapshot state.Snapshot, secrets state.ConnectionProfileSecretReader) error {
		disk := systemchanges.DiskRequirement{PreparationBytes: 8 << 20, TemporaryBytes: 8 << 20, SnapshotBytes: 32 << 20, JournalBytes: 8 << 20, RollbackBytes: 8 << 20, OverheadBytes: 256 << 20}
		network, err := observeRevisionOneClientAccess(snapshot, disk)
		if err != nil {
			return err
		}
		request, err := clientAccessRegistryRequest(snapshot.DesiredState, snapshot.Revision, secrets, networkpolicy.NewRevisionOneListenerContribution(network), cloudflaretunnel.XHTTPRouteHealth{}, cloudflaretunnel.WebSocketRouteHealth{})
		if err != nil {
			return err
		}
		registry := connectionprofiles.New(profilesubuntu.NewRealityHost("/")).ViewRegistry(ctx, request)
		status = healthdiagnostics.HealthStatus(registry.Health.Outcome)
		return nil
	})
	return capabilities, status, err == nil
}

func healthCapabilitiesFromState(module state.Interface, observed systemchanges.Observation, release state.ReleaseIdentity) healthdiagnostics.CapabilityInspection {
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return healthdiagnostics.CapabilityInspection{}
	}
	return healthCapabilities(loaded.Snapshot.Revision, loaded.Snapshot.DesiredState.ConnectionProfiles)
}

func healthCapabilities(revision uint64, profiles state.ConnectionProfiles) healthdiagnostics.CapabilityInspection {
	states := [...]struct {
		lifecycle state.ProfileLifecycle
		enabled   bool
	}{
		{profiles.VLESSRealityVision.Lifecycle, profiles.VLESSRealityVision.Enabled},
		{profiles.VLESSXHTTP.Lifecycle, profiles.VLESSXHTTP.Enabled},
		{profiles.VLESSWebSocket.Lifecycle, profiles.VLESSWebSocket.Enabled},
		{profiles.Hysteria2.Lifecycle, profiles.Hysteria2.Enabled},
		{profiles.TUIC.Lifecycle, profiles.TUIC.Enabled},
		{profiles.AnyTLS.Lifecycle, profiles.AnyTLS.Enabled},
	}
	names := [...]healthdiagnostics.ConnectionProfile{
		healthdiagnostics.VLESSRealityVision, healthdiagnostics.VLESSXHTTP, healthdiagnostics.VLESSWebSocket,
		healthdiagnostics.Hysteria2, healthdiagnostics.TUIC, healthdiagnostics.AnyTLS,
	}
	result := healthdiagnostics.CapabilityInspection{CommittedRevision: revision, CapabilityRows: make([]healthdiagnostics.CapabilityFact, len(states))}
	for index, profile := range states {
		lifecycle := profile.lifecycle
		if lifecycle == "" {
			lifecycle = state.ProfileDisabled
			if profile.enabled {
				lifecycle = state.ProfileEnabled
			}
		}
		result.CapabilityRows[index] = healthdiagnostics.CapabilityFact{Name: names[index], Lifecycle: map[state.ProfileLifecycle]healthdiagnostics.ProfileLifecycle{
			state.ProfileNotSetUp: healthdiagnostics.ProfileNotSetUp,
			state.ProfileEnabled:  healthdiagnostics.ProfileEnabled,
			state.ProfileDisabled: healthdiagnostics.ProfileDisabled,
		}[lifecycle]}
	}
	return result
}

func healthObservation() (systemchanges.Observation, error) {
	if runtime.GOOS != "linux" {
		return systemchanges.Observation{}, errors.New("Ubuntu health observation is unavailable")
	}
	return systemubuntu.RecoveryHealthObservation("/", installRecoveryObservation)
}

func productionDiagnosticsPresentation(ctx context.Context) (ownerconsole.DiagnosticsPresentation, error) {
	module, installation, inspections := productionHealthInputs(ctx)
	result := module.Check(ctx, installation, inspections...)
	bundles, err := healthfilesystem.NewBundleStorage().Existing()
	if err != nil {
		return ownerconsole.DiagnosticsPresentation{}, err
	}
	services := make([]ownerconsole.ServiceHealthPresentation, 0, 10)
	for _, unit := range healthDiagnosticUnits() {
		services = append(services, ownerconsole.ServiceHealthPresentation{Service: unit, Status: ownerModuleHealth(unitHealth(ctx, unit))})
	}
	presentation, err := diagnosticsPresentation(result, bundles, services)
	if err != nil {
		return ownerconsole.DiagnosticsPresentation{}, err
	}
	if result.Installation.Status == healthdiagnostics.Managed {
		policy, err := managedReclamationPolicy()
		if err != nil {
			return ownerconsole.DiagnosticsPresentation{}, err
		}
		presentation.Reclamation = reclamationDiagnostics(ctx, policy, os.Lstat, runReclamationDiagnosticCommand)
	}
	return presentation, nil
}

func managedReclamationPolicy() (state.ReclamationPolicy, error) {
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return state.ReclamationPolicy{}, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil || loaded.Snapshot == nil {
		return state.ReclamationPolicy{}, errors.New("current reclamation policy unavailable")
	}
	return loaded.Snapshot.DesiredState.Reclamation, nil
}

func runReclamationDiagnosticCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return command.Output()
}

func reclamationDiagnostics(ctx context.Context, policy state.ReclamationPolicy, lstat func(string) (os.FileInfo, error), run func(context.Context, string, ...string) ([]byte, error)) []ownerconsole.ReclamationAdvisoryPresentation {
	if policy.Version == 0 {
		return nil
	}
	held := policy.Held
	advisory := ownerconsole.ReclamationAdvisoryPresentation{Package: held.Name, Version: held.Version, DeletedExecutable: held.DeletedExecutable, HoldStatus: "Held", Code: "NETWORK-RECLAMATION-PACKAGE-HELD", NoRollback: true}
	if _, err := lstat(held.DeletedExecutable); err == nil {
		advisory.HoldStatus, advisory.Code = "Executable returned", "NETWORK-RECLAMATION-EXECUTABLE-RETURNED"
	} else if !errors.Is(err, os.ErrNotExist) {
		advisory.HoldStatus, advisory.Code = "Unknown", "NETWORK-RECLAMATION-INSPECTION-UNKNOWN"
	}
	output, err := run(ctx, "/usr/bin/apt-mark", "showhold")
	if err != nil {
		advisory.HoldStatus, advisory.Code = "Unknown", "NETWORK-RECLAMATION-INSPECTION-UNKNOWN"
	} else if !slices.Contains(strings.Fields(string(output)), held.Name) && advisory.HoldStatus == "Held" {
		advisory.HoldStatus, advisory.Code = "Hold missing", "NETWORK-RECLAMATION-HOLD-MISSING"
	}
	return []ownerconsole.ReclamationAdvisoryPresentation{advisory}
}

func diagnosticsPresentation(result healthdiagnostics.CheckResult, bundles []string, services []ownerconsole.ServiceHealthPresentation) (ownerconsole.DiagnosticsPresentation, error) {
	presentation := ownerconsole.DiagnosticsPresentation{
		Installation:        ownerInstallationStatus(result.Installation.Status),
		Retention:           ownerconsole.DiagnosticsRetention{EventDays: 30, EventMiB: 50, BundleLimit: 3},
		ExternalCopyWarning: "A copied or moved bundle is outside SBXR retention, deletion, permission, and redaction control.", Services: append([]ownerconsole.ServiceHealthPresentation(nil), services...),
	}
	for _, checked := range result.Modules {
		presentation.Modules = append(presentation.Modules, ownerconsole.ModuleHealthPresentation{
			Module: string(checked.Module), CheckedAt: checked.CheckedAt.Format(time.RFC3339), Code: string(checked.Code),
			Explanation: checked.Explanation, NextAction: checked.NextAction, Status: ownerModuleHealth(checked.Status),
		})
	}
	presentedBundles, err := supportBundlePresentations(bundles)
	if err != nil {
		return ownerconsole.DiagnosticsPresentation{}, err
	}
	presentation.Bundles = presentedBundles
	return presentation, nil
}

func productionSupportBundle(ctx context.Context, replacement ownerconsole.BundleReplacement) ownerconsole.SupportBundleResult {
	module, installation, inspections := productionHealthInputs(ctx)
	check := module.Check(ctx, installation, inspections...)
	events, err := healthdiagnostics.NewEventHistory(healthfilesystem.NewEventStorage(), nil).Events()
	if err != nil {
		return ownerconsole.SupportBundleResult{Code: "HEALTH-DIAGNOSTICS-BUNDLE-EVENTS"}
	}
	release, err := managedHealthReleaseFacts()
	if err != nil {
		return ownerconsole.SupportBundleResult{Code: "HEALTH-DIAGNOSTICS-BUNDLE-RELEASE"}
	}
	platform, err := platformFacts()
	if err != nil {
		return ownerconsole.SupportBundleResult{Code: "HEALTH-DIAGNOSTICS-BUNDLE-PLATFORM"}
	}
	storage := healthfilesystem.NewBundleStorage()
	return buildSupportBundle(module, storage, healthdiagnostics.BundleRequest{
		Check: check, Events: events, Release: release, Platform: platform, Units: diagnosticUnitSummaries(ctx),
		Replacement: healthdiagnostics.ReviewBundleReplacement(replacement.Archive),
	})
}

func buildSupportBundle(module healthdiagnostics.Interface, storage healthdiagnostics.BundleStorage, request healthdiagnostics.BundleRequest) ownerconsole.SupportBundleResult {
	result := module.BuildSupportBundle(storage, request)
	if result.Status() != healthdiagnostics.BundleCreated {
		return ownerconsole.SupportBundleResult{Code: string(result.Code())}
	}
	names, err := storage.Existing()
	if err != nil {
		return ownerconsole.SupportBundleResult{Code: "HEALTH-DIAGNOSTICS-BUNDLE-PRESENTATION"}
	}
	bundles, err := supportBundlePresentations(names)
	if err != nil {
		return ownerconsole.SupportBundleResult{Code: "HEALTH-DIAGNOSTICS-BUNDLE-PRESENTATION"}
	}
	return ownerconsole.SupportBundleResult{Created: result.ArchiveName(), Code: string(result.Code()), ExternalCopyWarning: result.ExternalCopyWarning(), Bundles: bundles}
}

func supportBundlePresentations(names []string) ([]ownerconsole.SupportBundlePresentation, error) {
	result := make([]ownerconsole.SupportBundlePresentation, 0, len(names))
	for _, archive := range names {
		created := strings.TrimSuffix(strings.TrimPrefix(archive, "sbxr-support-"), ".tar.gz")
		when, err := time.Parse("20060102T150405Z", created)
		if err != nil {
			return nil, err
		}
		result = append(result, ownerconsole.SupportBundlePresentation{Archive: archive, CreatedAt: when.Format(time.RFC3339)})
	}
	return result, nil
}

func managedHealthReleaseFacts() (healthdiagnostics.ReleaseFacts, error) {
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return healthdiagnostics.ReleaseFacts{}, err
	}
	module := statefilesystem.New()
	loaded, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}})
	if err != nil {
		return healthdiagnostics.ReleaseFacts{}, err
	}
	facts := healthdiagnostics.ReleaseFactsFrom(systemchanges.NewReleaseHealthInspection(module.HealthReleaseInspection(loaded)))
	return facts, nil
}

func platformFacts() (healthdiagnostics.PlatformFacts, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return healthdiagnostics.PlatformFacts{}, err
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && (key == "ID" || key == "VERSION_ID") {
			values[key] = strings.Trim(value, `"`)
		}
	}
	if scanner.Err() != nil || values["ID"] != "ubuntu" || values["VERSION_ID"] != "24.04" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return healthdiagnostics.PlatformFacts{}, errors.New("supported Ubuntu platform was not proven")
	}
	return healthdiagnostics.PlatformFacts{OperatingSystem: "Ubuntu Server", Version: values["VERSION_ID"], Architecture: runtime.GOARCH}, nil
}

func diagnosticUnitSummaries(ctx context.Context) []healthdiagnostics.UnitSummary {
	result := make([]healthdiagnostics.UnitSummary, 0, 10)
	for _, unit := range healthDiagnosticUnits() {
		status := map[healthdiagnostics.HealthStatus]healthdiagnostics.UnitStatus{
			healthdiagnostics.Healthy: healthdiagnostics.UnitActive, healthdiagnostics.NeedsAttention: healthdiagnostics.UnitInactive,
			healthdiagnostics.Failed: healthdiagnostics.UnitFailed, healthdiagnostics.Unknown: healthdiagnostics.UnitUnknown,
		}[unitHealth(ctx, unit)]
		result = append(result, healthdiagnostics.UnitSummary{Unit: unit, Status: status})
	}
	return result
}

func healthDiagnosticUnits() []string {
	units := softwarelifecycle.ManagedUnitNames()
	result := make([]string, 0, len(units)-1)
	for _, unit := range units {
		if unit != "sbxr-update-check.service" {
			result = append(result, unit)
		}
	}
	return result
}

func unitHealth(ctx context.Context, unit string) healthdiagnostics.HealthStatus {
	output, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	status := strings.TrimSpace(string(output))
	if err == nil && status == "active" {
		return healthdiagnostics.Healthy
	}
	if status == "failed" {
		return healthdiagnostics.Failed
	}
	if status == "inactive" {
		return healthdiagnostics.NeedsAttention
	}
	return healthdiagnostics.Unknown
}

func ownerInstallationStatus(status healthdiagnostics.InstallationStatus) ownerconsole.InstallationStatus {
	return map[healthdiagnostics.InstallationStatus]ownerconsole.InstallationStatus{
		healthdiagnostics.NotInstalled: ownerconsole.InstallationNotInstalled, healthdiagnostics.Managed: ownerconsole.InstallationManaged,
		healthdiagnostics.ChangeInProgress: ownerconsole.InstallationChangeInProgress, healthdiagnostics.RecoveryRequired: ownerconsole.InstallationRecoveryRequired,
	}[status]
}

func ownerModuleHealth(status healthdiagnostics.HealthStatus) ownerconsole.ModuleHealth {
	return map[healthdiagnostics.HealthStatus]ownerconsole.ModuleHealth{
		healthdiagnostics.Healthy: ownerconsole.HealthHealthy, healthdiagnostics.NeedsAttention: ownerconsole.HealthNeedsAttention,
		healthdiagnostics.Failed: ownerconsole.HealthFailed, healthdiagnostics.Unknown: ownerconsole.HealthUnknown,
	}[status]
}

func scheduledInspections(installation systemchanges.InstallationHealthFacts, statuses map[healthdiagnostics.Module]healthdiagnostics.HealthStatus, capabilities healthdiagnostics.CapabilityInspection) []healthdiagnostics.NamedInspection {
	stateModule := statefilesystem.New()
	return []healthdiagnostics.NamedInspection{
		inspection(healthdiagnostics.StateModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			if status, available := statuses[healthdiagnostics.StateModule]; available {
				return status, nil
			}
			return stateHealthStatus(stateModule, installation)
		}),
		inspection(healthdiagnostics.SystemChangesModule, func(context.Context) (healthdiagnostics.HealthStatus, error) {
			switch installation.Status {
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
		moduleHealthInspection(healthdiagnostics.NetworkPolicyModule, statuses),
		moduleHealthInspection(healthdiagnostics.CloudflareTunnelModule, statuses),
		moduleHealthInspection(healthdiagnostics.CertificateLifecycleModule, statuses),
		connectionProfileHealthInspection(statuses, capabilities),
		moduleHealthInspection(healthdiagnostics.SubscriptionPublicationModule, statuses),
		moduleHealthInspection(healthdiagnostics.SubscriptionServingModule, statuses),
		moduleHealthInspection(healthdiagnostics.HealthDiagnosticsModule, statuses),
		moduleHealthInspection(healthdiagnostics.SoftwareLifecycleModule, statuses),
		moduleHealthInspection(healthdiagnostics.OwnerConsoleModule, statuses),
		moduleHealthInspection(healthdiagnostics.InstallationModule, statuses),
		moduleHealthInspection(healthdiagnostics.CloudflareProfileSetupModule, statuses),
	}
}

func connectionProfileHealthInspection(statuses map[healthdiagnostics.Module]healthdiagnostics.HealthStatus, capabilities healthdiagnostics.CapabilityInspection) healthdiagnostics.NamedInspection {
	status, available := statuses[healthdiagnostics.ConnectionProfilesModule]
	if !available && capabilities.CommittedRevision == 0 {
		return healthdiagnostics.NamedInspection{Module: healthdiagnostics.ConnectionProfilesModule, Role: healthdiagnostics.Required}
	}
	if !available {
		status = healthdiagnostics.Unknown
	}
	return healthdiagnostics.NamedInspection{Module: healthdiagnostics.ConnectionProfilesModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
		return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.ConnectionProfilesModule, status), Capabilities: capabilities}, nil
	}}
}

func moduleHealthInspection(module healthdiagnostics.Module, statuses map[healthdiagnostics.Module]healthdiagnostics.HealthStatus) healthdiagnostics.NamedInspection {
	status, available := statuses[module]
	if !available {
		return healthdiagnostics.NamedInspection{Module: module, Role: healthdiagnostics.Required}
	}
	return inspection(module, func(context.Context) (healthdiagnostics.HealthStatus, error) { return status, nil })
}

func stateHealthStatus(module state.Interface, installation systemchanges.InstallationHealthFacts) (healthdiagnostics.HealthStatus, error) {
	if installation.Status == systemchanges.NotInstalled {
		result, err := module.Load(state.LoadRequest{Baseline: state.CleanVPS})
		if err == nil && result.Status == state.NotInstalled {
			return healthdiagnostics.Healthy, nil
		}
		return healthdiagnostics.Unknown, err
	}
	observed, release, err := managedLoadEvidence()
	if err != nil {
		return healthdiagnostics.Unknown, err
	}
	lineage := &state.LineageProof{Revision: observed.StateRevision, LastCompletedChangeSet: state.ChangeSetIdentity(observed.LastChangeSet), ReleaseIdentity: release}
	if installation.Status == systemchanges.ChangeInProgress {
		lineage.ActiveChangeSet = state.ChangeSetIdentity(installation.CurrentChangeSet)
	}
	result, err := module.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: release, Lineage: lineage})
	if err != nil {
		return healthdiagnostics.Unknown, err
	}
	if result.Status == state.ChangeInProgress {
		return healthdiagnostics.NeedsAttention, nil
	}
	if result.Status == state.Managed {
		return healthdiagnostics.Healthy, nil
	}
	return healthdiagnostics.Unknown, nil
}

func inspection(module healthdiagnostics.Module, inspect func(context.Context) (healthdiagnostics.HealthStatus, error)) healthdiagnostics.NamedInspection {
	return healthdiagnostics.NamedInspection{Module: module, Role: healthdiagnostics.Required, Inspect: func(ctx context.Context) (healthdiagnostics.Finding, error) {
		status, err := inspect(ctx)
		return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(module, status)}, err
	}}
}
