package healthdiagnostics_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

var checkedAt = time.Date(2026, 8, 8, 12, 0, 0, 0, time.FixedZone("test", 8*60*60))

func TestCheckReportsEveryInstallationAndModuleHealthCombination(t *testing.T) {
	installationStatuses := []healthdiagnostics.InstallationStatus{
		healthdiagnostics.NotInstalled,
		healthdiagnostics.Managed,
		healthdiagnostics.ChangeInProgress,
		healthdiagnostics.RecoveryRequired,
	}
	healthStatuses := []healthdiagnostics.HealthStatus{
		healthdiagnostics.Healthy,
		healthdiagnostics.NeedsAttention,
		healthdiagnostics.Failed,
		healthdiagnostics.Unknown,
	}
	modules := []healthdiagnostics.Module{
		healthdiagnostics.StateModule,
		healthdiagnostics.NetworkPolicyModule,
		healthdiagnostics.SystemChangesModule,
		healthdiagnostics.CloudflareTunnelModule,
		healthdiagnostics.CertificateLifecycleModule,
		healthdiagnostics.ConnectionProfilesModule,
		healthdiagnostics.SubscriptionPublicationModule,
		healthdiagnostics.SubscriptionServingModule,
		healthdiagnostics.HealthDiagnosticsModule,
		healthdiagnostics.SoftwareLifecycleModule,
		healthdiagnostics.OwnerConsoleModule,
	}
	module := healthdiagnostics.New(func() time.Time { return checkedAt })

	for _, installationStatus := range installationStatuses {
		for _, healthStatus := range healthStatuses {
			t.Run(string(installationStatus)+"/"+string(healthStatus), func(t *testing.T) {
				inspections := make([]healthdiagnostics.NamedInspection, 0, len(modules))
				for _, owner := range modules {
					owner := owner
					inspections = append(inspections, healthdiagnostics.NamedInspection{Module: owner, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
						return finding(owner, healthStatus), nil
					}})
				}
				installation := installationSummary(installationStatus)

				got := module.Check(t.Context(), installation, inspections...)
				if got.Installation.Status != installationStatus || len(got.Modules) != len(modules) {
					t.Fatalf("Check() = installation %q and %d Modules", got.Installation.Status, len(got.Modules))
				}
				if (installationStatus == healthdiagnostics.ChangeInProgress || installationStatus == healthdiagnostics.RecoveryRequired) && !got.Installation.Correction.Complete() {
					t.Fatalf("installation has incomplete Correction Flow: %#v", got.Installation.Correction)
				}
				for index, result := range got.Modules {
					if result.CheckedAt != checkedAt.UTC() || result.Module != modules[index] || result.Status != healthStatus || result.Code == "" || result.Role != healthdiagnostics.Required || result.Explanation == "" || result.NextAction == "" {
						t.Fatalf("result %d = %#v", index, result)
					}
					if healthStatus != healthdiagnostics.Healthy && !result.Correction.Complete() {
						t.Fatalf("result %d has incomplete Correction Flow: %#v", index, result.Correction)
					}
				}
			})
		}
	}
}

func TestCheckReportsExactSafeInstallationProgressAndRecoveryFacts(t *testing.T) {
	module := healthdiagnostics.New(func() time.Time { return checkedAt })
	change := module.Check(t.Context(), installationSummary(healthdiagnostics.ChangeInProgress))
	if !strings.Contains(change.Installation.Correction.Found, "change-42 completed 2 of 5 steps") || change.Installation.Correction.SBXRCorrection != "Review Retry automatic rollback in System Changes." {
		t.Fatalf("Change in progress = %#v", change.Installation)
	}

	recovery := module.Check(t.Context(), installationSummary(healthdiagnostics.RecoveryRequired))
	if !strings.Contains(recovery.Installation.Correction.Found, string(healthdiagnostics.CurrentStateDrift)) || !strings.Contains(recovery.Installation.Correction.SBXRCorrection, "forward-repair Plan") {
		t.Fatalf("Recovery Required = %#v", recovery.Installation)
	}

	malformedFacts := systemchanges.New(installationAdapter{observation: systemchanges.Observation{Status: systemchanges.ChangeInProgress, CurrentChangeSet: "unsafe marker value", Lock: systemchanges.LockReleased}}).InstallationHealthInspection()
	malformed := module.Check(t.Context(), healthdiagnostics.InstallationSummaryFrom(malformedFacts))
	if malformed.Installation.Status != healthdiagnostics.RecoveryRequired || malformed.Installation.RecoveryCause() != healthdiagnostics.StateLineageUnprovable || strings.Contains(malformed.Installation.Correction.Evidence, "unsafe marker value") {
		t.Fatalf("malformed installation = %#v", malformed.Installation)
	}

	contradictory := []systemchanges.Observation{
		{Status: systemchanges.Managed, CurrentChangeSet: "change-42", LastChangeSet: "change-41", Lock: systemchanges.LockReleased},
		{Status: systemchanges.ChangeInProgress, CurrentChangeSet: "change-42", Checkpoint: systemchanges.PreparedCheckpoint, TotalSteps: 5, Lock: systemchanges.LockReleased, RollbackAvailable: true, ForwardRepairAvailable: true},
	}
	for _, observation := range contradictory {
		summary := healthdiagnostics.InstallationSummaryFrom(systemchanges.New(installationAdapter{observation: observation}).InstallationHealthInspection())
		if summary.Status != healthdiagnostics.RecoveryRequired || summary.RecoveryCause() != healthdiagnostics.StateLineageUnprovable {
			t.Fatalf("contradictory installation = %#v", summary)
		}
	}
}

func TestCheckFailsClosedOnMalformedContradictoryTimedOutOrUnexpectedResults(t *testing.T) {
	const secretMarker = "PRIVATE-MARKER-9F934B"
	module := healthdiagnostics.New(func() time.Time { return checkedAt })
	inspections := []healthdiagnostics.NamedInspection{
		{Module: healthdiagnostics.StateModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return finding(healthdiagnostics.StateModule, healthdiagnostics.Healthy), errors.New("raw " + secretMarker)
		}},
		{Module: healthdiagnostics.NetworkPolicyModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			value := finding(healthdiagnostics.NetworkPolicyModule, healthdiagnostics.Healthy)
			value.Code = "unstable code"
			return value, nil
		}},
		{Module: healthdiagnostics.SystemChangesModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			value := finding(healthdiagnostics.SystemChangesModule, healthdiagnostics.HealthStatus("Degraded"))
			return value, nil
		}},
		{Module: healthdiagnostics.CloudflareTunnelModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{}, context.DeadlineExceeded
		}},
		{Module: healthdiagnostics.CertificateLifecycleModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			panic("unexpected " + secretMarker)
		}},
		{Module: healthdiagnostics.ConnectionProfilesModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			value := finding(healthdiagnostics.ConnectionProfilesModule, healthdiagnostics.Failed)
			value.Code = "CONNECTION-PROFILES-PRIVATE-MARKER-9F934B"
			return value, nil
		}},
	}

	got := module.Check(t.Context(), installationSummary(healthdiagnostics.Managed), inspections...)
	if len(got.Modules) != len(inspections) {
		t.Fatalf("Check() returned %d Modules, want %d", len(got.Modules), len(inspections))
	}
	for _, result := range got.Modules {
		if result.Status != healthdiagnostics.Unknown || result.Code != "HEALTH-DIAGNOSTICS-CHECK-UNKNOWN" || result.Role != healthdiagnostics.Required || result.Gate != healthdiagnostics.GateStops || strings.Contains(result.Explanation+result.NextAction+result.Correction.Evidence, secretMarker) {
			t.Fatalf("unsafe malformed result = %#v", result)
		}
	}
}

func TestCheckClassifiesRequiredAndAdvisoryFactsWithoutOrchestrating(t *testing.T) {
	tests := []struct {
		role        healthdiagnostics.Role
		status      healthdiagnostics.HealthStatus
		disposition healthdiagnostics.GateDisposition
	}{
		{healthdiagnostics.Required, healthdiagnostics.Healthy, healthdiagnostics.GatePasses},
		{healthdiagnostics.Required, healthdiagnostics.NeedsAttention, healthdiagnostics.GateStops},
		{healthdiagnostics.Required, healthdiagnostics.Failed, healthdiagnostics.GateStops},
		{healthdiagnostics.Required, healthdiagnostics.Unknown, healthdiagnostics.GateStops},
		{healthdiagnostics.Advisory, healthdiagnostics.Healthy, healthdiagnostics.GatePasses},
		{healthdiagnostics.Advisory, healthdiagnostics.NeedsAttention, healthdiagnostics.GateRequiresPlanDisclosure},
		{healthdiagnostics.Advisory, healthdiagnostics.Failed, healthdiagnostics.GateStops},
		{healthdiagnostics.Advisory, healthdiagnostics.Unknown, healthdiagnostics.GateStops},
		{"", healthdiagnostics.Healthy, healthdiagnostics.NotAGate},
		{healthdiagnostics.Role("Optional"), healthdiagnostics.Healthy, healthdiagnostics.GateStops},
	}
	module := healthdiagnostics.New(func() time.Time { return checkedAt })
	for _, test := range tests {
		got := module.Check(t.Context(), installationSummary(healthdiagnostics.Managed), healthdiagnostics.NamedInspection{
			Module: healthdiagnostics.StateModule,
			Role:   test.role,
			Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
				return finding(healthdiagnostics.StateModule, test.status), nil
			},
		})
		if got.Modules[0].Gate != test.disposition {
			t.Errorf("%s %s gate = %q, want %q", test.role, test.status, got.Modules[0].Gate, test.disposition)
		}
	}
}

func TestCheckUsesFreshOwningModuleInspectionsAndNeverAdoptsTheirState(t *testing.T) {
	calls := 0
	module := healthdiagnostics.New(func() time.Time { return checkedAt })
	inspection := healthdiagnostics.NamedInspection{Module: healthdiagnostics.StateModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
		calls++
		return finding(healthdiagnostics.StateModule, healthdiagnostics.Healthy), nil
	}}

	first := module.Check(t.Context(), installationSummary(healthdiagnostics.Managed), inspection)
	second := module.Check(t.Context(), installationSummary(healthdiagnostics.Managed), inspection)
	if calls != 2 || !reflect.DeepEqual(first.Modules[0], second.Modules[0]) {
		t.Fatalf("fresh Checks made %d owning inspections; results differ = %t", calls, !reflect.DeepEqual(first.Modules[0], second.Modules[0]))
	}
}

func TestCheckReturnsOneUnknownResultForAContradictoryDuplicateInspection(t *testing.T) {
	module := healthdiagnostics.New(func() time.Time { return checkedAt })
	inspection := healthdiagnostics.NamedInspection{Module: healthdiagnostics.StateModule, Role: healthdiagnostics.Required, Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
		return finding(healthdiagnostics.StateModule, healthdiagnostics.Healthy), nil
	}}
	got := module.Check(t.Context(), installationSummary(healthdiagnostics.Managed), inspection, inspection)
	if len(got.Modules) != 1 || got.Modules[0].Status != healthdiagnostics.Unknown {
		t.Fatalf("duplicate inspection = %#v", got.Modules)
	}
}

func finding(module healthdiagnostics.Module, status healthdiagnostics.HealthStatus) healthdiagnostics.Finding {
	return healthdiagnostics.Finding{Status: status, Code: healthdiagnostics.NamedCheckCode(module, status)}
}

type installationAdapter struct{ observation systemchanges.Observation }

func (adapter installationAdapter) Observe() (systemchanges.Observation, error) {
	return adapter.observation, nil
}
func (installationAdapter) TryLock() (systemchanges.Lock, bool, error) { return nil, false, nil }

func installationSummary(status healthdiagnostics.InstallationStatus) healthdiagnostics.InstallationSummary {
	observation := systemchanges.Observation{Lock: systemchanges.LockReleased, Checkpoint: systemchanges.NoCheckpoint}
	switch status {
	case healthdiagnostics.NotInstalled:
		observation.Status = systemchanges.NotInstalled
	case healthdiagnostics.Managed:
		observation.Status, observation.LastChangeSet = systemchanges.Managed, "change-41"
	case healthdiagnostics.ChangeInProgress:
		observation.Status, observation.CurrentChangeSet, observation.Checkpoint = systemchanges.ChangeInProgress, "change-42", systemchanges.PreparedCheckpoint
		observation.CompletedSteps, observation.TotalSteps, observation.RollbackAvailable = 2, 5, true
	case healthdiagnostics.RecoveryRequired:
		observation.Status, observation.LastChangeSet, observation.RecoveryCause = systemchanges.RecoveryRequired, "change-41", systemchanges.CurrentStateDrift
		observation.ForwardRepairAvailable, observation.StateRevision, observation.StateSHA256 = true, 1, strings.Repeat("a", 64)
	}
	return healthdiagnostics.InstallationSummaryFrom(systemchanges.New(installationAdapter{observation: observation}).InstallationHealthInspection())
}
