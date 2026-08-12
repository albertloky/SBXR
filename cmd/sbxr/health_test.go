package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestReclamationDiagnosticsPersistentlyReportsHoldAndReturnedExecutableDrift(t *testing.T) {
	policy := state.ReclamationPolicy{Version: 1, Held: state.HeldPackagePolicy{Name: "vendor-proxy", Version: "4.5.6", DeletedExecutable: "/opt/vendor-proxy/proxy", SHA256: strings.Repeat("a", 64)}}
	run := func(context.Context, string, ...string) ([]byte, error) { return []byte("vendor-proxy\n"), nil }
	held := reclamationDiagnostics(t.Context(), policy, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, run)
	if len(held) != 1 || held[0].HoldStatus != "Held" || held[0].Code != "NETWORK-RECLAMATION-PACKAGE-HELD" || !held[0].NoRollback {
		t.Fatalf("held package advisory = %+v", held)
	}
	returned := reclamationDiagnostics(t.Context(), policy, func(string) (os.FileInfo, error) { return nil, nil }, run)
	if len(returned) != 1 || returned[0].HoldStatus != "Executable returned" || returned[0].Code != "NETWORK-RECLAMATION-EXECUTABLE-RETURNED" {
		t.Fatalf("returned executable drift = %+v", returned)
	}
	missing := reclamationDiagnostics(t.Context(), policy, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, func(context.Context, string, ...string) ([]byte, error) { return nil, nil })
	if len(missing) != 1 || missing[0].HoldStatus != "Hold missing" || missing[0].Code != "NETWORK-RECLAMATION-HOLD-MISSING" {
		t.Fatalf("missing hold drift = %+v", missing)
	}
}

type healthEventMemory struct {
	events []healthdiagnostics.DiagnosticEvent
}

type healthStateMemory []byte

func (memory healthStateMemory) Read() ([]byte, error) { return append([]byte(nil), memory...), nil }
func (healthStateMemory) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("unused")
}

type healthBundleMemory struct {
	names   []string
	archive []byte
}

func (memory *healthBundleMemory) Existing() ([]string, error) {
	return append([]string(nil), memory.names...), nil
}
func (memory *healthBundleMemory) Publish(candidate healthdiagnostics.BundleCandidate) error {
	memory.names = append(memory.names, candidate.Name())
	memory.archive = candidate.Archive()
	return nil
}

func TestProductionDiagnosticsPresentationUsesTheSameElevenModuleCheck(t *testing.T) {
	presentation, err := productionDiagnosticsPresentation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(presentation.Modules) != 11 || len(presentation.Services) != 10 {
		t.Fatalf("diagnostics counts = %d Modules, %d services", len(presentation.Modules), len(presentation.Services))
	}
	if presentation.Retention.EventDays != 30 || presentation.Retention.EventMiB != 50 || presentation.Retention.BundleLimit != 3 {
		t.Fatalf("diagnostics retention = %+v", presentation.Retention)
	}
	seen := map[string]bool{}
	for _, module := range presentation.Modules {
		if module.Code == "" || module.CheckedAt == "" || seen[module.Module] {
			t.Fatalf("diagnostics Module = %+v", module)
		}
		seen[module.Module] = true
	}
	if !seen[string(healthdiagnostics.StateModule)] || !seen[string(healthdiagnostics.OwnerConsoleModule)] {
		t.Fatalf("diagnostics Modules = %#v", seen)
	}
}

func TestExecutableBundleCompositionUsesOnlyOpaqueStateAndSafeCheckFacts(t *testing.T) {
	document, err := os.ReadFile("../../internal/state/testdata/complete-state.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Revision               uint64                  `json:"revision"`
		ReleaseIdentity        state.ReleaseIdentity   `json:"release_identity"`
		LastCompletedChangeSet state.ChangeSetIdentity `json:"last_completed_change_set"`
	}
	if json.Unmarshal(document, &envelope) != nil {
		t.Fatal("State fixture was not readable")
	}
	stateModule := state.New(healthStateMemory(document))
	loaded, err := stateModule.Load(state.LoadRequest{Baseline: state.ManagedEvidence, SupportedRelease: envelope.ReleaseIdentity, Lineage: &state.LineageProof{Revision: envelope.Revision, LastCompletedChangeSet: envelope.LastCompletedChangeSet, ReleaseIdentity: envelope.ReleaseIdentity}})
	if err != nil {
		t.Fatal(err)
	}
	module, installation, inspections := productionHealthInputs(t.Context())
	storage := &healthBundleMemory{}
	result := buildSupportBundle(module, storage, healthdiagnostics.BundleRequest{
		Check:    module.Check(t.Context(), installation, inspections...),
		Release:  healthdiagnostics.ReleaseFactsFrom(systemchanges.NewReleaseHealthInspection(stateModule.HealthReleaseInspection(loaded))),
		Platform: healthdiagnostics.PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []healthdiagnostics.UnitSummary{{Unit: "sbxr-health-check.timer", Status: healthdiagnostics.UnitActive}},
	})
	if result.Created == "" || len(storage.names) != 1 || !healthdiagnostics.ValidCompletedBundle(storage.archive) {
		t.Fatalf("support bundle result = %+v", result)
	}
	if bytes.Contains(storage.archive, []byte("SECRET-MARKER")) || bytes.Contains(storage.archive, []byte("CLOUDFLARE-MANAGEMENT")) {
		t.Fatal("support bundle exposed protected State values")
	}
}

func TestScheduledInspectionsUseOwningModuleManagedResults(t *testing.T) {
	statuses := map[healthdiagnostics.Module]healthdiagnostics.HealthStatus{
		healthdiagnostics.NetworkPolicyModule:           healthdiagnostics.Healthy,
		healthdiagnostics.CloudflareTunnelModule:        healthdiagnostics.NeedsAttention,
		healthdiagnostics.CertificateLifecycleModule:    healthdiagnostics.Failed,
		healthdiagnostics.ConnectionProfilesModule:      healthdiagnostics.Unknown,
		healthdiagnostics.SubscriptionPublicationModule: healthdiagnostics.Healthy,
		healthdiagnostics.SubscriptionServingModule:     healthdiagnostics.NeedsAttention,
		healthdiagnostics.SoftwareLifecycleModule:       healthdiagnostics.Failed,
		healthdiagnostics.OwnerConsoleModule:            healthdiagnostics.Healthy,
	}
	result := healthdiagnostics.New(nil).Check(t.Context(), healthdiagnostics.InstallationSummary{}, scheduledInspections(systemchanges.InstallationHealthFacts{Status: systemchanges.Managed}, statuses)...)
	for _, checked := range result.Modules {
		if want, ok := statuses[checked.Module]; ok && checked.Status != want {
			t.Fatalf("%s health = %s, want %s", checked.Module, checked.Status, want)
		}
	}
}

func (memory *healthEventMemory) Load() ([]healthdiagnostics.DiagnosticEvent, error) {
	return append([]healthdiagnostics.DiagnosticEvent(nil), memory.events...), nil
}

func (memory *healthEventMemory) Replace(events []healthdiagnostics.DiagnosticEvent) error {
	memory.events = append([]healthdiagnostics.DiagnosticEvent(nil), events...)
	return nil
}

func (*healthEventMemory) EncodedSize(events []healthdiagnostics.DiagnosticEvent) (int64, error) {
	return int64(len(events)), nil
}

func TestPrivateScheduledHealthCommandCallsScheduledCheck(t *testing.T) {
	memory := &healthEventMemory{}
	if err := runScheduledHealthCheck(t.Context(), healthdiagnostics.NewEventHistory(memory, nil)); err != nil {
		t.Fatal(err)
	}
	if len(memory.events) != 11 {
		t.Fatalf("scheduled health events = %d", len(memory.events))
	}
	seen := map[healthdiagnostics.Module]bool{}
	for _, event := range memory.events {
		record := event.Record()
		if record.OperationID != healthdiagnostics.CheckOperation || record.Code == "" || seen[record.Module] {
			t.Fatalf("scheduled health event = %#v", record)
		}
		seen[record.Module] = true
	}
	if !seen[healthdiagnostics.StateModule] || !seen[healthdiagnostics.SubscriptionServingModule] || !seen[healthdiagnostics.HealthDiagnosticsModule] || !seen[healthdiagnostics.SoftwareLifecycleModule] || !seen[healthdiagnostics.OwnerConsoleModule] {
		t.Fatalf("scheduled owning Modules = %#v", seen)
	}
	for _, event := range memory.events {
		if record := event.Record(); record.Module == healthdiagnostics.HealthDiagnosticsModule && record.Severity != healthdiagnostics.ErrorSeverity {
			t.Fatalf("unavailable self-check did not fail closed: %#v", record)
		}
		if record := event.Record(); runtime.GOOS != "linux" && (record.Module == healthdiagnostics.StateModule || record.Module == healthdiagnostics.SystemChangesModule) && !strings.HasSuffix(string(record.Code), "UNKNOWN") {
			t.Fatalf("unavailable owning inspection invented a failure: %#v", record)
		}
	}
}
