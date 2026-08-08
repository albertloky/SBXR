package main

import (
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

type healthEventMemory struct {
	events []healthdiagnostics.DiagnosticEvent
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
		if record := event.Record(); (record.Module == healthdiagnostics.StateModule || record.Module == healthdiagnostics.SystemChangesModule) && !strings.HasSuffix(string(record.Code), "UNKNOWN") {
			t.Fatalf("unavailable owning inspection invented a failure: %#v", record)
		}
	}
}
