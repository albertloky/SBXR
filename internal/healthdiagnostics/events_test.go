package healthdiagnostics_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

type eventMemory struct {
	events        []healthdiagnostics.DiagnosticEvent
	bytesPerEvent int64
	loadErr       error
}

func (memory *eventMemory) Load() ([]healthdiagnostics.DiagnosticEvent, error) {
	return append([]healthdiagnostics.DiagnosticEvent(nil), memory.events...), memory.loadErr
}

func (memory *eventMemory) Replace(events []healthdiagnostics.DiagnosticEvent) error {
	memory.events = append([]healthdiagnostics.DiagnosticEvent(nil), events...)
	return nil
}

func (memory *eventMemory) EncodedSize(events []healthdiagnostics.DiagnosticEvent) (int64, error) {
	return int64(len(events)) * memory.bytesPerEvent, nil
}

func TestEventHistoryRetainsOnlyAllowlistedCheckFacts(t *testing.T) {
	markers := []string{
		"CLIENT-ACCESS-VALUE-6F68D8", "INFRASTRUCTURE-SECRET-1A54F0", "AUTHORIZATION-VALUE-DF0931",
		"COMPLETE-URL-1A8F2C", "PRIVATE-KEY-0E921B", "ACME-MATERIAL-E31C64", "CLOUDFLARE-TOKEN-40AC21",
		"RAW-CONFIGURATION-A9F147", "RAW-OUTPUT-CC2801", "JOURNAL-CONTENT-4A91E3", "SNAPSHOT-CONTENT-817BC0",
		"SECRET-DERIVED-HASH-2F3A91", "ENVIRONMENT-VALUE-6D4E73", "COMMAND-ARGUMENT-7BB301",
		"CLIENT-ADDRESS-B61ED0", "DESTINATION-2B43A8", "ACCESS-LOG-88DE10", "TRAFFIC-EVENT-EB719C",
		"LIVE-COUNTER-C47F20", "TELEMETRY-949CE1", "UPLOAD-625B7A", "THIRD-PARTY-CREDENTIAL-C8D104",
		"PACKET-CAPTURE-D13687", "CRASH-REPORT-5B823A", "CORE-DUMP-30AE74",
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	check := healthdiagnostics.New(func() time.Time { return now })
	result := check.Check(t.Context(), healthdiagnostics.InstallationSummary{}, healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.SubscriptionServingModule,
		Role:   healthdiagnostics.Required,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{}, errors.New(strings.Join(markers, " "))
		},
	})
	memory := &eventMemory{bytesPerEvent: 1}
	history := healthdiagnostics.NewEventHistory(memory, func() time.Time { return now })
	if err := history.RecordCheck(result); err != nil {
		t.Fatal(err)
	}
	events, err := history.Events()
	if err != nil || len(events) != 1 {
		t.Fatalf("Events() = %#v, %v", events, err)
	}
	record := events[0].Record()
	want := healthdiagnostics.EventRecord{
		Time: now, Module: healthdiagnostics.SubscriptionServingModule, OperationID: healthdiagnostics.CheckOperation,
		Severity: healthdiagnostics.ErrorSeverity, Code: "HEALTH-DIAGNOSTICS-CHECK-UNKNOWN",
		Explanation: "A safe conclusion about The authenticated IP HTTPS subscription service could not be established.",
	}
	rendered := strings.Join([]string{string(record.Module), string(record.OperationID), string(record.ChangeSetID), string(record.Severity), string(record.Code), record.Explanation, string(record.Outcome)}, " ")
	for _, marker := range markers {
		if strings.Contains(rendered, marker) {
			t.Fatalf("retained forbidden marker %q in %#v", marker, record)
		}
	}
	if !reflect.DeepEqual(record, want) {
		t.Fatalf("retained event = %#v", record)
	}

	if err := history.RecordCheck(healthdiagnostics.CheckResult{Modules: []healthdiagnostics.ModuleResult{{Explanation: markers[0]}}}); err != nil {
		t.Fatal(err)
	}
	events, _ = history.Events()
	if len(events) != 1 {
		t.Fatalf("caller-forged CheckResult retained %d events", len(events))
	}

	for _, unsafe := range []healthdiagnostics.EventRecord{
		{Time: now, Module: healthdiagnostics.StateModule, OperationID: healthdiagnostics.CheckOperation, ChangeSetID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Severity: healthdiagnostics.InfoSeverity, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.StateModule, healthdiagnostics.Healthy), Explanation: "Desired State lineage proved its required external behavior."},
		{Time: now, Module: healthdiagnostics.StateModule, OperationID: healthdiagnostics.CheckOperation, Severity: healthdiagnostics.InfoSeverity, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.StateModule, healthdiagnostics.Healthy), Explanation: "Desired State lineage proved its required external behavior.", Outcome: "AUTHORIZATIONVALUE9B6201"},
	} {
		if _, err := healthdiagnostics.RestoreDiagnosticEvent(unsafe); err == nil {
			t.Fatalf("unsafe persisted event was accepted: %#v", unsafe)
		}
	}
}

func TestEventHistoryAppliesExactAgeAndSizeLimitsOldestFirst(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	current := now.Add(-healthdiagnostics.EventRetentionPeriod - time.Nanosecond)
	memory := &eventMemory{bytesPerEvent: 20 << 20}
	history := healthdiagnostics.NewEventHistory(memory, func() time.Time { return now })

	for _, at := range []time.Time{
		current,
		now.Add(-healthdiagnostics.EventRetentionPeriod),
		now.Add(-20 * 24 * time.Hour),
		now.Add(-10 * 24 * time.Hour),
	} {
		current = at
		check := healthdiagnostics.New(func() time.Time { return current })
		result := check.Check(t.Context(), healthdiagnostics.InstallationSummary{}, healthdiagnostics.NamedInspection{
			Module: healthdiagnostics.StateModule, Role: healthdiagnostics.Required,
			Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
				return healthdiagnostics.Finding{Status: healthdiagnostics.Healthy, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.StateModule, healthdiagnostics.Healthy)}, nil
			},
		})
		if err := history.RecordCheck(result); err != nil {
			t.Fatal(err)
		}
	}

	events, err := history.Events()
	if err != nil || len(events) != 2 {
		t.Fatalf("Events() = %d, %v; want two events under 50 MiB", len(events), err)
	}
	if events[0].Record().Time != now.Add(-20*24*time.Hour) || events[1].Record().Time != now.Add(-10*24*time.Hour) {
		t.Fatalf("rotation kept wrong events: %#v", events)
	}
	if size, _ := memory.EncodedSize(events); size > healthdiagnostics.EventRetentionBytes {
		t.Fatalf("retained size = %d", size)
	}
}

func TestEventHistorySurvivesReconstructionAndFailsClosedOnStorageErrors(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	memory := &eventMemory{bytesPerEvent: 1}
	check := healthdiagnostics.New(func() time.Time { return now })
	result := check.Check(t.Context(), healthdiagnostics.InstallationSummary{}, healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.HealthDiagnosticsModule, Role: healthdiagnostics.Required,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{Status: healthdiagnostics.Healthy, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.HealthDiagnosticsModule, healthdiagnostics.Healthy)}, nil
		},
	})
	if err := healthdiagnostics.NewEventHistory(memory, func() time.Time { return now }).RecordCheck(result); err != nil {
		t.Fatal(err)
	}
	restarted := healthdiagnostics.NewEventHistory(memory, func() time.Time { return now.Add(time.Hour) })
	if events, err := restarted.Events(); err != nil || len(events) != 1 {
		t.Fatalf("reconstructed Events() = %#v, %v", events, err)
	}

	memory.loadErr = errors.New("raw storage marker")
	if err := restarted.RecordCheck(result); err == nil || len(memory.events) != 1 {
		t.Fatalf("storage failure = %v; retained events = %d", err, len(memory.events))
	}
}

func TestScheduledCheckUsesTheSameCheckInterfaceAndClassification(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	module := healthdiagnostics.New(func() time.Time { return now })
	inspection := healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.NetworkPolicyModule, Role: healthdiagnostics.Advisory,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{Status: healthdiagnostics.NeedsAttention, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.NetworkPolicyModule, healthdiagnostics.NeedsAttention)}, nil
		},
	}
	want := module.Check(t.Context(), healthdiagnostics.InstallationSummary{}, inspection)
	memory := &eventMemory{bytesPerEvent: 1}
	got, err := module.ScheduledCheck(t.Context(), healthdiagnostics.NewEventHistory(memory, func() time.Time { return now }), healthdiagnostics.InstallationSummary{}, inspection)
	if err != nil || !reflect.DeepEqual(got.Modules, want.Modules) || len(memory.events) != 1 || memory.events[0].Record().Code != want.Modules[0].Code {
		t.Fatalf("ScheduledCheck() = %#v, %v; events=%#v", got, err, memory.events)
	}
}
