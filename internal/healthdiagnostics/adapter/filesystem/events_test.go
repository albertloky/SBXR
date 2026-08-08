package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

func TestEventStorageIsRootOnlySurvivesRebootAndCannotTouchTransactionEvidence(t *testing.T) {
	const marker = "LIVE-TRAFFIC-MARKER-8802E1"
	root := t.TempDir()
	base := filepath.Join(root, "var/lib/sbxr")
	transaction := filepath.Join(base, "system-changes/active/journal-and-rollback-snapshot")
	if err := os.MkdirAll(filepath.Dir(transaction), 0o700); err != nil || os.Chmod(base, 0o700) != nil || os.WriteFile(transaction, []byte("required transaction evidence"), 0o600) != nil {
		t.Fatal("prepare controlled storage")
	}
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	storage := newEventStorage(root, os.Geteuid())
	history := healthdiagnostics.NewEventHistory(storage, func() time.Time { return now })
	check := healthdiagnostics.New(func() time.Time { return now })
	result := check.Check(t.Context(), healthdiagnostics.InstallationSummary{}, healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.SubscriptionServingModule, Role: healthdiagnostics.Required,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{Status: healthdiagnostics.Healthy, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.SubscriptionServingModule, healthdiagnostics.Healthy)}, nil
		},
	})
	if err := history.RecordCheck(result); err != nil {
		t.Fatal(err)
	}

	directory := filepath.Join(base, "diagnostics")
	eventFile := filepath.Join(directory, "events.json")
	directoryInfo, directoryErr := os.Stat(directory)
	fileInfo, fileErr := os.Stat(eventFile)
	data, readErr := os.ReadFile(eventFile)
	if directoryErr != nil || fileErr != nil || readErr != nil || directoryInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600 || strings.Contains(string(data), marker) {
		t.Fatalf("unsafe event storage: directory=%v file=%v read=%v modes=%o/%o body=%q", directoryErr, fileErr, readErr, directoryInfo.Mode().Perm(), fileInfo.Mode().Perm(), data)
	}

	restarted := healthdiagnostics.NewEventHistory(newEventStorage(root, os.Geteuid()), func() time.Time { return now.Add(time.Hour) })
	if events, err := restarted.Events(); err != nil || len(events) != 1 {
		t.Fatalf("reboot Events() = %#v, %v", events, err)
	}
	if evidence, err := os.ReadFile(transaction); err != nil || string(evidence) != "required transaction evidence" {
		t.Fatalf("transaction evidence changed: %q, %v", evidence, err)
	}
}

func TestEventStorageRejectsUnsafeOrMarkerBearingHistoryWithoutReplacingIt(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "var/lib/sbxr")
	if err := os.MkdirAll(filepath.Join(base, "diagnostics"), 0o700); err != nil || os.Chmod(base, 0o700) != nil {
		t.Fatal(err)
	}
	eventFile := filepath.Join(base, "diagnostics/events.json")
	body := `[{"time":"2026-08-09T12:00:00Z","module":"State","operation_id":"Check","severity":"Info","code":"STATE-HEALTHY","explanation":"UNIQUE-PRIVATE-KEY-MARKER-926B42"}]`
	if err := os.WriteFile(eventFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	history := healthdiagnostics.NewEventHistory(newEventStorage(root, os.Geteuid()), func() time.Time {
		return time.Date(2026, 8, 9, 13, 0, 0, 0, time.UTC)
	})
	if _, err := history.Events(); err == nil {
		t.Fatal("marker-bearing history was accepted")
	}
	data, err := os.ReadFile(eventFile)
	if err != nil || string(data) != body {
		t.Fatalf("invalid history was replaced: %q, %v", data, err)
	}

	if err := os.Chmod(eventFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := history.Events(); err == nil {
		t.Fatal("broad event mode was accepted")
	}
}
