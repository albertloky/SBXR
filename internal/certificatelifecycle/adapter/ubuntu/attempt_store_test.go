package ubuntu

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

func TestRenewalAttemptStoreSurvivesSeparateSchedulerProcesses(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/sbxr"), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	first := newRenewalAttemptStore(root, os.Geteuid())
	if err := first.StoreAttempt(certificatelifecycle.IPLineage, now, certificatelifecycle.RenewalFailed); err != nil {
		t.Fatal(err)
	}
	if err := first.StoreAttempt(certificatelifecycle.DomainLineage, now.Add(time.Minute), certificatelifecycle.RenewalBusy); err != nil {
		t.Fatal(err)
	}
	second := newRenewalAttemptStore(root, os.Geteuid())
	at, outcome, found, err := second.LoadAttempt(certificatelifecycle.IPLineage)
	if err != nil || !found || !at.Equal(now) || outcome != certificatelifecycle.RenewalFailed {
		t.Fatalf("reloaded attempt = (%s, %q, %t, %v)", at, outcome, found, err)
	}
	domainAt, domainOutcome, domainFound, err := second.LoadAttempt(certificatelifecycle.DomainLineage)
	if err != nil || !domainFound || !domainAt.Equal(now.Add(time.Minute)) || domainOutcome != certificatelifecycle.RenewalBusy {
		t.Fatalf("reloaded domain attempt = (%s, %q, %t, %v)", domainAt, domainOutcome, domainFound, err)
	}
	path := filepath.Join(root, "var/lib/sbxr/certificate-renewal/ip-attempt.json")
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("attempt file = (%+v, %v)", info, err)
	}
	if err := second.ClearAttempt(certificatelifecycle.IPLineage); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := newRenewalAttemptStore(root, os.Geteuid()).LoadAttempt(certificatelifecycle.IPLineage); err != nil || found {
		t.Fatalf("cleared attempt = (%t, %v)", found, err)
	}
	if _, _, found, err := newRenewalAttemptStore(root, os.Geteuid()).LoadAttempt(certificatelifecycle.DomainLineage); err != nil || !found {
		t.Fatalf("IP cleanup changed domain attempt = (%t, %v)", found, err)
	}
}

func TestRenewalAttemptStoreRejectsUnsafeOrMalformedHistory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "var/lib/sbxr/certificate-renewal")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ip-attempt.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"time":"not-time","outcome":"failed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newRenewalAttemptStore(root, os.Geteuid())
	if _, _, _, err := store.LoadAttempt(certificatelifecycle.IPLineage); err == nil {
		t.Fatal("malformed attempt history was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.LoadAttempt(certificatelifecycle.IPLineage); err == nil {
		t.Fatal("symlink attempt history was accepted")
	}
}
