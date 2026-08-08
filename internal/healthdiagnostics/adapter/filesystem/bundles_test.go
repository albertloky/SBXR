package filesystem

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	stdunsafe "unsafe"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

func TestBundleStoragePublishesRootOnlyArchiveAndPreservesTransactionEvidence(t *testing.T) {
	root := t.TempDir()
	if err := newBundleStorage(root, os.Geteuid()).Publish(healthdiagnostics.BundleCandidate{}); err == nil {
		t.Fatal("filesystem Adapter accepted a caller-forged bundle candidate")
	}
	base := filepath.Join(root, "var/lib/sbxr")
	evidence := filepath.Join(base, "system-changes/active/journal-snapshot-rollback-proof")
	if err := os.MkdirAll(filepath.Dir(evidence), 0o700); err != nil || os.Chmod(base, 0o700) != nil || os.WriteFile(evidence, []byte("required transaction evidence"), 0o600) != nil {
		t.Fatal("prepare controlled root")
	}
	module, request := bundleFixture(t)
	result := module.BuildSupportBundle(newBundleStorage(root, os.Geteuid()), request)
	if result.Status() != healthdiagnostics.BundleCreated {
		t.Fatalf("BuildSupportBundle() = %q %q", result.Status(), result.Code())
	}

	diagnostics := filepath.Join(base, "diagnostics")
	bundles := filepath.Join(diagnostics, "bundles")
	staging := filepath.Join(diagnostics, "staging")
	archive := filepath.Join(bundles, result.ArchiveName())
	for name, mode := range map[string]os.FileMode{diagnostics: 0o700, bundles: 0o700, staging: 0o700, archive: 0o600} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s = mode %o, %v", name, info.Mode().Perm(), err)
		}
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging after publication = %#v, %v", entries, err)
	}
	existing, err := newBundleStorage(root, os.Geteuid()).Existing()
	if err != nil || len(existing) != 1 || existing[0] != result.ArchiveName() {
		t.Fatalf("Existing() = %#v, %v", existing, err)
	}
	if body, err := os.ReadFile(evidence); err != nil || string(body) != "required transaction evidence" {
		t.Fatalf("transaction evidence changed: %q, %v", body, err)
	}
}

func TestBuildSupportBundleRejectsHostileManagedStorageAndLeavesNoPartialOutput(t *testing.T) {
	tests := []struct {
		name      string
		uidOffset int
		plant     func(string) error
	}{
		{name: "symbolic link", plant: func(root string) error {
			return os.Symlink("/etc/passwd", filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz"))
		}},
		{name: "symbolic lock", plant: func(root string) error {
			return os.Symlink("bundles", filepath.Join(root, "var/lib/sbxr/diagnostics/.bundle.lock"))
		}},
		{name: "non regular entry", plant: func(root string) error {
			return os.Mkdir(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz"), 0o700)
		}},
		{name: "unexpected future file", plant: func(root string) error {
			return os.WriteFile(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/future-MARKER-72E2A4"), []byte("unknown"), 0o600)
		}},
		{name: "broad archive mode", plant: func(root string) error {
			return os.WriteFile(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz"), []byte("not an archive"), 0o640)
		}},
		{name: "broad bundle directory mode", plant: func(root string) error {
			return os.Chmod(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles"), 0o750)
		}},
		{name: "wrong owner", uidOffset: 1, plant: func(string) error { return nil }},
		{name: "short archive read", plant: func(root string) error {
			return os.WriteFile(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz"), []byte{0x1f, 0x8b}, 0o600)
		}},
		{name: "unknown gzip content", plant: func(root string) error {
			return os.WriteFile(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz"), hostileBundle(t, "unexpected.txt"), 0o600)
		}},
		{name: "traversal archive entry", plant: func(root string) error {
			return os.WriteFile(filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz"), hostileBundle(t, "../MARKER-8E4C21"), 0o600)
		}},
		{name: "unexpected staging entry", plant: func(root string) error {
			return os.WriteFile(filepath.Join(root, "var/lib/sbxr/diagnostics/staging/partial-MARKER-39E8B1"), []byte("partial"), 0o600)
		}},
		{name: "hard linked archive", plant: func(root string) error {
			first := filepath.Join(root, "var/lib/sbxr/diagnostics/bundles/sbxr-support-20260801T000000Z.tar.gz")
			if err := os.WriteFile(first, []byte("not an archive"), 0o600); err != nil {
				return err
			}
			return os.Link(first, first+".copy")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for _, directory := range []string{"var/lib/sbxr/diagnostics/bundles", "var/lib/sbxr/diagnostics/staging"} {
				if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(filepath.Join(root, "var/lib/sbxr"), 0o700); err != nil || test.plant(root) != nil {
				t.Fatal("plant hostile storage")
			}
			module, request := bundleFixture(t)
			result := module.BuildSupportBundle(newBundleStorage(root, os.Geteuid()+test.uidOffset), request)
			if result.Status() != healthdiagnostics.BundleNotCreated || result.ArchiveName() != "" {
				t.Fatalf("hostile storage result = %q %q", result.Status(), result.Code())
			}
			entries, err := os.ReadDir(filepath.Join(root, "var/lib/sbxr/diagnostics/staging"))
			if err != nil || len(entries) > 1 {
				t.Fatalf("partial staging = %#v, %v", entries, err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".stage") {
					t.Fatalf("partial staging directory remains: %s", entry.Name())
				}
			}
		})
	}
}

func TestBuildSupportBundleRejectsChangingFilesAndReadFailures(t *testing.T) {
	for _, failure := range []string{"changing file", "read failure"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "var/lib/sbxr")
			if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
				t.Fatal(err)
			}
			module, request := bundleFixtureAt(t, time.Date(2026, 8, 8, 15, 4, 5, 0, time.UTC))
			if created := module.BuildSupportBundle(newBundleStorage(root, os.Geteuid()), request); created.Status() != healthdiagnostics.BundleCreated {
				t.Fatalf("fixture bundle = %q %q", created.Status(), created.Code())
			}

			storage := newBundleStorage(root, os.Geteuid())
			if failure == "read failure" {
				storage.read = func(*os.Root, string) ([]byte, error) { return nil, errors.New("controlled read failure") }
			} else {
				storage.afterRead = func(name string) {
					path := filepath.Join(base, "diagnostics/bundles", name)
					when := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
					if err := os.Chtimes(path, when, when); err != nil {
						t.Error(err)
					}
				}
			}
			module, request = bundleFixtureAt(t, time.Date(2026, 8, 9, 15, 4, 5, 0, time.UTC))
			result := module.BuildSupportBundle(storage, request)
			if result.Status() != healthdiagnostics.BundleNotCreated || result.ArchiveName() != "" {
				t.Fatalf("hostile read = %q %q", result.Status(), result.Code())
			}
		})
	}
}

func TestBundleStorageKeepsThreeBundlesAndDeletesOnlyTheReviewedOne(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "var/lib/sbxr")
	if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
		t.Fatal(err)
	}
	storage := newBundleStorage(root, os.Geteuid())
	created := make([]string, 0, 3)
	for day := 1; day <= 3; day++ {
		module, request := bundleFixtureAt(t, time.Date(2026, 8, day, 15, 4, 5, 0, time.UTC))
		result := module.BuildSupportBundle(storage, request)
		if result.Status() != healthdiagnostics.BundleCreated {
			t.Fatalf("bundle %d = %q %q", day, result.Status(), result.Code())
		}
		created = append(created, result.ArchiveName())
	}

	module, request := bundleFixtureAt(t, time.Date(2026, 8, 4, 15, 4, 5, 0, time.UTC))
	blocked := module.BuildSupportBundle(storage, request)
	if blocked.Status() != healthdiagnostics.BundleNotCreated || len(blocked.ReplacementCandidates()) != 3 {
		t.Fatalf("fourth bundle without review = %q %#v", blocked.Code(), blocked.ReplacementCandidates())
	}
	externalCopy := filepath.Join(root, "owner-copy.tar.gz")
	body, err := os.ReadFile(filepath.Join(base, "diagnostics/bundles", created[1]))
	if err != nil || os.WriteFile(externalCopy, body, 0o600) != nil {
		t.Fatal("copy bundle outside SBXR")
	}
	request.Replacement = healthdiagnostics.ReviewBundleReplacement(created[1])
	replaced := module.BuildSupportBundle(storage, request)
	if replaced.Status() != healthdiagnostics.BundleCreated {
		t.Fatalf("reviewed replacement = %q %q", replaced.Status(), replaced.Code())
	}
	existing, err := storage.Existing()
	if err != nil || len(existing) != 3 || containsBundle(existing, created[1]) || !containsBundle(existing, replaced.ArchiveName()) {
		t.Fatalf("retained bundles = %#v, %v", existing, err)
	}
	if copied, err := os.ReadFile(externalCopy); err != nil || !bytes.Equal(copied, body) {
		t.Fatalf("external copy was managed: %d bytes, %v", len(copied), err)
	}
}

func TestBundleStorageRecoversEveryReplacementCrashPhase(t *testing.T) {
	for _, phase := range []string{"prepared", "reviewed", "published", "cleanup", "committing"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "var/lib/sbxr")
			if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
				t.Fatal(err)
			}
			storage := newBundleStorage(root, os.Geteuid())
			created := make([]string, 0, 3)
			for day := 1; day <= 3; day++ {
				module, request := bundleFixtureAt(t, time.Date(2026, 8, day, 15, 4, 5, 0, time.UTC))
				result := module.BuildSupportBundle(storage, request)
				if result.Status() != healthdiagnostics.BundleCreated {
					t.Fatalf("fixture bundle %d = %q %q", day, result.Status(), result.Code())
				}
				created = append(created, result.ArchiveName())
			}

			module, request := bundleFixtureAt(t, time.Date(2026, 8, 4, 15, 4, 5, 0, time.UTC))
			request.Replacement = healthdiagnostics.ReviewBundleReplacement(created[1])
			crashing := newBundleStorage(root, os.Geteuid())
			crashing.crashAt = phase
			if result := module.BuildSupportBundle(crashing, request); result.Status() != healthdiagnostics.BundleNotCreated {
				t.Fatalf("simulated crash = %q %q", result.Status(), result.Code())
			}

			existing, err := newBundleStorage(root, os.Geteuid()).Existing()
			if err != nil || len(existing) != 3 {
				t.Fatalf("recovered bundles = %#v, %v", existing, err)
			}
			newName := "sbxr-support-20260804T150405Z.tar.gz"
			if phase == "committing" {
				if containsBundle(existing, created[1]) || !containsBundle(existing, newName) {
					t.Fatalf("commit recovery = %#v", existing)
				}
			} else if !containsBundle(existing, created[1]) || containsBundle(existing, newName) {
				t.Fatalf("rollback recovery = %#v", existing)
			}
			staging, err := os.ReadDir(filepath.Join(base, "diagnostics/staging"))
			if err != nil || len(staging) != 0 {
				t.Fatalf("recovered staging = %#v, %v", staging, err)
			}
		})
	}
}

func TestBundleStorageRollsBackFinalDurabilityAndTransactionCleanupFailures(t *testing.T) {
	for _, failure := range []string{"final sync", "transaction removal", "rollback after durable phase"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "var/lib/sbxr")
			if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
				t.Fatal(err)
			}
			storage := newBundleStorage(root, os.Geteuid())
			created := make([]string, 0, 3)
			for day := 1; day <= 3; day++ {
				module, request := bundleFixtureAt(t, time.Date(2026, 8, day, 15, 4, 5, 0, time.UTC))
				result := module.BuildSupportBundle(storage, request)
				if result.Status() != healthdiagnostics.BundleCreated {
					t.Fatalf("fixture bundle %d = %q %q", day, result.Status(), result.Code())
				}
				created = append(created, result.ArchiveName())
			}
			module, request := bundleFixtureAt(t, time.Date(2026, 8, 4, 15, 4, 5, 0, time.UTC))
			request.Replacement = healthdiagnostics.ReviewBundleReplacement(created[1])
			failing := newBundleStorage(root, os.Geteuid())
			failing.failFinalSync = failure == "final sync" || failure == "rollback after durable phase"
			failing.failTransactionRemove = failure == "transaction removal"
			failing.failRollbackAfterPhase = failure == "rollback after durable phase"
			result := module.BuildSupportBundle(failing, request)
			if result.Status() != healthdiagnostics.BundleNotCreated || result.ArchiveName() != "" {
				t.Fatalf("late failure = %q %q", result.Status(), result.Code())
			}
			existing, err := storage.Existing()
			if err != nil || strings.Join(existing, ",") != strings.Join(created, ",") {
				t.Fatalf("rolled-back bundles = %#v, %v", existing, err)
			}
			staging, err := os.ReadDir(filepath.Join(base, "diagnostics/staging"))
			if err != nil || len(staging) != 0 {
				t.Fatalf("late-failure staging = %#v, %v", staging, err)
			}
		})
	}
}

func TestBundleStorageRecoversCrashDuringLateRollback(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "var/lib/sbxr")
	if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
		t.Fatal(err)
	}
	storage := newBundleStorage(root, os.Geteuid())
	created := make([]string, 0, 3)
	for day := 1; day <= 3; day++ {
		module, request := bundleFixtureAt(t, time.Date(2026, 8, day, 15, 4, 5, 0, time.UTC))
		result := module.BuildSupportBundle(storage, request)
		if result.Status() != healthdiagnostics.BundleCreated {
			t.Fatalf("fixture bundle %d = %q %q", day, result.Status(), result.Code())
		}
		created = append(created, result.ArchiveName())
	}
	module, request := bundleFixtureAt(t, time.Date(2026, 8, 4, 15, 4, 5, 0, time.UTC))
	request.Replacement = healthdiagnostics.ReviewBundleReplacement(created[1])
	crashing := newBundleStorage(root, os.Geteuid())
	crashing.failFinalSync, crashing.crashAt = true, "rolling-back"
	if result := module.BuildSupportBundle(crashing, request); result.Status() != healthdiagnostics.BundleNotCreated {
		t.Fatalf("late rollback crash = %q %q", result.Status(), result.Code())
	}
	existing, err := storage.Existing()
	if err != nil || strings.Join(existing, ",") != strings.Join(created, ",") {
		t.Fatalf("late rollback recovery = %#v, %v", existing, err)
	}
	staging, err := os.ReadDir(filepath.Join(base, "diagnostics/staging"))
	if err != nil || len(staging) != 0 {
		t.Fatalf("late rollback staging = %#v, %v", staging, err)
	}
}

func TestBundleStorageRejectsRollbackMaterialAndCommitPhaseFailures(t *testing.T) {
	for _, failure := range []string{"stage", "write", "sync", "commit phase"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "var/lib/sbxr")
			if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
				t.Fatal(err)
			}
			storage := newBundleStorage(root, os.Geteuid())
			created := make([]string, 0, 3)
			for day := 1; day <= 3; day++ {
				module, request := bundleFixtureAt(t, time.Date(2026, 8, day, 15, 4, 5, 0, time.UTC))
				result := module.BuildSupportBundle(storage, request)
				if result.Status() != healthdiagnostics.BundleCreated {
					t.Fatalf("fixture bundle %d = %q %q", day, result.Status(), result.Code())
				}
				created = append(created, result.ArchiveName())
			}
			module, request := bundleFixtureAt(t, time.Date(2026, 8, 4, 15, 4, 5, 0, time.UTC))
			request.Replacement = healthdiagnostics.ReviewBundleReplacement(created[1])
			failing := newBundleStorage(root, os.Geteuid())
			failing.failRollbackStage = failure == "stage"
			failing.failRollbackWrite = failure == "write"
			failing.failRollbackSync = failure == "sync"
			failing.failCommitPhase = failure == "commit phase"
			result := module.BuildSupportBundle(failing, request)
			if result.Status() != healthdiagnostics.BundleNotCreated || result.ArchiveName() != "" {
				t.Fatalf("pre-commit failure = %q %q", result.Status(), result.Code())
			}
			existing, err := storage.Existing()
			if err != nil || strings.Join(existing, ",") != strings.Join(created, ",") {
				t.Fatalf("pre-commit rollback = %#v, %v", existing, err)
			}
			staging, err := os.ReadDir(filepath.Join(base, "diagnostics/staging"))
			if err != nil || len(staging) != 0 {
				t.Fatalf("pre-commit staging = %#v, %v", staging, err)
			}
		})
	}
}

func TestBundleStorageSerializesConcurrentPublication(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "var/lib/sbxr")
	if err := os.MkdirAll(base, 0o700); err != nil || os.Chmod(base, 0o700) != nil {
		t.Fatal(err)
	}
	storage := newBundleStorage(root, os.Geteuid())
	for day := 1; day <= 2; day++ {
		module, request := bundleFixtureAt(t, time.Date(2026, 8, day, 15, 4, 5, 0, time.UTC))
		if result := module.BuildSupportBundle(storage, request); result.Status() != healthdiagnostics.BundleCreated {
			t.Fatalf("fixture bundle %d = %q %q", day, result.Status(), result.Code())
		}
	}
	type attempt struct {
		module  healthdiagnostics.Interface
		request healthdiagnostics.BundleRequest
	}
	attempts := make([]attempt, 2)
	for index := range attempts {
		attempts[index].module, attempts[index].request = bundleFixtureAt(t, time.Date(2026, 8, 3+index, 15, 4, 5, 0, time.UTC))
	}
	results := make([]healthdiagnostics.BundleStatus, 2)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index] = attempts[index].module.BuildSupportBundle(newBundleStorage(root, os.Geteuid()), attempts[index].request).Status()
		}(index)
	}
	wait.Wait()
	created := 0
	for _, status := range results {
		if status == healthdiagnostics.BundleCreated {
			created++
		}
	}
	existing, err := storage.Existing()
	if created != 1 || err != nil || len(existing) != 3 {
		t.Fatalf("concurrent publication = statuses %#v bundles %#v, %v", results, existing, err)
	}
}

func bundleFixture(t *testing.T) (healthdiagnostics.Interface, healthdiagnostics.BundleRequest) {
	t.Helper()
	return bundleFixtureAt(t, time.Date(2026, 8, 9, 15, 4, 5, 0, time.UTC))
}

func bundleFixtureAt(t *testing.T, now time.Time) (healthdiagnostics.Interface, healthdiagnostics.BundleRequest) {
	t.Helper()
	module := healthdiagnostics.New(func() time.Time { return now })
	check := module.Check(t.Context(), healthdiagnostics.InstallationSummary{}, healthdiagnostics.NamedInspection{
		Module: healthdiagnostics.HealthDiagnosticsModule, Role: healthdiagnostics.Required,
		Inspect: func(context.Context) (healthdiagnostics.Finding, error) {
			return healthdiagnostics.Finding{Status: healthdiagnostics.Healthy, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.HealthDiagnosticsModule, healthdiagnostics.Healthy)}, nil
		},
	})
	return module, healthdiagnostics.BundleRequest{
		Check: check, Events: check.DiagnosticEvents(),
		Release:  bundleReleaseFacts(),
		Platform: healthdiagnostics.PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []healthdiagnostics.UnitSummary{{Unit: "sbxr-health-check.timer", Status: healthdiagnostics.UnitActive}},
	}
}

func bundleReleaseFacts() healthdiagnostics.ReleaseFacts {
	// ReleaseFacts is intentionally opaque outside its owning proof path. This
	// test-only layout keeps the filesystem integration test off the product API.
	value := struct {
		Repository, Tag, Commit, ReleaseIndexSHA256 string
		Verified                                    bool
	}{"github.com/albertloky/SBXR", "v1.0.0", strings.Repeat("a", 40), strings.Repeat("b", 64), true}
	return *(*healthdiagnostics.ReleaseFacts)(stdunsafe.Pointer(&value))
}

func hostileBundle(t *testing.T, name string) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	body := []byte("safe-looking content")
	if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil || archive.Close() != nil || compressed.Close() != nil {
		t.Fatal("build hostile archive")
	}
	return output.Bytes()
}

func containsBundle(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
