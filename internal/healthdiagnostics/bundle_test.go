package healthdiagnostics

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type bundleMemory struct {
	existing          []string
	name, replacement string
	archive           []byte
	err               error
}

func (memory *bundleMemory) Existing() ([]string, error) {
	return append([]string(nil), memory.existing...), memory.err
}

func (memory *bundleMemory) Publish(candidate BundleCandidate) error {
	if memory.err != nil {
		return memory.err
	}
	memory.name, memory.replacement = candidate.Name(), candidate.Replacement()
	memory.archive = candidate.Archive()
	return nil
}

func TestBuildSupportBundlePublishesOnlyAllowlistedTypedFacts(t *testing.T) {
	const forbidden = "CLIENT-ACCESS-VALUE-MARKER-91DA04"
	now := time.Date(2026, 8, 9, 15, 4, 5, 0, time.UTC)
	module := New(func() time.Time { return now })
	check := module.Check(t.Context(), InstallationSummary{}, NamedInspection{
		Module: SubscriptionServingModule, Role: Required,
		Inspect: func(context.Context) (Finding, error) {
			return Finding{}, errors.New("raw " + forbidden)
		},
	})
	storage := &bundleMemory{}
	result := module.BuildSupportBundle(storage, BundleRequest{
		Check: check, Events: check.DiagnosticEvents(),
		Release:  testReleaseFacts(),
		Platform: PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []UnitSummary{{Unit: "sbxr-subscription.service", Status: UnitActive}},
	})
	if result.Status() != BundleCreated || result.Code() != "HEALTH-DIAGNOSTICS-BUNDLE-CREATED" || result.ArchiveName() != "sbxr-support-20260809T150405Z.tar.gz" || result.ExternalCopyWarning() == "" {
		t.Fatalf("BuildSupportBundle() = status %q code %q archive %q warning %q", result.Status(), result.Code(), result.ArchiveName(), result.ExternalCopyWarning())
	}
	if storage.name != result.ArchiveName() || storage.replacement != "" || len(storage.archive) == 0 || len(storage.archive) > BundleArchiveBytes {
		t.Fatalf("published bundle = name %q replacement %q bytes %d", storage.name, storage.replacement, len(storage.archive))
	}

	items := readBundle(t, storage.archive)
	if len(items) != 3 || items["manifest.json"] == nil || items["report.txt"] == nil || items["facts.json"] == nil {
		t.Fatalf("bundle items = %#v", items)
	}
	var facts map[string]json.RawMessage
	if err := json.Unmarshal(items["facts.json"], &facts); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{"schema", "created_at", "installation_status", "findings", "events", "release", "platform", "units", "external_copy_warning"}
	if len(facts) != len(wantFields) {
		t.Fatalf("facts fields = %#v", facts)
	}
	for _, field := range wantFields {
		if facts[field] == nil {
			t.Fatalf("facts missing %q", field)
		}
	}
	for name, body := range items {
		if strings.Contains(string(body), forbidden) || len(body) > BundleItemBytes {
			t.Fatalf("unsafe item %q (%d bytes)", name, len(body))
		}
	}
}

func TestBuildSupportBundleFailsClosedOnHostileInputsBoundsAndPublication(t *testing.T) {
	now := time.Date(2026, 8, 9, 15, 4, 5, 0, time.UTC)
	module := New(func() time.Time { return now })
	check := module.Check(t.Context(), InstallationSummary{}, NamedInspection{
		Module: StateModule, Role: Required,
		Inspect: func(context.Context) (Finding, error) {
			return Finding{Status: Healthy, Code: NamedCheckCode(StateModule, Healthy)}, nil
		},
	})
	valid := BundleRequest{
		Check: check, Events: check.DiagnosticEvents(),
		Release:  testReleaseFacts(),
		Platform: PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []UnitSummary{{Unit: "xray.service", Status: UnitActive}},
	}
	tests := []struct {
		name    string
		request BundleRequest
		storage *bundleMemory
	}{
		{name: "caller-forged Check result", request: func() BundleRequest {
			value := valid
			value.Check = CheckResult{Modules: []ModuleResult{{Explanation: "INFRASTRUCTURE-SECRET-MARKER-50D1F0"}}}
			return value
		}(), storage: &bundleMemory{}},
		{name: "complete URL in release facts", request: func() BundleRequest {
			value := valid
			value.Release.tag = "https://MARKER-2B0C91"
			return value
		}(), storage: &bundleMemory{}},
		{name: "caller-authored hex release secret", request: func() BundleRequest {
			value := valid
			value.Release = ReleaseFacts{repository: "github.com/albertloky/SBXR", tag: "v1.0.0", commit: hex.EncodeToString([]byte("SECRET-MARKER-123456")), releaseIndexSHA256: strings.Repeat("b", 64)}
			return value
		}(), storage: &bundleMemory{}},
		{name: "unknown future unit", request: func() BundleRequest {
			value := valid
			value.Units = []UnitSummary{{Unit: "../../MARKER-CE1910.service", Status: UnitActive}}
			return value
		}(), storage: &bundleMemory{}},
		{name: "unreviewed existing storage", request: valid, storage: &bundleMemory{existing: []string{"unexpected-MARKER-09B4A1"}}},
		{name: "publication failure", request: valid, storage: &bundleMemory{err: errors.New("short write MARKER-F104DC")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := module.BuildSupportBundle(test.storage, test.request)
			if result.Status() != BundleNotCreated || result.Code() == "" || len(test.storage.archive) != 0 || result.ArchiveName() != "" {
				t.Fatalf("failure = status %q code %q archive %q published %d bytes", result.Status(), result.Code(), result.ArchiveName(), len(test.storage.archive))
			}
		})
	}

	oversized := valid
	oversized.Events = make([]DiagnosticEvent, 0, 4096)
	for len(oversized.Events) < cap(oversized.Events) {
		oversized.Events = append(oversized.Events, check.DiagnosticEvents()[0])
	}
	storage := &bundleMemory{}
	result := module.BuildSupportBundle(storage, oversized)
	if result.Status() != BundleNotCreated || result.Code() != "HEALTH-DIAGNOSTICS-BUNDLE-SIZE" || len(storage.archive) != 0 {
		t.Fatalf("oversized bundle = status %q code %q bytes %d", result.Status(), result.Code(), len(storage.archive))
	}
}

func TestBuildSupportBundleRequiresReviewedDeletionBeforeFourthBundle(t *testing.T) {
	now := time.Date(2026, 8, 9, 15, 4, 5, 0, time.UTC)
	module := New(func() time.Time { return now })
	check := module.Check(t.Context(), InstallationSummary{}, NamedInspection{
		Module: HealthDiagnosticsModule, Role: Required,
		Inspect: func(context.Context) (Finding, error) {
			return Finding{Status: Healthy, Code: NamedCheckCode(HealthDiagnosticsModule, Healthy)}, nil
		},
	})
	existing := []string{"sbxr-support-20260801T000000Z.tar.gz", "sbxr-support-20260802T000000Z.tar.gz", "sbxr-support-20260803T000000Z.tar.gz"}
	request := BundleRequest{
		Check: check, Events: check.DiagnosticEvents(),
		Release:  testReleaseFacts(),
		Platform: PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []UnitSummary{{Unit: "sbxr-health-check.timer", Status: UnitActive}},
	}
	storage := &bundleMemory{existing: existing}
	blocked := module.BuildSupportBundle(storage, request)
	if blocked.Status() != BundleNotCreated || blocked.Code() != "HEALTH-DIAGNOSTICS-BUNDLE-REPLACEMENT-REVIEW-REQUIRED" || strings.Join(blocked.ReplacementCandidates(), ",") != strings.Join(existing, ",") || len(storage.archive) != 0 {
		t.Fatalf("unreviewed replacement = status %q code %q candidates %#v", blocked.Status(), blocked.Code(), blocked.ReplacementCandidates())
	}

	request.Replacement = ReviewBundleReplacement(existing[1])
	created := module.BuildSupportBundle(storage, request)
	if created.Status() != BundleCreated || storage.replacement != existing[1] || len(storage.archive) == 0 {
		t.Fatalf("reviewed replacement = status %q replacement %q bytes %d", created.Status(), storage.replacement, len(storage.archive))
	}
}

func readBundle(t *testing.T, archive []byte) map[string][]byte {
	t.Helper()
	compressed, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	items := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if header.Mode != 0o600 || header.Typeflag != tar.TypeReg {
			t.Fatalf("unsafe archive header = %#v", header)
		}
		items[header.Name] = body
	}
	return items
}

func testReleaseFacts() ReleaseFacts {
	return ReleaseFacts{repository: "github.com/albertloky/SBXR", tag: "v1.0.0", commit: strings.Repeat("a", 40), releaseIndexSHA256: strings.Repeat("b", 64), verified: true}
}
