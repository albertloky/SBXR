package healthdiagnostics

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type failingBundleStorage struct{ published bool }

func (*failingBundleStorage) Existing() ([]string, error) { return nil, nil }
func (storage *failingBundleStorage) Publish(BundleCandidate) error {
	storage.published = true
	return nil
}

func TestBuildSupportBundleFailsClosedOnCompressionAndIndependentBounds(t *testing.T) {
	now := time.Date(2026, 8, 9, 15, 4, 5, 0, time.UTC)
	module := New(func() time.Time { return now })
	check := module.Check(t.Context(), InstallationSummary{}, NamedInspection{
		Module: HealthDiagnosticsModule, Role: Required,
		Inspect: func(context.Context) (Finding, error) {
			return Finding{Status: Healthy, Code: NamedCheckCode(HealthDiagnosticsModule, Healthy)}, nil
		},
	})
	request := BundleRequest{
		Check: check, Events: check.DiagnosticEvents(),
		Release:  testReleaseFacts(),
		Platform: PlatformFacts{OperatingSystem: "Ubuntu Server", Version: "24.04", Architecture: "amd64"},
		Units:    []UnitSummary{{Unit: "sbxr-health-check.timer", Status: UnitActive}},
	}

	storage := &failingBundleStorage{}
	module.compress = func(map[string][]byte, time.Time) ([]byte, error) { return nil, errors.New("compression failed") }
	result := module.BuildSupportBundle(storage, request)
	if result.Status() != BundleNotCreated || result.Code() != "HEALTH-DIAGNOSTICS-BUNDLE-CANDIDATE" || storage.published {
		t.Fatalf("compression failure = %q %q published %t", result.Status(), result.Code(), storage.published)
	}

	module = New(func() time.Time { return now })
	normalCompressor := module.compress
	module.compress = func(items map[string][]byte, createdAt time.Time) ([]byte, error) {
		candidate, err := normalCompressor(items, createdAt)
		if err != nil {
			return nil, err
		}
		var trailing bytes.Buffer
		member := gzip.NewWriter(&trailing)
		if _, err := member.Write([]byte("SECRET-MARKER-TRAILING-7C41E9")); err != nil || member.Close() != nil {
			return nil, errors.New("trailing member failed")
		}
		return append(candidate, trailing.Bytes()...), nil
	}
	storage = &failingBundleStorage{}
	result = module.BuildSupportBundle(storage, request)
	if result.Status() != BundleNotCreated || result.Code() != "HEALTH-DIAGNOSTICS-BUNDLE-CANDIDATE" || storage.published {
		t.Fatalf("trailing archive member = %q %q published %t", result.Status(), result.Code(), storage.published)
	}

	module = New(func() time.Time { return now })
	for len(request.Events) < 4096 {
		request.Events = append(request.Events, check.DiagnosticEvents()[0])
		facts, ok := bundleRequestFacts(request, now)
		if !ok {
			t.Fatal("typed fixture became invalid")
		}
		structured, err := json.MarshalIndent(facts, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		plain := plainBundle(facts)
		if len(structured) <= BundleItemBytes && len(plain) <= BundleItemBytes && len(structured)+len(plain) > BundleTotalBytes {
			storage = &failingBundleStorage{}
			result = module.BuildSupportBundle(storage, request)
			if result.Status() != BundleNotCreated || result.Code() != "HEALTH-DIAGNOSTICS-BUNDLE-SIZE" || storage.published {
				t.Fatalf("total bound = %q %q published %t", result.Status(), result.Code(), storage.published)
			}
			return
		}
	}
	t.Fatal("fixture did not reach the total bound independently")
}
