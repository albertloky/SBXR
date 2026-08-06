package state_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/state"
)

const validDocument = `{
  "schema_version": 1,
  "revision": 7,
  "release_identity": {
    "repository": "https://github.com/albertloky/SBXR",
    "tag": "v1.0.0",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "release_index_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "last_completed_change_set": "change-0007",
  "payload": {},
  "checksum": "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
}`

var release = state.ReleaseIdentity{
	Repository:         "https://github.com/albertloky/SBXR",
	Tag:                "v1.0.0",
	Commit:             "0123456789abcdef0123456789abcdef01234567",
	ReleaseIndexSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
}

type memoryStorage struct {
	document string
	err      error
}

func (s memoryStorage) Read() ([]byte, error) { return []byte(s.document), s.err }
func (s memoryStorage) Publish([]byte, []byte, string) ([]byte, error) {
	return nil, errors.New("publication is not used by Load tests")
}

func managedRequest() state.LoadRequest {
	return state.LoadRequest{
		Baseline:         state.ManagedEvidence,
		SupportedRelease: release,
		Lineage: &state.LineageProof{
			Revision:               7,
			LastCompletedChangeSet: "change-0007",
			ReleaseIdentity:        release,
		},
	}
}

func TestLoadCleanAbsence(t *testing.T) {
	result, err := state.New(memoryStorage{err: fs.ErrNotExist}).Load(state.LoadRequest{Baseline: state.CleanVPS})
	if err != nil || result.Status != state.NotInstalled || result.Snapshot != nil {
		t.Fatalf("Load() = (%+v, %v), want a proven Not installed baseline", result, err)
	}
}

func TestLoadValidCurrentState(t *testing.T) {
	completeDocument := completeDocument(t)
	result, err := state.New(memoryStorage{document: completeDocument}).Load(managedRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != state.Managed || result.Snapshot == nil {
		t.Fatalf("Load() = %+v, want Managed with a snapshot", result)
	}
	if result.Snapshot.Revision != 7 || result.Snapshot.ReleaseIdentity != release || result.Snapshot.LastCompletedChangeSet != "change-0007" {
		t.Fatalf("Load() snapshot = %+v, want the complete typed envelope", result.Snapshot)
	}
	request := managedRequest()
	request.Lineage.ActiveChangeSet = "change-0008"
	result, err = state.New(memoryStorage{document: completeDocument}).Load(request)
	if err != nil || result.Status != state.ChangeInProgress {
		t.Fatalf("Load() = (%+v, %v), want Change in progress", result, err)
	}
}

func TestLoadRefusesUnsafeOrUnprovableState(t *testing.T) {
	secret := "UNIQUE-INFRASTRUCTURE-SECRET-MARKER"
	completeDocument := completeDocument(t)
	storageRefusal := &state.Finding{Code: "STATE-STORAGE-MODE", Concept: "Desired State file", Found: "broader permissions", Required: "0600", Why: "the protected boundary is not proven", NextAction: "correct the mode and check again"}
	tests := []struct {
		name     string
		document string
		request  state.LoadRequest
		readErr  error
		code     string
	}{
		{name: "missing beside managed evidence", readErr: fs.ErrNotExist, request: managedRequest(), code: "STATE-LINEAGE-MISSING"},
		{name: "state beside clean baseline", document: validDocument, request: state.LoadRequest{Baseline: state.CleanVPS}, code: "STATE-LINEAGE-UNPROVABLE"},
		{name: "storage boundary", request: managedRequest(), readErr: storageRefusal, code: "STATE-STORAGE-MODE"},
		{name: "storage read failure", request: managedRequest(), readErr: errors.New("device read failed"), code: "STATE-STORAGE-READ"},
		{name: "malformed JSON", document: `{`, request: managedRequest(), code: "STATE-DOCUMENT-MALFORMED"},
		{name: "trailing JSON", document: validDocument + `{}`, request: managedRequest(), code: "STATE-DOCUMENT-MALFORMED"},
		{name: "duplicate key", document: strings.Replace(validDocument, `"revision": 7,`, `"revision": 7, "revision": 7,`, 1), request: managedRequest(), code: "STATE-DOCUMENT-DUPLICATE-KEY"},
		{name: "unknown schema", document: strings.Replace(validDocument, `"schema_version": 1`, `"schema_version": 2`, 1), request: managedRequest(), code: "STATE-SCHEMA-UNSUPPORTED"},
		{name: "unknown envelope field", document: strings.Replace(validDocument, `"schema_version": 1,`, `"schema_version": 1, "mystery": true,`, 1), request: managedRequest(), code: "STATE-DOCUMENT-UNSUPPORTED-FIELD"},
		{name: "case-changed envelope field", document: strings.Replace(validDocument, `"revision": 7`, `"Revision": 7`, 1), request: managedRequest(), code: "STATE-DOCUMENT-UNSUPPORTED-FIELD"},
		{name: "unknown Release Identity field", document: strings.Replace(validDocument, `"repository":`, `"mystery": true, "repository":`, 1), request: managedRequest(), code: "STATE-DOCUMENT-UNSUPPORTED-FIELD"},
		{name: "case-changed Release Identity field", document: strings.Replace(validDocument, `"repository":`, `"Repository":`, 1), request: managedRequest(), code: "STATE-DOCUMENT-UNSUPPORTED-FIELD"},
		{name: "unknown payload field is secret-safe", document: strings.Replace(validDocument, `"payload": {}`, `"payload": {"mystery":"`+secret+`"}`, 1), request: managedRequest(), code: "STATE-DOCUMENT-UNSUPPORTED-FIELD"},
		{name: "null payload", document: strings.Replace(validDocument, `"payload": {}`, `"payload": null`, 1), request: managedRequest(), code: "STATE-DOCUMENT-INVALID"},
		{name: "invalid revision", document: strings.Replace(validDocument, `"revision": 7`, `"revision": 0`, 1), request: managedRequest(), code: "STATE-DOCUMENT-INVALID"},
		{name: "invalid Release Identity", document: strings.Replace(validDocument, release.Commit, "not-a-commit", 1), request: managedRequest(), code: "STATE-DOCUMENT-INVALID"},
		{name: "checksum failure", document: corruptChecksum(completeDocument), request: managedRequest(), code: "STATE-CHECKSUM-MISMATCH"},
		{name: "revision disagreement", document: completeDocument, request: func() state.LoadRequest { r := managedRequest(); r.Lineage.Revision = 8; return r }(), code: "STATE-LINEAGE-REVISION"},
		{name: "Release Identity disagreement", document: completeDocument, request: func() state.LoadRequest { r := managedRequest(); r.Lineage.ReleaseIdentity.Tag = "v2.0.0"; return r }(), code: "STATE-LINEAGE-RELEASE"},
		{name: "unsupported Release Identity", document: completeDocument, request: func() state.LoadRequest { r := managedRequest(); r.SupportedRelease.Tag = "v2.0.0"; return r }(), code: "STATE-RELEASE-UNSUPPORTED"},
		{name: "Change Set disagreement", document: completeDocument, request: func() state.LoadRequest {
			r := managedRequest()
			r.Lineage.LastCompletedChangeSet = "change-0006"
			return r
		}(), code: "STATE-LINEAGE-CHANGE-SET"},
		{name: "invalid active Change Set", document: completeDocument, request: func() state.LoadRequest {
			r := managedRequest()
			r.Lineage.ActiveChangeSet = "invalid\nidentity"
			return r
		}(), code: "STATE-LINEAGE-ACTIVE-CHANGE-SET"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := state.New(memoryStorage{document: tt.document, err: tt.readErr}).Load(tt.request)
			if result.Status != state.RecoveryRequired {
				t.Fatalf("status = %q, want %q", result.Status, state.RecoveryRequired)
			}
			var finding *state.Finding
			if !errors.As(err, &finding) || finding.Code != tt.code {
				t.Fatalf("error = %#v, want finding code %q", err, tt.code)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(finding.Found, secret) {
				t.Fatal("finding exposed protected content")
			}
			if finding.Concept == "" || finding.Found == "" || finding.Required == "" || finding.Why == "" || finding.NextAction == "" {
				t.Fatalf("finding is incomplete: %+v", finding)
			}
		})
	}

	t.Run("missing storage Adapter", func(t *testing.T) {
		result, err := state.New(nil).Load(managedRequest())
		if result.Status != state.RecoveryRequired || err == nil || !strings.Contains(err.Error(), "STATE-STORAGE-UNAVAILABLE") {
			t.Fatalf("Load() = (%+v, %v), want STATE-STORAGE-UNAVAILABLE", result, err)
		}
	})
}

func corruptChecksum(document string) string {
	start := strings.Index(document, `"checksum":"`) + len(`"checksum":"`)
	replacement := "0"
	if document[start] == '0' {
		replacement = "1"
	}
	return document[:start] + replacement + document[start+1:]
}

func completeDocument(t *testing.T) string {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("testdata", "complete-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(document))
}
