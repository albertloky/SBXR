package softwarelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type controlledLocalInspector struct{ evidence localInspection }

func (inspector controlledLocalInspector) inspect(context.Context) localInspection {
	return inspector.evidence
}

type changingLocalInspector struct{ next func() localInspection }

func (inspector changingLocalInspector) inspect(context.Context) localInspection {
	return inspector.next()
}

type controlledLatestSource struct {
	result  LatestRelease
	outcome LatestReleaseOutcome
	check   func()
}

func (source controlledLatestSource) CheckLatest(context.Context) (LatestRelease, LatestReleaseOutcome) {
	if source.check != nil {
		source.check()
	}
	return source.result, source.outcome
}

func TestStatusReportsReadyFromVerifiedInstalledEvidence(t *testing.T) {
	identity := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	evidence := installedEvidence(t, identity, 17, AMD64)

	var lifecycle Interface = newInstalledInterface(controlledLocalInspector{evidence}, nil)
	got := lifecycle.Status(context.Background())

	if got.State != Ready || got.Code != StatusReady || got.Message != "SBXR is ready." || got.Installed == nil || *got.Installed != identity {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestStatusRequiresRecoveryForUnverifiedLocalEvidence(t *testing.T) {
	identity := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	tests := []struct {
		name   string
		change func(*localInspection)
	}{
		{"missing", func(value *localInspection) { value.installedRecord = nil }},
		{"malformed", func(value *localInspection) { value.installedRecord = []byte(`{"schema":1`) }},
		{"contradictory release identity", func(value *localInspection) {
			value.installedRecord = []byte(strings.Replace(string(value.installedRecord), `"tag":"v2.0.0"`, `"tag":"v2.0.1"`, 1))
		}},
		{"contradictory release sequence", func(value *localInspection) {
			value.installedRecord = []byte(strings.Replace(string(value.installedRecord), `"sequence":17`, `"sequence":18`, 1))
		}},
		{"contradictory architecture", func(value *localInspection) {
			value.installedRecord = []byte(strings.Replace(string(value.installedRecord), `"architecture":"amd64"`, `"architecture":"arm64"`, 1))
		}},
		{"contradictory executable digest", func(value *localInspection) {
			var record installedRecord
			if json.Unmarshal(value.installedRecord, &record) != nil {
				panic("invalid test fixture")
			}
			record.ExecutableSHA256 = strings.Repeat("c", 64)
			value.installedRecord, _ = json.Marshal(record)
		}},
		{"unsafe", func(value *localInspection) { value.inspectionValid = false }},
		{"unfinished", func(value *localInspection) { value.transactionEvidence = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := installedEvidence(t, identity, 17, AMD64)
			test.change(&evidence)

			got := newInstalledInterface(controlledLocalInspector{evidence}, nil).Status(context.Background())

			if got.State != RecoveryRequiredState || got.Code != StatusRecoveryRequired || got.Message != "SBXR needs recovery before normal operations can continue." || strings.Contains(got.Message, "installed.json") {
				t.Fatalf("Status() = %#v", got)
			}
		})
	}
}

func TestStatusReportsConcurrentUpdateWithoutExposingLockFacts(t *testing.T) {
	evidence := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	evidence.lockHeld = true

	got := newInstalledInterface(controlledLocalInspector{evidence}, nil).Status(context.Background())

	if got.State != UpdateInProgress || got.Code != StatusUpdateInProgress || got.Message != "Another Software Lifecycle change is in progress." || strings.Contains(got.Message, "lock") {
		t.Fatalf("Status() = %#v", got)
	}
}

func TestPendingOperationsReturnVerifiedStatusWithoutInventingAnOutcome(t *testing.T) {
	evidence := installedEvidence(t, ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, 17, AMD64)
	var lifecycle Interface = newInstalledInterface(controlledLocalInspector{evidence}, nil)

	for name, result := range map[string]Result{
		"Update":  lifecycle.Update(context.Background(), nil),
		"Recover": lifecycle.Recover(context.Background(), nil),
	} {
		if result.State != Ready || result.Code != StatusReady || result.Message != "SBXR is ready." {
			t.Fatalf("%s() = %#v", name, result)
		}
	}
	if result := lifecycle.Check(context.Background(), nil); result.State != Ready || result.Code != CheckReleaseRefused {
		t.Fatalf("Check() = %#v", result)
	}

	evidence.transactionEvidence = true
	lifecycle = newInstalledInterface(controlledLocalInspector{evidence}, nil)
	if result := lifecycle.Recover(context.Background(), nil); result.State != RecoveryRequiredState || result.Code != StatusRecoveryRequired {
		t.Fatalf("Recover() = %#v", result)
	}
}

func TestCheckReportsQualifiedLatestReleaseBySequence(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	latest := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	evidence := installedEvidence(t, installed, 17, AMD64)

	for _, test := range []struct {
		name     string
		release  LatestRelease
		wantCode ResultCode
		wantLast *ReleaseIdentity
	}{
		{"higher sequence", LatestRelease{Identity: latest, Sequence: 18}, CheckUpdateAvailable, &latest},
		{"same identity and sequence", LatestRelease{Identity: installed, Sequence: 17}, CheckAlreadyCurrent, &installed},
		{"same sequence different identity", LatestRelease{Identity: latest, Sequence: 17}, CheckReleaseRefused, nil},
		{"lower sequence", LatestRelease{Identity: latest, Sequence: 16}, CheckReleaseRefused, nil},
		{"same identity different sequence", LatestRelease{Identity: installed, Sequence: 18}, CheckReleaseRefused, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := newInstalledInterface(controlledLocalInspector{evidence: evidence}, controlledLatestSource{result: test.release, outcome: LatestReleaseAccepted}).Check(t.Context(), nil)
			if result.State != Ready || result.Code != test.wantCode || result.Installed == nil || *result.Installed != installed || !reflect.DeepEqual(result.Latest, test.wantLast) {
				t.Fatalf("Check() = %#v", result)
			}
		})
	}
}

func TestCheckDistinguishesSafeReleaseAndLocalOutcomes(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	evidence := installedEvidence(t, installed, 17, AMD64)
	for _, test := range []struct {
		name    string
		outcome LatestReleaseOutcome
		want    ResultCode
	}{
		{"release refused", LatestReleaseRefused, CheckReleaseRefused},
		{"release unavailable", LatestReleaseUnavailable, CheckReleaseUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := newInstalledInterface(controlledLocalInspector{evidence: evidence}, controlledLatestSource{outcome: test.outcome}).Check(t.Context(), nil)
			if result.State != Ready || result.Code != test.want || result.Latest != nil || strings.Contains(result.Message, "PRIVATE-MARKER") {
				t.Fatalf("Check() = %#v", result)
			}
		})
	}

	called := false
	notReady := evidence
	notReady.transactionEvidence = true
	result := newInstalledInterface(controlledLocalInspector{evidence: notReady}, controlledLatestSource{check: func() { called = true }}).Check(t.Context(), nil)
	if called || result.State != RecoveryRequiredState || result.Code != CheckNotReady {
		t.Fatalf("Check() = %#v, remote called = %t", result, called)
	}
}

func TestCheckRefusesResultAfterAnyConcurrentLocalChange(t *testing.T) {
	installed := ReleaseIdentity{Repository: Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	latest := ReleaseIdentity{Repository: Repository, Tag: "v2.0.1", Commit: strings.Repeat("c", 40), IndexSHA256: strings.Repeat("d", 64)}
	before := installedEvidence(t, installed, 17, AMD64)
	after := before
	after.lockHeld = true
	reads := 0
	local := changingLocalInspector{next: func() localInspection {
		reads++
		if reads == 1 {
			return before
		}
		return after
	}}

	result := newInstalledInterface(local, controlledLatestSource{result: LatestRelease{Identity: latest, Sequence: 18}, outcome: LatestReleaseAccepted}).Check(t.Context(), nil)

	if result.State != UpdateInProgress || result.Code != CheckConcurrentChange || result.Latest != nil || reads != 2 {
		t.Fatalf("Check() = %#v, reads = %d", result, reads)
	}
}

func installedEvidence(t *testing.T, identity ReleaseIdentity, sequence uint64, architecture Architecture) localInspection {
	t.Helper()
	payload := []byte("test executable")
	executable := installedExecutableFixture(t, payload, embeddedIdentity{Schema: 1, Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, Sequence: sequence, Architecture: architecture})
	executableDigest := sha256.Sum256(executable)
	record := installedRecord{Schema: 1, Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, ReleaseIndexSHA256: identity.IndexSHA256, Sequence: sequence, Architecture: architecture, ExecutableSHA256: hex.EncodeToString(executableDigest[:])}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return localInspection{inspectionValid: true, installedRecord: append(body, '\n'), executable: executable}
}

func installedExecutableFixture(t *testing.T, payload []byte, identity embeddedIdentity) []byte {
	t.Helper()
	payloadDigest := sha256.Sum256(payload)
	identity.PayloadSHA256 = hex.EncodeToString(payloadDigest[:])
	document, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	documentDigest := sha256.Sum256(document)
	result := append([]byte(nil), payload...)
	result = append(result, document...)
	result = append(result, documentDigest[:]...)
	result = binary.LittleEndian.AppendUint64(result, uint64(len(document)))
	return append(result, identityMagic...)
}
