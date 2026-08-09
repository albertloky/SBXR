package softwarelifecycle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

var verifiedAt = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func TestViewReportsOneExactVerifiedReleaseWithoutUsingIt(t *testing.T) {
	evidence := validEvidence()
	source := &releaseSource{evidence: evidence}
	module := softwarelifecycle.New(source, softwarelifecycle.VerifierQualification{
		Version:            "2.97.0",
		SigningFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
	}, func() time.Time { return verifiedAt })

	got := module.View(t.Context(), softwarelifecycle.ViewRequest{
		Tag:                "v1.0.0",
		InstallationStatus: softwarelifecycle.NotInstalled,
	})

	indexDigest := sha256.Sum256(evidence.Index)
	wantIdentity := softwarelifecycle.ReleaseIdentity{
		Repository:  "albertloky/SBXR",
		Tag:         "v1.0.0",
		Commit:      "0123456789abcdef0123456789abcdef01234567",
		IndexSHA256: hex.EncodeToString(indexDigest[:]),
	}
	if got.Refusal != nil || got.VerifiedCandidate == nil || got.VerifiedCandidate.Identity != wantIdentity {
		t.Fatalf("View() = %#v, want exact verified candidate %#v", got, wantIdentity)
	}
	if got.InstallationStatus != softwarelifecycle.NotInstalled || got.UpdateEligible || got.MigrationSummary != "State schema 1; minimum updater schema 1" || !reflect.DeepEqual(got.AffectedComponents, []softwarelifecycle.Component{softwarelifecycle.ApplicationAMD64, softwarelifecycle.ApplicationARM64}) || !reflect.DeepEqual(got.PermittedActions, []softwarelifecycle.Action{softwarelifecycle.ReviewInstall}) {
		t.Fatalf("unsafe or incomplete View = %#v", got)
	}
	if got.VerifiedCandidate.Sequence != 1 || got.VerifiedCandidate.VerifiedAt != verifiedAt || len(got.VerifiedCandidate.Assets) != 2 {
		t.Fatalf("proof = %#v", got.VerifiedCandidate)
	}
	if source.extracted != 0 || source.executed != 0 || source.mutated != 0 {
		t.Fatalf("View used candidate: extract=%d execute=%d mutate=%d", source.extracted, source.executed, source.mutated)
	}
}

func TestViewFailsClosedForEveryChangedReleaseFact(t *testing.T) {
	const secretMarker = "PRIVATE-MARKER-4F7D9A"
	tests := []struct {
		name   string
		change func(*softwarelifecycle.ReleaseEvidence)
	}{
		{"source failure", func(value *softwarelifecycle.ReleaseEvidence) {}},
		{"repository", func(value *softwarelifecycle.ReleaseEvidence) { value.Repository = "attacker/SBXR" }},
		{"tag", func(value *softwarelifecycle.ReleaseEvidence) { value.Tag = "v1.0.1" }},
		{"commit", func(value *softwarelifecycle.ReleaseEvidence) { value.Commit = strings.Repeat("a", 40) }},
		{"unsigned verifier distribution", func(value *softwarelifecycle.ReleaseEvidence) { value.Verifier.OfficialSignedDistribution = false }},
		{"verifier version", func(value *softwarelifecycle.ReleaseEvidence) { value.Verifier.Version = "2.96.0" }},
		{"verifier fingerprint", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Verifier.SigningFingerprint = strings.Repeat("A", 40)
		}},
		{"release verifier failure", func(value *softwarelifecycle.ReleaseEvidence) { value.Verifier.ReleaseVerified = false }},
		{"asset verifier failure", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Verifier.VerifiedAssets = value.Verifier.VerifiedAssets[:2]
		}},
		{"index changed after attestation", func(value *softwarelifecycle.ReleaseEvidence) { value.Index = append(value.Index, ' ') }},
		{"earlier successful proof", func(value *softwarelifecycle.ReleaseEvidence) {
			value.AttestedAssets[1].SHA256 = strings.Repeat("a", 64)
		}},
		{"unknown index field", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"assets":`, `"future":true,"assets":`)
		}},
		{"duplicate index field", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"schema":1`, `"schema":1,"schema":1`)
		}},
		{"schema type", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"schema":1`, `"schema":"1"`)
		}},
		{"unsupported schema", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"schema":1`, `"schema":2`)
		}},
		{"product", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"product":"sbxr"`, `"product":"other"`)
		}},
		{"index repository", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"repository":"albertloky/SBXR"`, `"repository":"attacker/SBXR"`)
		}},
		{"version type", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"version":"1.0.0"`, `"version":1`)
		}},
		{"unsafe version", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"version":"1.0.0"`, `"version":"../1.0.0"`)
		}},
		{"sequence type", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"sequence":1`, `"sequence":"1"`)
		}},
		{"zero sequence", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"sequence":1`, `"sequence":0`)
		}},
		{"index tag", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"tag":"v1.0.0"`, `"tag":"v1.0.1"`)
		}},
		{"index commit", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"commit":"0123456789abcdef0123456789abcdef01234567"`, `"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
		}},
		{"state schema type", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"state_schema":1`, `"state_schema":"1"`)
		}},
		{"zero state schema", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"state_schema":1`, `"state_schema":0`)
		}},
		{"minimum updater schema type", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"minimum_updater_schema":1`, `"minimum_updater_schema":"1"`)
		}},
		{"zero minimum updater schema", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"minimum_updater_schema":1`, `"minimum_updater_schema":0`)
		}},
		{"unknown asset field", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `"name":"sbxr-linux-amd64.tar.gz"`, `"future":true,"name":"sbxr-linux-amd64.tar.gz"`)
		}},
		{"missing role", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `application-linux-arm64`, `application-linux-amd64`)
		}},
		{"unsafe role", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `application-linux-arm64`, `application-linux-riscv64`)
		}},
		{"duplicate name", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `sbxr-linux-arm64.tar.gz`, `sbxr-linux-amd64.tar.gz`)
		}},
		{"unsafe name", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `sbxr-linux-amd64.tar.gz`, `../sbxr-linux-amd64.tar.gz`)
		}},
		{"source archive", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, `sbxr-linux-amd64.tar.gz`, `source.zip`)
		}},
		{"size type", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, fmt.Sprintf(`"size":%d`, len(value.Assets[0].Bytes)), `"size":"23"`)
		}},
		{"zero size", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, fmt.Sprintf(`"size":%d`, len(value.Assets[0].Bytes)), `"size":0`)
		}},
		{"wrong size", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Assets[0].Bytes = append(value.Assets[0].Bytes, 'x')
		}},
		{"malformed hash", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Index = replaceIndex(value.Index, value.AttestedAssets[1].SHA256, strings.ToUpper(value.AttestedAssets[1].SHA256))
		}},
		{"wrong digest", func(value *softwarelifecycle.ReleaseEvidence) { value.Assets[0].Bytes[0] ^= 1 }},
		{"archive missing sbxr executable", func(value *softwarelifecycle.ReleaseEvidence) {
			replaceArchive(value, 0, namedArchive("other", "not sbxr"))
		}},
		{"missing downloaded asset", func(value *softwarelifecycle.ReleaseEvidence) { value.Assets = value.Assets[:1] }},
		{"extra downloaded asset", func(value *softwarelifecycle.ReleaseEvidence) {
			value.Assets = append(value.Assets, softwarelifecycle.DownloadedAsset{Name: "extra.tar.gz", Bytes: []byte("extra")})
		}},
		{"duplicate downloaded asset", func(value *softwarelifecycle.ReleaseEvidence) { value.Assets = append(value.Assets, value.Assets[0]) }},
		{"missing attested asset", func(value *softwarelifecycle.ReleaseEvidence) { value.AttestedAssets = value.AttestedAssets[:2] }},
		{"extra attested asset", func(value *softwarelifecycle.ReleaseEvidence) {
			value.AttestedAssets = append(value.AttestedAssets, softwarelifecycle.AttestedAsset{Name: "extra.tar.gz", SHA256: strings.Repeat("a", 64)})
		}},
		{"duplicate attested asset", func(value *softwarelifecycle.ReleaseEvidence) {
			value.AttestedAssets = append(value.AttestedAssets, value.AttestedAssets[0])
		}},
		{"secret marker", func(value *softwarelifecycle.ReleaseEvidence) { value.Repository = secretMarker }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := validEvidence()
			test.change(&evidence)
			if test.name != "index changed after attestation" {
				syncIndexAttestation(&evidence)
			}
			source := &releaseSource{evidence: evidence}
			if test.name == "source failure" {
				source.err = errors.New("raw failure " + secretMarker)
			}
			module := softwarelifecycle.New(source, qualification(), func() time.Time { return verifiedAt })
			got := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
			if got.Refusal == nil || got.Refusal.Code != softwarelifecycle.ReleaseVerificationRefused || got.VerifiedCandidate != nil || got.MigrationSummary != "" || got.UpdateEligible || got.AffectedComponents != nil || got.PermittedActions != nil || strings.Contains(fmt.Sprintf("%#v", got), secretMarker) {
				t.Fatalf("unsafe refusal = %#v", got)
			}
			if source.extracted != 0 || source.executed != 0 || source.mutated != 0 {
				t.Fatalf("refused release was used")
			}
		})
	}
}

func TestViewRejectsEveryMissingOrWrongIndexFieldAndType(t *testing.T) {
	fields := []string{"schema", "product", "repository", "version", "sequence", "tag", "commit", "state_schema", "minimum_updater_schema", "assets"}
	for _, field := range fields {
		for _, variant := range []string{"missing", "wrong type"} {
			t.Run(field+"/"+variant, func(t *testing.T) {
				evidence := validEvidence()
				var document map[string]json.RawMessage
				if err := json.Unmarshal(evidence.Index, &document); err != nil {
					t.Fatal(err)
				}
				if variant == "missing" {
					delete(document, field)
				} else {
					document[field] = json.RawMessage("false")
				}
				var err error
				evidence.Index, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				syncIndexAttestation(&evidence)
				got := softwarelifecycle.New(&releaseSource{evidence: evidence}, qualification(), func() time.Time { return verifiedAt }).View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
				if got.Refusal == nil || got.VerifiedCandidate != nil {
					t.Fatalf("%s %s accepted: %#v", field, variant, got)
				}
			})
		}
	}
	for _, field := range []string{"role", "name", "size", "sha256"} {
		for _, variant := range []string{"missing", "wrong type"} {
			t.Run("asset/"+field+"/"+variant, func(t *testing.T) {
				evidence := validEvidence()
				var document map[string]json.RawMessage
				if err := json.Unmarshal(evidence.Index, &document); err != nil {
					t.Fatal(err)
				}
				var assets []map[string]json.RawMessage
				if err := json.Unmarshal(document["assets"], &assets); err != nil {
					t.Fatal(err)
				}
				if variant == "missing" {
					delete(assets[0], field)
				} else {
					assets[0][field] = json.RawMessage("false")
				}
				var err error
				document["assets"], err = json.Marshal(assets)
				if err != nil {
					t.Fatal(err)
				}
				evidence.Index, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				syncIndexAttestation(&evidence)
				got := softwarelifecycle.New(&releaseSource{evidence: evidence}, qualification(), func() time.Time { return verifiedAt }).View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
				if got.Refusal == nil || got.VerifiedCandidate != nil {
					t.Fatalf("asset %s %s accepted: %#v", field, variant, got)
				}
			})
		}
	}
}

func TestViewNeverReusesAnEarlierSuccessfulProof(t *testing.T) {
	source := &releaseSource{evidence: validEvidence()}
	module := softwarelifecycle.New(source, qualification(), func() time.Time { return verifiedAt })
	first := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
	if first.VerifiedCandidate == nil || first.Refusal != nil {
		t.Fatalf("first View = %#v", first)
	}
	source.err = errors.New("current verification failed")
	second := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
	if second.Refusal == nil || second.VerifiedCandidate != nil || second.PermittedActions != nil {
		t.Fatalf("earlier proof was reused: %#v", second)
	}
}

func TestViewRejectsEveryMaliciousOrAmbiguousArchive(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"absolute path", archiveEntries(tar.Header{Name: "/sbxr", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})},
		{"traversal", archiveEntries(tar.Header{Name: "../sbxr", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})},
		{"symbolic link", archiveEntries(tar.Header{Name: "sbxr", Linkname: "target", Mode: 0o755, Typeflag: tar.TypeSymlink})},
		{"hard link", archiveEntries(tar.Header{Name: "sbxr", Linkname: "target", Mode: 0o755, Typeflag: tar.TypeLink})},
		{"special file", archiveEntries(tar.Header{Name: "sbxr", Mode: 0o755, Typeflag: tar.TypeChar})},
		{"unsafe mode", archiveEntries(tar.Header{Name: "sbxr", Mode: 0o777, Size: 1, Typeflag: tar.TypeReg})},
		{"Owner-managed path", archiveEntries(tar.Header{Name: "var/lib/sbxr/state.json", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})},
		{"duplicate destination", archiveEntries(tar.Header{Name: "sbxr", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg}, tar.Header{Name: "sbxr", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})},
		{"extra destination", archiveEntries(tar.Header{Name: "sbxr", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg}, tar.Header{Name: "extra", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})},
		{"concatenated gzip member", append(executableArchive("first"), executableArchive("second")...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := validEvidence()
			replaceArchive(&evidence, 0, test.body)
			got := softwarelifecycle.New(&releaseSource{evidence: evidence}, qualification(), func() time.Time { return verifiedAt }).View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.NotInstalled})
			if got.Refusal == nil || got.VerifiedCandidate != nil {
				t.Fatalf("malicious archive accepted: %#v", got)
			}
		})
	}
}

func TestViewTreatsVersionAndTagAsSafeOpaqueStrings(t *testing.T) {
	evidence := validEvidence()
	evidence.Tag = "release_2026+1"
	evidence.Index = replaceIndex(evidence.Index, `"version":"1.0.0"`, `"version":"build_2026+1"`)
	evidence.Index = replaceIndex(evidence.Index, `"tag":"v1.0.0"`, `"tag":"release_2026+1"`)
	syncIndexAttestation(&evidence)
	got := softwarelifecycle.New(&releaseSource{evidence: evidence}, qualification(), func() time.Time { return verifiedAt }).View(t.Context(), softwarelifecycle.ViewRequest{Tag: "release_2026+1", InstallationStatus: softwarelifecycle.NotInstalled})
	if got.Refusal != nil || got.VerifiedCandidate == nil || got.VerifiedCandidate.Version != "build_2026+1" {
		t.Fatalf("safe opaque strings refused: %#v", got)
	}
}

func TestViewReportsOnlyEligibleActionsForCurrentInstallationState(t *testing.T) {
	installed := &softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v0.9.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}, Sequence: 1}
	evidence := validEvidence()
	evidence.Index = replaceIndex(evidence.Index, `"sequence":1`, `"sequence":2`)
	indexDigest := sha256.Sum256(evidence.Index)
	evidence.AttestedAssets[0].SHA256 = hex.EncodeToString(indexDigest[:])
	module := softwarelifecycle.New(&releaseSource{evidence: evidence}, qualification(), func() time.Time { return verifiedAt })
	managed := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.Managed, Installed: installed})
	if managed.Refusal != nil || !managed.UpdateEligible || !reflect.DeepEqual(managed.PermittedActions, []softwarelifecycle.Action{softwarelifecycle.ReviewUpdate}) || managed.Installed == nil || managed.Installed.Tag != "v0.9.0" {
		t.Fatalf("Managed View = %#v", managed)
	}
	unsafe := *installed
	unsafe.Identity.Tag = "PRIVATE MARKER 4F7D9A"
	refused := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: softwarelifecycle.Managed, Installed: &unsafe})
	if refused.Refusal == nil || refused.Installed != nil || strings.Contains(fmt.Sprintf("%#v", refused), "PRIVATE MARKER 4F7D9A") {
		t.Fatalf("unsafe installed proof crossed View = %#v", refused)
	}
	for _, status := range []softwarelifecycle.InstallationStatus{softwarelifecycle.ChangeInProgress, softwarelifecycle.RecoveryRequired} {
		got := module.View(t.Context(), softwarelifecycle.ViewRequest{Tag: "v1.0.0", InstallationStatus: status})
		if got.Refusal != nil || got.UpdateEligible || got.PermittedActions != nil {
			t.Fatalf("%s View = %#v", status, got)
		}
	}
}

type releaseSource struct {
	evidence                     softwarelifecycle.ReleaseEvidence
	err                          error
	extracted, executed, mutated int
}

func (source *releaseSource) Verify(context.Context, string) (softwarelifecycle.ReleaseEvidence, error) {
	return source.evidence, source.err
}

func validEvidence() softwarelifecycle.ReleaseEvidence {
	amd64 := executableArchive("verified amd64 executable")
	arm64 := executableArchive("verified arm64 executable")
	amd64Digest := sha256.Sum256(amd64)
	arm64Digest := sha256.Sum256(arm64)
	index := []byte(fmt.Sprintf(`{"schema":1,"product":"sbxr","repository":"albertloky/SBXR","version":"1.0.0","sequence":1,"tag":"v1.0.0","commit":"0123456789abcdef0123456789abcdef01234567","state_schema":1,"minimum_updater_schema":1,"assets":[{"role":"application-linux-amd64","name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"role":"application-linux-arm64","name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":"%s"}]}`, len(amd64), hex.EncodeToString(amd64Digest[:]), len(arm64), hex.EncodeToString(arm64Digest[:])))
	indexDigest := sha256.Sum256(index)
	return softwarelifecycle.ReleaseEvidence{
		Repository: "albertloky/SBXR",
		Tag:        "v1.0.0",
		Commit:     "0123456789abcdef0123456789abcdef01234567",
		Index:      index,
		Assets: []softwarelifecycle.DownloadedAsset{
			{Name: "sbxr-linux-amd64.tar.gz", Bytes: amd64},
			{Name: "sbxr-linux-arm64.tar.gz", Bytes: arm64},
		},
		AttestedAssets: []softwarelifecycle.AttestedAsset{
			{Name: "release-index.json", SHA256: hex.EncodeToString(indexDigest[:])},
			{Name: "sbxr-linux-amd64.tar.gz", SHA256: hex.EncodeToString(amd64Digest[:])},
			{Name: "sbxr-linux-arm64.tar.gz", SHA256: hex.EncodeToString(arm64Digest[:])},
		},
		Verifier: softwarelifecycle.VerifierEvidence{
			Version:                    "2.97.0",
			SigningFingerprint:         "0123456789ABCDEF0123456789ABCDEF01234567",
			OfficialSignedDistribution: true,
			ReleaseVerified:            true,
			VerifiedAssets:             []string{"release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"},
		},
	}
}

func qualification() softwarelifecycle.VerifierQualification {
	return softwarelifecycle.VerifierQualification{Version: "2.97.0", SigningFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"}
}

func replaceIndex(index []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(index), old, replacement, 1))
}

func executableArchive(executable string) []byte {
	return namedArchive("sbxr", executable)
}

func namedArchive(name, executable string) []byte {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(executable)), Typeflag: tar.TypeReg}); err != nil {
		panic(err)
	}
	if _, err := archive.Write([]byte(executable)); err != nil {
		panic(err)
	}
	if err := archive.Close(); err != nil {
		panic(err)
	}
	if err := compressed.Close(); err != nil {
		panic(err)
	}
	return output.Bytes()
}

func archiveEntries(headers ...tar.Header) []byte {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for index := range headers {
		if err := archive.WriteHeader(&headers[index]); err != nil {
			panic(err)
		}
		if headers[index].Size > 0 {
			if _, err := archive.Write(bytes.Repeat([]byte{'x'}, int(headers[index].Size))); err != nil {
				panic(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		panic(err)
	}
	if err := compressed.Close(); err != nil {
		panic(err)
	}
	return output.Bytes()
}

func replaceArchive(evidence *softwarelifecycle.ReleaseEvidence, index int, body []byte) {
	oldBody := evidence.Assets[index].Bytes
	oldDigest := sha256.Sum256(oldBody)
	newDigest := sha256.Sum256(body)
	evidence.Assets[index].Bytes = body
	evidence.Index = replaceIndex(evidence.Index, fmt.Sprintf(`"size":%d`, len(oldBody)), fmt.Sprintf(`"size":%d`, len(body)))
	evidence.Index = replaceIndex(evidence.Index, hex.EncodeToString(oldDigest[:]), hex.EncodeToString(newDigest[:]))
	for assetIndex := range evidence.AttestedAssets {
		if evidence.AttestedAssets[assetIndex].Name == evidence.Assets[index].Name {
			evidence.AttestedAssets[assetIndex].SHA256 = hex.EncodeToString(newDigest[:])
		}
	}
	syncIndexAttestation(evidence)
}

func syncIndexAttestation(evidence *softwarelifecycle.ReleaseEvidence) {
	indexDigest := sha256.Sum256(evidence.Index)
	for index := range evidence.AttestedAssets {
		if evidence.AttestedAssets[index].Name == "release-index.json" {
			evidence.AttestedAssets[index].SHA256 = hex.EncodeToString(indexDigest[:])
		}
	}
}
