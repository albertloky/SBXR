package softwarelifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPackageQualificationEvidenceIsStrictOrderedAndIdentityBound(t *testing.T) {
	build := EmbeddedBuildIdentity{Repository: Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), PayloadSHA256: strings.Repeat("b", 64)}
	component, err := NewBoundComponentManifest(AMD64, build, "5.4.0", componentFixtureFiles())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("components"))
	document, err := BuildPackageQualificationEvidence(build, AMD64, component, hex.EncodeToString(digest[:]), PackageQualificationProcedureCodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(document) == 0 || document[len(document)-1] != '\n' || ValidatePackageQualificationEvidence(document[:len(document)-1], build, AMD64, component, hex.EncodeToString(digest[:])) == nil {
		t.Fatal("package qualification evidence did not require one trailing newline")
	}
	if _, err := BuildPackageQualificationEvidence(build, AMD64, component, hex.EncodeToString(digest[:]), PackageQualificationProcedureCodes[:6]); err == nil {
		t.Fatal("incomplete package qualification procedures accepted")
	}
	if err := ValidatePackageQualificationEvidence(document, build, AMD64, component, hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	first := []byte(`{"code":"` + PackageQualificationProcedureCodes[0] + `","status":"Passed"}`)
	second := []byte(`{"code":"` + PackageQualificationProcedureCodes[1] + `","status":"Passed"}`)
	last := []byte(`,{"code":"` + PackageQualificationProcedureCodes[len(PackageQualificationProcedureCodes)-1] + `","status":"Passed"}`)
	reordered := bytes.Replace(document, first, []byte("PACKAGE-QUALIFICATION-TEMP"), 1)
	reordered = bytes.Replace(reordered, second, first, 1)
	reordered = bytes.Replace(reordered, []byte("PACKAGE-QUALIFICATION-TEMP"), second, 1)
	for _, changed := range [][]byte{
		bytes.Replace(document, []byte(`"schema":1`), []byte(`"schema":2`), 1),
		bytes.Replace(document, []byte(`{"schema":1`), []byte(`{"schema":1,"unknown":true`), 1),
		bytes.Replace(document, []byte(`{"schema":1`), []byte(`{"schema":1,"schema":1`), 1),
		bytes.Replace(document, []byte(`"status":"Passed"`), []byte(`"status":"Failed"`), 1),
		bytes.Replace(document, []byte(PackageQualificationProcedureCodes[0]), []byte(PackageQualificationProcedureCodes[1]), 1),
		bytes.Replace(document, last, nil, 1),
		reordered,
		append(append([]byte(nil), document...), []byte(` {}`)...),
		append(append([]byte(nil), document...), '\r'),
		append(append([]byte(nil), document...), 0),
	} {
		if ValidatePackageQualificationEvidence(changed, build, AMD64, component, hex.EncodeToString(digest[:])) == nil {
			t.Fatalf("changed qualification evidence accepted: %q", changed)
		}
	}
	oversized := bytes.Repeat([]byte{'x'}, MaxPackageQualificationEvidenceBytes+1)
	if ValidatePackageQualificationEvidence(oversized, build, AMD64, component, hex.EncodeToString(digest[:])) == nil {
		t.Fatal("oversized qualification evidence accepted")
	}
	changedBuild := build
	changedBuild.Commit = strings.Repeat("c", 40)
	changedManifest := component
	changedManifest.Xray = "v26.3.28"
	for _, mismatch := range []error{
		ValidatePackageQualificationEvidence(document, changedBuild, AMD64, component, hex.EncodeToString(digest[:])),
		ValidatePackageQualificationEvidence(document, build, ARM64, component, hex.EncodeToString(digest[:])),
		ValidatePackageQualificationEvidence(document, build, AMD64, changedManifest, hex.EncodeToString(digest[:])),
		ValidatePackageQualificationEvidence(document, build, AMD64, component, strings.Repeat("d", 64)),
	} {
		if mismatch == nil {
			t.Fatal("identity-mismatched qualification evidence accepted")
		}
	}
}
