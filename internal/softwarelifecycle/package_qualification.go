package softwarelifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
)

const MaxPackageQualificationEvidenceBytes = 64 << 10

var PackageQualificationProcedureCodes = []string{
	"RELEASE-STAGED-INSTALL-REVISION-1",
	"RELEASE-CLOUDFLARE-PROFILE-SETUP-N-TO-N+1",
	"RELEASE-STAGED-ONBOARDING-CHAIN",
	"RELEASE-STAGED-ONBOARDING-SECRET-SCAN",
	"RELEASE-STAGED-ONBOARDING-CLIENT-OUTPUT",
	"RELEASE-STAGED-ONBOARDING-TERMINAL",
	"RELEASE-STAGED-ONBOARDING-GUIDE-TEXT",
}

type PackageQualificationComponent struct {
	ArchiveSHA256 string `json:"archive_sha256"`
	Xray          string `json:"xray"`
	SingBox       string `json:"sing_box"`
	Cloudflared   string `json:"cloudflared"`
	Certbot       string `json:"certbot"`
	Python        string `json:"python"`
}

type PackageQualificationProcedure struct {
	Code   string `json:"code"`
	Status string `json:"status"`
}

type PackageQualificationEvidence struct {
	Schema       int                             `json:"schema"`
	Build        EmbeddedBuildIdentity           `json:"build"`
	Architecture Architecture                    `json:"architecture"`
	Component    PackageQualificationComponent   `json:"component"`
	Procedures   []PackageQualificationProcedure `json:"procedures"`
}

func BuildPackageQualificationEvidence(build EmbeddedBuildIdentity, architecture Architecture, manifest ComponentManifest, archiveSHA256 string, completed []string) ([]byte, error) {
	if !slices.Equal(completed, PackageQualificationProcedureCodes) {
		return nil, errors.New("package qualification procedures refused")
	}
	report, err := packageQualificationReport(build, architecture, manifest, archiveSHA256)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(report)
	if err != nil || len(document)+1 > MaxPackageQualificationEvidenceBytes {
		return nil, errors.New("package qualification evidence unavailable")
	}
	return append(document, '\n'), nil
}

func ValidatePackageQualificationEvidence(document []byte, build EmbeddedBuildIdentity, architecture Architecture, manifest ComponentManifest, archiveSHA256 string) error {
	if len(document) < 2 || len(document) > MaxPackageQualificationEvidenceBytes || document[len(document)-1] != '\n' || bytes.ContainsAny(document, "\r\x00") || ValidateUniqueJSON(document) != nil {
		return errors.New("package qualification evidence refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var got PackageQualificationEvidence
	if decoder.Decode(&got) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("package qualification evidence refused")
	}
	want, err := packageQualificationReport(build, architecture, manifest, archiveSHA256)
	canonical, marshalErr := json.Marshal(got)
	canonical = append(canonical, '\n')
	if err != nil || marshalErr != nil || !bytes.Equal(canonical, document) || !reflect.DeepEqual(got, want) {
		return errors.New("package qualification evidence refused")
	}
	return nil
}

// ValidatePackagedQualificationEvidence binds strict evidence to one exact
// application archive, matching component archive, and canonical secret scan.
func ValidatePackagedQualificationEvidence(applicationArchive, componentArchive, document []byte) error {
	executable, ok := executableArchiveBytes(applicationArchive)
	if !ok {
		return errors.New("packaged qualification application refused")
	}
	metadata, _, err := ReadPayloadMetadata(bytes.NewReader(executable), int64(len(executable)))
	if err != nil {
		return errors.New("packaged qualification application refused")
	}
	manifest, err := ValidateComponentArchive(componentArchive, metadata.Architecture)
	digest := sha256.Sum256(componentArchive)
	archiveSHA256 := hex.EncodeToString(digest[:])
	if err != nil || metadata.ComponentsSHA256 != archiveSHA256 || ValidatePackageQualificationEvidence(document, metadata.Build, metadata.Architecture, manifest, archiveSHA256) != nil {
		return errors.New("packaged qualification evidence refused")
	}
	return QualifyControlledStagedOnboardingSurfaces(map[string][]byte{"evidence": document}, []string{"evidence"})
}

func packageQualificationReport(build EmbeddedBuildIdentity, architecture Architecture, manifest ComponentManifest, archiveSHA256 string) (PackageQualificationEvidence, error) {
	if !validEmbeddedBuildIdentity(build) || architecture != AMD64 && architecture != ARM64 || manifest.Build != build || manifest.Architecture != architecture || !validComponentManifest(manifest, architecture) || !hashPattern.MatchString(archiveSHA256) {
		return PackageQualificationEvidence{}, errors.New("package qualification identity refused")
	}
	report := PackageQualificationEvidence{
		Schema: 1, Build: build, Architecture: architecture,
		Component: PackageQualificationComponent{ArchiveSHA256: archiveSHA256, Xray: manifest.Xray, SingBox: manifest.SingBox, Cloudflared: manifest.Cloudflared, Certbot: manifest.Certbot, Python: manifest.Python},
	}
	for _, code := range PackageQualificationProcedureCodes {
		report.Procedures = append(report.Procedures, PackageQualificationProcedure{Code: code, Status: "Passed"})
	}
	return report, nil
}
