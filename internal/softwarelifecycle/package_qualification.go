package softwarelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
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

func BuildPackageQualificationEvidence(build EmbeddedBuildIdentity, architecture Architecture, manifest ComponentManifest, archiveSHA256 string) ([]byte, error) {
	report, err := packageQualificationReport(build, architecture, manifest, archiveSHA256)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(report)
	if err != nil || len(document) > MaxPackageQualificationEvidenceBytes {
		return nil, errors.New("package qualification evidence unavailable")
	}
	return document, nil
}

func ValidatePackageQualificationEvidence(document []byte, build EmbeddedBuildIdentity, architecture Architecture, manifest ComponentManifest, archiveSHA256 string) error {
	if len(document) == 0 || len(document) > MaxPackageQualificationEvidenceBytes || bytes.ContainsAny(document, "\r\x00") || ValidateUniqueJSON(document) != nil {
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
	if err != nil || marshalErr != nil || !bytes.Equal(canonical, document) || !reflect.DeepEqual(got, want) {
		return errors.New("package qualification evidence refused")
	}
	return nil
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
