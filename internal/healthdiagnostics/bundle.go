package healthdiagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	BundleItemBytes    = 256 << 10
	BundleTotalBytes   = 384 << 10
	BundleArchiveBytes = 512 << 10

	externalCopyWarning = "A copied or moved bundle is outside SBXR retention, deletion, permission, and redaction control."
)

type ReleaseFacts struct {
	repository, tag, commit, releaseIndexSHA256 string
	verified                                    bool
}

// ReleaseFactsFrom accepts only System Changes' opaque handoff of State's
// exact fresh Managed Release Identity proof.
func ReleaseFactsFrom(inspection systemchanges.ReleaseHealthInspection) ReleaseFacts {
	identity, ok := inspection.ReleaseIdentityFacts()
	if !ok {
		return ReleaseFacts{}
	}
	repository, tag, commit, indexSHA256 := identity.Repository, identity.Tag, identity.Commit, identity.ReleaseIndexSHA256
	repository = strings.TrimPrefix(repository, "https://")
	if repository == "albertloky/SBXR" {
		repository = "github.com/" + repository
	}
	return ReleaseFacts{repository: repository, tag: tag, commit: commit, releaseIndexSHA256: indexSHA256, verified: true}
}

type releaseRecord struct {
	Repository         string `json:"repository"`
	Tag                string `json:"tag"`
	Commit             string `json:"commit"`
	ReleaseIndexSHA256 string `json:"release_index_sha256"`
}

type PlatformFacts struct {
	OperatingSystem string `json:"operating_system"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture"`
}

type UnitStatus string

const (
	UnitActive   UnitStatus = "Active"
	UnitInactive UnitStatus = "Inactive"
	UnitFailed   UnitStatus = "Failed"
	UnitUnknown  UnitStatus = "Unknown"
)

type UnitSummary struct {
	Unit   string     `json:"unit"`
	Status UnitStatus `json:"status"`
}

type ReplacementReview struct{ archive string }

func ReviewBundleReplacement(archive string) ReplacementReview {
	if !validBundleName(archive) {
		return ReplacementReview{}
	}
	return ReplacementReview{archive: archive}
}

type BundleRequest struct {
	Check       CheckResult
	Events      []DiagnosticEvent
	Release     ReleaseFacts
	Platform    PlatformFacts
	Units       []UnitSummary
	Replacement ReplacementReview
}

type BundleCandidate struct {
	name, replacement string
	archive           []byte
	verified          bool
}

func (candidate BundleCandidate) Name() string        { return candidate.name }
func (candidate BundleCandidate) Replacement() string { return candidate.replacement }
func (candidate BundleCandidate) Archive() []byte     { return append([]byte(nil), candidate.archive...) }
func (candidate BundleCandidate) Verified() bool      { return candidate.verified }

type BundleStorage interface {
	Existing() ([]string, error)
	Publish(BundleCandidate) error
}

func (result BundleResult) Status() BundleStatus        { return result.status }
func (result BundleResult) Code() FindingCode           { return result.code }
func (result BundleResult) ArchiveName() string         { return result.archive }
func (result BundleResult) ExternalCopyWarning() string { return result.warning }
func (result BundleResult) ReplacementCandidates() []string {
	return append([]string(nil), result.replacementCandidates...)
}

type bundleFacts struct {
	Schema              string             `json:"schema"`
	CreatedAt           time.Time          `json:"created_at"`
	InstallationStatus  InstallationStatus `json:"installation_status"`
	Findings            []EventRecord      `json:"findings"`
	Events              []EventRecord      `json:"events"`
	Release             releaseRecord      `json:"release"`
	Platform            PlatformFacts      `json:"platform"`
	Units               []UnitSummary      `json:"units"`
	ExternalCopyWarning string             `json:"external_copy_warning"`
}

type bundleManifest struct {
	Schema              string               `json:"schema"`
	CreatedAt           time.Time            `json:"created_at"`
	Items               []bundleManifestItem `json:"items"`
	ExternalCopyWarning string               `json:"external_copy_warning"`
}

type bundleManifestItem struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func (module Interface) BuildSupportBundle(storage BundleStorage, request BundleRequest) BundleResult {
	if storage == nil || !request.Check.bundleReady || len(request.Check.events) == 0 || !validRelease(request.Release) || !validPlatform(request.Platform) || !validUnits(request.Units) {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-INPUT")
	}
	existing, err := storage.Existing()
	if err != nil || !validExistingBundles(existing) {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-STORAGE")
	}
	sort.Strings(existing)
	replacement := request.Replacement.archive
	if len(existing) == 3 {
		if !contains(existing, replacement) {
			return BundleResult{status: BundleNotCreated, code: "HEALTH-DIAGNOSTICS-BUNDLE-REPLACEMENT-REVIEW-REQUIRED", replacementCandidates: append([]string(nil), existing...)}
		}
	} else if replacement != "" {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-REPLACEMENT-INVALID")
	}

	createdAt := module.now().UTC()
	name := "sbxr-support-" + createdAt.Format("20060102T150405Z") + ".tar.gz"
	if contains(existing, name) {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-NAME-COLLISION")
	}
	facts, ok := bundleRequestFacts(request, createdAt)
	if !ok {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-INPUT")
	}
	items, ok := bundleItems(facts)
	if !ok {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-SIZE")
	}
	archive, err := module.compress(items, createdAt)
	if err != nil || len(archive) > BundleArchiveBytes || verifyBundle(archive, items) != nil {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-CANDIDATE")
	}
	candidate := BundleCandidate{name: name, archive: archive, replacement: replacement, verified: true}
	if err := storage.Publish(candidate); err != nil {
		return bundleFailure("HEALTH-DIAGNOSTICS-BUNDLE-PUBLICATION")
	}
	return BundleResult{status: BundleCreated, code: "HEALTH-DIAGNOSTICS-BUNDLE-CREATED", archive: name, warning: externalCopyWarning}
}

func bundleRequestFacts(request BundleRequest, createdAt time.Time) (bundleFacts, bool) {
	findings := make([]EventRecord, len(request.Check.events))
	for index, event := range request.Check.events {
		if !validDiagnosticEvent(event) {
			return bundleFacts{}, false
		}
		findings[index] = event.Record()
	}
	events := make([]EventRecord, len(request.Events))
	for index, event := range request.Events {
		if !validDiagnosticEvent(event) {
			return bundleFacts{}, false
		}
		events[index] = event.Record()
	}
	return bundleFacts{
		Schema: "sbxr-support-bundle-v1", CreatedAt: createdAt, InstallationStatus: request.Check.bundleStatus,
		Findings: findings, Events: events, Release: request.Release.record(), Platform: request.Platform,
		Units: append([]UnitSummary(nil), request.Units...), ExternalCopyWarning: externalCopyWarning,
	}, true
}

func bundleItems(facts bundleFacts) (map[string][]byte, bool) {
	structured, err := json.MarshalIndent(facts, "", "  ")
	if err != nil {
		return nil, false
	}
	plain := plainBundle(facts)
	items := map[string][]byte{"facts.json": structured, "report.txt": plain}
	manifest := bundleManifest{Schema: "sbxr-support-bundle-manifest-v1", CreatedAt: facts.CreatedAt, ExternalCopyWarning: externalCopyWarning}
	for _, name := range []string{"facts.json", "report.txt"} {
		digest := sha256.Sum256(items[name])
		manifest.Items = append(manifest.Items, bundleManifestItem{Name: name, Bytes: len(items[name]), SHA256: hex.EncodeToString(digest[:])})
	}
	items["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, false
	}
	total := 0
	for name, body := range items {
		if len(body) == 0 || len(body) > BundleItemBytes || forbiddenBundleContent(name, body) {
			return nil, false
		}
		total += len(body)
	}
	return items, total <= BundleTotalBytes
}

func plainBundle(facts bundleFacts) []byte {
	var report strings.Builder
	report.WriteString("SBXR support bundle\nCreated: " + facts.CreatedAt.Format(time.RFC3339) + "\nInstallation: " + string(facts.InstallationStatus) + "\n")
	report.WriteString("Release: " + facts.Release.Repository + " " + facts.Release.Tag + " " + facts.Release.Commit + " " + facts.Release.ReleaseIndexSHA256 + "\n")
	report.WriteString("Platform: " + facts.Platform.OperatingSystem + " " + facts.Platform.Version + " " + facts.Platform.Architecture + "\nFindings:\n")
	for _, finding := range facts.Findings {
		report.WriteString(plainEvent(finding))
	}
	report.WriteString("Events:\n")
	for _, event := range facts.Events {
		report.WriteString(plainEvent(event))
	}
	report.WriteString("Units:\n")
	for _, unit := range facts.Units {
		report.WriteString("- " + unit.Unit + " | " + string(unit.Status) + "\n")
	}
	report.WriteString("Warning: " + externalCopyWarning + "\n")
	return []byte(report.String())
}

func plainEvent(event EventRecord) string {
	return "- " + event.Time.Format(time.RFC3339) + " | " + string(event.Module) + " | " + string(event.OperationID) + " | " + string(event.ChangeSetID) + " | " + string(event.Severity) + " | " + string(event.Code) + " | " + event.Explanation + " | " + string(event.Outcome) + "\n"
}

func compressBundle(items map[string][]byte, createdAt time.Time) ([]byte, error) {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	compressed.Header.ModTime = createdAt
	archive := tar.NewWriter(compressed)
	for _, name := range []string{"manifest.json", "report.txt", "facts.json"} {
		body := items[name]
		header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: createdAt, Typeflag: tar.TypeReg}
		if archive.WriteHeader(header) != nil {
			return nil, errors.New("bundle header failed")
		}
		if written, err := archive.Write(body); err != nil || written != len(body) {
			return nil, errors.New("bundle write failed")
		}
	}
	if archive.Close() != nil || compressed.Close() != nil {
		return nil, errors.New("bundle compression failed")
	}
	return output.Bytes(), nil
}

func verifyBundle(candidate []byte, expected map[string][]byte) error {
	items, err := readCompletedBundle(candidate)
	if err != nil || len(items) != len(expected) {
		return errors.New("bundle candidate is invalid")
	}
	for name, body := range expected {
		if !bytes.Equal(items[name], body) {
			return errors.New("bundle candidate is invalid")
		}
	}
	return nil
}

func ValidCompletedBundle(candidate []byte) bool {
	_, err := readCompletedBundle(candidate)
	return err == nil
}

func readCompletedBundle(candidate []byte) (map[string][]byte, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(candidate))
	if err != nil {
		return nil, err
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	expected := map[string]bool{"manifest.json": true, "report.txt": true, "facts.json": true}
	items := map[string][]byte{}
	seen := map[string]bool{}
	total := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || header.Mode != 0o600 || seen[header.Name] || !expected[header.Name] || header.Size <= 0 || header.Size > BundleItemBytes {
			return nil, errors.New("bundle candidate is invalid")
		}
		body, err := io.ReadAll(io.LimitReader(reader, BundleItemBytes+1))
		if err != nil || int64(len(body)) != header.Size || forbiddenBundleContent(header.Name, body) {
			return nil, errors.New("bundle candidate is invalid")
		}
		seen[header.Name] = true
		items[header.Name] = body
		total += len(body)
	}
	trailing, trailingErr := io.ReadAll(io.LimitReader(compressed, 1))
	if len(seen) != len(expected) || total > BundleTotalBytes || trailingErr != nil || len(trailing) != 0 || compressed.Close() != nil || !validCompletedBundleItems(items) {
		return nil, errors.New("bundle candidate is incomplete")
	}
	return items, nil
}

func validCompletedBundleItems(items map[string][]byte) bool {
	var facts bundleFacts
	var manifest bundleManifest
	if !decodeExactJSON(items["facts.json"], &facts) || !decodeExactJSON(items["manifest.json"], &manifest) || facts.Schema != "sbxr-support-bundle-v1" || manifest.Schema != "sbxr-support-bundle-manifest-v1" || facts.CreatedAt.IsZero() || facts.CreatedAt.Location() != time.UTC || manifest.CreatedAt != facts.CreatedAt || facts.ExternalCopyWarning != externalCopyWarning || manifest.ExternalCopyWarning != externalCopyWarning || !validInstallationStatus(facts.InstallationStatus) || !validReleaseRecord(facts.Release) || !validPlatform(facts.Platform) || !validUnits(facts.Units) || !validEventRecords(facts.Findings, true) || !validEventRecords(facts.Events, false) || !bytes.Equal(items["report.txt"], plainBundle(facts)) || len(manifest.Items) != 2 {
		return false
	}
	for index, name := range []string{"facts.json", "report.txt"} {
		item := manifest.Items[index]
		digest := sha256.Sum256(items[name])
		if item.Name != name || item.Bytes != len(items[name]) || item.SHA256 != hex.EncodeToString(digest[:]) {
			return false
		}
	}
	return true
}

func decodeExactJSON(body []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination) == nil && decoder.Decode(&struct{}{}) == io.EOF
}

func validEventRecords(records []EventRecord, required bool) bool {
	if required && len(records) == 0 {
		return false
	}
	for _, record := range records {
		if _, err := RestoreDiagnosticEvent(record); err != nil {
			return false
		}
	}
	return true
}

func validInstallationStatus(status InstallationStatus) bool {
	return status == NotInstalled || status == Managed || status == ChangeInProgress || status == RecoveryRequired
}

func forbiddenBundleContent(name string, body []byte) bool {
	value := strings.ToLower(name + "\n" + string(body))
	for _, forbidden := range []string{
		"../", "https://", "client_access_value", "infrastructure_secret", "authorization", "private_key", "-----begin ",
		"acme_material", "cloudflare_token", "raw_configuration", "raw_output", "journal_content", "rollback_snapshot",
		"secret-derived", "environment_value", "command_argument", "client_address", "destination_address", "access_log",
		"traffic_history", "telemetry", "upload_url", "credential_test", "packet_capture", "crash_report", "core_dump", "marker-", "secret-marker",
	} {
		if strings.Contains(value, forbidden) {
			return true
		}
	}
	return false
}

func (release ReleaseFacts) record() releaseRecord {
	return releaseRecord{Repository: release.repository, Tag: release.tag, Commit: release.commit, ReleaseIndexSHA256: release.releaseIndexSHA256}
}

func validRelease(release ReleaseFacts) bool {
	return release.verified && validReleaseRecord(release.record())
}

func validReleaseRecord(release releaseRecord) bool {
	return release.Repository == "github.com/albertloky/SBXR" && validTag(release.Tag) && validHex(release.Commit, 40) && validHex(release.ReleaseIndexSHA256, 64)
}

func validPlatform(platform PlatformFacts) bool {
	return platform.OperatingSystem == "Ubuntu Server" && platform.Version == "24.04" && (platform.Architecture == "amd64" || platform.Architecture == "arm64")
}

func validUnits(units []UnitSummary) bool {
	if len(units) == 0 || len(units) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, unit := range units {
		if !knownUnit(unit.Unit) || seen[unit.Unit] || unit.Status != UnitActive && unit.Status != UnitInactive && unit.Status != UnitFailed && unit.Status != UnitUnknown {
			return false
		}
		seen[unit.Unit] = true
	}
	return true
}

func knownUnit(unit string) bool {
	switch unit {
	case "xray.service", "sing-box.service", "cloudflared.service", "sbxr-subscription.service", "sbxr-cert-renew.service", "sbxr-cert-renew.timer", "sbxr-update-check.timer", "sbxr-health-check.service", "sbxr-health-check.timer", "sbxr-recovery.service":
		return true
	default:
		return false
	}
}

func validTag(tag string) bool {
	if len(tag) < 2 || len(tag) > 32 || tag[0] != 'v' {
		return false
	}
	for _, character := range tag[1:] {
		if character >= '0' && character <= '9' || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validExistingBundles(existing []string) bool {
	if len(existing) > 3 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range existing {
		if !validBundleName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func validBundleName(name string) bool {
	if len(name) != len("sbxr-support-20060102T150405Z.tar.gz") || !strings.HasPrefix(name, "sbxr-support-") || !strings.HasSuffix(name, ".tar.gz") {
		return false
	}
	_, err := time.Parse("20060102T150405Z", strings.TrimSuffix(strings.TrimPrefix(name, "sbxr-support-"), ".tar.gz"))
	return err == nil
}

func contains(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func bundleFailure(code FindingCode) BundleResult {
	return BundleResult{status: BundleNotCreated, code: code}
}
