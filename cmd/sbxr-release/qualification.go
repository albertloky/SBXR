package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const (
	qualificationFactsSchema    = "sbxr-release-qualification-facts-v1"
	qualificationDecisionSchema = "sbxr-release-qualification-decision-v1"
	candidatePreflightStage     = "candidate-preflight"
	maxQualificationFactsBytes  = 16 << 20
)

type qualificationFacts struct {
	ArchiveCommit          string            `json:"archive_commit"`
	ArchiveRemoteCommit    string            `json:"archive_remote_commit"`
	ArchiveRemoteTagObject string            `json:"archive_remote_tag_object"`
	ArchiveTagObject       string            `json:"archive_tag_object"`
	ArchiveType            string            `json:"archive_type"`
	BurnedIdentities       []burnedIdentity  `json:"burned_identities"`
	Candidate              candidateRequest  `json:"candidate"`
	ChecklistSHA256        string            `json:"checklist_sha256"`
	Commit                 string            `json:"commit"`
	DefectIssue            *defectIssue      `json:"defect_issue"`
	FailedNormalRun        *failedNormalRun  `json:"failed_normal_run"`
	LatestTag              *string           `json:"latest_tag"`
	Releases               []observedRelease `json:"releases"`
	RemoteMain             string            `json:"remote_main"`
	Schema                 string            `json:"schema"`
	Stage                  string            `json:"stage"`
	Tags                   []string          `json:"tags"`
}

type burnedIdentity struct {
	Commit              string `json:"commit"`
	OriginalTag         string `json:"original_tag"`
	QualificationRunURL string `json:"qualification_run_url"`
	Reason              string `json:"reason"`
	RecordedAt          string `json:"recorded_at"`
	ReleaseIndexSHA256  string `json:"release_index_sha256"`
	Sequence            uint64 `json:"sequence"`
}

type candidateRequest struct {
	ASequence         uint64  `json:"a_sequence"`
	ATag              string  `json:"a_tag"`
	BSequence         uint64  `json:"b_sequence"`
	BTag              string  `json:"b_tag"`
	DefectIssueURL    *string `json:"defect_issue_url"`
	FailedNormalRunID *string `json:"failed_normal_run_id"`
	Mode              string  `json:"mode"`
}

type defectIssue struct {
	IsPullRequest bool   `json:"is_pull_request"`
	State         string `json:"state"`
	URL           string `json:"url"`
}

type failedNormalRun struct {
	Conclusion string `json:"conclusion"`
	ID         string `json:"id"`
	Mode       string `json:"mode"`
	Path       string `json:"path"`
}

type observedAsset struct {
	Digest string `json:"digest"`
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
}

type observedIndex struct {
	Commit     string `json:"commit"`
	Repository string `json:"repository"`
	Sequence   uint64 `json:"sequence"`
	SHA256     string `json:"sha256"`
	Tag        string `json:"tag"`
}

type observedRelease struct {
	Assets     []observedAsset `json:"assets"`
	Body       string          `json:"body"`
	Commit     string          `json:"commit"`
	Draft      bool            `json:"draft"`
	ID         int64           `json:"id"`
	Immutable  bool            `json:"immutable"`
	Index      *observedIndex  `json:"index"`
	Prerelease bool            `json:"prerelease"`
	Sequence   *uint64         `json:"sequence"`
	Tag        string          `json:"tag"`
}

type buildReleaseAction struct {
	Commit   string `json:"commit"`
	Sequence uint64 `json:"sequence"`
	Tag      string `json:"tag"`
	Type     string `json:"type"`
}

type decisionAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type decisionReleaseIdentity struct {
	Commit             string `json:"commit"`
	ReleaseIndexSHA256 string `json:"release_index_sha256"`
	Repository         string `json:"repository"`
	Tag                string `json:"tag"`
}

type useSourceReleaseAction struct {
	Assets          []decisionAsset         `json:"assets"`
	Commit          string                  `json:"commit"`
	Draft           bool                    `json:"draft"`
	Immutable       bool                    `json:"immutable"`
	Prerelease      bool                    `json:"prerelease"`
	ReleaseID       int64                   `json:"release_id"`
	ReleaseIdentity decisionReleaseIdentity `json:"release_identity"`
	Sequence        uint64                  `json:"sequence"`
	Tag             string                  `json:"tag"`
	Type            string                  `json:"type"`
}

type qualificationDecision struct {
	Actions     []json.RawMessage `json:"actions"`
	FactsSHA256 string            `json:"facts_sha256"`
	Outcome     string            `json:"outcome"`
	Schema      string            `json:"schema"`
	SourceState string            `json:"source_state"`
	Stage       string            `json:"stage"`
}

func runQualification(input io.Reader, output io.Writer) error {
	document, err := io.ReadAll(io.LimitReader(input, maxQualificationFactsBytes+1))
	if err != nil || len(document) == 0 || len(document) > maxQualificationFactsBytes || softwarelifecycle.ValidateUniqueJSON(document) != nil {
		return errors.New("qualification facts refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var facts qualificationFacts
	if decoder.Decode(&facts) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("qualification facts refused")
	}
	canonical, err := marshalCanonical(facts)
	if err != nil || !bytes.Equal(canonical, document) {
		return errors.New("qualification facts refused")
	}
	decision, err := evaluateCandidatePreflight(facts, document)
	if err != nil {
		return err
	}
	body, err := marshalCanonical(decision)
	if err != nil {
		return errors.New("qualification decision refused")
	}
	_, err = output.Write(body)
	return err
}

func evaluateCandidatePreflight(facts qualificationFacts, document []byte) (qualificationDecision, error) {
	candidate := facts.Candidate
	if facts.Schema != qualificationFactsSchema || facts.Stage != candidatePreflightStage ||
		!validCommit(facts.Commit) || facts.RemoteMain != facts.Commit ||
		!validCommit(facts.ArchiveCommit) || facts.ArchiveCommit != facts.ArchiveRemoteCommit ||
		!validCommit(facts.ArchiveTagObject) || facts.ArchiveTagObject != facts.ArchiveRemoteTagObject ||
		facts.ArchiveType != "tag" ||
		!validSHA256(facts.ChecklistSHA256) || facts.BurnedIdentities == nil || facts.Releases == nil || facts.Tags == nil ||
		!validTag(candidate.ATag) || !validTag(candidate.BTag) || candidate.ATag == candidate.BTag || candidate.ASequence == 0 || candidate.BSequence <= candidate.ASequence ||
		!validObservedFacts(facts) {
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	var actions []json.RawMessage
	var sourceState string
	switch candidate.Mode {
	case "normal":
		if candidate.DefectIssueURL != nil || candidate.FailedNormalRunID != nil || facts.DefectIssue != nil || facts.FailedNormalRun != nil {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		latest, hasQualifiedLatest := qualifiedLatest(facts)
		if !hasQualifiedLatest {
			if tagPresent(facts.Tags, candidate.ATag) || tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.ATag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.ASequence, "") != 0 || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.ATag, candidate.ASequence) || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			highest := highestSequence(facts)
			if candidate.ASequence != highest+1 || candidate.BSequence != candidate.ASequence+1 || highest == 16 && (candidate.ATag != "v2.0.0" || candidate.BTag != "v2.0.1") {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			sourceState = "initial-normal"
			actions = []json.RawMessage{mustJSON(buildReleaseAction{facts.Commit, candidate.ASequence, candidate.ATag, "build-release"}), mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
		} else {
			source, ok := releaseByTag(facts.Releases, candidate.ATag)
			if latest.Tag != candidate.ATag || !ok || !qualifiedStableRelease(source) || source.Index.Sequence != candidate.ASequence || tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.ASequence, "") != 1 || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.ATag, candidate.ASequence) || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) {
				return qualificationDecision{}, errors.New("candidate preflight refused")
			}
			sourceState = "later-normal"
			actions = []json.RawMessage{mustJSON(sourceAction(source)), mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
		}
	case "rescue":
		source, ok := releaseByTag(facts.Releases, candidate.ATag)
		if !ok || candidate.DefectIssueURL == nil || candidate.FailedNormalRunID == nil || facts.DefectIssue == nil || facts.FailedNormalRun == nil ||
			!validRescueAuthority(candidate, *facts.DefectIssue, *facts.FailedNormalRun) || !qualifiedSourceRelease(source, true) ||
			tagPresent(facts.Tags, candidate.BTag) || releaseByTagExists(facts.Releases, candidate.BTag) || sequenceUseCount(facts.Releases, candidate.ASequence, "") != 1 || sequenceUseCount(facts.Releases, candidate.BSequence, "") != 0 || collidesWithBurned(facts.BurnedIdentities, candidate.BTag, candidate.BSequence) ||
			!exactBurnedSource(facts.BurnedIdentities, source, failedRunURL(*candidate.FailedNormalRunID)) || !strings.Contains(source.Body, failedRunURL(*candidate.FailedNormalRunID)) {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		if latest, exists := qualifiedLatest(facts); exists && strings.Contains(latest.Body, "Stable result code: RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION\n") {
			return qualificationDecision{}, errors.New("candidate preflight refused")
		}
		sourceState = "rescue"
		actions = []json.RawMessage{mustJSON(sourceAction(source)), mustJSON(buildReleaseAction{facts.Commit, candidate.BSequence, candidate.BTag, "build-release"})}
	default:
		return qualificationDecision{}, errors.New("candidate preflight refused")
	}
	digest := sha256.Sum256(document)
	return qualificationDecision{
		Actions: actions, FactsSHA256: hex.EncodeToString(digest[:]), Outcome: "accepted", Schema: qualificationDecisionSchema, SourceState: sourceState, Stage: candidatePreflightStage,
	}, nil
}

func validObservedFacts(facts qualificationFacts) bool {
	if !slices.IsSorted(facts.Tags) || !slices.IsSortedFunc(facts.BurnedIdentities, func(a, b burnedIdentity) int { return strings.Compare(a.OriginalTag, b.OriginalTag) }) || !slices.IsSortedFunc(facts.Releases, func(a, b observedRelease) int { return cmp.Compare(a.ID, b.ID) }) {
		return false
	}
	seenTags := map[string]bool{}
	seenIDs := map[int64]bool{}
	seenBurnSequences := map[uint64]bool{}
	seenReleaseSequences := map[uint64]bool{}
	for index, tag := range facts.Tags {
		if !validTag(tag) || index > 0 && tag == facts.Tags[index-1] {
			return false
		}
	}
	for index, burned := range facts.BurnedIdentities {
		if !validBurnedIdentity(burned) || seenBurnSequences[burned.Sequence] || index > 0 && burned.OriginalTag == facts.BurnedIdentities[index-1].OriginalTag {
			return false
		}
		seenBurnSequences[burned.Sequence] = true
	}
	for _, release := range facts.Releases {
		if release.Draft || release.ID <= 0 || seenIDs[release.ID] || seenTags[release.Tag] || !validTag(release.Tag) || !validCommit(release.Commit) || !slices.IsSortedFunc(release.Assets, func(a, b observedAsset) int { return strings.Compare(a.Name, b.Name) }) {
			return false
		}
		seenIDs[release.ID], seenTags[release.Tag] = true, true
		for assetIndex, asset := range release.Assets {
			if asset.ID <= 0 || asset.Name == "" || asset.Size <= 0 || assetIndex > 0 && asset.Name == release.Assets[assetIndex-1].Name {
				return false
			}
		}
		if release.Sequence != nil && (*release.Sequence == 0 || seenReleaseSequences[*release.Sequence]) || release.Index != nil && (release.Sequence == nil || release.Index.Repository != softwarelifecycle.Repository || release.Index.Tag != release.Tag || release.Index.Commit != release.Commit || release.Index.Sequence != *release.Sequence || !validSHA256(release.Index.SHA256)) {
			return false
		}
		if release.Sequence != nil {
			seenReleaseSequences[*release.Sequence] = true
		}
	}
	if facts.LatestTag != nil && !releaseByTagExists(facts.Releases, *facts.LatestTag) {
		return false
	}
	return true
}

func qualifiedLatest(facts qualificationFacts) (observedRelease, bool) {
	if facts.LatestTag == nil {
		return observedRelease{}, false
	}
	release, exists := releaseByTag(facts.Releases, *facts.LatestTag)
	return release, exists && qualifiedStableRelease(release)
}

func highestSequence(facts qualificationFacts) uint64 {
	highest := uint64(16)
	for _, release := range facts.Releases {
		if release.Sequence != nil && *release.Sequence > highest {
			highest = *release.Sequence
		}
	}
	for _, burned := range facts.BurnedIdentities {
		if burned.Sequence > highest {
			highest = burned.Sequence
		}
	}
	return highest
}

func collidesWithBurned(burned []burnedIdentity, tag string, sequence uint64) bool {
	for _, identity := range burned {
		if identity.OriginalTag == tag || identity.Sequence == sequence {
			return true
		}
	}
	return false
}

func releaseByTag(releases []observedRelease, tag string) (observedRelease, bool) {
	for _, release := range releases {
		if release.Tag == tag {
			return release, true
		}
	}
	return observedRelease{}, false
}

func releaseByTagExists(releases []observedRelease, tag string) bool {
	_, ok := releaseByTag(releases, tag)
	return ok
}

func tagPresent(tags []string, want string) bool { return slices.Contains(tags, want) }

func sequenceUseCount(releases []observedRelease, sequence uint64, tag string) int {
	count := 0
	for _, release := range releases {
		if release.Sequence != nil && *release.Sequence == sequence && (tag == "" || release.Tag == tag) {
			count++
		}
	}
	return count
}

func qualifiedSourceRelease(release observedRelease, prerelease bool) bool {
	if release.Draft || release.Prerelease != prerelease || !release.Immutable || release.Index == nil || len(release.Assets) != 4 {
		return false
	}
	expected := softwarelifecycle.LatestReleaseAssetNames()
	for index, asset := range release.Assets {
		if asset.Name != expected[index] || !validSHA256(asset.Digest) || asset.Name == "release-index.json" && asset.Digest != release.Index.SHA256 {
			return false
		}
	}
	return true
}

func qualifiedStableRelease(release observedRelease) bool {
	if !qualifiedSourceRelease(release, false) {
		return false
	}
	required := []string{"# SBXR Installer-Updater Acceptance Record\n", "Status: Qualified\n", "Repository: " + softwarelifecycle.Repository + "\n", "Tag: " + release.Tag + "\n", "Commit: " + release.Commit + "\n", "Sequence: " + strconv.FormatUint(release.Index.Sequence, 10) + "\n", "Release index SHA-256: " + release.Index.SHA256 + "\n", "Module Verification: Passed\n", "Seam Verification: Passed\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64\n", "Codex Live Acceptance: Passed\n", "Owner Acceptance: Not required\n", "Secret-safe result: Passed\n"}
	for _, line := range required {
		if strings.Count(release.Body, line) != 1 {
			return false
		}
	}
	for _, asset := range release.Assets {
		if strings.Count(release.Body, "Asset: "+asset.Name+" "+strconv.FormatInt(asset.Size, 10)+" "+asset.Digest+"\n") != 1 {
			return false
		}
	}
	return strings.Count(release.Body, "Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\n")+strings.Count(release.Body, "Stable result code: RELEASE-INSTALLER-UPDATER-RESCUE-QUALIFICATION\n") == 1 &&
		oneMatch(release.Body, `(?m)^Qualification role: (Clean-installed source release|Discovered, installed, recovered, final latest release|Rescue direct-install and lower-sequence replacement release)$`) &&
		oneMatch(release.Body, `(?m)^Workflow evidence: https://github\.com/albertloky/SBXR/actions/runs/[1-9][0-9]*$`) &&
		oneMatch(release.Body, `(?m)^Runner: Ubuntu Server 24\.04 linux/amd64$`) &&
		oneMatch(release.Body, `(?m)^Go toolchain: go[0-9]+\.[0-9]+\.[0-9]+$`) &&
		oneMatch(release.Body, `(?m)^Public verifier: [0-9]+\.[0-9]+\.[0-9]+ [A-F0-9]{64}$`)
}

func oneMatch(value, pattern string) bool {
	return len(regexp.MustCompile(pattern).FindAllString(value, 2)) == 1
}

func validRescueAuthority(candidate candidateRequest, issue defectIssue, run failedNormalRun) bool {
	if candidate.DefectIssueURL == nil || candidate.FailedNormalRunID == nil || issue.URL != *candidate.DefectIssueURL || issue.State != "open" || issue.IsPullRequest || run.ID != *candidate.FailedNormalRunID || run.Path != ".github/workflows/candidate.yml" || run.Mode != "normal" || run.Conclusion == "success" || run.Conclusion == "" {
		return false
	}
	issueID := strings.TrimPrefix(issue.URL, "https://github.com/"+softwarelifecycle.Repository+"/issues/")
	runID, runErr := strconv.ParseUint(run.ID, 10, 64)
	issueNumber, issueErr := strconv.ParseUint(issueID, 10, 64)
	return runErr == nil && runID > 0 && issueErr == nil && issueNumber > 0
}

func failedRunURL(id string) string {
	return "https://github.com/" + softwarelifecycle.Repository + "/actions/runs/" + id
}

func exactBurnedSource(burned []burnedIdentity, source observedRelease, runURL string) bool {
	matches := 0
	for _, identity := range burned {
		if identity.OriginalTag == source.Tag || identity.Sequence == source.Index.Sequence {
			if identity.OriginalTag != source.Tag || identity.Sequence != source.Index.Sequence || identity.Commit != source.Commit || identity.ReleaseIndexSHA256 != source.Index.SHA256 || identity.QualificationRunURL != runURL {
				return false
			}
			matches++
		}
	}
	return matches == 1
}

func sourceAction(release observedRelease) useSourceReleaseAction {
	assets := make([]decisionAsset, len(release.Assets))
	for index, asset := range release.Assets {
		assets[index] = decisionAsset{Name: asset.Name, SHA256: asset.Digest, Size: asset.Size}
	}
	return useSourceReleaseAction{Assets: assets, Commit: release.Commit, Draft: release.Draft, Immutable: release.Immutable, Prerelease: release.Prerelease, ReleaseID: release.ID, ReleaseIdentity: decisionReleaseIdentity{Commit: release.Commit, ReleaseIndexSHA256: release.Index.SHA256, Repository: softwarelifecycle.Repository, Tag: release.Tag}, Sequence: release.Index.Sequence, Tag: release.Tag, Type: "use-source-release"}
}

func mustJSON(value any) json.RawMessage {
	body, err := marshalCanonical(value)
	if err != nil {
		panic(err)
	}
	return body
}

func marshalCanonical(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func validBurnedIdentity(burned burnedIdentity) bool {
	runID := strings.TrimPrefix(burned.QualificationRunURL, "https://github.com/"+softwarelifecycle.Repository+"/actions/runs/")
	parsedRunID, runErr := strconv.ParseUint(runID, 10, 64)
	_, timeErr := time.Parse(time.RFC3339, burned.RecordedAt)
	return validTag(burned.OriginalTag) && burned.Sequence > 0 && validCommit(burned.Commit) && validSHA256(burned.ReleaseIndexSHA256) && parsedRunID > 0 && runErr == nil && timeErr == nil && burned.Reason != ""
}
