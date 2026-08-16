package softwarelifecycle_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	ubuntuadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/state"
)

type discoveryReleaseSource struct {
	evidence                     softwarelifecycle.ReleaseEvidence
	listing                      softwarelifecycle.ReleaseListing
	discoverErr, verifyErr       error
	discoveredTag                string
	verifications                int
	extracted, executed, mutated int
}

func (source *discoveryReleaseSource) Discover(_ context.Context, reviewedTag string) (softwarelifecycle.ReleaseListing, error) {
	source.discoveredTag = reviewedTag
	return source.listing, source.discoverErr
}

func (source *discoveryReleaseSource) Verify(context.Context, string) (softwarelifecycle.ReleaseEvidence, error) {
	source.verifications++
	return source.evidence, source.verifyErr
}

func TestDowngradeInputGuidanceAndValidationUseImmutableReleaseTags(t *testing.T) {
	guidance := softwarelifecycle.DowngradeInputGuidance()
	if guidance.URL != "https://github.com/albertloky/SBXR/releases" || !strings.Contains(guidance.AcceptedFormat, "vX.Y.Z") || !strings.Contains(guidance.Purpose, "compatible") {
		t.Fatalf("DowngradeInputGuidance() = %+v", guidance)
	}
	for _, value := range []string{"", "vX.Y.Z", "1.2.3", "v1.2", "v01.2.3", "v1.2.3-rc.1"} {
		if softwarelifecycle.ValidDowngradeTag(value) {
			t.Fatalf("ValidDowngradeTag(%q) = true", value)
		}
	}
	if !softwarelifecycle.ValidDowngradeTag("v1.2.3") {
		t.Fatal("ValidDowngradeTag(v1.2.3) = false")
	}
}

func TestViewDiscoveryHonorsStableAndReviewedAlternateChannels(t *testing.T) {
	tests := []struct {
		name       string
		listing    softwarelifecycle.ReleaseListing
		alternate  string
		want       bool
		wantVerify int
	}{
		{name: "stable release", listing: softwarelifecycle.ReleaseListing{Tag: "v1.1.0"}, want: true, wantVerify: 1},
		{name: "draft", listing: softwarelifecycle.ReleaseListing{Tag: "v1.1.0", Draft: true}},
		{name: "unreviewed prerelease", listing: softwarelifecycle.ReleaseListing{Tag: "v1.1.0-rc.1", Prerelease: true}},
		{name: "reviewed prerelease", listing: softwarelifecycle.ReleaseListing{Tag: "v1.1.0-rc.1", Prerelease: true}, alternate: "v1.1.0-rc.1", want: true, wantVerify: 1},
		{name: "alternate channel cannot cross", listing: softwarelifecycle.ReleaseListing{Tag: "v1.1.0-rc.2", Prerelease: true}, alternate: "v1.1.0-rc.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := updateEvidence(2, test.listing.Tag, strings.Repeat("b", 40))
			source := &discoveryReleaseSource{evidence: evidence, listing: test.listing}
			store := &candidateMemory{}
			module := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt }, store)
			installed := installedRelease(1)
			discovery := softwarelifecycle.StableUpdateDiscovery()
			if test.alternate != "" {
				var err error
				discovery, err = softwarelifecycle.ReviewedAlternateUpdateDiscovery(test.alternate)
				if err != nil {
					t.Fatal(err)
				}
			}

			got := module.View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})

			if (got.VerifiedCandidate != nil) != test.want || got.UpdateEligible != test.want || source.verifications != test.wantVerify || store.replaces != test.wantVerify {
				t.Fatalf("View() = %#v, verifications=%d replaces=%d", got, source.verifications, store.replaces)
			}
		})
	}
}

func TestViewDiscoveryRejectsSameOlderAndIncompatibleReleases(t *testing.T) {
	tests := []struct {
		name      string
		sequence  uint64
		tag       string
		transform func([]byte) []byte
	}{
		{name: "same identity", sequence: 2, tag: "v1.0.0"},
		{name: "automatic downgrade", sequence: 1, tag: "v0.9.0"},
		{name: "newer updater schema", sequence: 2, tag: "v1.1.0", transform: func(index []byte) []byte {
			return replaceIndex(index, `"minimum_updater_schema":1`, `"minimum_updater_schema":2`)
		}},
		{name: "different state schema", sequence: 2, tag: "v1.1.0", transform: func(index []byte) []byte { return replaceIndex(index, `"state_schema":1`, `"state_schema":2`) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := updateEvidence(test.sequence, test.tag, strings.Repeat("b", 40))
			if test.name == "same identity" {
				evidence.Commit = strings.Repeat("a", 40)
				evidence.Index = replaceIndex(evidence.Index, `"commit":"`+strings.Repeat("b", 40)+`"`, `"commit":"`+strings.Repeat("a", 40)+`"`)
			}
			if test.transform != nil {
				evidence.Index = test.transform(evidence.Index)
			}
			refreshIndexAttestation(&evidence)
			source := &discoveryReleaseSource{evidence: evidence, listing: softwarelifecycle.ReleaseListing{Tag: test.tag}}
			store := &candidateMemory{}
			module := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt }, store)
			installed := installedRelease(1)
			if test.name == "same identity" {
				digest := sha256.Sum256(evidence.Index)
				installed.Identity = softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: evidence.Tag, Commit: evidence.Commit, IndexSHA256: hex.EncodeToString(digest[:])}
			}
			discovery := softwarelifecycle.StableUpdateDiscovery()

			got := module.View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})

			if got.Refusal != nil || got.VerifiedCandidate != nil || got.UpdateEligible || store.replaces != 0 {
				t.Fatalf("View() = %#v, replaces=%d", got, store.replaces)
			}
		})
	}
}

func TestViewDiscoveryDoesNotOfferTheRootRuntimeReleaseToV106(t *testing.T) {
	evidence := updateEvidence(2, "v1.1.0", strings.Repeat("b", 40))
	source := &discoveryReleaseSource{evidence: evidence, listing: softwarelifecycle.ReleaseListing{Tag: evidence.Tag}}
	store := &candidateMemory{}
	installed := installedRelease(1)
	installed.Identity.Tag = "v1.0.6"
	discovery := softwarelifecycle.StableUpdateDiscovery()

	got := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt }, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})

	if got.Refusal != nil || got.VerifiedCandidate != nil || got.UpdateEligible || len(got.PermittedActions) != 0 || store.present || store.replaces != 0 {
		t.Fatalf("v1.0.6 discovery = %#v, store=%+v", got, store)
	}
}

func TestViewDiscoveryAcceptsACompleteForwardStateMigrationPath(t *testing.T) {
	evidence := updateEvidenceWithMigration(2, "v1.1.0", strings.Repeat("b", 40))
	source := &discoveryReleaseSource{evidence: evidence, listing: softwarelifecycle.ReleaseListing{Tag: evidence.Tag}}
	store := &candidateMemory{}
	installed := installedRelease(1)
	discovery := softwarelifecycle.StableUpdateDiscovery()

	got := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt }, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if got.Refusal != nil || got.VerifiedCandidate == nil || got.VerifiedCandidate.StateSchema != 2 || len(got.VerifiedCandidate.Migrations) != 1 || !got.UpdateEligible || !strings.Contains(got.MigrationSummary, "complete migration path 1 -> 2") {
		t.Fatalf("View() = %#v", got)
	}
}

func TestViewDiscoveryReplacesOnlyWithNewerAndSurvivesRestart(t *testing.T) {
	oldEvidence := updateEvidence(2, "v1.1.0", strings.Repeat("b", 40))
	store := &candidateMemory{present: true, record: softwarelifecycle.CandidateRecord{Sequence: 2, Evidence: oldEvidence, VerifiedAt: verifiedAt}}
	newEvidence := updateEvidence(3, "v1.2.0", strings.Repeat("c", 40))
	source := &discoveryReleaseSource{evidence: newEvidence, listing: softwarelifecycle.ReleaseListing{Tag: newEvidence.Tag}}
	installed := installedRelease(1)
	discovery := softwarelifecycle.StableUpdateDiscovery()

	got := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt.Add(time.Hour) }, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if got.VerifiedCandidate == nil || got.VerifiedCandidate.Sequence != 3 || store.replaces != 1 {
		t.Fatalf("replacement = %#v, store=%+v", got, store)
	}
	olderEvidence := updateEvidence(2, "v1.1.0", strings.Repeat("b", 40))
	olderSource := &discoveryReleaseSource{evidence: olderEvidence, listing: softwarelifecycle.ReleaseListing{Tag: olderEvidence.Tag}}
	got = softwarelifecycle.NewWithCandidateRetention(olderSource, qualification(), time.Now, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if got.VerifiedCandidate == nil || got.VerifiedCandidate.Sequence != 3 || store.replaces != 1 {
		t.Fatalf("older discovery = %#v, store=%+v", got, store)
	}

	restartedSource := &discoveryReleaseSource{discoverErr: errors.New("offline")}
	got = softwarelifecycle.NewWithCandidateRetention(restartedSource, qualification(), time.Now, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if got.Refusal != nil || got.VerifiedCandidate == nil || got.VerifiedCandidate.Sequence != 3 || store.replaces != 1 || restartedSource.verifications != 0 {
		t.Fatalf("restart = %#v, store=%+v", got, store)
	}
}

func TestViewRefusesTamperedRetainedEvidenceWithoutLeakingIt(t *testing.T) {
	const marker = "PRIVATE-MARKER-UPDATE-CANDIDATE"
	record := softwarelifecycle.CandidateRecord{Sequence: 2, Evidence: updateEvidence(2, "v1.1.0", strings.Repeat("b", 40)), VerifiedAt: verifiedAt}
	record.Evidence.Index = []byte(marker)
	store := &candidateMemory{present: true, record: record}
	installed := installedRelease(1)
	discovery := softwarelifecycle.StableUpdateDiscovery()
	got := softwarelifecycle.NewWithCandidateRetention(&discoveryReleaseSource{}, qualification(), time.Now, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if got.Refusal == nil || got.VerifiedCandidate != nil || strings.Contains(got.Refusal.NextAction, marker) {
		t.Fatalf("View() = %#v", got)
	}
}

func TestViewReportsTheOneDiskRetainedCandidateAfterRestart(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".sbxr-view-candidate-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	directory := filepath.Join(root, "candidates")
	store := ubuntuadapter.NewCandidateStoreAt(directory)
	evidence := updateEvidence(2, "v1.1.0", strings.Repeat("b", 40))
	installed := installedRelease(1)
	discovery := softwarelifecycle.StableUpdateDiscovery()
	source := &discoveryReleaseSource{evidence: evidence, listing: softwarelifecycle.ReleaseListing{Tag: evidence.Tag}}
	first := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt }, store).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if first.VerifiedCandidate == nil {
		t.Fatalf("first View() = %#v", first)
	}

	offline := &discoveryReleaseSource{discoverErr: errors.New("offline")}
	restarted := softwarelifecycle.NewWithCandidateRetention(offline, qualification(), time.Now, ubuntuadapter.NewCandidateStoreAt(directory)).View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})
	if restarted.Refusal != nil || restarted.VerifiedCandidate == nil || restarted.VerifiedCandidate.Identity != first.VerifiedCandidate.Identity || !restarted.UpdateEligible {
		t.Fatalf("restarted View() = %#v", restarted)
	}
}

type candidateMemory struct {
	record   softwarelifecycle.CandidateRecord
	present  bool
	replaces int
	err      error
}

func (memory *candidateMemory) Load() (softwarelifecycle.CandidateRecord, error) {
	if memory.err != nil {
		return softwarelifecycle.CandidateRecord{}, memory.err
	}
	if !memory.present {
		return softwarelifecycle.CandidateRecord{}, softwarelifecycle.ErrCandidateNotFound
	}
	return memory.record, nil
}

func (memory *candidateMemory) RetainNewest(record softwarelifecycle.CandidateRecord) error {
	if !memory.present || record.Sequence > memory.record.Sequence {
		memory.record, memory.present = record, true
		memory.replaces++
	}
	return nil
}

func TestViewDiscoversVerifiesAndRetainsOneHigherStableCandidate(t *testing.T) {
	evidence := updateEvidence(2, "v1.1.0", strings.Repeat("b", 40))
	source := &discoveryReleaseSource{evidence: evidence, listing: softwarelifecycle.ReleaseListing{Tag: evidence.Tag}}
	store := &candidateMemory{}
	module := softwarelifecycle.NewWithCandidateRetention(source, qualification(), func() time.Time { return verifiedAt }, store)
	installed := installedRelease(1)
	discovery := softwarelifecycle.StableUpdateDiscovery()

	got := module.View(t.Context(), softwarelifecycle.ViewRequest{InstallationStatus: softwarelifecycle.Managed, Installed: &installed, UpdateDiscovery: &discovery})

	if got.Refusal != nil || got.VerifiedCandidate == nil || got.VerifiedCandidate.Identity.Tag != "v1.1.0" || !got.UpdateEligible || !reflect.DeepEqual(got.PermittedActions, []softwarelifecycle.Action{softwarelifecycle.ReviewUpdate}) {
		t.Fatalf("View() = %#v", got)
	}
	if source.discoveredTag != "" || store.replaces != 1 || !store.present || store.record.Evidence.Tag != "v1.1.0" || len(store.record.Evidence.Assets) != 5 {
		t.Fatalf("discovery retention = source tag %q, store %+v", source.discoveredTag, store)
	}
	if source.extracted != 0 || source.executed != 0 || source.mutated != 0 {
		t.Fatalf("discovery used candidate: extract=%d execute=%d mutate=%d", source.extracted, source.executed, source.mutated)
	}
}

func installedRelease(sequence uint64) softwarelifecycle.VerifiedRelease {
	return softwarelifecycle.VerifiedRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("a", 64)}, Sequence: sequence, StateSchema: 1, MinimumUpdaterSchema: 1}
}

func updateEvidence(sequence uint64, tag, commit string) softwarelifecycle.ReleaseEvidence {
	evidence := validEvidence()
	evidence.Tag, evidence.Commit = tag, commit
	evidence.Index = replaceIndex(evidence.Index, `"version":"1.0.0"`, `"version":"1.1.0"`)
	evidence.Index = replaceIndex(evidence.Index, `"sequence":1`, `"sequence":`+strconv.FormatUint(sequence, 10))
	evidence.Index = replaceIndex(evidence.Index, `"tag":"v1.0.0"`, `"tag":"`+tag+`"`)
	evidence.Index = replaceIndex(evidence.Index, `"commit":"0123456789abcdef0123456789abcdef01234567"`, `"commit":"`+commit+`"`)
	refreshIndexAttestation(&evidence)
	return evidence
}

func updateEvidenceWithMigration(sequence uint64, tag, commit string) softwarelifecycle.ReleaseEvidence {
	evidence := updateEvidence(sequence, tag, commit)
	evidence.Index = replaceIndex(evidence.Index, `"state_schema":1`, `"state_schema":2`)
	for index, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		metadata := payloadMetadata()
		metadata.Build.Tag, metadata.Build.Commit, metadata.Architecture = tag, commit, architecture
		metadata.StateSchema = 2
		metadata.Schemas["desired-state-v2.schema.json"] = []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"SBXR Desired State v2","type":"object"}`)
		metadata.Migrations = []softwarelifecycle.EmbeddedMigration{{Name: "state-v1-to-v2.json", From: 1, To: 2, Document: state.ReleaseMigrations()["state-v1-to-v2.json"]}}
		stamped, err := softwarelifecycle.StampPayload([]byte("qualified executable"), metadata)
		if err != nil {
			panic(err)
		}
		old := evidence.Assets[index]
		oldDigest := sha256.Sum256(old.Bytes)
		archive := executableArchive(string(stamped))
		newDigest := sha256.Sum256(archive)
		evidence.Index = replaceIndex(evidence.Index,
			fmt.Sprintf(`"name":"%s","size":%d,"sha256":"%s"`, old.Name, len(old.Bytes), hex.EncodeToString(oldDigest[:])),
			fmt.Sprintf(`"name":"%s","size":%d,"sha256":"%s"`, old.Name, len(archive), hex.EncodeToString(newDigest[:])))
		evidence.Assets[index].Bytes = archive
		for proofIndex := range evidence.AttestedAssets {
			if evidence.AttestedAssets[proofIndex].Name == old.Name {
				evidence.AttestedAssets[proofIndex].SHA256 = hex.EncodeToString(newDigest[:])
			}
		}
	}
	refreshIndexAttestation(&evidence)
	return evidence
}

func refreshIndexAttestation(evidence *softwarelifecycle.ReleaseEvidence) {
	digest := sha256.Sum256(evidence.Index)
	evidence.AttestedAssets[0].SHA256 = hex.EncodeToString(digest[:])
}
