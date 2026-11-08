package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestQ214ExactUnknownSigningReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.140", Sequence: 214, ReleaseID: 437573394,
		Commit: "3c3735dcd3ebca409ccdaba277a0d50deb0b9432", RunID: "42370644704", SigningState: "unknown",
		ReleaseIndexSHA256: "acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69",
		Assets: []observedAsset{
			{ID: 720694599, Name: "install.sh", Size: 76781, Digest: "3a9276acd48156aa72bec598c7cc73c7a2fb59ac5b20cc0f606b390e5a7ccf97"},
			{ID: 720694593, Name: "release-index.json", Size: 609, Digest: "acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69"},
			{ID: 720694592, Name: "sbxr-linux-amd64.tar.gz", Size: 6236680, Digest: "2744f7f9d2c5b5fcc79f061a5b0cff2e7d288a302a1847ee17ec50f2010d1923"},
			{ID: 720694600, Name: "sbxr-linux-arm64.tar.gz", Size: 5335593, Digest: "842b39c302535f6a07927e678a25f05ba028a47f13cddf12c51cf84ebe7cc9df"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 12 || !reflect.DeepEqual(policy[11], expected) {
		t.Fatal("the exact unknown-signing build 214 must be the twelfth reservation")
	}
	prior := sha256.Sum256(mustJSON(policy[:11]))
	if fmt.Sprintf("%x", prior) != "26c3832466dc2d37a81d2b5c730afb312f84f9d5b84b2d197aa8bcf8c8533b25" {
		t.Fatal("the preceding eleven reservation bytes changed")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("unchanged twelve-draft set refused")
	}
	for _, identity := range []struct {
		tag       string
		sequence  uint64
		releaseID int64
	}{
		{expected.Tag, 0, 0}, {"", expected.Sequence, 0}, {"", 0, expected.ReleaseID},
	} {
		if !reservedCandidate(identity.tag, identity.sequence, identity.releaseID) {
			t.Fatal("build 214 identity may be reused")
		}
	}
	if reservedCandidate("v3.1.141", 215, 8) {
		t.Fatal("fresh candidate incorrectly reserved")
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing twelfth": func(o *reservationObservations) { o.Releases = o.Releases[:11] },
		"published":       func(o *reservationObservations) { o.Releases[11].Draft = false },
		"immutable":       func(o *reservationObservations) { o.Releases[11].Immutable = true },
		"prerelease":      func(o *reservationObservations) { o.Releases[11].Prerelease = true },
		"source":          func(o *reservationObservations) { o.Releases[11].Commit = strings.Repeat("a", 40) },
		"asset identity":  func(o *reservationObservations) { o.Releases[11].Assets[0].ID++ },
		"asset bytes":     func(o *reservationObservations) { o.Releases[11].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":      func(o *reservationObservations) { o.Releases[11].Assets[0].Size++ },
		"qualified body":  func(o *reservationObservations) { o.Releases[11].Body = "Qualified" },
		"tag present":     func(o *reservationObservations) { o.Refs[11].Release.State = "present" },
		"burn present":    func(o *reservationObservations) { o.Refs[11].Burn.State = "present" },
		"unknown tag":     func(o *reservationObservations) { o.Refs[11].Release.State = "unavailable" },
		"unknown burn":    func(o *reservationObservations) { o.Refs[11].Burn.State = "unavailable" },
		"duplicate":       func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[11]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			observed := reservationFixture()
			change(&observed)
			if checkCandidateReservations(observed, nil) {
				t.Fatal("changed build 214 authority accepted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("reserved build 214 allowed as a current candidate")
	}
}

func TestQ214ReservationBindsNextCandidateWithoutOmissionOrRelabeling(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.141", 215
	facts.ReservedIdentities = approvedCandidateReservations()
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh candidate with exact reservations: %v", err)
	}
	for name, mutate := range map[string]func(*qualificationFacts){
		"old eleven only":    func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:11] },
		"unsigned":           func(f *qualificationFacts) { f.ReservedIdentities[11].SigningState = "unsigned" },
		"invented signature": func(f *qualificationFacts) { f.ReservedIdentities[11].SigningState = "signed-unqualified" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[11].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"run":            func(f *qualificationFacts) { f.ReservedIdentities[11].RunID = "42370644705" },
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.140" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 214 },
		"skip sequence":  func(f *qualificationFacts) { f.Candidate.BSequence = 216 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("build 214 reservation bypassed")
			}
		})
	}
}
