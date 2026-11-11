package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestQ213ExactSignedUnqualifiedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.139", Sequence: 213, ReleaseID: 435196915,
		Commit: "f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3", RunID: "42023983739", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf",
		QualificationManifestSHA256: "e0ce70ea6c28537a3f8e33b1f29a6af75f0037ff87b572eb5e0cd201ffa3bc4c",
		Assets: []observedAsset{
			{ID: 713400894, Name: "install.sh", Size: 76781, Digest: "b1d9a300b98cf4a9b43c091df7a4df389e0ec6e095a64220d39777d130156244"},
			{ID: 713400892, Name: "release-index.json", Size: 609, Digest: "be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf"},
			{ID: 713400881, Name: "sbxr-linux-amd64.tar.gz", Size: 6236661, Digest: "b6863602a4c4aeaaaa9e4015b0fd784cfba40a4051b007118d59970a302dc8d5"},
			{ID: 713400886, Name: "sbxr-linux-arm64.tar.gz", Size: 5335640, Digest: "667326fc04d4554fcfcf5fb86d314e04bc4e14f6a307a0d9a20c975ef3e4c7aa"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 13 || !reflect.DeepEqual(policy[10], expected) {
		t.Fatal("the exact signed, unqualified build 213 must be the eleventh reservation")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("unchanged thirteen-draft set refused")
	}
	for _, identity := range []struct {
		tag       string
		sequence  uint64
		releaseID int64
	}{
		{expected.Tag, 0, 0}, {"", expected.Sequence, 0}, {"", 0, expected.ReleaseID},
	} {
		if !reservedCandidate(identity.tag, identity.sequence, identity.releaseID) {
			t.Fatal("build 213 identity may be reused")
		}
	}
	if reservedCandidate("v3.1.142", 216, 8) {
		t.Fatal("fresh candidate incorrectly reserved")
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing eleventh": func(o *reservationObservations) { o.Releases = o.Releases[:10] },
		"published":        func(o *reservationObservations) { o.Releases[10].Draft = false },
		"immutable":        func(o *reservationObservations) { o.Releases[10].Immutable = true },
		"prerelease":       func(o *reservationObservations) { o.Releases[10].Prerelease = true },
		"source":           func(o *reservationObservations) { o.Releases[10].Commit = strings.Repeat("a", 40) },
		"asset identity":   func(o *reservationObservations) { o.Releases[10].Assets[0].ID++ },
		"asset bytes":      func(o *reservationObservations) { o.Releases[10].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":       func(o *reservationObservations) { o.Releases[10].Assets[0].Size++ },
		"qualified body":   func(o *reservationObservations) { o.Releases[10].Body = "Qualified" },
		"tag present":      func(o *reservationObservations) { o.Refs[10].Release.State = "present" },
		"burn present":     func(o *reservationObservations) { o.Refs[10].Burn.State = "present" },
		"unknown tag":      func(o *reservationObservations) { o.Refs[10].Release.State = "unavailable" },
		"unknown burn":     func(o *reservationObservations) { o.Refs[10].Burn.State = "unavailable" },
		"duplicate":        func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[10]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			observed := reservationFixture()
			change(&observed)
			if checkCandidateReservations(observed, nil) {
				t.Fatal("changed build 213 authority accepted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("reserved build 213 allowed as a current candidate")
	}
}

func TestQ213ReservationBindsNextCandidateWithoutOmissionOrRelabeling(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.142", 216
	facts.ReservedIdentities = approvedCandidateReservations()
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh candidate with exact reservations: %v", err)
	}
	for name, mutate := range map[string]func(*qualificationFacts){
		"old ten only":    func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:10] },
		"unsigned":        func(f *qualificationFacts) { f.ReservedIdentities[10].SigningState = "unsigned" },
		"unknown signing": func(f *qualificationFacts) { f.ReservedIdentities[10].SigningState = "unknown" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[10].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"run":            func(f *qualificationFacts) { f.ReservedIdentities[10].RunID = "42023983740" },
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.139" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 213 },
		"skip sequence":  func(f *qualificationFacts) { f.Candidate.BSequence = 217 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("build 213 reservation bypassed")
			}
		})
	}
}
