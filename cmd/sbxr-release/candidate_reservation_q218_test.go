package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestQ218SignedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.144", Sequence: 218, ReleaseID: 445390275,
		Commit: "a04bcd46ce4a3759a9c67f7b43049437a3f8d914", RunID: "43605935683", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "d24d75239e91d0cdb173fdff10fe8ba704c199b6ba6857e8b64bd952021c1d0e",
		QualificationManifestSHA256: "5ae9b2ef3ac4d6621bc88e76ff0e571a31c063761e9e1681c7fdf7f055941a21",
		Assets: []observedAsset{
			{ID: 747892008, Name: "install.sh", Size: 76781, Digest: "f7863549ba929d72d5d5ecc2cc231dacb917f392ff720e4c437674396ad61d8f"},
			{ID: 747892004, Name: "release-index.json", Size: 609, Digest: "d24d75239e91d0cdb173fdff10fe8ba704c199b6ba6857e8b64bd952021c1d0e"},
			{ID: 747892005, Name: "sbxr-linux-amd64.tar.gz", Size: 6238584, Digest: "46536e76e183058d1ed4493054be990df24f5f041fb95e9c2b25580d5b930666"},
			{ID: 747892012, Name: "sbxr-linux-arm64.tar.gz", Size: 5271862, Digest: "6028cbb24789d2c24c01cfb5431f28ea9a741f96d269018a628614d861dfed6c"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 33 || !reflect.DeepEqual(policy[15], expected) {
		t.Fatal("exact signed build 218 reservation missing")
	}
	if fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:15]))) != "84cc1f55bb7b603413bf5b6740afe399b38555e9d7fedddc8df298b22ce38957" {
		t.Fatal("prior fifteen reservation bytes changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) || !reservedCandidate("", 218, 0) || !reservedCandidate("", 0, 445390275) {
		t.Fatal("retained identity reusable")
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("retained draft allowed as current candidate")
	}
	for _, mutate := range []func(*qualificationFacts){
		func(f *qualificationFacts) { f.Candidate.BTag = expected.Tag },
		func(f *qualificationFacts) { f.Candidate.BSequence = 218 },
		func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:15] },
		func(f *qualificationFacts) { f.ReservedIdentities[15].SigningState = "unknown" },
		func(f *qualificationFacts) { f.ReservedIdentities[15].QualificationManifestSHA256 = "" },
	} {
		f := candidateFacts("v3")
		f.Candidate.ATag = ""
		f.Candidate.ASequence = 0
		f.Candidate.BTag = "v3.1.162"
		f.Candidate.BSequence = 236
		f.ReservedIdentities = approvedCandidateReservations()
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err != nil {
			t.Fatalf("fresh build 236 refused: %v", err)
		}
		mutate(&f)
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
			t.Fatal("reserved authority bypassed")
		}
	}
}
