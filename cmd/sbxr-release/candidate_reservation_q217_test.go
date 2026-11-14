package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestQ217Reservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.143", Sequence: 217, ReleaseID: 445168533,
		Commit: "80a35da8c4ef94d15db00762a52e5548459e320a", RunID: "43575753539", SigningState: "unknown",
		ReleaseIndexSHA256: "34db70d4b0e7c07004b4e7931ce5181a73773fe0f924ee0c8268a06ed488086a",
		Assets: []observedAsset{
			{ID: 746937416, Name: "install.sh", Size: 76781, Digest: "6f3952e00c19afd3b7ff3892929381d547bbccc7900975170d7b6a6d5c6a1207"},
			{ID: 746937413, Name: "release-index.json", Size: 609, Digest: "34db70d4b0e7c07004b4e7931ce5181a73773fe0f924ee0c8268a06ed488086a"},
			{ID: 746937418, Name: "sbxr-linux-amd64.tar.gz", Size: 6238647, Digest: "d63beb8f9060b3c77d99150228e6c4b1afd2d3cd12bdf82b34a60083b1bc7e07"},
			{ID: 746937415, Name: "sbxr-linux-arm64.tar.gz", Size: 5271822, Digest: "f9bed1eb1429e5eaf19b3e36353568d41b554f537711d15415014f74e35c7fa6"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 15 || !reflect.DeepEqual(policy[14], expected) {
		t.Fatal("exact retained q217 reservation missing")
	}
	if fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:14]))) != "80a38a9345fd26d44762f4f701912d70fc7c24fe9a44fb5addfa561ce15e49b2" {
		t.Fatal("prior fourteen records changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) || !reservedCandidate("", 217, 0) || !reservedCandidate("", 0, 445168533) {
		t.Fatal("retained identity reusable")
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("retained draft allowed as current candidate")
	}
	for _, mutate := range []func(*qualificationFacts){
		func(f *qualificationFacts) { f.Candidate.BTag = expected.Tag },
		func(f *qualificationFacts) { f.Candidate.BSequence = 217 },
		func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:14] },
		func(f *qualificationFacts) { f.ReservedIdentities[14].SigningState = "unsigned" },
		func(f *qualificationFacts) { f.ReservedIdentities[14].QualificationManifestSHA256 = "invented" },
	} {
		f := candidateFacts("v3")
		f.Candidate.ATag = ""
		f.Candidate.ASequence = 0
		f.Candidate.BTag = "v3.1.144"
		f.Candidate.BSequence = 218
		f.ReservedIdentities = approvedCandidateReservations()
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err != nil {
			t.Fatalf("fresh 218 refused: %v", err)
		}
		mutate(&f)
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
			t.Fatal("reservation bypassed")
		}
	}
}
