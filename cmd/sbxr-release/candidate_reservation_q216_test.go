package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestQ216SignedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.142", Sequence: 216, ReleaseID: 443034374,
		Commit: "11aaa5ac6d327d2237fc5fb79bbcff24fc4bc02e", RunID: "43226718845", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "6ff736f4217abecb8237f207453ae571ec1acda25910b6ad87f8e80df4f23ef8",
		QualificationManifestSHA256: "3eefdb8c1f8e9afd0efacda45bfb5c8acbf5c90e58729a333109de9c39c27b5e",
		Assets: []observedAsset{
			{ID: 739727621, Name: "install.sh", Size: 76781, Digest: "5e585878252d639acd5a9d51f38ba2cd5dccb77b0bb54a71a791e1775b3a7103"},
			{ID: 739727622, Name: "release-index.json", Size: 609, Digest: "6ff736f4217abecb8237f207453ae571ec1acda25910b6ad87f8e80df4f23ef8"},
			{ID: 739727626, Name: "sbxr-linux-amd64.tar.gz", Size: 6241059, Digest: "9d13c3986401a5ad646679b31228f25c9ddd914188ce7bb2b39196d4f341bcd7"},
			{ID: 739727618, Name: "sbxr-linux-arm64.tar.gz", Size: 5271842, Digest: "65775973b3c079a77532bbb62e1c289324bf0b7269d41bb79ed467ced4df1b11"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 15 || !reflect.DeepEqual(policy[13], expected) {
		t.Fatal("exact signed build 216 reservation missing")
	}
	if fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:13]))) != "75bbcdff2cb955889129d3c5bb085ecb40666fe6fca26c2ed590c201d1fa620f" {
		t.Fatal("prior thirteen reservation bytes changed")
	}
	for _, mutate := range []func(*qualificationFacts){
		func(f *qualificationFacts) { f.Candidate.BTag = expected.Tag },
		func(f *qualificationFacts) { f.Candidate.BSequence = 216 },
		func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:13] },
		func(f *qualificationFacts) { f.ReservedIdentities[13].SigningState = "unknown" },
		func(f *qualificationFacts) { f.ReservedIdentities[13].QualificationManifestSHA256 = "" },
	} {
		f := candidateFacts("v3")
		f.Candidate.ATag = ""
		f.Candidate.ASequence = 0
		f.Candidate.BTag = "v3.1.144"
		f.Candidate.BSequence = 218
		f.ReservedIdentities = approvedCandidateReservations()
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err != nil {
			t.Fatalf("fresh build 218 refused: %v", err)
		}
		mutate(&f)
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
			t.Fatal("reserved authority bypassed")
		}
	}
}
