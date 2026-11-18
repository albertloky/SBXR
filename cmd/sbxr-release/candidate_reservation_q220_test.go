package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestQ220SignedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.146", Sequence: 220, ReleaseID: 447230997,
		Commit: "066cbd5aa0814c32d9d6e450fcce30b620249dd9", RunID: "43888940342", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "50adcb3f65a64176a54fa4fe5262543396b1ccba30e8525ab1449c28a73adb40",
		QualificationManifestSHA256: "6ecd1c526d9b6cd714ef4e5a840ec73a0a5268e40f0dac03375194c5605f96c1",
		Assets: []observedAsset{
			{ID: 755378906, Name: "install.sh", Size: 76781, Digest: "7f6bd88269ce91cacde9fbeb98e2e6d37b878778eb6837929826623a46fd54b9"},
			{ID: 755378907, Name: "release-index.json", Size: 609, Digest: "50adcb3f65a64176a54fa4fe5262543396b1ccba30e8525ab1449c28a73adb40"},
			{ID: 755378911, Name: "sbxr-linux-amd64.tar.gz", Size: 6239583, Digest: "76056c60c9f3ced0079c93e37b6bcb905f2f6879e9053a65aa0f2335a709979c"},
			{ID: 755378908, Name: "sbxr-linux-arm64.tar.gz", Size: 5274350, Digest: "89b6f938f7a58d4328a64c91b691b6413470270cef9fdf18e5d04184564339e8"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 19 || !reflect.DeepEqual(policy[17], expected) {
		t.Fatal("exact signed build 220 reservation missing")
	}
	if fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:17]))) != "39d47f77a01126b85c6307f6ff2f4574a5e23e16d212e7c8fe7eec3224b92f10" {
		t.Fatal("prior seventeen reservation bytes changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) || !reservedCandidate("", 220, 0) || !reservedCandidate("", 0, 447230997) {
		t.Fatal("retained identity reusable")
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("retained draft allowed as current candidate")
	}
	for _, mutate := range []func(*qualificationFacts){
		func(f *qualificationFacts) { f.Candidate.BTag = expected.Tag },
		func(f *qualificationFacts) { f.Candidate.BSequence = 220 },
		func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:17] },
		func(f *qualificationFacts) { f.ReservedIdentities[17].SigningState = "unknown" },
		func(f *qualificationFacts) { f.ReservedIdentities[17].QualificationManifestSHA256 = "" },
	} {
		f := candidateFacts("v3")
		f.Candidate.ATag = ""
		f.Candidate.ASequence = 0
		f.Candidate.BTag = "v3.1.148"
		f.Candidate.BSequence = 222
		f.ReservedIdentities = approvedCandidateReservations()
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err != nil {
			t.Fatalf("fresh build 222 refused: %v", err)
		}
		mutate(&f)
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
			t.Fatal("reserved authority bypassed")
		}
	}
}
