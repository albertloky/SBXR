package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestQ219SignedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.145", Sequence: 219, ReleaseID: 445854747,
		Commit: "2443140fcb9fee0180e520350ad9e2cf46263629", RunID: "43681700607", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "1345061e29b4ffaa3b2da16cf150710271bff2e9a59e0fa48bceb5a429c92f0d",
		QualificationManifestSHA256: "a5fa50f2b04c5b85a4dd743500b188ad83c8424d70b3786b0eb1ac3455445d07",
		Assets: []observedAsset{
			{ID: 750053230, Name: "install.sh", Size: 76781, Digest: "5333f5b426283cf56fafab48b709b9664ad8f68baa22a1cc9c26c8c165ace75f"},
			{ID: 750053233, Name: "release-index.json", Size: 609, Digest: "1345061e29b4ffaa3b2da16cf150710271bff2e9a59e0fa48bceb5a429c92f0d"},
			{ID: 750053229, Name: "sbxr-linux-amd64.tar.gz", Size: 6238642, Digest: "9efaf8b8645c79cef576840f18b5b8a961a2116f75e6c5190f734491de3d8269"},
			{ID: 750053231, Name: "sbxr-linux-arm64.tar.gz", Size: 5271806, Digest: "0a1b95bfaf19ff9efb28e2846a23255c877610d569fb517fe0c02cf8708d4947"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 39 || !reflect.DeepEqual(policy[16], expected) {
		t.Fatal("exact signed build 219 reservation missing")
	}
	if fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:16]))) != "2d22f822b492e55bdd3abfa5bc0681719c06aaa2a36cb5580f38baba34dde680" {
		t.Fatal("prior sixteen reservation bytes changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) || !reservedCandidate("", 219, 0) || !reservedCandidate("", 0, 445854747) {
		t.Fatal("retained identity reusable")
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("retained draft allowed as current candidate")
	}
	for _, mutate := range []func(*qualificationFacts){
		func(f *qualificationFacts) { f.Candidate.BTag = expected.Tag },
		func(f *qualificationFacts) { f.Candidate.BSequence = 219 },
		func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:16] },
		func(f *qualificationFacts) { f.ReservedIdentities[16].SigningState = "unknown" },
		func(f *qualificationFacts) { f.ReservedIdentities[16].QualificationManifestSHA256 = "" },
	} {
		f := candidateFacts("v3")
		f.Candidate.ATag = ""
		f.Candidate.ASequence = 0
		f.Candidate.BTag = "v3.1.168"
		f.Candidate.BSequence = 242
		f.ReservedIdentities = approvedCandidateReservations()
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err != nil {
			t.Fatalf("fresh build 242 refused: %v", err)
		}
		mutate(&f)
		if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
			t.Fatal("reserved authority bypassed")
		}
	}
}
