package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild224IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.150", Sequence: 224, ReleaseID: 451038149,
		Commit: "2718e77049ddc15b2013c5425591dca9ef083322", RunID: "44478371554", SigningState: "unknown",
		ReleaseIndexSHA256: "f3ba111127897f96844e52dedad7b7e5b85445d8999154dfe5a3e7d758273e98",
		Assets: []observedAsset{
			{ID: 766801935, Name: "install.sh", Size: 77206, Digest: "f77581a2dbc40a6d701d0ef9624070d2662ce02b1f9640b2da285f3836cccde7"},
			{ID: 766801934, Name: "release-index.json", Size: 609, Digest: "f3ba111127897f96844e52dedad7b7e5b85445d8999154dfe5a3e7d758273e98"},
			{ID: 766801933, Name: "sbxr-linux-amd64.tar.gz", Size: 6245862, Digest: "9344aab30a66c052468d681fe5a7e8b2e31467834e33c0a4bf88cfc648152412"},
			{ID: 766801936, Name: "sbxr-linux-arm64.tar.gz", Size: 5338718, Digest: "0eaead6db2c8a484f5f90d1b852a9993b88ec7cfe96f2ec851c48023e7e836bb"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 26 || !reflect.DeepEqual(policy[21], expected) {
		t.Fatal("exact build 224 reservation is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:21]))); got != "1993110b4a9ea2f0aeee3690d45df42e52183681b1c5d17ae4303d7a0a5fa8ef" {
		t.Fatal("an earlier reservation changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) ||
		!reservedCandidate("", expected.Sequence, 0) ||
		!reservedCandidate("", 0, expected.ReleaseID) {
		t.Fatal("retired build can be reused by tag, sequence or draft ID")
	}
	observed := reservationFixture()
	if !checkCandidateReservations(observed, nil) ||
		checkCandidateReservations(observed, []string{expected.Tag}) {
		t.Fatal("build 224 must be preserved and unavailable to the current candidate")
	}
	for _, signingState := range []string{"unsigned", "signed-unqualified"} {
		facts := candidateFacts("v3")
		facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
		facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.155", 229
		facts.ReservedIdentities = approvedCandidateReservations()
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
			t.Fatalf("fresh build 229 refused: %v", err)
		}
		facts.ReservedIdentities[21].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatal("build 224 signing authority was relabeled")
		}
	}
}
