package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild232IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.158", Sequence: 232, ReleaseID: 454275266,
		Commit: "d0b1ed9a1939b14815218c33baad974b7bc6fd43", RunID: "44994457142", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "dd4077698b52304982e9de0df949eb2518fa5e3e94fbce195d04b2bfd3527536",
		QualificationManifestSHA256: "80d7cf2a3f94669c47ed90703f8a6c9681cca656c99762273e5b31bd072ae355",
		Assets: []observedAsset{
			{ID: 778254507, Name: "install.sh", Size: 77206, Digest: "e4c8101a2608d34aa13fbbecd27064f8e8008dcad2a8e9dcd023cf6e04edcf1d"},
			{ID: 778254505, Name: "release-index.json", Size: 609, Digest: "dd4077698b52304982e9de0df949eb2518fa5e3e94fbce195d04b2bfd3527536"},
			{ID: 778254509, Name: "sbxr-linux-amd64.tar.gz", Size: 6254568, Digest: "b45e3019497d831e7af7b29ab0db95a68951f0679a14007dd62b14b5d7d90a5f"},
			{ID: 778254506, Name: "sbxr-linux-arm64.tar.gz", Size: 5340609, Digest: "5b808db55f486beb8c56798d5125dc4b25ea115870fe6230e090f5c32c48926e"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 36 || !reflect.DeepEqual(policy[29], expected) {
		t.Fatal("exact signed-unqualified reservation for build 232 is missing")
	}
	if documentSHA256(mustJSON(policy[:29])) != "7a172f31c6eaa9edf7e67eaa9e774747d160d250e2726387cbcac535057092be" {
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
		t.Fatal("build 232 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.165", 239
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 239 refused: %v", err)
	}
}
