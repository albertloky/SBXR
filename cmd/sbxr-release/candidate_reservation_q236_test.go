package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild236IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.162", Sequence: 236, ReleaseID: 454999136,
		Commit: "8c29ef7a65a16ba50fa0c2020bee325ebea686af", RunID: "45108911492", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "11296eec38cd27eaae81c95b2ba684b190d3cced3f776ecba0c184499148267b",
		QualificationManifestSHA256: "d3c470c314e4dc49cf87a35d37e619bb9bf82b9582e18c5ca545e35e9918ecec",
		Assets: []observedAsset{
			{ID: 781564659, Name: "install.sh", Size: 77206, Digest: "43fcba6924849bc4ef4ecd20342a074d545e1e662779efdbc94d00abed3b1b70"},
			{ID: 781564658, Name: "release-index.json", Size: 609, Digest: "11296eec38cd27eaae81c95b2ba684b190d3cced3f776ecba0c184499148267b"},
			{ID: 781564657, Name: "sbxr-linux-amd64.tar.gz", Size: 6254562, Digest: "3df54af16298e8ea8afb18fead11a868adc3d9f6ecb14b0e4480ba75aabcb065"},
			{ID: 781564660, Name: "sbxr-linux-arm64.tar.gz", Size: 5340624, Digest: "8de68b912819567acd16e7ef4d31fb40a562396a725474ff0bf6fc14a6dc2e2f"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 41 || !reflect.DeepEqual(policy[33], expected) {
		t.Fatal("exact build 236 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:33])) != "ff9f7e52e62f532397d32e09ea2241d2225fa3df3f8f74c760434bcaa700b567" {
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
		t.Fatal("build 236 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.170", 244
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 244 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[33].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 236 signing authority accepted the label %q", signingState)
		}
	}
}
