package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild244IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.170", Sequence: 244, ReleaseID: 459294133,
		Commit: "f75bf18f88caf4f882feb4ee5210b65221866acb", RunID: "45798016021", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "08e0feedd89f14e8217e2020b1ffea4ac9ac4db2d23f6022fd10a8927796f53a",
		QualificationManifestSHA256: "2711e184db9e4ffa9c8ef8753a2685e1b22176a825a557cb80d8cd4094d9084c",
		Assets: []observedAsset{
			{ID: 795491249, Name: "install.sh", Size: 77206, Digest: "c84640badd9decfa939f6a6510ab5f04e0ee9181170b458eb00c013a15ad1f48"},
			{ID: 795491251, Name: "release-index.json", Size: 609, Digest: "08e0feedd89f14e8217e2020b1ffea4ac9ac4db2d23f6022fd10a8927796f53a"},
			{ID: 795491244, Name: "sbxr-linux-amd64.tar.gz", Size: 6259763, Digest: "3c66769a2476c6a6e8652980a843644659e74e6f766e4022cc9c7ace9d9d3bb1"},
			{ID: 795491245, Name: "sbxr-linux-arm64.tar.gz", Size: 5333929, Digest: "89ca6bda99cd319c3e849c0a8e46bd00c9f3d24fd7760967f0cd0ec24ae13c38"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 43 || !reflect.DeepEqual(policy[41], expected) {
		t.Fatal("exact build 244 reservation is missing")
	}
	if documentSHA256(mustJSON(policy[:41])) != "ae5fc7b9928eed8e9062721ced4dc53e1b52fb068c7cbf06ee991e56727d48f9" {
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
		t.Fatal("build 244 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.172", 246
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 246 refused: %v", err)
	}
	for _, signingState := range []string{"unsigned", "unknown"} {
		facts.ReservedIdentities = approvedCandidateReservations()
		facts.ReservedIdentities[41].SigningState = signingState
		if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
			t.Fatalf("build 244 signing authority accepted the label %q", signingState)
		}
	}
}
