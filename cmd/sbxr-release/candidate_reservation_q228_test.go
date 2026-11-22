package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild228IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.154", Sequence: 228, ReleaseID: 453091507,
		Commit: "ae4005f39e7e509cbe7bab489cb8367be4448634", RunID: "44793775813", SigningState: "unknown",
		ReleaseIndexSHA256: "e3444151ab3294e8f47e90ffc99d82a835bf6c94d30442805c79364853b47600",
		Assets: []observedAsset{
			{ID: 773046202, Name: "install.sh", Size: 77206, Digest: "aa820398a3903ecc6f6f3389eada66f7e1fc7b149a62a58220c8eb57c5362892"},
			{ID: 773046204, Name: "release-index.json", Size: 609, Digest: "e3444151ab3294e8f47e90ffc99d82a835bf6c94d30442805c79364853b47600"},
			{ID: 773046203, Name: "sbxr-linux-amd64.tar.gz", Size: 6254039, Digest: "b38f9e7a4febddbaad3627ca0a76968051731d5beea61cf79b117f62383d8256"},
			{ID: 773046200, Name: "sbxr-linux-arm64.tar.gz", Size: 5311348, Digest: "64233488d5a20bf4f697be7a8b37e324d6bf8e179a8124c5f73870be00957059"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 30 || !reflect.DeepEqual(policy[25], expected) {
		t.Fatal("exact build 228 reservation is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:25]))); got != "65ccae2bc6723fdf2232da6ed6ed984d03cf1a5ec92308ef9463e53e305ffd5d" {
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
		t.Fatal("build 228 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.159", 233
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 233 refused: %v", err)
	}
}
