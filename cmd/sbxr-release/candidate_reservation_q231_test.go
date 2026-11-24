package main

import (
	"reflect"
	"testing"
)

func TestRetiredBuild231IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.157", Sequence: 231, ReleaseID: 453817808,
		Commit: "117082a372d0a88e0752b5394c152be1354fef72", RunID: "44919705888", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "00bf50aab187fe6593356d290ba2cac0b5d577f83cdaff1db52f9d9a71bd6c91",
		QualificationManifestSHA256: "85970e5ec1dd9736e48c52f67712ce80aeecff0e84d9a1e02c1e07e6608cd416",
		Assets: []observedAsset{
			{ID: 776140523, Name: "install.sh", Size: 77206, Digest: "81172be2fea33ff2c75552e6537d6066467eed161d94cac068623993d2fe806f"},
			{ID: 776140520, Name: "release-index.json", Size: 609, Digest: "00bf50aab187fe6593356d290ba2cac0b5d577f83cdaff1db52f9d9a71bd6c91"},
			{ID: 776140522, Name: "sbxr-linux-amd64.tar.gz", Size: 6254783, Digest: "d1fd6b605d68565b3a25104bb19b6a6a59d1370d1546dbb9a494bcc3fd34fff8"},
			{ID: 776140527, Name: "sbxr-linux-arm64.tar.gz", Size: 5340440, Digest: "3d9c794fcd0e46e5e042ffa9ae766ce8379e283f6f77709c3d85ea1fdcfe3faa"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 34 || !reflect.DeepEqual(policy[28], expected) {
		t.Fatal("exact signed-unqualified reservation for build 231 is missing")
	}
	if documentSHA256(mustJSON(policy[:28])) != "ade3cfacc4a282449ed99636d3d11ee2791bf9c94cd03ef645f89f571873fcf3" {
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
		t.Fatal("build 231 must be preserved and unavailable to the current candidate")
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.163", 237
	facts.ReservedIdentities = policy
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh build 237 refused: %v", err)
	}
}
