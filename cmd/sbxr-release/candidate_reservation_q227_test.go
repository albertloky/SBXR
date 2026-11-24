package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild227IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.153", Sequence: 227, ReleaseID: 452614336,
		Commit: "6f0f507be44b2b2da1fee9d49947b1bfec974d66", RunID: "44721369198", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "08d832c67bee2c4b5762490a5a17d6f15ded9b303ab02b1c617d9c94d091fbdb",
		QualificationManifestSHA256: "ee2c4887d618324ed73383198caca6261ce72cbf8e15279734868e7e813a39de",
		Assets: []observedAsset{
			{ID: 771584033, Name: "install.sh", Size: 77206, Digest: "fe8e40607bbe326fc10caacfb394208ec43a39c8884fee7800ff54455bae56b4"},
			{ID: 771584036, Name: "release-index.json", Size: 609, Digest: "08d832c67bee2c4b5762490a5a17d6f15ded9b303ab02b1c617d9c94d091fbdb"},
			{ID: 771584042, Name: "sbxr-linux-amd64.tar.gz", Size: 6254244, Digest: "b86f1cac4ffc1b682cc5be25009f4988e2e549e24be03b4fa563404d957020b8"},
			{ID: 771584041, Name: "sbxr-linux-arm64.tar.gz", Size: 5311392, Digest: "0d2e301694bf97d9ec66518df4ade389fe94cbc5a4929c4fe28c280990650027"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 35 || !reflect.DeepEqual(policy[24], expected) {
		t.Fatal("exact signed-unqualified reservation for build 227 is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:24]))); got != "530a20cc294e9e0752eb40822ff9c6fac6b810fcafecef43f6fa48d18def803e" {
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
		t.Fatal("build 227 must be preserved and unavailable to the current candidate")
	}
}
