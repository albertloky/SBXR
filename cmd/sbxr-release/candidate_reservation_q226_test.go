package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild226IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.152", Sequence: 226, ReleaseID: 452235987,
		Commit: "73b0c6d6d47d8b9d11c1e6d571bba60f11373a87", RunID: "44663342311", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "b93b39ab6edef7a0e9cc24e6ef28f3e834dd875bad8eafee09689d1d965419ca",
		QualificationManifestSHA256: "9763600934e3444f34bc089992b09a22052e7500b617ae213530439c0e3f2ea4",
		Assets: []observedAsset{
			{ID: 770307842, Name: "install.sh", Size: 77206, Digest: "4d65c8e9726bbc5f3b178849102709fcd785fdad0df64a30fa1563d84dcababb"},
			{ID: 770307846, Name: "release-index.json", Size: 609, Digest: "b93b39ab6edef7a0e9cc24e6ef28f3e834dd875bad8eafee09689d1d965419ca"},
			{ID: 770307839, Name: "sbxr-linux-amd64.tar.gz", Size: 6254225, Digest: "f39cd56dd8715d47848c560b54d37712e0f09de1637c0f6eff92c7276d8c4d5e"},
			{ID: 770307841, Name: "sbxr-linux-arm64.tar.gz", Size: 5311203, Digest: "5907abe52d0228ff667e74096b4eefbd979562b61cc9c84e3a17b6dddcee96a3"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 26 || !reflect.DeepEqual(policy[23], expected) {
		t.Fatal("exact signed-unqualified reservation for build 226 is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:23]))); got != "4053caf5588740885b00f6e367c834daecb15d9ddea45dc30d1ee412a7895af5" {
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
		t.Fatal("build 226 must be preserved and unavailable to the current candidate")
	}
}
