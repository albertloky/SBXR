package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
)

func TestRetiredBuild222IsPinnedAndCannotBeReused(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.148", Sequence: 222, ReleaseID: 450141673,
		Commit: "2b1ae4d6c702e6eff433cd418b5d616428e71852", RunID: "44321290506", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "c0898423020a77fd05a691304e9282c8a42b0cf52b63f79fdf9f4fa77e04434b",
		QualificationManifestSHA256: "774894328bd2a6347ce873c9a1a2e3d750e08941bcc0a60bd6422edb029d9551",
		Assets: []observedAsset{
			{ID: 763814976, Name: "install.sh", Size: 77206, Digest: "2c6adbcbd46e5f1bc7800b9a9da9cb4ae660ad18b38942b35f61263527575761"},
			{ID: 763814974, Name: "release-index.json", Size: 609, Digest: "c0898423020a77fd05a691304e9282c8a42b0cf52b63f79fdf9f4fa77e04434b"},
			{ID: 763814968, Name: "sbxr-linux-amd64.tar.gz", Size: 6245711, Digest: "5a0a7279695e4a2339c8c23750ddd8dacd564a6c80bb84b32c3a3faea292083e"},
			{ID: 763814975, Name: "sbxr-linux-arm64.tar.gz", Size: 5338627, Digest: "2d3997e8c2244c04e349ba5339bcf6ff4921e4280e5229a255342b9a875522dc"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 28 || !reflect.DeepEqual(policy[19], expected) {
		t.Fatal("exact signed-unqualified reservation for build 222 is missing")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustJSON(policy[:19]))); got != "5c7f263bfa70493752ed621890d706310d4dc677bac8e27e06d2095cf9692889" {
		t.Fatal("an earlier signed or retained identity changed")
	}
	if !reservedCandidate(expected.Tag, 0, 0) ||
		!reservedCandidate("", expected.Sequence, 0) ||
		!reservedCandidate("", 0, expected.ReleaseID) {
		t.Fatal("retired build can be reused by tag, sequence or draft ID")
	}
	observed := reservationFixture()
	if !checkCandidateReservations(observed, nil) ||
		checkCandidateReservations(observed, []string{expected.Tag}) {
		t.Fatal("build 222 must be preserved and unavailable to the current candidate")
	}
}
