package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestQ212ExactSignedUnqualifiedReservation(t *testing.T) {
	expected := candidateReservation{
		Tag: "v3.1.138", Sequence: 212, ReleaseID: 434759360,
		Commit: "13431bc29500bf20dc108dc325590403d0ca056c", RunID: "41958829811", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "f006de0f4719bc8a6fe21af86a11fd837cc20cf7e73911e13b905e0cdd187a98",
		QualificationManifestSHA256: "30bbbeb56f16bb16ebc6be0cb2dbfa305cc16e403d0c3a609dc0918ac2591b74",
		Assets: []observedAsset{
			{ID: 711955170, Name: "install.sh", Size: 76781, Digest: "ce5eb38b4ed36acaa538cba191be8cf6b07c62a57957ed9703095f76634e9263"},
			{ID: 711955169, Name: "release-index.json", Size: 609, Digest: "f006de0f4719bc8a6fe21af86a11fd837cc20cf7e73911e13b905e0cdd187a98"},
			{ID: 711955171, Name: "sbxr-linux-amd64.tar.gz", Size: 6231778, Digest: "38b156d63f4f0fb9e56ed184298578497b27a6a78a086b97cc3399620a69db76"},
			{ID: 711955172, Name: "sbxr-linux-arm64.tar.gz", Size: 5332376, Digest: "0b47b5925a941ffc7c46d7f45dda305b4551456cf43b6138d32437c5b5543253"},
		},
	}
	policy := approvedCandidateReservations()
	if len(policy) != 15 || !reflect.DeepEqual(policy[9], expected) {
		t.Fatal("the exact signed, unqualified build 212 must be the tenth reservation")
	}
	observed := reservationFixture()
	if !checkCandidateReservations(observed, nil) {
		t.Fatal("unchanged fifteen-draft set refused")
	}
	for _, identity := range []struct {
		tag       string
		sequence  uint64
		releaseID int64
	}{
		{expected.Tag, 0, 0}, {"", expected.Sequence, 0}, {"", 0, expected.ReleaseID},
	} {
		if !reservedCandidate(identity.tag, identity.sequence, identity.releaseID) {
			t.Fatal("build 212 identity may be reused")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing tenth":  func(o *reservationObservations) { o.Releases = o.Releases[:9] },
		"published":      func(o *reservationObservations) { o.Releases[9].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[9].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[9].Prerelease = true },
		"source":         func(o *reservationObservations) { o.Releases[9].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[9].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[9].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[9].Assets[0].Size++ },
		"qualified body": func(o *reservationObservations) { o.Releases[9].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[9].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[9].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[9].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[9]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			observed := reservationFixture()
			change(&observed)
			if checkCandidateReservations(observed, nil) {
				t.Fatal("changed build 212 authority accepted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{expected.Tag}) {
		t.Fatal("reserved build 212 allowed as a current candidate")
	}
}

func TestQ212ReservationBindsNextCandidateWithoutOmissionOrRelabeling(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.144", 218
	facts.ReservedIdentities = approvedCandidateReservations()
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatalf("fresh candidate with exact reservations: %v", err)
	}
	for name, mutate := range map[string]func(*qualificationFacts){
		"old nine only":   func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:9] },
		"unsigned":        func(f *qualificationFacts) { f.ReservedIdentities[9].SigningState = "unsigned" },
		"unknown signing": func(f *qualificationFacts) { f.ReservedIdentities[9].SigningState = "unknown" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[9].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"run":            func(f *qualificationFacts) { f.ReservedIdentities[9].RunID = "41958829812" },
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.138" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 212 },
		"skip sequence":  func(f *qualificationFacts) { f.Candidate.BSequence = 219 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("build 212 reservation bypassed")
			}
		})
	}
}
