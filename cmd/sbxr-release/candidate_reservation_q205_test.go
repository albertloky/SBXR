package main

import (
	"strings"
	"testing"
)

func TestQ205ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 3 || p[2].Tag != "v3.1.131" || p[2].Sequence != 205 || p[2].ReleaseID != 427637410 || p[2].SigningState != "signed-unqualified" || p[2].RunID != "40840504747" {
		t.Fatal("wrong third identity")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.131", 0, 0}, {"", 205, 0}, {"", 0, 427637410}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing third":  func(o *reservationObservations) { o.Releases = o.Releases[:2] },
		"published":      func(o *reservationObservations) { o.Releases[2].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[2].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[2].Prerelease = true },
		"commit":         func(o *reservationObservations) { o.Releases[2].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[2].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[2].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[2].Assets[0].Size++ },
		"body":           func(o *reservationObservations) { o.Releases[2].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[2].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[2].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[2].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[2]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe third admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.131"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ205ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.132", 206
	for name, mutate := range map[string]func(*qualificationFacts){
		"old two only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:2] },
		"unsigned":     func(f *qualificationFacts) { f.ReservedIdentities[2].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[2].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.131" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 205 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q205 reservation bypassed")
			}
		})
	}
}
