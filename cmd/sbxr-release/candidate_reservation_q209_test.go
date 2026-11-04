package main

import (
	"strings"
	"testing"
)

func TestQ209ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 9 || p[6].Tag != "v3.1.135" || p[6].Sequence != 209 || p[6].ReleaseID != 430383576 || p[6].SigningState != "signed-unqualified" || p[6].RunID != "41274423664" {
		t.Fatal("wrong seventh identity")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.135", 0, 0}, {"", 209, 0}, {"", 0, 430383576}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing seventh": func(o *reservationObservations) { o.Releases = o.Releases[:6] },
		"published":       func(o *reservationObservations) { o.Releases[6].Draft = false },
		"immutable":       func(o *reservationObservations) { o.Releases[6].Immutable = true },
		"prerelease":      func(o *reservationObservations) { o.Releases[6].Prerelease = true },
		"commit":          func(o *reservationObservations) { o.Releases[6].Commit = strings.Repeat("a", 40) },
		"asset identity":  func(o *reservationObservations) { o.Releases[6].Assets[0].ID++ },
		"asset bytes":     func(o *reservationObservations) { o.Releases[6].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":      func(o *reservationObservations) { o.Releases[6].Assets[0].Size++ },
		"body":            func(o *reservationObservations) { o.Releases[6].Body = "Qualified" },
		"tag present":     func(o *reservationObservations) { o.Refs[6].Release.State = "present" },
		"burn present":    func(o *reservationObservations) { o.Refs[6].Burn.State = "present" },
		"unknown ref":     func(o *reservationObservations) { o.Refs[6].Release.State = "unavailable" },
		"duplicate":       func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[6]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe seventh admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.135"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ209ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.138", 212
	for name, mutate := range map[string]func(*qualificationFacts){
		"old six only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:6] },
		"unsigned":     func(f *qualificationFacts) { f.ReservedIdentities[6].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[6].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.135" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 209 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q209 reservation bypassed")
			}
		})
	}
}
