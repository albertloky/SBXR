package main

import (
	"strings"
	"testing"
)

func TestQ206ExactReservation(t *testing.T) {
	p := approvedCandidateReservations()
	if len(p) != 5 || p[3].Tag != "v3.1.132" || p[3].Sequence != 206 || p[3].ReleaseID != 429718783 || p[3].SigningState != "signed-unqualified" || p[3].RunID != "41165244627" {
		t.Fatal("wrong fourth identity")
	}
	if !checkCandidateReservations(reservationFixture(), nil) {
		t.Fatal("exact set refused")
	}
	for _, a := range []struct {
		tag string
		seq uint64
		id  int64
	}{{"v3.1.132", 0, 0}, {"", 206, 0}, {"", 0, 429718783}} {
		if !reservedCandidate(a.tag, a.seq, a.id) {
			t.Fatal("reuse allowed")
		}
	}
	for name, change := range map[string]func(*reservationObservations){
		"missing fourth": func(o *reservationObservations) { o.Releases = o.Releases[:3] },
		"published":      func(o *reservationObservations) { o.Releases[3].Draft = false },
		"immutable":      func(o *reservationObservations) { o.Releases[3].Immutable = true },
		"prerelease":     func(o *reservationObservations) { o.Releases[3].Prerelease = true },
		"commit":         func(o *reservationObservations) { o.Releases[3].Commit = strings.Repeat("a", 40) },
		"asset identity": func(o *reservationObservations) { o.Releases[3].Assets[0].ID++ },
		"asset bytes":    func(o *reservationObservations) { o.Releases[3].Assets[0].Digest = strings.Repeat("a", 64) },
		"asset size":     func(o *reservationObservations) { o.Releases[3].Assets[0].Size++ },
		"body":           func(o *reservationObservations) { o.Releases[3].Body = "Qualified" },
		"tag present":    func(o *reservationObservations) { o.Refs[3].Release.State = "present" },
		"burn present":   func(o *reservationObservations) { o.Refs[3].Burn.State = "present" },
		"unknown ref":    func(o *reservationObservations) { o.Refs[3].Release.State = "unavailable" },
		"duplicate":      func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[3]) },
		"unrelated draft": func(o *reservationObservations) {
			o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v9.9.9", Draft: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := reservationFixture()
			change(&o)
			if checkCandidateReservations(o, nil) {
				t.Fatal("unsafe fourth admitted")
			}
		})
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.132"}) {
		t.Fatal("reserved allowlist admitted")
	}
}

func TestQ206ReservationCannotBeOmittedOrRelabeled(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.134", 208
	for name, mutate := range map[string]func(*qualificationFacts){
		"old three only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:3] },
		"unsigned":       func(f *qualificationFacts) { f.ReservedIdentities[3].SigningState = "unsigned" },
		"manifest": func(f *qualificationFacts) {
			f.ReservedIdentities[3].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.132" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 206 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("q206 reservation bypassed")
			}
		})
	}
}
