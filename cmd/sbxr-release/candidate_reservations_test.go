package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func reservationFixture() reservationObservations {
	absent := reservationRef{State: "absent", Value: json.RawMessage("null")}
	o := reservationObservations{Releases: []reservationRelease{}}
	for _, r := range approvedCandidateReservations() {
		o.Refs = append(o.Refs, reservationIdentityRefs{Tag: r.Tag, Release: absent, Burn: absent})
		o.Releases = append(o.Releases, reservationRelease{Assets: r.Assets, Body: "Qualification pending.", Commit: r.Commit, Draft: true, ID: r.ReleaseID, Tag: r.Tag})
	}
	return o
}

func TestCandidateReservationRefusesMissingChangedAndConcurrentAuthority(t *testing.T) {
	for index := range approvedCandidateReservations() {
		for name, change := range map[string]func(*reservationObservations){
			"missing draft":  func(o *reservationObservations) { o.Releases = []reservationRelease{} },
			"duplicate page": func(o *reservationObservations) { o.Releases = append(o.Releases, o.Releases[index]) },
			"other pending draft": func(o *reservationObservations) {
				o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v3.1.132", Draft: true})
			},
			"published":        func(o *reservationObservations) { o.Releases[index].Draft = false },
			"immutable":        func(o *reservationObservations) { o.Releases[index].Immutable = true },
			"prerelease":       func(o *reservationObservations) { o.Releases[index].Prerelease = true },
			"retagged":         func(o *reservationObservations) { o.Releases[index].Tag = "v3.1.132" },
			"replacement id":   func(o *reservationObservations) { o.Releases[index].ID++ },
			"changed commit":   func(o *reservationObservations) { o.Releases[index].Commit = strings.Repeat("a", 40) },
			"changed body":     func(o *reservationObservations) { o.Releases[index].Body = "Qualified" },
			"missing asset":    func(o *reservationObservations) { o.Releases[index].Assets = o.Releases[index].Assets[:3] },
			"changed asset id": func(o *reservationObservations) { o.Releases[index].Assets[0].ID++ },
			"changed digest":   func(o *reservationObservations) { o.Releases[index].Assets[0].Digest = strings.Repeat("a", 64) },
			"changed size":     func(o *reservationObservations) { o.Releases[index].Assets[0].Size++ },
			"new tag":          func(o *reservationObservations) { o.Refs[index].Release.State = "present" },
			"new burn":         func(o *reservationObservations) { o.Refs[index].Burn.State = "present" },
			"unknown tag":      func(o *reservationObservations) { o.Refs[index].Release.State = "unavailable" },
		} {
			t.Run(name, func(t *testing.T) {
				o := reservationFixture()
				change(&o)
				if checkCandidateReservations(o, nil) {
					t.Fatal("unsafe reservation accepted")
				}
			})
		}
	}

	o := reservationFixture()
	if !checkCandidateReservations(o, nil) {
		t.Fatal("unchanged retained draft refused")
	}
	o.Releases = append(o.Releases, reservationRelease{ID: 8, Tag: "v3.1.132", Draft: true})
	if !checkCandidateReservations(o, []string{"v3.1.132"}) {
		t.Fatal("current candidate draft refused")
	}
	if checkCandidateReservations(o, []string{"v3.1.129", "v3.1.132"}) {
		t.Fatal("reserved tag allowlist accepted")
	}
	o.Releases[0].Draft = false
	if checkCandidateReservations(o, []string{"v3.1.132"}) {
		t.Fatal("current candidate hid old draft promotion")
	}
}

func TestCandidateReservationBindsSequenceAndPreservesHistoricalReplay(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.132", 206
	facts.ReservedIdentities = approvedCandidateReservations()
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*qualificationFacts){
		"missing reservation": func(f *qualificationFacts) { f.ReservedIdentities = nil },
		"changed reservation": func(f *qualificationFacts) { f.ReservedIdentities[0].SigningState = "unsigned" },
		"duplicate reservation": func(f *qualificationFacts) {
			f.ReservedIdentities = append(f.ReservedIdentities, f.ReservedIdentities[0])
		},
		"reserved tag":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.129" },
		"reserved sequence": func(f *qualificationFacts) { f.Candidate.BSequence = 203 },
		"skipped sequence":  func(f *qualificationFacts) { f.Candidate.BSequence = 207 },
		"published collision": func(f *qualificationFacts) {
			r := qualifiedRelease(false)
			r.Sequence = uint64Pointer(203)
			r.Index.Sequence = 203
			f.Releases = []observedRelease{r}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			change(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("invalid reservation facts accepted")
			}
		})
	}
	facts.ReservedIdentities = nil
	facts.Candidate.BSequence = 203
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
		t.Fatal("legacy facts reused reserved sequence")
	}
	facts.Candidate.BSequence = 206
	release := qualifiedRelease(false)
	release.Sequence = uint64Pointer(204)
	release.Index.Sequence = 204
	facts.Releases = []observedRelease{release}
	if _, err := evaluateCandidatePreflight(facts, mustJSON(facts)); err == nil {
		t.Fatal("later candidate omitted permanent reservation")
	}
	var historical qualificationFacts
	if !decodeCanonical([]byte(initialNormalFacts), &historical) {
		t.Fatal("historical fixture")
	}
	decision, err := evaluateCandidatePreflight(historical, []byte(initialNormalFacts))
	if err != nil || !bytes.Equal(mustJSON(decision), []byte(initialNormalDecision)) {
		t.Fatal("historical decision changed")
	}
	if !reservedCandidate("v3.1.129", 204, 8) || !reservedCandidate("v3.1.132", 203, 8) || !reservedCandidate("v3.1.132", 206, 426359967) {
		t.Fatal("reservation collision incomplete")
	}
}

func TestCandidateReservationCommandAndRealObservationAdapter(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	workspace, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	scripts := filepath.Join(root, ".github/scripts")
	if err = os.MkdirAll(scripts, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"check-candidate-reservations.sh", "observe-github-resource.py"} {
		body, e := os.ReadFile(filepath.Join(workspace, ".github/scripts", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(scripts, name), body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	// The real shell, jq, HTTP classification and Go validator run unchanged.
	// Only network transport and go-run compilation are replaced by inert adapters.
	goAdapter := "#!/bin/sh\ntest \"$1 $2 $3\" = 'run ./cmd/sbxr-release candidate-reservations' || exit 99\nshift 3\nexec \"$RESERVATION_BINARY\" candidate-reservations \"$@\"\n"
	ghAdapter := `#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
if args==['api','repos/albertloky/SBXR/releases?per_page=100','--paginate','--slurp']:
 if os.environ['CASE']=='unavailable':sys.exit(1)
 print(os.environ['PAGES']);sys.exit(0)
if args[:2]==['api','--include'] and args[2] in ['repos/albertloky/SBXR/git/ref/tags/'+t for t in ['v3.1.129','v3.1.130','v3.1.131','release-burned/v3.1.129','release-burned/v3.1.130','release-burned/v3.1.131']]:
 code=403 if os.environ['CASE']=='ref-unavailable' or (os.environ['CASE']=='third-ref-unavailable' and args[2].endswith('v3.1.131')) or (os.environ['CASE']=='second-ref-unavailable' and args[2].endswith('v3.1.130')) else (200 if (os.environ['CASE']=='third-burn-present' and args[2].endswith('release-burned/v3.1.131')) or os.environ['CASE']=='second-burn-present' and args[2].endswith('release-burned/v3.1.130') else 404)
 print('HTTP/2.0 '+str(code)+' Fixture\nContent-Type: application/json\n\n{}');sys.exit(0 if code==200 else 1)
sys.exit(99)
`
	for name, body := range map[string]string{"go": goAdapter, "gh": ghAdapter} {
		if err = os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	r := approvedCandidateReservations()[0]
	releases := []any{}
	for _, reservation := range approvedCandidateReservations() {
		assets := []map[string]any{}
		for _, a := range reservation.Assets {
			assets = append(assets, map[string]any{"id": a.ID, "name": a.Name, "size": a.Size, "digest": "sha256:" + a.Digest})
		}
		releases = append(releases, map[string]any{"id": reservation.ReleaseID, "tag_name": reservation.Tag, "target_commitish": reservation.Commit, "draft": true, "prerelease": false, "immutable": false, "body": "Qualification pending.", "assets": assets})
	}
	for _, name := range []string{"retained", "published-without-digest", "current-candidate", "unexpected-candidate", "missing", "malformed", "unavailable", "ref-unavailable", "second-ref-unavailable", "second-burn-present", "second-missing", "third-missing", "third-ref-unavailable", "third-burn-present", "duplicate-page"} {
		t.Run(name, func(t *testing.T) {
			pages := any([]any{releases})
			switch name {
			case "published-without-digest", "current-candidate", "unexpected-candidate":
				other := map[string]any{"id": 8, "tag_name": "v3.1.132", "target_commitish": r.Commit, "draft": name != "published-without-digest", "prerelease": false, "immutable": name == "published-without-digest", "body": nil, "assets": []any{map[string]any{"digest": nil}}}
				pages = []any{append(append([]any{}, releases...), other)}

			case "third-missing":
				pages = []any{releases[:2]}
			case "second-missing":
				pages = []any{releases[:1]}
			case "missing":
				pages = []any{[]any{}}
			case "malformed":
				pages = []any{map[string]any{}}
			case "duplicate-page":
				pages = []any{releases, releases}
			}
			raw, _ := json.Marshal(pages)
			args := []string{filepath.Join(scripts, "check-candidate-reservations.sh")}
			if name == "current-candidate" {
				args = append(args, `["v3.1.132"]`)
			}
			command := exec.Command("bash", args...)
			command.Dir = root
			command.Env = append(os.Environ(), "PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"), "RESERVATION_BINARY="+binary, "GITHUB_REPOSITORY=albertloky/SBXR", "CASE="+name, "PAGES="+string(raw), "PYTHONDONTWRITEBYTECODE=1")
			output, e := command.CombinedOutput()
			if name == "retained" || name == "published-without-digest" || name == "current-candidate" {
				if e != nil || !bytes.Equal(output, mustJSON(approvedCandidateReservations())) {
					t.Fatalf("retained draft: %v %s", e, output)
				}
			} else if e == nil {
				t.Fatalf("unsafe observation accepted: %s", output)
			}
		})
	}
	for _, raw := range []string{"", `{}`, string(mustJSON(reservationFixture())) + "\n", `{"burn":null,"burn":null}`} {
		if runCandidateReservations(nil, strings.NewReader(raw), &bytes.Buffer{}) == nil {
			t.Fatal("malformed/duplicate observation accepted")
		}
	}
}

func TestReservedDraftAllowsFreshCompleteQualificationAndPublication(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	boundary, manifest, evidence := mvpQualificationFixtureWithReservations(t, binary, false, true, true, approvedCandidateReservations())
	document := recurringResultFixture(t, boundary, manifest, evidence)
	result, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("fresh qualification: %v %s", err, result)
	}
	var bf qualificationBoundaryFacts
	var vf candidateDraftVerificationFacts
	var cf candidateDraftConstructionFacts
	var pre qualificationFacts
	var m qualificationManifest
	if !decodeCanonical([]byte(boundary), &bf) || !decodeCanonical(bf.DraftVerificationFacts, &vf) || !decodeCanonical(vf.ConstructionFacts, &cf) || !decodeCanonical(cf.PreflightFacts, &pre) || !decodeCanonical(manifest, &m) {
		t.Fatal("reservation chain decode")
	}
	if pre.Candidate.BSequence != 206 || len(pre.ReservedIdentities) != 3 || pre.ReservedIdentities[0].SigningState != "unknown" || pre.ReservedIdentities[1].SigningState != "signed-unqualified" {
		t.Fatal("reservation not bound to fresh sequence")
	}
	for _, reserved := range approvedCandidateReservations() {
		invalid := vf
		invalid.Observations = append([]observedDraft(nil), vf.Observations...)
		invalid.Observations[0].ReleaseID = reserved.ReleaseID
		invalid.Observations[0].CreatedReleaseID = reserved.ReleaseID
		if _, err := evaluateCandidateDraftVerification(invalid, mustJSON(invalid)); err == nil {
			t.Fatal("reserved release ID reused by fresh qualification")
		}
	}
	assertCleanInstallOnlyPublication(t, binary, pre, m, document, result)
}

func TestSecondReservationCannotBeOmittedRelabeledOrReused(t *testing.T) {
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.132", 206
	for name, mutate := range map[string]func(*qualificationFacts){
		"old policy only": func(f *qualificationFacts) { f.ReservedIdentities = f.ReservedIdentities[:1] },
		"signing unknown": func(f *qualificationFacts) { f.ReservedIdentities[1].SigningState = "unknown" },
		"manifest changed": func(f *qualificationFacts) {
			f.ReservedIdentities[1].QualificationManifestSHA256 = strings.Repeat("a", 64)
		},
		"tag reuse":      func(f *qualificationFacts) { f.Candidate.BTag = "v3.1.130" },
		"sequence reuse": func(f *qualificationFacts) { f.Candidate.BSequence = 204 },
	} {
		t.Run(name, func(t *testing.T) {
			f := facts
			f.ReservedIdentities = approvedCandidateReservations()
			mutate(&f)
			if _, err := evaluateCandidatePreflight(f, mustJSON(f)); err == nil {
				t.Fatal("second reservation bypassed")
			}
		})
	}
	for _, r := range approvedCandidateReservations() {
		if !reservedCandidate(r.Tag, 0, 0) || !reservedCandidate("v3.1.132", r.Sequence, 0) || !reservedCandidate("v3.1.132", 206, r.ReleaseID) {
			t.Fatal("reserved identity collision missed")
		}
	}
	for _, mutate := range []func(*reservationObservations){
		func(o *reservationObservations) { o.Refs = o.Refs[:1] },
		func(o *reservationObservations) { o.Refs[1] = o.Refs[0] },
		func(o *reservationObservations) { o.Refs[1].Release.Value = json.RawMessage(`{}`) },
	} {
		o := reservationFixture()
		mutate(&o)
		if checkCandidateReservations(o, nil) {
			t.Fatal("incomplete or duplicated ref proof accepted")
		}
	}
	if checkCandidateReservations(reservationFixture(), []string{"v3.1.130"}) {
		t.Fatal("signed retained draft allowed as current candidate")
	}
}
