package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestSourceNativeAttestationSelectionAcceptsEquivalentExactProofs(t *testing.T) {
	for _, order := range []string{"exact-only", "older-first", "exact-first", "identical-exact-duplicates", "equivalent-exact-duplicates", "reordered-equivalent", "older-and-equivalent-exacts", "complete-99"} {
		t.Run(order, func(t *testing.T) {
			fixture := newLatestReleaseFixture(t)
			exact, older := nativeSelectionStatements(t, fixture)
			records := []nativeSelectionRecord{nativeSelectionProof("exact", exact)}
			switch order {
			case "older-first":
				records = append([]nativeSelectionRecord{nativeSelectionProof("older", older)}, records...)
			case "exact-first":
				records = append(records, nativeSelectionProof("older", older))
			case "identical-exact-duplicates":
				records = append(records, nativeSelectionProof("duplicate", exact))
			case "reordered-equivalent":
				equivalent := nativeSelectionMutate(t, exact, func(statement map[string]any) {
					subjects := nativeSelectionSubjects(statement)
					subjects[1], subjects[4] = subjects[4], subjects[1]
					for _, field := range []string{"databaseId", "ownerId", "packageId", "repositoryId"} {
						nativeSelectionPredicate(statement)[field] = "another-nonempty-id"
					}
				})
				records = append(records, nativeSelectionProof("reordered-different-ids", equivalent))
			case "complete-99":
				for i := 1; i < 99; i++ {
					records = append(records, nativeSelectionProof(fmt.Sprintf("older-%d", i), older))
				}
			case "equivalent-exact-duplicates", "older-and-equivalent-exacts":
				var pretty bytes.Buffer
				if err := json.Indent(&pretty, exact, "", "  "); err != nil {
					t.Fatal(err)
				}
				records = append(records, nativeSelectionProof("equivalent-different-bundle", pretty.Bytes()))
				if order == "older-and-equivalent-exacts" {
					records = append([]nativeSelectionRecord{nativeSelectionProof("older", older)}, records...)
				}
			}
			source, audit := nativeSelectionSource(t, fixture, records)
			got, outcome := source.CheckLatest(t.Context())
			if outcome != softwarelifecycle.LatestReleaseAccepted || got.Identity.Tag != fixture.release.Tag || got.Identity.Commit != fixtureCommit || got.Sequence != 17 {
				t.Fatalf("CheckLatest() = %#v, %v; want the exact qualified release", got, outcome)
			}
			for _, record := range records {
				if audit.verified[record.key] != 1 {
					t.Errorf("record %q verified %d times; want once before accepting", record.key, audit.verified[record.key])
				}
			}
			if audit.assetFetches != 1 || audit.assetFetchedBeforeAllVerified {
				t.Fatalf("asset fetches = %d, before complete verification = %v; want only the index after every proof", audit.assetFetches, audit.assetFetchedBeforeAllVerified)
			}
		})
	}
}

func TestSourceNativeAttestationSelectionRefusesUnsafeHistories(t *testing.T) {
	for _, name := range []string{"empty", "only-other-tag", "other-tag-with-exact-hashes", "only-conflicting-exact-tag", "conflicting-exact-first", "conflicting-exact-last", "invalid-signature-first", "invalid-signature-last", "non-github-exact", "non-github-first", "non-github-last"} {
		t.Run(name, func(t *testing.T) {
			fixture := newLatestReleaseFixture(t)
			exact, older := nativeSelectionStatements(t, fixture)
			conflicting := nativeSelectionMutate(t, exact, func(statement map[string]any) {
				nativeSelectionSubjects(statement)[1].(map[string]any)["digest"] = map[string]any{"sha256": strings.Repeat("f", 64)}
			})
			target := nativeSelectionProof("exact", exact)
			other := nativeSelectionProof("older", older)
			var records []nativeSelectionRecord
			switch name {
			case "empty":
			case "only-other-tag":
				records = []nativeSelectionRecord{other}
			case "other-tag-with-exact-hashes":
				records = []nativeSelectionRecord{nativeSelectionProof("other", []byte(strings.ReplaceAll(string(exact), fixture.release.Tag, "v1.9.9")))}
			case "only-conflicting-exact-tag":
				records = []nativeSelectionRecord{nativeSelectionProof("conflict", conflicting)}
			case "conflicting-exact-first":
				records = []nativeSelectionRecord{nativeSelectionProof("conflict", conflicting), target}
			case "conflicting-exact-last":
				records = []nativeSelectionRecord{target, nativeSelectionProof("conflict", conflicting)}
			case "invalid-signature-first", "invalid-signature-last":
				other.invalidSignature = true
				records = []nativeSelectionRecord{other, target}
				if name == "invalid-signature-last" {
					records[0], records[1] = records[1], records[0]
				}
			case "non-github-exact":
				target.initiator = "external"
				records = []nativeSelectionRecord{target}
			case "non-github-first", "non-github-last":
				other.initiator = "external"
				records = []nativeSelectionRecord{other, target}
				if name == "non-github-last" {
					records[0], records[1] = records[1], records[0]
				}
			}
			nativeSelectionAssertRefused(t, fixture, records)
		})
	}

	mutations := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong-repository", func(statement map[string]any) { nativeSelectionPredicate(statement)["repository"] = "another/SBXR" }},
		{"wrong-commit", func(statement map[string]any) {
			nativeSelectionSubjects(statement)[0].(map[string]any)["digest"] = map[string]any{"sha1": strings.Repeat("a", 40)}
		}},
		{"wrong-predicate-type", func(statement map[string]any) { statement["predicateType"] = "https://example.invalid/other-predicate" }},
		{"unknown-predicate-field", func(statement map[string]any) { nativeSelectionPredicate(statement)["unexpected"] = "value" }},
		{"unknown-statement-field", func(statement map[string]any) { statement["unexpected"] = true }},
		{"missing-release-id", func(statement map[string]any) { delete(nativeSelectionPredicate(statement), "databaseId") }},
		{"wrong-purl", func(statement map[string]any) {
			nativeSelectionPredicate(statement)["purl"] = "pkg:github/another/SBXR@v1.9.9"
		}},
		{"missing-asset", func(statement map[string]any) { statement["subject"] = nativeSelectionSubjects(statement)[:4] }},
		{"invalid-asset-hash", func(statement map[string]any) {
			nativeSelectionSubjects(statement)[1].(map[string]any)["digest"] = map[string]any{"sha256": "invalid"}
		}},
		{"empty-tag", func(statement map[string]any) { nativeSelectionRetag(statement, "") }},
		{"non-version-tag", func(statement map[string]any) { nativeSelectionRetag(statement, "latest") }},
	}
	for _, mutation := range mutations {
		for _, order := range []string{"unrelated-first", "exact-first"} {
			t.Run(mutation.name+"/"+order, func(t *testing.T) {
				fixture := newLatestReleaseFixture(t)
				exact, older := nativeSelectionStatements(t, fixture)
				bad := nativeSelectionMutate(t, older, mutation.mutate)
				records := []nativeSelectionRecord{nativeSelectionProof("invalid-unrelated", bad), nativeSelectionProof("exact", exact)}
				if order == "exact-first" {
					records[0], records[1] = records[1], records[0]
				}
				nativeSelectionAssertRefused(t, fixture, records)
			})
		}
	}
	for _, bad := range []string{"{", "null", `{"_type":"duplicate","_type":"duplicate"}`} {
		t.Run("malformed-json/"+bad, func(t *testing.T) {
			fixture := newLatestReleaseFixture(t)
			exact, _ := nativeSelectionStatements(t, fixture)
			nativeSelectionAssertRefused(t, fixture, []nativeSelectionRecord{nativeSelectionProof("exact", exact), nativeSelectionProof("malformed", []byte(bad))})
		})
	}
}

func TestSourceNativeAttestationSelectionRefusesSaturatedPageBeforeVerification(t *testing.T) {
	fixture := newLatestReleaseFixture(t)
	exact, older := nativeSelectionStatements(t, fixture)
	records := []nativeSelectionRecord{nativeSelectionProof("exact", exact)}
	for i := 1; i < 100; i++ {
		records = append(records, nativeSelectionProof(fmt.Sprintf("older-%d", i), older))
	}
	source, audit := nativeSelectionSource(t, fixture, records)
	if _, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseRefused {
		t.Fatalf("saturated first page outcome = %v; uniqueness is not established", outcome)
	}
	if len(audit.verified) != 0 || audit.assetFetches != 0 {
		t.Fatalf("saturated page verified %d records and fetched %d assets; want refusal before either", len(audit.verified), audit.assetFetches)
	}
}

func TestSourceNativeAttestationSelectionRefusesLinkedPageBeforeVerification(t *testing.T) {
	for _, link := range []string{`<https://api.github.com/next>; rel="next"`, `<https://api.github.com/last>; rel="last"`, "unparseable"} {
		t.Run(link, func(t *testing.T) {
			fixture := newLatestReleaseFixture(t)
			exact, _ := nativeSelectionStatements(t, fixture)
			source, audit := nativeSelectionSource(t, fixture, []nativeSelectionRecord{nativeSelectionProof("exact", exact)})
			transport := source.client.Transport
			source.client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(request)
				if err == nil && strings.Contains(request.URL.Path, "/attestations/") {
					response.Header.Set("Link", link)
				}
				return response, err
			})
			if _, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseRefused {
				t.Fatalf("linked incomplete page outcome = %v; want refusal", outcome)
			}
			if len(audit.verified) != 0 || audit.assetFetches != 0 {
				t.Fatalf("linked page verified %d records and fetched %d assets; want refusal before either", len(audit.verified), audit.assetFetches)
			}
		})
	}
}

func TestSourceNativeAttestationSelectionStopsOnCancellation(t *testing.T) {
	for _, when := range []string{"before-verifier", "after-verifier"} {
		t.Run(when, func(t *testing.T) {
			fixture := newLatestReleaseFixture(t)
			exact, _ := nativeSelectionStatements(t, fixture)
			source, audit := nativeSelectionSource(t, fixture, []nativeSelectionRecord{nativeSelectionProof("exact", exact)})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wantVerified := 0
			if when == "before-verifier" {
				transport := source.client.Transport
				source.client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					response, err := transport.RoundTrip(request)
					if err == nil && strings.Contains(request.URL.Path, "/attestations/") {
						cancel()
					}
					return response, err
				})
			} else {
				wantVerified = 1
				verifier := source.verifier
				source.verifier = func(bundle []byte, algorithm, digest string) ([]byte, error) {
					statement, err := verifier(bundle, algorithm, digest)
					cancel()
					return statement, err
				}
			}
			if _, outcome := source.CheckLatest(ctx); outcome == softwarelifecycle.LatestReleaseAccepted {
				t.Fatal("canceled selection accepted")
			}
			if audit.verified["exact"] != wantVerified || audit.assetFetches != 0 {
				t.Fatalf("canceled %s: verified = %d, asset fetches = %d; want %d and zero", when, audit.verified["exact"], audit.assetFetches, wantVerified)
			}
		})
	}
}

type nativeSelectionRecord struct {
	key              string
	statement        []byte
	initiator        string
	invalidSignature bool
}

type nativeSelectionAudit struct {
	verified                      map[string]int
	assetFetches                  int
	assetFetchedBeforeAllVerified bool
}

func nativeSelectionProof(key string, statement []byte) nativeSelectionRecord {
	return nativeSelectionRecord{key: key, statement: statement, initiator: "github"}
}

func nativeSelectionStatements(t *testing.T, fixture *latestReleaseFixture) ([]byte, []byte) {
	t.Helper()
	exact, err := fixture.verifier([]byte(`{"fixture":true}`), "sha1", fixtureCommit)
	if err != nil {
		t.Fatal(err)
	}
	older := nativeSelectionMutate(t, exact, func(statement map[string]any) {
		nativeSelectionRetag(statement, "v1.9.9")
		for i, subject := range nativeSelectionSubjects(statement)[1:] {
			subject.(map[string]any)["digest"] = map[string]any{"sha256": fmt.Sprintf("%064x", i+1)}
		}
	})
	return exact, older
}

func nativeSelectionMutate(t *testing.T, body []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var statement map[string]any
	if err := json.Unmarshal(body, &statement); err != nil {
		t.Fatal(err)
	}
	mutate(statement)
	changed, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func nativeSelectionPredicate(statement map[string]any) map[string]any {
	return statement["predicate"].(map[string]any)
}

func nativeSelectionSubjects(statement map[string]any) []any {
	return statement["subject"].([]any)
}

func nativeSelectionRetag(statement map[string]any, tag string) {
	purl := "pkg:github/" + softwarelifecycle.Repository + "@" + tag
	predicate := nativeSelectionPredicate(statement)
	predicate["tag"], predicate["purl"] = tag, purl
	nativeSelectionSubjects(statement)[0].(map[string]any)["uri"] = purl
}

func nativeSelectionSource(t *testing.T, fixture *latestReleaseFixture, records []nativeSelectionRecord) (Source, *nativeSelectionAudit) {
	t.Helper()
	audit := &nativeSelectionAudit{verified: map[string]int{}}
	proofs := map[string]nativeSelectionRecord{}
	response := attestationResponse{Attestations: []githubAttestation{}}
	for _, record := range records {
		if _, exists := proofs[record.key]; exists {
			t.Fatalf("duplicate fixture proof key %q", record.key)
		}
		proofs[record.key] = record
		bundle, err := json.Marshal(map[string]string{"record": record.key})
		if err != nil {
			t.Fatal(err)
		}
		response.Attestations = append(response.Attestations, githubAttestation{Bundle: bundle, Initiator: record.initiator})
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	client := *fixture.server.Client()
	transport := client.Transport
	client.Transport = roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/repos/"+softwarelifecycle.Repository+"/attestations/sha1:"+fixtureCommit {
			if request.URL.Query().Get("predicate_type") != "release" || request.URL.Query().Get("per_page") != "100" {
				t.Errorf("attestation request does not bind release predicate and complete bounded page: %s", request.URL.RequestURI())
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded)), Request: request}, nil
		}
		if strings.Contains(request.URL.Path, "/releases/assets/") {
			audit.assetFetches++
			for _, record := range records {
				if audit.verified[record.key] != 1 {
					audit.assetFetchedBeforeAllVerified = true
				}
			}
		}
		return transport.RoundTrip(request)
	})
	verifier := func(bundle []byte, algorithm, digest string) ([]byte, error) {
		var key map[string]string
		if err := json.Unmarshal(bundle, &key); err != nil || algorithm != "sha1" || digest != fixtureCommit {
			return nil, fmt.Errorf("unexpected verification input")
		}
		proof, ok := proofs[key["record"]]
		if !ok {
			return nil, fmt.Errorf("unknown fixture proof")
		}
		audit.verified[proof.key]++
		if proof.invalidSignature {
			return nil, fmt.Errorf("invalid signature")
		}
		return append([]byte(nil), proof.statement...), nil
	}
	return NewWithEndpoint(&client, fixture.server.URL, verifier), audit
}

func nativeSelectionAssertRefused(t *testing.T, fixture *latestReleaseFixture, records []nativeSelectionRecord) {
	t.Helper()
	source, audit := nativeSelectionSource(t, fixture, records)
	if _, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseRefused {
		t.Fatalf("unsafe attestation history outcome = %v; want refusal", outcome)
	}
	if audit.assetFetches != 0 {
		t.Fatalf("refused attestation history fetched %d assets", audit.assetFetches)
	}
}
