package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func publicationRecoveryFixture(t *testing.T) (stablePreflightFacts, qualificationManifest, map[string]string, []burnedIdentity) {
	t.Helper()
	commit := strings.Repeat("a", 40)
	release := qualificationRelease{Commit: commit, ReleaseID: 95, Sequence: 173, Tag: "v3.1.95", ReleaseIdentity: decisionReleaseIdentity{Commit: commit, ReleaseIndexSHA256: strings.Repeat("b", 64), Repository: softwarelifecycle.Repository, Tag: "v3.1.95"}, Assets: []decisionAsset{{Name: "release-index.json", SHA256: strings.Repeat("b", 64), Size: 610}}}
	manifest := qualificationManifest{Schema: "sbxr-qualification-manifest-v3", Mode: "v3", SourceState: "v3-subscription-clean", Repository: softwarelifecycle.Repository, Releases: []qualificationRelease{release}, Workflow: qualificationWorkflow{Commit: commit, RunID: "101", RunURL: failedRunURL("101"), Path: ".github/workflows/candidate.yml"}, V3Attempt: &v3QualificationAttempt{Schema: "sbxr-v3-qualification-attempt-v3", Support: &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallOnly, Sources: []decisionReleaseIdentity{}}, Sources: []v3QualificationSource{}}}
	body, err := buildRecurringAcceptanceRecord(manifest, v3RecurringResultFacts{EvaluationTime: "2026-10-15T11:27:38Z", DetailedEvidenceSHA256: strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	failureRun := stableFinalizationRun{CreatedAt: "2026-10-15T11:30:00Z", HeadSHA: commit, ID: "102", Path: ".github/workflows/stable.yml", URL: failedRunURL("102")}
	failed, err := buildStableFailedAcceptanceRecord(manifest, release, body, failureRun.URL)
	if err != nil {
		t.Fatal(err)
	}
	burn := burnedIdentity{Commit: commit, OriginalTag: release.Tag, QualificationRunURL: manifest.Workflow.RunURL, Reason: "prepublication-failure", RecordedAt: "2026-10-15T11:36:48Z", ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Sequence: release.Sequence}
	facts := stablePreflightFacts{CandidateRun: stableCandidateRun{CreatedAt: "2026-10-15T10:11:14Z"}, ObservedAt: "2026-10-15T12:00:00Z", BurnedIdentities: []burnedIdentity{burn}, Releases: []stableReleaseObservation{{Assets: release.Assets, Body: failed, Commit: commit, Immutable: true, Prerelease: true, ReleaseID: release.ReleaseID, ReleaseIdentity: release.ReleaseIdentity, Sequence: release.Sequence, Tag: release.Tag}}, PublicationRecovery: &stablePublicationRecovery{BurnAttested: true, BurnAttestationRunID: failureRun.ID, FailureRun: failureRun, FailedBody: failed, Burn: burn}}
	return facts, manifest, map[string]string{release.Tag: body}, []burnedIdentity{}
}

func TestStablePublicationRecoveryPreservesQualifiedBytesAndAudit(t *testing.T) {
	facts, manifest, records, originalBurns := publicationRecoveryFixture(t)
	before := qualificationDocument(t, facts)
	recovered, err := assessStablePublicationRecovery(facts, manifest, records, originalBurns)
	if err != nil {
		t.Fatal(err)
	}
	body := recovered[manifest.Releases[0].Tag]
	if !strings.HasPrefix(body, records[manifest.Releases[0].Tag]) || strings.Count(body, "Status: Qualified\n") != 1 || !strings.Contains(body, "Publication recovery: original qualification and asset bytes preserved\n") || !strings.Contains(body, "Prior publication failure: "+facts.PublicationRecovery.FailureRun.URL+"\n") || !strings.Contains(body, "Preserved burn: release-burned/v3.1.95\n") || !strings.Contains(body, "Prior failed record SHA-256: "+documentSHA256([]byte(facts.PublicationRecovery.FailedBody))+"\n") {
		t.Fatalf("recovery lost qualification or audit: %s", body)
	}
	if !strings.Contains(body, "Prior failed record base64: "+base64.StdEncoding.EncodeToString([]byte(facts.PublicationRecovery.FailedBody))+"\n") {
		t.Fatal("recovery lost the exact prior failed record")
	}
	if qualificationDocument(t, facts) != before || !reflect.DeepEqual(originalBurns, []burnedIdentity{}) {
		t.Fatal("recovery changed source facts or burn history")
	}
	facts.Releases[0].Prerelease, facts.Releases[0].Body = false, body
	if retried, err := assessStablePublicationRecovery(facts, manifest, records, originalBurns); err != nil || retried[manifest.Releases[0].Tag] != body {
		t.Fatalf("retry after metadata promotion: %v", err)
	}
	facts.PublicationRecovery = nil
	if recovered, err := assessStablePublicationRecovery(facts, manifest, records, originalBurns); err != nil || recovered != nil {
		t.Fatal("ordinary publication unexpectedly changed")
	}
}

func TestStablePublicationRecoveryRefusesChangedOrUnauthenticatedHistory(t *testing.T) {
	for name, change := range map[string]func(*stablePreflightFacts, *qualificationManifest, map[string]string, *[]burnedIdentity){
		"unattested burn": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.BurnAttested = false
		},
		"wrong attestation run": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.BurnAttestationRunID = "103"
		},
		"wrong failure workflow": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.FailureRun.Path = ".github/workflows/candidate.yml"
		},
		"failure before candidate": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.FailureRun.CreatedAt = "2026-10-15T09:00:00Z"
		},
		"burn before failure": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.Burn.RecordedAt = "2026-10-15T11:00:00Z"
		},
		"observation before burn": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.ObservedAt = "2026-10-15T11:00:00Z"
		},
		"qualification failure burn": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.Burn.Reason = "post-sign-qualification-failure"
		},
		"wrong candidate run": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.Burn.QualificationRunURL = failedRunURL("100")
		},
		"wrong index": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.Burn.ReleaseIndexSHA256 = strings.Repeat("d", 64)
		},
		"changed failure record": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.PublicationRecovery.FailedBody += "changed\n"
		},
		"unrelated burn delta": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.BurnedIdentities = append(f.BurnedIdentities, burnedIdentity{OriginalTag: "v3.1.96"})
		},
		"burn existed before qualification": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, b *[]burnedIdentity) {
			*b = append(*b, f.PublicationRecovery.Burn)
		},
		"not clean only": func(_ *stablePreflightFacts, m *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			m.V3Attempt.Support.Scope = softwarelifecycle.RecurringSubscriptionUpgrade
		},
		"Owner exception": func(_ *stablePreflightFacts, m *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			m.V3Attempt.OwnerException = "exception"
		},
		"changed current record": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.Releases[0].Body += "changed\n"
		},
		"draft recovery": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.Releases[0].Draft = true
		},
		"mutable recovery": func(f *stablePreflightFacts, _ *qualificationManifest, _ map[string]string, _ *[]burnedIdentity) {
			f.Releases[0].Immutable = false
		},
		"stable without audit": func(f *stablePreflightFacts, _ *qualificationManifest, r map[string]string, _ *[]burnedIdentity) {
			f.Releases[0].Prerelease, f.Releases[0].Body = false, r[f.Releases[0].Tag]
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts, manifest, records, originalBurns := publicationRecoveryFixture(t)
			change(&facts, &manifest, records, &originalBurns)
			if _, err := assessStablePublicationRecovery(facts, manifest, records, originalBurns); err == nil {
				t.Fatal("unsafe publication recovery accepted")
			}
		})
	}
}

func TestStablePublicationRecoveryPreservesOriginalBurnsAndAllowsUnrelatedAdditions(t *testing.T) {
	facts, manifest, records, original := publicationRecoveryFixture(t)
	prior := facts.PublicationRecovery.Burn
	prior.OriginalTag, prior.Sequence, prior.Reason = "v3.1.90", 168, "owner-abandoned"
	original = append(original, prior)
	unrelated := prior
	unrelated.OriginalTag, unrelated.Sequence = "v3.1.96", 174
	facts.BurnedIdentities = []burnedIdentity{prior, facts.PublicationRecovery.Burn, unrelated}
	if _, err := assessStablePublicationRecovery(facts, manifest, records, original); err != nil {
		t.Fatalf("unrelated new burn invalidated successful qualification: %v", err)
	}
	facts.BurnedIdentities[0].Commit = strings.Repeat("d", 40)
	if _, err := assessStablePublicationRecovery(facts, manifest, records, original); err == nil {
		t.Fatal("changed original burn accepted")
	}
	facts.BurnedIdentities = facts.BurnedIdentities[1:]
	if _, err := assessStablePublicationRecovery(facts, manifest, records, original); err == nil {
		t.Fatal("removed original burn accepted")
	}
}

func TestStablePublicationRecoveryCLI(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	pre := mainReviewPreflightFixture(t, binary)
	var manifest qualificationManifest
	if !decodeCanonical([]byte(qualificationDocument(t, pre["signed_manifest"])), &manifest) {
		t.Fatal("qualification manifest fixture")
	}
	release := manifest.Releases[0]
	metadata := pre["releases"].([]any)[0].(map[string]any)
	originalBody := metadata["body"].(string)
	failure := stableFinalizationRun{CreatedAt: "2026-09-02T00:00:01Z", HeadSHA: manifest.Workflow.Commit, ID: "900", Path: ".github/workflows/stable.yml", URL: failedRunURL("900")}
	failedBody, err := buildStableFailedAcceptanceRecord(manifest, release, originalBody, failure.URL)
	if err != nil {
		t.Fatal(err)
	}
	burn := burnedIdentity{Commit: release.Commit, OriginalTag: release.Tag, QualificationRunURL: manifest.Workflow.RunURL, Reason: "prepublication-failure", RecordedAt: "2026-09-02T00:00:02Z", ReleaseIndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Sequence: release.Sequence}
	pre["burned_identities"], pre["observed_at"] = []burnedIdentity{burn}, "2026-09-02T00:00:03Z"
	metadata["body"], metadata["draft"], metadata["immutable"], metadata["prerelease"] = failedBody, false, true, true
	assertQualificationRefused(t, binary, qualificationDocument(t, pre), "burned failed prerelease has no recovery authority")
	pre["publication_recovery"] = stablePublicationRecovery{Burn: burn, BurnAttestationRunID: failure.ID, BurnAttested: true, FailedBody: failedBody, FailureRun: failure}
	publication := automaticPublicationFixture(t, binary, pre)
	observation := publication["observation"].(map[string]any)
	recoveredBody := observation["body"].(string)
	observation["body"], observation["draft"], observation["immutable"], observation["prerelease"] = failedBody, false, true, true
	publicationDocument := qualificationDocument(t, publication)
	decision, err := runQualificationCommand(binary, publicationDocument)
	if err != nil || jsonObject(t, decision)["outcome"] != "actions-required" {
		t.Fatalf("failed prerelease publication: %v %s", err, decision)
	}
	// A failed transport request has no effect on qualification or its next action.
	if retried, err := runQualificationCommand(binary, publicationDocument); err != nil || string(retried) != string(decision) {
		t.Fatalf("retry before metadata mutation changed authority: %v %s", err, retried)
	}
	verification := map[string]any{"attempt": 60, "observation": nil, "observed_at": "2026-09-02T00:01:05Z", "prior_decision_sha256": sha256String(string(decision)), "publication_decision": jsonObject(t, decision), "publication_facts": publication, "schema": qualificationFactsSchema, "stage": stablePublicationVerificationStage}
	if out, err := runQualificationCommand(binary, qualificationDocument(t, verification)); err != nil || jsonObject(t, out)["outcome"] != "propagation-exhausted" {
		t.Fatalf("recoverable observation exhaustion: %v %s", err, out)
	}
	public := jsonObject(t, []byte(qualificationDocument(t, observation)))
	public["body"], public["prerelease"], public["latest_release_id"] = recoveredBody, false, release.ReleaseID
	public["latest_install_sha256"] = release.Assets[0].SHA256
	public["attestation"] = stableReleaseAttestation{Commit: release.Commit, Count: 1, Initiator: "github", PredicateType: "release"}
	public["public_verification"] = publicLatestVerification{Outcome: "accepted", ReleaseIdentity: &release.ReleaseIdentity, Sequence: &release.Sequence}
	verification["attempt"], verification["observation"] = 1, public
	verified, err := runQualificationCommand(binary, qualificationDocument(t, verification))
	if err != nil || jsonObject(t, verified)["outcome"] != "accepted" {
		t.Fatalf("public recovered release verification: %v %s", err, verified)
	}
	finalization := map[string]any{"observed_at": "2026-09-02T00:01:06Z", "prior_decision_sha256": sha256String(string(verified)), "publication_verification_decision": jsonObject(t, verified), "publication_verification_facts": verification, "schema": qualificationFactsSchema, "stage": stableV3FinalizationStage}
	if out, err := runQualificationCommand(binary, qualificationDocument(t, finalization)); err != nil || jsonObject(t, out)["outcome"] != "accepted" {
		t.Fatalf("recovered stable finalization: %v %s", err, out)
	}
	var history v3ReleaseHistory
	if err := json.Unmarshal([]byte(qualificationDocument(t, pre["subscription_history"])), &history); err != nil {
		t.Fatal(err)
	}
	assets := make([]observedAsset, len(release.Assets))
	for i, a := range release.Assets {
		assets[i] = observedAsset{Digest: a.SHA256, ID: int64(1000 + i), Name: a.Name, Size: a.Size}
	}
	history.Releases = append(history.Releases, observedRelease{Assets: assets, Body: recoveredBody, Commit: release.Commit, ID: release.ReleaseID, Immutable: true, Index: &observedIndex{Commit: release.Commit, Repository: softwarelifecycle.Repository, Schema: 2, Sequence: release.Sequence, SHA256: release.ReleaseIdentity.ReleaseIndexSHA256, Support: manifest.V3Attempt.Support, Tag: release.Tag}, Sequence: &release.Sequence, Tag: release.Tag})
	sort.Slice(history.Releases, func(i, j int) bool { return history.Releases[i].ID < history.Releases[j].ID })
	history.PublicLatest = publicLatestVerification{Outcome: "accepted", ReleaseIdentity: &release.ReleaseIdentity, Sequence: &release.Sequence}
	pre["subscription_history"], pre["latest_release_id"], pre["latest_tag"], pre["observed_at"] = history, release.ReleaseID, release.Tag, "2026-09-02T00:02:00Z"
	metadata["body"], metadata["prerelease"] = recoveredBody, false
	retry := automaticPublicationFixture(t, binary, pre)
	retryObservation := retry["observation"].(map[string]any)
	retryObservation["draft"], retryObservation["immutable"] = false, true
	if out, err := runQualificationCommand(binary, qualificationDocument(t, retry)); err != nil || jsonObject(t, out)["outcome"] != "actions-required" {
		t.Fatalf("retry after this candidate became Latest: %v %s", err, out)
	}
	retryObservation["downloads"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("f", 64)
	assertQualificationRefused(t, binary, qualificationDocument(t, retry), "retry cannot conceal changed downloaded bytes")

	support := manifest.V3Attempt.Support.lifecycle()
	publicRelease := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: release.Tag, Commit: release.Commit, IndexSHA256: release.ReleaseIdentity.ReleaseIndexSHA256}, Sequence: release.Sequence, Support: &support}
	path := filepath.Join(t.TempDir(), "recovered-record.json")
	if err := os.WriteFile(path, []byte(qualificationDocument(t, map[string]any{"body": recoveredBody, "release": publicRelease, "assets": release.Assets})), 0600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command("go", "test", "../../internal/softwarelifecycle/adapter/github", "-run", "^TestCleanInstallOnlyRecordCompatibility$", "-count=1")
	check.Env = append(os.Environ(), "SBXR_TEST_CLEAN_INSTALL_ONLY_RECORD="+path)
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("public reader refused transparent recovery footer: %v %s", err, out)
	}
}
