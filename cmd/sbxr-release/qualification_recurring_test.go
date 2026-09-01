package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQualificationCommandRequiresCompleteRecurringEvidence(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.0", 18, 2
	source := qualifiedRelease(false)
	source.Body = strings.NewReplacer("# SBXR Installer-Updater Acceptance Record\n", "# SBXR Acceptance Record\n", "Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\n", "Stable result code: RELEASE-V3-PACKAGED-LIVE-QUALIFICATION\n", "Qualification role: Clean-installed source release\n", "Qualification role: Clean-installed V3 release\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and outside runner\n").Replace(source.Body)
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	attempt := recurringAttemptFixture(t, source)
	boundary, manifest := qualificationBoundaryForCandidate(t, binary, facts, attempt)
	evidence := recurringEvidenceFixture(t, manifest, attempt)
	document := recurringResultFixture(t, boundary, manifest, evidence)
	output, err := runQualificationCommand(binary, document)
	if err != nil {
		t.Fatalf("complete recurring evidence: %v\n%s", err, output)
	}
	result := jsonObject(t, output)
	if result["outcome"] != "accepted" || len(result["records"].([]any)) != 1 {
		t.Fatalf("one Acceptance Record required: %s", output)
	}
	body := result["records"].([]any)[0].(map[string]any)["body"].(string)
	for _, required := range []string{"RELEASE-V3-SUBSCRIPTION-QUALIFICATION", "Natural timer firing and naturally due certificate renewal: Not observed", "Unsupported new or renamed renewal route: May execute before detection; historical outcomes unknown", "Karing macOS: Passed", "source-v2.0.0-precommit"} {
		if !strings.Contains(body, required) {
			t.Fatalf("record lacks %q", required)
		}
	}
	if retry, err := runQualificationCommand(binary, document); err != nil || !bytes.Equal(output, retry) {
		t.Fatal("historical revalidation changed timestamps or record")
	}
	inclusive := jsonObject(t, []byte(qualificationDocument(t, evidence)))
	at := time.Date(2026, 9, 1, 0, 1, 0, 0, time.UTC)
	for _, raw := range inclusive["scenarios"].([]any) {
		s := raw.(map[string]any)
		duration := 30 * time.Minute
		if s["scenario_id"] == "karing-final" {
			duration = 2 * time.Hour
		}
		completed := at.Add(duration)
		validated := completed.Add(5 * time.Minute)
		s["started_at"], s["preflight_at"], s["completed_at"], s["validated_at"] = at.Format(time.RFC3339), at.Format(time.RFC3339), completed.Format(time.RFC3339), validated.Format(time.RFC3339)
		for _, ref := range s["evidence"].([]any) {
			ref.(map[string]any)["record"].(map[string]any)["observed_at"] = completed.Format(time.RFC3339)
		}
		at = validated.Add(time.Minute)
		inclusive["observed_at"] = validated.Format(time.RFC3339)
	}
	rebindRecurringEvidence(t, inclusive)
	if accepted, err := runQualificationCommand(binary, recurringResultFixture(t, boundary, manifest, inclusive)); err != nil {
		t.Fatalf("inclusive limits: %v\n%s", err, accepted)
	}
	late := jsonObject(t, []byte(recurringResultFixture(t, boundary, manifest, inclusive)))
	end, _ := time.Parse(time.RFC3339, late["evaluation_time"].(string))
	late["evaluation_time"] = end.Add(time.Second).Format(time.RFC3339)
	assertQualificationRefused(t, binary, qualificationDocument(t, late), "record produced one second late")
	duplicate := strings.Replace(document, `"stage":"v3-packaged-live-result"`, `"stage":"v3-packaged-live-result","stage":"v3-packaged-live-result"`, 1)
	assertQualificationRefused(t, binary, duplicate, "duplicate JSON member")
	for name, mutate := range map[string]func(map[string]any){
		"missing scenario":   func(e map[string]any) { e["scenarios"] = e["scenarios"].([]any)[1:] },
		"duplicate scenario": func(e map[string]any) { s := e["scenarios"].([]any); s[1] = s[0] },
		"unlisted scenario":  func(e map[string]any) { e["scenarios"].([]any)[0].(map[string]any)["scenario_id"] = "unlisted" },
		"different candidate": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["candidate"].(map[string]any)["commit"] = strings.Repeat("f", 40)
		},
		"different VPS":  func(e map[string]any) { e["scenarios"].([]any)[0].(map[string]any)["vps_id"] = "vps-2" },
		"borrowed pass":  func(e map[string]any) { e["scenarios"].([]any)[0].(map[string]any)["attempt_id"] = "run-122-attempt-1" },
		"wrong recovery": func(e map[string]any) { e["scenarios"].([]any)[2].(map[string]any)["recovery_direction"] = "forward" },
		"failed scenario": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["actual_result"] = "unexpected-failure"
		},
		"stale preflight": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["preflight_at"] = "2026-09-01T00:00:00Z"
		},
		"validation late": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["validated_at"] = "2026-09-01T00:26:01Z"
		},
		"scenario timeout": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["completed_at"] = "2026-09-01T00:31:01Z"
		},
		"future observation": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["evidence"].([]any)[0].(map[string]any)["record"].(map[string]any)["observed_at"] = "2027-01-01T00:00:00Z"
		},
		"credential correlation": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["link_id"] = "01234567-89ab-4cde-8f01-23456789abcd"
		},
		"raw capture": func(e map[string]any) { e["scenarios"].([]any)[0].(map[string]any)["raw_capture"] = "redacted" },
		"package drift": func(e map[string]any) {
			e["scenarios"].([]any)[0].(map[string]any)["packages_after"].(map[string]any)["certbot"].(map[string]any)["version"] = "5.9.9"
		},
		"missing final removal": func(e map[string]any) {
			s := e["scenarios"].([]any)
			s[len(s)-1].(map[string]any)["final_state"] = "Running"
		},
		"Karing not last": func(e map[string]any) { s := e["scenarios"].([]any); s[0], s[len(s)-1] = s[len(s)-1], s[0] },
	} {
		t.Run(name, func(t *testing.T) {
			variant := jsonObject(t, []byte(qualificationDocument(t, evidence)))
			mutate(variant)
			rebindRecurringEvidence(t, variant)
			assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, variant), name)
		})
	}
	// Every required observation is independently necessary, even with freshly
	// recalculated digests. This includes real updater and genuinely due refresh.
	for index, s := range evidence["scenarios"].([]any) {
		scenario := s.(map[string]any)
		t.Run("missing-proof/"+scenario["scenario_id"].(string), func(t *testing.T) {
			variant := jsonObject(t, []byte(qualificationDocument(t, evidence)))
			item := variant["scenarios"].([]any)[index].(map[string]any)
			refs := item["evidence"].([]any)
			item["evidence"] = refs[:len(refs)-1]
			rebindRecurringEvidence(t, variant)
			assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, variant), "missing observation")
		})
	}
	// The same command validates a prefix promptly, but cannot issue acceptance.
	prefix := jsonObject(t, []byte(qualificationDocument(t, evidence)))
	prefix["scenarios"] = prefix["scenarios"].([]any)[:1]
	prefix["observed_at"] = prefix["scenarios"].([]any)[0].(map[string]any)["validated_at"]
	prefixFacts := jsonObject(t, []byte(recurringResultFixture(t, boundary, manifest, prefix)))
	prefixFacts["stage"] = "v3-scenario-result"
	if validated, err := runQualificationCommand(binary, qualificationDocument(t, prefixFacts)); err != nil || jsonObject(t, validated)["outcome"] != "accepted" || len(jsonObject(t, validated)["records"].([]any)) != 0 {
		t.Fatalf("scenario validation: %v\n%s", err, validated)
	}
	stopFacts := map[string]any{
		"failure":                      map[string]any{"actual_result": "timeout", "attempt_id": attempt["attempt_id"], "boundary": "unknown", "candidate": jsonObject(t, manifest)["releases"].([]any)[0], "expected_result": "expected-safety-and-final-state-proved", "host_state": "Unknown", "observed_at": "2026-09-01T00:32:00Z", "operation_id": "operation-1", "scenario_id": "baseline-clean", "schema": "sbxr-v3-scenario-failure-v2", "vps_id": "vps-1"},
		"qualification_boundary_facts": jsonValue(t, boundary), "qualification_manifest": jsonObject(t, manifest), "qualification_manifest_attested": true,
		"safety_cleanup": map[string]any{"host_state": "Not installed", "status": "completed"}, "schema": qualificationFactsSchema, "stage": "v3-scenario-failure",
	}
	stopped, stopErr := runQualificationCommand(binary, qualificationDocument(t, stopFacts))
	if stopErr != nil || jsonObject(t, stopped)["outcome"] != "failed" || jsonObject(t, stopped)["stop_test_mutations"] != true || jsonObject(t, stopped)["burn_required"] != true {
		t.Fatalf("failure and separate cleanup: %v\n%s", stopErr, stopped)
	}
	m := jsonObject(t, manifest)
	target := m["releases"].([]any)[0].(map[string]any)
	stableFacts := map[string]any{
		"acceptance_decision": result, "acceptance_facts": jsonValue(t, document),
		"archive":           map[string]any{"commit": facts.ArchiveCommit, "remote_commit": facts.ArchiveRemoteCommit, "remote_tag_object": facts.ArchiveRemoteTagObject, "tag_object": facts.ArchiveTagObject, "type": "tag"},
		"burned_identities": []any{}, "candidate_run": map[string]any{"conclusion": "success", "created_at": "2026-09-01T00:00:00Z", "event": "workflow_dispatch", "head_sha": facts.Commit, "id": "123", "path": ".github/workflows/candidate.yml"},
		"checklist_sha256": facts.ChecklistSHA256, "latest_release_id": source.ID, "latest_tag": source.Tag, "manifest_attested": true, "observed_at": "2026-09-02T00:00:00Z",
		"releases":    []any{map[string]any{"assets": target["assets"], "body": body, "commit": target["commit"], "draft": true, "immutable": false, "prerelease": false, "release_id": target["release_id"], "release_identity": target["release_identity"], "sequence": target["sequence"], "tag": target["tag"]}},
		"remote_main": facts.Commit, "schema": qualificationFactsSchema, "signed_manifest": m, "stage": "stable-preflight",
	}
	if stable, err := runQualificationCommand(binary, qualificationDocument(t, stableFacts)); err != nil || len(jsonObject(t, stable)["actions"].([]any)) != 1 {
		t.Fatalf("recurring stable gate: %v\n%s", err, stable)
	}
	failure := map[string]any{
		"burned_identities": []any{}, "candidate_commit_ancestor": true, "candidate_run": stableFacts["candidate_run"],
		"finalization_run":  map[string]any{"created_at": "2026-09-02T00:00:00Z", "head_sha": facts.Commit, "id": "456", "path": ".github/workflows/stable.yml", "url": "https://github.com/albertloky/SBXR/actions/runs/456"},
		"manifest_attested": true, "observations": []any{map[string]any{"assets": target["assets"], "body": body, "commit": target["commit"], "draft": true, "immutable": false, "prerelease": false, "release_id": target["release_id"], "release_identity": target["release_identity"], "release_present": true, "sequence": target["sequence"], "tag": target["tag"], "tag_commit": target["commit"]}},
		"observed_at": "2026-09-02T00:01:00Z", "operation": "publish", "publication_stage": "prepublication", "schema": qualificationFactsSchema, "signed_manifest": m, "stage": "stable-failure-finalization",
	}
	failure["observations"].([]any)[0].(map[string]any)["publicly_verified"] = false
	burned, err := runQualificationCommand(binary, qualificationDocument(t, failure))
	if err != nil || jsonObject(t, burned)["outcome"] != "failed-prerelease" || jsonObject(t, burned)["actions"].([]any)[0].(map[string]any)["burn_required"] != true {
		t.Fatalf("recurring stable failure burn: %v\n%s", err, burned)
	}
}

func rebindRecurringEvidence(t *testing.T, evidence map[string]any) {
	previous := evidence["qualification_manifest_sha256"].(string)
	for _, value := range evidence["scenarios"].([]any) {
		s := value.(map[string]any)
		s["prior_scenario_sha256"] = previous
		for _, raw := range s["evidence"].([]any) {
			ref := raw.(map[string]any)
			ref["sha256"] = sha256String(qualificationDocument(t, ref["record"]))
		}
		previous = sha256String(qualificationDocument(t, s))
	}
}

func recurringResultFixture(t *testing.T, boundary string, manifest []byte, evidence map[string]any) string {
	m := jsonObject(t, manifest)
	return qualificationDocument(t, map[string]any{
		"detailed_evidence": evidence, "detailed_evidence_sha256": sha256String(qualificationDocument(t, evidence)),
		"evaluation_time": evidence["observed_at"], "observed_at": evidence["observed_at"], "prior_decision_sha256": sha256String(string(manifest)),
		"qualification_boundary_facts": jsonValue(t, boundary), "qualification_manifest": m, "qualification_manifest_attested": true,
		"releases": m["releases"], "runner": m["v3_attempt"].(map[string]any)["runner"], "schema": qualificationFactsSchema, "stage": "v3-packaged-live-result",
	})
}

func recurringEvidenceFixture(t *testing.T, manifest []byte, attempt map[string]any) map[string]any {
	m := jsonObject(t, manifest)
	candidate := m["releases"].([]any)[0]
	manifestDigest := sha256String(string(manifest))
	previous := manifestDigest
	start := time.Date(2026, 9, 1, 0, 1, 0, 0, time.UTC)
	packages := attempt["packages"]
	var scenarios []any
	for index, id := range attempt["required_scenarios"].([]string) {
		// Fixture values state the intended public contract, not a captured live pass.
		initial, boundary, recovery, final := "Running", "observed", "none", "Running"
		if strings.Contains(id, "precommit") {
			boundary, recovery = "before-commitment", "rollback"
		}
		if strings.Contains(id, "postcommit") {
			boundary, recovery = "after-commitment", "forward"
		}
		if strings.HasPrefix(id, "remove-") || id == "baseline-removal" || id == "baseline-clean" || id == "karing-final" {
			final = "Not installed"
		}
		if strings.HasPrefix(id, "baseline-") || strings.HasPrefix(id, "enable-") {
			initial = "Not set up"
		}
		if id == "baseline-refusal" || id == "baseline-precommit" || id == "enable-precommit" || id == "enable-schema2-absent" {
			final = "Not set up"
		}
		if strings.HasPrefix(id, "remove-") && (strings.HasSuffix(id, "precommit") || strings.HasSuffix(id, "postcommit")) {
			initial = "Change incomplete"
			recovery = "forward"
		}
		if id == "remove-certbot" || id == "remove-writer" || id == "remove-admission-race" || id == "update-incompatible" || id == "update-unlisted" {
			final, boundary = "Running", "refusal"
		}
		var source any
		if strings.HasPrefix(id, "source-") {
			source = attempt["sources"].([]any)[0]
		}
		completed := start.Add(20 * time.Minute)
		validated := completed.Add(time.Minute)
		before := packages
		if id == "snap-refresh" {
			packages = attempt["after_snap_refresh"]
		}
		checks := fixtureRecurringChecks(id)
		var references []any
		for _, check := range checks {
			record := map[string]any{"check": check, "observed_at": completed.Format(time.RFC3339), "result": "observed"}
			references = append(references, map[string]any{"record": record, "sha256": sha256String(qualificationDocument(t, record))})
		}
		scenario := map[string]any{
			"actual_result": "expected-safety-and-final-state-proved", "attempt_id": attempt["attempt_id"], "boundary": boundary, "candidate": candidate,
			"completed_at": completed.Format(time.RFC3339), "evidence": references, "expected_result": "expected-safety-and-final-state-proved", "final_state": final, "initial_state": initial,
			"link_id": "link-1", "operation_id": fmt.Sprintf("operation-%d", index+1), "packages_after": packages, "packages_before": before,
			"preflight_at": start.Format(time.RFC3339), "prior_scenario_sha256": previous, "recovery_direction": recovery,
			"scenario_id": id, "schema": "sbxr-v3-scenario-evidence-v2", "source": source,
			"started_at": start.Format(time.RFC3339), "validated_at": validated.Format(time.RFC3339), "vps_id": attempt["vps_id"], "vps_identity_sha256": attempt["vps_identity_sha256"],
		}
		previous = sha256String(qualificationDocument(t, scenario))
		scenarios = append(scenarios, scenario)
		start = validated.Add(time.Minute)
	}
	return map[string]any{"attempt_id": attempt["attempt_id"], "observed_at": scenarios[len(scenarios)-1].(map[string]any)["validated_at"], "qualification_manifest_sha256": manifestDigest, "scenarios": scenarios, "schema": "sbxr-v3-packaged-live-evidence-v2"}
}

func fixtureRecurringChecks(id string) []string {
	checks := strings.Fields(`fresh-disposable-vps-preflight unchanged-candidate-bytes initial-state-proved boundary-observed final-state-proved original-ssh-continuity supported-effective-route-inspected capture-coverage-complete exact-secrets-absent prohibited-patterns-absent`)
	family := strings.Split(id, "-")[0]
	extra := map[string]string{
		"baseline":    `clean-direct-install reviewed-setup safety-refusals local-activation outside-proxy-traffic complete-owned-removal`,
		"enable":      `schema1-conversion schema2-absent-retained provisional-cleanup same-generation-finishing proxy-and-traffic-unchanged`,
		"link":        `one-prepared-target no-old-process-or-request-overlap old-link-404 client-identity-unchanged proxy-traffic-unchanged`,
		"repair":      `diagnosed-correction production-certificate-issued canonical-publication accepted-activation outside-tls-presentation missed-activation-finished`,
		"activation":  `diagnosed-correction production-certificate-issued canonical-publication accepted-activation outside-tls-presentation missed-activation-finished`,
		"invalid":     `invalid-replacement-refused valid-loaded-certificate-preserved`,
		"managed":     `supported-managed-attempt-interrupted recorder-unknown-or-failed reviewed-repair-targeted-production-replacement fault-retained-until-proof official-schedule-integration recorder-start recorder-outcome production-issuance canonical-publication accepted-activation outside-tls natural-timer-not-observed naturally-due-renewal-not-observed`,
		"recorder":    `start-failure outcome-failure stale-attempt live-attempt retention lock-order-contention child-and-writer-death reboot-exclusion official-route`,
		"snap":        `supported-snap-refresh effective-generated-route-preserved recorder-and-hooks-verified planned-package-change-only`,
		"unsupported": `new-or-renamed-route-detected problem-detected accounting-gap-explicit bypass-prevention-not-claimed historical-outcomes-unknown`,
		"identity":    `old-established-outside-session old-new-connection-attempts owned-process-groups-and-descendants-terminated outside-target-healthy startup-publication reload effective-route source-only-before-gate ordinary-start-denied-after-gate source-restoration-only-before-revocation one-target-forward-after-revocation unchanged-link-and-noncredential-fields unavailable-subscription-fallback absent-subscription-fallback`,
		"source":      `actual-source-packaged-updater actual-source-packaged-recovery source-record-schema-proved both-releases-understand-recovery admission-exclusion creation-provenance-preserved no-ownership-migration prior-exact-restoration candidate-forward-runtime-completion serving-only-restart proxy-not-restarted both-credentials-unchanged no-helper-or-intermediate-release`,
		"update":      `incompatible-downgrade-refused unlisted-source-refused no-replacement-on-refusal`,
		"remove":      `idle-pending-takeover both-commitment-sides full-pending-provenance no-repair-or-revoked-start certbot-and-writer-exclusion admission-races directory-locks no-recreation-after-death-or-reboot shared-route-delay-and-restoration unrelated-resources-preserved final-state-directory-inspection one-authoritative-location exact-finishing-executable unknown-residue-refused all-owned-resources-absent-or-safely-retained-on-refusal`,
		"secret":      `sandbox-cannot-read-token canonical-and-candidate-protection units-arguments-environment-safe runner-vps-mac-terminal-workflow-retained-scans qualification-secrets-and-client-processes-cleaned unrelated-data-preserved`,
		"karing":      `latest-official-stable-macos-package one-real-remote-profile one-vless-reality-node all-fields-and-name-match settings-preserved direct-and-proxied-traffic manual-refresh genuinely-due-five-minute-auto-refresh old-established-session-terminated owned-process-groups-and-descendants-terminated old-new-connections-refused outside-target-healthy unchanged-real-link replacement-uuid-adopted other-fields-preserved traffic-restored direct-refresh-correction-or-confirmed-fallback https-outage-preserves-node same-link-recovery complete-removal outside-access-unusable full-owned-absence temporary-secret-and-process-cleanup`,
	}
	return append(checks, strings.Fields(extra[family])...)
}

func TestQualificationCommandBindsRecurringAttempt(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence, facts.Candidate.EvidenceVersion = "v3.1.0", 18, 2
	source := qualifiedRelease(false)
	source.Body = strings.NewReplacer("# SBXR Installer-Updater Acceptance Record\n", "# SBXR Acceptance Record\n", "Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\n", "Stable result code: RELEASE-V3-PACKAGED-LIVE-QUALIFICATION\n", "Qualification role: Clean-installed source release\n", "Qualification role: Clean-installed V3 release\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and outside runner\n").Replace(source.Body)
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	attempt := recurringAttemptFixture(t, source)
	boundary, manifest := qualificationBoundaryForCandidate(t, binary, facts, attempt)
	value := jsonObject(t, manifest)
	if value["schema"] != "sbxr-qualification-manifest-v2" || value["v3_attempt"] == nil || len(value["releases"].([]any)) != 1 {
		t.Fatalf("unbound recurring manifest: %s", manifest)
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing attempt":  func(v map[string]any) { delete(v, "v3_attempt") },
		"unknown field":    func(v map[string]any) { v["v3_attempt"].(map[string]any)["waiver"] = true },
		"shortened matrix": func(v map[string]any) { v["v3_attempt"].(map[string]any)["required_scenarios"] = []any{"karing-final"} },
		"no source":        func(v map[string]any) { v["v3_attempt"].(map[string]any)["sources"] = []any{} },
		"extended limit":   func(v map[string]any) { v["v3_attempt"].(map[string]any)["scenario_limit_seconds"] = 1801 },
	} {
		t.Run(name, func(t *testing.T) {
			variant := jsonObject(t, []byte(boundary))
			mutate(variant)
			assertQualificationRefused(t, binary, qualificationDocument(t, variant), name)
		})
	}
}

func recurringAttemptFixture(t *testing.T, source observedRelease) map[string]any {
	t.Helper()
	packageIdentity := func(name, repository, architecture, version string) map[string]any {
		return map[string]any{"architecture": architecture, "name": name, "repository": repository, "sha256": strings.Repeat("a", 64), "size": 100, "version": version}
	}
	packages := map[string]any{
		"certbot": packageIdentity("certbot", "https://snapcraft.io/certbot", "amd64", "5.0.0"),
		"karing":  packageIdentity("karing", "https://github.com/KaringX/karing", "macos-arm64", "1.2.0"),
		"snap":    packageIdentity("snapd", "https://snapcraft.io/snapd", "amd64", "2.70"),
	}
	after := jsonObject(t, []byte(qualificationDocument(t, packages)))
	after["certbot"].(map[string]any)["version"] = "5.0.1"
	after["certbot"].(map[string]any)["sha256"] = strings.Repeat("b", 64)
	return map[string]any{
		"after_snap_refresh": after, "attempt_id": "run-123-attempt-1", "karing_latest_checked_at": "2026-09-01T00:00:00Z",
		"karing_limit_seconds": 7200, "packages": packages, "proxy_package": expectedV3PackageIdentity(),
		"required_scenarios": strings.Fields(`baseline-clean baseline-refusal baseline-precommit baseline-postcommit baseline-drift baseline-removal
enable-schema1 enable-precommit enable-postcommit enable-schema2-absent link-precommit link-postcommit
repair-precommit repair-postcommit activation-precommit activation-postcommit invalid-replacement managed-renewal
recorder-start recorder-outcome recorder-stale recorder-live recorder-retention recorder-locks recorder-death recorder-reboot snap-refresh unsupported-route
identity-precommit identity-postcommit identity-unavailable identity-absent
source-v2.0.0-upgrade source-v2.0.0-precommit source-v2.0.0-postcommit update-incompatible update-unlisted
remove-enable-precommit remove-enable-postcommit remove-link-precommit remove-link-postcommit remove-repair-precommit remove-repair-postcommit remove-activation-precommit remove-activation-postcommit remove-identity-precommit remove-identity-postcommit
remove-certbot remove-writer remove-admission-race remove-directory-lock remove-death remove-reboot remove-shared-route remove-finalization remove-exact-restoration secret-containment karing-final`),
		"run_attempt": 1, "runner": map[string]any{"architecture": "amd64", "go_toolchain": "go1.26.6", "operating_system": "Ubuntu Server 24.04", "public_verifier": "1.3.0 26B3382D5700AFBCD84F980D1D5B6C52BFF743DC2A8EE86B8B44C8E1245CE485"},
		"scenario_limit_seconds": 1800, "schema": "sbxr-v3-qualification-attempt-v2",
		"sources":    []any{map[string]any{"assets": sourceAction(source).Assets, "ownership_schema": 1, "public_verification": "accepted", "release_identity": sourceAction(source).ReleaseIdentity, "sequence": source.Index.Sequence}},
		"started_at": "2026-09-01T00:00:00Z", "validation_limit_seconds": 300,
		"vps_id": "vps-1", "vps_identity_sha256": strings.Repeat("c", 64), "outside_runner_id": "runner-1", "mac_runner_id": "mac-1", "macos_version": "15.7.0",
	}
}

func TestQualificationCommandAdmitsRecurringV3OnlyWithVersionedEvidence(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "sbxr-release")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	facts := candidateFacts("v3")
	facts.Candidate.ATag, facts.Candidate.ASequence = "", 0
	facts.Candidate.BTag, facts.Candidate.BSequence = "v3.1.0", 18
	source := qualifiedRelease(false)
	source.Body = strings.NewReplacer("# SBXR Installer-Updater Acceptance Record\n", "# SBXR Acceptance Record\n", "Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION\n", "Stable result code: RELEASE-V3-PACKAGED-LIVE-QUALIFICATION\n", "Qualification role: Clean-installed source release\n", "Qualification role: Clean-installed V3 release\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64\n", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and outside runner\n").Replace(source.Body)
	facts.Releases, facts.LatestTag = []observedRelease{source}, &source.Tag
	document := jsonObject(t, []byte(canonicalFacts(t, facts)))
	document["candidate"].(map[string]any)["evidence_version"] = 2
	output, err := runQualificationCommand(binary, qualificationDocument(t, document))
	if err != nil || jsonObject(t, output)["source_state"] != "v3-recurring" {
		t.Fatalf("recurring V3 preflight: %v\n%s", err, output)
	}
	assertQualificationRefused(t, binary, canonicalFacts(t, facts), "historical evidence cannot admit recurring V3")
	document["candidate"].(map[string]any)["evidence_version"] = 3
	assertQualificationRefused(t, binary, qualificationDocument(t, document), "unknown evidence version")
}
