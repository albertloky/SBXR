package github

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"strings"
	"testing"
)

func TestSourceBindsCleanInstallSupportToQualifiedIndex(t *testing.T) {
	for _, scope := range []string{softwarelifecycle.FirstSubscriptionCleanInstall, softwarelifecycle.SubscriptionCleanInstallRepair} {
		for _, exception := range []bool{false, true} {
			t.Run(scope+"/"+map[bool]string{false: "qualified", true: "owner-exception"}[exception], func(t *testing.T) {
				testCleanInstallSupport(t, scope, exception, softwarelifecycle.RepairEvidencePolicy)
			})
		}
	}
	t.Run("latency-policy", func(t *testing.T) {
		testCleanInstallSupport(t, softwarelifecycle.SubscriptionCleanInstallRepair, false, "repair-issuance-bounded-v3")
	})
}

func TestUniqueRecordValueRefusesEmptyFirstAndDuplicateRecords(t *testing.T) {
	for _, body := range []string{
		"Evidence policy: \nEvidence policy: " + softwarelifecycle.RepairEvidencePolicy,
		"Evidence policy: " + softwarelifecycle.RepairEvidencePolicy + "\nEvidence policy: " + softwarelifecycle.RepairEvidencePolicy,
	} {
		if _, ok := uniqueRecordValue(body, "Evidence policy: "); ok {
			t.Fatal("duplicate record accepted")
		}
	}
}

func testCleanInstallSupport(t *testing.T, scope string, exception bool, policy string) {
	fixture := newLatestReleaseFixture(t)
	sequence := uint64(17)
	if exception {
		fixture.release.Tag, sequence = "v3.1.0", 83
	}
	support := softwarelifecycle.ReleaseSupport{Scope: scope, Sources: []softwarelifecycle.ReleaseIdentity{}, Contract: softwarelifecycle.SubscriptionUpdateContract}
	var assets []softwarelifecycle.LatestAssetProof
	for _, name := range softwarelifecycle.LatestReleaseIndexedAssetNames() {
		assets = append(assets, softwarelifecycle.LatestAssetProof{Name: name, Size: int64(len(fixture.assets[name])), SHA256: fixture.digests[name]})
	}
	index, err := softwarelifecycle.BuildSubscriptionReleaseIndex(fixture.release.Tag, fixtureCommit, sequence, assets, support)
	if err != nil {
		t.Fatal(err)
	}
	fixture.assets["release-index.json"] = index
	digest := sha256.Sum256(index)
	fixture.digests["release-index.json"] = hex.EncodeToString(digest[:])
	for i, asset := range fixture.release.Assets {
		if asset.Name == "release-index.json" {
			fixture.release.Assets[i].Digest = "sha256:" + fixture.digests[asset.Name]
			fixture.release.Assets[i].Size = int64(len(index))
		}
	}
	body := strings.NewReplacer(
		"# SBXR Installer-Updater Acceptance Record", "# SBXR Acceptance Record",
		"Qualification role: Discovered, installed, recovered, final latest release", "Qualification role: Clean-installed subscription-capable V3 release",
		"Stable result code: RELEASE-INSTALLER-UPDATER-TWO-RELEASE-QUALIFICATION", "Stable result code: RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION",
		"Integrated Verification: Passed on live Ubuntu Server 24.04 amd64", "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and Karing macOS",
	).Replace(fixture.acceptanceRecord())
	encoded, _ := json.Marshal(support)
	body += "Release support: " + string(encoded) + "\nDetailed evidence SHA-256: " + strings.Repeat("a", 64) + "\nProxy package: sing-box 1.13.19 amd64 fb628b8cedf3e4c7cb32aa9c5103e0457e65ebb35ef510d041118836ef3b33bf\nKaring package: karing 1.2.0 macos-arm64 " + strings.Repeat("b", 64) + "\nKaring macOS: Passed\nNatural timer firing and naturally due certificate renewal: Not observed\nUnsupported new or renamed renewal route: May execute before detection; historical outcomes unknown\n"
	if scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		body += "Evidence policy: " + policy + "\nAutomated-only scenarios (not live): " + softwarelifecycle.RepairAutomatedOnlyScenarios + "\nAutomated-only result: Passed in native amd64/arm64 workflow\n"
		if policy == "repair-issuance-bounded-v3" {
			body += "Automated-only checks (not live): " + softwarelifecycle.RepairAutomatedOnlyChecks + "\nKaring connectivity evidence: " + softwarelifecycle.RepairKaringConnectivityEvidence + "\nKaring checks not performed: " + softwarelifecycle.RepairKaringChecksNotPerformed + "\n"
		}
	}
	if exception {
		body = strings.NewReplacer("Tag: v2.0.0", "Tag: v3.1.0", "Sequence: 17", "Sequence: 83", "Status: Qualified", "Status: Qualified by Owner exception", "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION", softwarelifecycle.OwnerExceptionCode, "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and Karing macOS", "Integrated Verification: "+softwarelifecycle.OwnerExceptionLive, "Codex Live Acceptance: Passed", "Codex Live Acceptance: "+softwarelifecycle.OwnerExceptionLive, "Owner Acceptance: Not required", "Owner Acceptance: One-release exception approved", "Secret-safe result: Passed", "Secret-safe result: "+softwarelifecycle.OwnerExceptionSecrets, "Karing macOS: Passed", "Karing macOS: "+softwarelifecycle.OwnerExceptionLive).Replace(body)
		body += "Owner exception: " + softwarelifecycle.OwnerExceptionID + "\nLive qualification: Incomplete\nClient compatibility: static-official-evidence-passed-live-karing-pending\n"
	}
	fixture.release.Body = body
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
	latest := softwarelifecycle.LatestRelease{Identity: softwarelifecycle.ReleaseIdentity{Tag: fixture.release.Tag}, Sequence: sequence, Support: &support}
	refusedException := exception && scope == softwarelifecycle.SubscriptionCleanInstallRepair
	if qualifiedReleaseSupport(body, latest) == refusedException {
		t.Fatal("public support result did not match its scope")
	}
	if refusedException {
		if _, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseRefused {
			t.Fatal("repair Owner exception admitted")
		}
		return
	}
	if got, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseAccepted || got.Support == nil || got.Support.Scope != scope {
		t.Fatalf("CheckLatest=%+v %v", got, outcome)
	}
	mutations := []string{strings.Replace(body, "Release support: ", "Unknown support: ", 1), strings.Replace(body, scope, softwarelifecycle.RecurringSubscriptionUpgrade, 1)}
	if scope == softwarelifecycle.SubscriptionCleanInstallRepair {
		mutations = append(mutations,
			strings.Replace(body, "Evidence policy: "+policy, "Evidence policy: unknown", 1),
			strings.Replace(body, "Automated-only scenarios (not live): "+softwarelifecycle.RepairAutomatedOnlyScenarios, "Automated-only scenarios (not live): ", 1),
			strings.Replace(body, "Automated-only result: Passed in native amd64/arm64 workflow", "Automated-only result: Passed", 1),
			body+"Scenario: enable-precommit "+strings.Repeat("a", 64)+" https://github.com/albertloky/SBXR/actions/runs/17#artifacts\n",
		)
		if policy == "repair-issuance-bounded-v3" {
			mutations = append(mutations,
				strings.Replace(body, "Karing connectivity evidence: "+softwarelifecycle.RepairKaringConnectivityEvidence+"\n", "", 1),
				strings.Replace(body, "Karing checks not performed: "+softwarelifecycle.RepairKaringChecksNotPerformed+"\n", "", 1),
			)
		}
	} else {
		mutations = append(mutations, body+"Evidence policy: "+softwarelifecycle.RepairEvidencePolicy+"\nAutomated-only scenarios (not live): "+softwarelifecycle.RepairAutomatedOnlyScenarios+"\nAutomated-only result: Passed in native amd64/arm64 workflow\n")
	}
	if exception {
		mutations = append(mutations, strings.Replace(body, "Sequence: 83", "Sequence: 84", 1), strings.Replace(body, softwarelifecycle.OwnerExceptionID, "other", 1), strings.ReplaceAll(body, softwarelifecycle.OwnerExceptionLive, "Passed"), strings.Replace(body, "Live qualification: Incomplete", "Live qualification: Complete", 1))
	} else {
		mutations = append(mutations, strings.Replace(body, "Karing macOS: Passed", "Karing macOS: Not tested", 1))
		mutations = append(mutations, strings.Replace(body, "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION", "RELEASE-V3-SUBSCRIPTION-QUALIFICATION", 1))
	}
	for _, mutated := range mutations {
		fixture.release.Body = mutated
		if _, outcome := source.CheckLatest(t.Context()); outcome == softwarelifecycle.LatestReleaseAccepted {
			t.Fatal("unbound support admitted")
		}
	}
}

func TestQualifiedReleaseSupportRefusesPolicyOnHistoricalRelease(t *testing.T) {
	if qualifiedReleaseSupport("Evidence policy: "+softwarelifecycle.RepairEvidencePolicy+"\n", softwarelifecycle.LatestRelease{}) {
		t.Fatal("historical release accepted a repair policy")
	}
}

func TestQualifiedReleaseSupportBindsRepairV2CheckDisclosure(t *testing.T) {
	support := softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []softwarelifecycle.ReleaseIdentity{}, Contract: softwarelifecycle.SubscriptionUpdateContract}
	encoded, _ := json.Marshal(support)
	body := "Release support: " + string(encoded) + "\nStable result code: RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION\nEvidence policy: repair-issuance-bounded-v2\nAutomated-only scenarios (not live): " + softwarelifecycle.RepairAutomatedOnlyScenarios + "\nAutomated-only result: Passed in native amd64/arm64 workflow\n"
	line := "Automated-only checks (not live): lifecycle-menu/explicit-confirmation lifecycle-menu/clean-install-target-refused\n"
	release := softwarelifecycle.LatestRelease{Support: &support}
	if !qualifiedReleaseSupport(body+line, release) {
		t.Fatal("exact v2 disclosure refused")
	}
	for _, changed := range []string{
		body, body + line + line,
		body + "Automated-only checks (not live): \n" + line,
		body + strings.Replace(line, "lifecycle-menu/explicit-confirmation ", "", 1),
		body + strings.Replace(line, "\n", " lifecycle-menu/safe-no-update\n", 1),
		body + "Automated-only checks (not live): lifecycle-menu/clean-install-target-refused lifecycle-menu/explicit-confirmation\n",
		strings.Replace(body, "repair-issuance-bounded-v2", softwarelifecycle.RepairEvidencePolicy, 1) + line,
	} {
		if qualifiedReleaseSupport(changed, release) {
			t.Fatal("changed or historical check disclosure accepted")
		}
	}
	for _, scope := range []string{softwarelifecycle.FirstSubscriptionCleanInstall, softwarelifecycle.RecurringSubscriptionUpgrade} {
		support.Scope = scope
		encoded, _ = json.Marshal(support)
		if qualifiedReleaseSupport("Release support: "+string(encoded)+"\nStable result code: RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION\n"+line, release) {
			t.Fatal("check disclosure accepted outside repair")
		}
	}
	if qualifiedReleaseSupport(line, softwarelifecycle.LatestRelease{}) {
		t.Fatal("check disclosure accepted without support")
	}
}

func TestQualifiedReleaseSupportBindsRepairLatencyDisclosure(t *testing.T) {
	support := softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.SubscriptionCleanInstallRepair, Sources: []softwarelifecycle.ReleaseIdentity{}, Contract: softwarelifecycle.SubscriptionUpdateContract}
	encoded, _ := json.Marshal(support)
	body := "Release support: " + string(encoded) + "\nStable result code: RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION\nEvidence policy: repair-issuance-bounded-v3\nAutomated-only scenarios (not live): " + softwarelifecycle.RepairAutomatedOnlyScenarios + "\nAutomated-only result: Passed in native amd64/arm64 workflow\nAutomated-only checks (not live): " + softwarelifecycle.RepairAutomatedOnlyChecks + "\n"
	coverage := "Karing connectivity evidence: Fresh per-node latency; current connection preserved; no Karing browsing or established-session claim\n"
	excluded := "Karing checks not performed: karing-final/direct-and-proxied-traffic karing-final/old-established-session-terminated karing-final/traffic-restored karing-final/direct-refresh-correction-or-confirmed-fallback\n"
	release := softwarelifecycle.LatestRelease{Support: &support}
	if !qualifiedReleaseSupport(body+coverage+excluded, release) {
		t.Fatal("exact latency disclosure refused")
	}
	for _, changed := range []string{
		body, body + coverage, body + excluded,
		body + coverage + excluded + coverage, body + coverage + excluded + excluded,
		body + strings.Replace(coverage, "Fresh per-node latency", "Full traffic passed", 1) + excluded,
		body + coverage + strings.Replace(excluded, "karing-final/old-established-session-terminated ", "", 1),
		strings.Replace(body, "repair-issuance-bounded-v3", "repair-issuance-bounded-v2", 1) + coverage + excluded,
		strings.Replace(body, "repair-issuance-bounded-v3", "repair-issuance-bounded-v1", 1) + coverage + excluded,
	} {
		if qualifiedReleaseSupport(changed, release) {
			t.Fatal("altered or historical latency disclosure accepted")
		}
	}
	for _, scope := range []string{softwarelifecycle.FirstSubscriptionCleanInstall, softwarelifecycle.RecurringSubscriptionUpgrade} {
		support.Scope = scope
		encoded, _ = json.Marshal(support)
		if qualifiedReleaseSupport("Release support: "+string(encoded)+"\nStable result code: RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION\n"+coverage+excluded, release) {
			t.Fatal("latency disclosure accepted outside repair")
		}
	}
	if qualifiedReleaseSupport(coverage+excluded, softwarelifecycle.LatestRelease{}) {
		t.Fatal("latency disclosure accepted without support")
	}
}
