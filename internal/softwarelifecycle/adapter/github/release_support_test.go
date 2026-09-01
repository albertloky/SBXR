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
	for _, exception := range []bool{false, true} {
		t.Run(map[bool]string{false: "qualified", true: "owner-exception"}[exception], func(t *testing.T) { testCleanInstallSupport(t, exception) })
	}
}

func testCleanInstallSupport(t *testing.T, exception bool) {
	fixture := newLatestReleaseFixture(t)
	sequence := uint64(17)
	if exception {
		fixture.release.Tag, sequence = "v3.1.0", 83
	}
	support := softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.FirstSubscriptionCleanInstall, Sources: []softwarelifecycle.ReleaseIdentity{}, Contract: softwarelifecycle.SubscriptionUpdateContract}
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
	if exception {
		body = strings.NewReplacer("Tag: v2.0.0", "Tag: v3.1.0", "Sequence: 17", "Sequence: 83", "Status: Qualified", "Status: Qualified by Owner exception", "RELEASE-V3-SUBSCRIPTION-CLEAN-INSTALL-QUALIFICATION", softwarelifecycle.OwnerExceptionCode, "Integrated Verification: Passed on live Ubuntu Server 24.04 amd64 and Karing macOS", "Integrated Verification: "+softwarelifecycle.OwnerExceptionLive, "Codex Live Acceptance: Passed", "Codex Live Acceptance: "+softwarelifecycle.OwnerExceptionLive, "Owner Acceptance: Not required", "Owner Acceptance: One-release exception approved", "Secret-safe result: Passed", "Secret-safe result: "+softwarelifecycle.OwnerExceptionSecrets, "Karing macOS: Passed", "Karing macOS: "+softwarelifecycle.OwnerExceptionLive).Replace(body)
		body += "Owner exception: " + softwarelifecycle.OwnerExceptionID + "\nLive qualification: Incomplete\nClient compatibility: static-official-evidence-passed-live-karing-pending\n"
	}
	fixture.release.Body = body
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
	if got, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseAccepted || got.Support == nil || got.Support.Scope != softwarelifecycle.FirstSubscriptionCleanInstall {
		t.Fatalf("CheckLatest=%+v %v", got, outcome)
	}
	mutations := []string{strings.Replace(body, "Release support: ", "Unknown support: ", 1), strings.Replace(body, "first-subscription-clean-install", "recurring-subscription-upgrade", 1)}
	if exception {
		mutations = append(mutations, strings.Replace(body, "Sequence: 83", "Sequence: 84", 1), strings.Replace(body, softwarelifecycle.OwnerExceptionID, "other", 1), strings.ReplaceAll(body, softwarelifecycle.OwnerExceptionLive, "Passed"), strings.Replace(body, "Live qualification: Incomplete", "Live qualification: Complete", 1))
	} else {
		mutations = append(mutations, strings.Replace(body, "Karing macOS: Passed", "Karing macOS: Not tested", 1))
	}
	for _, mutated := range mutations {
		fixture.release.Body = mutated
		if _, outcome := source.CheckLatest(t.Context()); outcome == softwarelifecycle.LatestReleaseAccepted {
			t.Fatal("unbound support admitted")
		}
	}
}
