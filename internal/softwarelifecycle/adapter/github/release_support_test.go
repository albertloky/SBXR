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
	fixture := newLatestReleaseFixture(t)
	support := softwarelifecycle.ReleaseSupport{Scope: softwarelifecycle.FirstSubscriptionCleanInstall, Sources: []softwarelifecycle.ReleaseIdentity{}, Contract: softwarelifecycle.SubscriptionUpdateContract}
	var assets []softwarelifecycle.LatestAssetProof
	for _, name := range softwarelifecycle.LatestReleaseIndexedAssetNames() {
		assets = append(assets, softwarelifecycle.LatestAssetProof{Name: name, Size: int64(len(fixture.assets[name])), SHA256: fixture.digests[name]})
	}
	index, err := softwarelifecycle.BuildSubscriptionReleaseIndex(fixture.release.Tag, fixtureCommit, 17, assets, support)
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
	fixture.release.Body = body
	source := NewWithEndpoint(fixture.server.Client(), fixture.server.URL, fixture.verifier)
	if got, outcome := source.CheckLatest(t.Context()); outcome != softwarelifecycle.LatestReleaseAccepted || got.Support == nil || got.Support.Scope != softwarelifecycle.FirstSubscriptionCleanInstall {
		t.Fatalf("CheckLatest=%+v %v", got, outcome)
	}
	for _, mutated := range []string{strings.Replace(body, "Release support: ", "Unknown support: ", 1), strings.Replace(body, "first-subscription-clean-install", "recurring-subscription-upgrade", 1), strings.Replace(body, "Karing macOS: Passed", "Karing macOS: Not tested", 1)} {
		fixture.release.Body = mutated
		if _, outcome := source.CheckLatest(t.Context()); outcome == softwarelifecycle.LatestReleaseAccepted {
			t.Fatal("unbound support admitted")
		}
	}
}
