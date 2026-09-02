package softwarelifecycle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildLatestReleaseIndexUsesPortableAssetFieldNames(t *testing.T) {
	assets := make([]LatestAssetProof, 0, len(latestIndexedAssetNames))
	for _, name := range latestIndexedAssetNames {
		assets = append(assets, LatestAssetProof{Name: name, Size: 1, SHA256: strings.Repeat("a", 64)})
	}
	body, err := BuildLatestReleaseIndex("v2.0.0", strings.Repeat("b", 40), 17, assets)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `"name":"install.sh","size":1,"sha256":"`) || strings.Contains(text, `"Name"`) {
		t.Fatalf("release index asset fields are not portable: %s", text)
	}
}

func TestSubscriptionIndexBindsScopeSourcesAndContract(t *testing.T) {
	assets := []LatestAssetProof{}
	for _, name := range LatestReleaseIndexedAssetNames() {
		assets = append(assets, LatestAssetProof{Name: name, Size: 1, SHA256: strings.Repeat("a", 64)})
	}
	source := ReleaseIdentity{Repository: Repository, Tag: "v3.0.22", Commit: strings.Repeat("b", 40), IndexSHA256: strings.Repeat("c", 64)}
	for _, support := range []ReleaseSupport{
		{Scope: FirstSubscriptionCleanInstall, Sources: []ReleaseIdentity{}, Contract: SubscriptionUpdateContract},
		{Scope: SubscriptionCleanInstallRepair, Sources: []ReleaseIdentity{}, Contract: SubscriptionUpdateContract},
		{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{source}, Contract: SubscriptionUpdateContract},
	} {
		body, err := BuildSubscriptionReleaseIndex("v3.0.23", strings.Repeat("d", 40), 23, assets, support)
		if err != nil {
			t.Fatal(err)
		}
		proofs := append(append([]LatestAssetProof{}, assets...), LatestAssetProof{Name: "release-index.json", Size: int64(len(body)), SHA256: digestBytes(body)})
		release, ok := VerifyLatestReleaseIndex(Repository, "v3.0.23", strings.Repeat("d", 40), body, proofs)
		if !ok || release.Support == nil || release.Support.Scope != support.Scope || supportedUpdate(release, source, true) != (support.Scope == RecurringSubscriptionUpgrade) {
			t.Fatalf("scope lost: %+v", release)
		}
	}
	for _, support := range []ReleaseSupport{
		{Scope: FirstSubscriptionCleanInstall, Sources: []ReleaseIdentity{source}, Contract: SubscriptionUpdateContract},
		{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{}, Contract: SubscriptionUpdateContract},
		{Scope: RecurringSubscriptionUpgrade, Sources: []ReleaseIdentity{source, source}, Contract: SubscriptionUpdateContract},
		{Scope: FirstSubscriptionCleanInstall, Contract: SubscriptionUpdateContract},
		{Scope: FirstSubscriptionCleanInstall, Sources: []ReleaseIdentity{}, Contract: "unknown"},
		{Scope: SubscriptionCleanInstallRepair, Sources: []ReleaseIdentity{source}, Contract: SubscriptionUpdateContract},
		{Scope: SubscriptionCleanInstallRepair, Contract: SubscriptionUpdateContract},
		{Scope: SubscriptionCleanInstallRepair, Sources: []ReleaseIdentity{}, Contract: "unknown"},
	} {
		if _, err := BuildSubscriptionReleaseIndex("v3.0.23", strings.Repeat("d", 40), 23, assets, support); err == nil {
			t.Fatalf("invalid support admitted: %+v", support)
		}
		body, err := json.Marshal(latestReleaseIndex{Schema: 2, Repository: Repository, Tag: "v3.0.23", Commit: strings.Repeat("d", 40), Sequence: 23, Assets: assets, Support: &support})
		if err != nil {
			t.Fatal(err)
		}
		proofs := append(append([]LatestAssetProof{}, assets...), LatestAssetProof{Name: "release-index.json", Size: int64(len(body)), SHA256: digestBytes(body)})
		if _, ok := VerifyLatestReleaseIndex(Repository, "v3.0.23", strings.Repeat("d", 40), body, proofs); ok {
			t.Fatalf("invalid indexed support admitted: %+v", support)
		}
	}
}
