package softwarelifecycle

import (
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
