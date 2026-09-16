package architecture_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestReleaseAssetDownloadTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", ".github/scripts/test_download_release_asset.py", "-v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("release asset transport: %v\n%s", err, output)
	}
}

func TestAuthenticatedReleaseDownloadsUseSharedTransport(t *testing.T) {
	for path, count := range map[string]int{
		".github/workflows/candidate.yml":              3,
		".github/workflows/stable.yml":                 2,
		".github/scripts/recheck-qualified-release.sh": 1,
		".github/scripts/release-history.sh":           1,
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(body), "download-release-asset.py") != count || strings.Contains(string(body), "releases/assets/") {
			t.Fatalf("%s bypasses the authenticated asset transport", path)
		}
	}
}
