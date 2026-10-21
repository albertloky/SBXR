package architecture_test

import (
	"context"
	"os/exec"
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
