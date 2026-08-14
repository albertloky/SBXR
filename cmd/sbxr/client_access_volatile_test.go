package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

func TestClientAccessVolatileDigestChangesWithReviewedArtifactsAndSystemState(t *testing.T) {
	root := t.TempDir()
	paths := []string{"etc/sbxr/xray/config.json", "etc/sbxr/sing-box/config.json", "var/lib/sbxr/subscriptions/current/serving.json"}
	for _, name := range subscriptionpublication.Names() {
		paths = append(paths, filepath.Join("var/lib/sbxr/subscriptions/current", name))
	}
	for _, name := range paths {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil || os.WriteFile(path, []byte(name), 0o644) != nil {
			t.Fatal("write reviewed artifact")
		}
	}
	state := "reviewed"
	runner := func(context.Context, string, ...string) ([]byte, error) { return []byte(state), nil }
	first, err := clientAccessVolatileSHAAt(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	state = "changed"
	second, err := clientAccessVolatileSHAAt(root, runner)
	if err != nil || first == second {
		t.Fatalf("volatile digests = %q, %q; err=%v", first, second, err)
	}
}
