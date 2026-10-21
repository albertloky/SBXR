package proxyinstallation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedInstallerRemovalJournalsAreSupportedProductAuthority(t *testing.T) {
	paths, err := filepath.Glob("testdata/removal-recovery/*.json")
	if err != nil || len(paths) < 8 {
		t.Fatalf("missing shared recovery fixtures: %v", err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		record, valid := decodeOwnership(body)
		if err != nil || !valid || record.Direction != removalRequired {
			t.Fatalf("unsupported shared journal %s: %v", path, err)
		}
	}
}
