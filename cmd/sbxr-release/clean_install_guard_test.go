package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCleanInstallOnlyBootstrapPreservesExistingInstallation(t *testing.T) {
	fixture := newInstallerFixture(t)
	indexPath := filepath.Join(fixture.root, "fixtures/release-index.json")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	index = []byte(strings.TrimSuffix(strings.Replace(string(index), `"schema":1`, `"schema":2`, 1), "}\n") + `,"support":{"scope":"subscription-clean-install-only","sources":[],"contract":"sbxr-subscription-update-v1"}}` + "\n")
	if err := os.WriteFile(indexPath, index, 0600); err != nil {
		t.Fatal(err)
	}
	if body, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") {
		t.Fatalf("fresh clean-only install = %v, %q", err, body)
	}
	assertInstalledFixture(t, fixture.root, fixture.executable)

	before := installerAuthoritySnapshot(t, fixture.root)
	if body, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT") {
		t.Fatalf("exact-current clean-only install = %v, %q", err, body)
	}
	if after := installerAuthoritySnapshot(t, fixture.root); !reflect.DeepEqual(before, after) {
		t.Fatal("exact-current bootstrap changed installation authority")
	}

	setInstalledIdentity(t, fixture.root, "v1.9.9", strings.Repeat("d", 40), 16)
	before = installerAuthoritySnapshot(t, fixture.root)
	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED" {
		t.Fatalf("install over existing release = %v, %q", err, body)
	}
	if after := installerAuthoritySnapshot(t, fixture.root); !reflect.DeepEqual(before, after) {
		t.Fatal("refused bootstrap changed existing installation authority")
	}
}
