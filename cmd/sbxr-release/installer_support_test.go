package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestGeneratedInstallerAcceptsPackagedSupportIndexes(t *testing.T) {
	for _, test := range []struct {
		name, scope string
		sources     int
	}{
		{"schema1", "", 0},
		{"first", softwarelifecycle.FirstSubscriptionCleanInstall, 0},
		{"repair", softwarelifecycle.SubscriptionCleanInstallRepair, 0},
		{"recurring", softwarelifecycle.RecurringSubscriptionUpgrade, 1},
		{"recurring maximum sources", softwarelifecycle.RecurringSubscriptionUpgrade, 32},
	} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(test.name+"/"+arch, func(t *testing.T) {
				fixture := newInstallerFixture(t)
				body := buildInstallerSupportIndex(t, fixture, test.scope, test.sources)
				release, ok := verifyInstallerSupportIndex(t, fixture, body)
				if !ok {
					t.Fatal("packaged index refused by the Go reader")
				}
				if test.scope != "" {
					want := installerSupport(test.scope, test.sources).lifecycle()
					if !reflect.DeepEqual(release.Support, &want) {
						t.Fatal("packaging changed the support declaration")
					}
				}
				if err := verifyReleasePackage(packageVerificationOptions{directory: filepath.Join(fixture.root, "fixtures"), architecture: softwarelifecycle.Architecture(arch)}); err != nil {
					t.Fatalf("package verification: %v", err)
				}
				wantExecutable := fixture.executable
				if arch == "arm64" {
					if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/arm64"), []byte("1"), 0600); err != nil {
						t.Fatal(err)
					}
					wantExecutable = installerExecutable(t, installerPayload(t, arch), "v2.0.0", strings.Repeat("a", 40), 17, arch)
				}
				output, err := exec.Command("bash", fixture.script).CombinedOutput()
				if err != nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") {
					t.Fatalf("install = %v, %q", err, output)
				}
				assertInstalledFixtureForArchitecture(t, fixture.root, wantExecutable, arch)
				assertInstallerWorkCleaned(t, fixture)
				before := installerAuthoritySnapshot(t, fixture.root)
				output, err = exec.Command("bash", fixture.script).CombinedOutput()
				if err != nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT") {
					t.Fatalf("repeat install = %v, %q", err, output)
				}
				if after := installerAuthoritySnapshot(t, fixture.root); !reflect.DeepEqual(before, after) {
					t.Fatal("repeat install changed the installed pair")
				}
				assertInstallerWorkCleaned(t, fixture)
			})
		}
	}
}

func TestGeneratedInstallerRefusesMalformedSupportIndexes(t *testing.T) {
	source, err := json.Marshal(installerSupport(softwarelifecycle.RecurringSubscriptionUpgrade, 1).lifecycle().Sources[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, old, new string }{
		{"unknown scope", `recurring-subscription-upgrade`, `unknown-scope`},
		{"unknown contract", `sbxr-subscription-update-v1`, `sbxr-subscription-update-v2`},
		{"missing contract", `,"contract":"sbxr-subscription-update-v1"`, ``},
		{"empty recurring sources", string(source), ``},
		{"null sources", `[` + string(source) + `]`, `null`},
		{"object sources", `[` + string(source) + `]`, string(source)},
		{"missing sources", `"sources":[` + string(source) + `],`, ``},
		{"duplicate source", string(source), string(source) + `,` + string(source)},
		{"too many sources", string(source), installerSourceList(t, 33)},
		{"first scope with source", `recurring-subscription-upgrade`, `first-subscription-clean-install`},
		{"repair scope with source", `recurring-subscription-upgrade`, `subscription-clean-install-repair`},
		{"source repository", `"Repository":"albertloky/SBXR"`, `"Repository":"other/SBXR"`},
		{"source missing repository", `"Repository":"albertloky/SBXR",`, ``},
		{"source tag", `"Tag":"v1.0.0"`, `"Tag":"latest"`},
		{"source tag leading zero", `"Tag":"v1.0.0"`, `"Tag":"v01.0.0"`},
		{"source tag separator", `"Tag":"v1.0.0"`, `"Tag":"v1x0x0"`},
		{"source commit", `"Commit":"` + strings.Repeat("c", 40) + `"`, `"Commit":"short"`},
		{"source uppercase commit", `"Commit":"` + strings.Repeat("c", 40) + `"`, `"Commit":"` + strings.Repeat("C", 40) + `"`},
		{"source index digest", `"IndexSHA256":"` + strings.Repeat("d", 64) + `"`, `"IndexSHA256":"short"`},
		{"source unknown field", `"Tag":"v1.0.0"`, `"Tag":"v1.0.0","unknown":true`},
		{"source duplicate field", `"Tag":"v1.0.0"`, `"Tag":"v1.0.0","Tag":"v1.0.0"`},
		{"support unknown field", `"scope":`, `"unknown":true,"scope":`},
		{"support duplicate field", `"scope":`, `"scope":"recurring-subscription-upgrade","scope":`},
		{"schema1 with support", `"schema":2`, `"schema":1`},
		{"unknown schema", `"schema":2`, `"schema":3`},
		{"candidate repository", `"repository":"albertloky/SBXR"`, `"repository":"other/SBXR"`},
		{"candidate tag", `"tag":"v2.0.0"`, `"tag":"v2.0.1"`},
		{"candidate commit", `"commit":"` + strings.Repeat("a", 40) + `"`, `"commit":"` + strings.Repeat("b", 40) + `"`},
		{"unknown index field", `"schema":2`, `"schema":2,"unknown":true`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			body := buildInstallerSupportIndex(t, fixture, softwarelifecycle.RecurringSubscriptionUpgrade, 1)
			changed := strings.Replace(string(body), test.old, test.new, 1)
			if changed == string(body) {
				t.Fatal("mutation did not change the index")
			}
			if _, ok := verifyInstallerSupportIndex(t, fixture, []byte(changed)); ok {
				t.Fatal("malformed index admitted by the Go reader")
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/release-index.json"), []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			assertInstallerReleaseRefused(t, fixture)
		})
	}
}

func TestGeneratedInstallerRecurringIndexPreservesReleaseChecks(t *testing.T) {
	for _, name := range []string{"sequence", "source field case", "extra document", "archive size", "archive digest", "ELF architecture", "executable digest"} {
		t.Run(name, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			body := buildInstallerSupportIndex(t, fixture, softwarelifecycle.RecurringSubscriptionUpgrade, 1)
			switch name {
			case "sequence":
				body = []byte(strings.Replace(string(body), `"sequence":17`, `"sequence":18`, 1))
			case "source field case":
				// The shell accepts only the packager's canonical encoding, even
				// where Go's JSON decoder would also accept case-insensitive keys.
				body = []byte(strings.Replace(string(body), `"Repository":`, `"repository":`, 1))
			case "extra document":
				body = append(body, []byte("\n{}\n")...)
			case "archive size", "archive digest":
				path := filepath.Join(fixture.root, "fixtures/sbxr-linux-amd64.tar.gz")
				archive, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if name == "archive size" {
					archive = archive[:len(archive)-1]
				} else {
					archive[len(archive)-1] ^= 1
				}
				if err := os.WriteFile(path, archive, 0600); err != nil {
					t.Fatal(err)
				}
			case "ELF architecture", "executable digest":
				payload := installerPayload(t, "arm64")
				if name == "executable digest" {
					payload = installerPayload(t, "amd64")
					payload[len(payload)-1] ^= 1
				}
				executable := installerExecutable(t, payload, "v2.0.0", strings.Repeat("a", 40), 17, "amd64")
				replaceInstallerArchiveProof(t, fixture.root, "amd64", executable)
				var err error
				body, err = os.ReadFile(filepath.Join(fixture.root, "fixtures/release-index.json"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/release-index.json"), body, 0600); err != nil {
				t.Fatal(err)
			}
			assertInstallerReleaseRefused(t, fixture)
		})
	}
}

func installerSupport(scope string, count int) v3ReleaseSupport {
	support := v3ReleaseSupport{Scope: scope, Contract: softwarelifecycle.SubscriptionUpdateContract, Sources: []decisionReleaseIdentity{}}
	for i := 0; i < count; i++ {
		support.Sources = append(support.Sources, decisionReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: fmt.Sprintf("v1.0.%d", i), Commit: strings.Repeat("c", 40), ReleaseIndexSHA256: strings.Repeat("d", 64)})
	}
	return support
}

func installerSourceList(t *testing.T, count int) string {
	t.Helper()
	body, err := json.Marshal(installerSupport(softwarelifecycle.RecurringSubscriptionUpgrade, count).lifecycle().Sources)
	if err != nil {
		t.Fatal(err)
	}
	return string(body[1 : len(body)-1])
}

// Exercise the production packaging entry point, not a hand-built support suffix.
// curl is fixture transport; the generated shell parser and install run unchanged.
func buildInstallerSupportIndex(t *testing.T, fixture installerFixture, scope string, count int) []byte {
	t.Helper()
	directory := filepath.Join(fixture.root, "fixtures")
	script, err := os.ReadFile(fixture.script)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "install.sh"), script, 0600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(directory, "release-index.json")
	if scope != "" {
		if err := os.Remove(index); err != nil {
			t.Fatal(err)
		}
		support := filepath.Join(fixture.root, "support.json")
		if err := os.WriteFile(support, []byte(qualificationDocument(t, installerSupport(scope, count))), 0600); err != nil {
			t.Fatal(err)
		}
		if err := buildReleaseIndexFile(indexOptions{tag: "v2.0.0", commit: strings.Repeat("a", 40), sequence: 17, directory: directory, output: index, support: support}); err != nil {
			t.Fatal(err)
		}
	} else {
		body, err := softwarelifecycle.BuildLatestReleaseIndex("v2.0.0", strings.Repeat("a", 40), 17, installerAssetProofs(t, fixture))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(index, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func installerAssetProofs(t *testing.T, fixture installerFixture) []softwarelifecycle.LatestAssetProof {
	t.Helper()
	var proofs []softwarelifecycle.LatestAssetProof
	for _, name := range softwarelifecycle.LatestReleaseIndexedAssetNames() {
		body, err := os.ReadFile(filepath.Join(fixture.root, "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		proofs = append(proofs, softwarelifecycle.LatestAssetProof{Name: name, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])})
	}
	return proofs
}

func verifyInstallerSupportIndex(t *testing.T, fixture installerFixture, body []byte) (softwarelifecycle.LatestRelease, bool) {
	t.Helper()
	digest := sha256.Sum256(body)
	proofs := append(installerAssetProofs(t, fixture), softwarelifecycle.LatestAssetProof{Name: "release-index.json", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])})
	return softwarelifecycle.VerifyLatestReleaseIndex(softwarelifecycle.Repository, "v2.0.0", strings.Repeat("a", 40), body, proofs)
}

func assertInstallerReleaseRefused(t *testing.T, fixture installerFixture) {
	t.Helper()
	before := installerAuthoritySnapshot(t, fixture.root)
	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-RELEASE-REFUSED" {
		t.Fatalf("release refusal = %v, %q", err, body)
	}
	if after := installerAuthoritySnapshot(t, fixture.root); !reflect.DeepEqual(before, after) {
		t.Fatal("release refusal changed installation authority")
	}
	assertInstallerWorkCleaned(t, fixture)
}

func assertInstallerWorkCleaned(t *testing.T, fixture installerFixture) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(fixture.root, "tmp"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("installer temporary material remains: %v, %v", entries, err)
	}
}
