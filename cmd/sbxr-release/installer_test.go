package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestGeneratedInstallerRefusesNonRootBeforeMutation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "install.sh")
	if err := buildBootstrapFile(bootstrapOptions{
		version: "2.0.0", sequence: 17, tag: "v2.0.0",
		commit: strings.Repeat("a", 40), output: output,
		amd64ExecutableSHA256: strings.Repeat("b", 64), arm64ExecutableSHA256: strings.Repeat("c", 64),
	}); err != nil {
		t.Fatal(err)
	}

	command := exec.Command("bash", output)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	body, err := command.CombinedOutput()
	if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-HOST-REFUSED" {
		t.Fatalf("non-root install = %v, %q", err, body)
	}
}

func TestGeneratedInstallerSupportsOnlyFixedUbuntuHosts(t *testing.T) {
	t.Run("standard os-release link", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		if err := os.MkdirAll(filepath.Join(fixture.root, "usr/lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(fixture.root, "etc/os-release"), filepath.Join(fixture.root, "usr/lib/os-release")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../usr/lib/os-release", filepath.Join(fixture.root, "etc/os-release")); err != nil {
			t.Fatal(err)
		}
		body, err := exec.Command("bash", fixture.script).CombinedOutput()
		if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") {
			t.Fatalf("standard os-release link = %v, %q", err, body)
		}
	})

	t.Run("arm64", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/arm64"), []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
		body, err := exec.Command("bash", fixture.script).CombinedOutput()
		if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") {
			t.Fatalf("arm64 = %v, %q", err, body)
		}
		record, _ := os.ReadFile(filepath.Join(fixture.root, "var/lib/sbxr/installed.json"))
		if !strings.Contains(string(record), `"architecture":"arm64"`) {
			t.Fatalf("arm64 record = %q", record)
		}
	})

	for _, test := range []struct {
		name   string
		change func(t *testing.T, fixture installerFixture)
	}{
		{"architecture", func(t *testing.T, fixture installerFixture) {
			if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/unsupported"), []byte("1"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"release", func(t *testing.T, fixture installerFixture) {
			if err := os.WriteFile(filepath.Join(fixture.root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=22.04\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			test.change(t, fixture)
			body, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-HOST-REFUSED" {
				t.Fatalf("unsupported host = %v, %q", err, body)
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "run/lock/sbxr.lock")); !os.IsNotExist(err) {
				t.Fatalf("unsupported host reached lifecycle mutation: %v", err)
			}
		})
	}
}

func TestGeneratedInstallerInstallsQualifiedReleaseWithoutATerminal(t *testing.T) {
	fixture := newInstallerFixture(t)

	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err != nil {
		t.Fatalf("install = %v, %q", err, body)
	}
	if got := string(body); !strings.Contains(got, "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") || !strings.Contains(got, "Installed v2.0.0") || !strings.Contains(got, "Run: sudo sbxr") {
		t.Fatalf("install output = %q", body)
	}
	assertInstalledFixture(t, fixture.root, fixture.executable)
}

func TestPasteableInstallCommandRestoresOnlyTheReleaseCommittedForRemoval(t *testing.T) {
	for _, variant := range []int{1, 2, 3} {
		schema := variant
		if variant == 3 {
			schema = 2
		}
		t.Run(fmt.Sprint(variant), func(t *testing.T) {
			fixture := newInstallerFixture(t)
			if body, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil {
				t.Fatalf("initial install = %v, %q", err, body)
			}
			installedRecord := filepath.Join(fixture.root, "var/lib/sbxr/installed.json")
			installedBefore, err := os.ReadFile(installedRecord)
			if err != nil {
				t.Fatal(err)
			}
			index, err := os.ReadFile(filepath.Join(fixture.root, "fixtures/release-index.json"))
			if err != nil {
				t.Fatal(err)
			}
			indexDigest := sha256.Sum256(index)
			finisherJSON, err := json.Marshal(softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: hex.EncodeToString(indexDigest[:])})
			if err != nil {
				t.Fatal(err)
			}
			ownership := []byte(fmt.Sprintf(`{"schema":1,"phase":"Removal committed","unfinished_direction":"removal required","release_identity":%s,"proxy_package_identity":"","public_ipv4":"","destination_address":"","destination_server_name":"","configuration_sha256":"","permitted_resources":["/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1","/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority","/usr/local/bin/sbxr exact committed Release Identity","/var/lib/sbxr/installed.json exact committed Release Identity"],"cleanup_checkpoint":0,"removal_checkpoint":3}`+"\n", finisherJSON))
			if schema == 2 {
				// Keep canonical field order produced by the removal commitment.
				ownership = []byte(strings.Replace(string(ownership), `"schema":1`, `"schema":2`, 1))
				ownership = []byte(strings.Replace(string(ownership), `one-link schema-1`, `one-link schema-2`, 1))
				creatorJSON, err := json.Marshal(softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.21", Commit: strings.Repeat("e", 40), IndexSHA256: strings.Repeat("f", 64)})
				if err != nil {
					t.Fatal(err)
				}
				ownership = bytes.Replace(ownership, finisherJSON, creatorJSON, 1)
				ownership = []byte(strings.TrimSuffix(string(ownership), "}\n") + `,"resource_creating_releases":[` + string(creatorJSON) + `,` + string(creatorJSON) + `,` + string(creatorJSON) + `,` + string(creatorJSON) + `],"finishing_release_identity":` + string(finisherJSON) + "}\n")
			}
			if variant == 3 {
				ownership, err = os.ReadFile("../../internal/proxyinstallation/testdata/subscription-absent-schema2.json")
				if err != nil {
					t.Fatal(err)
				}
				ownership = bytes.Replace(ownership, []byte(`"phase":"Running","unfinished_direction":"none"`), []byte(`"phase":"Removal committed","unfinished_direction":"removal required"`), 1)
				ownership = bytes.Replace(ownership, []byte(`"removal_checkpoint":0`), []byte(`"removal_checkpoint":11`), 1)
				ownership = []byte(strings.TrimSuffix(string(ownership), "}\n") + `,"finishing_release_identity":` + string(finisherJSON) + "}\n")
			}
			ownershipPath := filepath.Join(fixture.root, "var/lib/sbxr/proxy-ownership.json")
			if err := os.WriteFile(ownershipPath, ownership, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(fixture.root, "usr/local/bin/sbxr")); err != nil {
				t.Fatal(err)
			}
			restorer := filepath.Join(fixture.root, "restore-newer-latest.sh")
			if err := buildBootstrapFile(bootstrapOptions{
				version: "2.0.1", sequence: 18, tag: "v2.0.1", commit: strings.Repeat("c", 40), output: restorer, root: fixture.root,
				amd64ExecutableSHA256: strings.Repeat("d", 64), arm64ExecutableSHA256: strings.Repeat("e", 64),
			}); err != nil {
				t.Fatal(err)
			}

			for name, wrong := range map[string][]byte{
				"unknown schema":             bytes.Replace(ownership, []byte(fmt.Sprintf(`"schema":%d`, schema)), []byte(`"schema":99`), 1),
				"unknown operation":          bytes.Replace(ownership, []byte(`"phase":`), []byte(`"operation":{},"phase":`), 1),
				"conflicting identity alias": bytes.Replace(ownership, []byte(`"Tag":`), []byte(`"tag":"v9.0.0","Tag":`), 1),
				"unknown resource":           bytes.Replace(ownership, []byte(`root:root 0600 one-link`), []byte(`unproved resource`), 1),
			} {
				t.Run(name, func(t *testing.T) {
					if err := os.WriteFile(ownershipPath, wrong, 0o600); err != nil {
						t.Fatal(err)
					}
					body, err := exec.Command("bash", restorer).CombinedOutput()
					if err == nil || !bytes.Contains(body, []byte("SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED")) {
						t.Fatalf("invalid authority accepted: %v", err)
					}
					if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
						t.Fatal("refusal restored an executable")
					}
				})
			}
			if err := os.WriteFile(ownershipPath, ownership, 0o600); err != nil {
				t.Fatal(err)
			}
			wrongInstalled := bytes.Replace(installedBefore, []byte(`"tag":"v2.0.0"`), []byte(`"tag":"v2x0x0"`), 1)
			if err := os.WriteFile(installedRecord, wrongInstalled, 0o600); err != nil {
				t.Fatal(err)
			}
			refused, refusedErr := exec.Command("bash", restorer).CombinedOutput()
			if refusedErr == nil || !bytes.Contains(refused, []byte("SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED")) {
				t.Fatal("inexact Installed Record tag accepted")
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
				t.Fatal("inexact tag restored executable before refusal")
			}
			if err := os.WriteFile(installedRecord, installedBefore, 0o600); err != nil {
				t.Fatal(err)
			}
			if variant == 1 {
				t.Run("symlink executable parent", func(t *testing.T) {
					parent := filepath.Join(fixture.root, "usr/local/bin")
					if err := os.Rename(parent, parent+"-outside"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(parent+"-outside", parent); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						_ = os.Remove(filepath.Join(parent, "sbxr"))
						_ = os.Remove(parent)
						_ = os.Rename(parent+"-outside", parent)
					})
					body, err := exec.Command("bash", restorer).CombinedOutput()
					if err == nil || !bytes.Contains(body, []byte("SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED")) {
						t.Fatal("restoration followed a symlink parent")
					}
					if _, err := os.Lstat(filepath.Join(parent, "sbxr")); !os.IsNotExist(err) {
						t.Fatal("unsafe restoration created an executable")
					}
				})
			}

			body, err := exec.Command("bash", restorer).CombinedOutput()
			if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED") {
				t.Fatalf("restore = %v, %q", err, body)
			}
			restored, restoredErr := os.ReadFile(filepath.Join(fixture.root, "usr/local/bin/sbxr"))
			installedAfter, installedErr := os.ReadFile(installedRecord)
			ownershipAfter, ownershipErr := os.ReadFile(ownershipPath)
			if restoredErr != nil || !bytes.Equal(restored, fixture.executable) || installedErr != nil || !bytes.Equal(installedAfter, installedBefore) || ownershipErr != nil || !bytes.Equal(ownershipAfter, ownership) {
				t.Fatalf("restored=%v installed=%v ownership=%v", restoredErr, installedErr, ownershipErr)
			}

			finalOwnershipPath := filepath.Join(fixture.root, "var/lib/.sbxr-removal.json")
			if err := os.Rename(ownershipPath, finalOwnershipPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(installedRecord); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Dir(installedRecord)); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(fixture.root, "usr/local/bin/sbxr")); err != nil {
				t.Fatal(err)
			}
			body, err = exec.Command("bash", restorer).CombinedOutput()
			if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED") {
				t.Fatalf("finalization restore = %v, %q", err, body)
			}
			finalOwnership, finalOwnershipErr := os.ReadFile(finalOwnershipPath)
			if finalOwnershipErr != nil || !bytes.Equal(finalOwnership, ownership) {
				t.Fatalf("finalization ownership=%v", finalOwnershipErr)
			}
		})
	}
}

func TestGeneratedInstallerRefusesWrongELFArchitectureBeforeMutation(t *testing.T) {
	fixture := newInstallerFixture(t)
	wrong := installerExecutable(t, installerPayload(t, "arm64"), "v2.0.0", strings.Repeat("a", 40), 17, "amd64")
	replaceInstallerArchiveProof(t, fixture.root, "amd64", wrong)

	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-RELEASE-REFUSED" {
		t.Fatalf("wrong ELF architecture = %v, %q", err, body)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
		t.Fatalf("wrong ELF architecture changed the executable path: %v", err)
	}
}

func TestGeneratedInstallerRefusesAChangedSelfConsistentExecutable(t *testing.T) {
	fixture := newInstallerFixture(t)
	payload := installerPayload(t, "amd64")
	payload[len(payload)-1] ^= 1
	changed := installerExecutable(t, payload, "v2.0.0", strings.Repeat("a", 40), 17, "amd64")
	replaceInstallerArchiveProof(t, fixture.root, "amd64", changed)

	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-RELEASE-REFUSED" {
		t.Fatalf("changed executable = %v, %q", err, body)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
		t.Fatalf("changed executable reached mutation: %v", err)
	}
}

func TestGeneratedInstallerRefusesExtraIndexMaterialBeforeMutation(t *testing.T) {
	fixture := newInstallerFixture(t)
	index := filepath.Join(fixture.root, "fixtures/release-index.json")
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, append(body, []byte("{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err == nil || strings.TrimSpace(string(result)) != "SOFTWARE-LIFECYCLE-INSTALL-RELEASE-REFUSED" {
		t.Fatalf("extra index material = %v, %q", err, result)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
		t.Fatalf("extra index material changed the executable path: %v", err)
	}
}

func TestGeneratedInstallerLaunchesTheMenuThroughAControllingTerminal(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the packaged linux/amd64 executable runs only on its native host")
	}
	fixture := newInstallerFixture(t)
	command := exec.Command("script", "-qec", fmt.Sprintf("bash %q </dev/null", fixture.script), "/dev/null")
	command.Env = append(os.Environ(), "SBXR_INSTALL_TEST_ROOT="+fixture.root)
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("terminal install = %v, %q", err, body)
	}
	if _, err := os.Stat(filepath.Join(fixture.root, "fixtures/launched")); err != nil {
		t.Fatalf("installed menu was not launched: %v", err)
	}
	locale, err := os.ReadFile(filepath.Join(fixture.root, "fixtures/launched-locale"))
	if err != nil || string(locale) != "C.UTF-8" {
		t.Fatalf("installed menu locale = %q, %v", locale, err)
	}
}

func TestGeneratedInstallerLaunchesTheMenuWithAUTF8Locale(t *testing.T) {
	if !strings.Contains(bootstrapBody, `LC_ALL='C.UTF-8' LANG='C.UTF-8' exec "$ROOT/usr/local/bin/sbxr" </dev/tty >/dev/tty 2>/dev/tty`) {
		t.Fatal("installer does not give the launched menu a UTF-8 locale")
	}
}

func TestGeneratedInstallerIsANoopForExactCurrent(t *testing.T) {
	fixture := newInstallerFixture(t)
	if body, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil {
		t.Fatalf("first install = %v, %q", err, body)
	}
	executable := filepath.Join(fixture.root, "usr/local/bin/sbxr")
	record := filepath.Join(fixture.root, "var/lib/sbxr/installed.json")
	beforeExecutable, _ := os.ReadFile(executable)
	beforeRecord, _ := os.ReadFile(record)
	if err := os.Remove(filepath.Join(fixture.root, "usr/bin/tar")); err != nil {
		t.Fatal(err)
	}
	aptMarker := filepath.Join(fixture.root, "fixtures/apt-called")
	if err := os.WriteFile(filepath.Join(fixture.root, "usr/bin/apt-get"), []byte(fmt.Sprintf("#!/usr/bin/env bash\nprintf called >%q\nexit 1\n", aptMarker)), 0o755); err != nil {
		t.Fatal(err)
	}

	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT") {
		t.Fatalf("second install = %v, %q", err, body)
	}
	afterExecutable, _ := os.ReadFile(executable)
	afterRecord, _ := os.ReadFile(record)
	if string(afterExecutable) != string(beforeExecutable) || string(afterRecord) != string(beforeRecord) {
		t.Fatal("exact-current install changed the installed pair")
	}
	if _, err := os.Stat(aptMarker); !os.IsNotExist(err) {
		t.Fatalf("exact-current install changed APT: %v", err)
	}
}

func TestGeneratedInstallerRepairsOrReplacesReclaimableStates(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(t *testing.T, fixture installerFixture)
	}{
		{"older", func(t *testing.T, fixture installerFixture) {
			setInstalledIdentity(t, fixture.root, "v1.9.9", strings.Repeat("d", 40), 16)
		}},
		{"corrupt", func(t *testing.T, fixture installerFixture) {
			if err := os.WriteFile(filepath.Join(fixture.root, "usr/local/bin/sbxr"), []byte("corrupt"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"contradictory", func(t *testing.T, fixture installerFixture) {
			replaceInstalledRecord(t, fixture.root, `"executable_sha256":"`, `"executable_sha256":"aaaaaaaa`)
		}},
		{"extra record line", func(t *testing.T, fixture installerFixture) {
			name := filepath.Join(fixture.root, "var/lib/sbxr/installed.json")
			body, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(body, []byte("{}\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"interrupted", func(t *testing.T, fixture installerFixture) {
			if err := os.Remove(filepath.Join(fixture.root, "usr/local/bin/sbxr")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "var/lib/sbxr/partial"), []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unrelated", func(t *testing.T, fixture installerFixture) {
			if err := os.RemoveAll(filepath.Join(fixture.root, "usr/local/bin/sbxr")); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(fixture.root, "usr/local/bin/sbxr/data"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			if body, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil {
				t.Fatalf("initial install = %v, %q", err, body)
			}
			test.change(t, fixture)
			body, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") {
				t.Fatalf("replacement = %v, %q", err, body)
			}
			assertInstalledFixture(t, fixture.root, fixture.executable)
		})
	}
}

func TestGeneratedInstallerRefusesAValidHigherSequenceUnchanged(t *testing.T) {
	fixture := newInstallerFixture(t)
	if body, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil {
		t.Fatalf("initial install = %v, %q", err, body)
	}
	setInstalledIdentity(t, fixture.root, "v2.0.1", strings.Repeat("c", 40), 18)
	record := filepath.Join(fixture.root, "var/lib/sbxr/installed.json")
	before, _ := os.ReadFile(record)

	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	after, _ := os.ReadFile(record)
	if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-DOWNGRADE-REFUSED" || string(after) != string(before) {
		t.Fatalf("downgrade = %v, %q", err, body)
	}
}

func TestGeneratedInstallerKeepsReclamationInsidePhysicalUnmountedPaths(t *testing.T) {
	t.Run("does not follow links", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		outside := filepath.Join(fixture.root, "fixtures/outside")
		if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(fixture.root, "usr/local/bin/sbxr")); err != nil {
			t.Fatal(err)
		}

		body, err := exec.Command("bash", fixture.script).CombinedOutput()
		kept, _ := os.ReadFile(outside)
		if err != nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") || string(kept) != "keep" {
			t.Fatalf("linked path = %v, %q, outside %q", err, body, kept)
		}
	})

	for _, test := range []struct {
		name, marker string
	}{
		{"active mount", "mounted"},
		{"failed mount inspection", "mount-failure"},
		{"changed physical entry", "race"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			target := filepath.Join(fixture.root, "usr/local/bin/sbxr")
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
			marker := []byte("1")
			if test.marker == "mounted" {
				marker = []byte(target + "\n")
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "fixtures", test.marker), marker, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.marker == "race" {
				if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/outside"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			body, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || strings.TrimSpace(string(body)) != "SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED" {
				t.Fatalf("unsafe path = %v, %q", err, body)
			}
		})
	}
}

func TestGeneratedInstallerReportsConcurrencyPrerequisiteAndInterruption(t *testing.T) {
	for _, test := range []struct {
		name, marker, want string
		prepare            func(t *testing.T, fixture installerFixture)
	}{
		{"concurrency", "locked", "SOFTWARE-LIFECYCLE-INSTALL-CONCURRENT-MUTATION", nil},
		{"prerequisite", "", "SOFTWARE-LIFECYCLE-INSTALL-PREREQUISITE-FAILED", func(t *testing.T, fixture installerFixture) {
			if err := os.Remove(filepath.Join(fixture.root, "usr/bin/tar")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "usr/bin/apt-get"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"prerequisite remains absent", "", "SOFTWARE-LIFECYCLE-INSTALL-PREREQUISITE-FAILED", func(t *testing.T, fixture installerFixture) {
			if err := os.Remove(filepath.Join(fixture.root, "usr/bin/tar")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "usr/bin/apt-get"), []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"interruption", "interrupt", "SOFTWARE-LIFECYCLE-INSTALL-INTERRUPTED", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			if test.marker != "" {
				if err := os.WriteFile(filepath.Join(fixture.root, "fixtures", test.marker), []byte("1"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.prepare != nil {
				test.prepare(t, fixture)
			}
			body, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || strings.TrimSpace(string(body)) != test.want {
				t.Fatalf("result = %v, %q", err, body)
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
				t.Fatalf("refusal changed executable path: %v", err)
			}
			matches, _ := filepath.Glob(filepath.Join(fixture.root, "tmp/sbxr-install.*"))
			if len(matches) != 0 {
				t.Fatalf("temporary material remains: %v", matches)
			}
		})
	}
}

func TestGeneratedInstallerDefersSignalAfterReclamationUntilInstalled(t *testing.T) {
	fixture := newInstallerFixture(t)
	if err := os.MkdirAll(filepath.Join(fixture.root, "usr/local/bin/sbxr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "fixtures/interrupt-after"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}

	body, err := exec.Command("bash", fixture.script).CombinedOutput()
	if err == nil || !strings.Contains(string(body), "SOFTWARE-LIFECYCLE-INSTALL-INSTALLED") {
		t.Fatalf("deferred signal = %v, %q", err, body)
	}
	assertInstalledFixture(t, fixture.root, fixture.executable)
}

func TestGeneratedInstallerRefusesProvenHistoricalFullProductUnchanged(t *testing.T) {
	fixture := newInstallerFixture(t)
	commit := strings.Repeat("d", 40)
	payload := strings.Repeat("e", 64)
	body := fmt.Sprintf("#!/usr/bin/env bash\nprintf '%%s\\n' '%s'\n", fmt.Sprintf(`{"build":{"repository":"albertloky/SBXR","tag":"v1.0.15","commit":"%s","payload_sha256":"%s"},"architecture":"amd64","state_schema":2}`, commit, payload))
	indexSHA256 := writeHistoricalReleaseFixture(t, fixture.root, commit, []byte(body))
	target := fmt.Sprintf("/opt/sbxr/releases/v1.0.15-%s-%s/sbxr", commit, indexSHA256)
	physical := fixture.root + target
	if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(physical, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(fixture.root, "usr/local/bin/sbxr")
	if err := os.Symlink(target, active); err != nil {
		t.Fatal(err)
	}

	result, err := exec.Command("bash", fixture.script).CombinedOutput()
	link, linkErr := os.Readlink(active)
	if err == nil || strings.TrimSpace(string(result)) != "SOFTWARE-LIFECYCLE-INSTALL-LEGACY-REFUSED" || linkErr != nil || link != target {
		t.Fatalf("legacy = %v, %q, link %q, %v", err, result, link, linkErr)
	}
}

func TestGeneratedInstallerDoesNotTrustAForgedHistoricalSelfReport(t *testing.T) {
	fixture := newInstallerFixture(t)
	commit := strings.Repeat("d", 40)
	body := fmt.Sprintf("#!/usr/bin/env bash\nprintf '%%s\\n' '%s'\n", fmt.Sprintf(`{"build":{"repository":"albertloky/SBXR","tag":"v1.0.15","commit":"%s","payload_sha256":"%s"},"architecture":"amd64","state_schema":2}`, commit, strings.Repeat("e", 64)))
	target := fmt.Sprintf("/opt/sbxr/releases/v1.0.15-%s-%s/sbxr", commit, strings.Repeat("f", 64))
	physical := fixture.root + target
	if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(physical, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(fixture.root, "usr/local/bin/sbxr")); err != nil {
		t.Fatal(err)
	}

	if result, err := exec.Command("bash", fixture.script).CombinedOutput(); err != nil {
		t.Fatalf("install over forged legacy identity = %v, %q", err, result)
	}
	assertInstalledFixture(t, fixture.root, fixture.executable)
}

func writeHistoricalReleaseFixture(t *testing.T, root, commit string, executable []byte) string {
	t.Helper()
	archive := filepath.Join(root, "fixtures/legacy-sbxr-linux-amd64.tar.gz")
	writeInstallerArchive(t, archive, executable)
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	index := fmt.Sprintf(`{"schema":1,"product":"sbxr","repository":"albertloky/SBXR","version":"1.0.15","sequence":16,"tag":"v1.0.15","commit":"%s","state_schema":2,"minimum_updater_schema":1,"assets":[{"role":"application-linux-amd64","name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":"%s"}]}`, commit, len(body), hex.EncodeToString(digest[:]))
	if err := os.WriteFile(filepath.Join(root, "fixtures/legacy-release-index.json"), []byte(index), 0o600); err != nil {
		t.Fatal(err)
	}
	indexDigest := sha256.Sum256([]byte(index))
	return hex.EncodeToString(indexDigest[:])
}

func replaceInstalledRecord(t *testing.T, root, old, new string) {
	t.Helper()
	name := filepath.Join(root, "var/lib/sbxr/installed.json")
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(body), old, new, 1)
	if changed == string(body) {
		t.Fatalf("record does not contain %q", old)
	}
	if err := os.WriteFile(name, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
}

func setInstalledIdentity(t *testing.T, root, tag, commit string, sequence uint64) {
	t.Helper()
	executable := installerExecutable(t, installerPayload(t, "amd64"), tag, commit, sequence, "amd64")
	digest := sha256.Sum256(executable)
	if err := os.WriteFile(filepath.Join(root, "usr/local/bin/sbxr"), executable, 0o755); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "var/lib/sbxr/installed.json")
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Schema             int    `json:"schema"`
		Repository         string `json:"repository"`
		Tag                string `json:"tag"`
		Commit             string `json:"commit"`
		ReleaseIndexSHA256 string `json:"release_index_sha256"`
		Sequence           uint64 `json:"sequence"`
		Architecture       string `json:"architecture"`
		ExecutableSHA256   string `json:"executable_sha256"`
	}
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	record.Tag, record.Commit, record.Sequence, record.ExecutableSHA256 = tag, commit, sequence, hex.EncodeToString(digest[:])
	body, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

type installerFixture struct {
	root, script string
	executable   []byte
}

func newInstallerFixture(t *testing.T) installerFixture {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"bin", "etc", "run/lock", "tmp", "usr/bin", "usr/local/bin", "var/lib", "fixtures"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=24.04\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := installerPayload(t, "amd64")
	executable := installerExecutable(t, payload, "v2.0.0", strings.Repeat("a", 40), 17, "amd64")
	archive := filepath.Join(root, "fixtures/sbxr-linux-amd64.tar.gz")
	writeInstallerArchive(t, archive, executable)
	archiveBody, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveDigest := sha256.Sum256(archiveBody)
	armArchive := filepath.Join(root, "fixtures/sbxr-linux-arm64.tar.gz")
	armExecutable := installerExecutable(t, installerPayload(t, "arm64"), "v2.0.0", strings.Repeat("a", 40), 17, "arm64")
	writeInstallerArchive(t, armArchive, armExecutable)
	armArchiveBody, err := os.ReadFile(armArchive)
	if err != nil {
		t.Fatal(err)
	}
	armArchiveDigest := sha256.Sum256(armArchiveBody)
	indexBody := []byte(fmt.Sprintf(`{"schema":1,"repository":"albertloky/SBXR","tag":"v2.0.0","commit":"%s","sequence":17,"assets":[{"name":"install.sh","size":1,"sha256":"%s"},{"name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":"%s"}]}`, strings.Repeat("a", 40), strings.Repeat("b", 64), len(archiveBody), hex.EncodeToString(archiveDigest[:]), len(armArchiveBody), hex.EncodeToString(armArchiveDigest[:])))
	if err := os.WriteFile(filepath.Join(root, "fixtures/release-index.json"), append(indexBody, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	writeInstallerTools(t, root)
	script := filepath.Join(root, "install.sh")
	executableDigest := sha256.Sum256(executable)
	armExecutableDigest := sha256.Sum256(armExecutable)
	if err := buildBootstrapFile(bootstrapOptions{
		version: "2.0.0", sequence: 17, tag: "v2.0.0", commit: strings.Repeat("a", 40),
		output: script, root: root,
		amd64ExecutableSHA256: hex.EncodeToString(executableDigest[:]), arm64ExecutableSHA256: hex.EncodeToString(armExecutableDigest[:]),
	}); err != nil {
		t.Fatal(err)
	}
	return installerFixture{root: root, script: script, executable: executable}
}

var installerPayloadCache = struct {
	sync.Mutex
	values map[string][]byte
}{values: map[string][]byte{}}

func installerPayload(t *testing.T, architecture string) []byte {
	t.Helper()
	installerPayloadCache.Lock()
	defer installerPayloadCache.Unlock()
	if body := installerPayloadCache.values[architecture]; body != nil {
		return append([]byte(nil), body...)
	}
	directory, err := os.MkdirTemp("", "sbxr-installer-payload-")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "main.go")
	if err := os.WriteFile(source, []byte(`package main
import "os"
func main() {
	if root := os.Getenv("SBXR_INSTALL_TEST_ROOT"); root != "" {
		_ = os.WriteFile(root+"/fixtures/launched", []byte("launched"), 0600)
		_ = os.WriteFile(root+"/fixtures/launched-locale", []byte(os.Getenv("LC_ALL")), 0600)
	}
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "sbxr")
	command := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", output, source)
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture)
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s fixture: %v, %s", architecture, err, body)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	installerPayloadCache.values[architecture] = body
	return append([]byte(nil), body...)
}

func installerExecutable(t *testing.T, payload []byte, tag, commit string, sequence uint64, architecture string) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	identity := struct {
		Schema        int    `json:"schema"`
		Repository    string `json:"repository"`
		Tag           string `json:"tag"`
		Commit        string `json:"commit"`
		Sequence      uint64 `json:"sequence"`
		Architecture  string `json:"architecture"`
		PayloadSHA256 string `json:"payload_sha256"`
	}{1, "albertloky/SBXR", tag, commit, sequence, architecture, hex.EncodeToString(digest[:])}
	document, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	documentDigest := sha256.Sum256(document)
	result := append([]byte(nil), payload...)
	result = append(result, document...)
	result = append(result, documentDigest[:]...)
	result = binary.LittleEndian.AppendUint64(result, uint64(len(document)))
	return append(result, []byte("SBXR-IDENTITY-V1")...)
}

func writeInstallerArchive(t *testing.T, name string, executable []byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(executable))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(executable); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func replaceInstallerArchiveProof(t *testing.T, root, architecture string, executable []byte) {
	t.Helper()
	archive := filepath.Join(root, "fixtures/sbxr-linux-"+architecture+".tar.gz")
	oldBody, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest := sha256.Sum256(oldBody)
	writeInstallerArchive(t, archive, executable)
	newBody, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	newDigest := sha256.Sum256(newBody)
	index := filepath.Join(root, "fixtures/release-index.json")
	indexBody, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	name := "sbxr-linux-" + architecture + ".tar.gz"
	oldProof := fmt.Sprintf(`"name":"%s","size":%d,"sha256":"%s"`, name, len(oldBody), hex.EncodeToString(oldDigest[:]))
	newProof := fmt.Sprintf(`"name":"%s","size":%d,"sha256":"%s"`, name, len(newBody), hex.EncodeToString(newDigest[:]))
	if err := os.WriteFile(index, []byte(strings.Replace(string(indexBody), oldProof, newProof, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeInstallerTools(t *testing.T, root string) {
	t.Helper()
	checksumCommand := "/usr/bin/shasum -a 256"
	statCommand := "/usr/bin/stat -f '%d:%i:%Lp:%l:%HT'"
	if runtime.GOOS == "linux" {
		checksumCommand = "/usr/bin/sha256sum"
		statCommand = "/usr/bin/stat -c '%d:%i:%a:%h:%F'"
	}
	write := func(name, body string) {
		path := filepath.Join(root, "usr/bin", name)
		if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("id", `printf '0\n'`)
	write("uname", fmt.Sprintf(`case "${1-}" in -s) printf 'Linux\n' ;; -m) if [ -f %q/fixtures/unsupported ]; then printf 'riscv64\n'; elif [ -f %q/fixtures/arm64 ]; then printf 'aarch64\n'; else printf 'x86_64\n'; fi ;; *) exit 1 ;; esac`, root, root))
	write("curl", fmt.Sprintf(`out=''; legacy=''; while [ "$#" -gt 0 ]; do case "$1" in --output) out=$2; shift 2 ;; http*) url=$1; asset=${1##*/}; case "$url" in */v1.0.15/*) legacy='legacy-' ;; esac; shift ;; *) shift ;; esac; done; if [ -f %q/fixtures/interrupt ]; then parent=$(/bin/ps -o ppid= -p "$PPID"); /bin/kill -TERM "$parent"; exit 1; fi; /bin/cp %q/fixtures/"$legacy$asset" "$out" || exit 1; printf 'https://release-assets.githubusercontent.com/exact\n200'`, root, root))
	write("sha256sum", fmt.Sprintf(`if [ "$#" -eq 0 ]; then %s; else %s "$1"; fi`, checksumCommand, checksumCommand))
	write("flock", fmt.Sprintf(`[ ! -f %q/fixtures/locked ]`, root))
	write("findmnt", fmt.Sprintf(`[ ! -f %q/fixtures/mount-failure ] || exit 1; [ ! -f %q/fixtures/mounted ] || /bin/cat %q/fixtures/mounted`, root, root, root))
	write("rm", fmt.Sprintf(`args=(); signal=0; for value in "$@"; do [ "$value" = '--one-file-system' ] || args+=("$value"); [[ "$value" = */usr/local/bin/sbxr ]] && signal=1; done; if [ "$signal" -eq 1 ] && [ -f %q/fixtures/interrupt-after ]; then /bin/kill -TERM "$PPID"; fi; exec /bin/rm "${args[@]}"`, root))
	write("sync", `exit 0`)
	write("stat", fmt.Sprintf(`format=$2; path=$3; case "$path" in /proc/*/fd/9) path=%q/run/lock/sbxr.lock ;; esac; if [ "$format" = '%%d:%%i:%%F' ] && [ -f %q/fixtures/race ] && [[ "$path" = */usr/local/bin/sbxr ]]; then if [ -f %q/fixtures/race-seen ]; then /bin/rm -rf "$path"; /bin/ln -s %q/fixtures/outside "$path"; else : >%q/fixtures/race-seen; fi; fi; facts=$(%s "$path") || exit 1; device=${facts%%%%:*}; rest=${facts#*:}; inode=${rest%%%%:*}; rest=${rest#*:}; mode=${rest%%%%:*}; rest=${rest#*:}; links=${rest%%%%:*}; kind=${rest#*:}; case "$kind" in 'Regular File') kind='regular file' ;; Directory) kind='directory' ;; 'Symbolic Link') kind='symbolic link' ;; esac; if [[ "$path" = */run/lock/sbxr.lock ]] && [ "$kind" = 'regular file' ]; then kind='regular empty file'; fi; case "$format" in '%%u:%%a:%%h:%%F') printf '0:%%s:%%s:%%s\n' "$mode" "$links" "$kind" ;; '%%u:%%a:%%F') printf '0:%%s:%%s\n' "$mode" "$kind" ;; '%%d:%%i:%%F') printf '%%s:%%s:%%s\n' "$device" "$inode" "$kind" ;; '%%d:%%i') printf '%%s:%%s\n' "$device" "$inode" ;; *) exit 1 ;; esac`, root, root, root, root, root, statCommand))
	for _, name := range []string{"chmod", "cmp", "cut", "dd", "find", "grep", "head", "mkdir", "mktemp", "mv", "od", "readlink", "sed", "tail", "tar", "tr", "wc"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(root, "usr/bin", name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"chmod", "mkdir", "mv", "rm"} {
		if err := os.Symlink(filepath.Join("..", "usr", "bin", name), filepath.Join(root, "bin", name)); err != nil {
			t.Fatal(err)
		}
	}
}

func assertInstalledFixture(t *testing.T, root string, wantExecutable []byte) {
	t.Helper()
	executable := filepath.Join(root, "usr/local/bin/sbxr")
	got, err := os.ReadFile(executable)
	if err != nil || string(got) != string(wantExecutable) {
		t.Fatalf("installed executable = %q, %v", got, err)
	}
	if info, err := os.Stat(executable); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("executable mode = %v, %v", info, err)
	}
	directory := filepath.Join(root, "var/lib/sbxr")
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "installed.json" {
		t.Fatalf("installed directory = %v, %v", entries, err)
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("installed directory mode = %v, %v", info, err)
	}
	record, err := os.Open(filepath.Join(directory, "installed.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer record.Close()
	var document map[string]any
	if err := json.NewDecoder(io.LimitReader(record, 4097)).Decode(&document); err != nil || document["tag"] != "v2.0.0" || document["sequence"] != float64(17) || document["architecture"] != "amd64" {
		t.Fatalf("installed record = %#v, %v", document, err)
	}
	if info, err := record.Stat(); err != nil || info.Mode().Perm() != 0o600 || info.Size() > 4096 {
		t.Fatalf("installed record mode = %v, %v", info, err)
	}
}
