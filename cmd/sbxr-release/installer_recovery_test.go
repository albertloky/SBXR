package main

import (
	"bytes"
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

func installerRemovalFixture(t *testing.T) installerFixture {
	t.Helper()
	fixture := newInstallerFixture(t)
	index, err := os.ReadFile(filepath.Join(fixture.root, "fixtures/release-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(index)
	identity, err := json.Marshal(softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"schema":1,"phase":"Removal committed","unfinished_direction":"removal required","release_identity":%s,"proxy_package_identity":"","public_ipv4":"","destination_address":"","destination_server_name":"","configuration_sha256":"","permitted_resources":["/var/lib/sbxr/proxy-ownership.json root:root 0600 one-link schema-1","/var/lib/.sbxr-removal.json root:root 0600 one-link finalization authority","/usr/local/bin/sbxr exact committed Release Identity","/var/lib/sbxr/installed.json exact committed Release Identity"],"cleanup_checkpoint":0,"removal_checkpoint":3}`+"\n", identity)
	if err := os.WriteFile(filepath.Join(fixture.root, "var/lib/.sbxr-removal.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestInstallerRemovalRestorationSurvivesPublicationDeath(t *testing.T) {
	for _, test := range []struct {
		name, boundary string
		beforeRename   bool
	}{
		{name: "installed.json", boundary: "installed.json"},
		{name: "sbxr", boundary: "sbxr"},
		{name: "prepared executable stage", boundary: "sbxr", beforeRename: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := installerRemovalFixture(t)
			mv, err := exec.LookPath("mv")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixture.root, "usr/bin/mv")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(fixture.root, "fixtures/publication-death")
			body := fmt.Sprintf("#!/bin/bash\nif [[ \"${@: -1}\" = */%s ]] && [ ! -e %q ]; then\n  if [ %t = false ]; then %q \"$@\" || exit 1; fi\n  : >%q; /bin/kill -KILL \"$PPID\"; exit 1\nfi\nexec %q \"$@\"\n", test.boundary, marker, test.beforeRename, mv, marker, mv)
			if err := os.WriteFile(path, []byte(body), 0755); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil {
				t.Fatalf("publication death did not interrupt: %s", output)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("publication boundary was not reached: %s %v", output, err)
			}
			if test.beforeRename {
				final := filepath.Join(fixture.root, "usr/local/bin/sbxr")
				if _, err := os.Lstat(final); !os.IsNotExist(err) {
					t.Fatal("pre-rename interruption published the executable")
				}
				digest := sha256.Sum256(fixture.executable)
				stage := final + ".sbxr-restore-" + hex.EncodeToString(digest[:])
				info, err := os.Stat(stage)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatalf("completed stage mode = %v, %v", info, err)
				}
				staged, err := os.ReadFile(stage)
				if err != nil || !bytes.Equal(staged, fixture.executable) {
					t.Fatal("pre-rename interruption did not retain the complete staged executable")
				}
			}
			output, err = exec.Command("bash", fixture.script).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED") {
				t.Fatalf("fresh restoration after %s: %s %v", test.name, output, err)
			}
			assertInstalledFixture(t, fixture.root, fixture.executable)
		})
	}
}

func TestInstallerRemovalRestorationSurvivesCopyDeath(t *testing.T) {
	for _, boundary := range []string{"installed.json", "sbxr"} {
		t.Run(boundary, func(t *testing.T) {
			fixture := installerRemovalFixture(t)
			marker := filepath.Join(fixture.root, "fixtures/copy-death")
			for _, tool := range []string{"mv", "dd"} {
				original, err := exec.LookPath(tool)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(fixture.root, "usr/bin", tool)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				// Emulate mv's EXDEV copy at the old boundary, and interrupt the
				// destination-side staging copy at the repaired boundary. Both
				// write real partial bytes before killing the installer process.
				body := fmt.Sprintf(`#!/bin/bash
source=''; destination=''
if [ %q = mv ]; then
  source="${@: -2:1}"; destination="${@: -1}"
else
  for value in "$@"; do case "$value" in if=*) source=${value#if=} ;; of=*) destination=${value#of=} ;; esac; done
fi
if [[ "$source" = %q/tmp/* ]] && { [[ "$destination" = */%s ]] || [[ "$destination" = */%s.sbxr-restore-* ]]; } && [ ! -e %q ]; then
  /usr/bin/head -c 64 "$source" >"$destination" || exit 1
  : >%q
  /bin/kill -KILL "$PPID"
  exit 1
fi
exec %q "$@"
`, tool, fixture.root, boundary, boundary, marker, marker, original)
				if err := os.WriteFile(path, []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil {
				t.Fatalf("copy death did not interrupt: %s", output)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("copy boundary not reached: %s %v", output, err)
			}
			final := filepath.Join(fixture.root, "usr/local/bin/sbxr")
			if boundary == "installed.json" {
				final = filepath.Join(fixture.root, "var/lib/sbxr/installed.json")
			}
			if _, err := os.Lstat(final); !os.IsNotExist(err) {
				t.Fatal("copy interruption exposed a partial final file")
			}
			stages, err := filepath.Glob(final + ".sbxr-restore-*")
			if err != nil || len(stages) != 1 {
				t.Fatalf("missing destination-side staging: %v %v", stages, err)
			}
			partial, err := os.ReadFile(stages[0])
			if err != nil || len(partial) != 64 {
				t.Fatalf("copy fixture did not leave partial staged bytes: %d %v", len(partial), err)
			}
			output, err = exec.Command("bash", fixture.script).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED") {
				t.Fatalf("fresh restoration after copying %s: %s %v", boundary, output, err)
			}
			assertInstalledFixture(t, fixture.root, fixture.executable)
		})
	}
}

func TestInstallerRemovalRestorationRefusesForeignStaging(t *testing.T) {
	for _, variant := range []string{"bytes", "mode", "symlink", "hard link", "foreign identity"} {
		t.Run(variant, func(t *testing.T) {
			fixture := installerRemovalFixture(t)
			digest := sha256.Sum256(fixture.executable)
			stage := filepath.Join(fixture.root, "usr/local/bin/sbxr.sbxr-restore-"+hex.EncodeToString(digest[:]))
			body, mode := fixture.executable[:64], os.FileMode(0600)
			if variant == "foreign identity" {
				if err := os.Mkdir(filepath.Join(fixture.root, "var/lib/sbxr"), 0700); err != nil {
					t.Fatal(err)
				}
				stage = filepath.Join(fixture.root, "var/lib/sbxr/installed.json.sbxr-restore-"+strings.Repeat("f", 64))
			}
			if variant == "bytes" {
				body = []byte("unknown owner bytes")
			}
			if variant == "mode" {
				mode = 0644
			}
			if variant == "symlink" {
				if err := os.Symlink(filepath.Join(fixture.root, "fixtures/release-index.json"), stage); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(stage, body, mode); err != nil {
				t.Fatal(err)
			}
			if variant == "hard link" {
				if err := os.Link(stage, filepath.Join(fixture.root, "fixtures/staging-copy")); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(stage)
			if err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED") {
				t.Fatalf("foreign staging accepted: %v %s", err, output)
			}
			after, err := os.ReadFile(stage)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed foreign staging")
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
				t.Fatal("foreign staging allowed executable publication")
			}
		})
	}
}

func TestInstallerSynchronizesFinalFilesAfterPublicationAndModes(t *testing.T) {
	for _, restoring := range []bool{false, true} {
		t.Run(fmt.Sprint("restoring=", restoring), func(t *testing.T) {
			fixture := newInstallerFixture(t)
			if restoring {
				fixture = installerRemovalFixture(t)
			}
			log := filepath.Join(fixture.root, "fixtures/final-sync.log")
			script := fmt.Sprintf("#!/bin/bash\nfor path in \"$@\"; do\ncase \"$path\" in %q/usr/local/bin/sbxr) [ -x \"$path\" ] && printf 'executable\\n' >>%q ;; %q/var/lib/sbxr/installed.json) printf 'record\\n' >>%q ;; esac\ndone\nexit 0\n", fixture.root, log, fixture.root, log)
			if err := os.WriteFile(filepath.Join(fixture.root, "usr/bin/sync"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err != nil {
				t.Fatalf("install: %s %v", output, err)
			}
			body, err := os.ReadFile(log)
			if err != nil || !strings.Contains(string(body), "record\n") || !strings.Contains(string(body), "executable\n") {
				t.Fatalf("final files were not synchronized: %s %v", body, err)
			}
		})
	}
}

func TestInstallerFinalFileSyncFailureResumesFresh(t *testing.T) {
	for _, restoring := range []bool{false, true} {
		t.Run(fmt.Sprint("restoring=", restoring), func(t *testing.T) {
			fixture := newInstallerFixture(t)
			if restoring {
				fixture = installerRemovalFixture(t)
			}
			marker := filepath.Join(fixture.root, "fixtures/failed-final-sync")
			script := fmt.Sprintf("#!/bin/bash\nfor path in \"$@\"; do\nif [ \"$path\" = %q/usr/local/bin/sbxr ] && [ -x \"$path\" ] && [ ! -e %q ]; then : >%q; exit 1; fi\ndone\nexit 0\n", fixture.root, marker, marker)
			if err := os.WriteFile(filepath.Join(fixture.root, "usr/bin/sync"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-FAILED") {
				t.Fatalf("sync failure accepted: %s %v", output, err)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("final synchronization was not reached: %v", err)
			}
			// Retry must run a new durability barrier, including Already Current.
			if err := os.Remove(marker); err != nil {
				t.Fatal(err)
			}
			output, err = exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-FAILED") {
				t.Fatalf("fresh run bypassed failed durability barrier: %s %v", output, err)
			}
			if err := os.WriteFile(filepath.Join(fixture.root, "usr/bin/sync"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
				t.Fatal(err)
			}
			output, err = exec.Command("bash", fixture.script).CombinedOutput()
			if err != nil {
				t.Fatalf("fresh durable completion: %s %v", output, err)
			}
			assertInstalledFixture(t, fixture.root, fixture.executable)
		})
	}
}

func TestInstallerRestoresProductEmittedRemovalJournals(t *testing.T) {
	paths, err := filepath.Glob("../../internal/proxyinstallation/testdata/removal-recovery/*.json")
	if err != nil || len(paths) < 8 {
		t.Fatalf("missing product-emitted journals: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			fixture, body, journal := installerProductRemovalFixture(t, path)
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED") {
				t.Fatalf("restore emitted journal: %s %v", output, err)
			}
			active, readErr := os.ReadFile(filepath.Join(fixture.root, "usr/local/bin/sbxr"))
			if readErr != nil || !bytes.Equal(active, fixture.executable) {
				t.Fatal("wrong restored executable")
			}

			installedBody, err := os.ReadFile(filepath.Join(fixture.root, "var/lib/sbxr/installed.json"))
			if err != nil {
				t.Fatal(err)
			}
			var installed map[string]any
			index, err := os.ReadFile(filepath.Join(fixture.root, "fixtures/release-index.json"))
			if err != nil {
				t.Fatal(err)
			}
			indexDigest, executableDigest := sha256.Sum256(index), sha256.Sum256(fixture.executable)
			expected := map[string]any{"schema": float64(1), "repository": softwarelifecycle.Repository, "tag": "v2.0.0", "commit": strings.Repeat("a", 40), "sequence": float64(17), "architecture": "amd64", "release_index_sha256": hex.EncodeToString(indexDigest[:]), "executable_sha256": hex.EncodeToString(executableDigest[:])}
			if json.Unmarshal(installedBody, &installed) != nil || !reflect.DeepEqual(installed, expected) {
				t.Fatalf("wrong exact Installed Record: %s", installedBody)
			}
			after, _ := os.ReadFile(journal)
			if !bytes.Equal(after, body) {
				t.Fatal("restoration changed product recovery direction")
			}
		})
	}
}

func installerProductRemovalFixture(t *testing.T, path string) (installerFixture, []byte, string) {
	t.Helper()
	fixture := installerRemovalFixture(t)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(fixture.root, "fixtures/release-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	indexDigest := sha256.Sum256(index)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	finisher, _ := json.Marshal(softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v2.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: hex.EncodeToString(indexDigest[:])})
	body = bytes.Replace(body, append([]byte(`"finishing_release_identity":`), fields["finishing_release_identity"]...), append([]byte(`"finishing_release_identity":`), finisher...), 1)
	if err := os.Remove(filepath.Join(fixture.root, "var/lib/.sbxr-removal.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(fixture.root, "var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(fixture.root, "var/lib/sbxr/proxy-ownership.json")
	if err := os.WriteFile(journal, body, 0600); err != nil {
		t.Fatal(err)
	}
	return fixture, body, journal
}

func TestInstallerRefusesAlteredSupportedRemovalJournals(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"unknown journal member": func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"client_identity_rotation":{"operation_id":`), []byte(`"client_identity_rotation":{"unexpected":true,"operation_id":`), 1)
		},
		"invalid checkpoint": func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"checkpoint":"target published"`), []byte(`"checkpoint":"prepared"`), 1)
		},
		"foreign permitted resource": func(body []byte) []byte {
			return bytes.Replace(body, []byte(`/var/lib/sbxr/client-identity-target.json root:root 0600`), []byte(`/var/lib/sbxr/owner.json root:root 0600`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, body, journal := installerProductRemovalFixture(t, "../../internal/proxyinstallation/testdata/removal-recovery/client-subscription.json")
			changed := mutate(body)
			if bytes.Equal(changed, body) {
				t.Fatal("refusal mutation missed actual journal")
			}
			if err := os.WriteFile(journal, changed, 0600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("bash", fixture.script).CombinedOutput()
			if err == nil || !strings.Contains(string(output), "SOFTWARE-LIFECYCLE-INSTALL-PATH-REFUSED") {
				t.Fatalf("altered journal admitted: %v %s", err, output)
			}
			after, err := os.ReadFile(journal)
			if err != nil || !bytes.Equal(after, changed) {
				t.Fatal("refused authority was changed")
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "usr/local/bin/sbxr")); !os.IsNotExist(err) {
				t.Fatal("refused journal restored executable")
			}
		})
	}
}
