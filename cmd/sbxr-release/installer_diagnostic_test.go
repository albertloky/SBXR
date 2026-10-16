package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGeneratedInstallerDiagnosticsKeepResultsAndRejectSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, result, diagnostic string
		change                   func(*testing.T, installerFixture)
	}{
		{"host version", "HOST-REFUSED", "install/host/ubuntu-version expected=24.04 observed=mismatch", func(t *testing.T, f installerFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_ID=sensitive-version-marker\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"download", "RELEASE-UNAVAILABLE", "install/download/curl asset=release-index.json exit=28 http=unknown", func(t *testing.T, f installerFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "usr/bin/curl"), []byte("#!/usr/bin/env bash\nprintf 'https://secret.invalid/token/sensitive-url-marker\\nsensitive-http-marker'\nprintf 'sensitive-curl-marker' >&2\nexit 28\n"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"HTTP unavailable", "RELEASE-UNAVAILABLE", "install/download/curl asset=release-index.json exit=22 http=503", func(t *testing.T, f installerFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "usr/bin/curl"), []byte("#!/usr/bin/env bash\nprintf 'https://secret.invalid/token/sensitive-url-marker\\n503'\nexit 22\n"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"HTTP control characters", "RELEASE-REFUSED", "install/download/curl asset=release-index.json exit=22 http=unknown", func(t *testing.T, f installerFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "usr/bin/curl"), []byte("#!/usr/bin/env bash\nprintf 'https://secret.invalid/token/sensitive-url-marker\\n403\\rsensitive-http-marker\\nsensitive-extra-line'\nexit 22\n"), 0755); err != nil {
				t.Fatal(err)
			}
		}},
		{"index contract", "RELEASE-REFUSED", "install/index/canonical-contract", func(t *testing.T, f installerFixture) {
			if err := os.WriteFile(filepath.Join(f.root, "fixtures/release-index.json"), []byte("sensitive-index-marker\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"archive digest", "RELEASE-REFUSED", "install/archive/sha256 expected=index observed=mismatch", func(t *testing.T, f installerFixture) {
			path := filepath.Join(f.root, "fixtures/sbxr-linux-amd64.tar.gz")
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body[0] ^= 1
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInstallerFixture(t)
			tc.change(t, f)
			before := installerAuthoritySnapshot(t, f.root)
			command := exec.Command("bash", f.script)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			if err == nil || stdout.String() != "SOFTWARE-LIFECYCLE-INSTALL-"+tc.result+"\n" || stderr.String() != tc.diagnostic+"\n" {
				t.Fatalf("error=%v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), "sensitive-") || !reflect.DeepEqual(before, installerAuthoritySnapshot(t, f.root)) {
				t.Fatal("refusal exposed values or changed installation authority")
			}
			assertInstallerWorkCleaned(t, f)
		})
	}
}
