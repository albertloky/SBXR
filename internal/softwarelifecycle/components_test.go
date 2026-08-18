package softwarelifecycle

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestComponentCertbotLauncherUsesOnlyTheBundledWheelDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "certbot")
	bin := filepath.Join(root, "bin")
	bundled := filepath.Join(root, "lib/python3.12/site-packages/certbot")
	hostile := filepath.Join(t.TempDir(), "certbot")
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bundled, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(hostile, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(bin, "certbot")
	if err := os.WriteFile(launcher, ComponentCertbotLauncher(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(python, filepath.Join(bin, "python3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundled, "main.py"), []byte("import sys\ndef main():\n print('bundled', *sys.argv[1:])\n return 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostile, "main.py"), []byte("def main():\n print('hostile')\n return 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(hostile), "dirname"), []byte("#!/bin/sh\necho hostile-dirname\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(launcher, "--version")
	command.Dir = filepath.Dir(hostile)
	command.Env = append(os.Environ(), "PATH="+filepath.Dir(hostile), "PYTHONHOME="+filepath.Dir(hostile), "PYTHONPATH="+filepath.Dir(hostile))
	output, err := command.CombinedOutput()
	if err != nil || string(output) != "bundled --version\n" {
		t.Fatalf("launcher output = %q, %v", output, err)
	}
}

func TestComponentArchiveIsExactOfflineAndArchitectureBound(t *testing.T) {
	files := componentFixtureFiles()
	build := EmbeddedBuildIdentity{Repository: Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), PayloadSHA256: strings.Repeat("b", 64)}
	manifest, err := NewBoundComponentManifest(AMD64, build, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := BuildComponentArchive(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateComponentArchive(archive, AMD64)
	if err != nil || got.Architecture != AMD64 || got.Build != build || got.Xray != "v26.3.27" || got.SingBox != "v1.13.16" || got.Cloudflared != "2026.7.3" || got.Certbot != "5.4.0" || len(got.Files) != 7 {
		t.Fatalf("ValidateComponentArchive() = (%+v, %v)", got, err)
	}
	if _, err := ValidateComponentArchive(archive, ARM64); err == nil {
		t.Fatal("wrong architecture accepted")
	}
	surface, err := QualificationComponentSurface(archive, AMD64)
	if err != nil || !bytes.Contains(surface, []byte("cloudflared\nqualified cloudflared")) {
		t.Fatalf("QualificationComponentSurface() = (%q, %v)", surface, err)
	}
	changed := append([]byte(nil), archive...)
	changed[len(changed)/2] ^= 1
	if _, err := ValidateComponentArchive(changed, AMD64); err == nil {
		t.Fatal("changed component archive accepted")
	}
}

func TestComponentArchiveRefusesMalformedBaselineAndSource(t *testing.T) {
	files := componentFixtureFiles()
	manifest, err := NewComponentManifest(AMD64, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ComponentManifest){
		func(value *ComponentManifest) { value.Xray = "v26.3.28" },
		func(value *ComponentManifest) { value.Certbot = "5.3.9" },
		func(value *ComponentManifest) { value.Files[0].Path = "../xray" },
		func(value *ComponentManifest) { value.Files[0].SHA256 = string(bytes.Repeat([]byte{'a'}, 64)) },
	} {
		candidate := manifest
		candidate.Files = append([]ComponentFile(nil), manifest.Files...)
		change(&candidate)
		if _, err := BuildComponentArchive(candidate, files); err == nil {
			t.Fatalf("unsafe component manifest accepted: %+v", candidate)
		}
	}
}

func TestComponentArchivePreservesZeroByteWheelMarkers(t *testing.T) {
	files := componentFixtureFiles()
	files["certbot/lib/python3.12/site-packages/certbot/py.typed"] = []byte{}
	manifest, err := NewComponentManifest(AMD64, "5.4.0", files)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := BuildComponentArchive(manifest, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateComponentArchive(archive, AMD64); err != nil {
		t.Fatal(err)
	}
}

func componentFixtureFiles() map[string][]byte {
	return map[string][]byte{
		"xray":                []byte("qualified xray"),
		"sing-box":            []byte("qualified sing-box"),
		"cloudflared":         []byte("qualified cloudflared"),
		"certbot/bin/certbot": ComponentCertbotLauncher(),
		"certbot/pyvenv.cfg":  []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
}
