package ubuntu

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestRepositoryComponentSourceLockIsExact(t *testing.T) {
	lock, err := repositoryComponentSources()
	if err != nil {
		t.Fatal(err)
	}
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		sources, ok := lock.forArchitecture(architecture)
		if !ok || len(sources.Artifacts) != 22 {
			t.Fatalf("%s source count = %d, %v", architecture, len(sources.Artifacts), ok)
		}
		if sources.Artifacts[0].Role != "xray" || sources.Artifacts[1].Role != "sing-box" || sources.Artifacts[2].Role != "cloudflared" || sources.Artifacts[3].Role != "mihomo" {
			t.Fatalf("%s component roles = %+v", architecture, sources.Artifacts[:4])
		}
	}

	changed := bytes.Replace(componentSourceDocument, []byte(`"schema": 1`), []byte(`"schema": 1, "unknown": true`), 1)
	if _, err := parseComponentSources(changed); err == nil {
		t.Fatal("unknown component-source field accepted")
	}
	changed = bytes.Replace(componentSourceDocument, []byte("23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 1)
	if _, err := parseComponentSources(changed); err == nil {
		t.Fatal("changed reviewed component digest accepted")
	}
}

func TestAssembleReleaseComponentsUsesOnlyVerifiedSourceBytes(t *testing.T) {
	xray := zipFixture(t, "xray", []byte("xray"))
	singBox := tarFixture(t, "sing-box-1.13.16-linux-amd64/sing-box", []byte("sing-box"))
	cloudflared := []byte("cloudflared")
	mihomo := gzipFixture(t, []byte("mihomo"))
	wheel := zipFixture(t, "certbot/__init__.py", []byte("__version__ = '5.4.0'\n"))
	sources := architectureSources{Architecture: softwarelifecycle.AMD64, Artifacts: []componentSource{
		testComponentSource("xray", "Xray-linux-64.zip", xray),
		testComponentSource("sing-box", "sing-box-1.13.16-linux-amd64.tar.gz", singBox),
		testComponentSource("cloudflared", "cloudflared-linux-amd64", cloudflared),
		testComponentSource("mihomo", "mihomo-linux-amd64-v1.19.29.gz", mihomo),
		testComponentSource("certbot-wheel", "certbot-5.4.0-py3-none-any.whl", wheel),
	}}
	bodies := map[string][]byte{}
	for _, source := range sources.Artifacts {
		bodies[source.URL] = map[string][]byte{"xray": xray, "sing-box": singBox, "cloudflared": cloudflared, "mihomo": mihomo, "certbot-wheel": wheel}[source.Role]
	}
	qualified := false
	archive, err := assembleReleaseComponents(t.Context(), sources, func(_ context.Context, source componentSource) ([]byte, error) {
		return append([]byte(nil), bodies[source.URL]...), nil
	}, func(_ context.Context, root string, _ softwarelifecycle.PayloadMetadata) error {
		qualified = true
		for _, name := range []string{"xray", "sing-box", "cloudflared", "mihomo", "certbot/bin/certbot", "certbot/lib/python3.12/site-packages/certbot/__init__.py"} {
			if _, err := readComponentFile(root, name); err != nil {
				return err
			}
		}
		return nil
	}, softwarelifecycle.PayloadMetadata{Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40), PayloadSHA256: strings.Repeat("b", 64)}})
	if err != nil || !qualified {
		t.Fatalf("assembleReleaseComponents() = %v, qualified=%v", err, qualified)
	}
	manifest, err := softwarelifecycle.ValidateComponentArchive(archive, softwarelifecycle.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		if file.Path == "mihomo" {
			t.Fatal("qualification-only Mihomo entered the runtime component archive")
		}
	}

	sources.Artifacts[0].SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	if _, err := assembleReleaseComponents(t.Context(), sources, func(_ context.Context, source componentSource) ([]byte, error) {
		return bodies[source.URL], nil
	}, nil, softwarelifecycle.PayloadMetadata{}); err == nil {
		t.Fatal("changed source bytes accepted")
	}
}

func testComponentSource(role, filename string, body []byte) componentSource {
	digest := sha256.Sum256(body)
	return componentSource{Role: role, Source: "test/source", Version: "1", Filename: filename, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), URL: "https://example.invalid/" + filename}
}

func zipFixture(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	file, err := archive.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func tarFixture(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func gzipFixture(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	if _, err := compressed.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func readComponentFile(root, name string) ([]byte, error) {
	return os.ReadFile(root + "/" + name)
}
