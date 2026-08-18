package ubuntu

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

//go:embed component-sources.json
var componentSourceDocument []byte

const componentSourceDocumentSHA256 = "eb593370516bd6839ef0276dbe170bf85dd83092ab0a6683363892499769b340"

type componentSourceLock struct {
	Schema        int                   `json:"schema"`
	Architectures []architectureSources `json:"architectures"`
}

type architectureSources struct {
	Architecture softwarelifecycle.Architecture `json:"architecture"`
	Artifacts    []componentSource              `json:"artifacts"`
}

type componentSource struct {
	Role     string `json:"role"`
	Source   string `json:"source"`
	Version  string `json:"version"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}

type componentFetcher func(context.Context, componentSource) ([]byte, error)
type componentQualifier func(context.Context, string, softwarelifecycle.PayloadMetadata) error

func (lock componentSourceLock) forArchitecture(architecture softwarelifecycle.Architecture) (architectureSources, bool) {
	for _, sources := range lock.Architectures {
		if sources.Architecture == architecture {
			return sources, true
		}
	}
	return architectureSources{}, false
}

func repositoryComponentSources() (componentSourceLock, error) {
	return parseComponentSources(componentSourceDocument)
}

func parseComponentSources(document []byte) (componentSourceLock, error) {
	digest := sha256.Sum256(document)
	if hex.EncodeToString(digest[:]) != componentSourceDocumentSHA256 || softwarelifecycle.ValidateUniqueJSON(document) != nil {
		return componentSourceLock{}, errors.New("component source manifest refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var lock componentSourceLock
	if decoder.Decode(&lock) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validComponentSourceLock(lock) {
		return componentSourceLock{}, errors.New("component source manifest refused")
	}
	return lock, nil
}

func validComponentSourceLock(lock componentSourceLock) bool {
	if lock.Schema != 1 || len(lock.Architectures) != 2 {
		return false
	}
	for index, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		sources := lock.Architectures[index]
		if sources.Architecture != architecture || len(sources.Artifacts) != 22 {
			return false
		}
		roles, wheels := map[string]bool{}, map[string]bool{}
		for sourceIndex, source := range sources.Artifacts {
			parsed, err := url.Parse(source.URL)
			if err != nil || parsed.Scheme != "https" || parsed.RawQuery != "" || parsed.Fragment != "" || path.Base(parsed.Path) != source.Filename || source.Size <= 0 || source.Size > softwarelifecycle.MaxAssetBytes || len(source.SHA256) != sha256.Size*2 {
				return false
			}
			if sourceIndex < 4 {
				wantRole := []string{"xray", "sing-box", "cloudflared", "mihomo"}[sourceIndex]
				if source.Role != wantRole || roles[source.Role] {
					return false
				}
				roles[source.Role] = true
			} else if source.Role != "certbot-wheel" || wheels[source.Filename] {
				return false
			} else {
				wheels[source.Filename] = true
			}
		}
		if !validReviewedComponents(sources) || !validWheelClosure(wheels, architecture) {
			return false
		}
	}
	return true
}

func validReviewedComponents(sources architectureSources) bool {
	xrayName, singBoxName, cloudflaredName, mihomoName := "Xray-linux-64.zip", "sing-box-1.13.16-linux-amd64.tar.gz", "cloudflared-linux-amd64", "mihomo-linux-amd64-v1.19.29.gz"
	if sources.Architecture == softwarelifecycle.ARM64 {
		xrayName, singBoxName, cloudflaredName, mihomoName = "Xray-linux-arm64-v8a.zip", "sing-box-1.13.16-linux-arm64.tar.gz", "cloudflared-linux-arm64", "mihomo-linux-arm64-v1.19.29.gz"
	}
	want := []struct{ source, version, filename, prefix string }{
		{"github:XTLS/Xray-core", "v26.3.27", xrayName, "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/"},
		{"github:SagerNet/sing-box", "v1.13.16", singBoxName, "https://github.com/SagerNet/sing-box/releases/download/v1.13.16/"},
		{"github:cloudflare/cloudflared", "2026.7.3", cloudflaredName, "https://github.com/cloudflare/cloudflared/releases/download/2026.7.3/"},
		{"github:MetaCubeX/mihomo", "v1.19.29", mihomoName, "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/"},
	}
	for index, expected := range want {
		got := sources.Artifacts[index]
		if got.Source != expected.source || got.Version != expected.version || got.Filename != expected.filename || got.URL != expected.prefix+expected.filename {
			return false
		}
	}
	return true
}

func validWheelClosure(filenames map[string]bool, architecture softwarelifecycle.Architecture) bool {
	arch := "x86_64"
	if architecture == softwarelifecycle.ARM64 {
		arch = "aarch64"
	}
	want := []string{
		"acme-5.7.0-py3-none-any.whl", "certbot-5.4.0-py3-none-any.whl", "certifi-2026.7.22-py3-none-any.whl",
		"cffi-2.1.1-cp312-cp312-manylinux2014_" + arch + ".manylinux_2_17_" + arch + ".whl",
		"charset_normalizer-3.4.9-cp312-cp312-manylinux2014_" + arch + ".manylinux_2_17_" + arch + ".manylinux_2_28_" + arch + ".whl",
		"configargparse-1.7.5-py3-none-any.whl", "configobj-5.0.9-py2.py3-none-any.whl",
		"cryptography-50.0.0-cp311-abi3-manylinux2014_" + arch + ".manylinux_2_17_" + arch + ".whl",
		"distro-1.9.0-py3-none-any.whl", "idna-3.18-py3-none-any.whl", "josepy-2.2.0-py3-none-any.whl",
		"parsedatetime-2.6-py3-none-any.whl", "pycparser-3.0-py3-none-any.whl", "pyopenssl-26.4.0-py3-none-any.whl",
		"pyrfc3339-2.1.0-py3-none-any.whl", "requests-2.34.2-py3-none-any.whl", "typing_extensions-4.16.0-py3-none-any.whl", "urllib3-2.7.0-py3-none-any.whl",
	}
	if len(filenames) != len(want) {
		return false
	}
	for _, filename := range want {
		if !filenames[filename] {
			return false
		}
	}
	return true
}

// BuildReleaseComponentArchive retrieves the repository-reviewed offline
// component closure and qualifies the assembled programs before packaging it.
func BuildReleaseComponentArchive(ctx context.Context, architecture softwarelifecycle.Architecture, metadata softwarelifecycle.PayloadMetadata) ([]byte, error) {
	lock, err := repositoryComponentSources()
	if err != nil {
		return nil, err
	}
	sources, ok := lock.forArchitecture(architecture)
	if !ok || runtime.GOOS != "linux" || runtime.GOARCH != string(architecture) {
		return nil, errors.New("component release build requires matching Linux architecture")
	}
	return assembleReleaseComponents(ctx, sources, fetchComponentSource, qualifyReleaseComponents, metadata)
}

func fetchComponentSource(ctx context.Context, source componentSource) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return nil, errors.New("component source unavailable")
	}
	client := http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(_ *http.Request, previous []*http.Request) error {
		if len(previous) >= 5 {
			return errors.New("component source redirect limit exceeded")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("component source unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > source.Size {
		return nil, errors.New("component source unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, source.Size+1))
	if err != nil || int64(len(body)) != source.Size {
		return nil, errors.New("component source unavailable")
	}
	return body, nil
}

func assembleReleaseComponents(ctx context.Context, sources architectureSources, fetch componentFetcher, qualify componentQualifier, metadata softwarelifecycle.PayloadMetadata) ([]byte, error) {
	if ctx == nil || fetch == nil || sources.Architecture != softwarelifecycle.AMD64 && sources.Architecture != softwarelifecycle.ARM64 {
		return nil, errors.New("component release build refused")
	}
	files := map[string][]byte{
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(),
		"certbot/pyvenv.cfg":  []byte("home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12\n"),
	}
	for _, source := range sources.Artifacts {
		body, err := fetch(ctx, source)
		digest := sha256.Sum256(body)
		if err != nil || int64(len(body)) != source.Size || hex.EncodeToString(digest[:]) != source.SHA256 {
			return nil, errors.New("component source verification failed")
		}
		switch source.Role {
		case "xray":
			files["xray"], err = exactZipFile(body, "xray")
		case "sing-box":
			files["sing-box"], err = exactTarGzipFile(body, strings.TrimSuffix(source.Filename, ".tar.gz")+"/sing-box")
		case "cloudflared":
			files["cloudflared"] = append([]byte(nil), body...)
		case "mihomo":
			files["mihomo"], err = exactGzipFile(body)
		case "certbot-wheel":
			err = addWheel(files, body)
		default:
			err = errors.New("component source role refused")
		}
		if err != nil {
			return nil, errors.New("component source extraction failed")
		}
	}
	root, err := materializeComponentFiles(files)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	if qualify == nil {
		return nil, errors.New("component native qualification refused")
	}
	if err := qualify(ctx, root, metadata); err != nil {
		return nil, err
	}
	delete(files, "mihomo")
	manifest, err := softwarelifecycle.NewBoundComponentManifest(sources.Architecture, metadata.Build, "5.4.0", files)
	if err != nil {
		return nil, err
	}
	return softwarelifecycle.BuildComponentArchive(manifest, files)
}

func exactGzipFile(body []byte) ([]byte, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	value, readErr := io.ReadAll(io.LimitReader(compressed, softwarelifecycle.MaxAssetBytes+1))
	closeErr := compressed.Close()
	if readErr != nil || closeErr != nil || len(value) == 0 || len(value) > softwarelifecycle.MaxAssetBytes {
		return nil, errors.New("component archive refused")
	}
	return value, nil
}

func exactZipFile(body []byte, name string) ([]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	var found []byte
	for _, file := range archive.File {
		if file.Name != name {
			continue
		}
		if found != nil || !file.Mode().IsRegular() || file.UncompressedSize64 > softwarelifecycle.MaxAssetBytes {
			return nil, errors.New("component archive refused")
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		found, err = io.ReadAll(io.LimitReader(reader, softwarelifecycle.MaxAssetBytes+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || uint64(len(found)) != file.UncompressedSize64 {
			return nil, errors.New("component archive refused")
		}
	}
	if len(found) == 0 {
		return nil, errors.New("component executable missing")
	}
	return found, nil
}

func exactTarGzipFile(body []byte, name string) ([]byte, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	archive := tar.NewReader(compressed)
	var found []byte
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Name != name {
			continue
		}
		if found != nil || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > softwarelifecycle.MaxAssetBytes {
			return nil, errors.New("component archive refused")
		}
		found, err = io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(found)) != header.Size {
			return nil, errors.New("component archive refused")
		}
	}
	if compressed.Close() != nil || len(found) == 0 {
		return nil, errors.New("component executable missing")
	}
	return found, nil
}

func addWheel(files map[string][]byte, body []byte) error {
	archive, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return err
	}
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}
		clean := path.Clean(file.Name)
		if clean != file.Name || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, ".data/") || !file.Mode().IsRegular() || file.UncompressedSize64 > softwarelifecycle.MaxAssetBytes {
			return errors.New("wheel entry refused")
		}
		name := "certbot/lib/python3.12/site-packages/" + clean
		if _, duplicate := files[name]; duplicate {
			return errors.New("duplicate wheel entry")
		}
		reader, err := file.Open()
		if err != nil {
			return err
		}
		value, readErr := io.ReadAll(io.LimitReader(reader, softwarelifecycle.MaxAssetBytes+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || uint64(len(value)) != file.UncompressedSize64 {
			return errors.New("wheel entry unavailable")
		}
		files[name] = value
	}
	return nil
}

func materializeComponentFiles(files map[string][]byte) (string, error) {
	root, err := os.MkdirTemp("", "sbxr-component-qualification-")
	if err != nil {
		return "", errors.New("component qualification unavailable")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		clean := path.Clean(name)
		if clean != name || strings.HasPrefix(clean, "../") {
			os.RemoveAll(root)
			return "", errors.New("component path refused")
		}
		filename := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(filename), 0o700) != nil {
			os.RemoveAll(root)
			return "", errors.New("component qualification unavailable")
		}
		mode := os.FileMode(0o600)
		if name == "xray" || name == "sing-box" || name == "cloudflared" || name == "mihomo" || name == "certbot/bin/certbot" {
			mode = 0o700
		}
		if os.WriteFile(filename, files[name], mode) != nil {
			os.RemoveAll(root)
			return "", errors.New("component qualification unavailable")
		}
	}
	if os.Symlink("/usr/bin/python3", filepath.Join(root, "certbot/bin/python3")) != nil {
		os.RemoveAll(root)
		return "", errors.New("component qualification unavailable")
	}
	return root, nil
}

func qualifyReleaseComponents(ctx context.Context, root string, metadata softwarelifecycle.PayloadMetadata) error {
	validator := newNativeValidatorForComponents(nil, root)
	return validator.Validate(ctx, metadata)
}
