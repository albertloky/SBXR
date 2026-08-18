package softwarelifecycle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const componentManifestName = "component-manifest.json"

var componentCertbotLauncher = []byte("#!/bin/sh\ncase $0 in */certbot/bin/certbot) root=${0%/bin/certbot} ;; *) exit 1 ;; esac\nexec \"$root/bin/python3\" -I -S -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); sys.argv[0] = \"certbot\"; from certbot.main import main; raise SystemExit(main())' \"$root/lib/python3.12/site-packages\" \"$@\"\n")

func ComponentCertbotLauncher() []byte { return append([]byte(nil), componentCertbotLauncher...) }

type ComponentFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Type   string `json:"type"`
	Target string `json:"target"`
	Mode   int64  `json:"mode"`
	Size   int64  `json:"size"`
}

type ComponentManifest struct {
	Schema       int                   `json:"schema"`
	Architecture Architecture          `json:"architecture"`
	Build        EmbeddedBuildIdentity `json:"build"`
	Xray         string                `json:"xray"`
	SingBox      string                `json:"sing_box"`
	Cloudflared  string                `json:"cloudflared"`
	Certbot      string                `json:"certbot"`
	Python       string                `json:"python"`
	Files        []ComponentFile       `json:"files"`
}

var componentCertbotVersion = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.[0-9]+)?$`)

func ValidateComponentArchive(body []byte, architecture Architecture) (ComponentManifest, error) {
	if len(body) == 0 || len(body) > MaxAssetBytes || architecture != AMD64 && architecture != ARM64 {
		return ComponentManifest{}, errors.New("component archive refused")
	}
	input := bytes.NewReader(body)
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return ComponentManifest{}, errors.New("component archive refused")
	}
	compressed.Multistream(false)
	archive := tar.NewReader(io.LimitReader(compressed, MaxAssetBytes+1))
	header, err := archive.Next()
	if err != nil || header.Name != componentManifestName || !safeComponentHeader(header, tar.TypeReg, 0o644) || header.Size <= 0 || header.Size > MaxIndexBytes {
		return ComponentManifest{}, errors.New("component manifest refused")
	}
	document, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(document)) != header.Size || ValidateUniqueJSON(document) != nil {
		return ComponentManifest{}, errors.New("component manifest refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest ComponentManifest
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validComponentManifest(manifest, architecture) {
		return ComponentManifest{}, errors.New("component manifest refused")
	}
	canonical, _ := json.Marshal(manifest)
	if !bytes.Equal(document, canonical) {
		return ComponentManifest{}, errors.New("component manifest is not canonical")
	}
	for _, expected := range manifest.Files {
		header, err := archive.Next()
		kind := byte(tar.TypeReg)
		if expected.Type == "symlink" {
			kind = tar.TypeSymlink
		}
		if err != nil || header.Name != expected.Path || !safeComponentHeader(header, kind, expected.Mode) || header.Size != expected.Size || header.Linkname != expected.Target {
			return ComponentManifest{}, errors.New("component entry refused")
		}
		if expected.Type == "symlink" {
			continue
		}
		digest := sha256.New()
		copied, copyErr := io.Copy(digest, archive)
		if copyErr != nil || copied != expected.Size || hex.EncodeToString(digest.Sum(nil)) != expected.SHA256 {
			return ComponentManifest{}, errors.New("component digest refused")
		}
	}
	if _, err := archive.Next(); err != io.EOF {
		return ComponentManifest{}, errors.New("extra component entry")
	}
	remaining, err := io.Copy(io.Discard, compressed)
	if err != nil || remaining != 0 || compressed.Close() != nil || input.Len() != 0 {
		return ComponentManifest{}, errors.New("trailing component content")
	}
	return manifest, nil
}

// QualificationComponent returns one validated core from an exact component archive.
func QualificationComponent(body []byte, architecture Architecture, name string) ([]byte, string, bool) {
	if name != "xray" && name != "sing-box" {
		return nil, "", false
	}
	manifest, err := ValidateComponentArchive(body, architecture)
	if err != nil {
		return nil, "", false
	}
	compressed, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, "", false
	}
	defer compressed.Close()
	archive := tar.NewReader(compressed)
	for {
		header, err := archive.Next()
		if err != nil {
			return nil, "", false
		}
		if header.Name != name {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
		if err != nil || int64(len(content)) != header.Size {
			return nil, "", false
		}
		version := manifest.Xray
		if name == "sing-box" {
			version = strings.TrimPrefix(manifest.SingBox, "v")
		}
		return content, version, true
	}
}

func validComponentManifest(manifest ComponentManifest, architecture Architecture) bool {
	if manifest.Schema != 1 || manifest.Architecture != architecture || manifest.Xray != "v26.3.27" || manifest.SingBox != "v1.13.16" || manifest.Cloudflared != "2026.7.3" || manifest.Python != "3.12" || !certbotAtLeast54(manifest.Certbot) || len(manifest.Files) < 7 {
		return false
	}
	if manifest.Build != (EmbeddedBuildIdentity{}) && !validEmbeddedBuildIdentity(manifest.Build) {
		return false
	}
	required := map[string]bool{"xray": false, "sing-box": false, "cloudflared": false, "certbot/bin/certbot": false, "certbot/bin/python3": false, "certbot/pyvenv.cfg": false}
	previous := ""
	for _, file := range manifest.Files {
		clean := path.Clean(file.Path)
		if clean != file.Path || clean == "." || strings.HasPrefix(clean, "../") || strings.ContainsAny(clean, "\x00\r\n") || file.Path <= previous {
			return false
		}
		previous = file.Path
		if file.Type == "symlink" {
			if file.Path != "certbot/bin/python3" || file.Target != "/usr/bin/python3" || file.Size != 0 || file.SHA256 != "" || file.Mode != 0o777 {
				return false
			}
		} else if file.Type != "regular" || file.Target != "" || file.Size < 0 || file.Size > MaxAssetBytes || !hashPattern.MatchString(file.SHA256) || file.Mode != 0o644 && file.Mode != 0o755 {
			return false
		}
		if file.Path == "xray" || file.Path == "sing-box" || file.Path == "cloudflared" || file.Path == "certbot/bin/certbot" {
			if file.Type != "regular" || file.Mode != 0o755 || file.Size == 0 {
				return false
			}
		}
		if _, ok := required[file.Path]; ok {
			required[file.Path] = true
		}
	}
	for _, present := range required {
		if !present {
			return false
		}
	}
	return true
}

func safeComponentHeader(header *tar.Header, kind byte, mode int64) bool {
	return header.Typeflag == kind && header.Mode == mode && header.Uid == 0 && header.Gid == 0 && (header.Uname == "" || header.Uname == "root") && (header.Gname == "" || header.Gname == "root") && (kind == tar.TypeSymlink || header.Linkname == "")
}

func certbotAtLeast54(version string) bool {
	match := componentCertbotVersion.FindStringSubmatch(version)
	if match == nil {
		return false
	}
	major, majorErr := strconv.Atoi(match[1])
	minor, minorErr := strconv.Atoi(match[2])
	return majorErr == nil && minorErr == nil && (major > 5 || major == 5 && minor >= 4)
}

// BuildComponentArchive assembles a release-build-qualified bundle from exact
// manifest-listed bytes. Release tooling validates the programs before calling it.
func BuildComponentArchive(manifest ComponentManifest, files map[string][]byte) ([]byte, error) {
	if !validComponentManifest(manifest, manifest.Architecture) {
		return nil, errors.New("component manifest refused")
	}
	canonical, _ := json.Marshal(manifest)
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	if archive.WriteHeader(&tar.Header{Name: componentManifestName, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(canonical)), Uid: 0, Gid: 0}) != nil {
		return nil, errors.New("component archive unavailable")
	}
	if _, err := archive.Write(canonical); err != nil {
		return nil, err
	}
	for _, file := range manifest.Files {
		header := &tar.Header{Name: file.Path, Mode: file.Mode, Size: file.Size, Uid: 0, Gid: 0, Typeflag: tar.TypeReg}
		if file.Type == "symlink" {
			header.Typeflag, header.Linkname = tar.TypeSymlink, file.Target
		}
		if archive.WriteHeader(header) != nil {
			return nil, errors.New("component archive unavailable")
		}
		if file.Type == "regular" {
			body, ok := files[file.Path]
			digest := sha256.Sum256(body)
			if !ok || int64(len(body)) != file.Size || hex.EncodeToString(digest[:]) != file.SHA256 {
				return nil, errors.New("component source mismatch")
			}
			if _, err := archive.Write(body); err != nil {
				return nil, err
			}
		}
	}
	if archive.Close() != nil || compressed.Close() != nil || output.Len() > MaxAssetBytes {
		return nil, errors.New("component archive unavailable")
	}
	return output.Bytes(), nil
}

func NewComponentManifest(architecture Architecture, certbot string, files map[string][]byte) (ComponentManifest, error) {
	return newComponentManifest(architecture, EmbeddedBuildIdentity{}, certbot, files)
}

// NewBoundComponentManifest binds the component archive to one exact packaged application.
func NewBoundComponentManifest(architecture Architecture, build EmbeddedBuildIdentity, certbot string, files map[string][]byte) (ComponentManifest, error) {
	if !validEmbeddedBuildIdentity(build) {
		return ComponentManifest{}, errors.New("component build identity refused")
	}
	return newComponentManifest(architecture, build, certbot, files)
}

func newComponentManifest(architecture Architecture, build EmbeddedBuildIdentity, certbot string, files map[string][]byte) (ComponentManifest, error) {
	if !bytes.Equal(files["certbot/bin/certbot"], componentCertbotLauncher) {
		return ComponentManifest{}, errors.New("component Certbot launcher refused")
	}
	names := make([]string, 0, len(files)+1)
	for name := range files {
		names = append(names, name)
	}
	names = append(names, "certbot/bin/python3")
	sort.Strings(names)
	manifest := ComponentManifest{Schema: 1, Architecture: architecture, Build: build, Xray: "v26.3.27", SingBox: "v1.13.16", Cloudflared: "2026.7.3", Certbot: certbot, Python: "3.12"}
	for _, name := range names {
		if name == "certbot/bin/python3" {
			manifest.Files = append(manifest.Files, ComponentFile{Path: name, Type: "symlink", Target: "/usr/bin/python3", Mode: 0o777})
			continue
		}
		body := files[name]
		digest := sha256.Sum256(body)
		mode := int64(0o644)
		if name == "xray" || name == "sing-box" || name == "cloudflared" || name == "certbot/bin/certbot" {
			mode = 0o755
		}
		manifest.Files = append(manifest.Files, ComponentFile{Path: name, SHA256: hex.EncodeToString(digest[:]), Type: "regular", Mode: mode, Size: int64(len(body))})
	}
	if !validComponentManifest(manifest, architecture) {
		return ComponentManifest{}, errors.New("component inputs refused")
	}
	return manifest, nil
}

func validEmbeddedBuildIdentity(build EmbeddedBuildIdentity) bool {
	return build.Repository == Repository && safeTag(build.Tag) && commitPattern.MatchString(build.Commit) && hashPattern.MatchString(build.PayloadSHA256)
}
