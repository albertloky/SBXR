package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/creack/pty"
)

func TestBuildCompleteReleaseWritesApplicationAndQualifiedComponentsTogether(t *testing.T) {
	root := t.TempDir()
	application := filepath.Join(root, "sbxr-linux-amd64.tar.gz")
	components := filepath.Join(root, "sbxr-components-linux-amd64.tar.gz")
	options := buildOptions{tag: "v1.0.0", commit: strings.Repeat("a", 40), architecture: softwarelifecycle.AMD64, output: application, componentOutput: components}
	called := false
	err := buildCompleteRelease(t.Context(), options, currentSource, func(_ context.Context, architecture softwarelifecycle.Architecture, metadata softwarelifecycle.PayloadMetadata) ([]byte, error) {
		called = true
		if architecture != softwarelifecycle.AMD64 || metadata.Build.Tag != "v1.0.0" {
			return nil, io.ErrUnexpectedEOF
		}
		return []byte("qualified-components"), nil
	})
	if err != nil || !called {
		t.Fatalf("buildCompleteRelease() = %v, called=%v", err, called)
	}
	if body, err := os.ReadFile(components); err != nil || string(body) != "qualified-components" {
		t.Fatalf("component output = %q, %v", body, err)
	}
	if _, err := os.Stat(application); err != nil {
		t.Fatal(err)
	}

	failedApplication := filepath.Join(root, "failed-application.tar.gz")
	failedComponents := filepath.Join(root, "failed-components.tar.gz")
	options.output, options.componentOutput = failedApplication, failedComponents
	if err := buildCompleteRelease(t.Context(), options, currentSource, func(context.Context, softwarelifecycle.Architecture, softwarelifecycle.PayloadMetadata) ([]byte, error) {
		return nil, errors.New("release qualification refused: mihomo-config")
	}); err == nil || err.Error() != "release qualification refused: mihomo-config" {
		t.Fatalf("component qualification failure = %v", err)
	}
	if _, err := os.Stat(failedApplication); !os.IsNotExist(err) {
		t.Fatalf("partial application output remains: %v", err)
	}

	blockedApplication := filepath.Join(root, "blocked-application.tar.gz")
	blockedComponents := filepath.Join(root, "blocked-components.tar.gz")
	if err := os.WriteFile(blockedComponents, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	options.output, options.componentOutput = blockedApplication, blockedComponents
	if err := buildCompleteRelease(t.Context(), options, currentSource, func(context.Context, softwarelifecycle.Architecture, softwarelifecycle.PayloadMetadata) ([]byte, error) {
		return []byte("qualified-components"), nil
	}); err == nil {
		t.Fatal("occupied component output accepted")
	}
	if _, err := os.Stat(blockedApplication); !os.IsNotExist(err) {
		t.Fatalf("partial application output remains: %v", err)
	}
	if body, err := os.ReadFile(blockedComponents); err != nil || string(body) != "existing" {
		t.Fatalf("existing component output changed: %q, %v", body, err)
	}
}

func TestVerifyCandidateRefusesInvalidTagBeforeExternalVerification(t *testing.T) {
	if err := verifyCandidate(t.Context(), ""); err == nil {
		t.Fatal("empty candidate tag accepted")
	}
}

func TestBuildBootstrapFileBindsOneReleaseWithoutAnIndexSelfReference(t *testing.T) {
	output := filepath.Join(t.TempDir(), "install.sh")
	err := buildBootstrapFile(bootstrapOptions{version: "1.0.0", sequence: 7, tag: "v1.0.0", commit: "0123456789abcdef0123456789abcdef01234567", output: output})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, exact := range []string{"REPOSITORY=", "albertloky/SBXR", "TAG=", "v1.0.0", "COMMIT=", "0123456789abcdef0123456789abcdef01234567", "VERSION=", "1.0.0", "SEQUENCE=", "7", "ARCHITECTURES=", "amd64 arm64", "install.sh release-index.json sbxr-linux-amd64.tar.gz sbxr-linux-arm64.tar.gz sbxr-components-linux-amd64.tar.gz sbxr-components-linux-arm64.tar.gz"} {
		if !strings.Contains(text, exact) {
			t.Fatalf("bootstrap does not bind %q", exact)
		}
	}
	if strings.Contains(strings.ToLower(text), "index_sha256=") {
		t.Fatal("bootstrap recreated the impossible release-index self-reference")
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("bootstrap mode = %v, %v", info.Mode(), err)
	}
	if err := exec.Command("/bin/sh", "-n", output).Run(); err != nil {
		t.Fatalf("generated bootstrap syntax: %v", err)
	}
}

func TestGeneratedBootstrapVerifiesAndLaunchesOnlyTheExactReleaseAsTheOwner(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		arm64     bool
	}{{}, {arguments: []string{"--tag", "v1.0.0"}}, {arm64: true}} {
		fixture := newBootstrapFixture(t)
		if test.arm64 {
			fixture.machine = "aarch64"
			fixture.version = strings.Replace(fixture.version, `"architecture":"amd64"`, `"architecture":"arm64"`, 1)
			fixture.writeBoundaries(t)
		}
		fixture.hostileEnvironment = true
		fixture.writeBoundaries(t)
		output, err := fixture.run(test.arguments...)
		if err != nil {
			t.Fatalf("bootstrap %v = %v\n%s", test, err, output)
		}
		if !strings.Contains(output, "SBXR bootstrap: verifying release") || !strings.Contains(output, "SBXR bootstrap: launching Owner Console") || strings.Contains(output, "PRIVATE-SECRET-MARKER") {
			t.Fatalf("unsafe bootstrap output = %q", output)
		}
		launched, err := os.ReadFile(fixture.launchRecord)
		if err != nil || strings.Contains(string(launched), "PRIVATE-SECRET-MARKER") || !strings.Contains(string(launched), "HOME="+fixture.home) || !strings.Contains(string(launched), "USER=owner") {
			t.Fatalf("Owner launch environment = %q, %v", launched, err)
		}
		if matches, _ := filepath.Glob(filepath.Join(fixture.root, "tmp", "sbxr-bootstrap.*")); len(matches) != 0 {
			t.Fatalf("bootstrap temporary material remains: %v", matches)
		}
	}
}

func TestGeneratedBootstrapRefusesHostileInputsWithOnlyFixedSafeOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*bootstrapFixture)
		args   []string
	}{
		{name: "wrong pinned tag", args: []string{"--tag", "v1.0.1"}},
		{name: "changed index", change: func(f *bootstrapFixture) { f.index = strings.Replace(f.index, `"sequence":7`, `"sequence":8`, 1) }},
		{name: "changed archive", change: func(f *bootstrapFixture) { f.archive = []byte("changed archive") }},
		{name: "extra archive material", change: func(f *bootstrapFixture) { f.tarList = "sbxr\nextra" }},
		{name: "path substitution", change: func(f *bootstrapFixture) { f.substitute = true }},
		{name: "redirect substitution", change: func(f *bootstrapFixture) { f.redirect = "https://attacker.invalid/PRIVATE-SECRET-MARKER" }},
		{name: "unsupported architecture", change: func(f *bootstrapFixture) { f.machine = "riscv64" }},
		{name: "wrong executable identity", change: func(f *bootstrapFixture) {
			f.version = strings.Replace(f.version, `"commit":"0123456789abcdef0123456789abcdef01234567"`, `"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, 1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			if test.change != nil {
				test.change(fixture)
				fixture.writeBoundaries(t)
			}
			output, err := fixture.run(test.args...)
			if err == nil || !strings.Contains(output, "SBXR-BOOTSTRAP-REFUSED") || strings.Contains(output, "PRIVATE-SECRET-MARKER") {
				t.Fatalf("hostile bootstrap = %v, %q", err, output)
			}
			if _, statErr := os.Stat(fixture.launchRecord); !os.IsNotExist(statErr) {
				t.Fatalf("hostile bootstrap launched: %v", statErr)
			}
		})
	}

	fixture := newBootstrapFixture(t)
	command := exec.Command("/bin/sh", fixture.script)
	output, err := command.CombinedOutput()
	if err == nil || string(output) != "SBXR-BOOTSTRAP-REFUSED\n" {
		t.Fatalf("non-interactive bootstrap = %v, %q", err, output)
	}

	interrupted := newBootstrapFixture(t)
	interrupted.interrupt = true
	interrupted.writeBoundaries(t)
	interruptedOutput, interruptErr := interrupted.run()
	if interruptErr == nil || !strings.Contains(interruptedOutput, "SBXR-BOOTSTRAP-INTERRUPTED") || strings.Contains(interruptedOutput, "PRIVATE-SECRET-MARKER") {
		t.Fatalf("interrupted bootstrap = %v, %q", interruptErr, interruptedOutput)
	}

	cleanupFailure := newBootstrapFixture(t)
	cleanupFailure.cleanupFail = true
	cleanupFailure.writeBoundaries(t)
	cleanupOutput, cleanupErr := cleanupFailure.run()
	if cleanupErr == nil || !strings.Contains(cleanupOutput, "SBXR-BOOTSTRAP-CLEANUP-FAILED") || strings.Contains(cleanupOutput, "PRIVATE-SECRET-MARKER") {
		t.Fatalf("cleanup failure = %v, %q", cleanupErr, cleanupOutput)
	}
}

type bootstrapFixture struct {
	root, home, script, launchRecord string
	index, version, redirect         string
	archive                          []byte
	machine, tarList                 string
	substitute, interrupt            bool
	hostileEnvironment, cleanupFail  bool
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	root := t.TempDir()
	fixture := &bootstrapFixture{root: root, home: filepath.Join(root, "home", "owner"), script: filepath.Join(root, "install.sh"), launchRecord: filepath.Join(root, "launched"), redirect: "https://release-assets.githubusercontent.com/exact", archive: []byte("exact archive bytes"), machine: "x86_64", tarList: "sbxr"}
	for _, directory := range []string{"bin", "usr/bin", "etc", "tmp", "fixtures", "home/owner"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/bin/sh", filepath.Join(root, "bin", "sh")); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(fixture.archive)
	archiveSHA := fmt.Sprintf("%x", digest)
	otherSHA := strings.Repeat("a", 64)
	fixture.index = fmt.Sprintf(`{"schema":1,"product":"sbxr","repository":"albertloky/SBXR","version":"1.0.0","sequence":7,"tag":"v1.0.0","commit":"0123456789abcdef0123456789abcdef01234567","state_schema":2,"minimum_updater_schema":1,"assets":[{"role":"application-linux-amd64","name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"role":"application-linux-arm64","name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":"%s"},{"role":"components-linux-amd64","name":"sbxr-components-linux-amd64.tar.gz","size":1,"sha256":"%s"},{"role":"components-linux-arm64","name":"sbxr-components-linux-arm64.tar.gz","size":1,"sha256":"%s"},{"role":"bootstrap","name":"install.sh","size":1,"sha256":"%s"}]}`, len(fixture.archive), archiveSHA, len(fixture.archive), archiveSHA, otherSHA, otherSHA, otherSHA)
	fixture.version = `{"build":{"repository":"albertloky/SBXR","tag":"v1.0.0","commit":"0123456789abcdef0123456789abcdef01234567","payload_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"architecture":"amd64","state_schema":2}`
	fixture.writeBoundaries(t)
	if err := buildBootstrapFile(bootstrapOptions{version: "1.0.0", sequence: 7, tag: "v1.0.0", commit: "0123456789abcdef0123456789abcdef01234567", output: fixture.script, root: root}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *bootstrapFixture) writeBoundaries(t *testing.T) {
	t.Helper()
	mustScript := func(name, body string) {
		path := filepath.Join(fixture.root, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "etc", "os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "fixtures", "index"), []byte(fixture.index), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.root, "fixtures", "archive"), fixture.archive, 0o600); err != nil {
		t.Fatal(err)
	}
	mustScript("usr/bin/id", `if [ "${1-}" = "-un" ]; then echo owner; else echo 1000; fi`)
	mustScript("usr/bin/uname", `echo `+fixture.machine)
	mustScript("usr/bin/getent", fmt.Sprintf(`echo 'owner:x:1000:1000::%s:/bin/sh'`, fixture.home))
	mustScript("usr/bin/mktemp", `path=${2%XXXXXX}TEST; mkdir "$path" || exit 1; echo "$path"`)
	mustScript("usr/bin/stat", `if [ "$1" = "-c" ]; then format=$2; path=$3; case "$format" in '%s') exec /usr/bin/stat -f '%z' "$path" ;; '%u:%a:%F') if [ -d "$path" ]; then echo '1000:700:directory'; else echo '1000:600:regular file'; fi ;; '%u:%a:%h:%F') echo '1000:700:1:regular file' ;; esac; fi`)
	mustScript("usr/bin/sha256sum", `shasum -a 256 "$1"`)
	curlEffect := fmt.Sprintf(`case "$url" in */release-index.json) cp '%s' "$out" ;; */sbxr-linux-amd64.tar.gz|*/sbxr-linux-arm64.tar.gz) cp '%s' "$out" ;; *) exit 1 ;; esac; printf '%%s' '%s'`, filepath.Join(fixture.root, "fixtures", "index"), filepath.Join(fixture.root, "fixtures", "archive"), fixture.redirect)
	if fixture.substitute {
		curlEffect = fmt.Sprintf(`ln -s '%s' "$out"; printf '%%s' '%s'`, filepath.Join(fixture.root, "fixtures", "archive"), fixture.redirect)
	}
	if fixture.interrupt {
		curlEffect = `kill -TERM "$PPID"; sleep 1; exit 1`
	}
	mustScript("usr/bin/curl", `if [ -n "${CURL_HOME-}${TAR_OPTIONS-}${CLOUDFLARE_API_TOKEN-}" ]; then printf '%s\n' 'PRIVATE-SECRET-MARKER' >&2; exit 1; fi; printf '%s\n' 'PRIVATE-SECRET-MARKER' >&2; out=''; url=''; while [ "$#" -gt 0 ]; do case "$1" in --output) out=$2; shift 2 ;; http*) url=$1; shift ;; *) shift ;; esac; done; `+curlEffect)
	mustScript("usr/bin/tar", fmt.Sprintf(`case "$1" in -tzf) printf '%%s\n' '%s' ;; -xzf) while [ "$#" -gt 0 ]; do if [ "$1" = '-C' ]; then destination=$2; fi; shift; done; cat >"$destination/sbxr" <<'SBXR'
#!/bin/sh
if [ "${1-}" = version ] && [ "${2-}" = --json ]; then printf '%%s\n' '%s'; exit 0; fi
/usr/bin/env >'%s'
SBXR
chmod 700 "$destination/sbxr" ;; *) exit 1 ;; esac`, fixture.tarList, fixture.version, fixture.launchRecord))
	for _, tool := range []string{"grep", "sed", "cut", "env"} {
		mustScript("usr/bin/"+tool, `exec /usr/bin/`+tool+` "$@"`)
	}
	for _, tool := range []string{"chmod", "rm"} {
		mustScript("bin/"+tool, `exec /bin/`+tool+` "$@"`)
	}
	if fixture.cleanupFail {
		mustScript("bin/rm", `exit 1`)
	}
}

func (fixture *bootstrapFixture) run(arguments ...string) (string, error) {
	command := exec.Command("/bin/sh", append([]string{fixture.script}, arguments...)...)
	command.Env = append(os.Environ(), "TERM=xterm-256color", "CLOUDFLARE_API_TOKEN=PRIVATE-SECRET-MARKER")
	if fixture.hostileEnvironment {
		command.Env = append(command.Env, "SBXR_BOOTSTRAP_CLEAN=1", "CURL_HOME=/PRIVATE-SECRET-MARKER", "TAR_OPTIONS=--checkpoint-action=exec=PRIVATE-SECRET-MARKER")
	}
	terminal, err := pty.Start(command)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(terminal)
	waitErr := command.Wait()
	_ = terminal.Close()
	return strings.ReplaceAll(string(body), "\r", ""), waitErr
}

func TestBuildReleaseIndexFileReadsOnlyInstallAndTheExactFourReleaseArchives(t *testing.T) {
	root := t.TempDir()
	assets := []softwarelifecycle.ReleaseIndexAsset{
		{Role: softwarelifecycle.ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Bytes: []byte("amd64 application")},
		{Role: softwarelifecycle.ApplicationARM64, Name: "sbxr-linux-arm64.tar.gz", Bytes: []byte("arm64 application")},
		{Role: softwarelifecycle.ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Bytes: []byte("amd64 components")},
		{Role: softwarelifecycle.ComponentsARM64, Name: "sbxr-components-linux-arm64.tar.gz", Bytes: []byte("arm64 components")},
		{Role: softwarelifecycle.Bootstrap, Name: "install.sh", Bytes: []byte("#!/bin/sh\nexit 1\n")},
	}
	for _, asset := range assets {
		if err := os.WriteFile(filepath.Join(root, asset.Name), asset.Bytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commit := "0123456789abcdef0123456789abcdef01234567"
	output := filepath.Join(root, "release-index.json")
	if err := os.WriteFile(filepath.Join(root, "unexpected.tar.gz"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: output}); err == nil {
		t.Fatal("extra release asset was indexed")
	}
	if err := os.Remove(filepath.Join(root, "unexpected.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: output}); err != nil {
		t.Fatal(err)
	}
	metadata, err := releaseMetadata(softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: commit}, softwarelifecycle.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	want, err := softwarelifecycle.BuildReleaseIndex(softwarelifecycle.ReleaseIndexRequest{Version: "1.0.0", Sequence: 1, Tag: "v1.0.0", Commit: commit, StateSchema: metadata.StateSchema, MinimumUpdaterSchema: metadata.MinimumUpdaterSchema, Assets: assets})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(output); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("release index = %s, %v; want %s", got, err, want)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: output}); err == nil {
		t.Fatal("occupied release index was replaced")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "sbxr-components-linux-arm64.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: filepath.Join(root, "missing-index.json")}); err == nil {
		t.Fatal("incomplete release asset set was indexed")
	}
	if err := os.Symlink(filepath.Join(root, "sbxr-components-linux-amd64.tar.gz"), filepath.Join(root, "sbxr-components-linux-arm64.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: commit, directory: root, output: filepath.Join(root, "linked-index.json")}); err == nil {
		t.Fatal("linked release asset was indexed")
	}
}

func TestBuildReleaseIndexFileRefusesAnAssetChangedWhileReading(t *testing.T) {
	root := t.TempDir()
	names := []string{"sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "install.sh"}
	for index, name := range names {
		body := []byte("asset")
		if index == 0 {
			body = bytes.Repeat([]byte("a"), 64<<20)
		}
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	changing, err := os.OpenFile(filepath.Join(root, names[0]), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		first := true
		for value := byte('b'); ; value ^= 1 {
			if _, err := changing.WriteAt([]byte{value}, 4<<20); err != nil {
				return
			}
			if first {
				close(started)
				first = false
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	<-started
	err = buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: strings.Repeat("a", 40), directory: root, output: filepath.Join(root, "release-index.json")})
	close(stop)
	<-done
	if closeErr := changing.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err == nil {
		t.Fatal("asset changed during index construction was accepted")
	}
}

func TestBuildReleaseIndexFileRefusesAReplacedAssetPath(t *testing.T) {
	root := t.TempDir()
	names := []string{"sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "install.sh"}
	for index, name := range names {
		body := []byte("asset")
		if index == 1 {
			body = bytes.Repeat([]byte("a"), 128<<20)
		}
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, names[0])
	replacement := filepath.Join(t.TempDir(), "replacement")
	if err := os.WriteFile(replacement, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		time.Sleep(10 * time.Millisecond)
		_ = os.Rename(replacement, target)
		<-stop
	}()
	<-started
	err := buildReleaseIndexFile(indexOptions{version: "1.0.0", sequence: 1, tag: "v1.0.0", commit: strings.Repeat("a", 40), directory: root, output: filepath.Join(root, "release-index.json")})
	close(stop)
	<-done
	if err == nil {
		t.Fatal("replaced release asset path was accepted")
	}
}

type acceptingValidator struct{ calls int }

func (validator *acceptingValidator) Validate(_ context.Context, metadata softwarelifecycle.PayloadMetadata) error {
	validator.calls++
	if len(metadata.Schemas) != 2 || len(metadata.Migrations) != 1 || len(metadata.Units) != 11 || len(metadata.Artifacts) != 10 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestBuildArchiveProducesOneQualifiedExecutableForBothArchitectures(t *testing.T) {
	for _, architecture := range []softwarelifecycle.Architecture{softwarelifecycle.AMD64, softwarelifecycle.ARM64} {
		t.Run(string(architecture), func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "sbxr-linux-"+string(architecture)+".tar.gz")
			validator := &acceptingValidator{}
			if err := buildArchive(t.Context(), buildOptions{tag: "v1.0.0", commit: strings.Repeat("a", 40), architecture: architecture, output: output}, validator, currentSource); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			compressed, err := gzip.NewReader(file)
			if err != nil {
				t.Fatal(err)
			}
			archive := tar.NewReader(compressed)
			header, err := archive.Next()
			if err != nil || header.Name != "sbxr" || header.Mode != 0o755 || header.Uid != 0 || header.Gid != 0 {
				t.Fatalf("archive header = %#v, %v", header, err)
			}
			body, err := io.ReadAll(archive)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Next(); err != io.EOF || validator.calls != 1 {
				t.Fatalf("archive entries or validation = %v, %d", err, validator.calls)
			}
			binary := filepath.Join(t.TempDir(), "sbxr")
			if err := os.WriteFile(binary, body, 0o700); err != nil {
				t.Fatal(err)
			}
			metadata, _, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(body), int64(len(body)))
			if err != nil || metadata.Architecture != architecture || metadata.Build.Tag != "v1.0.0" || metadata.Build.PayloadSHA256 == "" {
				t.Fatalf("metadata = %#v, %v", metadata, err)
			}
			elfFile, err := elf.Open(binary)
			if err != nil {
				t.Fatal(err)
			}
			libraries, importErr := elfFile.ImportedLibraries()
			elfFile.Close()
			build, buildErr := buildinfo.ReadFile(binary)
			if importErr != nil || len(libraries) != 0 || buildErr != nil || build.GoVersion != "go1.26.5" {
				t.Fatalf("runtime proof: libraries=%v import=%v build=%v", libraries, importErr, buildErr)
			}
		})
	}
}

func currentSource(_ context.Context, _, _ string) (string, error) {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), nil
}

func TestVerifiedGitSourceBindsTheCleanExactCommit(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "go.mod")
	runGit(t, root, "-c", "user.name=SBXR", "-c", "user.email=sbxr@example.com", "commit", "-m", "source")
	commit := strings.TrimSpace(runGit(t, root, "rev-parse", "HEAD"))
	destination := filepath.Join(t.TempDir(), "source")
	if got, err := verifiedGitSource(t.Context(), root, commit, destination); err != nil || got != destination {
		t.Fatalf("verified source = %q, %v", got, err)
	}
	if _, err := verifiedGitSource(t.Context(), root, strings.Repeat("a", 40), filepath.Join(t.TempDir(), "wrong")); err == nil {
		t.Fatal("wrong source commit accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedGitSource(t.Context(), root, commit, filepath.Join(t.TempDir(), "dirty")); err == nil {
		t.Fatal("dirty tracked source accepted")
	}
}

func runGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}
