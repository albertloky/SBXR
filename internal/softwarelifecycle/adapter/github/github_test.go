package github_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	githubadapter "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/github"
)

func TestSourceUsesExactGitHubReleaseAndPerAssetVerificationContracts(t *testing.T) {
	const tag = "v1.0.0"
	assets := releaseAssets()
	commands := [][]string{}
	runner := func(_ context.Context, name string, arguments []string, limit int64) ([]byte, error) {
		commands = append(commands, append([]string{name}, arguments...))
		if output, ok := distributionOutput(name, arguments); ok {
			return []byte(output), nil
		}
		switch {
		case reflect.DeepEqual(arguments, []string{"release", "verify", tag, "--repo", softwarelifecycle.Repository, "--format", "json"}):
			return releaseVerificationJSON(t, tag, assets), nil
		case len(arguments) == 10 && reflect.DeepEqual(arguments[:6], []string{"release", "download", tag, "--repo", softwarelifecycle.Repository, "--pattern"}) && reflect.DeepEqual(arguments[7:], []string{"--output", "-", "--allow-escape-sequences"}):
			body := assets[arguments[6]]
			if int64(len(body)) > limit {
				return nil, errors.New("bounded")
			}
			return body, nil
		case len(arguments) == 4 && arguments[0] == "release" && arguments[1] == "verify-asset" && arguments[2] == tag:
			return []byte(`{"verified":true}`), nil
		default:
			return nil, fmt.Errorf("unexpected command: %s %v", name, arguments)
		}
	}
	source := githubadapter.NewWithRunner(runner)

	got, err := source.Verify(t.Context(), tag)
	if err != nil {
		t.Fatal(err)
	}
	if got.Repository != softwarelifecycle.Repository || got.Tag != tag || got.Commit != "0123456789abcdef0123456789abcdef01234567" || len(got.Assets) != 4 || len(got.AttestedAssets) != 5 || !got.Verifier.ReleaseVerified || !got.Verifier.OfficialSignedDistribution || got.Verifier.SigningFingerprint != githubadapter.SigningFingerprint {
		t.Fatalf("Verify() = %#v", got)
	}
	if len(commands) != 19 || !reflect.DeepEqual(commands[8], []string{"/usr/bin/gh", "release", "verify", tag, "--repo", softwarelifecycle.Repository, "--format", "json"}) {
		t.Fatalf("commands = %#v", commands)
	}
	verified := []string{}
	for _, command := range commands[9:] {
		if len(command) == 11 && command[1] == "release" && command[2] == "download" {
			verified = append(verified, command[7])
			continue
		}
		if len(command) != 5 || command[0] != "/usr/bin/gh" || command[1] != "release" || command[2] != "verify-asset" || command[3] != tag {
			t.Fatalf("asset command = %#v", command)
		}
		if filepath.Base(command[4]) == "" {
			t.Fatalf("empty verified path")
		}
	}
	sort.Strings(verified)
	if !reflect.DeepEqual(verified, []string{"release-index.json", "sbxr-components-linux-amd64.tar.gz", "sbxr-components-linux-arm64.tar.gz", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"}) {
		t.Fatalf("bounded downloads = %v", verified)
	}
}

func TestSourceDiscoversOnlyTheRequestedGitHubReleaseChannel(t *testing.T) {
	tests := []struct {
		name, reviewedTag string
		wantArguments     []string
		output            string
		want              softwarelifecycle.ReleaseListing
	}{
		{name: "stable default", wantArguments: []string{"release", "view", "--repo", softwarelifecycle.Repository, "--json", "tagName,isDraft,isPrerelease"}, output: `{"tagName":"v1.1.0","isDraft":false,"isPrerelease":false}`, want: softwarelifecycle.ReleaseListing{Tag: "v1.1.0"}},
		{name: "reviewed alternate", reviewedTag: "v1.2.0-rc.1", wantArguments: []string{"release", "view", "v1.2.0-rc.1", "--repo", softwarelifecycle.Repository, "--json", "tagName,isDraft,isPrerelease"}, output: `{"tagName":"v1.2.0-rc.1","isDraft":false,"isPrerelease":true}`, want: softwarelifecycle.ReleaseListing{Tag: "v1.2.0-rc.1", Prerelease: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotName string
			var gotArguments []string
			source := githubadapter.NewWithRunner(func(_ context.Context, name string, arguments []string, _ int64) ([]byte, error) {
				gotName, gotArguments = name, append([]string(nil), arguments...)
				return []byte(test.output), nil
			})

			got, err := source.Discover(t.Context(), test.reviewedTag)
			if err != nil || !reflect.DeepEqual(got, test.want) || gotName != "/usr/bin/gh" || !reflect.DeepEqual(gotArguments, test.wantArguments) {
				t.Fatalf("Discover() = %#v, %v; command=%s %v", got, err, gotName, gotArguments)
			}
		})
	}
}

func TestSourceDiscoveryFailsClosedOnAmbiguousOrUnsafeOutput(t *testing.T) {
	for _, output := range []string{
		`{"tagName":"v1.1.0","tagName":"v1.2.0","isDraft":false,"isPrerelease":false}`,
		`{"tagName":"../latest","isDraft":false,"isPrerelease":false}`,
		`{"tagName":"v1.1.0","isDraft":false,"isPrerelease":false,"extra":true}`,
		`{"tagName":"v1.1.0","isDraft":false,"isPrerelease":false} {}`,
	} {
		source := githubadapter.NewWithRunner(func(context.Context, string, []string, int64) ([]byte, error) { return []byte(output), nil })
		if got, err := source.Discover(t.Context(), ""); err == nil || got.Tag != "" {
			t.Fatalf("Discover(%q) = %#v, %v", output, got, err)
		}
	}
}

func TestSourceFailsClosedOnDistributionVerifierDownloadAssetOrAttestationFailure(t *testing.T) {
	const secretMarker = "PRIVATE-MARKER-E5932C"
	tests := []struct {
		name string
		run  githubadapter.CommandRunner
	}{
		{"wrong executable version", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, arguments []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/gh" && reflect.DeepEqual(arguments, []string{"--version"}) {
				return []byte("gh version 2.96.0 (wrong)\n"), nil
			}
			return nil, nil
		})},
		{"wrong installed package version", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, _ []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/dpkg-query" {
				return []byte("2.96.0\n"), nil
			}
			return nil, nil
		})},
		{"wrong APT origin", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, _ []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/apt-cache" {
				return []byte("Installed: 2.97.0\n https://archive.ubuntu.com community\n"), nil
			}
			return nil, nil
		})},
		{"changed installed package", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, _ []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/dpkg" {
				return []byte("??5?????? /usr/bin/gh\n"), nil
			}
			return nil, nil
		})},
		{"unsigned distribution", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, arguments []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/gpg" {
				return []byte("fpr:::::::::ATTACKER:"), nil
			}
			return nil, nil
		})},
		{"wrong signed-by source", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, _ []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/cat" {
				return []byte("deb https://cli.github.com/packages stable main\n"), nil
			}
			return nil, nil
		})},
		{"wrong installed binary", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(name string, _ []string, _ int64) ([]byte, error) {
			if name == "/usr/bin/sha256sum" {
				return []byte(strings.Repeat("a", 64) + "  /usr/bin/gh\n"), nil
			}
			return nil, nil
		})},
		{"release verifier failure", fixtureRunner(t, nil, func(_ string, arguments []string, _ int64) ([]byte, error) {
			if len(arguments) > 1 && arguments[1] == "verify" {
				return nil, fmt.Errorf("raw %s", secretMarker)
			}
			return nil, nil
		})},
		{"malformed verifier output", fixtureRunner(t, []byte(`{"attestation":{}}`), nil)},
		{"wrong attested repository", fixtureRunner(t, releaseVerificationJSONFor(t, "attacker/SBXR", "v1.0.0", releaseAssets()), nil)},
		{"wrong attested tag", fixtureRunner(t, releaseVerificationJSONFor(t, softwarelifecycle.Repository, "v1.0.1", releaseAssets()), nil)},
		{"bounded download failure", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(_ string, arguments []string, limit int64) ([]byte, error) {
			if len(arguments) > 1 && arguments[1] == "download" {
				return make([]byte, limit+1), nil
			}
			return nil, nil
		})},
		{"asset verification failure", fixtureRunner(t, releaseVerificationJSON(t, "v1.0.0", releaseAssets()), func(_ string, arguments []string, _ int64) ([]byte, error) {
			if len(arguments) > 1 && arguments[1] == "verify-asset" {
				return nil, fmt.Errorf("raw asset failure %s", secretMarker)
			}
			return nil, nil
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := githubadapter.NewWithRunner(test.run)
			got, err := source.Verify(t.Context(), "v1.0.0")
			if err == nil || got.Repository != "" || strings.Contains(err.Error(), secretMarker) {
				t.Fatalf("Verify() = %#v, %v", got, err)
			}
		})
	}
}

func distributionOutput(name string, arguments []string) (string, bool) {
	switch name {
	case "/usr/bin/gh":
		if reflect.DeepEqual(arguments, []string{"--version"}) {
			return "gh version 2.97.0 (2026-07-31)\n", true
		}
	case "/usr/bin/dpkg-query":
		return "2.97.0\n", true
	case "/usr/bin/apt-cache":
		return "Installed: 2.97.0\n *** 2.97.0 500\n https://cli.github.com/packages stable/main amd64 Packages\n", true
	case "/usr/bin/dpkg":
		if reflect.DeepEqual(arguments, []string{"--print-architecture"}) {
			return "amd64\n", true
		}
		return "", true
	case "/usr/bin/gpg":
		return "fpr:::::::::" + githubadapter.SigningFingerprint + ":\n", true
	case "/usr/bin/cat":
		return "deb [arch=amd64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n", true
	case "/usr/bin/sha256sum":
		return "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409  /usr/bin/gh\n", true
	}
	return "", false
}

type failure func(string, []string, int64) ([]byte, error)

func fixtureRunner(t *testing.T, releaseOutput []byte, fail failure) githubadapter.CommandRunner {
	t.Helper()
	assets := releaseAssets()
	return func(_ context.Context, name string, arguments []string, limit int64) ([]byte, error) {
		if fail != nil {
			if output, err := fail(name, arguments, limit); output != nil || err != nil {
				return output, err
			}
		}
		if output, ok := distributionOutput(name, arguments); ok {
			return []byte(output), nil
		}
		switch {
		case len(arguments) > 1 && arguments[1] == "verify":
			return releaseOutput, nil
		case len(arguments) > 1 && arguments[1] == "download":
			return assets[arguments[6]], nil
		case len(arguments) > 1 && arguments[1] == "verify-asset":
			return []byte("verified"), nil
		default:
			return nil, fmt.Errorf("unexpected command")
		}
	}
}

func releaseAssets() map[string][]byte {
	amd64 := executableArchive("verified amd64 executable")
	arm64 := executableArchive("verified arm64 executable")
	amd64Components := githubComponentArchive(softwarelifecycle.AMD64)
	arm64Components := githubComponentArchive(softwarelifecycle.ARM64)
	amd64Digest := sha256.Sum256(amd64)
	arm64Digest := sha256.Sum256(arm64)
	amd64ComponentsDigest := sha256.Sum256(amd64Components)
	arm64ComponentsDigest := sha256.Sum256(arm64Components)
	index := []byte(fmt.Sprintf(`{"schema":1,"product":"sbxr","repository":"albertloky/SBXR","version":"1.0.0","sequence":1,"tag":"v1.0.0","commit":"0123456789abcdef0123456789abcdef01234567","state_schema":1,"minimum_updater_schema":1,"assets":[{"role":"application-linux-amd64","name":"sbxr-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"role":"application-linux-arm64","name":"sbxr-linux-arm64.tar.gz","size":%d,"sha256":"%s"},{"role":"components-linux-amd64","name":"sbxr-components-linux-amd64.tar.gz","size":%d,"sha256":"%s"},{"role":"components-linux-arm64","name":"sbxr-components-linux-arm64.tar.gz","size":%d,"sha256":"%s"}]}`, len(amd64), hex.EncodeToString(amd64Digest[:]), len(arm64), hex.EncodeToString(arm64Digest[:]), len(amd64Components), hex.EncodeToString(amd64ComponentsDigest[:]), len(arm64Components), hex.EncodeToString(arm64ComponentsDigest[:])))
	return map[string][]byte{"release-index.json": index, "sbxr-linux-amd64.tar.gz": amd64, "sbxr-linux-arm64.tar.gz": arm64, "sbxr-components-linux-amd64.tar.gz": amd64Components, "sbxr-components-linux-arm64.tar.gz": arm64Components}
}

func githubComponentArchive(architecture softwarelifecycle.Architecture) []byte {
	files := map[string][]byte{
		"xray": []byte("qualified xray"), "sing-box": []byte("qualified sing-box"), "cloudflared": []byte("qualified cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	manifest, _ := softwarelifecycle.NewComponentManifest(architecture, "5.4.0", files)
	archive, _ := softwarelifecycle.BuildComponentArchive(manifest, files)
	return archive
}

func releaseVerificationJSON(t *testing.T, tag string, assets map[string][]byte) []byte {
	t.Helper()
	return releaseVerificationJSONFor(t, softwarelifecycle.Repository, tag, assets)
}

func releaseVerificationJSONFor(t *testing.T, repository, tag string, assets map[string][]byte) []byte {
	t.Helper()
	type subject struct {
		Name, URI string
		Digest    map[string]string
	}
	subjects := []subject{{URI: "pkg:github/" + repository + "@" + tag, Digest: map[string]string{"sha1": "0123456789abcdef0123456789abcdef01234567"}}}
	names := make([]string, 0, len(assets))
	for name := range assets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		digest := sha256.Sum256(assets[name])
		subjects = append(subjects, subject{Name: name, Digest: map[string]string{"sha256": hex.EncodeToString(digest[:])}})
	}
	payload, err := json.Marshal(map[string]any{"subject": subjects, "predicate": map[string]string{"repository": repository, "tag": tag}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := json.Marshal(map[string]any{"attestation": map[string]any{"bundle": map[string]any{"dsseEnvelope": map[string]any{"payload": base64.StdEncoding.EncodeToString(payload)}}}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func executableArchive(executable string) []byte {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(executable)), Typeflag: tar.TypeReg}); err != nil {
		panic(err)
	}
	if _, err := archive.Write([]byte(executable)); err != nil {
		panic(err)
	}
	if err := archive.Close(); err != nil {
		panic(err)
	}
	if err := compressed.Close(); err != nil {
		panic(err)
	}
	return output.Bytes()
}
