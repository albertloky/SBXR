package architecture_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var transportStagingFiles = []string{
	"qualification.bundle", "sbxr-release", "gateway.crt", "gateway.key", "ca.crt",
	"v3-qualification-transport.sh", "staging-owned", "transport-owned", "unit",
	"deadline", "runtime-deadline", "hosts.before", "hosts.after",
}

var transportStagingAssets = []string{
	"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz",
}

func makeTransportStaging(t *testing.T, withAssets bool) (string, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "stage")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	writeTransportStaging(t, root, "qualification-manifest.json", `{"releases":[{"tag":"v3.1.95"}]}`)
	for _, name := range transportStagingFiles {
		writeTransportStaging(t, root, name, "owned fixture\n")
	}
	if withAssets {
		for _, name := range transportStagingAssets {
			writeTransportStaging(t, root, "assets/v3.1.95/"+name, "owned asset\n")
		}
	}
	writeTransportStaging(t, parent, "unrelated", "preserve outside staging\n")
	return parent, root
}

func writeTransportStaging(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func removeTransportStaging(t *testing.T, root string, extraEnv ...string) ([]byte, error) {
	t.Helper()
	script, err := filepath.Abs(".github/scripts/v3-qualification-transport.sh")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-e", "-c", `source "$1"; root="$2"; remove_staging`, "staging-check", script, root)
	command.Env = append(os.Environ(), extraEnv...)
	return command.CombinedOutput()
}

// Record the real filesystem without following links or printing file contents.
func snapshotTransportStaging(t *testing.T, root string) (map[string]string, map[string]os.FileInfo) {
	t.Helper()
	contents := map[string]string{}
	identities := map[string]os.FileInfo{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		identities[path] = info
		if info.Mode().IsRegular() {
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			contents[path] = string(body)
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(path)
			if readErr != nil {
				return readErr
			}
			contents[path] = target
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return contents, identities
}

func assertTransportStagingUntouched(t *testing.T, root string, contents map[string]string, identities map[string]os.FileInfo) {
	t.Helper()
	afterContents, afterIdentities := snapshotTransportStaging(t, root)
	if !reflect.DeepEqual(contents, afterContents) || len(identities) != len(afterIdentities) {
		t.Fatal("refusal changed staging or unrelated file contents")
	}
	for path, before := range identities {
		after, ok := afterIdentities[path]
		if !ok || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Fatalf("refusal changed file identity/type: %s", path)
		}
	}
}

func TestQualificationTransportStagingRemovesOnlyKnownOwnedTreeAndAllowsPartialRetry(t *testing.T) {
	for _, test := range []struct {
		name       string
		withAssets bool
		partial    bool
	}{
		{name: "complete nested assets", withAssets: true},
		{name: "partially removed known leaves", withAssets: true, partial: true},
		{name: "fixed root files without assets"},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, root := makeTransportStaging(t, test.withAssets)
			if test.partial {
				for _, name := range []string{"gateway.key", "hosts.after", "assets/v3.1.95/install.sh"} {
					if err := os.Remove(filepath.Join(root, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			outside := filepath.Join(parent, "unrelated")
			before, err := os.Stat(outside)
			if err != nil {
				t.Fatal(err)
			}
			if output, err := removeTransportStaging(t, root); err != nil {
				t.Fatalf("owned staging cleanup failed: %v %s", err, output)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("owned staging remains: %v", err)
			}
			after, err := os.Stat(outside)
			body, readErr := os.ReadFile(outside)
			if err != nil || readErr != nil || !os.SameFile(before, after) || string(body) != "preserve outside staging\n" {
				t.Fatal("cleanup changed an unrelated outside file")
			}
		})
	}
}

func TestQualificationTransportStagingRefusesUnsafeTreeBeforeDeletingAnything(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string, string)
	}{
		{name: "unknown root file", prepare: func(t *testing.T, _, root string) {
			writeTransportStaging(t, root, "unknown", "preserve unknown\n")
		}},
		{name: "unknown nested asset", prepare: func(t *testing.T, _, root string) {
			writeTransportStaging(t, root, "assets/v3.1.95/unknown", "preserve unknown\n")
		}},
		{name: "undeclared release directory", prepare: func(t *testing.T, _, root string) {
			writeTransportStaging(t, root, "assets/v3.1.96/install.sh", "not this manifest\n")
		}},
		{name: "unknown empty directory", prepare: func(t *testing.T, _, root string) {
			if err := os.Mkdir(filepath.Join(root, "unknown"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group writable staging directory", prepare: func(t *testing.T, _, root string) {
			if err := os.Chmod(root, 0770); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group writable asset directory", prepare: func(t *testing.T, _, root string) {
			if err := os.Chmod(filepath.Join(root, "assets", "v3.1.95"), 0770); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "fixed file changed to directory", prepare: func(t *testing.T, _, root string) {
			path := filepath.Join(root, "gateway.key")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "root symlink", prepare: func(t *testing.T, parent, root string) {
			if err := os.Rename(root, filepath.Join(parent, "real-stage")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(parent, "real-stage"), root); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "asset directory symlink", prepare: func(t *testing.T, parent, root string) {
			path := filepath.Join(root, "assets", "v3.1.95")
			if err := os.Rename(path, filepath.Join(parent, "real-assets")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(parent, "real-assets"), path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "leaf symlink", prepare: replaceTransportStagingLeafWithLink(false, "gateway.key")},
		{name: "dangling leaf symlink", prepare: func(t *testing.T, parent, root string) {
			path := filepath.Join(root, "gateway.key")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(parent, "missing"), path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "leaf hardlink", prepare: replaceTransportStagingLeafWithLink(true, "gateway.key")},
		{name: "asset hardlink", prepare: replaceTransportStagingLeafWithLink(true, "assets/v3.1.95/install.sh")},
		{name: "manifest hardlink", prepare: func(t *testing.T, parent, root string) {
			if err := os.Link(filepath.Join(root, "qualification-manifest.json"), filepath.Join(parent, "manifest-alias")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, root := makeTransportStaging(t, true)
			test.prepare(t, parent, root)
			contents, identities := snapshotTransportStaging(t, parent)
			if output, err := removeTransportStaging(t, root); err == nil {
				t.Fatalf("unsafe staging accepted: %s", output)
			}
			assertTransportStagingUntouched(t, parent, contents, identities)
		})
	}
}

func TestQualificationTransportStagingInterruptedUnlinkPreservesAuthorityAndFreshRetryCompletes(t *testing.T) {
	parent, root := makeTransportStaging(t, true)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(parent, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	// The fixture interpreter executes the unchanged cleanup source. Its second
	// real unlink fails once, after the first leaf was actually removed.
	shim := "#!" + python + "\n" + `import os, pathlib, sys
source = sys.stdin.read()
root = pathlib.Path(sys.argv[2])
record = pathlib.Path(os.environ["SBXR_STAGING_INJECTION"])
original_unlink = pathlib.Path.unlink
calls = 0
def interrupted_unlink(path, *args, **kwargs):
    global calls
    calls += 1
    if calls == 2:
        record.write_text(str(path.relative_to(root)))
        raise OSError("fixture-interrupted-unlink")
    result = original_unlink(path, *args, **kwargs)
    with record.with_suffix(".removed").open("a") as stream:
        stream.write(str(path.relative_to(root)) + "\n")
    return result
pathlib.Path.unlink = interrupted_unlink
sys.argv = sys.argv[1:]
exec(compile(source, "<transport-staging-cleanup>", "exec"))
`
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	authority := map[string]os.FileInfo{}
	authorityContents := map[string]string{}
	for _, name := range []string{"qualification-manifest.json", "transport-owned"} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		authority[name] = info
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		authorityContents[name] = string(body)
	}
	marker := filepath.Join(parent, "injection")
	output, err := removeTransportStaging(t, root, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "SBXR_STAGING_INJECTION="+marker)
	if err == nil || !strings.Contains(string(output), "fixture-interrupted-unlink") {
		t.Fatalf("expected real interrupted unlink: %v %s", err, output)
	}
	removed, err := os.ReadFile(marker + ".removed")
	if err != nil || len(strings.Fields(string(removed))) != 1 {
		t.Fatal("injection did not occur after exactly one real leaf deletion")
	}
	if _, err := os.Lstat(filepath.Join(root, strings.TrimSpace(string(removed)))); !os.IsNotExist(err) {
		t.Fatal("first real unlink did not remove its staged leaf")
	}
	for name, before := range authority {
		after, err := os.Lstat(filepath.Join(root, name))
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("interrupted cleanup removed retry authority: %s", name)
		}
		if body, err := os.ReadFile(filepath.Join(root, name)); err != nil || string(body) != authorityContents[name] {
			t.Fatalf("interrupted cleanup altered retry authority: %s", name)
		}
	}
	if output, err := removeTransportStaging(t, root); err != nil {
		t.Fatalf("fresh retry did not finish remaining real cleanup: %v %s", err, output)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("staging remains after retry: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(parent, "unrelated")); err != nil || string(body) != "preserve outside staging\n" {
		t.Fatal("interruption/retry changed unrelated outside file")
	}
}

func replaceTransportStagingLeafWithLink(hard bool, name string) func(*testing.T, string, string) {
	return func(t *testing.T, parent, root string) {
		t.Helper()
		path, outside := filepath.Join(root, name), filepath.Join(parent, "unrelated")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		link := os.Symlink
		if hard {
			link = os.Link
		}
		if err := link(outside, path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestQualificationTransportStagingRefusesInvalidManifestBeforeDeletingAnything(t *testing.T) {
	for name, manifest := range map[string]string{
		"invalid JSON":        "not JSON",
		"missing releases":    `{}`,
		"wrong releases type": `{"releases":{}}`,
		"missing tag":         `{"releases":[{}]}`,
		"wrong tag type":      `{"releases":[{"tag":95}]}`,
		"path traversal":      `{"releases":[{"tag":"../outside"}]}`,
		"noncanonical tag":    `{"releases":[{"tag":"v03.1.95"}]}`,
		"duplicate tag":       `{"releases":[{"tag":"v3.1.95"},{"tag":"v3.1.95"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			parent, root := makeTransportStaging(t, true)
			writeTransportStaging(t, root, "qualification-manifest.json", manifest)
			contents, identities := snapshotTransportStaging(t, parent)
			if output, err := removeTransportStaging(t, root); err == nil {
				t.Fatalf("invalid staging manifest accepted: %s", output)
			}
			assertTransportStagingUntouched(t, parent, contents, identities)
		})
	}
}
