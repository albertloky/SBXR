package architecture_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/albertloky/SBXR"

func TestInstallerUpdaterIsTheOnlyProduct(t *testing.T) {
	assertDirectories(t, "cmd", []string{"sbxr", "sbxr-release"})
	assertDirectories(t, "internal", []string{"softwarelifecycle"})
}

func TestExternalDependenciesStayInTheGitHubAdapter(t *testing.T) {
	command := exec.Command("go", "list", "-json", "./...")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for decoder.More() {
		var current struct {
			ImportPath string
			Imports    []string
		}
		if err := decoder.Decode(&current); err != nil {
			t.Fatal(err)
		}
		for _, imported := range current.Imports {
			if strings.Contains(imported, ".") && !strings.HasPrefix(imported, modulePath) && current.ImportPath != modulePath+"/internal/softwarelifecycle/adapter/github" {
				t.Fatalf("%s imports external dependency %s", current.ImportPath, imported)
			}
		}
	}
}

func assertDirectories(t *testing.T, root string, want []string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		if entry.IsDir() {
			got = append(got, entry.Name())
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s product directories = %v, want %v", root, got, want)
	}
}
