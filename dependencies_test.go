package architecture_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const modulePath = "github.com/albertloky/SBXR"

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
