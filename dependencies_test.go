package architecture_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/albertloky/SBXR"

var registeredModules = map[string]bool{
	"ownerconsole":            true,
	"connectionprofiles":      true,
	"subscriptionpublication": true,
	"subscriptionserving":     true,
	"certificatelifecycle":    true,
	"cloudflaretunnel":        true,
	"softwarelifecycle":       true,
	"healthdiagnostics":       true,
	"networkpolicy":           true,
	"state":                   true,
	"systemchanges":           true,
}

// Exact cross-Module connections remain empty until an approved design ticket
// registers one. Foundational Modules never gain upward entries here.
var approvedModuleDependencies = map[string]map[string]bool{
	"cloudflaretunnel": {"networkpolicy": true},
}

var forbiddenStandardLibrary = map[string]bool{
	"database/sql": true,
	"plugin":       true,
}

type packageInfo struct {
	ImportPath string
	Imports    []string
	Standard   bool
}

func TestRepositoryDependencies(t *testing.T) {
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-deps", "-json", "./...")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var packages []packageInfo
	for decoder.More() {
		var current packageInfo
		if err := decoder.Decode(&current); err != nil {
			t.Fatal(err)
		}
		if !current.Standard && current.ImportPath != modulePath && !strings.HasPrefix(current.ImportPath, modulePath+"/") {
			t.Fatalf("unapproved production dependency %q; SBXR is standard-library-first", current.ImportPath)
		}
		if strings.HasPrefix(current.ImportPath, modulePath+"/") {
			packages = append(packages, current)
		}
	}
	if err := validatePackages(packages); err != nil {
		t.Fatal(err)
	}
}

func TestModuleRegistry(t *testing.T) {
	want := "certificatelifecycle,cloudflaretunnel,connectionprofiles,healthdiagnostics,networkpolicy,ownerconsole,softwarelifecycle,state,subscriptionpublication,subscriptionserving,systemchanges"
	got := make([]string, 0, len(registeredModules))
	for module := range registeredModules {
		got = append(got, module)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != want {
		t.Fatalf("Module registry = %s, want exactly %s", strings.Join(got, ","), want)
	}
}

func TestArchitecturePolicyRejectsForbiddenShapes(t *testing.T) {
	tests := []struct {
		name     string
		packages []packageInfo
		want     string
	}{
		{name: "unregistered Module", packages: []packageInfo{{ImportPath: modulePath + "/internal/backup"}}, want: "unregistered product package"},
		{name: "generic dumping ground", packages: []packageInfo{{ImportPath: modulePath + "/internal/utils"}}, want: "generic package"},
		{name: "shallow types package", packages: []packageInfo{{ImportPath: modulePath + "/internal/state/types"}}, want: "shallow package"},
		{name: "unapproved Module import", packages: []packageInfo{{ImportPath: modulePath + "/internal/state", Imports: []string{modulePath + "/internal/ownerconsole"}}, {ImportPath: modulePath + "/internal/ownerconsole"}}, want: "unapproved Module dependency"},
		{name: "Subscription Serving reads State", packages: []packageInfo{{ImportPath: modulePath + "/internal/subscriptionserving", Imports: []string{modulePath + "/internal/state"}}, {ImportPath: modulePath + "/internal/state"}}, want: "unapproved Module dependency"},
		{name: "production fixture import", packages: []packageInfo{{ImportPath: modulePath + "/internal/state", Imports: []string{modulePath + "/internal/state/fixtures"}}}, want: "production-only material"},
		{name: "database", packages: []packageInfo{{ImportPath: modulePath + "/internal/state", Imports: []string{"database/sql"}}}, want: "forbidden standard-library capability"},
		{name: "plugins", packages: []packageInfo{{ImportPath: modulePath + "/internal/state", Imports: []string{"plugin"}}}, want: "forbidden standard-library capability"},
		{name: "cycle", packages: []packageInfo{{ImportPath: modulePath + "/internal/state", Imports: []string{modulePath + "/internal/state/adapter/filesystem"}}, {ImportPath: modulePath + "/internal/state/adapter/filesystem", Imports: []string{modulePath + "/internal/state"}}}, want: "cycle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePackages(tt.packages); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validatePackages() = %v, want %q rejection", err, tt.want)
			}
		})
	}
}

func TestStateStorageConstructionBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStateConstruction(root); err != nil {
		t.Fatal(err)
	}

	t.Run("rejects a second production persistence path", func(t *testing.T) {
		directory := t.TempDir()
		mustWriteArchitectureFile(t, directory, "internal/systemchanges/unsafe.go", `package systemchanges
import "github.com/albertloky/SBXR/internal/state"
func unsafe(storage state.Storage) state.Interface { return state.New(storage) }
`)
		if err := validateStateConstruction(directory); err == nil || !strings.Contains(err.Error(), "only the State filesystem Adapter") {
			t.Fatalf("validateStateConstruction() = %v, want second persistence path rejection", err)
		}
	})
}

func TestInfrastructureSecretConsumptionBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInfrastructureSecretConsumption(root); err != nil {
		t.Fatal(err)
	}

	t.Run("rejects direct secret consumption outside State", func(t *testing.T) {
		directory := t.TempDir()
		mustWriteArchitectureFile(t, directory, "internal/ownerconsole/unsafe.go", `package ownerconsole
func unsafe(source interface{ ConsumeInfrastructureSecret() (string, bool) }) string {
	value, _ := source.ConsumeInfrastructureSecret()
	return value
}
`)
		if err := validateInfrastructureSecretConsumption(directory); err == nil || !strings.Contains(err.Error(), "only State") {
			t.Fatalf("validateInfrastructureSecretConsumption() = %v, want direct consumption rejection", err)
		}
	})
}

func validateInfrastructureSecretConsumption(root string) error {
	return walkProductionGoFiles(root, func(relative string, source *ast.File) error {
		if strings.HasPrefix(filepath.ToSlash(relative), "internal/state/") {
			return nil
		}
		var consumes bool
		ast.Inspect(source, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			consumes = consumes || ok && selector.Sel.Name == "ConsumeInfrastructureSecret"
			return true
		})
		if consumes {
			return fmt.Errorf("only State may consume a verified Infrastructure Secret: %s", relative)
		}
		return nil
	})
}

func validateStateConstruction(root string) error {
	return walkProductionGoFiles(root, func(relative string, source *ast.File) error {
		stateAlias := ""
		for _, imported := range source.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || importPath != modulePath+"/internal/state" {
				continue
			}
			stateAlias = "state"
			if imported.Name != nil {
				stateAlias = imported.Name.Name
			}
		}
		if stateAlias == "" || stateAlias == "_" {
			return nil
		}
		allowed := strings.HasPrefix(filepath.ToSlash(relative), "internal/state/adapter/filesystem/")
		if stateAlias == "." && !allowed {
			return fmt.Errorf("only the State filesystem Adapter may import State with constructor access: %s", relative)
		}
		var constructs bool
		ast.Inspect(source, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "New" {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			constructs = constructs || ok && identifier.Name == stateAlias
			return true
		})
		if constructs && !allowed {
			return fmt.Errorf("only the State filesystem Adapter may construct State from raw storage: %s", relative)
		}
		return nil
	})
}

func walkProductionGoFiles(root string, visit func(string, *ast.File) error) error {
	return filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(filePath) != ".go" || strings.HasSuffix(filePath, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		source, err := parser.ParseFile(token.NewFileSet(), filePath, nil, 0)
		if err != nil {
			return err
		}
		return visit(relative, source)
	})
}

func mustWriteArchitectureFile(t *testing.T, root, name, content string) {
	t.Helper()
	filePath := filepath.Join(root, filepath.FromSlash(path.Clean(name)))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func validatePackages(packages []packageInfo) error {
	byPath := make(map[string]packageInfo, len(packages))
	for _, current := range packages {
		byPath[current.ImportPath] = current
		parts := strings.Split(strings.TrimPrefix(current.ImportPath, modulePath+"/"), "/")
		if genericPart(parts) != "" {
			return fmt.Errorf("generic package %q is forbidden", current.ImportPath)
		}
		if len(parts) == 0 || parts[0] != "internal" {
			if current.ImportPath != modulePath+"/cmd/sbxr" {
				return fmt.Errorf("unregistered product package %q", current.ImportPath)
			}
			continue
		}
		if len(parts) < 2 || !registeredModules[parts[1]] {
			return fmt.Errorf("unregistered product package %q", current.ImportPath)
		}
		if len(parts) > 2 && (len(parts) != 4 || parts[2] != "adapter") {
			return fmt.Errorf("shallow package %q; keep implementation with its Module", current.ImportPath)
		}
	}

	for _, current := range packages {
		from := owningModule(current.ImportPath)
		for _, imported := range current.Imports {
			if forbiddenStandardLibrary[imported] {
				return fmt.Errorf("forbidden standard-library capability %s -> %s", current.ImportPath, imported)
			}
			if strings.Contains(imported, "/fixtures") || strings.Contains(imported, "/testdata") || strings.Contains(imported, "/evidence") || strings.Contains(imported, "/acceptance") {
				return fmt.Errorf("production-only material cannot import tests, fixtures, evidence, or acceptance tooling: %s -> %s", current.ImportPath, imported)
			}
			to := owningModule(imported)
			if from != "" && to != "" && from != to && (!permittedDirection(from, to) || !approvedModuleDependencies[from][to]) {
				return fmt.Errorf("unapproved Module dependency %s -> %s", from, to)
			}
		}
	}
	return rejectCycles(byPath)
}

func permittedDirection(from, to string) bool {
	if from == "networkpolicy" || from == "state" || from == "systemchanges" || from == "subscriptionserving" {
		return false
	}
	return to != "ownerconsole"
}

func owningModule(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, modulePath+"/"), "/")
	if len(parts) >= 2 && parts[0] == "internal" && registeredModules[parts[1]] {
		return parts[1]
	}
	return ""
}

func genericPart(parts []string) string {
	forbidden := map[string]bool{"common": true, "shared": true, "helpers": true, "utils": true, "services": true, "models": true, "platform": true}
	for _, part := range parts {
		if forbidden[part] {
			return part
		}
	}
	return ""
}

func rejectCycles(packages map[string]packageInfo) error {
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var visit func(string) error
	visit = func(path string) error {
		if visiting[path] {
			return fmt.Errorf("production dependency cycle includes %s", path)
		}
		if visited[path] {
			return nil
		}
		visiting[path] = true
		imports := append([]string(nil), packages[path].Imports...)
		sort.Strings(imports)
		for _, imported := range imports {
			if _, exists := packages[imported]; exists {
				if err := visit(imported); err != nil {
					return err
				}
			}
		}
		visiting[path] = false
		visited[path] = true
		return nil
	}
	paths := make([]string, 0, len(packages))
	for path := range packages {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if err := visit(path); err != nil {
			return err
		}
	}
	return nil
}
