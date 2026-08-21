package architecture_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
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
	"cloudflareprofilesetup":  true,
	"softwarelifecycle":       true,
	"healthdiagnostics":       true,
	"installation":            true,
	"networkpolicy":           true,
	"state":                   true,
	"systemchanges":           true,
}

// Exact cross-Module connections are registered only by approved design tickets.
// Foundational Modules never gain upward entries here.
var approvedModuleDependencies = map[string]map[string]bool{
	"certificatelifecycle":    {"softwarelifecycle": true, "systemchanges": true},
	"cloudflaretunnel":        {"networkpolicy": true, "softwarelifecycle": true, "systemchanges": true},
	"cloudflareprofilesetup":  {"certificatelifecycle": true, "cloudflaretunnel": true, "connectionprofiles": true, "networkpolicy": true, "state": true, "subscriptionpublication": true, "systemchanges": true},
	"connectionprofiles":      {"cloudflaretunnel": true, "softwarelifecycle": true, "state": true, "systemchanges": true},
	"healthdiagnostics":       {"systemchanges": true},
	"installation":            {"certificatelifecycle": true, "connectionprofiles": true, "healthdiagnostics": true, "networkpolicy": true, "softwarelifecycle": true, "state": true, "subscriptionpublication": true, "systemchanges": true},
	"softwarelifecycle":       {"networkpolicy": true, "systemchanges": true},
	"subscriptionpublication": {"connectionprofiles": true, "softwarelifecycle": true, "state": true, "systemchanges": true},
}

var forbiddenStandardLibrary = map[string]bool{
	"database/sql": true,
	"plugin":       true,
}

var approvedExternalImports = map[string]bool{
	"charm.land/bubbletea/v2":        true,
	"charm.land/lipgloss/v2":         true,
	"github.com/yeqown/go-qrcode/v2": true,
}

var approvedSoftwareLifecycleExternalImports = map[string]bool{
	"github.com/klauspost/compress/snappy":       true,
	"github.com/sigstore/sigstore-go/pkg/bundle": true,
	"github.com/sigstore/sigstore-go/pkg/root":   true,
	"github.com/sigstore/sigstore-go/pkg/verify": true,
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
		if strings.HasPrefix(current.ImportPath, modulePath+"/") {
			packages = append(packages, current)
		}
	}
	if err := validatePackages(packages); err != nil {
		t.Fatal(err)
	}
}

func TestModuleRegistry(t *testing.T) {
	want := "certificatelifecycle,cloudflareprofilesetup,cloudflaretunnel,connectionprofiles,healthdiagnostics,installation,networkpolicy,ownerconsole,softwarelifecycle,state,subscriptionpublication,subscriptionserving,systemchanges"
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
		{name: "unapproved external dependency", packages: []packageInfo{{ImportPath: modulePath + "/internal/ownerconsole", Imports: []string{"example.com/ui"}}}, want: "unapproved production dependency"},
		{name: "UI dependency outside Owner Console", packages: []packageInfo{{ImportPath: modulePath + "/internal/state", Imports: []string{"charm.land/bubbletea/v2"}}}, want: "unapproved production dependency"},
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

func TestSubscriptionServingMutationBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSubscriptionServingMutation(root); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, source string
	}{
		{"aliased file write", `package subscriptionserving
import host "os"
func unsafe() { _ = host.WriteFile("/tmp/unsafe", nil, 0o600) }
`},
		{"writable file", `package subscriptionserving
import "os"
func unsafe() { _, _ = os.OpenFile("/tmp/unsafe", os.O_WRONLY, 0o600) }
`},
		{"file write", `package subscriptionserving
import "os"
func unsafe() { file, _ := os.Open("/tmp/unsafe"); _, _ = file.Write(nil) }
`},
		{"root file write", `package subscriptionserving
import "os"
func unsafe() { root, _ := os.OpenRoot("/tmp"); file, _ := root.Open("unsafe"); _, _ = file.Write(nil) }
`},
		{"root writable file", `package subscriptionserving
import "os"
func unsafe() { root, _ := os.OpenRoot("/tmp"); _, _ = root.OpenFile("unsafe", os.O_WRONLY|os.O_CREATE, 0o600) }
`},
		{"root direct write", `package subscriptionserving
import "os"
func unsafe() { root, _ := os.OpenRoot("/tmp"); _ = root.WriteFile("unsafe", nil, 0o600) }
`},
		{"copied root write", `package subscriptionserving
import "os"
func unsafe(root *os.Root) { other := root; _ = other.WriteFile("unsafe", nil, 0o600) }
`},
		{"stored root write", `package subscriptionserving
import "os"
type holder struct { root *os.Root }
func unsafe(value holder) { _ = value.root.WriteFile("unsafe", nil, 0o600) }
`},
		{"arbitrary command", `package subscriptionserving
import "os/exec"
func unsafe() { _ = exec.Command("unsafe") }
`},
		{"raw syscall", `package subscriptionserving
import "syscall"
func unsafe() { _ = syscall.Unlink("/tmp/unsafe") }
`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			mustWriteArchitectureFile(t, directory, "internal/subscriptionserving/unsafe.go", test.source)
			if err := validateSubscriptionServingMutation(directory); err == nil || !strings.Contains(err.Error(), "read-only") {
				t.Fatalf("validateSubscriptionServingMutation() = %v, want read-only rejection", err)
			}
		})
	}
}

func TestCloudflareProfileSetupCompositionBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCloudflareProfileSetupComposition(root); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct{ name, source string }{
		{"host mutation", `package cloudflareprofilesetup
import "os"
func unsafe() { _ = os.WriteFile("/tmp/unsafe", nil, 0o600) }
`},
		{"arbitrary command", `package cloudflareprofilesetup
import "os/exec"
func unsafe() { _ = exec.Command("unsafe") }
`},
		{"provider mutation", `package cloudflareprofilesetup
import "net/http"
func unsafe() { _, _ = http.Post("https://example.com", "", nil) }
`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			mustWriteArchitectureFile(t, directory, "internal/cloudflareprofilesetup/unsafe.go", test.source)
			if err := validateCloudflareProfileSetupComposition(directory); err == nil || !strings.Contains(err.Error(), "composition-only") {
				t.Fatalf("validateCloudflareProfileSetupComposition() = %v", err)
			}
		})
	}
}

func TestHealthDiagnosticsReadOnlyBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHealthDiagnosticsReadOnly(root); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct{ name, source string }{
		{"arbitrary command", `package healthdiagnostics
import "os/exec"
func unsafe() { _ = exec.Command("unsafe") }
`},
		{"generic file reader", `package healthdiagnostics
import "os"
func Read(path string) { _, _ = os.ReadFile(path) }
`},
		{"service control", `package healthdiagnostics
import "syscall"
func Stop(pid int) { _ = syscall.Kill(pid, 0) }
`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			mustWriteArchitectureFile(t, directory, "internal/healthdiagnostics/unsafe.go", test.source)
			if err := validateHealthDiagnosticsReadOnly(directory); err == nil || !strings.Contains(err.Error(), "typed read-only inspections") {
				t.Fatalf("validateHealthDiagnosticsReadOnly() = %v", err)
			}
		})
	}
}

func TestOwnerConsolePresentationBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOwnerConsolePresentation(root); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, source string }{
		{"host mutation", `package ownerconsole
import "os"
func unsafe() { _ = os.WriteFile("/tmp/unsafe", nil, 0o600) }
`},
		{"arbitrary command", `package ownerconsole
import "os/exec"
func unsafe() { _ = exec.Command("unsafe") }
`},
		{"product logic", `package ownerconsole
import "github.com/albertloky/SBXR/internal/state"
func unsafe(value state.Interface) { _ = value }
`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			mustWriteArchitectureFile(t, directory, "internal/ownerconsole/unsafe.go", test.source)
			if err := validateOwnerConsolePresentation(directory); err == nil || !strings.Contains(err.Error(), "terminal presentation only") {
				t.Fatalf("validateOwnerConsolePresentation() = %v", err)
			}
		})
	}
}

func TestSoftwareLifecycleVerificationBoundary(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSoftwareLifecycleVerification(root); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct{ name, source string }{
		{"executes candidate", `package softwarelifecycle
import "os/exec"
func unsafe() { _ = exec.Command("candidate") }
`},
		{"mutates host", `package softwarelifecycle
import "os"
func unsafe() { _ = os.WriteFile("/tmp/unsafe", nil, 0o600) }
`},
		{"calls an unapproved Module", `package softwarelifecycle
import "github.com/albertloky/SBXR/internal/state"
func unsafe(value state.Interface) { _ = value }
`},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			mustWriteArchitectureFile(t, directory, "internal/softwarelifecycle/unsafe.go", test.source)
			if err := validateSoftwareLifecycleVerification(directory); err == nil || !strings.Contains(err.Error(), "verification-only") {
				t.Fatalf("validateSoftwareLifecycleVerification() = %v", err)
			}
		})
	}
}

func validateSoftwareLifecycleVerification(root string) error {
	directory := filepath.Join(root, "internal/softwarelifecycle")
	files, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	fileSet := token.NewFileSet()
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, filepath.Join(directory, file.Name()), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			hostInspection := file.Name() == "status_local.go" && (importPath == "os" || importPath == "syscall")
			if !hostInspection && (importPath == "os" || importPath == "os/exec" || importPath == "syscall" || importPath == "unsafe") || strings.HasPrefix(importPath, modulePath+"/internal/") && importPath != modulePath+"/internal/systemchanges" && importPath != modulePath+"/internal/networkpolicy" && importPath != modulePath+"/internal/softwarelifecycle/contract" {
				return fmt.Errorf("Software Lifecycle core must remain verification-only before staging: %s imports %s", file.Name(), importPath)
			}
		}
	}
	return nil
}

func validateCloudflareProfileSetupComposition(root string) error {
	allowed := map[string]bool{
		"context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true, "strings": true, "sync/atomic": true, "time": true,
		modulePath + "/internal/certificatelifecycle":    true,
		modulePath + "/internal/cloudflaretunnel":        true,
		modulePath + "/internal/connectionprofiles":      true,
		modulePath + "/internal/networkpolicy":           true,
		modulePath + "/internal/state":                   true,
		modulePath + "/internal/subscriptionpublication": true,
		modulePath + "/internal/systemchanges":           true,
	}
	return walkProductionGoFiles(root, func(relative string, source *ast.File) error {
		if filepath.ToSlash(filepath.Dir(relative)) != "internal/cloudflareprofilesetup" {
			return nil
		}
		for _, imported := range source.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !allowed[importPath] {
				return fmt.Errorf("Cloudflare Profile Setup must remain composition-only: %s imports %s", relative, importPath)
			}
		}
		return nil
	})
}

func validateSubscriptionServingMutation(root string) error {
	allowed := map[string]map[string]bool{
		"os": {
			"FileInfo": true, "Getegid": true, "Geteuid": true, "Lstat": true, "ModeSymlink": true,
			"OpenRoot": true, "ReadFile": true, "Readlink": true, "Root": true,
		},
		"syscall": {"Stat_t": true},
	}
	allowedRootMethods := map[string]bool{"Close": true, "FS": true, "Lstat": true, "ReadFile": true}
	directory := filepath.Join(root, "internal/subscriptionserving")
	fileSet := token.NewFileSet()
	filesByPackage, err := parser.ParseDir(fileSet, directory, func(info fs.FileInfo) bool { return !strings.HasSuffix(info.Name(), "_test.go") }, 0)
	if err != nil {
		return err
	}
	parsed := filesByPackage["subscriptionserving"]
	if parsed == nil {
		return errors.New("Subscription Serving production package unavailable")
	}
	files := make([]*ast.File, 0, len(parsed.Files))
	for _, file := range parsed.Files {
		for _, imported := range file.Imports {
			path, _ := strconv.Unquote(imported.Path.Value)
			if imported.Name != nil && imported.Name.Name == "." && (path == "os" || path == "os/exec" || path == "syscall") {
				return fmt.Errorf("Subscription Serving must remain read-only: dot import of %s", path)
			}
		}
		files = append(files, file)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	configuration := types.Config{Importer: importer.Default()}
	if _, err := configuration.Check(modulePath+"/internal/subscriptionserving", fileSet, files, info); err != nil {
		return err
	}
	var violation error
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || violation != nil {
				return violation == nil
			}
			name := selector.Sel.Name
			if selection := info.Selections[selector]; selection != nil {
				receiver := types.TypeString(selection.Recv(), func(pkg *types.Package) string { return pkg.Path() })
				if receiver == "*os.Root" && !allowedRootMethods[name] || receiver == "*os.File" {
					violation = fmt.Errorf("Subscription Serving must remain read-only: %s.%s", receiver, name)
				}
				return violation == nil
			}
			object := info.Uses[selector.Sel]
			if object == nil || object.Pkg() == nil {
				return true
			}
			path := object.Pkg().Path()
			if path == "os/exec" || allowed[path] != nil && !allowed[path][name] {
				violation = fmt.Errorf("Subscription Serving must remain read-only: %s.%s", path, name)
			}
			return violation == nil
		})
	}
	return violation
}

func validateHealthDiagnosticsReadOnly(root string) error {
	allowed := map[string]bool{"archive/tar": true, "bytes": true, "compress/gzip": true, "context": true, "crypto/sha256": true, "embed": true, "encoding/hex": true, "encoding/json": true, "errors": true, "io": true, "io/fs": true, "sort": true, "strconv": true, "strings": true, "time": true, modulePath + "/internal/systemchanges": true}
	return walkProductionGoFiles(root, func(relative string, source *ast.File) error {
		if filepath.ToSlash(filepath.Dir(relative)) != "internal/healthdiagnostics" {
			return nil
		}
		for _, imported := range source.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !allowed[importPath] {
				return fmt.Errorf("Health and Diagnostics accepts only typed read-only inspections: %s imports %s", relative, importPath)
			}
		}
		var genericReader string
		ast.Inspect(source, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok {
				return true
			}
			for _, name := range field.Names {
				lower := strings.ToLower(name.Name)
				for _, capability := range []string{"command", "file", "path", "log", "service"} {
					if strings.Contains(lower, capability) {
						genericReader = name.Name
					}
				}
			}
			return genericReader == ""
		})
		if genericReader != "" {
			return fmt.Errorf("Health and Diagnostics accepts only typed read-only inspections: generic capability %s", genericReader)
		}
		return nil
	})
}

func validateOwnerConsolePresentation(root string) error {
	allowed := map[string]bool{
		"context": true, "errors": true, "fmt": true, "io": true, "os": true,
		"net/url": true, "slices": true, "strconv": true, "strings": true, "sync/atomic": true, "syscall": true,
		"time": true, "unicode": true, "unsafe": true,
	}
	return walkProductionGoFiles(root, func(relative string, source *ast.File) error {
		if filepath.ToSlash(filepath.Dir(relative)) != "internal/ownerconsole" {
			return nil
		}
		for _, imported := range source.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !allowed[importPath] && !approvedExternalImports[importPath] {
				return fmt.Errorf("Owner Console contains terminal presentation only: %s imports %s", relative, importPath)
			}
		}
		var mutation string
		ast.Inspect(source, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			base, direct := selector.X.(*ast.Ident)
			if direct && base.Name == "os" && selector.Sel.Name != "File" && selector.Sel.Name != "Environ" && selector.Sel.Name != "ModeCharDevice" {
				mutation = "os." + selector.Sel.Name
			}
			return mutation == ""
		})
		if mutation != "" {
			return fmt.Errorf("Owner Console contains terminal presentation only: %s uses %s", relative, mutation)
		}
		return nil
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
			if current.ImportPath != modulePath+"/cmd/sbxr" && current.ImportPath != modulePath+"/cmd/sbxr-release" {
				return fmt.Errorf("unregistered product package %q", current.ImportPath)
			}
			continue
		}
		if len(parts) < 2 || !registeredModules[parts[1]] {
			return fmt.Errorf("unregistered product package %q", current.ImportPath)
		}
		if len(parts) > 2 && current.ImportPath != modulePath+"/internal/softwarelifecycle/contract" && (len(parts) != 4 || parts[2] != "adapter") {
			return fmt.Errorf("shallow package %q; keep implementation with its Module", current.ImportPath)
		}
	}

	for _, current := range packages {
		from := owningModule(current.ImportPath)
		for _, imported := range current.Imports {
			if isExternalImport(imported) && (from != "ownerconsole" || !approvedExternalImports[imported]) && (from != "softwarelifecycle" || !approvedSoftwareLifecycleExternalImports[imported]) {
				return fmt.Errorf("unapproved production dependency %s -> %s", current.ImportPath, imported)
			}
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

func isExternalImport(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return strings.Contains(first, ".") && importPath != modulePath && !strings.HasPrefix(importPath, modulePath+"/")
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
