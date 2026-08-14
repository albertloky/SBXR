package ubuntu

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/healthdiagnostics"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionserving"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestInstallerActivatesAndRollsBackOnlyTheReviewedRelease(t *testing.T) {
	installer := installFixture(t)
	installer.manageRecoveryUnit = true
	installer.enableRecovery = func() error { return nil }
	installer.disableRecovery = func() error { return nil }
	step, err := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var rollback []byte
	if err := installer.CaptureRollback(root, step, func(source io.Reader) error { rollback, _ = io.ReadAll(source); return nil }); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rollback, []byte(`"identities"`)) {
		t.Fatalf("fresh-install rollback retained service identities: %s", rollback)
	}
	evidence, err := installer.Activate(root, step, time.Minute)
	if err != nil || evidence.Code != "software-release-installed" {
		t.Fatalf("Activate() = (%+v, %v)", evidence, err)
	}
	if status, checkErr := installer.Check(root, systemchanges.Check{Owner: systemchanges.SoftwareModule, Code: "SOFTWARE-LIFECYCLE-INSTALL-AGREEMENT"}, systemchanges.PostPublication, time.Minute); checkErr != nil || status != systemchanges.Healthy {
		t.Fatalf("Check() = (%s, %v)", status, checkErr)
	}
	if status := inspectRelease(root, installer.staged.Identity, uint32(os.Geteuid())); status != systemchanges.Healthy {
		t.Fatalf("InspectRelease() = %s", status)
	}
	releaseDirectory := filepath.Join(root, strings.TrimPrefix(path.Dir(installer.staged.InstallPath), "/"))
	xray := filepath.Join(releaseDirectory, "xray")
	xrayUnit, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/xray.service"))
	if body, err := os.ReadFile(xray); err != nil || string(body) != "qualified xray" || !bytes.Contains(xrayUnit, []byte(path.Dir(installer.staged.InstallPath)+"/xray")) || bytes.Contains(xrayUnit, []byte("/usr/bin/xray")) {
		t.Fatalf("versioned components not activated: xray=%q err=%v unit=%q", body, err, xrayUnit)
	}
	unit := filepath.Join(root, "etc/systemd/system/xray.service")
	original, _ := os.ReadFile(unit)
	if err := os.WriteFile(unit, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := inspectRelease(root, installer.staged.Identity, uint32(os.Geteuid())); status != systemchanges.Failed {
		t.Fatalf("InspectRelease() after drift = %s", status)
	}
	if _, err := installer.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err == nil {
		t.Fatal("changed installed unit was deleted")
	}
	if err := os.WriteFile(unit, original, 0o644); err != nil {
		t.Fatal(err)
	}
	recovery := NewRecoveryInstaller()
	recovery.manageRecoveryUnit = false
	if _, err := recovery.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(xray); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("component remains after rollback: %v", err)
	}
	if effect, inspectErr := installer.Inspect(root, step, bytes.NewReader(rollback), time.Minute); inspectErr != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("Inspect() = (%s, %v)", effect, inspectErr)
	}
}

func TestInstallerEnablesAndRollsBackRestartRecoveryWithoutServiceIdentities(t *testing.T) {
	installer := installFixture(t)
	installer.manageRecoveryUnit = true
	calls := []string{}
	installer.enableRecovery = func() error { calls = append(calls, "enable-recovery"); return nil }
	installer.disableRecovery = func() error { calls = append(calls, "disable-recovery"); return nil }
	step, _ := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	root := t.TempDir()
	var rollback []byte
	if err := installer.CaptureRollback(root, step, func(source io.Reader) error { rollback, _ = io.ReadAll(source); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Activate(root, step, time.Minute); err != nil {
		t.Fatal(err)
	}
	recovery := NewRecoveryInstaller()
	recovery.disableRecovery = installer.disableRecovery
	if effect, err := recovery.Inspect(root, step, bytes.NewReader(rollback), time.Minute); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("recovery Inspect() = (%s, %v)", effect, err)
	}
	if _, err := recovery.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls, ","); got != "enable-recovery,disable-recovery" {
		t.Fatalf("restart recovery lifecycle = %q", got)
	}
}

func TestInstallerRefusesAnOccupiedOrLinkedInstallTarget(t *testing.T) {
	installer := installFixture(t)
	step, _ := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/unrelated", filepath.Join(root, "usr/local/bin/sbxr")); err != nil {
		t.Fatal(err)
	}
	if err := installer.CaptureRollback(root, step, func(io.Reader) error { return nil }); err == nil {
		t.Fatal("occupied symlink target accepted")
	}
}

func TestInstallerRefusesChangedPreparedComponentBytes(t *testing.T) {
	installer := installFixture(t)
	installer.components[0] ^= 1
	step, _ := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if _, err := installer.Activate(t.TempDir(), step, time.Minute); err == nil {
		t.Fatal("changed prepared component archive accepted")
	}
}

func TestInstallerRollsBackAValidatedPartialActivation(t *testing.T) {
	installer := installFixture(t)
	step, _ := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	root := t.TempDir()
	var rollback []byte
	if err := installer.CaptureRollback(root, step, func(source io.Reader) error { rollback, _ = io.ReadAll(source); return nil }); err != nil {
		t.Fatal(err)
	}
	executable, metadata, err := installer.material()
	if err != nil {
		t.Fatal(err)
	}
	unit := softwarelifecycle.ManagedUnitNames()[0]
	units, err := softwarelifecycle.RenderManagedUnits(metadata, installer.staged.Identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{path.Dir(strings.TrimPrefix(installer.staged.InstallPath, "/")), "etc/systemd/system", "usr/local/bin", "opt/sbxr/releases", "etc/sbxr"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	executableName := filepath.Join(root, strings.TrimPrefix(installer.staged.InstallPath, "/"))
	unitName := filepath.Join(root, "etc/systemd/system", unit)
	if os.WriteFile(executableName, executable, 0o755) != nil || os.WriteFile(unitName, units[unit], 0o644) != nil {
		t.Fatal("partial activation fixture")
	}
	if _, err := installer.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{executableName, unitName} {
		if _, err := os.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("partial target remains: %s: %v", name, err)
		}
	}
}

func installFixture(t *testing.T) Installer {
	return installFixtureVersion(t, "v1.0.0", "0123456789abcdef0123456789abcdef01234567", "qualified-static-linux-elf-fixture")
}

func installFixtureVersion(t *testing.T, tag, commit, marker string) Installer {
	t.Helper()
	artifacts, err := subscriptionpublication.QualificationArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	artifacts["cloudflared.yml"] = cloudflaretunnel.QualificationConfiguration()
	definitions, err := state.ReleaseDefinitions()
	if err != nil {
		t.Fatal(err)
	}
	units := []map[string]string{{"cloudflared.service": cloudflaretunnel.CloudflaredServiceUnit()}, {"sbxr-subscription.service": subscriptionserving.ServiceUnit()}, connectionprofiles.SystemdUnits(), softwarelifecycle.SystemdUnits(), systemchanges.SystemdUnits()}
	for _, read := range []func() (map[string]string, error){certificatelifecycle.SystemdUnits, healthdiagnostics.SystemdUnits} {
		set, readErr := read()
		if readErr != nil {
			t.Fatal(readErr)
		}
		units = append(units, set)
	}
	identity := softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: tag, Commit: commit}
	metadata, err := softwarelifecycle.NewPayloadMetadata(identity, softwarelifecycle.AMD64, softwarelifecycle.PayloadMaterial{StateDefinitions: definitions, StateMigrations: state.ReleaseMigrations(), UnitSets: units, ArtifactSets: []map[string][]byte{artifacts}})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(marker)
	stamped, err := softwarelifecycle.StampPayload(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	compressed := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressed)
	if err := writer.WriteHeader(&tar.Header{Name: "sbxr", Mode: 0o755, Size: int64(len(stamped)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(stamped)
	if writer.Close() != nil || compressed.Close() != nil {
		t.Fatal("archive close")
	}
	digest := sha256.Sum256(stamped)
	componentFiles := map[string][]byte{
		"xray": []byte("qualified xray"), "sing-box": []byte("qualified sing-box"), "cloudflared": []byte("qualified cloudflared"),
		"certbot/bin/certbot": softwarelifecycle.ComponentCertbotLauncher(), "certbot/pyvenv.cfg": []byte("home = /usr/bin\nversion = 3.12\n"),
		"certbot/lib/python3.12/site-packages/certbot/__init__.py": []byte("__version__ = '5.4.0'\n"),
	}
	componentManifest, err := softwarelifecycle.NewComponentManifest(softwarelifecycle.AMD64, "5.4.0", componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	components, err := softwarelifecycle.BuildComponentArchive(componentManifest, componentFiles)
	if err != nil {
		t.Fatal(err)
	}
	componentDigest := sha256.Sum256(components)
	release := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: identity.Tag, Commit: identity.Commit, IndexSHA256: strings.Repeat("b", 64)}
	rawDigest := sha256.Sum256(raw)
	staged := softwarelifecycle.StagedRelease{Identity: release, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, PayloadSHA256: hex.EncodeToString(rawDigest[:])}, Architecture: softwarelifecycle.AMD64, ExecutableSHA256: hex.EncodeToString(digest[:]), ComponentsSHA256: hex.EncodeToString(componentDigest[:]), InstallPath: softwarelifecycle.ReleaseInstallPath(release), StateSchema: 2}
	installer, err := newInstaller(staged, archive.Bytes(), components)
	if err != nil {
		t.Fatal(err)
	}
	return installer
}
