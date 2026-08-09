package ubuntu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestUpdaterSwitchesAndRestoresTheExactReleaseFromOneSnapshot(t *testing.T) {
	prior := installFixtureVersion(t, "v1.0.0", strings.Repeat("a", 40), "UNIQUE-PRIOR-EXECUTABLE")
	candidate := installFixtureVersion(t, "v1.1.0", strings.Repeat("b", 40), "UNIQUE-CANDIDATE-EXECUTABLE")
	step, _ := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	root := t.TempDir()
	if _, err := prior.Activate(root, step, time.Minute); err != nil {
		t.Fatal(err)
	}
	updater, err := newUpdater(candidate, prior, softwarelifecycle.VerifiedRelease{Identity: prior.staged.Identity, Sequence: 1, StateSchema: prior.staged.StateSchema, MinimumUpdaterSchema: 1})
	if err != nil {
		t.Fatal(err)
	}
	var commands []string
	updater.command = func(_ context.Context, name string, arguments ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		return nil, nil
	}
	var rollback []byte
	if err := updater.CaptureRollback(root, step, func(source io.Reader) error { rollback, _ = io.ReadAll(source); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(rollback) == 0 || !bytes.Contains(rollback, []byte("UNIQUE-PRIOR-EXECUTABLE")) {
		t.Fatal("prior release is absent from the rollback snapshot")
	}
	if evidence, err := updater.Activate(root, step, time.Minute); err != nil || evidence.Code != "software-release-updated" {
		t.Fatalf("Activate() = (%+v, %v)", evidence, err)
	}
	active, _ := os.Readlink(filepath.Join(root, "usr/local/bin/sbxr"))
	if active != candidate.staged.InstallPath {
		t.Fatalf("active release = %q", active)
	}
	if effect, err := updater.Inspect(root, step, bytes.NewReader(rollback), time.Minute); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("Inspect(candidate) = (%s, %v)", effect, err)
	}
	if status, err := updater.Check(root, systemchanges.Check{Owner: systemchanges.SoftwareModule, Code: "SOFTWARE-LIFECYCLE-UPDATE-STAGED"}, systemchanges.PrePublication, time.Minute); err != nil || status != systemchanges.Healthy {
		t.Fatalf("Check(pre-publication) = (%s, %v)", status, err)
	}
	if _, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(path.Dir(prior.staged.InstallPath), "/"))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("prior release remains outside rollback snapshot: %v", err)
	}
	candidateExecutable := filepath.Join(root, strings.TrimPrefix(candidate.staged.InstallPath, "/"))
	candidateBody, _ := os.ReadFile(candidateExecutable)
	if err := os.WriteFile(candidateExecutable, []byte("changed candidate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := updater.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err == nil {
		t.Fatal("changed candidate was deleted during rollback")
	}
	if body, _ := os.ReadFile(candidateExecutable); string(body) != "changed candidate" {
		t.Fatal("changed candidate did not remain for Recovery Required")
	}
	if err := os.WriteFile(candidateExecutable, candidateBody, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := updater.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"/usr/bin/systemctl daemon-reload", "/usr/bin/systemctl restart cloudflared.service sbxr-subscription.service sing-box.service xray.service"}) {
		t.Fatalf("rollback commands = %v", commands)
	}
	active, _ = os.Readlink(filepath.Join(root, "usr/local/bin/sbxr"))
	priorBody, readErr := os.ReadFile(filepath.Join(root, strings.TrimPrefix(prior.staged.InstallPath, "/")))
	if active != prior.staged.InstallPath || readErr != nil || !bytes.Contains(priorBody, []byte("UNIQUE-PRIOR-EXECUTABLE")) {
		t.Fatalf("prior release not restored: active=%q err=%v body=%q", active, readErr, priorBody)
	}
	if effect, err := updater.Inspect(root, step, bytes.NewReader(rollback), time.Minute); err != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("Inspect(prior) = (%s, %v)", effect, err)
	}
	if _, err := os.Lstat(filepath.Join(root, strings.TrimPrefix(path.Dir(candidate.staged.InstallPath), "/"))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("candidate remains after rollback: %v", err)
	}
}

func TestUpdaterRejectsTamperedSnapshotAndRestoresAPartialSwitch(t *testing.T) {
	prior := installFixtureVersion(t, "v1.0.0", strings.Repeat("c", 40), "PRIOR-PARTIAL-MARKER")
	candidate := installFixtureVersion(t, "v1.1.0", strings.Repeat("d", 40), "CANDIDATE-PARTIAL-MARKER")
	step, _ := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	root := t.TempDir()
	if _, err := prior.Activate(root, step, time.Minute); err != nil {
		t.Fatal(err)
	}
	updater, _ := newUpdater(candidate, prior, softwarelifecycle.VerifiedRelease{Identity: prior.staged.Identity, Sequence: 1, StateSchema: prior.staged.StateSchema, MinimumUpdaterSchema: 1})
	var rollback []byte
	if err := updater.CaptureRollback(root, step, func(source io.Reader) error { rollback, _ = io.ReadAll(source); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := updater.Reverse(root, step, bytes.NewReader(append(append([]byte(nil), rollback...), 'x')), time.Minute); err == nil {
		t.Fatal("snapshot with trailing bytes accepted")
	}
	if _, err := updater.Reverse(root, step, bytes.NewReader(append(append([]byte(nil), rollback...), rollback...)), time.Minute); err == nil {
		t.Fatal("snapshot with a second tar archive accepted")
	}
	if err := os.Symlink(candidate.staged.InstallPath, filepath.Join(root, "usr/local/bin/sbxr.sbxr-update")); err != nil {
		t.Fatal(err)
	}
	if _, err := updater.Activate(root, step, time.Minute); err == nil {
		t.Fatal("partial-switch fixture did not fail")
	}
	if _, err := updater.Reverse(root, step, bytes.NewReader(rollback), time.Minute); err != nil {
		t.Fatal(err)
	}
	active, _ := os.Readlink(filepath.Join(root, "usr/local/bin/sbxr"))
	if active != prior.staged.InstallPath {
		t.Fatalf("partial switch restored %q", active)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr/local/bin/sbxr.sbxr-update")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temporary switch path remains: %v", err)
	}
}

func TestUpdaterRefusesMalformedInstalledReleasePaths(t *testing.T) {
	prior := installFixtureVersion(t, "v1.0.0", strings.Repeat("e", 40), "PRIOR-PATH-MARKER")
	candidate := installFixtureVersion(t, "v1.1.0", strings.Repeat("f", 40), "CANDIDATE-PATH-MARKER")
	installed := softwarelifecycle.VerifiedRelease{Identity: prior.staged.Identity, Sequence: 1, StateSchema: prior.staged.StateSchema, MinimumUpdaterSchema: 1}
	installed.Identity.Tag = "../outside"
	if _, err := newUpdater(candidate, prior, installed); err == nil {
		t.Fatal("path-bearing installed identity accepted")
	}
}
