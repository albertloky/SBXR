package filesystem

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"time"

	"github.com/albertloky/SBXR/internal/healthdiagnostics"
)

type SelfInspector struct {
	root string
	uid  int
	now  func() time.Time
}

func NewSelfInspector() SelfInspector {
	return SelfInspector{root: "/", uid: 0, now: time.Now}
}

func newSelfInspector(root string, uid int, now func() time.Time) SelfInspector {
	return SelfInspector{root: root, uid: uid, now: now}
}

// Inspect proves Health and Diagnostics' fixed storage and scheduled units without repairing them.
func (inspector SelfInspector) Inspect() (healthdiagnostics.Finding, error) {
	finding := healthdiagnostics.Finding{Status: healthdiagnostics.Healthy, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.HealthDiagnosticsModule, healthdiagnostics.Healthy)}
	events, err := (EventStorage{root: inspector.root, uid: inspector.uid}).Load()
	if err != nil {
		return healthdiagnostics.Finding{}, err
	}
	now := inspector.now().UTC()
	for _, event := range events {
		if event.Record().Time.Before(now.Add(-healthdiagnostics.EventRetentionPeriod)) {
			return healthdiagnostics.Finding{Status: healthdiagnostics.NeedsAttention, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.HealthDiagnosticsModule, healthdiagnostics.NeedsAttention)}, nil
		}
	}
	if err := inspector.inspectBundles(); err != nil {
		return healthdiagnostics.Finding{}, err
	}
	units, err := healthdiagnostics.SystemdUnits()
	if err != nil {
		return healthdiagnostics.Finding{}, err
	}
	root, err := os.OpenRoot(inspector.root)
	if err != nil {
		return healthdiagnostics.Finding{}, err
	}
	defer root.Close()
	for name, expected := range units {
		info, err := root.Lstat(path.Join("etc/systemd/system", name))
		body, readErr := root.ReadFile(path.Join("etc/systemd/system", name))
		if err != nil || readErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || owner(info) != inspector.uid || !bytes.Equal(body, []byte(expected)) {
			return healthdiagnostics.Finding{Status: healthdiagnostics.Failed, Code: healthdiagnostics.NamedCheckCode(healthdiagnostics.HealthDiagnosticsModule, healthdiagnostics.Failed)}, nil
		}
	}
	return finding, nil
}

func (inspector SelfInspector) inspectBundles() error {
	diagnostics, err := (EventStorage{root: inspector.root, uid: inspector.uid}).open(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer diagnostics.Close()
	bundlesInfo, bundlesErr := diagnostics.Lstat("bundles")
	stagingInfo, stagingErr := diagnostics.Lstat("staging")
	if errors.Is(bundlesErr, os.ErrNotExist) && errors.Is(stagingErr, os.ErrNotExist) {
		return nil
	}
	if bundlesErr != nil || stagingErr != nil || !safeDirectory(bundlesInfo, inspector.uid) || !safeDirectory(stagingInfo, inspector.uid) {
		return errors.New("support bundle storage is unsafe")
	}
	staging, err := diagnostics.OpenRoot("staging")
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(staging.FS(), ".")
	staging.Close()
	if err != nil || len(entries) != 0 {
		return errors.New("support bundle staging is not empty")
	}
	bundles, err := diagnostics.OpenRoot("bundles")
	if err != nil {
		return err
	}
	defer bundles.Close()
	entries, err = fs.ReadDir(bundles.FS(), ".")
	if err != nil || len(entries) > 3 {
		return errors.New("support bundle storage is invalid")
	}
	for _, entry := range entries {
		info, err := bundles.Lstat(entry.Name())
		body, readErr := bundles.ReadFile(entry.Name())
		if err != nil || readErr != nil || !bundleName(entry.Name()) || !safeBundleFile(info, inspector.uid, healthdiagnostics.BundleArchiveBytes) || !healthdiagnostics.ValidCompletedBundle(body) {
			return errors.New("support bundle archive is unsafe")
		}
	}
	return nil
}
