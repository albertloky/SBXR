package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestInstallHostActivatesAndReversesOnlyPreparedProxyConfigurations(t *testing.T) {
	root := t.TempDir()
	prepared := filepath.Join(root, transactionDirectory, "install-session-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/sbxr"), 0o755); err != nil {
		t.Fatal(err)
	}
	xray, singBox := []byte(`{"inbounds":[{"tag":"xray"}]}`), []byte(`{"inbounds":[{"tag":"sing-box"}]}`)
	writePreparedInstall(t, prepared, xray, singBox, false)
	var commands []string
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), xrayGID: os.Getegid(), singGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(_ context.Context, name string, arguments ...string) error {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		return nil
	}}
	step, err := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot []byte
	if err := host.CaptureRollback(step, func(source io.Reader) error { snapshot, err = io.ReadAll(source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"etc/sbxr/xray/config.json": xray, "etc/sbxr/sing-box/config.json": singBox} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, %v", name, got, err)
		}
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("InspectStep = %q, %v", effect, err)
	}
	if _, err := host.Reverse(step, bytes.NewReader(snapshot), time.Second); err != nil {
		t.Fatal(err)
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("rollback InspectStep = %q, %v", effect, err)
	}
	if len(commands) < 3 {
		t.Fatalf("managed systemd lifecycle was not invoked: %v", commands)
	}
}

func TestInstallHostEnforcesRootRuntimeManifest(t *testing.T) {
	root := t.TempDir()
	prepared := filepath.Join(root, transactionDirectory, "root-runtime-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/sbxr"), 0o755); err != nil {
		t.Fatal(err)
	}
	xray, singBox := []byte(`{"inbounds":[{"tag":"xray"}]}`), []byte(`{"inbounds":[{"tag":"sing-box"}]}`)
	writePreparedInstall(t, prepared, xray, singBox, true)
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), xrayGID: -1, singGID: -1, units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
	step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	for _, name := range installConfigurationPaths() {
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		stat, ok := info.Sys().(*syscall.Stat_t)
		if err != nil || !ok || info.Mode().Perm() != 0o644 || info.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 {
			t.Fatalf("root-runtime artifact %s = %v, %v", name, info, err)
		}
		if directory, err := os.Stat(filepath.Dir(path)); err != nil || directory.Mode().Perm() != 0o755 {
			t.Fatalf("root-runtime directory %s = %v, %v", name, directory, err)
		}
	}
}

func TestInstallHostRefusesChangedDigestAndLinkedReplacement(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(string, string) error
	}{
		{"changed digest", func(_ string, prepared string) error {
			return os.WriteFile(filepath.Join(prepared, "xray.json"), []byte(`{"changed":true}`), 0o600)
		}},
		{"linked replacement", func(root, _ string) error {
			directory := filepath.Join(root, "etc/sbxr/xray")
			if err := os.MkdirAll(directory, 0o755); err != nil {
				return err
			}
			source := filepath.Join(directory, "linked")
			if err := os.WriteFile(source, []byte("prior"), 0o644); err != nil {
				return err
			}
			return os.Link(source, filepath.Join(directory, "config.json"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			prepared := filepath.Join(root, transactionDirectory, "root-runtime-refusal", "prepared")
			if err := os.MkdirAll(prepared, 0o700); err != nil || os.MkdirAll(filepath.Join(root, "etc/sbxr"), 0o755) != nil {
				t.Fatal("prepare test root")
			}
			writePreparedInstall(t, prepared, []byte(`{"xray":true}`), []byte(`{"sing_box":true}`), true)
			if err := test.change(root, prepared); err != nil {
				t.Fatal(err)
			}
			host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), xrayGID: -1, singGID: -1, units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
			step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
			if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err == nil {
				t.Fatal("InstallHost accepted changed artifact identity")
			}
		})
	}
}

func TestInstallHostReconcilesSafeTemporaryAfterRestart(t *testing.T) {
	root := t.TempDir()
	prepared := filepath.Join(root, transactionDirectory, "root-runtime-restart", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil || os.MkdirAll(filepath.Join(root, "etc/sbxr/xray"), 0o755) != nil || os.MkdirAll(filepath.Join(root, "etc/sbxr/sing-box"), 0o755) != nil {
		t.Fatal("prepare test root")
	}
	writePreparedInstall(t, prepared, []byte(`{"xray":true}`), []byte(`{"sing_box":true}`), true)
	for _, name := range installConfigurationPaths() {
		if err := os.WriteFile(filepath.Join(root, name+".preparing"), []byte("interrupted"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), xrayGID: -1, singGID: -1, units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
	step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
}

func TestInstallHostProvesEverySelectedClientAccessListener(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string]string{
		"etc/sbxr/xray/config.json":     `{"inbounds":[{"listen":"127.0.0.1","port":11080}]}`,
		"etc/sbxr/sing-box/config.json": `{"inbounds":[{"type":"tuic","listen":"0.0.0.0","listen_port":8443}]}`,
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil || os.WriteFile(path, []byte(body), 0o640) != nil {
			t.Fatal("write active configuration")
		}
	}
	prepared := filepath.Join(root, transactionDirectory, "client-access-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal("write reviewed configuration")
	}
	writePreparedInstall(t, prepared, []byte(`{"inbounds":[{"listen":"127.0.0.1","port":11080}]}`), []byte(`{"inbounds":[{"type":"tuic","listen":"0.0.0.0","listen_port":8443}]}`), false)
	listeners := []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\n")
	host := InstallHost{root: root, output: func(context.Context, string, ...string) ([]byte, error) { return listeners, nil }}
	check := systemchanges.Check{Owner: systemchanges.ConnectionProfilesModule, Code: "CONNECTION-PROFILES-CLIENT-ACCESS-LISTENERS"}
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Healthy {
		t.Fatalf("listener health = %s, %v", status, err)
	}
	listeners = listeners[:bytes.Index(listeners, []byte("udp"))]
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("missing listener health = %s, %v", status, err)
	}
	listeners = []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\ntcp LISTEN 0 4096 0.0.0.0:9999 0.0.0.0:* users:((\"sing-box\",pid=2,fd=3))\n")
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("extra listener health = %s, %v", status, err)
	}
	listeners = []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\ntcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=3,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\n")
	if status, err := host.Check(check, systemchanges.PostPublication, time.Second); err != nil || status != systemchanges.Failed {
		t.Fatalf("duplicate listener health = %s, %v", status, err)
	}
}

func TestManagedInstallHostSnapshotsActivatesAndRestoresPriorConfigurations(t *testing.T) {
	root := t.TempDir()
	prior := map[string][]byte{"etc/sbxr/xray/config.json": []byte(`{"prior":"xray"}`), "etc/sbxr/sing-box/config.json": []byte(`{"prior":"sing-box"}`)}
	for name, body := range prior {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil || os.WriteFile(path, body, 0o640) != nil {
			t.Fatal("write prior configuration")
		}
	}
	prepared := filepath.Join(root, transactionDirectory, "client-access-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal("write prepared configuration")
	}
	writePreparedInstall(t, prepared, []byte(`{"next":"xray"}`), []byte(`{"next":"sing-box"}`), false)
	var commands []string
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), xrayGID: os.Getegid(), singGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), managed: true, run: func(_ context.Context, name string, arguments ...string) error {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		return nil
	}}
	step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	var snapshot []byte
	if err := host.CaptureRollback(step, func(source io.Reader) error { var err error; snapshot, err = io.ReadAll(source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "systemctl restart xray.service") || !slices.Contains(commands, "systemctl restart sing-box.service") {
		t.Fatalf("affected core restarts = %v", commands)
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("candidate effect = %s, %v", effect, err)
	}
	if _, err := host.Reverse(step, bytes.NewReader(snapshot), time.Second); err != nil {
		t.Fatal(err)
	}
	if effect, err := host.InspectStep(step, bytes.NewReader(snapshot), time.Second); err != nil || effect != systemchanges.StepEffectAbsent {
		t.Fatalf("restored effect = %s, %v", effect, err)
	}
	for name, want := range prior {
		if got, err := os.ReadFile(filepath.Join(root, name)); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored %s = %q, %v", name, got, err)
		}
	}
}

func writePreparedInstall(t *testing.T, prepared string, xray, singBox []byte, rootRuntime bool) {
	t.Helper()
	group, directoryMode, fileMode := "xray", 0o750, 0o640
	if rootRuntime {
		group, directoryMode, fileMode = "root", 0o755, 0o644
	}
	xrayDigest, singDigest := sha256.Sum256(xray), sha256.Sum256(singBox)
	manifests := fmt.Sprintf(`{"xray":{"Service":"xray.service","OwningModule":"connectionprofiles","CandidateRevision":8,"ChangeSet":"change-0008","Owner":"root","Group":%q,"DirectoryMode":%d,"FileMode":%d,"SHA256":"%x"},"sing_box":{"Service":"sing-box.service","OwningModule":"connectionprofiles","CandidateRevision":8,"ChangeSet":"change-0008","Owner":"root","Group":%q,"DirectoryMode":%d,"FileMode":%d,"SHA256":"%x"}}`, group, directoryMode, fileMode, xrayDigest, map[bool]string{true: "root", false: "sing-box"}[rootRuntime], directoryMode, fileMode, singDigest)
	for name, body := range map[string][]byte{"xray.json": xray, "sing-box.json": singBox, "manifests.json": []byte(manifests)} {
		if err := os.WriteFile(filepath.Join(prepared, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
