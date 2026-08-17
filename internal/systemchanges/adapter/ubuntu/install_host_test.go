package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
	xray := []byte(`{"inbounds":[{"tag":"xray"}]}`)
	writePreparedRealityInstall(t, prepared, xray)
	var commands []string
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(_ context.Context, name string, arguments ...string) error {
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
	for name, want := range map[string][]byte{"etc/sbxr/xray/config.json": xray} {
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
	if !slices.Contains(commands, "systemctl disable --now cloudflared.service sing-box.service") || !slices.Contains(commands, "systemctl enable --now xray.service") || slices.Contains(commands, "systemctl enable --now sbxr-cert-renew.timer sbxr-health-check.timer sbxr-subscription.service sbxr-update-check.timer xray.service") || slices.Contains(commands, "systemctl restart sing-box.service") {
		t.Fatalf("revision 1 service state = %v", commands)
	}
}

func TestFreshInstallAgreementRequiresDeferredServicesInactiveAndDisabled(t *testing.T) {
	deferredActive, xrayDisabled := false, false
	host := InstallHost{run: func(_ context.Context, name string, arguments ...string) error {
		if name == "systemctl" && len(arguments) == 2 && arguments[0] == "is-enabled" && arguments[1] == "xray.service" && xrayDisabled {
			return fmt.Errorf("xray is disabled")
		}
		if name == "systemctl" && len(arguments) == 2 && slices.Contains(revisionOneInactiveUnits, arguments[1]) && (arguments[0] == "is-active" || arguments[0] == "is-enabled") && !deferredActive {
			return fmt.Errorf("%s is inactive", arguments[1])
		}
		return nil
	}}
	agreement := systemchanges.Agreement{Revision: 1, ChangeSet: "install-revision-1", CandidateSHA256: strings.Repeat("a", 64), PublishedStateSHA256: strings.Repeat("b", 64), PreparedManifestSHA256: strings.Repeat("c", 64)}
	if err := host.VerifyAgreement(agreement, time.Second); err != nil {
		t.Fatal(err)
	}
	deferredActive = true
	if err := host.VerifyAgreement(agreement, time.Second); err == nil {
		t.Fatal("fresh install accepted an active deferred service")
	}
	deferredActive, xrayDisabled = false, true
	if err := host.VerifyAgreement(agreement, time.Second); err == nil {
		t.Fatal("fresh install accepted a disabled active service")
	}
}

func TestFreshInstallHostActivatesInspectsAndReversesPostCertificateUnits(t *testing.T) {
	var commands []string
	healthy := true
	host := InstallHost{run: func(_ context.Context, name string, arguments ...string) error {
		commands = append(commands, name+" "+strings.Join(arguments, " "))
		if !healthy && len(arguments) == 2 && (arguments[0] == "is-active" || arguments[0] == "is-enabled") {
			return errors.New("unit unavailable")
		}
		return nil
	}}
	if err := host.activatePostCertificateUnits(time.Second); err != nil || host.inspectPostCertificateUnits(time.Second) != nil || host.reversePostCertificateUnits(time.Second) != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "systemctl enable --now sbxr-cert-renew.timer sbxr-health-check.timer sbxr-subscription.service sbxr-update-check.timer") || !slices.Contains(commands, "systemctl disable --now sbxr-cert-renew.timer sbxr-health-check.timer sbxr-subscription.service sbxr-update-check.timer") {
		t.Fatalf("post-certificate lifecycle = %v", commands)
	}
	healthy = false
	if host.inspectPostCertificateUnits(time.Second) == nil {
		t.Fatal("post-certificate inspection accepted an unavailable unit")
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
	xray := []byte(`{"inbounds":[{"tag":"xray"}]}`)
	writePreparedRealityInstall(t, prepared, xray)
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
	step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/sbxr/xray/config.json"} {
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

func TestInstallHostRefusesLegacyServiceIdentityManifest(t *testing.T) {
	root := t.TempDir()
	prepared := filepath.Join(root, transactionDirectory, "legacy-runtime-refusal", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil || os.MkdirAll(filepath.Join(root, "etc/sbxr"), 0o755) != nil {
		t.Fatal("prepare test root")
	}
	writePreparedRealityInstall(t, prepared, []byte(`{"xray":true}`))
	manifestPath := filepath.Join(prepared, "manifests.json")
	manifests, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifests = bytes.Replace(manifests, []byte(`"Group":"root"`), []byte(`"Group":"xray"`), 1)
	manifests = bytes.Replace(manifests, []byte(`"Group":"root"`), []byte(`"Group":"sing-box"`), 1)
	manifests = bytes.ReplaceAll(manifests, []byte(`"DirectoryMode":493`), []byte(`"DirectoryMode":488`))
	manifests = bytes.ReplaceAll(manifests, []byte(`"FileMode":420`), []byte(`"FileMode":416`))
	if err := os.WriteFile(manifestPath, manifests, 0o600); err != nil {
		t.Fatal(err)
	}
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
	step, _ := systemchanges.NewStep(systemchanges.ConnectionProfilesModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if _, err := host.Execute(step, time.Second, systemchanges.NewCancellation()); err == nil {
		t.Fatal("InstallHost accepted the removed service-identity artifact form")
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
			writePreparedRealityInstall(t, prepared, []byte(`{"xray":true}`))
			if err := test.change(root, prepared); err != nil {
				t.Fatal(err)
			}
			host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
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
	if err := os.MkdirAll(prepared, 0o700); err != nil || os.MkdirAll(filepath.Join(root, "etc/sbxr/xray"), 0o755) != nil {
		t.Fatal("prepare test root")
	}
	writePreparedRealityInstall(t, prepared, []byte(`{"xray":true}`))
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), run: func(context.Context, string, ...string) error { return nil }}
	for _, name := range []string{"etc/sbxr/xray/config.json"} {
		if err := os.WriteFile(filepath.Join(root, name+".preparing"), []byte("interrupted"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
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
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil || os.WriteFile(path, []byte(body), 0o644) != nil {
			t.Fatal("write active configuration")
		}
	}
	prepared := filepath.Join(root, transactionDirectory, "client-access-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal("write reviewed configuration")
	}
	writePreparedInstall(t, prepared, []byte(`{"inbounds":[{"listen":"127.0.0.1","port":11080}]}`), []byte(`{"inbounds":[{"type":"tuic","listen":"0.0.0.0","listen_port":8443}]}`))
	listeners := []byte("tcp LISTEN 0 4096 127.0.0.1:11080 0.0.0.0:* users:((\"xray\",pid=1,fd=1))\nudp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"sing-box\",pid=2,fd=2))\n")
	host := InstallHost{root: root, managed: true, output: func(context.Context, string, ...string) ([]byte, error) { return listeners, nil }}
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
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil || os.WriteFile(path, body, 0o644) != nil {
			t.Fatal("write prior configuration")
		}
	}
	prepared := filepath.Join(root, transactionDirectory, "client-access-0001", "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal("write prepared configuration")
	}
	writePreparedInstall(t, prepared, []byte(`{"next":"xray"}`), []byte(`{"next":"sing-box"}`))
	var commands []string
	host := InstallHost{root: root, uid: os.Geteuid(), rootGID: os.Getegid(), units: append([]string(nil), fixedInstallUnits...), managed: true, run: func(_ context.Context, name string, arguments ...string) error {
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

func writePreparedInstall(t *testing.T, prepared string, xray, singBox []byte) {
	t.Helper()
	xrayDigest, singDigest := sha256.Sum256(xray), sha256.Sum256(singBox)
	manifests := fmt.Sprintf(`{"xray":{"Service":"xray.service","OwningModule":"connectionprofiles","CandidateRevision":8,"ChangeSet":"change-0008","Owner":"root","Group":"root","DirectoryMode":493,"FileMode":420,"SHA256":"%x"},"sing_box":{"Service":"sing-box.service","OwningModule":"connectionprofiles","CandidateRevision":8,"ChangeSet":"change-0008","Owner":"root","Group":"root","DirectoryMode":493,"FileMode":420,"SHA256":"%x"}}`, xrayDigest, singDigest)
	for name, body := range map[string][]byte{"xray.json": xray, "sing-box.json": singBox, "manifests.json": []byte(manifests)} {
		if err := os.WriteFile(filepath.Join(prepared, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writePreparedRealityInstall(t *testing.T, prepared string, xray []byte) {
	t.Helper()
	digest := sha256.Sum256(xray)
	manifests := fmt.Sprintf(`{"xray":{"Service":"xray.service","OwningModule":"connectionprofiles","CandidateRevision":1,"ChangeSet":"install-revision-1","Owner":"root","Group":"root","DirectoryMode":493,"FileMode":420,"SHA256":"%x"}}`, digest)
	for name, body := range map[string][]byte{"xray.json": xray, "manifests.json": []byte(manifests)} {
		if err := os.WriteFile(filepath.Join(prepared, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
