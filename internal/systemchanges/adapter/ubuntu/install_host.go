package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

var fixedInstallUnits = []string{"cloudflared.service", "sbxr-cert-renew.service", "sbxr-cert-renew.timer", "sbxr-health-check.service", "sbxr-health-check.timer", "sbxr-recovery.service", "sbxr-subscription.service", "sbxr-update-check.service", "sbxr-update-check.timer", "sing-box.service", "xray.service"}

// InstallHost owns the remaining fixed Ubuntu effects for the first install:
// activating the prepared proxy-core configurations and systemd lifecycle.
type InstallHost struct {
	root             string
	uid              int
	xrayGID, singGID int
	units            []string
	run              func(context.Context, string, ...string) error
}

func NewInstallHost(root string, units []string) (InstallHost, error) {
	xrayGID, err := installGroupID("xray")
	if err != nil {
		return InstallHost{}, err
	}
	singGID, err := installGroupID("sing-box")
	if err != nil {
		return InstallHost{}, err
	}
	if !slices.Equal(units, fixedInstallUnits) {
		return InstallHost{}, errors.New("managed units unavailable")
	}
	return InstallHost{root: root, uid: 0, xrayGID: xrayGID, singGID: singGID, units: append([]string(nil), units...), run: runInstallCommand}, nil
}

func NewFreshInstallHost(root string, units []string) (InstallHost, error) {
	if !slices.Equal(units, fixedInstallUnits) {
		return InstallHost{}, errors.New("managed units unavailable")
	}
	return InstallHost{root: root, uid: 0, xrayGID: -1, singGID: -1, units: append([]string(nil), units...), run: runInstallCommand}, nil
}

func (host InstallHost) resolved() (InstallHost, error) {
	if host.xrayGID >= 0 && host.singGID >= 0 {
		return host, nil
	}
	var err error
	host.xrayGID, err = installGroupID("xray")
	if err != nil {
		return InstallHost{}, err
	}
	host.singGID, err = installGroupID("sing-box")
	return host, err
}

func (host InstallHost) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	if !connectionProfilesInstallStep(step) || write == nil {
		return errors.New("install host rollback capture unavailable")
	}
	for _, name := range installConfigurationPaths() {
		if _, err := os.Lstat(filepath.Join(host.root, name)); !errors.Is(err, fs.ErrNotExist) {
			return errors.New("an SBXR configuration target already exists")
		}
	}
	return write(strings.NewReader(`{"absent":true}`))
}

func (host InstallHost) Execute(step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	if !connectionProfilesInstallStep(step) || timeout <= 0 || cancellation == nil || cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("install host step refused")
	}
	var resolveErr error
	host, resolveErr = host.resolved()
	if resolveErr != nil {
		return systemchanges.StepEvidence{}, resolveErr
	}
	prepared, err := host.preparedConfigurations()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	groups := map[string]int{"etc/sbxr/xray/config.json": host.xrayGID, "etc/sbxr/sing-box/config.json": host.singGID}
	for name, body := range prepared {
		gid, ok := groups[name]
		if !ok {
			return systemchanges.StepEvidence{}, errors.New("prepared configuration owner unavailable")
		}
		if err := writeInstallConfiguration(host.root, name, body, host.uid, gid); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if !slices.Equal(host.units, fixedInstallUnits) || host.command(ctx, "systemctl", "daemon-reload") != nil || host.command(ctx, "systemctl", append([]string{"enable"}, host.activeUnits()...)...) != nil || host.command(ctx, "systemctl", "restart", "xray.service") != nil {
		return systemchanges.StepEvidence{}, errors.New("managed service activation failed")
	}
	if cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("install cancelled at a safe checkpoint")
	}
	digest := sha256.Sum256(append(append([]byte(nil), prepared["etc/sbxr/xray/config.json"]...), prepared["etc/sbxr/sing-box/config.json"]...))
	return systemchanges.StepEvidence{Code: "connection-profiles-activated", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (host InstallHost) Reverse(step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	body, err := io.ReadAll(io.LimitReader(snapshot, 1<<20))
	if !connectionProfilesInstallStep(step) || err != nil || string(body) != `{"absent":true}` {
		return systemchanges.StepEvidence{}, errors.New("install host rollback refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	active := host.activeUnits()
	if !slices.Equal(host.units, fixedInstallUnits) || host.command(ctx, "systemctl", append([]string{"disable", "--now"}, active...)...) != nil {
		return systemchanges.StepEvidence{}, errors.New("managed service rollback failed")
	}
	for _, name := range installConfigurationPaths() {
		if err := os.Remove(filepath.Join(host.root, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return systemchanges.StepEvidence{}, err
		}
	}
	for _, directory := range []string{"etc/sbxr/xray", "etc/sbxr/sing-box"} {
		_ = os.Remove(filepath.Join(host.root, directory))
	}
	digest := sha256.Sum256(body)
	return systemchanges.StepEvidence{Code: "connection-profiles-removed", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (host InstallHost) HoldServices() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, unit := range host.activeUnits() {
		_ = host.command(ctx, "systemctl", "stop", unit)
	}
	return nil
}

func (host InstallHost) AllowProvenServices(recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	if recovery.LastCheckpoint != systemchanges.Complete {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return host.command(ctx, "systemctl", append([]string{"start"}, host.activeUnits()...)...)
}

func (host InstallHost) activeUnits() []string {
	result := make([]string, 0, len(host.units))
	for _, unit := range host.units {
		if unit != "sbxr-recovery.service" {
			result = append(result, unit)
		}
	}
	return result
}

func (host InstallHost) InspectStep(step systemchanges.Step, snapshot io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	body, err := io.ReadAll(io.LimitReader(snapshot, 1<<20))
	if !connectionProfilesInstallStep(step) || err != nil || string(body) != `{"absent":true}` {
		return "", errors.New("install host inspection refused")
	}
	present := 0
	for _, name := range installConfigurationPaths() {
		if _, err := os.Lstat(filepath.Join(host.root, name)); err == nil {
			present++
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	if present == 0 {
		return systemchanges.StepEffectAbsent, nil
	}
	if present == len(installConfigurationPaths()) {
		return systemchanges.StepEffectPresent, nil
	}
	return "", errors.New("partial Connection Profiles activation")
}

func (host InstallHost) VerifyStartingServices(recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	if recovery.Starting.Status != systemchanges.NotInstalled {
		return errors.New("install recovery starting lineage changed")
	}
	for _, name := range installConfigurationPaths() {
		if _, err := os.Lstat(filepath.Join(host.root, name)); !errors.Is(err, fs.ErrNotExist) {
			return errors.New("install rollback retained configuration")
		}
	}
	return nil
}

func (host InstallHost) Check(check systemchanges.Check, _ systemchanges.GatePhase, timeout time.Duration) (systemchanges.HealthStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	switch check.Owner {
	case systemchanges.ConnectionProfilesModule:
		if host.command(ctx, "systemctl", "is-active", "xray.service") == nil && host.command(ctx, "systemctl", "is-active", "sing-box.service") == nil {
			return systemchanges.Healthy, nil
		}
	case systemchanges.NetworkPolicyModule:
		if host.command(ctx, "nft", "list", "table", "inet", "sbxr") == nil {
			return systemchanges.Healthy, nil
		}
	default:
		return systemchanges.Unknown, errors.New("install host check is not owned here")
	}
	return systemchanges.Failed, nil
}

func (host InstallHost) VerifyAgreement(agreement systemchanges.Agreement, timeout time.Duration) error {
	if agreement.Revision != 1 || agreement.ChangeSet == "" || agreement.CandidateSHA256 == "" || agreement.PublishedStateSHA256 == "" || agreement.PreparedManifestSHA256 == "" {
		return errors.New("revision 1 agreement is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, unit := range []string{"xray.service", "sing-box.service", "cloudflared.service", "sbxr-subscription.service", "sbxr-cert-renew.timer", "sbxr-health-check.timer", "sbxr-update-check.timer"} {
		if host.command(ctx, "systemctl", "is-active", unit) != nil {
			return errors.New("managed unit agreement failed")
		}
	}
	return nil
}

func (host InstallHost) VerifyRollback(agreement systemchanges.RollbackAgreement, _ time.Duration) error {
	if agreement.Status != systemchanges.NotInstalled || agreement.Revision != 0 || agreement.SHA256 != "" {
		return errors.New("Not installed rollback agreement failed")
	}
	return nil
}

func (host InstallHost) preparedConfigurations() (map[string][]byte, error) {
	entries, err := os.ReadDir(filepath.Join(host.root, transactionDirectory))
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return nil, errors.New("active install transaction unavailable")
	}
	base := filepath.Join(host.root, transactionDirectory, entries[0].Name(), "prepared")
	result := map[string][]byte{}
	for source, destination := range map[string]string{"xray.json": "etc/sbxr/xray/config.json", "sing-box.json": "etc/sbxr/sing-box/config.json"} {
		body, err := os.ReadFile(filepath.Join(base, source))
		if err != nil || len(body) == 0 {
			return nil, errors.New("prepared Connection Profiles configuration unavailable")
		}
		result[destination] = body
	}
	return result, nil
}

func (host InstallHost) command(ctx context.Context, name string, arguments ...string) error {
	if host.run == nil {
		return errors.New("install command runner unavailable")
	}
	return host.run(ctx, name, arguments...)
}

func connectionProfilesInstallStep(step systemchanges.Step) bool {
	return step.Owner() == systemchanges.ConnectionProfilesModule && step.Forward() == systemchanges.ActivatePreparedConfiguration && step.Rollback() == systemchanges.RestorePriorConfiguration
}

func installConfigurationPaths() []string {
	return []string{"etc/sbxr/xray/config.json", "etc/sbxr/sing-box/config.json"}
}

func writeInstallConfiguration(root, name string, body []byte, uid, gid int) error {
	directory := filepath.Dir(filepath.Join(root, name))
	if err := os.Mkdir(directory, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := os.Chown(directory, uid, gid); err != nil || os.Chmod(directory, 0o750) != nil {
		return errors.New("managed configuration directory ownership failed")
	}
	temporary := filepath.Join(root, name+".preparing")
	if err := os.WriteFile(temporary, body, 0o640); err != nil {
		return err
	}
	if err := os.Chown(temporary, uid, gid); err != nil || os.Chmod(temporary, 0o640) != nil {
		_ = os.Remove(temporary)
		return errors.New("managed configuration ownership failed")
	}
	if err := os.Rename(temporary, filepath.Join(root, name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func installGroupID(name string) (int, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, errors.New("managed service group unavailable")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return 0, errors.New("managed service group is invalid")
	}
	return gid, nil
}

func runInstallCommand(ctx context.Context, name string, arguments ...string) error {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(nil), io.Discard, io.Discard
	return command.Run()
}
