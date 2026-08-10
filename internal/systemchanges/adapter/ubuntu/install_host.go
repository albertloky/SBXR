package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
	output           func(context.Context, string, ...string) ([]byte, error)
	managed          bool
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
	return InstallHost{root: root, uid: 0, xrayGID: xrayGID, singGID: singGID, units: append([]string(nil), units...), run: runInstallCommand, output: runInstallOutput, managed: true}, nil
}

func NewFreshInstallHost(root string, units []string) (InstallHost, error) {
	if !slices.Equal(units, fixedInstallUnits) {
		return InstallHost{}, errors.New("managed units unavailable")
	}
	return InstallHost{root: root, uid: 0, xrayGID: -1, singGID: -1, units: append([]string(nil), units...), run: runInstallCommand, output: runInstallOutput}, nil
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
	if host.managed {
		var resolveErr error
		host, resolveErr = host.resolved()
		if resolveErr != nil {
			return resolveErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, unit := range []string{"xray.service", "sing-box.service"} {
			if host.command(ctx, "systemctl", "is-active", unit) != nil {
				return errors.New("managed service rollback state unavailable")
			}
		}
		xray, err := host.readManagedConfiguration("etc/sbxr/xray/config.json", host.xrayGID)
		if err != nil {
			return err
		}
		singBox, err := host.readManagedConfiguration("etc/sbxr/sing-box/config.json", host.singGID)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(installRollback{Xray: xray, SingBox: singBox, ServicesActive: true})
		if err != nil {
			return err
		}
		return write(bytes.NewReader(encoded))
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
	restart := make([]string, 0, 2)
	if host.managed {
		for name, unit := range map[string]string{"etc/sbxr/xray/config.json": "xray.service", "etc/sbxr/sing-box/config.json": "sing-box.service"} {
			gid := host.xrayGID
			if unit == "sing-box.service" {
				gid = host.singGID
			}
			current, readErr := host.readManagedConfiguration(name, gid)
			if readErr != nil {
				return systemchanges.StepEvidence{}, readErr
			}
			if !bytes.Equal(current, prepared[name]) {
				restart = append(restart, unit)
			}
		}
	} else {
		restart = append(restart, "xray.service", "sing-box.service")
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
	if !slices.Equal(host.units, fixedInstallUnits) || host.command(ctx, "systemctl", "daemon-reload") != nil || host.command(ctx, "systemctl", append([]string{"enable"}, host.activeUnits()...)...) != nil {
		return systemchanges.StepEvidence{}, errors.New("managed service activation failed")
	}
	for _, unit := range restart {
		if host.command(ctx, "systemctl", "restart", unit) != nil {
			return systemchanges.StepEvidence{}, errors.New("managed service activation failed")
		}
	}
	if cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("install cancelled at a safe checkpoint")
	}
	digest := sha256.Sum256(append(append([]byte(nil), prepared["etc/sbxr/xray/config.json"]...), prepared["etc/sbxr/sing-box/config.json"]...))
	return systemchanges.StepEvidence{Code: "connection-profiles-activated", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (host InstallHost) Reverse(step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	body, err := io.ReadAll(io.LimitReader(snapshot, 1<<20))
	if !connectionProfilesInstallStep(step) || err != nil {
		return systemchanges.StepEvidence{}, errors.New("install host rollback refused")
	}
	if host.managed {
		prior, err := parseInstallRollback(body)
		if err != nil {
			return systemchanges.StepEvidence{}, err
		}
		host, err = host.resolved()
		if err != nil {
			return systemchanges.StepEvidence{}, err
		}
		for name, configuration := range map[string][]byte{"etc/sbxr/xray/config.json": prior.Xray, "etc/sbxr/sing-box/config.json": prior.SingBox} {
			gid := host.xrayGID
			if name == "etc/sbxr/sing-box/config.json" {
				gid = host.singGID
			}
			if err := writeInstallConfiguration(host.root, name, configuration, host.uid, gid); err != nil {
				return systemchanges.StepEvidence{}, err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if host.command(ctx, "systemctl", "restart", "xray.service") != nil || host.command(ctx, "systemctl", "restart", "sing-box.service") != nil {
			return systemchanges.StepEvidence{}, errors.New("managed service rollback failed")
		}
		digest := sha256.Sum256(body)
		return systemchanges.StepEvidence{Code: "connection-profiles-restored", SHA256: hex.EncodeToString(digest[:])}, nil
	}
	if string(body) != `{"absent":true}` {
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
	if !connectionProfilesInstallStep(step) || err != nil {
		return "", errors.New("install host inspection refused")
	}
	if host.managed {
		prior, err := parseInstallRollback(body)
		if err != nil {
			return "", err
		}
		active := make(map[string][]byte, 2)
		for _, name := range installConfigurationPaths() {
			active[name], err = os.ReadFile(filepath.Join(host.root, name))
			if err != nil {
				return "", errors.New("managed configuration inspection failed")
			}
		}
		if bytes.Equal(active["etc/sbxr/xray/config.json"], prior.Xray) && bytes.Equal(active["etc/sbxr/sing-box/config.json"], prior.SingBox) {
			return systemchanges.StepEffectAbsent, nil
		}
		candidate, err := host.preparedConfigurations()
		if err == nil && bytes.Equal(active["etc/sbxr/xray/config.json"], candidate["etc/sbxr/xray/config.json"]) && bytes.Equal(active["etc/sbxr/sing-box/config.json"], candidate["etc/sbxr/sing-box/config.json"]) {
			return systemchanges.StepEffectPresent, nil
		}
		return "", errors.New("managed Connection Profiles effect is contradictory")
	}
	if string(body) != `{"absent":true}` {
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

type installRollback struct {
	Xray, SingBox  []byte
	ServicesActive bool
}

func parseInstallRollback(body []byte) (installRollback, error) {
	var snapshot installRollback
	if json.Unmarshal(body, &snapshot) != nil || len(snapshot.Xray) == 0 || len(snapshot.SingBox) == 0 || !snapshot.ServicesActive {
		return installRollback{}, errors.New("managed install rollback snapshot unavailable")
	}
	return snapshot, nil
}

func (host InstallHost) readManagedConfiguration(name string, gid int) ([]byte, error) {
	file, err := os.Open(filepath.Join(host.root, name))
	if err != nil {
		return nil, errors.New("managed rollback configuration unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 || stat.Uid != uint32(host.uid) || stat.Gid != uint32(gid) || stat.Nlink != 1 {
		return nil, errors.New("managed rollback configuration identity changed")
	}
	body, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil || len(body) == 0 {
		return nil, errors.New("managed rollback configuration unavailable")
	}
	return body, nil
}

func (host InstallHost) VerifyStartingServices(recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	if recovery.Starting.Status == systemchanges.Managed {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		for _, name := range installConfigurationPaths() {
			if _, err := os.Lstat(filepath.Join(host.root, name)); err != nil {
				return errors.New("managed rollback configuration is unavailable")
			}
		}
		for _, unit := range []string{"xray.service", "sing-box.service", "sbxr-subscription.service"} {
			if host.command(ctx, "systemctl", "is-active", unit) != nil {
				return errors.New("managed rollback service is unavailable")
			}
		}
		return nil
	}
	if recovery.Starting.Status != systemchanges.NotInstalled {
		return errors.New("recovery starting lineage changed")
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
		if check.Code == "CONNECTION-PROFILES-CLIENT-ACCESS-LISTENERS" {
			if host.verifyClientAccessListeners(ctx) == nil {
				return systemchanges.Healthy, nil
			}
			return systemchanges.Failed, nil
		}
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
	if agreement.Revision == 0 || agreement.ChangeSet == "" || agreement.CandidateSHA256 == "" || agreement.PublishedStateSHA256 == "" || agreement.PreparedManifestSHA256 == "" {
		return errors.New("Managed agreement is incomplete")
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
	if agreement.Status == systemchanges.Managed {
		if agreement.Revision == 0 || agreement.SHA256 == "" {
			return errors.New("Managed rollback agreement failed")
		}
		return nil
	}
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
	_, err := runInstallOutput(ctx, name, arguments...)
	return err
}

func runInstallOutput(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdin, command.Stderr = bytes.NewReader(nil), io.Discard
	return command.Output()
}

func (host InstallHost) verifyClientAccessListeners(ctx context.Context) error {
	if host.output == nil {
		return errors.New("listener observation unavailable")
	}
	type inbound struct {
		Type, Listen string
		Port         uint16 `json:"port"`
		ListenPort   uint16 `json:"listen_port"`
	}
	expected := map[string]int{}
	prepared, err := host.preparedConfigurations()
	if err != nil {
		return errors.New("reviewed listener configuration unavailable")
	}
	for _, item := range []struct{ path, protocol, service string }{{"etc/sbxr/xray/config.json", "tcp", "xray"}, {"etc/sbxr/sing-box/config.json", "", "sing-box"}} {
		body, err := os.ReadFile(filepath.Join(host.root, item.path))
		candidate := prepared[item.path]
		var document struct {
			Inbounds []inbound `json:"inbounds"`
		}
		if err != nil || !bytes.Equal(body, candidate) || json.Unmarshal(candidate, &document) != nil {
			return errors.New("active listener configuration unavailable")
		}
		for _, got := range document.Inbounds {
			protocol, port := item.protocol, got.Port
			if port == 0 {
				port = got.ListenPort
			}
			if protocol == "" {
				protocol = "tcp"
				if got.Type == "hysteria2" || got.Type == "tuic" {
					protocol = "udp"
				}
			}
			if got.Listen == "" || port == 0 {
				return errors.New("active listener configuration is incomplete")
			}
			expected[protocol+"\x00"+net.JoinHostPort(got.Listen, strconv.Itoa(int(port)))+"\x00"+item.service]++
		}
	}
	observed, err := host.output(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return err
	}
	actual := map[string]int{}
	for _, line := range strings.Split(string(observed), "\n") {
		service := ""
		for _, candidate := range []string{"xray", "sing-box"} {
			if strings.Contains(line, `(("`+candidate+`",`) {
				service = candidate
				break
			}
		}
		if service == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return errors.New("selected listener observation malformed")
		}
		endpoint := ""
		for _, field := range fields[1:] {
			_, port, splitErr := net.SplitHostPort(field)
			if splitErr == nil {
				if _, numberErr := strconv.ParseUint(port, 10, 16); numberErr == nil {
					endpoint = field
					break
				}
			}
		}
		if endpoint == "" {
			return errors.New("selected listener observation malformed")
		}
		actual[strings.ToLower(fields[0])+"\x00"+endpoint+"\x00"+service]++
	}
	if !reflect.DeepEqual(actual, expected) {
		return errors.New("selected listener agreement failed")
	}
	return nil
}
