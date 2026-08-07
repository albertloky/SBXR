package ubuntu

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type TransactionExecutor struct {
	now      func() time.Time
	roots    *x509.CertPool
	uid, gid int
	run      func(context.Context, string, ...string) error
	prove    func(context.Context, string) error
}

func NewTransactionExecutor() (TransactionExecutor, error) {
	group, err := user.LookupGroup("sbxr-subscription")
	if err != nil {
		return TransactionExecutor{}, errors.New("sbxr-subscription group unavailable")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return TransactionExecutor{}, errors.New("sbxr-subscription group is invalid")
	}
	return TransactionExecutor{now: time.Now, uid: 0, gid: gid, run: runCertificateCommand, prove: proveSubscriptionHTTPS}, nil
}

func (executor TransactionExecutor) CaptureRollback(root string, step systemchanges.Step, write func(io.Reader) error) error {
	change, ok := step.CertificateChange()
	if !ok {
		return errors.New("certificate step unavailable")
	}
	snapshot := struct {
		Target string `json:"target,omitempty"`
	}{}
	if change.Action == systemchanges.CertificateIPActivate {
		target, err := os.Readlink(filepath.Join(root, "var/lib/sbxr/certificates/ip/current"))
		if err == nil {
			if !safeServingTarget(target) {
				return errors.New("unsafe active certificate pointer")
			}
			snapshot.Target = target
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("active certificate pointer is unprovable")
		}
	}
	encoded, _ := json.Marshal(snapshot)
	return write(strings.NewReader(string(encoded)))
}

func (executor TransactionExecutor) Execute(root string, step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	change, ok := step.CertificateChange()
	if !ok || cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("certificate action cancelled or invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	switch change.Action {
	case systemchanges.CertificateIPStage, systemchanges.CertificateIPOrder:
		order := certificatelifecycle.OrderContract{Lineage: certificatelifecycle.IPLineage, RequiredProfile: change.RequiredProfile, Identity: change.Identity, CertName: change.CertName, OwnerEmail: change.OwnerEmail, Staging: change.Action == systemchanges.CertificateIPStage, ConfigDirectory: change.ConfigDirectory, Account: change.Account}
		arguments, err := Arguments(order)
		if err != nil || executor.command(ctx, arguments[0], arguments[1:]...) != nil {
			return systemchanges.StepEvidence{}, errors.New("bounded Certbot order failed")
		}
		if err := validateIPCandidate(root, change, executor.clock(), executor.roots, executor.uid, change.Action == systemchanges.CertificateIPOrder); err != nil {
			return systemchanges.StepEvidence{}, err
		}
		if change.Action == systemchanges.CertificateIPOrder {
			_ = os.RemoveAll(filepath.Join(root, "var/lib/sbxr/certbot/staging/sbxr-ip"))
		}
		code := "certificate-ip-staged"
		if change.Action == systemchanges.CertificateIPOrder {
			code = "certificate-ip-ordered"
		}
		return certificateEvidence(code, change), nil
	case systemchanges.CertificateIPActivate:
		if err := ValidateIPCandidate(root, productionChange(change), executor.clock(), executor.roots, executor.uid); err != nil {
			return systemchanges.StepEvidence{}, err
		}
		if err := executor.activate(root, change); err != nil {
			return systemchanges.StepEvidence{}, err
		}
		if err := executor.command(ctx, "systemctl", "reload-or-restart", change.SubscriptionUnit); err != nil {
			return systemchanges.StepEvidence{}, errors.New("Subscription Serving restart failed")
		}
		if err := executor.proof(ctx, change.Identity); err != nil {
			return systemchanges.StepEvidence{}, errors.New("Subscription Serving HTTPS proof failed")
		}
		return certificateEvidence("certificate-ip-activated", change), nil
	default:
		return systemchanges.StepEvidence{}, errors.New("unsupported certificate action")
	}
}

func (executor TransactionExecutor) Reverse(root string, step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	change, ok := step.CertificateChange()
	if !ok {
		return systemchanges.StepEvidence{}, errors.New("certificate rollback unavailable")
	}
	switch change.Action {
	case systemchanges.CertificateIPStage:
		if err := os.RemoveAll(filepath.Join(root, "var/lib/sbxr/certbot/staging/sbxr-ip")); err != nil {
			return systemchanges.StepEvidence{}, errors.New("staging cleanup failed")
		}
	case systemchanges.CertificateIPOrder:
		// Certbot's lineage is deliberately preserved; activation owns rollback.
	case systemchanges.CertificateIPActivate:
		var prior struct {
			Target string `json:"target,omitempty"`
		}
		if json.NewDecoder(io.LimitReader(snapshot, 4096)).Decode(&prior) != nil || prior.Target != "" && !safeServingTarget(prior.Target) {
			return systemchanges.StepEvidence{}, errors.New("prior certificate pointer is invalid")
		}
		candidate := candidateServingTarget(root, executor.uid)
		if err := switchServingPointer(root, prior.Target); err != nil {
			return systemchanges.StepEvidence{}, errors.New("prior certificate pointer restore failed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if executor.command(ctx, "systemctl", "reload-or-restart", change.SubscriptionUnit) != nil {
			return systemchanges.StepEvidence{}, errors.New("prior Subscription Serving restart failed")
		}
		if prior.Target != "" && executor.proof(ctx, change.Identity) != nil {
			return systemchanges.StepEvidence{}, errors.New("prior Subscription Serving proof failed")
		}
		if candidate != "" && candidate != prior.Target {
			directory := filepath.Join(root, "var/lib/sbxr/certificates/ip", candidate)
			if safeServingDirectory(directory, executor.uid, executor.gid) == nil {
				_ = os.RemoveAll(directory)
			}
		}
	}
	return certificateEvidence("certificate-ip-rollback", change), nil
}

func (executor TransactionExecutor) Inspect(root string, step systemchanges.Step, snapshot io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	change, ok := step.CertificateChange()
	if !ok {
		return "", errors.New("certificate inspection unavailable")
	}
	if change.Action != systemchanges.CertificateIPActivate {
		trusted := change.Action == systemchanges.CertificateIPOrder
		if validateIPCandidate(root, change, executor.clock(), executor.roots, executor.uid, trusted) == nil {
			return systemchanges.StepEffectPresent, nil
		}
		return systemchanges.StepEffectAbsent, nil
	}
	var prior struct {
		Target string `json:"target,omitempty"`
	}
	if json.NewDecoder(io.LimitReader(snapshot, 4096)).Decode(&prior) != nil {
		return "", errors.New("certificate snapshot is invalid")
	}
	current, err := os.Readlink(filepath.Join(root, "var/lib/sbxr/certificates/ip/current"))
	if errors.Is(err, os.ErrNotExist) {
		current = ""
	} else if err != nil {
		return "", err
	}
	if current == prior.Target {
		return systemchanges.StepEffectAbsent, nil
	}
	return systemchanges.StepEffectPresent, nil
}

func (executor TransactionExecutor) Check(root, code string, _ systemchanges.GatePhase, timeout time.Duration) (systemchanges.HealthStatus, error) {
	identity, servingErr := servingIPIdentity(root, executor.roots, executor.clock(), executor.uid, executor.gid)
	change := systemchanges.CertificateChange{Action: systemchanges.CertificateIPOrder, Identity: identity, RequiredProfile: "shortlived", CertName: "sbxr-ip", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"}
	if change.Identity == "" {
		return systemchanges.Failed, servingErr
	}
	if code == "CERTIFICATE-IP-CANDIDATE" {
		if err := ValidateIPCandidate(root, change, executor.clock(), executor.roots, executor.uid); err != nil {
			return systemchanges.Failed, err
		}
		return systemchanges.Healthy, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := executor.proof(ctx, change.Identity); err != nil {
		return systemchanges.Failed, errors.New("Subscription Serving HTTPS proof failed")
	}
	return systemchanges.Healthy, nil
}

func (executor TransactionExecutor) Cleanup(root string) error {
	base := filepath.Join(root, "var/lib/sbxr/certificates/ip")
	current, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil || !safeServingTarget(current) {
		return errors.New("current serving certificate pointer is invalid")
	}
	entries, err := os.ReadDir(filepath.Join(base, "sets"))
	if err != nil {
		return errors.New("serving certificate sets are unavailable")
	}
	for _, entry := range entries {
		target := "sets/" + entry.Name()
		if target == current {
			continue
		}
		if !entry.IsDir() || !safeServingTarget(target) {
			return errors.New("unexpected serving certificate set")
		}
		directory := filepath.Join(base, target)
		if safeServingDirectory(directory, executor.uid, executor.gid) != nil {
			return errors.New("old serving certificate set is unsafe")
		}
		children, readErr := os.ReadDir(directory)
		if readErr != nil || len(children) != 2 {
			return errors.New("old serving certificate set is incomplete")
		}
		for _, name := range []string{"fullchain.pem", "privkey.pem"} {
			file := filepath.Join(directory, name)
			if _, fileErr := safeServingFile(file, executor.uid, executor.gid); fileErr != nil || os.Remove(file) != nil {
				return errors.New("old serving certificate file cleanup failed")
			}
		}
		if os.Remove(directory) != nil {
			return errors.New("old serving certificate set cleanup failed")
		}
	}
	return nil
}

func (executor TransactionExecutor) activate(root string, change systemchanges.CertificateChange) error {
	source := filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-ip")
	chain, err := safeFile(filepath.Join(source, "fullchain.pem"), executor.uid, 0o600)
	if err != nil {
		return err
	}
	key, err := safeFile(filepath.Join(source, "privkey.pem"), executor.uid, 0o600)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(chain)
	id := "ip-" + hex.EncodeToString(digest[:8])
	base := filepath.Join(root, "var/lib/sbxr/certificates/ip")
	set := filepath.Join(base, "sets", id)
	for _, directory := range []string{base, filepath.Join(base, "sets"), set} {
		if err := os.MkdirAll(directory, 0o750); err != nil || ensureServingDirectory(directory, executor.uid, executor.gid) != nil {
			return errors.New("serving certificate directory setup failed")
		}
	}
	for name, content := range map[string][]byte{"fullchain.pem": chain, "privkey.pem": key} {
		target := filepath.Join(set, name)
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if errors.Is(err, os.ErrExist) {
			existing, readErr := safeServingFile(target, executor.uid, executor.gid)
			if readErr != nil || string(existing) != string(content) {
				return errors.New("serving certificate version conflicts")
			}
		} else if err != nil {
			return errors.New("serving certificate write failed")
		} else if _, err = file.Write(content); err != nil || file.Sync() != nil || file.Close() != nil {
			return errors.New("serving certificate write failed")
		}
		if os.Chmod(target, 0o640) != nil || os.Chown(target, executor.uid, executor.gid) != nil {
			return errors.New("serving certificate write failed")
		}
	}
	return switchServingPointer(root, "sets/"+id)
}

func switchServingPointer(root, target string) error {
	current := filepath.Join(root, "var/lib/sbxr/certificates/ip/current")
	if target == "" {
		err := os.Remove(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !safeServingTarget(target) {
		return errors.New("unsafe serving target")
	}
	temporary := current + ".new"
	_ = os.Remove(temporary)
	defer os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, current)
}

func safeServingTarget(target string) bool {
	suffix, ok := strings.CutPrefix(target, "sets/ip-")
	if !ok || suffix == "" || len(suffix) > 128 || strings.ContainsAny(suffix, "/\\.") {
		return false
	}
	for _, character := range suffix {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func productionChange(change systemchanges.CertificateChange) systemchanges.CertificateChange {
	change.Action = systemchanges.CertificateIPOrder
	change.OwnerEmail, change.ConfigDirectory, change.Account, change.SubscriptionUnit = "", "/var/lib/sbxr/certbot/production", "production", ""
	return change
}

func candidateServingTarget(root string, uid int) string {
	chain, err := safeFile(filepath.Join(root, "var/lib/sbxr/certbot/production/live/sbxr-ip/fullchain.pem"), uid, 0o600)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(chain)
	return "sets/ip-" + hex.EncodeToString(digest[:8])
}

func servingIPIdentity(root string, roots *x509.CertPool, now time.Time, uid, gid int) (string, error) {
	target, err := os.Readlink(filepath.Join(root, "var/lib/sbxr/certificates/ip/current"))
	if err != nil || !safeServingTarget(target) {
		return "", errors.New("active IP certificate pointer unavailable")
	}
	set := filepath.Join(root, "var/lib/sbxr/certificates/ip", target)
	if err := safeServingDirectory(set, uid, gid); err != nil {
		return "", err
	}
	chain, err := safeServingFile(filepath.Join(set, "fullchain.pem"), uid, gid)
	if err != nil {
		return "", err
	}
	key, err := safeServingFile(filepath.Join(set, "privkey.pem"), uid, gid)
	if err != nil {
		return "", err
	}
	certificates, err := parseCertificates(chain)
	if err != nil || len(certificates) == 0 || len(certificates[0].IPAddresses) != 1 {
		return "", errors.New("active IP certificate identity unavailable")
	}
	address, err := netip.ParseAddr(certificates[0].IPAddresses[0].String())
	if err != nil || validateIPMaterial(chain, key, address, now, roots, true) != nil {
		return "", errors.New("active IP serving pair is invalid")
	}
	return address.String(), nil
}

func ensureServingDirectory(name string, uid, gid int) error {
	if err := os.Chown(name, uid, gid); err != nil || os.Chmod(name, 0o750) != nil {
		return errors.New("serving directory ownership failed")
	}
	return safeServingDirectory(name, uid, gid)
}

func safeServingDirectory(name string, uid, gid int) error {
	info, err := os.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 || fileUID(info) != uid || fileGID(info) != gid {
		return errors.New("serving directory is unsafe")
	}
	return nil
}

func safeServingFile(name string, uid, gid int) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o640 || info.Size() <= 0 || info.Size() > 1<<20 || fileUID(info) != uid || fileGID(info) != gid {
		return nil, errors.New("serving file is unsafe")
	}
	return os.ReadFile(name)
}

func certificateEvidence(code string, change systemchanges.CertificateChange) systemchanges.StepEvidence {
	encoded, _ := json.Marshal(struct {
		Code                    string
		Action                  systemchanges.CertificateAction
		Identity, Profile, Name string
	}{code, change.Action, change.Identity, change.RequiredProfile, change.CertName})
	digest := sha256.Sum256(encoded)
	return systemchanges.StepEvidence{Code: code, SHA256: hex.EncodeToString(digest[:])}
}

func (executor TransactionExecutor) clock() time.Time {
	if executor.now != nil {
		return executor.now().UTC()
	}
	return time.Now().UTC()
}
func (executor TransactionExecutor) command(ctx context.Context, name string, arguments ...string) error {
	if executor.run != nil {
		return executor.run(ctx, name, arguments...)
	}
	return runCertificateCommand(ctx, name, arguments...)
}
func (executor TransactionExecutor) proof(ctx context.Context, identity string) error {
	if executor.prove != nil {
		return executor.prove(ctx, identity)
	}
	return proveSubscriptionHTTPS(ctx, identity)
}

func runCertificateCommand(ctx context.Context, name string, arguments ...string) error {
	output := &limitedOutput{remaining: maximumOutput}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return errors.New("certificate command failed")
	}
	return nil
}

func proveSubscriptionHTTPS(ctx context.Context, identity string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(identity, "10443")+"/", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{}).DialContext}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Subscription Serving returned a non-success status")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return err
}
