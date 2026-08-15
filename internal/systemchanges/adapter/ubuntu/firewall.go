package ubuntu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const firewallWatchdogUnit = "sbxr-firewall-watchdog"

type firewallCommand func(context.Context, []byte, string, ...string) ([]byte, error)

// NativeFirewall applies only the typed inet sbxr contract under the
// transaction Adapter. The global System Changes lock serializes its state.
type NativeFirewall struct {
	run                    firewallCommand
	recordedHandle         uint64
	watchdogDirectory      string
	managerDropInDirectory string
}

func (firewall *NativeFirewall) VerifyReplacement(target systemchanges.FirewallReclamationTarget, timeout time.Duration) error {
	if firewall == nil || firewall.run == nil || timeout <= 0 {
		return errors.New("native firewall replacement unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := firewall.run(ctx, []byte(target.Candidate), "nft", "--check", "--file", "-"); err != nil {
		return errors.New("native firewall replacement candidate invalid")
	}
	manager, err := firewall.run(ctx, nil, "systemctl", "is-active", target.Manager)
	if err != nil || strings.TrimSpace(string(manager)) != "active" {
		return errors.New("reviewed firewall manager changed")
	}
	rules, err := firewall.run(ctx, nil, "nft", "-j", "list", "ruleset")
	digest, objects, outboundDigest, outbound, parseErr := replacementFirewallState(rules)
	if err != nil || parseErr != nil || digest != target.PriorSHA256 || !slices.Equal(objects, target.Objects) || outboundDigest != target.OutboundSHA256 || !slices.Equal(outbound, target.OutboundObjects) {
		return errors.New("reviewed inbound firewall changed")
	}
	return nil
}

func (firewall *NativeFirewall) ReplaceForward(target systemchanges.FirewallReclamationTarget, timeout time.Duration) (systemchanges.StepEvidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	effect, err := firewall.ReplacementState(target, timeout)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if effect == systemchanges.StepEffectAbsent {
		managerState, stateErr := firewall.run(ctx, nil, "systemctl", "is-active", target.Manager)
		if stateErr == nil || strings.TrimSpace(string(managerState)) != "inactive" {
			return systemchanges.StepEvidence{}, errors.New("competing firewall manager returned")
		}
		digest := sha256.Sum256([]byte(target.Candidate))
		return systemchanges.StepEvidence{Code: "inbound-firewall-replaced", SHA256: fmt.Sprintf("%x", digest)}, nil
	}
	manager, managerErr := firewall.run(ctx, nil, "systemctl", "is-active", target.Manager)
	state := strings.TrimSpace(string(manager))
	dropInPath, dropInErr := managerDropIn(firewall.managerDropInDirectory, target.Manager)
	if dropInErr != nil {
		return systemchanges.StepEvidence{}, errors.New("competing firewall manager recovery invalid")
	}
	if managerErr == nil && state == "active" {
		if _, err := firewall.run(ctx, nil, "systemctl", "disable", target.Manager); err != nil {
			return systemchanges.StepEvidence{}, errors.New("competing firewall manager did not stop")
		}
		if dropInPath == "" {
			dropInPath, err = writeManagerDropIn(firewall.managerDropInDirectory, target.Manager)
		}
		if err != nil {
			return systemchanges.StepEvidence{}, errors.New("competing firewall manager did not stop")
		}
		if _, err := firewall.run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			return systemchanges.StepEvidence{}, errors.New("competing firewall manager did not stop")
		}
		if _, err := firewall.run(ctx, nil, "systemctl", "stop", target.Manager); err != nil {
			return systemchanges.StepEvidence{}, errors.New("competing firewall manager did not stop")
		}
		managerState, stateErr := firewall.run(ctx, nil, "systemctl", "is-active", target.Manager)
		if stateErr == nil || strings.TrimSpace(string(managerState)) != "inactive" {
			return systemchanges.StepEvidence{}, errors.New("competing firewall manager remained active")
		}
		if err := firewall.verifyReplacementState(target, ctx); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	} else if state != "inactive" {
		return systemchanges.StepEvidence{}, errors.New("competing firewall manager changed")
	}
	if dropInPath != "" && os.Remove(dropInPath) != nil {
		return systemchanges.StepEvidence{}, errors.New("competing firewall manager cleanup failed")
	}
	if firewall.runError(ctx, "systemctl", "daemon-reload") != nil {
		return systemchanges.StepEvidence{}, errors.New("competing firewall manager cleanup failed")
	}
	script, err := replacementScript(target.Objects, target.Candidate)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	watchdogPath, err := writeForwardFirewallWatchdog(firewall.watchdogDirectory, string(script))
	if err != nil {
		return systemchanges.StepEvidence{}, errors.New("forward firewall watchdog unavailable")
	}
	if err := firewall.armWatchdog(ctx, watchdogPath); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if _, err := firewall.run(ctx, script, "nft", "--file", "-"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("forward inbound firewall replacement failed")
	}
	if err := firewall.verifySSH(ctx, listenerPort(target.Listener)); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if status, err := firewall.ReplacementState(target, timeout); err != nil || status != systemchanges.StepEffectAbsent {
		return systemchanges.StepEvidence{}, errors.New("forward inbound firewall replacement disagrees")
	}
	managerState, stateErr := firewall.run(ctx, nil, "systemctl", "is-active", target.Manager)
	if stateErr == nil || strings.TrimSpace(string(managerState)) != "inactive" {
		return systemchanges.StepEvidence{}, errors.New("competing firewall manager returned")
	}
	if err := firewall.cancelWatchdog(ctx); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := os.Remove(watchdogPath); err != nil {
		return systemchanges.StepEvidence{}, errors.New("forward firewall watchdog cleanup failed")
	}
	digest := sha256.Sum256([]byte(target.Candidate))
	return systemchanges.StepEvidence{Code: "inbound-firewall-replaced", SHA256: fmt.Sprintf("%x", digest)}, nil
}

func writeManagerDropIn(root, manager string) (string, error) {
	if strings.Contains(manager, "/") || manager == "" {
		return "", errors.New("invalid manager")
	}
	directory := filepath.Join(root, manager+".d")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	name := filepath.Join(directory, "90-sbxr-reclamation.conf")
	file, err := os.CreateTemp(directory, ".sbxr-reclamation-*")
	if err != nil {
		return "", err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", err
	}
	_, writeErr := file.WriteString("[Service]\nExecStop=\nExecStopPost=\nRestart=no\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := renameNoReplace(temporary, name); err != nil || syncHostDirectory(directory) != nil {
		return "", errors.New("manager drop-in publication failed")
	}
	return name, nil
}

func managerDropIn(root, manager string) (string, error) {
	name := filepath.Join(root, manager+".d", "90-sbxr-reclamation.conf")
	data, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || string(data) != "[Service]\nExecStop=\nExecStopPost=\nRestart=no\n" {
		return "", errors.New("manager drop-in changed")
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("manager drop-in invalid")
	}
	return name, nil
}

func (firewall *NativeFirewall) runError(ctx context.Context, name string, args ...string) error {
	_, err := firewall.run(ctx, nil, name, args...)
	return err
}

func (firewall *NativeFirewall) verifyReplacementState(target systemchanges.FirewallReclamationTarget, ctx context.Context) error {
	rules, err := firewall.run(ctx, nil, "nft", "-j", "list", "ruleset")
	digest, objects, outboundDigest, outbound, parseErr := replacementFirewallState(rules)
	if err != nil || parseErr != nil || digest != target.PriorSHA256 || !slices.Equal(objects, target.Objects) || outboundDigest != target.OutboundSHA256 || !slices.Equal(outbound, target.OutboundObjects) {
		return errors.New("reviewed firewall changed")
	}
	return nil
}

func writeForwardFirewallWatchdog(directory, candidate string) (string, error) {
	file, err := os.CreateTemp(directory, ".sbxr-firewall-forward-*")
	if err != nil {
		return "", err
	}
	name := file.Name()
	writeErr := file.Chmod(0o600)
	if writeErr == nil {
		_, writeErr = file.WriteString(candidate)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if writeErr == nil {
		writeErr = file.Close()
	}
	if writeErr != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", errors.New("forward firewall watchdog file unavailable")
	}
	return name, nil
}

func (firewall *NativeFirewall) ReplacementState(target systemchanges.FirewallReclamationTarget, timeout time.Duration) (systemchanges.StepEffect, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rules, err := firewall.run(ctx, nil, "nft", "-j", "list", "ruleset")
	if err != nil {
		return "", err
	}
	_, objects, outboundDigest, outbound, parseErr := replacementFirewallState(rules)
	if parseErr != nil {
		return "", parseErr
	}
	if outboundDigest != target.OutboundSHA256 || !slices.Equal(outbound, target.OutboundObjects) {
		return "", errors.New("outbound firewall changed")
	}
	if slices.Equal(objects, target.OutboundObjects) {
		active, err := firewall.run(ctx, nil, "nft", "list", "table", "inet", "sbxr")
		want, wantErr := canonicalNftPolicy([]byte(target.Candidate))
		got, gotErr := canonicalNftPolicy(active)
		if err == nil && wantErr == nil && gotErr == nil && want == got {
			managerState, stateErr := firewall.run(ctx, nil, "systemctl", "is-active", target.Manager)
			if stateErr == nil || strings.TrimSpace(string(managerState)) != "inactive" {
				return "", errors.New("competing firewall manager returned")
			}
			return systemchanges.StepEffectAbsent, nil
		}
	}
	if slices.Equal(objects, target.Objects) {
		return systemchanges.StepEffectPresent, nil
	}
	return "", errors.New("inbound firewall state changed")
}

func replacementFirewallState(data []byte) (string, []string, string, []string, error) {
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &document) != nil {
		return "", nil, "", nil, errors.New("invalid nftables ruleset")
	}
	chains := map[string]bool{}
	for _, item := range document.Nftables {
		var chain struct{ Family, Table, Name, Hook string }
		if raw := item["chain"]; len(raw) > 0 && json.Unmarshal(raw, &chain) == nil && chain.Hook == "input" && !(chain.Family == "inet" && chain.Table == "sbxr") {
			chains[chain.Family+"\x00"+chain.Table+"\x00"+chain.Name] = true
		}
	}
	var objects, outbound []string
	for _, item := range document.Nftables {
		delete(item, "counter")
		if rule := item["rule"]; len(rule) > 0 {
			var value map[string]any
			if json.Unmarshal(rule, &value) == nil {
				delete(value, "counter")
				if expressions, ok := value["expr"].([]any); ok {
					for _, expression := range expressions {
						if object, ok := expression.(map[string]any); ok {
							delete(object, "counter")
						}
					}
				}
				item["rule"], _ = json.Marshal(value)
			}
		}
		var identity struct{ Family, Table, Name, Chain string }
		encoded, _ := json.Marshal(item)
		if strings.Contains(string(encoded), `"family":"inet","name":"sbxr"`) || strings.Contains(string(encoded), `"family":"inet","table":"sbxr"`) {
			continue
		}
		objects = append(objects, string(encoded))
		chainRaw, ruleRaw := item["chain"], item["rule"]
		chainDeleted := len(chainRaw) > 0 && json.Unmarshal(chainRaw, &identity) == nil && chains[identity.Family+"\x00"+identity.Table+"\x00"+identity.Name]
		ruleDeleted := len(ruleRaw) > 0 && json.Unmarshal(ruleRaw, &identity) == nil && chains[identity.Family+"\x00"+identity.Table+"\x00"+identity.Chain]
		if !chainDeleted && !ruleDeleted {
			outbound = append(outbound, string(encoded))
		}
	}
	digest := sha256.Sum256([]byte(strings.Join(objects, "\n")))
	outboundDigest := sha256.Sum256([]byte(strings.Join(outbound, "\n")))
	return fmt.Sprintf("%x", digest), objects, fmt.Sprintf("%x", outboundDigest), outbound, nil
}

func replacementScript(objects []string, candidate string) ([]byte, error) {
	var commands []string
	for _, raw := range objects {
		var item map[string]json.RawMessage
		var chain struct{ Family, Table, Name, Hook string }
		if json.Unmarshal([]byte(raw), &item) != nil || len(item["chain"]) == 0 || json.Unmarshal(item["chain"], &chain) != nil || chain.Hook != "input" {
			continue
		}
		commands = append(commands, fmt.Sprintf("destroy chain %s %s %s", chain.Family, chain.Table, chain.Name))
	}
	if len(commands) == 0 {
		return nil, errors.New("reviewed inbound chains unavailable")
	}
	return []byte("destroy table inet sbxr\n" + strings.Join(commands, "\n") + "\n" + candidate), nil
}

func listenerPort(listener string) uint16 {
	value := strings.TrimSuffix(listener, "/tcp")
	_, port, err := net.SplitHostPort(value)
	parsed, parseErr := strconv.ParseUint(port, 10, 16)
	if err != nil || parseErr != nil {
		return 0
	}
	return uint16(parsed)
}

func NewNativeFirewall() *NativeFirewall { return newNativeFirewall(runFirewallCommand) }

func newNativeFirewall(run firewallCommand) *NativeFirewall {
	return &NativeFirewall{run: run, watchdogDirectory: "/run", managerDropInDirectory: "/run/systemd/system"}
}

func runFirewallCommand(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(stdin)
	return command.Output()
}

func (firewall *NativeFirewall) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	if firewall == nil || firewall.run == nil || write == nil {
		return errors.New("native firewall unavailable")
	}
	if _, ok := step.FirewallChange(); !ok {
		return errors.New("typed firewall change required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	present, err := firewall.tablePresent(ctx)
	if err != nil {
		return errors.New("prior inet sbxr identity unavailable")
	}
	rollback := []byte("delete table inet sbxr\n")
	if present {
		prior, err := firewall.run(ctx, nil, "nft", "list", "table", "inet", "sbxr")
		if err != nil || !strings.Contains(string(prior), "table inet sbxr") {
			return errors.New("prior inet sbxr policy unavailable")
		}
		rollback = append(rollback, prior...)
	}
	return write(bytes.NewReader(rollback))
}

func (firewall *NativeFirewall) Execute(step systemchanges.Step, rollbackPath string, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return firewall.execute(step, rollbackPath, timeout, cancellation, true)
}

func (firewall *NativeFirewall) ExecuteProtected(step systemchanges.Step, rollbackPath string, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	return firewall.execute(step, rollbackPath, timeout, cancellation, false)
}

func (firewall *NativeFirewall) execute(step systemchanges.Step, rollbackPath string, timeout time.Duration, cancellation *systemchanges.Cancellation, legacySSHCheck bool) (systemchanges.StepEvidence, error) {
	change, ok := step.FirewallChange()
	if firewall == nil || firewall.run == nil || !ok || timeout <= 0 || rollbackPath == "" {
		return systemchanges.StepEvidence{}, errors.New("native firewall contract unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if change.Action == systemchanges.HTTP01CloseAction {
		return firewall.closeHTTP01(ctx)
	}
	if _, err := firewall.run(ctx, []byte(change.Candidate), "nft", "--check", "--file", "-"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("native nftables validation failed")
	}
	if err := firewall.armWatchdog(ctx, rollbackPath); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	present, err := firewall.tablePresent(ctx)
	if err != nil {
		return systemchanges.StepEvidence{}, errors.New("current inet sbxr identity unavailable")
	}
	script := []byte(change.Candidate)
	if present {
		script = append([]byte("delete table inet sbxr\n"), script...)
	}
	if _, err := firewall.run(ctx, script, "nft", "--file", "-"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("atomic inet sbxr apply failed")
	}
	if legacySSHCheck {
		if err := firewall.verifySSH(ctx, change.SSHPort); err != nil {
			return systemchanges.StepEvidence{}, err
		}
	}
	if cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("firewall cancellation reached the proven SSH-safe checkpoint")
	}
	identity := change.Candidate
	code := "network-policy-applied"
	if change.Action == systemchanges.HTTP01OpenAction {
		handle, err := firewall.http01Handle(ctx)
		if err != nil {
			return systemchanges.StepEvidence{}, err
		}
		firewall.recordedHandle = handle
		identity = fmt.Sprintf("inet/sbxr/input/%d/sbxr:acme-http-01", handle)
		code = fmt.Sprintf("network-http01-handle-%d", handle)
	}
	digest := sha256.Sum256([]byte(identity))
	return systemchanges.StepEvidence{Code: code, SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (firewall *NativeFirewall) Commit(step systemchanges.Step, evidence systemchanges.StepEvidence) error {
	change, ok := step.FirewallChange()
	if firewall == nil || firewall.run == nil || !ok {
		return errors.New("native firewall commit unavailable")
	}
	if change.Action == systemchanges.HTTP01CloseAction {
		return nil
	}
	if change.Action == systemchanges.HTTP01OpenAction && !strings.HasPrefix(evidence.Code, "network-http01-handle-") || change.Action == systemchanges.FirewallPolicyAction && evidence.Code != "network-policy-applied" {
		return errors.New("durable firewall evidence does not match the applied action")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return firewall.cancelWatchdog(ctx)
}

func (firewall *NativeFirewall) Reverse(_ systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if firewall == nil || firewall.run == nil || snapshot == nil || timeout <= 0 {
		return systemchanges.StepEvidence{}, errors.New("native firewall rollback unavailable")
	}
	prior, err := io.ReadAll(snapshot)
	if err != nil || !strings.HasPrefix(string(prior), "delete table inet sbxr\n") {
		return systemchanges.StepEvidence{}, errors.New("prior inet sbxr rollback is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	apply := true
	if string(prior) == "delete table inet sbxr\n" {
		present, presentErr := firewall.tablePresent(ctx)
		if presentErr != nil {
			return systemchanges.StepEvidence{}, errors.New("inet sbxr rollback identity unavailable")
		}
		apply = present
	}
	if apply {
		if _, err := firewall.run(ctx, prior, "nft", "--file", "-"); err != nil {
			return systemchanges.StepEvidence{}, errors.New("prior inet sbxr restore failed")
		}
	}
	if err := firewall.cancelWatchdog(ctx); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	firewall.recordedHandle = 0
	digest := sha256.Sum256(prior)
	return systemchanges.StepEvidence{Code: "network-policy-restored", SHA256: fmt.Sprintf("%x", digest)}, nil
}

func (firewall *NativeFirewall) Inspect(step systemchanges.Step, _ io.Reader, timeout time.Duration) (systemchanges.StepEffect, error) {
	change, ok := step.FirewallChange()
	if firewall == nil || firewall.run == nil || !ok || timeout <= 0 {
		return "", errors.New("native firewall inspection unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if change.Action == systemchanges.HTTP01OpenAction || change.Action == systemchanges.HTTP01CloseAction {
		_, err := firewall.http01Handle(ctx)
		if err == nil {
			return systemchanges.StepEffectPresent, nil
		}
		return systemchanges.StepEffectAbsent, nil
	}
	present, err := firewall.tablePresent(ctx)
	if err != nil {
		return "", errors.New("inet sbxr inspection failed")
	}
	if present {
		return systemchanges.StepEffectPresent, nil
	}
	return systemchanges.StepEffectAbsent, nil
}

func (firewall *NativeFirewall) CheckCandidate(step systemchanges.Step, timeout time.Duration) (systemchanges.HealthStatus, error) {
	change, ok := step.FirewallChange()
	if firewall == nil || firewall.run == nil || !ok || change.Action != systemchanges.FirewallPolicyAction || timeout <= 0 {
		return systemchanges.Unknown, errors.New("native firewall candidate check unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	active, err := firewall.run(ctx, nil, "nft", "list", "table", "inet", "sbxr")
	want, wantErr := canonicalNftPolicy([]byte(change.Candidate))
	got, gotErr := canonicalNftPolicy(active)
	if err != nil || wantErr != nil || gotErr != nil {
		return systemchanges.Unknown, errors.New("inet sbxr candidate agreement unavailable")
	}
	if got != want {
		return systemchanges.Failed, nil
	}
	return systemchanges.Healthy, nil
}

func canonicalNftPolicy(policy []byte) (string, error) {
	text := strings.NewReplacer("{", " { ", "}", " } ", ";", " ; ", ",", " , ").Replace(string(policy))
	fields := strings.Fields(text)
	if len(fields) < 5 || fields[0] != "table" || fields[1] != "inet" || fields[2] != "sbxr" || fields[3] != "{" || fields[len(fields)-1] != "}" {
		return "", errors.New("inet sbxr policy is malformed")
	}
	return strings.Join(fields, " "), nil
}

func (firewall *NativeFirewall) tablePresent(ctx context.Context) (bool, error) {
	data, err := firewall.run(ctx, nil, "nft", "-j", "list", "tables")
	if err != nil {
		return false, err
	}
	var ruleset struct {
		Nftables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(data, &ruleset) != nil {
		return false, errors.New("invalid nftables table list")
	}
	for _, item := range ruleset.Nftables {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == "sbxr" {
			return true, nil
		}
	}
	return false, nil
}

func (firewall *NativeFirewall) armWatchdog(ctx context.Context, rollbackPath string) error {
	_, err := firewall.run(ctx, nil, "systemd-run", "--quiet", "--unit", firewallWatchdogUnit, "--on-active=60s", "--property=Type=oneshot", "--", "/usr/sbin/nft", "--file", rollbackPath)
	if err != nil {
		return errors.New("root firewall rollback watchdog could not be armed")
	}
	return nil
}

func (firewall *NativeFirewall) cancelWatchdog(ctx context.Context) error {
	units := []string{firewallWatchdogUnit + ".timer", firewallWatchdogUnit + ".service"}
	_, _ = firewall.run(ctx, nil, "systemctl", append([]string{"stop"}, units...)...)
	states, _ := firewall.run(ctx, nil, "systemctl", append([]string{"is-active"}, units...)...)
	fields := strings.Fields(string(states))
	if len(fields) != len(units) {
		return errors.New("firewall rollback watchdog cancellation failed")
	}
	for _, state := range fields {
		if state != "inactive" && state != "failed" && state != "unknown" {
			return errors.New("firewall rollback watchdog cancellation failed")
		}
	}
	return nil
}

func (firewall *NativeFirewall) verifySSH(ctx context.Context, port uint16) error {
	return firewall.verifySSHIdentity(ctx, port, os.Getenv("SSH_CONNECTION"))
}

func (firewall *NativeFirewall) VerifySSHIdentity(identity string, timeout time.Duration) error {
	port, err := sshIdentityPort(identity)
	if firewall == nil || firewall.run == nil || err != nil || timeout <= 0 {
		return errors.New("SSH Preservation identity invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return firewall.verifySSHIdentity(ctx, port, identity)
}

func (firewall *NativeFirewall) VerifySSHSession(identity string, timeout time.Duration) error {
	port, err := sshIdentityPort(identity)
	if firewall == nil || firewall.run == nil || timeout <= 0 {
		return errors.New("SSH Preservation inspection unavailable")
	}
	if err != nil {
		return errors.New("SSH Preservation identity invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	connections, err := firewall.run(ctx, nil, "ss", "-Htn", "state", "established")
	if err != nil || !currentSSHSessionPresent(connections, port, identity) {
		return errors.New("existing SSH session is not responsive")
	}
	return nil
}

func sshIdentityPort(identity string) (uint16, error) {
	fields := strings.Fields(identity)
	if len(fields) != 4 {
		return 0, errors.New("invalid identity")
	}
	port, err := strconv.ParseUint(fields[3], 10, 16)
	if err != nil || port == 0 {
		return 0, errors.New("invalid identity")
	}
	return uint16(port), nil
}

func (firewall *NativeFirewall) verifySSHIdentity(ctx context.Context, port uint16, identity string) error {
	connections, err := firewall.run(ctx, nil, "ss", "-Htn", "state", "established")
	if err != nil || !currentSSHSessionPresent(connections, port, identity) {
		return errors.New("existing SSH session is not responsive")
	}
	policy, err := firewall.run(ctx, nil, "nft", "-j", "list", "table", "inet", "sbxr")
	if err != nil || !admitsTCPPort(policy, port) {
		return errors.New("resulting policy does not admit the detected SSH port")
	}
	return nil
}

func currentSSHSessionPresent(data []byte, port uint16, identity string) bool {
	parts := strings.Fields(identity)
	if len(parts) != 4 || parts[3] != strconv.Itoa(int(port)) {
		return false
	}
	wantClient, wantClientPort, wantServer, wantServerPort := parts[0], parts[1], parts[2], parts[3]
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		localHost, localPort, localErr := net.SplitHostPort(fields[len(fields)-2])
		peerHost, peerPort, peerErr := net.SplitHostPort(fields[len(fields)-1])
		if localErr == nil && peerErr == nil && localHost == wantServer && localPort == wantServerPort && peerHost == wantClient && peerPort == wantClientPort {
			return true
		}
	}
	return false
}

func admitsTCPPort(data []byte, port uint16) bool {
	var ruleset struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &ruleset) != nil {
		return false
	}
	for _, item := range ruleset.Nftables {
		var rule struct {
			Family string                       `json:"family"`
			Table  string                       `json:"table"`
			Chain  string                       `json:"chain"`
			Expr   []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(item["rule"], &rule) != nil || rule.Family != "inet" || rule.Table != "sbxr" || rule.Chain != "input" {
			continue
		}
		matched, accepted, unsafeVerdict := false, false, false
		for _, expression := range rule.Expr {
			if _, ok := expression["accept"]; ok {
				accepted = true
			}
			for _, verdict := range []string{"drop", "reject", "return", "jump", "goto", "queue"} {
				if _, ok := expression[verdict]; ok {
					unsafeVerdict = true
				}
			}
			var match struct {
				Op   string `json:"op"`
				Left struct {
					Payload struct {
						Protocol string `json:"protocol"`
						Field    string `json:"field"`
					} `json:"payload"`
				} `json:"left"`
				Right uint16 `json:"right"`
			}
			if json.Unmarshal(expression["match"], &match) == nil && match.Op == "==" && match.Left.Payload.Protocol == "tcp" && match.Left.Payload.Field == "dport" && match.Right == port {
				matched = true
			}
		}
		if unsafeVerdict {
			return false
		}
		if matched && accepted {
			return true
		}
	}
	return false
}

func (firewall *NativeFirewall) http01Handle(ctx context.Context) (uint64, error) {
	rules, err := firewall.run(ctx, nil, "nft", "-a", "list", "chain", "inet", "sbxr", "input")
	if err != nil {
		return 0, errors.New("temporary HTTP-01 rule inspection failed")
	}
	var handle uint64
	for _, line := range strings.Split(string(rules), "\n") {
		if !strings.Contains(line, `comment "sbxr:acme-http-01"`) {
			continue
		}
		fields := strings.Fields(line)
		for index := range fields {
			if fields[index] == "handle" && index+1 < len(fields) {
				parsed, parseErr := strconv.ParseUint(fields[index+1], 10, 64)
				if parseErr != nil || parsed == 0 || handle != 0 {
					return 0, errors.New("temporary HTTP-01 rule identity is ambiguous")
				}
				handle = parsed
			}
		}
	}
	if handle == 0 {
		return 0, errors.New("temporary HTTP-01 rule identity is absent")
	}
	return handle, nil
}

func (firewall *NativeFirewall) closeHTTP01(ctx context.Context) (systemchanges.StepEvidence, error) {
	handle, err := firewall.http01Handle(ctx)
	if err != nil || firewall.recordedHandle == 0 || handle != firewall.recordedHandle {
		return systemchanges.StepEvidence{}, errors.New("recorded HTTP-01 rule identity is unavailable")
	}
	if _, err := firewall.run(ctx, nil, "nft", "delete", "rule", "inet", "sbxr", "input", "handle", strconv.FormatUint(handle, 10)); err != nil {
		return systemchanges.StepEvidence{}, errors.New("recorded HTTP-01 rule removal failed")
	}
	if _, err := firewall.http01Handle(ctx); err == nil {
		return systemchanges.StepEvidence{}, errors.New("temporary HTTP-01 rule remains")
	}
	policy, err := firewall.run(ctx, nil, "nft", "list", "chain", "inet", "sbxr", "input")
	if err != nil || strings.Contains(string(policy), "tcp dport 80") {
		return systemchanges.StepEvidence{}, errors.New("TCP 80 did not return to the approved prior policy")
	}
	firewall.recordedHandle = 0
	digest := sha256.Sum256([]byte(fmt.Sprintf("inet/sbxr/input/%d/removed", handle)))
	return systemchanges.StepEvidence{Code: fmt.Sprintf("network-http01-removed-%d", handle), SHA256: fmt.Sprintf("%x", digest)}, nil
}
