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
	run            firewallCommand
	recordedHandle uint64
}

func NewNativeFirewall() *NativeFirewall { return newNativeFirewall(runFirewallCommand) }

func newNativeFirewall(run firewallCommand) *NativeFirewall { return &NativeFirewall{run: run} }

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
	if err := firewall.verifySSH(ctx, change.SSHPort); err != nil {
		return systemchanges.StepEvidence{}, err
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
	connections, err := firewall.run(ctx, nil, "ss", "-Htn", "state", "established")
	if err != nil || !currentSSHSessionPresent(connections, port, os.Getenv("SSH_CONNECTION")) {
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
