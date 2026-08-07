package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type CreateTunnelRequest struct {
	AccountID, Name string
	Token           ManagementToken
}
type CreatedTunnel struct {
	ID, Name string
	runToken string
}

// NewCreatedTunnelResult validates an injected provider Adapter result while
// keeping the run token redacted from every rendered value.
func NewCreatedTunnelResult(id, name, runToken string) (CreatedTunnel, error) {
	if !tunnelUUID.MatchString(id) || !safePlanName.MatchString(name) || runToken == "" {
		return CreatedTunnel{}, errors.New("invalid Cloudflare Tunnel creation result")
	}
	return CreatedTunnel{ID: id, Name: name, runToken: runToken}, nil
}

func (created CreatedTunnel) String() string {
	return fmt.Sprintf("created Cloudflare Tunnel id=%s name=%s token=redacted", created.ID, created.Name)
}
func (created CreatedTunnel) GoString() string { return created.String() }

type Route struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
}
type PutConfigurationRequest struct {
	AccountID, TunnelID string
	Token               ManagementToken
	Routes              []Route
}
type Configuration struct {
	TunnelID string
	Version  int
	Routes   []Route
}
type CreateDNSRecordRequest struct {
	ZoneID, Type, Name, Content string
	Proxied                     bool
	Token                       ManagementToken
}
type DeleteDNSRecordRequest struct {
	ZoneID, ID string
	Token      ManagementToken
}
type DeleteTunnelRequest struct {
	AccountID, ID string
	Token         ManagementToken
}
type DNSRecordReference struct{ ID string }
type WholeTunnelRequest struct {
	AccountID, ZoneID, TunnelID string
	DNSRecords                  []DNSRecordReference
	Token                       ManagementToken
}
type DNSObservation struct {
	ID, Name, Type, Content string
	Proxied                 bool
}
type WholeTunnelObservation struct {
	TunnelID                                       string
	Connected                                      bool
	Routes                                         []Route
	DNSRecords                                     []DNSObservation
	XHTTPOriginReachable, WebSocketOriginReachable bool
}

type rollbackRecord struct {
	Token string `json:"management_token"`
}

// Executor is the Cloudflare Adapter used only by the System Changes Ubuntu
// transaction host. Every call executes one typed provider mutation.
type Executor struct {
	api             MutationAPI
	token           ManagementToken
	runToken        TunnelRunToken
	request         PlanRequest
	observation     string
	tokenID         string
	binding         cloudflareEvidenceBinding
	serviceIdentity func() (int, int, int, error)
	command         func(context.Context, string, ...string) ([]byte, error)
}

func (plan *Plan) Executor(api MutationAPI) (Executor, error) {
	if plan == nil || api == nil || plan.runToken.cell == nil || plan.request.Authority.Token.value == "" {
		return Executor{}, errors.New("Cloudflare executor unavailable")
	}
	view := Interface{api: api, clock: SystemClock{}}.View(context.Background(), plan.request.Authority)
	if view.Health.Outcome != Healthy {
		return Executor{}, errors.New("Cloudflare executor authority unavailable")
	}
	return Executor{api: api, token: plan.request.Authority.Token, runToken: plan.runToken, request: plan.request, observation: plan.observation, tokenID: view.Credential.ID, binding: plan.binding, serviceIdentity: cloudflaredIdentity, command: runCommand}, nil
}

func (executor Executor) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	if _, ok := step.CloudflareChange(); !ok || write == nil || executor.token.value == "" {
		return errors.New("Cloudflare rollback capture unavailable")
	}
	data, err := json.Marshal(rollbackRecord{Token: executor.token.value})
	if err != nil {
		return err
	}
	return write(strings.NewReader(string(data)))
}

func (executor Executor) Execute(step systemchanges.Step, resolvedTunnelID string, timeout time.Duration) (systemchanges.StepEvidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	change, ok := step.CloudflareChange()
	if !ok || executor.api == nil || executor.token.value == "" {
		return systemchanges.StepEvidence{}, errors.New("Cloudflare step unavailable")
	}
	switch change.Action {
	case systemchanges.CloudflareTunnelCreate:
		if !executor.planStillFresh(ctx) {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare Plan observation changed")
		}
		created, err := executor.api.CreateTunnel(ctx, CreateTunnelRequest{AccountID: change.AccountID, Name: change.TunnelName, Token: executor.token})
		if err != nil || !tunnelUUID.MatchString(created.ID) || created.Name != change.TunnelName || !executor.runToken.cell.issue(created.runToken) {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare Tunnel creation unproved")
		}
		return providerEvidence("cloudflare-tunnel-created", string(systemchanges.CloudflareTunnelResource), created.ID), nil
	case systemchanges.CloudflareRoutesPut:
		routes := make([]Route, len(change.Routes))
		for index, route := range change.Routes {
			routes[index] = Route{Hostname: route.Hostname, Service: route.Origin}
		}
		configured, err := executor.api.PutConfiguration(ctx, PutConfigurationRequest{AccountID: change.AccountID, TunnelID: resolvedTunnelID, Token: executor.token, Routes: routes})
		if err != nil || configured.TunnelID != resolvedTunnelID || configured.Version < 1 || !sameRoutes(configured.Routes, routes) {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare routes unproved")
		}
		return providerEvidence("cloudflare-routes-configured", string(systemchanges.CloudflareRouteResource), "config-"+strconv.Itoa(configured.Version)), nil
	case systemchanges.CloudflareDNSCreate:
		content, proxied := change.Content, false
		if change.RecordType == "CNAME" {
			content, proxied = resolvedTunnelID+".cfargotunnel.com", true
		}
		record, err := executor.api.CreateDNSRecord(ctx, CreateDNSRecordRequest{ZoneID: change.ZoneID, Type: change.RecordType, Name: change.Hostname, Content: content, Proxied: proxied, Token: executor.token})
		if err != nil || record.ID == "" || record.Name != change.Hostname {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare DNS creation unproved")
		}
		return providerEvidence("cloudflare-dns-created", string(systemchanges.CloudflareDNSRecordResource), record.ID), nil
	case systemchanges.CloudflaredActivate:
		if executor.runToken.cell == nil || resolvedTunnelID == "" {
			return systemchanges.StepEvidence{}, errors.New("cloudflared activation unavailable")
		}
		return providerEvidence("cloudflared-activated", "", ""), nil
	}
	return systemchanges.StepEvidence{}, errors.New("unsupported Cloudflare step")
}

func (executor Executor) planStillFresh(ctx context.Context) bool {
	view := Interface{api: executor.api, clock: SystemClock{}}.View(ctx, executor.request.Authority)
	if view.Health.Outcome != Healthy || view.Credential.ID != executor.tokenID {
		return false
	}
	digests := make([]string, 0, 3)
	for _, hostname := range []string{executor.request.XHTTPHostname, executor.request.WebSocketHostname, executor.request.DirectHostname} {
		observed, err := executor.api.ObserveMutation(ctx, MutationRequest{AccountID: executor.request.Authority.AccountID, ZoneID: executor.request.Authority.ZoneID, Tunnel: executor.request.TunnelName, Hostname: hostname, Token: executor.token})
		if err != nil || len(observed.Tunnels) != 0 || len(observed.DNSRecords) != 0 || !sha256Text.MatchString(observed.Digest) {
			return false
		}
		digests = append(digests, observed.Digest)
	}
	return strings.Join(digests, "\n") == executor.observation
}

func (executor Executor) Reverse(step systemchanges.Step, evidence systemchanges.StepEvidence, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var rollback rollbackRecord
	if json.NewDecoder(io.LimitReader(snapshot, 4097)).Decode(&rollback) != nil || rollback.Token == "" {
		return systemchanges.StepEvidence{}, errors.New("Cloudflare rollback authority unavailable")
	}
	token := ManagementToken{value: rollback.Token}
	change, ok := step.CloudflareChange()
	if !ok {
		return systemchanges.StepEvidence{}, errors.New("Cloudflare rollback step unavailable")
	}
	var err error
	switch change.Action {
	case systemchanges.CloudflareTunnelCreate:
		if evidence.ResourceType != string(systemchanges.CloudflareTunnelResource) || !tunnelUUID.MatchString(evidence.ResourceID) {
			return systemchanges.StepEvidence{}, errors.New("journaled Cloudflare Tunnel identifier unavailable")
		}
		err = executor.api.DeleteTunnel(ctx, DeleteTunnelRequest{AccountID: change.AccountID, ID: evidence.ResourceID, Token: token})
	case systemchanges.CloudflareDNSCreate:
		if evidence.ResourceType != string(systemchanges.CloudflareDNSRecordResource) || evidence.ResourceID == "" {
			return systemchanges.StepEvidence{}, errors.New("journaled Cloudflare DNS identifier unavailable")
		}
		err = executor.api.DeleteDNSRecord(ctx, DeleteDNSRecordRequest{ZoneID: change.ZoneID, ID: evidence.ResourceID, Token: token})
	}
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	return providerEvidence("cloudflare-rollback-proved", "", ""), nil
}

func providerEvidence(code, resourceType, resourceID string) systemchanges.StepEvidence {
	digest := sha256.Sum256([]byte(code + "\n" + resourceType + "\n" + resourceID))
	return systemchanges.StepEvidence{Code: code, SHA256: hex.EncodeToString(digest[:]), ResourceType: resourceType, ResourceID: resourceID}
}

func (executor Executor) WaitForWholeTunnel(ctx context.Context, request WholeTunnelRequest, want WholeTunnelExpected, clock Clock) Health {
	deadline := clock.Now().Add(5 * time.Minute)
	temporaryFailures := 0
	for {
		observed, err := executor.api.ObserveWholeTunnel(ctx, request)
		if err == nil {
			health := EvaluateWholeTunnel(observed, want)
			if health.Outcome == Healthy || health.Outcome == Failed {
				health.Time = clock.Now().UTC()
				return health
			}
		} else if apiErrorIs(err, APITemporary) {
			temporaryFailures++
		} else {
			health := safeAPIHealth(err)
			health.Module = "Cloudflare Tunnel"
			switch {
			case apiErrorIs(err, APIAmbiguous):
				health.Code, health.Explanation = "CLOUDFLARE-OBSERVATION-CONTRADICTORY", "Cloudflare returned a valid but contradictory immutable identifier."
			case apiErrorIs(err, APIMalformed):
				health.Code, health.Explanation = "CLOUDFLARE-OBSERVATION-MALFORMED", "Cloudflare returned an unsupported observation shape."
			}
			health = finishHealth(health)
			health.Time = clock.Now().UTC()
			return health
		}
		if temporaryFailures >= 3 || !clock.Now().Before(deadline) || clock.Sleep(ctx, 10*time.Second) != nil {
			health := finishHealth(Health{Module: "Cloudflare Tunnel", Outcome: Unknown, Code: "CLOUDFLARE-CONVERGENCE-TIMEOUT", Explanation: "Cloudflare did not converge within five minutes.", NextActions: []string{"Check again", "Back"}})
			health.Time = clock.Now().UTC()
			return health
		}
	}
}

func (executor Executor) CheckWholeTunnel(evidence []systemchanges.StepEvidence, timeout time.Duration) (systemchanges.HealthStatus, error) {
	resource := func(step int, kind string) (string, bool) {
		if step < 1 || step > len(evidence) || evidence[step-1].ResourceType != kind || evidence[step-1].ResourceID == "" {
			return "", false
		}
		return evidence[step-1].ResourceID, true
	}
	tunnelID, ok := resource(executor.binding.tunnel, string(systemchanges.CloudflareTunnelResource))
	if !ok {
		return systemchanges.Unknown, errors.New("journaled Cloudflare health identity unavailable")
	}
	expected := WholeTunnelExpected{TunnelID: tunnelID, Routes: []Route{{Hostname: executor.request.XHTTPHostname, Service: xhttpOrigin}, {Hostname: executor.request.WebSocketHostname, Service: webSocketOrigin}, {Service: "http_status:404"}}}
	references := make([]DNSRecordReference, 0, 4)
	addDNS := func(step int, name, kind, content string, proxied bool) bool {
		if step == 0 {
			return true
		}
		id, found := resource(step, string(systemchanges.CloudflareDNSRecordResource))
		if !found {
			return false
		}
		references = append(references, DNSRecordReference{ID: id})
		expected.DNSRecords = append(expected.DNSRecords, DNSExpected{ID: id, Name: name, Type: kind, Content: content, Proxied: proxied})
		return true
	}
	if !addDNS(executor.binding.xhttp, executor.request.XHTTPHostname, "CNAME", tunnelID+".cfargotunnel.com", true) || !addDNS(executor.binding.websocket, executor.request.WebSocketHostname, "CNAME", tunnelID+".cfargotunnel.com", true) || !addDNS(executor.binding.directIPv4, executor.request.DirectHostname, "A", executor.request.PublicIPv4, false) || !addDNS(executor.binding.directIPv6, executor.request.DirectHostname, "AAAA", executor.request.PublicIPv6, false) {
		return systemchanges.Unknown, errors.New("journaled Cloudflare DNS health identity unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	health := executor.WaitForWholeTunnel(ctx, WholeTunnelRequest{AccountID: executor.request.Authority.AccountID, ZoneID: executor.request.Authority.ZoneID, TunnelID: tunnelID, DNSRecords: references, Token: executor.token}, expected, SystemClock{})
	switch health.Outcome {
	case Healthy:
		return systemchanges.Healthy, nil
	case NeedsAttention:
		return systemchanges.NeedsAttention, nil
	case Failed:
		return systemchanges.Failed, nil
	default:
		return systemchanges.Unknown, nil
	}
}

func (executor Executor) ValidateInstalledService(root string) error {
	return executor.validateInstalledService(root)
}

func (executor Executor) validateInstalledService(root string) error {
	identity := executor.serviceIdentity
	if identity == nil {
		identity = cloudflaredIdentity
	}
	rootUID, rootGID, cloudflaredGID, err := identity()
	if err != nil {
		return err
	}
	return ValidateInstalledService(root, rootUID, rootGID, cloudflaredGID)
}

func cloudflaredIdentity() (int, int, int, error) {
	account, err := user.Lookup("cloudflared")
	if err != nil {
		return 0, 0, 0, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, 0, err
	}
	return os.Geteuid(), os.Getegid(), gid, nil
}

func (executor Executor) ValidateNativeConfiguration(root string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := executor.command
	if command == nil {
		command = runCommand
	}
	if _, err := command(ctx, "/usr/bin/cloudflared", "--config", filepath.Join(root, "etc/sbxr/cloudflared/config.yml"), "tunnel", "ingress", "validate"); err != nil {
		return errors.New("cloudflared native configuration validation failed")
	}
	return nil
}

func runCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	return command.Output()
}
