package cloudflaretunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
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
type GetConfigurationRequest struct {
	AccountID, TunnelID string
	Token               ManagementToken
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
type GetDNSRecordRequest struct {
	ZoneID, ID string
	Token      ManagementToken
}
type PutDNSRecordRequest struct {
	ZoneID, ID, Type, Name, Content string
	Proxied                         bool
	Token                           ManagementToken
}
type DeleteDNSRecordRequest struct {
	ZoneID, ID string
	Token      ManagementToken
}
type DeleteTunnelRequest struct {
	AccountID, ID string
	Token         ManagementToken
}
type GetTunnelTokenRequest struct {
	AccountID, TunnelID string
	Token               ManagementToken
}

// TunnelTokenResult keeps the complete run token behind the same one-use
// Infrastructure Secret handoff used by State.
type TunnelTokenResult struct {
	token  TunnelRunToken
	sha256 string
}

type tunnelTokenAPI interface {
	GetTunnelToken(context.Context, GetTunnelTokenRequest) (TunnelTokenResult, error)
}

// NewRunTokenRotationExecutor reconstructs the provider seam after process
// restart from the current protected management authority.
func NewRunTokenRotationExecutor(api MutationAPI, token ManagementToken) (Executor, error) {
	if api == nil || token.value == "" {
		return Executor{}, errors.New("Cloudflare run-token recovery executor unavailable")
	}
	if _, ok := api.(tunnelTokenAPI); !ok {
		return Executor{}, errors.New("Cloudflare Tunnel token API unavailable")
	}
	return Executor{api: api, token: token, serviceIdentity: cloudflaredIdentity, command: runCommand}, nil
}

func NewRecoveryExecutor(api MutationAPI) (Executor, error) {
	if api == nil {
		return Executor{}, errors.New("Cloudflare recovery executor unavailable")
	}
	return Executor{api: api, command: runCommand, clock: SystemClock{}}, nil
}

func (TunnelTokenResult) String() string   { return "Cloudflare Tunnel run token: redacted" }
func (TunnelTokenResult) GoString() string { return "Cloudflare Tunnel run token: redacted" }
func (result TunnelTokenResult) ChangedFrom(sha256 string) bool {
	return sha256Text.MatchString(sha256) && result.sha256 != "" && result.sha256 != sha256
}
func (result TunnelTokenResult) ConsumeInfrastructureSecret() (string, bool) {
	return result.token.consume()
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

type CertificateDNSRequest struct {
	ZoneID, ZoneName, Hostname string
	PublicIPv4, PublicIPv6     string
	IPv4RecordID, IPv6RecordID string
	Token                      ManagementToken
}

func (request CertificateDNSRequest) String() string {
	return fmt.Sprintf("Certificate DNS observation: zone=%s hostname=%s IPv4=%s IPv6=%s token=masked", request.ZoneName, request.Hostname, request.PublicIPv4, request.PublicIPv6)
}
func (request CertificateDNSRequest) GoString() string { return request.String() }

type CAARecord struct {
	Flags uint8
	Tag   string
	Value string
}
type EffectiveCAA struct {
	Name    string
	Records []CAARecord
}
type CertificateDNSFacts struct {
	Hostname     string
	Addresses    []netip.Addr
	EffectiveCAA EffectiveCAA
}

type rollbackRecord struct {
	Token         string          `json:"management_token"`
	Configuration *Configuration  `json:"configuration,omitempty"`
	DNS           *DNSObservation `json:"dns,omitempty"`
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
	clock           Clock
	releaseUpdate   bool
}

func (plan *Plan) Executor(api MutationAPI) (Executor, error) {
	if plan == nil || api == nil || plan.runToken.cell == nil && plan.request.ManagedRepair.TunnelID == "" || plan.request.Authority.Token.value == "" {
		return Executor{}, errors.New("Cloudflare executor unavailable")
	}
	view := Interface{api: api, clock: SystemClock{}}.View(context.Background(), plan.request.Authority)
	if view.Health.Outcome != Healthy {
		return Executor{}, errors.New("Cloudflare executor authority unavailable")
	}
	return Executor{api: api, token: plan.request.Authority.Token, runToken: plan.runToken, request: plan.request, observation: plan.observation, tokenID: view.Credential.ID, binding: plan.binding, serviceIdentity: cloudflaredIdentity, command: runCommand, clock: SystemClock{}, releaseUpdate: plan.releaseUpdate}, nil
}

func (executor Executor) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	if _, ok := step.CloudflareChange(); !ok || write == nil || executor.token.value == "" {
		return errors.New("Cloudflare rollback capture unavailable")
	}
	change, _ := step.CloudflareChange()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if (change.Action == systemchanges.CloudflareRoutesPut && change.TunnelID != "" || change.Action == systemchanges.CloudflareDNSRepair) && !executor.repairPlanStillFresh(ctx) {
		return errors.New("Cloudflare repair Plan observation changed")
	}
	record := rollbackRecord{Token: executor.token.value}
	var err error
	if change.Action == systemchanges.CloudflareRoutesPut && change.TunnelID != "" {
		var configuration Configuration
		err = retryTemporary(ctx, executor.clock, func() error {
			var getErr error
			configuration, getErr = executor.api.GetConfiguration(ctx, GetConfigurationRequest{AccountID: change.AccountID, TunnelID: change.TunnelID, Token: executor.token})
			return getErr
		})
		record.Configuration = &configuration
	} else if change.Action == systemchanges.CloudflareDNSRepair {
		var dns DNSObservation
		err = retryTemporary(ctx, executor.clock, func() error {
			var getErr error
			dns, getErr = executor.api.GetDNSRecord(ctx, GetDNSRecordRequest{ZoneID: change.ZoneID, ID: change.DNSRecordID, Token: executor.token})
			return getErr
		})
		record.DNS = &dns
	}
	if err != nil {
		return err
	}
	data, err := json.Marshal(record)
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
		if change.TunnelID != "" {
			resolvedTunnelID = change.TunnelID
		}
		routes := make([]Route, len(change.Routes))
		for index, route := range change.Routes {
			routes[index] = Route{Hostname: route.Hostname, Service: route.Origin}
		}
		var configured Configuration
		var err error
		call := func() error {
			configured, err = executor.api.PutConfiguration(ctx, PutConfigurationRequest{AccountID: change.AccountID, TunnelID: resolvedTunnelID, Token: executor.token, Routes: routes})
			return err
		}
		if change.TunnelID != "" {
			err = retryTemporary(ctx, executor.clock, call)
		} else {
			err = call()
		}
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
	case systemchanges.CloudflareDNSRepair:
		proxied := change.RecordType == "CNAME"
		var record OwnedResource
		err := retryTemporary(ctx, executor.clock, func() error {
			var putErr error
			record, putErr = executor.api.PutDNSRecord(ctx, PutDNSRecordRequest{ZoneID: change.ZoneID, ID: change.DNSRecordID, Type: change.RecordType, Name: change.Hostname, Content: change.Content, Proxied: proxied, Token: executor.token})
			return putErr
		})
		if err != nil || record.ID != change.DNSRecordID || record.Name != change.Hostname {
			return systemchanges.StepEvidence{}, errors.New("Cloudflare DNS repair unproved")
		}
		return providerEvidence("cloudflare-dns-repaired", string(systemchanges.CloudflareDNSRecordResource), record.ID), nil
	case systemchanges.CloudflaredActivate:
		if executor.runToken.cell == nil || resolvedTunnelID == "" {
			return systemchanges.StepEvidence{}, errors.New("cloudflared activation unavailable")
		}
		return providerEvidence("cloudflared-activated", "", ""), nil
	}
	return systemchanges.StepEvidence{}, errors.New("unsupported Cloudflare step")
}

func (executor Executor) RetrieveRunToken(change systemchanges.CloudflareChange, priorSHA256 string, timeout time.Duration) (any, bool, error) {
	provider, ok := executor.api.(tunnelTokenAPI)
	if !ok || executor.token.value == "" || change.Action != systemchanges.CloudflareRunTokenActivate || !tunnelUUID.MatchString(change.TunnelID) || !sha256Text.MatchString(priorSHA256) {
		return nil, false, errors.New("Cloudflare run-token retrieval unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := provider.GetTunnelToken(ctx, GetTunnelTokenRequest{AccountID: change.AccountID, TunnelID: change.TunnelID, Token: executor.token})
	if err != nil {
		return nil, false, err
	}
	if !result.ChangedFrom(priorSHA256) {
		return nil, false, nil
	}
	return result, true, nil
}

func (executor Executor) CheckRunTokenRotation(change systemchanges.CloudflareChange, timeout time.Duration) (systemchanges.HealthStatus, error) {
	if change.Action != systemchanges.CloudflareRunTokenActivate || executor.api == nil || executor.token.value == "" {
		return systemchanges.Unknown, errors.New("Cloudflare rotation health unavailable")
	}
	request := PlanRequest{Authority: ViewRequest{AccountID: change.AccountID, ZoneID: change.ZoneID, Token: executor.token}, XHTTPHostname: change.Routes[0].Hostname, WebSocketHostname: change.Routes[1].Hostname, DirectHostname: change.DirectHostname, PublicIPv4: change.PublicIPv4, PublicIPv6: change.PublicIPv6, RunTokenRotation: RunTokenRotation{TunnelID: change.TunnelID, XHTTPDNSRecordID: change.XHTTPDNSRecordID, WebSocketDNSRecordID: change.WebSocketDNSRecordID, DirectIPv4RecordID: change.DirectIPv4RecordID, DirectIPv6RecordID: change.DirectIPv6RecordID}}
	expected, providerRequest := rotationHealthRequest(request)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	health := executor.WaitForWholeTunnel(ctx, providerRequest, expected, SystemClock{})
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

func (executor Executor) repairPlanStillFresh(ctx context.Context) bool {
	view := Interface{api: executor.api, clock: executor.clock}.View(ctx, executor.request.Authority)
	if view.Health.Outcome != Healthy || view.Credential.ID != executor.tokenID {
		return false
	}
	owned := executor.request.ManagedRepair
	expected := map[string][]string{
		executor.request.XHTTPHostname:     {owned.XHTTPDNSRecordID},
		executor.request.WebSocketHostname: {owned.WebSocketDNSRecordID},
		executor.request.DirectHostname:    compactIDs(owned.DirectIPv4RecordID, owned.DirectIPv6RecordID),
	}
	digests := make([]string, 0, 3)
	for _, hostname := range []string{executor.request.XHTTPHostname, executor.request.WebSocketHostname, executor.request.DirectHostname} {
		var observed MutationObservation
		if retryTemporary(ctx, executor.clock, func() error {
			var err error
			observed, err = executor.api.ObserveMutation(ctx, MutationRequest{AccountID: executor.request.Authority.AccountID, ZoneID: executor.request.Authority.ZoneID, Tunnel: executor.request.TunnelName, Hostname: hostname, Token: executor.token})
			return err
		}) != nil || !sameOwnedResources(observed.Tunnels, []OwnedResource{{ID: owned.TunnelID, Name: executor.request.TunnelName}}) || !sameOwnedIDs(observed.DNSRecords, hostname, expected[hostname]) {
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
	case systemchanges.CloudflareRoutesPut:
		if change.TunnelID == "" || rollback.Configuration == nil || rollback.Configuration.TunnelID != change.TunnelID {
			return systemchanges.StepEvidence{}, errors.New("prior Cloudflare routes unavailable")
		}
		err = retryTemporary(ctx, executor.clock, func() error {
			_, putErr := executor.api.PutConfiguration(ctx, PutConfigurationRequest{AccountID: change.AccountID, TunnelID: change.TunnelID, Routes: rollback.Configuration.Routes, Token: token})
			return putErr
		})
	case systemchanges.CloudflareDNSRepair:
		if rollback.DNS == nil || rollback.DNS.ID != change.DNSRecordID {
			return systemchanges.StepEvidence{}, errors.New("prior Cloudflare DNS unavailable")
		}
		err = retryTemporary(ctx, executor.clock, func() error {
			_, putErr := executor.api.PutDNSRecord(ctx, PutDNSRecordRequest{ZoneID: change.ZoneID, ID: rollback.DNS.ID, Type: rollback.DNS.Type, Name: rollback.DNS.Name, Content: rollback.DNS.Content, Proxied: rollback.DNS.Proxied, Token: token})
			return putErr
		})
	}
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	return providerEvidence("cloudflare-rollback-proved", "", ""), nil
}

func (executor Executor) InspectRepair(step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEffect, error) {
	var rollback rollbackRecord
	if json.NewDecoder(io.LimitReader(snapshot, 64<<10)).Decode(&rollback) != nil || rollback.Token == "" {
		return "", errors.New("Cloudflare repair inspection pre-image unavailable")
	}
	change, ok := step.CloudflareChange()
	if !ok {
		return "", errors.New("Cloudflare repair inspection unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	token := ManagementToken{value: rollback.Token}
	switch change.Action {
	case systemchanges.CloudflareRoutesPut:
		var current Configuration
		err := retryTemporary(ctx, executor.clock, func() error {
			var getErr error
			current, getErr = executor.api.GetConfiguration(ctx, GetConfigurationRequest{AccountID: change.AccountID, TunnelID: change.TunnelID, Token: token})
			return getErr
		})
		if err != nil || rollback.Configuration == nil {
			return "", errors.New("Cloudflare route repair inspection failed")
		}
		if sameRoutes(current.Routes, rollback.Configuration.Routes) {
			return systemchanges.StepEffectAbsent, nil
		}
		desired := make([]Route, len(change.Routes))
		for index, route := range change.Routes {
			desired[index] = Route{Hostname: route.Hostname, Service: route.Origin}
		}
		if sameRoutes(current.Routes, desired) {
			return systemchanges.StepEffectPresent, nil
		}
	case systemchanges.CloudflareDNSRepair:
		var current DNSObservation
		err := retryTemporary(ctx, executor.clock, func() error {
			var getErr error
			current, getErr = executor.api.GetDNSRecord(ctx, GetDNSRecordRequest{ZoneID: change.ZoneID, ID: change.DNSRecordID, Token: token})
			return getErr
		})
		if err != nil || rollback.DNS == nil {
			return "", errors.New("Cloudflare DNS repair inspection failed")
		}
		if current == *rollback.DNS {
			return systemchanges.StepEffectAbsent, nil
		}
		if current == (DNSObservation{ID: change.DNSRecordID, Name: change.Hostname, Type: change.RecordType, Content: change.Content, Proxied: change.RecordType == "CNAME"}) {
			return systemchanges.StepEffectPresent, nil
		}
	}
	return "", errors.New("Cloudflare repair effect is contradictory")
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
	if executor.request.ManagedRepair.TunnelID != "" {
		expected, request := managedHealthRequest(executor.request)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return systemHealth(executor.WaitForWholeTunnel(ctx, request, expected, SystemClock{})), nil
	}
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
	return systemHealth(health), nil
}

func systemHealth(health Health) systemchanges.HealthStatus {
	switch health.Outcome {
	case Healthy:
		return systemchanges.Healthy
	case NeedsAttention:
		return systemchanges.NeedsAttention
	case Failed:
		return systemchanges.Failed
	default:
		return systemchanges.Unknown
	}
}

func (executor Executor) CertificateDNSFacts(ctx context.Context, evidence []systemchanges.StepEvidence) (CertificateDNSFacts, error) {
	if executor.api == nil || executor.token.value == "" {
		return CertificateDNSFacts{}, errors.New("Certificate DNS observation unavailable")
	}
	recordID := func(step int) (string, bool) {
		if step == 0 {
			return "", true
		}
		if step > len(evidence) || evidence[step-1].ResourceType != string(systemchanges.CloudflareDNSRecordResource) || !immutableID.MatchString(evidence[step-1].ResourceID) {
			return "", false
		}
		return evidence[step-1].ResourceID, true
	}
	ipv4ID, ipv4OK := recordID(executor.binding.directIPv4)
	ipv6ID, ipv6OK := recordID(executor.binding.directIPv6)
	if !ipv4OK || !ipv6OK {
		return CertificateDNSFacts{}, errors.New("journaled Direct DNS identity unavailable")
	}
	facts, err := executor.api.ObserveCertificateDNS(ctx, CertificateDNSRequest{ZoneID: executor.request.Authority.ZoneID, ZoneName: executor.request.Authority.ZoneName, Hostname: executor.request.DirectHostname, PublicIPv4: executor.request.PublicIPv4, PublicIPv6: executor.request.PublicIPv6, IPv4RecordID: ipv4ID, IPv6RecordID: ipv6ID, Token: executor.token})
	if err != nil {
		return CertificateDNSFacts{}, err
	}
	if facts.Hostname != executor.request.DirectHostname || facts.EffectiveCAA.Name != "" && facts.EffectiveCAA.Name != facts.Hostname && facts.EffectiveCAA.Name != executor.request.Authority.ZoneName || facts.EffectiveCAA.Name == "" && len(facts.EffectiveCAA.Records) != 0 {
		return CertificateDNSFacts{}, errors.New("Certificate DNS observation invalid")
	}
	want := map[netip.Addr]bool{}
	for _, text := range []string{executor.request.PublicIPv4, executor.request.PublicIPv6} {
		if text != "" {
			want[netip.MustParseAddr(text)] = true
		}
	}
	for _, address := range facts.Addresses {
		if !want[address] {
			return CertificateDNSFacts{}, errors.New("Certificate DNS observation invalid")
		}
		delete(want, address)
	}
	for _, record := range facts.EffectiveCAA.Records {
		if record.Tag == "" || !safeProviderValue(record.Tag) || !safeProviderValue(record.Value) {
			return CertificateDNSFacts{}, errors.New("Certificate DNS observation invalid")
		}
	}
	if len(want) != 0 {
		return CertificateDNSFacts{}, errors.New("Certificate DNS observation incomplete")
	}
	return facts, nil
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
	if executor.releaseUpdate {
		installed, readErr := readManagedService(root, rootUID, rootGID, cloudflaredGID)
		if readErr != nil || !bytes.Equal(installed.Unit, []byte(executor.request.CandidateServiceUnit)) {
			return errors.New("candidate cloudflared service is unproved")
		}
		return nil
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
