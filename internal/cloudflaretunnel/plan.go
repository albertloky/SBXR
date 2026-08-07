package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

const (
	qualifiedCloudflaredVersion = "2026.7.3"
	xhttpOrigin                 = "http://127.0.0.1:11080"
	webSocketOrigin             = "http://127.0.0.1:11081"
	cloudflaredTokenPath        = "/etc/sbxr/cloudflared/token"
)

var (
	safePlanName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`)
	sha256Text   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tunnelUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	planUses     sync.Map
)

type MutationPlanner interface {
	ObserveMutation(context.Context, MutationRequest) (MutationObservation, error)
}

type MutationAPI interface {
	API
	MutationPlanner
	CreateTunnel(context.Context, CreateTunnelRequest) (CreatedTunnel, error)
	PutConfiguration(context.Context, PutConfigurationRequest) (Configuration, error)
	CreateDNSRecord(context.Context, CreateDNSRecordRequest) (OwnedResource, error)
	ObserveWholeTunnel(context.Context, WholeTunnelRequest) (WholeTunnelObservation, error)
	ObserveCertificateDNS(context.Context, CertificateDNSRequest) (CertificateDNSFacts, error)
	DeleteDNSRecord(context.Context, DeleteDNSRecordRequest) error
	DeleteTunnel(context.Context, DeleteTunnelRequest) error
}

type MutationRequest struct {
	AccountID string
	ZoneID    string
	Tunnel    string
	Hostname  string
	Token     ManagementToken
}

func (request MutationRequest) String() string {
	return fmt.Sprintf("Cloudflare mutation observation: account=%s zone=%s tunnel=%s hostname=%s token=masked", request.AccountID, request.ZoneID, request.Tunnel, request.Hostname)
}

type OwnedResource struct{ ID, Name string }
type MutationObservation struct {
	Digest     string
	Tunnels    []OwnedResource
	DNSRecords []OwnedResource
}

type runTokenCell struct {
	mu    sync.Mutex
	value string
	used  atomic.Bool
}

func (cell *runTokenCell) issue(value string) bool {
	cell.mu.Lock()
	defer cell.mu.Unlock()
	if cell.value != "" || value == "" {
		return false
	}
	cell.value = value
	return true
}

type TunnelRunToken struct{ cell *runTokenCell }

func (TunnelRunToken) String() string   { return "Cloudflare Tunnel run token: redacted" }
func (TunnelRunToken) GoString() string { return "Cloudflare Tunnel run token: redacted" }
func (token TunnelRunToken) ConsumeInfrastructureSecret() (string, bool) {
	if token.cell == nil || !token.cell.used.CompareAndSwap(false, true) {
		return "", false
	}
	token.cell.mu.Lock()
	defer token.cell.mu.Unlock()
	return token.cell.value, token.cell.value != ""
}

type PlanRequest struct {
	Authority          ViewRequest
	ChangeSet          string
	StartingRevision   uint64
	DesiredStateSHA256 string
	TunnelName         string
	XHTTPHostname      string
	WebSocketHostname  string
	DirectHostname     string
	PublicIPv4         string
	PublicIPv6         string
	CloudflaredVersion string
}

type Plan struct {
	identity, sha256, observation string
	request                       PlanRequest
	steps                         []systemchanges.Step
	checks                        []systemchanges.Check
	binding                       cloudflareEvidenceBinding
	runToken                      TunnelRunToken
	used                          *atomic.Bool
}

func (plan *Plan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *Plan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *Plan) Steps() []systemchanges.Step {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Step(nil), plan.steps...)
}
func (plan *Plan) Checks() []systemchanges.Check {
	if plan == nil {
		return nil
	}
	return append([]systemchanges.Check(nil), plan.checks...)
}
func (plan *Plan) String() string {
	if plan == nil {
		return "Cloudflare Plan: unavailable"
	}
	return fmt.Sprintf("Cloudflare Plan %s: one Tunnel %s; XHTTP %s to %s; WebSocket %s to %s; DNS-only Direct TLS %s; cloudflared.service --token-file %s; HTTP 404 fallback", plan.identity, plan.request.TunnelName, plan.request.XHTTPHostname, xhttpOrigin, plan.request.WebSocketHostname, webSocketOrigin, plan.request.DirectHostname, cloudflaredTokenPath)
}
func (plan *Plan) GoString() string { return plan.String() }

type PlanResult struct {
	Plan               *Plan
	Health             Health
	SuggestedHostnames []string
}

type cloudflareEvidenceBinding struct {
	tunnel, xhttp, websocket, directIPv4, directIPv6 int
}

func (i Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	health := Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: "CLOUDFLARE-PLAN-REFUSED", NextActions: []string{"Check again", "Back"}}
	planner, ok := i.api.(MutationPlanner)
	if !ok || !validPlanRequest(request) {
		health.Explanation = "The Cloudflare creation request is incomplete or outside the fixed contract."
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	authority := i.View(ctx, request.Authority)
	if authority.Health.Outcome != Healthy {
		return PlanResult{Health: authority.Health}
	}
	hostnames := []string{request.XHTTPHostname, request.WebSocketHostname, request.DirectHostname}
	digests := make([]string, 0, len(hostnames))
	for _, hostname := range hostnames {
		observed, err := planner.ObserveMutation(ctx, MutationRequest{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Tunnel: request.TunnelName, Hostname: hostname, Token: request.Authority.Token})
		if err != nil || !sha256Text.MatchString(observed.Digest) {
			if err != nil {
				health = safeAPIHealth(err)
			} else {
				health.Explanation = "The fresh provider observation is incomplete."
			}
			return PlanResult{Health: finish(healthResult(i, health)).Health}
		}
		if len(observed.Tunnels) != 0 || len(observed.DNSRecords) != 0 {
			health.Code = "CLOUDFLARE-UNOWNED-CONFLICT"
			health.Explanation = "A reviewed Tunnel or hostname is occupied and cannot be overwritten or adopted."
			health.NextActions = []string{"Check again", "Back"}
			if len(observed.Tunnels) == 0 {
				suggestion := suggestHostname(hostname, observed.Digest)
				available, suggestionErr := planner.ObserveMutation(ctx, MutationRequest{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Tunnel: request.TunnelName, Hostname: suggestion, Token: request.Authority.Token})
				if suggestionErr == nil && sha256Text.MatchString(available.Digest) && len(available.Tunnels) == 0 && len(available.DNSRecords) == 0 {
					health.NextActions = []string{"Use proposed hostname", "Check again", "Back"}
					return PlanResult{Health: finish(healthResult(i, health)).Health, SuggestedHostnames: []string{suggestion}}
				}
			}
			return PlanResult{Health: finish(healthResult(i, health)).Health}
		}
		digests = append(digests, observed.Digest)
	}
	steps, binding, err := installationSteps(request)
	if err != nil {
		health.Explanation = err.Error()
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	bound := struct {
		Request              PlanRequest
		TokenID, Observation string
	}{request, authority.Credential.ID, strings.Join(digests, "\n")}
	bound.Request.Authority.Token = ManagementToken{}
	encoded, _ := json.Marshal(bound)
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	use, _ := planUses.LoadOrStore(identity, &atomic.Bool{})
	plan := &Plan{identity: identity, sha256: checksum, observation: bound.Observation, request: request, steps: steps, checks: wholeTunnelChecks(), binding: binding, runToken: TunnelRunToken{cell: &runTokenCell{}}, used: use.(*atomic.Bool)}
	health = Health{Module: "Cloudflare Tunnel", Outcome: Healthy, Code: "CLOUDFLARE-PLAN-READY", Explanation: "The complete owned Cloudflare change is ready for review."}
	return PlanResult{Plan: plan, Health: finish(healthResult(i, health)).Health}
}

func suggestHostname(hostname, observation string) string {
	digest := sha256.Sum256([]byte(hostname + "\n" + observation))
	label, rest, ok := strings.Cut(hostname, ".")
	if !ok {
		return ""
	}
	if separator := strings.LastIndexByte(label, '-'); separator >= 0 && len(label)-separator-1 == 8 {
		if _, err := hex.DecodeString(label[separator+1:]); err == nil {
			label = label[:separator]
		}
	}
	return label + "-" + hex.EncodeToString(digest[:4]) + "." + rest
}

func (plan *Plan) StateDeferredCloudflare() (source any, bindingJSON []byte, templateSHA256 string, valid bool) {
	if plan == nil || plan.runToken.cell == nil || plan.binding.tunnel < 1 {
		return nil, nil, "", false
	}
	b := plan.binding
	bindingJSON, err := json.Marshal(struct {
		AccountID, ZoneID, TunnelName, XHTTPHostname, WebSocketHostname, DirectHostname string
		PublicIPv4, PublicIPv6                                                          string
		TunnelStep, XHTTPDNSRecordStep, WebSocketDNSRecordStep                          int
		DirectIPv4RecordStep, DirectIPv6RecordStep                                      int
	}{
		AccountID: plan.request.Authority.AccountID, ZoneID: plan.request.Authority.ZoneID,
		TunnelName: plan.request.TunnelName, XHTTPHostname: plan.request.XHTTPHostname,
		WebSocketHostname: plan.request.WebSocketHostname, DirectHostname: plan.request.DirectHostname,
		PublicIPv4: plan.request.PublicIPv4, PublicIPv6: plan.request.PublicIPv6,
		TunnelStep: b.tunnel, XHTTPDNSRecordStep: b.xhttp, WebSocketDNSRecordStep: b.websocket,
		DirectIPv4RecordStep: b.directIPv4, DirectIPv6RecordStep: b.directIPv6,
	})
	return plan.runToken, bindingJSON, plan.request.DesiredStateSHA256, err == nil
}

func (plan *Plan) Apply(module systemchanges.Interface, prepared systemchanges.PreparedStateCommit, starting systemchanges.StateLineage, volatileSHA256 string, disk systemchanges.DiskRequirement) systemchanges.ApplyResult {
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) || prepared == nil || !sha256Text.MatchString(volatileSHA256) || starting.Revision != plan.request.StartingRevision {
		return module.Apply(nil)
	}
	changeSet, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{Identity: plan.request.ChangeSet, Mutation: systemchanges.InstallationMutation, OutcomeOwner: systemchanges.CloudflareModule, StartingState: starting, TargetStateSHA256: plan.request.DesiredStateSHA256, Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: volatileSHA256}, PreparedState: prepared, Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute}, Disk: disk})
	if err != nil {
		return module.Apply(nil)
	}
	return module.Apply(changeSet)
}

func installationSteps(request PlanRequest) ([]systemchanges.Step, cloudflareEvidenceBinding, error) {
	changes := []systemchanges.CloudflareChange{
		{Action: systemchanges.CloudflareTunnelCreate, AccountID: request.Authority.AccountID, TunnelName: request.TunnelName},
		{Action: systemchanges.CloudflareRoutesPut, AccountID: request.Authority.AccountID, TunnelIDFromStep: 1, Routes: []systemchanges.CloudflareRoute{{Hostname: request.XHTTPHostname, Origin: xhttpOrigin}, {Hostname: request.WebSocketHostname, Origin: webSocketOrigin}, {Origin: "http_status:404"}}},
		{Action: systemchanges.CloudflareDNSCreate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, TunnelIDFromStep: 1, Hostname: request.XHTTPHostname, RecordType: "CNAME"},
		{Action: systemchanges.CloudflareDNSCreate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, TunnelIDFromStep: 1, Hostname: request.WebSocketHostname, RecordType: "CNAME"},
	}
	binding := cloudflareEvidenceBinding{tunnel: 1, xhttp: 3, websocket: 4}
	if request.PublicIPv4 != "" {
		changes = append(changes, systemchanges.CloudflareChange{Action: systemchanges.CloudflareDNSCreate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Hostname: request.DirectHostname, RecordType: "A", Content: request.PublicIPv4})
		binding.directIPv4 = len(changes)
	}
	if request.PublicIPv6 != "" {
		changes = append(changes, systemchanges.CloudflareChange{Action: systemchanges.CloudflareDNSCreate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Hostname: request.DirectHostname, RecordType: "AAAA", Content: request.PublicIPv6})
		binding.directIPv6 = len(changes)
	}
	steps := make([]systemchanges.Step, 0, len(changes)+1)
	for _, change := range changes {
		step, err := systemchanges.NewCloudflareStep(change)
		if err != nil {
			return nil, cloudflareEvidenceBinding{}, err
		}
		steps = append(steps, step)
	}
	activation, err := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return nil, cloudflareEvidenceBinding{}, err
	}
	steps = append(steps, activation)
	return steps, binding, nil
}

func wholeTunnelChecks() []systemchanges.Check {
	return []systemchanges.Check{
		{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CLOUDFLARE-WHOLE-TUNNEL"},
		{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CLOUDFLARE-WHOLE-TUNNEL"},
	}
}

func validPlanRequest(request PlanRequest) bool {
	return request.StartingRevision == 0 && safePlanName.MatchString(request.ChangeSet) && sha256Text.MatchString(request.DesiredStateSHA256) && safePlanName.MatchString(request.TunnelName) && request.CloudflaredVersion == qualifiedCloudflaredVersion && validOwnedHostname(request.XHTTPHostname, request.Authority.ZoneName, "xhttp") && validOwnedHostname(request.WebSocketHostname, request.Authority.ZoneName, "ws") && validOwnedHostname(request.DirectHostname, request.Authority.ZoneName, "direct") && request.XHTTPHostname != request.WebSocketHostname && request.XHTTPHostname != request.DirectHostname && request.WebSocketHostname != request.DirectHostname && validPublicAddresses(request.PublicIPv4, request.PublicIPv6)
}

func validOwnedHostname(hostname, zone, label string) bool {
	if !validZoneName(hostname) || !strings.HasSuffix(hostname, "."+zone) {
		return false
	}
	selected := strings.TrimSuffix(hostname, "."+zone)
	if selected == label {
		return true
	}
	suffix, ok := strings.CutPrefix(selected, label+"-")
	_, err := hex.DecodeString(suffix)
	return ok && len(suffix) == 8 && err == nil
}

func validPublicAddresses(ipv4, ipv6 string) bool {
	v4, v4Err := netip.ParseAddr(ipv4)
	v6, v6Err := netip.ParseAddr(ipv6)
	return (ipv4 == "" || v4Err == nil && v4.Is4()) && (ipv6 == "" || v6Err == nil && v6.Is6()) && (ipv4 != "" || ipv6 != "")
}

func healthResult(i Interface, health Health) ViewResult {
	result := ViewResult{Health: health}
	if i.clock != nil {
		result.LastCheck = i.clock.Now().UTC()
	}
	return result
}
