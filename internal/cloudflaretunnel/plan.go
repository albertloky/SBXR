package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
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
	GetConfiguration(context.Context, GetConfigurationRequest) (Configuration, error)
	GetTunnel(context.Context, GetTunnelRequest) (OwnedResource, error)
	CreateDNSRecord(context.Context, CreateDNSRecordRequest) (OwnedResource, error)
	GetDNSRecord(context.Context, GetDNSRecordRequest) (DNSObservation, error)
	PutDNSRecord(context.Context, PutDNSRecordRequest) (OwnedResource, error)
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
	Routes     []Route
}

type ReclamationKind string

const (
	ReclamationDNS    ReclamationKind = "DNS record"
	ReclamationRoutes ReclamationKind = "Tunnel routes"
	ReclamationTunnel ReclamationKind = "Tunnel"
)

type ReclamationConflict struct {
	Kind   ReclamationKind
	ID     string
	Name   string
	Routes []Route
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
	return token.consume()
}
func (token TunnelRunToken) consume() (string, bool) {
	if token.cell == nil || !token.cell.used.CompareAndSwap(false, true) {
		return "", false
	}
	token.cell.mu.Lock()
	defer token.cell.mu.Unlock()
	return token.cell.value, token.cell.value != ""
}

type PlanRequest struct {
	Authority            ViewRequest
	ChangeSet            string
	StartingRevision     uint64
	StartingStateSHA256  string
	DesiredStateSHA256   string
	TunnelName           string
	XHTTPHostname        string
	WebSocketHostname    string
	DirectHostname       string
	PublicIPv4           string
	PublicIPv6           string
	CloudflaredVersion   string
	ManagementToken      ManagementTokenChange
	RunTokenRotation     RunTokenRotation
	ManagedRepair        OwnedTunnelBinding
	ReleaseUpdate        bool
	CandidateServiceUnit string
	Reclamation          []ReclamationConflict
}

type ManagementTokenAction string

const (
	ManagementTokenReplace ManagementTokenAction = "replace"
	ManagementTokenRemove  ManagementTokenAction = "remove"
)

type ManagementTokenDependency string

const (
	TunnelDependency      ManagementTokenDependency = "Tunnel"
	DNSDependency         ManagementTokenDependency = "DNS"
	CertificateDependency ManagementTokenDependency = "certificate"
	ProfileDependency     ManagementTokenDependency = "profile"
	RepairDependency      ManagementTokenDependency = "repair"
	UpdateDependency      ManagementTokenDependency = "update"
)

type ManagementTokenChange struct {
	Action               ManagementTokenAction
	CurrentTokenID       string
	StartingTokenRemoved bool
	Inventory            ManagementTokenInventoryAuthority
	Resolution           ManagementTokenResolution
}

type ManagementTokenInventoryAuthority interface {
	StateManagementTokenInventory() (bindingJSON []byte, valid bool)
}

type ManagementTokenResolution string

const MarkDependenciesUnmanaged ManagementTokenResolution = "mark dependencies unmanaged"

type Plan struct {
	identity, sha256, observation string
	request                       PlanRequest
	steps                         []systemchanges.Step
	checks                        []systemchanges.Check
	binding                       cloudflareEvidenceBinding
	runToken                      TunnelRunToken
	managementToken               VerifiedManagementToken
	releaseUpdate                 bool
	managedRepair                 bool
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

func (plan *Plan) StateRuntimeArtifacts() (source any, services []string, valid bool) {
	if plan == nil || plan.identity == "" || !sha256Text.MatchString(plan.sha256) {
		return nil, nil, false
	}
	return plan, []string{"cloudflared.service"}, true
}

// CertificateLifecycleFreshDNSPlan exposes only the exact Direct DNS records
// contained in a reviewed fresh-install Plan.
func (plan *Plan) CertificateLifecycleFreshDNSPlan() (hostname, ipv4, ipv6, desiredStateSHA256 string, valid bool) {
	if plan == nil || plan.request.StartingRevision != 0 || !validPlanRequest(plan.request) || plan.identity == "" || plan.sha256 == "" {
		return "", "", "", "", false
	}
	return plan.request.DirectHostname, plan.request.PublicIPv4, plan.request.PublicIPv6, plan.request.DesiredStateSHA256, true
}

// MatchesDesiredState keeps Cloudflare's secret and fixed-fact comparison in
// the owning Module while State supplies the protected value through its lease.
func (plan *Plan) MatchesDesiredState(accountID, zoneID, zoneName, tunnelName, xhttpHostname, webSocketHostname, directHostname, publicIPv4, publicIPv6, managementToken string) bool {
	if plan == nil || plan.identity == "" || plan.sha256 == "" {
		return false
	}
	r := plan.request
	return accountID == r.Authority.AccountID && zoneID == r.Authority.ZoneID && zoneName == r.Authority.ZoneName && tunnelName == r.TunnelName && xhttpHostname == r.XHTTPHostname && webSocketHostname == r.WebSocketHostname && directHostname == r.DirectHostname && publicIPv4 == r.PublicIPv4 && publicIPv6 == r.PublicIPv6 && managementToken == r.Authority.Token.value
}

func (plan *Plan) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	if plan == nil || plan.request.StartingRevision != 0 || plan.request.ManagementToken.Action != "" || plan.request.RunTokenRotation.TunnelID != "" || plan.request.ManagedRepair.TunnelID != "" {
		return lifecyclecontract.InstallContribution{}
	}
	digest := sha256.Sum256([]byte(plan.observation))
	return lifecyclecontract.InstallContribution{Name: "Cloudflare Tunnel", Owner: systemchanges.CloudflareModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: hex.EncodeToString(digest[:]), ChangeSet: plan.request.ChangeSet, DesiredStateSHA256: plan.request.DesiredStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
}
func (plan *Plan) SoftwareLifecycleUpdateContribution() lifecyclecontract.UpdateContribution {
	if plan == nil || !plan.releaseUpdate || plan.request.StartingRevision == 0 {
		return lifecyclecontract.UpdateContribution{}
	}
	digest := sha256.Sum256([]byte(plan.observation))
	return lifecyclecontract.UpdateContribution{Name: "Cloudflare Tunnel", Owner: systemchanges.CloudflareModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: hex.EncodeToString(digest[:]), ChangeSet: plan.request.ChangeSet, DesiredStateSHA256: plan.request.DesiredStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
}
func (plan *Plan) SoftwareLifecycleRepairContribution() lifecyclecontract.RepairContribution {
	if plan == nil || !plan.managedRepair || plan.request.ManagedRepair.TunnelID == "" || plan.request.StartingRevision == 0 || plan.request.StartingStateSHA256 == "" {
		return lifecyclecontract.RepairContribution{}
	}
	digest := sha256.Sum256([]byte(plan.observation))
	return lifecyclecontract.RepairContribution{Name: "Cloudflare Tunnel", Owner: systemchanges.CloudflareModule, Identity: plan.identity, SHA256: plan.sha256, StableSHA256: hex.EncodeToString(digest[:]), ChangeSet: plan.request.ChangeSet, CurrentRevision: plan.request.StartingRevision, CurrentStateSHA256: plan.request.StartingStateSHA256, Steps: plan.Steps(), Checks: plan.Checks(), Details: []string{plan.String()}}
}
func (plan *Plan) String() string {
	if plan == nil {
		return "Cloudflare Plan: unavailable"
	}
	switch plan.request.ManagementToken.Action {
	case ManagementTokenReplace:
		return fmt.Sprintf("Cloudflare Plan %s: stored management token changes only at State publication; old token remains active; resources remain unchanged", plan.identity)
	case ManagementTokenRemove:
		return fmt.Sprintf("Cloudflare Plan %s: stored management token becomes deliberately absent; provider health becomes Unknown; repair and update remain blocked", plan.identity)
	default:
		if plan.releaseUpdate {
			return fmt.Sprintf("Cloudflare Plan %s: restart cloudflared.service with the candidate release and prove the exact owned Tunnel, routes, and DNS", plan.identity)
		}
		if plan.request.RunTokenRotation.TunnelID != "" {
			return fmt.Sprintf("Cloudflare Plan %s: Owner selects Rotate token for Tunnel %s; SBXR retrieves the changed token, restarts cloudflared, proves both routes, and uses forward-only recovery", plan.identity, plan.request.RunTokenRotation.TunnelID)
		}
		if plan.request.ManagedRepair.TunnelID != "" {
			return fmt.Sprintf("Cloudflare Plan %s: repair only committed Tunnel %s, routes, DNS, and cloudflared from exact rollback pre-images", plan.identity, plan.request.ManagedRepair.TunnelID)
		}
		return fmt.Sprintf("Cloudflare Plan %s: one Tunnel %s; XHTTP %s to %s; WebSocket %s to %s; DNS-only Direct TLS %s; cloudflared.service --token-file %s; HTTP 404 fallback", plan.identity, plan.request.TunnelName, plan.request.XHTTPHostname, xhttpOrigin, plan.request.WebSocketHostname, webSocketOrigin, plan.request.DirectHostname, cloudflaredTokenPath)
	}
}
func (plan *Plan) GoString() string { return plan.String() }

type PlanResult struct {
	Plan               *Plan
	Health             Health
	SuggestedHostnames []string
	Dependencies       []ManagementTokenDependency
	ResultingState     []string
	WritesProven       bool
}

type cloudflareEvidenceBinding struct {
	tunnel, xhttp, websocket, directIPv4, directIPv6 int
}

func (i Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	if request.ReleaseUpdate {
		return i.planReleaseUpdate(ctx, request)
	}
	if request.ManagementToken.Action != "" {
		return i.planManagementToken(ctx, request)
	}
	if request.RunTokenRotation.TunnelID != "" {
		return i.planRunTokenRotation(ctx, request)
	}
	if request.ManagedRepair.TunnelID != "" {
		return i.planManagedRepair(ctx, request)
	}
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
	var aggregate MutationObservation
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
		aggregate.Tunnels = appendUniqueResources(aggregate.Tunnels, observed.Tunnels...)
		aggregate.DNSRecords = appendUniqueResources(aggregate.DNSRecords, observed.DNSRecords...)
		if len(observed.Routes) > 0 {
			aggregate.Routes = append([]Route(nil), observed.Routes...)
		}
		if len(observed.Tunnels) != 0 || len(observed.DNSRecords) != 0 {
			if len(request.Reclamation) > 0 {
				digests = append(digests, observed.Digest)
				continue
			}
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
	if len(request.Reclamation) > 0 && !reclamationMatches(request.Reclamation, aggregate) {
		health.Code, health.Explanation = "CLOUDFLARE-UNOWNED-CONFLICT", "The reviewed Cloudflare conflict set changed or contains an unrelated resource."
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	steps, binding, err := installationSteps(request)
	if err != nil {
		health.Explanation = err.Error()
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	if err := i.validateNativeIngress(ctx, request); err != nil {
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

func validateNativeIngress(ctx context.Context, configuration []byte) error {
	file, err := os.CreateTemp("", "sbxr-cloudflared-*.json")
	if err != nil {
		return errors.New("cloudflared native configuration validation failed")
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(configuration); err != nil || file.Close() != nil {
		return errors.New("cloudflared native configuration validation failed")
	}
	if _, err = runCommand(ctx, "/usr/bin/cloudflared", "--config", name, "tunnel", "ingress", "validate"); err != nil {
		return errors.New("cloudflared native configuration validation failed")
	}
	return nil
}

func (i Interface) validateNativeIngress(ctx context.Context, request PlanRequest) error {
	if i.nativeIngress == nil {
		return errors.New("cloudflared native configuration validation failed")
	}
	material := serviceMaterial{Routes: []struct {
		Hostname string `json:"hostname"`
		Origin   string `json:"origin"`
	}{{Hostname: request.XHTTPHostname, Origin: xhttpOrigin}, {Hostname: request.WebSocketHostname, Origin: webSocketOrigin}}}
	return i.nativeIngress(ctx, serviceConfiguration(material))
}

func appendUniqueResources(current []OwnedResource, values ...OwnedResource) []OwnedResource {
	for _, value := range values {
		if !slices.Contains(current, value) {
			current = append(current, value)
		}
	}
	return current
}

func (i Interface) planReleaseUpdate(ctx context.Context, request PlanRequest) PlanResult {
	fail := func(explanation string) PlanResult {
		return PlanResult{Health: finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: "CLOUDFLARE-RELEASE-UPDATE-REFUSED", Explanation: explanation, NextActions: []string{"Check again", "Back"}})).Health}
	}
	owned := request.ManagedRepair
	validDirect := (request.PublicIPv4 == "") == (owned.DirectIPv4RecordID == "") && (request.PublicIPv6 == "") == (owned.DirectIPv6RecordID == "")
	if i.clock == nil || request.ManagementToken.Action != "" || request.RunTokenRotation.TunnelID != "" || request.StartingRevision == 0 || !safePlanName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || !tunnelUUID.MatchString(owned.TunnelID) || !immutableID.MatchString(owned.XHTTPDNSRecordID) || !immutableID.MatchString(owned.WebSocketDNSRecordID) || !validDirect || owned.DirectIPv4RecordID != "" && !immutableID.MatchString(owned.DirectIPv4RecordID) || owned.DirectIPv6RecordID != "" && !immutableID.MatchString(owned.DirectIPv6RecordID) || request.CloudflaredVersion != qualifiedCloudflaredVersion || !validReleaseUpdateServiceUnit(request.CandidateServiceUnit) || !validOwnedHostname(request.XHTTPHostname, request.Authority.ZoneName, "xhttp") || !validOwnedHostname(request.WebSocketHostname, request.Authority.ZoneName, "ws") || !validOwnedHostname(request.DirectHostname, request.Authority.ZoneName, "direct") || !validPublicAddresses(request.PublicIPv4, request.PublicIPv6) {
		return fail("The release update is incomplete or outside the committed Cloudflare ownership boundary.")
	}
	authority := i.View(ctx, request.Authority)
	observer, ok := i.api.(wholeTunnelObserver)
	if authority.Health.Outcome != Healthy || !ok {
		return PlanResult{Health: authority.Health}
	}
	expected, providerRequest := managedHealthRequest(request)
	observed, err := observer.ObserveWholeTunnel(ctx, providerRequest)
	if err != nil {
		return PlanResult{Health: finish(healthResult(i, safeAPIHealth(err))).Health}
	}
	if health := EvaluateWholeTunnel(observed, expected); health.Outcome != Healthy {
		return PlanResult{Health: health}
	}
	if err := i.validateNativeIngress(ctx, request); err != nil {
		return fail(err.Error())
	}
	step, err := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return fail("The cloudflared service update could not be built.")
	}
	bound := request
	bound.Authority.Token = ManagementToken{}
	encoded, _ := json.Marshal(struct {
		Request     PlanRequest
		Observation WholeTunnelObservation
	}{bound, observed})
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	use, _ := planUses.LoadOrStore(identity, &atomic.Bool{})
	plan := &Plan{identity: identity, sha256: checksum, observation: checksum, request: request, steps: []systemchanges.Step{step}, checks: wholeTunnelChecks(), releaseUpdate: true, used: use.(*atomic.Bool)}
	return PlanResult{Plan: plan, Health: finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Healthy, Code: "CLOUDFLARE-RELEASE-UPDATE-READY", Explanation: "The owned Tunnel is healthy and cloudflared.service is ready to restart with the candidate release."})).Health}
}

func validReleaseUpdateServiceUnit(unit string) bool {
	const marker = "ExecStart="
	start := strings.Index(unit, marker)
	if start < 0 {
		return false
	}
	start += len(marker)
	end := strings.IndexByte(unit[start:], ' ')
	if end < 0 {
		return false
	}
	program := unit[start : start+end]
	return strings.HasPrefix(program, "/opt/sbxr/releases/") && strings.HasSuffix(program, "/cloudflared") && !strings.Contains(program, "..") && !strings.ContainsAny(program, "\r\n\x00") && unit == strings.Replace(cloudflaredServiceUnit, "/usr/bin/cloudflared", program, 1)
}

func (i Interface) planManagementToken(ctx context.Context, request PlanRequest) PlanResult {
	failed := func(code, explanation string, dependencies []ManagementTokenDependency) PlanResult {
		health := finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: code, Explanation: explanation, NextActions: []string{"Check now", "Replace token", "Remove from SBXR"}})).Health
		return PlanResult{Health: health, Dependencies: append([]ManagementTokenDependency(nil), dependencies...)}
	}
	change := request.ManagementToken
	validCurrent := !change.StartingTokenRemoved && immutableID.MatchString(change.CurrentTokenID) || change.StartingTokenRemoved && change.CurrentTokenID == "" && change.Action == ManagementTokenReplace
	if i.clock == nil || !safePlanName.MatchString(request.ChangeSet) || request.StartingRevision == 0 || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || !validCurrent || !immutableID.MatchString(request.Authority.AccountID) || !immutableID.MatchString(request.Authority.ZoneID) || !validZoneName(request.Authority.ZoneName) {
		return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "The management-token change is incomplete or outside the fixed contract.", nil)
	}
	var replacement VerifiedManagementToken
	var dependencies []ManagementTokenDependency
	candidateTokenID := ""
	resultingState := []string{}
	switch change.Action {
	case ManagementTokenReplace:
		if change.Inventory != nil || change.Resolution != "" {
			return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "Replacement does not accept a removal dependency outcome.", nil)
		}
		view := i.View(ctx, request.Authority)
		if view.Health.Outcome != Healthy {
			return PlanResult{Health: view.Health}
		}
		if !change.StartingTokenRemoved && view.Credential.ID == change.CurrentTokenID {
			return failed("CLOUDFLARE-MANAGEMENT-TOKEN-UNCHANGED", "The replacement is the currently stored Cloudflare token.", nil)
		}
		var ok bool
		replacement, ok = view.VerifiedManagementToken()
		if !ok {
			return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "The verified replacement handoff is unavailable.", nil)
		}
		candidateTokenID = view.Credential.ID
		resultingState = []string{"stored management token changes only at State publication", "old token remains active", "resources remain unchanged"}
	case ManagementTokenRemove:
		var valid bool
		dependencies, valid = stateManagementTokenInventory(change.Inventory, request.StartingRevision, request.StartingStateSHA256)
		if !valid {
			return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "Removal requires the current State-owned dependency inventory.", nil)
		}
		if request.Authority.Token.value != "" || request.Authority.TokenRemoved {
			return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "Removal accepts no replacement credential.", dependencies)
		}
		if len(dependencies) != 0 && (change.Resolution != MarkDependenciesUnmanaged || len(dependencies) != 6) || len(dependencies) == 0 && change.Resolution != "" {
			return failed("CLOUDFLARE-MANAGEMENT-TOKEN-DEPENDENCIES", "The stored token remains required by reviewed dependent behavior.", dependencies)
		}
		resultingState = []string{"stored management token becomes deliberately absent"}
		for _, dependency := range dependencies {
			resultingState = append(resultingState, string(dependency)+" becomes "+string(MarkDependenciesUnmanaged))
		}
		resultingState = append(resultingState, "provider health becomes Unknown", "repair and update remain blocked")
	default:
		return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "The management-token action is unsupported.", dependencies)
	}
	steps, err := tokenLifecycleSteps()
	if err != nil {
		return failed("CLOUDFLARE-MANAGEMENT-TOKEN-REFUSED", "The management-token transaction could not be built.", dependencies)
	}
	bound := struct {
		Request          PlanRequest
		CandidateTokenID string
		Dependencies     []ManagementTokenDependency
	}{request, candidateTokenID, dependencies}
	bound.Request.Authority.Token = ManagementToken{}
	bound.Request.ManagementToken.Inventory = nil
	encoded, _ := json.Marshal(bound)
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	use, _ := planUses.LoadOrStore(identity, &atomic.Bool{})
	plan := &Plan{identity: identity, sha256: checksum, request: request, steps: steps, checks: tokenLifecycleChecks(change.Action), managementToken: replacement, used: use.(*atomic.Bool)}
	health := finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Healthy, Code: "CLOUDFLARE-MANAGEMENT-TOKEN-READY", Explanation: "The reviewed management-token change is ready for the State and System Changes transaction."})).Health
	return PlanResult{Plan: plan, Health: health, Dependencies: append([]ManagementTokenDependency(nil), dependencies...), ResultingState: resultingState}
}

func stateManagementTokenInventory(authority ManagementTokenInventoryAuthority, revision uint64, stateSHA256 string) ([]ManagementTokenDependency, bool) {
	typeOf := reflect.TypeOf(authority)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().PkgPath() != "github.com/albertloky/SBXR/internal/state" || typeOf.Elem().Name() != "ManagementTokenInventory" {
		return nil, false
	}
	bindingJSON, valid := authority.StateManagementTokenInventory()
	var binding struct {
		Revision     uint64
		StateSHA256  string
		Dependencies []ManagementTokenDependency
	}
	if json.Unmarshal(bindingJSON, &binding) != nil || !valid || binding.Revision != revision || binding.StateSHA256 != stateSHA256 || !validTokenDependencies(binding.Dependencies) {
		return nil, false
	}
	return binding.Dependencies, true
}

func validTokenDependencies(dependencies []ManagementTokenDependency) bool {
	seen := map[ManagementTokenDependency]bool{}
	for _, dependency := range dependencies {
		switch dependency {
		case TunnelDependency, DNSDependency, CertificateDependency, ProfileDependency, RepairDependency, UpdateDependency:
		default:
			return false
		}
		if seen[dependency] {
			return false
		}
		seen[dependency] = true
	}
	return true
}

func tokenLifecycleSteps() ([]systemchanges.Step, error) {
	step, err := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.RecordManagementTokenChange, systemchanges.RestoreManagementTokenRecord)
	if err != nil {
		return nil, err
	}
	return []systemchanges.Step{step}, nil
}

func tokenLifecycleChecks(action ManagementTokenAction) []systemchanges.Check {
	code := "CLOUDFLARE-MANAGEMENT-TOKEN-REPLACED"
	if action == ManagementTokenRemove {
		code = "CLOUDFLARE-MANAGEMENT-TOKEN-REMOVED"
	}
	return []systemchanges.Check{
		{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: code},
		{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: code},
	}
}

func (plan *Plan) StateManagementTokenChange() (source any, bindingJSON []byte, templateSHA256 string, valid bool) {
	if plan == nil || plan.request.ManagementToken.Action == "" || plan.used == nil {
		return nil, nil, "", false
	}
	change := plan.request.ManagementToken
	bindingJSON, err := json.Marshal(struct {
		Action               ManagementTokenAction
		CurrentTokenID       string
		StartingTokenRemoved bool
		AccountID            string
		ZoneID               string
		ZoneName             string
		Dependencies         []ManagementTokenDependency
		Resolution           ManagementTokenResolution
	}{change.Action, change.CurrentTokenID, change.StartingTokenRemoved, plan.request.Authority.AccountID, plan.request.Authority.ZoneID, plan.request.Authority.ZoneName, planDependencies(plan), change.Resolution})
	if change.Action == ManagementTokenReplace {
		source = plan.managementToken
	}
	return source, bindingJSON, plan.request.DesiredStateSHA256, err == nil
}

func planDependencies(plan *Plan) []ManagementTokenDependency {
	dependencies, _ := stateManagementTokenInventory(plan.request.ManagementToken.Inventory, plan.request.StartingRevision, plan.request.StartingStateSHA256)
	return dependencies
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
	mutation := systemchanges.InstallationMutation
	targetSHA256 := plan.request.DesiredStateSHA256
	if plan.request.ManagementToken.Action != "" || plan.request.RunTokenRotation.TunnelID != "" || plan.request.ManagedRepair.TunnelID != "" {
		changeSet, revision, startingSHA256, candidateSHA256, planIdentity, planSHA256, valid := prepared.SystemChangesPreparedState()
		if !valid || starting.Status != systemchanges.Managed || starting.SHA256 != plan.request.StartingStateSHA256 || changeSet != plan.request.ChangeSet || revision != starting.Revision+1 || startingSHA256 != starting.SHA256 || planIdentity != plan.identity || planSHA256 != plan.sha256 || !sha256Text.MatchString(candidateSHA256) {
			return module.Apply(nil)
		}
		mutation = systemchanges.SettingChangeMutation
		if plan.request.RunTokenRotation.TunnelID != "" {
			mutation = systemchanges.RotationMutation
		} else if plan.request.ManagedRepair.TunnelID != "" {
			mutation = systemchanges.RepairMutation
		}
		targetSHA256 = candidateSHA256
	}
	changeSet, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{Identity: plan.request.ChangeSet, Mutation: mutation, OutcomeOwner: systemchanges.CloudflareModule, StartingState: starting, TargetStateSHA256: targetSHA256, Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: volatileSHA256}, PreparedState: prepared, Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: 5 * time.Minute, Check: 5 * time.Minute}, Disk: disk})
	if err != nil {
		return module.Apply(nil)
	}
	return module.Apply(changeSet)
}

func installationSteps(request PlanRequest) ([]systemchanges.Step, cloudflareEvidenceBinding, error) {
	changes := make([]systemchanges.CloudflareChange, 0, len(request.Reclamation)+6)
	for _, conflict := range request.Reclamation {
		change := systemchanges.CloudflareChange{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, TunnelID: conflict.ID, TunnelName: conflict.Name}
		switch conflict.Kind {
		case ReclamationDNS:
			change.Action, change.DNSRecordID, change.Hostname, change.TunnelID, change.TunnelName = systemchanges.CloudflareDNSDelete, conflict.ID, conflict.Name, "", ""
		case ReclamationRoutes:
			change.Action, change.Routes = systemchanges.CloudflareRoutesDelete, systemRoutes(conflict.Routes)
		case ReclamationTunnel:
			change.Action = systemchanges.CloudflareTunnelDelete
		default:
			return nil, cloudflareEvidenceBinding{}, errors.New("unsupported Cloudflare reclamation target")
		}
		changes = append(changes, change)
	}
	offset := len(changes)
	changes = append(changes, []systemchanges.CloudflareChange{
		{Action: systemchanges.CloudflareTunnelCreate, AccountID: request.Authority.AccountID, TunnelName: request.TunnelName},
		{Action: systemchanges.CloudflareRoutesPut, AccountID: request.Authority.AccountID, TunnelIDFromStep: 1, Routes: []systemchanges.CloudflareRoute{{Hostname: request.XHTTPHostname, Origin: xhttpOrigin}, {Hostname: request.WebSocketHostname, Origin: webSocketOrigin}, {Origin: "http_status:404"}}},
		{Action: systemchanges.CloudflareDNSCreate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, TunnelIDFromStep: 1, Hostname: request.XHTTPHostname, RecordType: "CNAME"},
		{Action: systemchanges.CloudflareDNSCreate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, TunnelIDFromStep: 1, Hostname: request.WebSocketHostname, RecordType: "CNAME"},
	}...)
	for index := offset; index < len(changes); index++ {
		if changes[index].TunnelIDFromStep == 1 {
			changes[index].TunnelIDFromStep = offset + 1
		}
	}
	binding := cloudflareEvidenceBinding{tunnel: offset + 1, xhttp: offset + 3, websocket: offset + 4}
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

func reclamationMatches(want []ReclamationConflict, got MutationObservation) bool {
	if len(want) == 0 {
		return false
	}
	matched := 0
	for _, tunnel := range got.Tunnels {
		if !slices.ContainsFunc(want, func(item ReclamationConflict) bool {
			return item.Kind == ReclamationTunnel && item.ID == tunnel.ID && item.Name == tunnel.Name
		}) || !slices.ContainsFunc(want, func(item ReclamationConflict) bool {
			return item.Kind == ReclamationRoutes && item.ID == tunnel.ID && item.Name == tunnel.Name && reflect.DeepEqual(item.Routes, got.Routes)
		}) {
			return false
		}
		matched += 2
	}
	for _, dns := range got.DNSRecords {
		if !slices.ContainsFunc(want, func(item ReclamationConflict) bool {
			return item.Kind == ReclamationDNS && item.ID == dns.ID && item.Name == dns.Name
		}) {
			return false
		}
		matched++
	}
	return matched > 0 && matched == len(want)
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
