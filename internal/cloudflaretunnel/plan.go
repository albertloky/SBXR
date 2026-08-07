package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	qualifiedCloudflaredVersion = "2026.7.3"
	xhttpOrigin                 = "http://127.0.0.1:11080"
	cloudflaredTokenPath        = "/etc/sbxr/cloudflared/token"
)

var (
	safePlanName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`)
	sha256Text   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	planUses     sync.Map
)

type MutationPlanner interface {
	ObserveMutation(context.Context, MutationRequest) (MutationObservation, error)
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

type OwnedResource struct {
	ID   string
	Name string
}

type MutationObservation struct {
	Digest     string
	Tunnels    []OwnedResource
	DNSRecords []OwnedResource
}

type PlanRequest struct {
	Authority          ViewRequest
	ChangeSet          string
	StartingRevision   uint64
	DesiredStateSHA256 string
	TunnelName         string
	XHTTPHostname      string
	CloudflaredVersion string
}

type PlanResult struct {
	Plan   *Plan
	Health Health
}

func (result PlanResult) String() string {
	return fmt.Sprintf("Cloudflare Plan result: health=%s code=%s", result.Health.Outcome, result.Health.Code)
}

type Plan struct {
	identity     string
	sha256       string
	accountID    string
	zoneID       string
	tunnelName   string
	hostname     string
	observation  string
	desiredState string
	token        ManagementToken
	steps        []string
	used         *atomic.Bool
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
func (plan *Plan) Steps() []string {
	if plan == nil {
		return nil
	}
	return append([]string(nil), plan.steps...)
}
func (plan *Plan) String() string {
	if plan == nil {
		return "Cloudflare Plan: unavailable"
	}
	return fmt.Sprintf("Cloudflare Plan %s: create one named Tunnel %s; publish %s to %s through Cloudflare edge TLS; create its owned proxied DNS record; configure cloudflared.service with --token-file %s; end with HTTP 404 catch-all", plan.identity, plan.tunnelName, plan.hostname, xhttpOrigin, cloudflaredTokenPath)
}
func (plan *Plan) GoString() string { return plan.String() }

func (i Interface) Plan(ctx context.Context, request PlanRequest) PlanResult {
	health := Health{Outcome: Failed, Code: "CLOUDFLARE-PLAN-REFUSED", Module: "Cloudflare Tunnel"}
	planner, ok := i.api.(MutationPlanner)
	if !ok || !safePlanName.MatchString(request.ChangeSet) || request.StartingRevision > 0 || !sha256Text.MatchString(request.DesiredStateSHA256) || !safePlanName.MatchString(request.TunnelName) || !validZoneName(request.XHTTPHostname) || request.CloudflaredVersion != qualifiedCloudflaredVersion || request.Authority.ZoneName == request.XHTTPHostname || !strings.HasSuffix(request.XHTTPHostname, "."+request.Authority.ZoneName) {
		health.Explanation = "The XHTTP creation request is incomplete or outside the qualified contract."
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	authority := i.View(ctx, request.Authority)
	if authority.Health.Outcome != Healthy {
		return PlanResult{Health: authority.Health}
	}
	observed, err := planner.ObserveMutation(ctx, MutationRequest{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Tunnel: request.TunnelName, Hostname: request.XHTTPHostname, Token: request.Authority.Token})
	if err != nil || !sha256Text.MatchString(observed.Digest) {
		health = safeAPIHealth(err)
		if err == nil {
			health = Health{Outcome: Failed, Code: "CLOUDFLARE-OBSERVATION-INVALID", Explanation: "The fresh provider observation is incomplete."}
		}
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	if len(observed.Tunnels) != 0 || len(observed.DNSRecords) != 0 {
		health.Explanation = "The selected Tunnel name or XHTTP hostname is already occupied and cannot be adopted."
		health.NextActions = []string{"Choose the proposed available hostname", "Check again", "Back"}
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	binding := struct {
		ChangeSet, AccountID, ZoneID, TokenID, TunnelName, Hostname, Origin, Observation, DesiredState, Version string
		Revision                                                                                                uint64
	}{request.ChangeSet, request.Authority.AccountID, request.Authority.ZoneID, authority.Credential.ID, request.TunnelName, request.XHTTPHostname, xhttpOrigin, observed.Digest, request.DesiredStateSHA256, request.CloudflaredVersion, request.StartingRevision}
	encoded, _ := json.Marshal(binding)
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	use, _ := planUses.LoadOrStore(identity, &atomic.Bool{})
	plan := &Plan{identity: identity, sha256: checksum, accountID: request.Authority.AccountID, zoneID: request.Authority.ZoneID, tunnelName: request.TunnelName, hostname: request.XHTTPHostname, observation: observed.Digest, desiredState: request.DesiredStateSHA256, token: request.Authority.Token, steps: []string{"Create named Cloudflare Tunnel", "Record returned Tunnel identifier", "Publish XHTTP route and HTTP 404 catch-all", "Create owned proxied XHTTP DNS record and prepare cloudflared.service"}, used: use.(*atomic.Bool)}
	health = Health{Outcome: Healthy, Code: "CLOUDFLARE-XHTTP-PLAN", Module: "Cloudflare Tunnel", Explanation: "One exact XHTTP Tunnel creation is ready for review."}
	return PlanResult{Plan: plan, Health: finish(healthResult(i, health)).Health}
}

func healthResult(i Interface, health Health) ViewResult {
	result := ViewResult{Health: health}
	if i.clock != nil {
		result.LastCheck = i.clock.Now().UTC()
	}
	return result
}
