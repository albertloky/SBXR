package cloudflaretunnel

import (
	"context"
	"fmt"
	"regexp"
	"sync/atomic"
	"time"
)

var tunnelUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type MutationAPI interface {
	API
	MutationPlanner
	CreateTunnel(context.Context, CreateTunnelRequest) (CreatedTunnel, error)
	PutConfiguration(context.Context, PutConfigurationRequest) (Configuration, error)
	CreateDNSRecord(context.Context, CreateDNSRecordRequest) (OwnedResource, error)
	CheckXHTTP(context.Context, XHTTPHealthRequest) (bool, error)
	DeleteDNSRecord(context.Context, DeleteDNSRecordRequest) error
	DeleteTunnel(context.Context, DeleteTunnelRequest) error
}

type CreateTunnelRequest struct {
	AccountID, Name string
	Token           ManagementToken
}
type TunnelRunToken struct {
	value string
	used  *atomic.Bool
}

func newTunnelRunToken(value string) TunnelRunToken {
	return TunnelRunToken{value: value, used: &atomic.Bool{}}
}
func (TunnelRunToken) String() string   { return "Cloudflare Tunnel run token: redacted" }
func (TunnelRunToken) GoString() string { return "Cloudflare Tunnel run token: redacted" }
func (token TunnelRunToken) ConsumeInfrastructureSecret() (string, bool) {
	if token.used == nil || !token.used.CompareAndSwap(false, true) {
		return "", false
	}
	return token.value, true
}

type CreatedTunnel struct {
	ID, Name string
	RunToken TunnelRunToken
}

func (created CreatedTunnel) String() string {
	return fmt.Sprintf("created Cloudflare Tunnel id=%s name=%s token=redacted", created.ID, created.Name)
}
func (created CreatedTunnel) GoString() string { return created.String() }

type Route struct{ Hostname, Service string }
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
	ZoneID, Name, Content string
	Proxied               bool
	Token                 ManagementToken
}
type XHTTPHealthRequest struct {
	AccountID, ZoneID, TunnelID, DNSRecordID, Hostname, Origin string
	Token                                                      ManagementToken
}
type DeleteDNSRecordRequest struct {
	ZoneID, ID string
	Token      ManagementToken
}
type DeleteTunnelRequest struct {
	AccountID, ID string
	Token         ManagementToken
}

type ServiceContract struct {
	Unit, Identity, TokenPath string
	DirectoryMode, FileMode   uint32
	RunToken                  TunnelRunToken
}

func (contract ServiceContract) UnitFile() string {
	return "[Unit]\nDescription=SBXR Cloudflare Tunnel\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=notify\nUser=cloudflared\nGroup=cloudflared\nExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run --token-file " + contract.TokenPath + "\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n\n[Install]\nWantedBy=multi-user.target\n"
}

func (contract ServiceContract) ValidationConfig(hostname string) string {
	return "ingress:\n  - hostname: " + hostname + "\n    service: " + xhttpOrigin + "\n  - service: http_status:404\n"
}

func (contract ServiceContract) String() string {
	return fmt.Sprintf("%s identity=%s token-file=%s directory=%#o file=%#o token=redacted", contract.Unit, contract.Identity, contract.TokenPath, contract.DirectoryMode, contract.FileMode)
}
func (contract ServiceContract) GoString() string { return contract.String() }

// SystemChangesTransaction is the narrow handoff implemented by the one
// System Changes transaction Adapter. It durably records non-secret provider
// identities and writes protected service material before acknowledging them.
type SystemChangesTransaction interface {
	RecordCreated(kind, immutableID string) error
	PrepareCloudflared(ServiceContract) error
}

type ApplyOutcome string

const (
	ApplyCompleted         ApplyOutcome = "Completed"
	ApplyRefused           ApplyOutcome = "Refused"
	ApplyRollbackSucceeded ApplyOutcome = "Rollback succeeded"
	ApplyRecoveryRequired  ApplyOutcome = "Recovery Required"
)

type ApplyResult struct {
	Outcome               ApplyOutcome
	PlanConsumed          bool
	TunnelID, DNSRecordID string
	Code                  string
}

type ApplyRequest struct {
	Plan               *Plan
	StartingRevision   uint64
	DesiredStateSHA256 string
}

func (result ApplyResult) String() string {
	return fmt.Sprintf("Cloudflare Apply: outcome=%s code=%s tunnel=%s dns=%s", result.Outcome, result.Code, result.TunnelID, result.DNSRecordID)
}

func (i Interface) Apply(ctx context.Context, request ApplyRequest, transaction SystemChangesTransaction) ApplyResult {
	plan := request.Plan
	if plan == nil || plan.used == nil || transaction == nil || !plan.used.CompareAndSwap(false, true) {
		return ApplyResult{Outcome: ApplyRefused, Code: "CLOUDFLARE-PLAN-STALE"}
	}
	if request.StartingRevision != 0 || request.DesiredStateSHA256 != plan.desiredState {
		return ApplyResult{Outcome: ApplyRefused, PlanConsumed: true, Code: "CLOUDFLARE-PLAN-STALE"}
	}
	api, ok := i.api.(MutationAPI)
	if !ok || i.clock == nil {
		return ApplyResult{Outcome: ApplyRefused, PlanConsumed: true, Code: "CLOUDFLARE-APPLY-ADAPTER"}
	}
	observed, err := api.ObserveMutation(ctx, MutationRequest{AccountID: plan.accountID, ZoneID: plan.zoneID, Tunnel: plan.tunnelName, Hostname: plan.hostname, Token: plan.token})
	if err != nil || observed.Digest != plan.observation || len(observed.Tunnels) != 0 || len(observed.DNSRecords) != 0 {
		return ApplyResult{Outcome: ApplyRefused, PlanConsumed: true, Code: "CLOUDFLARE-PLAN-STALE"}
	}
	created, err := api.CreateTunnel(ctx, CreateTunnelRequest{AccountID: plan.accountID, Name: plan.tunnelName, Token: plan.token})
	if err != nil || !tunnelUUID.MatchString(created.ID) || created.Name != plan.tunnelName || created.RunToken.value == "" {
		return ApplyResult{Outcome: ApplyRollbackSucceeded, PlanConsumed: true, Code: "CLOUDFLARE-TUNNEL-CREATE"}
	}
	if err := transaction.RecordCreated("tunnel", created.ID); err != nil {
		return i.rollback(ctx, api, plan, created.ID, "", true)
	}
	routes := []Route{{Hostname: plan.hostname, Service: xhttpOrigin}, {Service: "http_status:404"}}
	configured, err := api.PutConfiguration(ctx, PutConfigurationRequest{AccountID: plan.accountID, TunnelID: created.ID, Token: plan.token, Routes: routes})
	if err != nil || configured.TunnelID != created.ID || configured.Version < 1 || !sameRoutes(configured.Routes, routes) {
		return i.rollback(ctx, api, plan, created.ID, "", true)
	}
	dns, err := api.CreateDNSRecord(ctx, CreateDNSRecordRequest{ZoneID: plan.zoneID, Name: plan.hostname, Content: created.ID + ".cfargotunnel.com", Proxied: true, Token: plan.token})
	if err != nil || !immutableID.MatchString(dns.ID) || dns.Name != plan.hostname {
		return i.rollback(ctx, api, plan, created.ID, "", true)
	}
	if err := transaction.RecordCreated("dns-record", dns.ID); err != nil {
		return i.rollback(ctx, api, plan, created.ID, dns.ID, true)
	}
	service := ServiceContract{Unit: "cloudflared.service", Identity: "cloudflared", TokenPath: cloudflaredTokenPath, DirectoryMode: 0o750, FileMode: 0o640, RunToken: created.RunToken}
	if err := transaction.PrepareCloudflared(service); err != nil {
		return i.rollback(ctx, api, plan, created.ID, dns.ID, true)
	}
	deadline := i.clock.Now().Add(5 * time.Minute)
	apiFailures := 0
	for {
		healthy, healthErr := api.CheckXHTTP(ctx, XHTTPHealthRequest{AccountID: plan.accountID, ZoneID: plan.zoneID, TunnelID: created.ID, DNSRecordID: dns.ID, Hostname: plan.hostname, Origin: xhttpOrigin, Token: plan.token})
		if healthErr == nil && healthy {
			return ApplyResult{Outcome: ApplyCompleted, PlanConsumed: true, TunnelID: created.ID, DNSRecordID: dns.ID, Code: "CLOUDFLARE-XHTTP-HEALTHY"}
		}
		wait := 10 * time.Second
		if healthErr != nil {
			apiFailures++
			wait = 30 * time.Second
		}
		if apiFailures >= 3 || !i.clock.Now().Before(deadline) || i.clock.Sleep(ctx, wait) != nil {
			return i.rollback(ctx, api, plan, created.ID, dns.ID, true)
		}
	}
}

func (i Interface) rollback(ctx context.Context, api MutationAPI, plan *Plan, tunnelID, dnsID string, consumed bool) ApplyResult {
	if dnsID != "" && api.DeleteDNSRecord(ctx, DeleteDNSRecordRequest{ZoneID: plan.zoneID, ID: dnsID, Token: plan.token}) != nil {
		return ApplyResult{Outcome: ApplyRecoveryRequired, PlanConsumed: consumed, Code: "CLOUDFLARE-ROLLBACK-UNPROVED"}
	}
	if tunnelID != "" && api.DeleteTunnel(ctx, DeleteTunnelRequest{AccountID: plan.accountID, ID: tunnelID, Token: plan.token}) != nil {
		return ApplyResult{Outcome: ApplyRecoveryRequired, PlanConsumed: consumed, Code: "CLOUDFLARE-ROLLBACK-UNPROVED"}
	}
	return ApplyResult{Outcome: ApplyRollbackSucceeded, PlanConsumed: consumed, Code: "CLOUDFLARE-ROLLED-BACK"}
}

func sameRoutes(left, right []Route) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
