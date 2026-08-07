package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

// OwnedTunnelBinding names the committed provider resources used by repair and
// run-token rotation. It contains no credential value.
type OwnedTunnelBinding struct {
	TunnelID             string
	XHTTPDNSRecordID     string
	WebSocketDNSRecordID string
	DirectIPv4RecordID   string
	DirectIPv6RecordID   string
}

type RunTokenRotation = OwnedTunnelBinding

type wholeTunnelObserver interface {
	ObserveWholeTunnel(context.Context, WholeTunnelRequest) (WholeTunnelObservation, error)
}

func (i Interface) planRunTokenRotation(ctx context.Context, request PlanRequest) PlanResult {
	fail := func(code, explanation string) PlanResult {
		return PlanResult{Health: finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: code, Explanation: explanation, NextActions: []string{"Check again", "Back"}})).Health}
	}
	rotation := request.RunTokenRotation
	validDirect := (request.PublicIPv4 == "") == (rotation.DirectIPv4RecordID == "") && (request.PublicIPv6 == "") == (rotation.DirectIPv6RecordID == "")
	if i.clock == nil || request.ManagementToken.Action != "" || request.StartingRevision == 0 || !safePlanName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || !tunnelUUID.MatchString(rotation.TunnelID) || !immutableID.MatchString(rotation.XHTTPDNSRecordID) || !immutableID.MatchString(rotation.WebSocketDNSRecordID) || !validDirect || rotation.DirectIPv4RecordID != "" && !immutableID.MatchString(rotation.DirectIPv4RecordID) || rotation.DirectIPv6RecordID != "" && !immutableID.MatchString(rotation.DirectIPv6RecordID) || request.CloudflaredVersion != qualifiedCloudflaredVersion || !validOwnedHostname(request.XHTTPHostname, request.Authority.ZoneName, "xhttp") || !validOwnedHostname(request.WebSocketHostname, request.Authority.ZoneName, "ws") || !validOwnedHostname(request.DirectHostname, request.Authority.ZoneName, "direct") || !validPublicAddresses(request.PublicIPv4, request.PublicIPv6) {
		return fail("CLOUDFLARE-RUN-TOKEN-ROTATION-REFUSED", "The run-token rotation request is incomplete or outside the committed ownership boundary.")
	}
	authority := i.View(ctx, request.Authority)
	observer, ok := i.api.(wholeTunnelObserver)
	if authority.Health.Outcome != Healthy || !ok {
		return PlanResult{Health: authority.Health}
	}
	expected, providerRequest := rotationHealthRequest(request)
	observed, err := observer.ObserveWholeTunnel(ctx, providerRequest)
	if err != nil {
		return PlanResult{Health: finish(healthResult(i, safeAPIHealth(err))).Health}
	}
	if health := EvaluateWholeTunnel(observed, expected); health.Outcome != Healthy {
		return PlanResult{Health: health}
	}
	change := systemchanges.CloudflareChange{
		Action: systemchanges.CloudflareRunTokenActivate, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID,
		TunnelID: rotation.TunnelID, XHTTPDNSRecordID: rotation.XHTTPDNSRecordID, WebSocketDNSRecordID: rotation.WebSocketDNSRecordID,
		DirectIPv4RecordID: rotation.DirectIPv4RecordID, DirectIPv6RecordID: rotation.DirectIPv6RecordID,
		DirectHostname: request.DirectHostname, PublicIPv4: request.PublicIPv4, PublicIPv6: request.PublicIPv6,
		Routes: []systemchanges.CloudflareRoute{{Hostname: request.XHTTPHostname, Origin: xhttpOrigin}, {Hostname: request.WebSocketHostname, Origin: webSocketOrigin}, {Origin: "http_status:404"}},
	}
	step, stepErr := systemchanges.NewCloudflareStep(change)
	if stepErr != nil {
		return fail("CLOUDFLARE-RUN-TOKEN-ROTATION-REFUSED", "The rotation transaction could not be built.")
	}
	bound := request
	bound.Authority.Token = ManagementToken{}
	encoded, _ := json.Marshal(bound)
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	use, _ := planUses.LoadOrStore(identity, &atomic.Bool{})
	plan := &Plan{identity: identity, sha256: checksum, request: request, steps: []systemchanges.Step{step}, checks: wholeTunnelChecks(), runToken: TunnelRunToken{cell: &runTokenCell{}}, used: use.(*atomic.Bool)}
	health := finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Healthy, Code: "CLOUDFLARE-RUN-TOKEN-ROTATION-READY", Explanation: "The Owner-assisted run-token rotation is ready for the State and System Changes transaction."})).Health
	return PlanResult{Plan: plan, Health: health}
}

func rotationHealthRequest(request PlanRequest) (WholeTunnelExpected, WholeTunnelRequest) {
	rotation := request.RunTokenRotation
	routes := []Route{{Hostname: request.XHTTPHostname, Service: xhttpOrigin}, {Hostname: request.WebSocketHostname, Service: webSocketOrigin}, {Service: "http_status:404"}}
	expected := WholeTunnelExpected{TunnelID: rotation.TunnelID, Routes: routes}
	references := []DNSRecordReference{{ID: rotation.XHTTPDNSRecordID}, {ID: rotation.WebSocketDNSRecordID}}
	expected.DNSRecords = append(expected.DNSRecords,
		DNSExpected{ID: rotation.XHTTPDNSRecordID, Name: request.XHTTPHostname, Type: "CNAME", Content: rotation.TunnelID + ".cfargotunnel.com", Proxied: true},
		DNSExpected{ID: rotation.WebSocketDNSRecordID, Name: request.WebSocketHostname, Type: "CNAME", Content: rotation.TunnelID + ".cfargotunnel.com", Proxied: true},
	)
	for _, item := range []struct{ id, kind, content string }{{rotation.DirectIPv4RecordID, "A", request.PublicIPv4}, {rotation.DirectIPv6RecordID, "AAAA", request.PublicIPv6}} {
		if item.id != "" {
			references = append(references, DNSRecordReference{ID: item.id})
			expected.DNSRecords = append(expected.DNSRecords, DNSExpected{ID: item.id, Name: request.DirectHostname, Type: item.kind, Content: item.content})
		}
	}
	return expected, WholeTunnelRequest{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, TunnelID: rotation.TunnelID, DNSRecords: references, Token: request.Authority.Token}
}

// StateRunTokenRotation hands State an empty one-use token slot plus exact
// immutable facts; the complete token never enters the Plan or journal.
func (plan *Plan) StateRunTokenRotation() (source any, bindingJSON []byte, templateSHA256 string, valid bool) {
	if plan == nil || plan.request.RunTokenRotation.TunnelID == "" || plan.runToken.cell == nil {
		return nil, nil, "", false
	}
	bindingJSON, err := json.Marshal(struct {
		AccountID, ZoneID, ZoneName, XHTTPHostname, WebSocketHostname, DirectHostname string
		PublicIPv4, PublicIPv6                                                        string
		RunTokenRotation
	}{plan.request.Authority.AccountID, plan.request.Authority.ZoneID, plan.request.Authority.ZoneName, plan.request.XHTTPHostname, plan.request.WebSocketHostname, plan.request.DirectHostname, plan.request.PublicIPv4, plan.request.PublicIPv6, plan.request.RunTokenRotation})
	return plan.runToken, bindingJSON, plan.request.DesiredStateSHA256, err == nil
}
