package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type ClientAccessRoutesRequest struct {
	ChangeSet, AccountID, ZoneID, TunnelID, XHTTPHostname, WebSocketHostname, XHTTPDNSRecordID, WebSocketDNSRecordID string
	CurrentXHTTP, CurrentWebSocket, CandidateXHTTP, CandidateWebSocket                                               bool
}

type ClientAccessRoutesPlan struct {
	identity, sha256 string
	step             systemchanges.Step
	request          ClientAccessRoutesRequest
}

func PrepareClientAccessRoutes(request ClientAccessRoutesRequest) (*ClientAccessRoutesPlan, error) {
	changed := request.CurrentXHTTP != request.CandidateXHTTP
	changed = changed != (request.CurrentWebSocket != request.CandidateWebSocket)
	if !safePlanName.MatchString(request.ChangeSet) || !immutableID.MatchString(request.AccountID) || !immutableID.MatchString(request.ZoneID) || !tunnelUUID.MatchString(request.TunnelID) || !immutableID.MatchString(request.XHTTPDNSRecordID) || !immutableID.MatchString(request.WebSocketDNSRecordID) || request.XHTTPDNSRecordID == request.WebSocketDNSRecordID || !zoneName.MatchString(request.XHTTPHostname) || !zoneName.MatchString(request.WebSocketHostname) || !changed {
		return nil, errors.New("exact Client Access route change required")
	}
	routes := make([]systemchanges.CloudflareRoute, 0, 3)
	if request.CandidateXHTTP {
		routes = append(routes, systemchanges.CloudflareRoute{Hostname: request.XHTTPHostname, Origin: xhttpOrigin})
	}
	if request.CandidateWebSocket {
		routes = append(routes, systemchanges.CloudflareRoute{Hostname: request.WebSocketHostname, Origin: webSocketOrigin})
	}
	routes = append(routes, systemchanges.CloudflareRoute{Origin: "http_status:404"})
	step, err := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareRoutesPut, AccountID: request.AccountID, TunnelID: request.TunnelID, Routes: routes})
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	return &ClientAccessRoutesPlan{identity: request.ChangeSet + "-cloudflare-routes-" + checksum[:12], sha256: checksum, step: step, request: request}, nil
}

func (plan *ClientAccessRoutesPlan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *ClientAccessRoutesPlan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *ClientAccessRoutesPlan) Steps() []systemchanges.Step {
	if plan == nil {
		return nil
	}
	return []systemchanges.Step{plan.step}
}
func (plan *ClientAccessRoutesPlan) Checks() []systemchanges.Check {
	if plan == nil {
		return nil
	}
	return []systemchanges.Check{
		{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CLOUDFLARE-CLIENT-ACCESS-CANDIDATE"},
		{Owner: systemchanges.CloudflareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "CLOUDFLARE-CLIENT-ACCESS-ACTIVE"},
	}
}

func (plan *ClientAccessRoutesPlan) Executor(api MutationAPI, token ManagementToken) (Executor, error) {
	if plan == nil || api == nil || token.value == "" {
		return Executor{}, errors.New("Client Access Cloudflare executor unavailable")
	}
	priorRequest := plan.request
	priorRequest.CandidateXHTTP, priorRequest.CandidateWebSocket = plan.request.CurrentXHTTP, plan.request.CurrentWebSocket
	prior := clientAccessRoutes(priorRequest)
	current, err := api.GetConfiguration(context.Background(), GetConfigurationRequest{AccountID: plan.request.AccountID, TunnelID: plan.request.TunnelID, Token: token})
	if err != nil || current.TunnelID != plan.request.TunnelID || !sameRoutes(current.Routes, prior) {
		return Executor{}, errors.New("Client Access Cloudflare Plan observation changed")
	}
	change, _ := plan.step.CloudflareChange()
	health := &clientAccessRouteHealth{
		request: WholeTunnelRequest{AccountID: plan.request.AccountID, ZoneID: plan.request.ZoneID, TunnelID: plan.request.TunnelID, DNSRecords: []DNSRecordReference{{ID: plan.request.XHTTPDNSRecordID}, {ID: plan.request.WebSocketDNSRecordID}}, Token: token},
		expected: WholeTunnelExpected{TunnelID: plan.request.TunnelID, Routes: clientAccessRoutes(plan.request), DNSRecords: []DNSExpected{
			{ID: plan.request.XHTTPDNSRecordID, Name: plan.request.XHTTPHostname, Type: "CNAME", Content: plan.request.TunnelID + ".cfargotunnel.com", Proxied: true},
			{ID: plan.request.WebSocketDNSRecordID, Name: plan.request.WebSocketHostname, Type: "CNAME", Content: plan.request.TunnelID + ".cfargotunnel.com", Proxied: true},
		}},
		xhttp: plan.request.CandidateXHTTP, websocket: plan.request.CandidateWebSocket,
	}
	return Executor{api: api, token: token, command: runCommand, clock: SystemClock{}, clientAccess: &change, clientAccessHealth: health, clientAccessPrior: prior}, nil
}

func clientAccessRoutes(request ClientAccessRoutesRequest) []Route {
	routes := make([]Route, 0, 3)
	if request.CandidateXHTTP {
		routes = append(routes, Route{Hostname: request.XHTTPHostname, Service: xhttpOrigin})
	}
	if request.CandidateWebSocket {
		routes = append(routes, Route{Hostname: request.WebSocketHostname, Service: webSocketOrigin})
	}
	return append(routes, Route{Service: "http_status:404"})
}
