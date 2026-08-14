package cloudflaretunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

type ManagedRepairView struct {
	Repairable   bool
	StableSHA256 string
	Health       Health
}

// ViewManagedRepair performs only fresh read-only ownership and agreement
// inspection. It never constructs mutation steps or an executor.
func (i Interface) ViewManagedRepair(ctx context.Context, request PlanRequest) ManagedRepairView {
	owned := request.ManagedRepair
	validDirect := (request.PublicIPv4 == "") == (owned.DirectIPv4RecordID == "") && (request.PublicIPv6 == "") == (owned.DirectIPv6RecordID == "")
	if i.clock == nil || request.StartingRevision == 0 || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || !tunnelUUID.MatchString(owned.TunnelID) || !immutableID.MatchString(owned.XHTTPDNSRecordID) || !immutableID.MatchString(owned.WebSocketDNSRecordID) || !validDirect || owned.DirectIPv4RecordID != "" && !immutableID.MatchString(owned.DirectIPv4RecordID) || owned.DirectIPv6RecordID != "" && !immutableID.MatchString(owned.DirectIPv6RecordID) || !validOwnedHostname(request.XHTTPHostname, request.Authority.ZoneName, "xhttp") || !validOwnedHostname(request.WebSocketHostname, request.Authority.ZoneName, "ws") || !validOwnedHostname(request.DirectHostname, request.Authority.ZoneName, "direct") || !validPublicAddresses(request.PublicIPv4, request.PublicIPv6) {
		return ManagedRepairView{Health: finish(healthResult(i, Health{Outcome: Failed, Code: "CLOUDFLARE-REPAIR-VIEW-REFUSED", Explanation: "The managed repair inspection is incomplete."})).Health}
	}
	authority := i.View(ctx, request.Authority)
	planner, plannerOK := i.api.(MutationPlanner)
	observer, observerOK := i.api.(wholeTunnelObserver)
	if authority.Health.Outcome != Healthy || !plannerOK || !observerOK {
		return ManagedRepairView{Health: authority.Health}
	}
	expectedDNS := map[string][]string{request.XHTTPHostname: {owned.XHTTPDNSRecordID}, request.WebSocketHostname: {owned.WebSocketDNSRecordID}, request.DirectHostname: compactIDs(owned.DirectIPv4RecordID, owned.DirectIPv6RecordID)}
	digests := make([]string, 0, 3)
	for _, hostname := range []string{request.XHTTPHostname, request.WebSocketHostname, request.DirectHostname} {
		observed, err := planner.ObserveMutation(ctx, MutationRequest{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Tunnel: request.TunnelName, Hostname: hostname, Token: request.Authority.Token})
		if err != nil || !sha256Text.MatchString(observed.Digest) || !sameOwnedResources(observed.Tunnels, []OwnedResource{{ID: owned.TunnelID, Name: request.TunnelName}}) || !sameOwnedIDs(observed.DNSRecords, hostname, expectedDNS[hostname]) {
			return ManagedRepairView{Health: finish(healthResult(i, Health{Outcome: Failed, Code: "CLOUDFLARE-REPAIR-OWNERSHIP", Explanation: "Committed provider ownership could not be proved."})).Health}
		}
		digests = append(digests, observed.Digest)
	}
	expected, providerRequest := managedHealthRequest(request)
	observed, err := observer.ObserveWholeTunnel(ctx, providerRequest)
	if err != nil || observed.TunnelID != owned.TunnelID || !observed.XHTTPOriginReachable || !observed.WebSocketOriginReachable {
		return ManagedRepairView{Health: EvaluateWholeTunnel(observed, expected)}
	}
	repairable := !sameRoutes(observed.Routes, expected.Routes) || !observed.Connected
	byID := make(map[string]DNSObservation, len(observed.DNSRecords))
	for _, record := range observed.DNSRecords {
		byID[record.ID] = record
	}
	for _, want := range expected.DNSRecords {
		got, exists := byID[want.ID]
		if !exists {
			return ManagedRepairView{Health: finish(healthResult(i, Health{Outcome: Failed, Code: "CLOUDFLARE-REPAIR-OWNERSHIP", Explanation: "A committed DNS identifier is absent."})).Health}
		}
		repairable = repairable || got.Name != want.Name || got.Type != want.Type || got.Content != want.Content || got.Proxied != want.Proxied
	}
	encoded, _ := json.Marshal(struct {
		Observation WholeTunnelObservation
		Digests     []string
	}{observed, digests})
	digest := sha256.Sum256(encoded)
	code := "CLOUDFLARE-REPAIR-NOT-REQUIRED"
	if repairable {
		code = "CLOUDFLARE-REPAIR-AVAILABLE"
	}
	return ManagedRepairView{Repairable: repairable, StableSHA256: hex.EncodeToString(digest[:]), Health: finish(healthResult(i, Health{Outcome: Healthy, Code: code})).Health}
}

func (i Interface) planManagedRepair(ctx context.Context, request PlanRequest) PlanResult {
	fail := func(code, found, required, explanation string) PlanResult {
		health := Health{Module: "Cloudflare Tunnel", Outcome: Failed, Code: code, Problem: explanation, Found: found, Required: required, Explanation: explanation, WhyStopped: "SBXR repairs only freshly proved committed ownership", NextActions: []string{"Check again", "Back"}}
		return PlanResult{Health: finish(healthResult(i, health)).Health}
	}
	owned := request.ManagedRepair
	validDirect := (request.PublicIPv4 == "") == (owned.DirectIPv4RecordID == "") && (request.PublicIPv6 == "") == (owned.DirectIPv6RecordID == "")
	if i.clock == nil || request.ManagementToken.Action != "" || request.RunTokenRotation.TunnelID != "" || request.StartingRevision == 0 || !safePlanName.MatchString(request.ChangeSet) || !sha256Text.MatchString(request.StartingStateSHA256) || !sha256Text.MatchString(request.DesiredStateSHA256) || !tunnelUUID.MatchString(owned.TunnelID) || !immutableID.MatchString(owned.XHTTPDNSRecordID) || !immutableID.MatchString(owned.WebSocketDNSRecordID) || !validDirect || owned.DirectIPv4RecordID != "" && !immutableID.MatchString(owned.DirectIPv4RecordID) || owned.DirectIPv6RecordID != "" && !immutableID.MatchString(owned.DirectIPv6RecordID) || request.CloudflaredVersion != qualifiedCloudflaredVersion || !validOwnedHostname(request.XHTTPHostname, request.Authority.ZoneName, "xhttp") || !validOwnedHostname(request.WebSocketHostname, request.Authority.ZoneName, "ws") || !validOwnedHostname(request.DirectHostname, request.Authority.ZoneName, "direct") || !validPublicAddresses(request.PublicIPv4, request.PublicIPv6) {
		return fail("CLOUDFLARE-REPAIR-REFUSED", "incomplete repair binding", "one exact current State and owned Cloudflare identity set", "The managed repair request is incomplete or outside the committed boundary.")
	}
	authority := i.View(ctx, request.Authority)
	planner, plannerOK := i.api.(MutationPlanner)
	observer, observerOK := i.api.(wholeTunnelObserver)
	if authority.Health.Outcome != Healthy || !plannerOK || !observerOK {
		return PlanResult{Health: authority.Health}
	}
	expectedDNS := map[string][]string{
		request.XHTTPHostname:     {owned.XHTTPDNSRecordID},
		request.WebSocketHostname: {owned.WebSocketDNSRecordID},
		request.DirectHostname:    compactIDs(owned.DirectIPv4RecordID, owned.DirectIPv6RecordID),
	}
	digests := make([]string, 0, 3)
	for _, hostname := range []string{request.XHTTPHostname, request.WebSocketHostname, request.DirectHostname} {
		var observed MutationObservation
		err := retryTemporary(ctx, i.clock, func() error {
			var observeErr error
			observed, observeErr = planner.ObserveMutation(ctx, MutationRequest{AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, Tunnel: request.TunnelName, Hostname: hostname, Token: request.Authority.Token})
			return observeErr
		})
		if err != nil {
			return PlanResult{Health: finish(healthResult(i, safeAPIHealth(err))).Health}
		}
		if !sha256Text.MatchString(observed.Digest) || !sameOwnedResources(observed.Tunnels, []OwnedResource{{ID: owned.TunnelID, Name: request.TunnelName}}) || !sameOwnedIDs(observed.DNSRecords, hostname, expectedDNS[hostname]) {
			return fail("CLOUDFLARE-REPAIR-OWNERSHIP", "missing or contradictory immutable provider ownership", "the committed Tunnel and DNS identifiers at their exact names", "A same-named or missing provider resource cannot be adopted or guessed as a repair target.")
		}
		digests = append(digests, observed.Digest)
	}
	expected, providerRequest := managedHealthRequest(request)
	var observed WholeTunnelObservation
	err := retryTemporary(ctx, i.clock, func() error {
		var observeErr error
		observed, observeErr = observer.ObserveWholeTunnel(ctx, providerRequest)
		return observeErr
	})
	if err != nil {
		return PlanResult{Health: finish(healthResult(i, safeAPIHealth(err))).Health}
	}
	if observed.TunnelID != owned.TunnelID {
		return fail("CLOUDFLARE-REPAIR-OWNERSHIP", "a different or missing Tunnel identifier", owned.TunnelID, "The committed Tunnel identity is not repairable in place.")
	}
	if !observed.XHTTPOriginReachable || !observed.WebSocketOriginReachable {
		return PlanResult{Health: EvaluateWholeTunnel(observed, expected)}
	}
	steps := make([]systemchanges.Step, 0, 6)
	if !sameRoutes(observed.Routes, expected.Routes) {
		step, _ := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareRoutesPut, AccountID: request.Authority.AccountID, TunnelID: owned.TunnelID, Routes: systemRoutes(expected.Routes)})
		steps = append(steps, step)
	}
	byID := make(map[string]DNSObservation, len(observed.DNSRecords))
	for _, record := range observed.DNSRecords {
		byID[record.ID] = record
	}
	for _, want := range expected.DNSRecords {
		got, exists := byID[want.ID]
		if !exists {
			return fail("CLOUDFLARE-REPAIR-OWNERSHIP", "a committed DNS identifier is absent", want.ID, "Missing owned DNS cannot be recreated under a guessed identity.")
		}
		if got.Name != want.Name || got.Type != want.Type || got.Content != want.Content || got.Proxied != want.Proxied {
			step, _ := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareDNSRepair, AccountID: request.Authority.AccountID, ZoneID: request.Authority.ZoneID, DNSRecordID: want.ID, Hostname: want.Name, RecordType: want.Type, Content: want.Content})
			steps = append(steps, step)
		}
	}
	if !observed.Connected {
		step, _ := systemchanges.NewStep(systemchanges.CloudflareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
		steps = append(steps, step)
	}
	if len(steps) == 0 {
		health := finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Healthy, Code: "CLOUDFLARE-REPAIR-NOT-REQUIRED", Explanation: "The committed Tunnel, routes, DNS, credentials, and service already agree."})).Health
		return PlanResult{Health: health}
	}
	if !observed.Connected {
		if err := i.validateNativeIngress(ctx, request); err != nil {
			return fail("CLOUDFLARE-REPAIR-REFUSED", "invalid native ingress", "one cloudflared-native valid candidate", err.Error())
		}
	}
	bound := request
	bound.Authority.Token = ManagementToken{}
	encoded, _ := json.Marshal(struct {
		Request     PlanRequest
		Observation []string
	}{bound, digests})
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	use, _ := planUses.LoadOrStore(identity, &atomic.Bool{})
	plan := &Plan{identity: identity, sha256: checksum, observation: strings.Join(digests, "\n"), request: request, steps: steps, checks: wholeTunnelChecks(), managedRepair: true, used: use.(*atomic.Bool)}
	health := finish(healthResult(i, Health{Module: "Cloudflare Tunnel", Outcome: Healthy, Code: "CLOUDFLARE-REPAIR-READY", Explanation: "The exact owned Cloudflare repair is ready for review."})).Health
	return PlanResult{Plan: plan, Health: health}
}

func retryTemporary(ctx context.Context, clock Clock, call func() error) error {
	if clock == nil {
		clock = SystemClock{}
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = call(); err == nil || !apiErrorIs(err, APITemporary) {
			return err
		}
		if attempt < 2 && clock.Sleep(ctx, 30*time.Second) != nil {
			return err
		}
	}
	return err
}

func managedHealthRequest(request PlanRequest) (WholeTunnelExpected, WholeTunnelRequest) {
	bound := request
	bound.RunTokenRotation = request.ManagedRepair
	return rotationHealthRequest(bound)
}

func compactIDs(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func sameOwnedResources(got, want []OwnedResource) bool {
	return slices.Equal(got, want)
}

func sameOwnedIDs(got []OwnedResource, name string, want []string) bool {
	ids := make([]string, 0, len(got))
	for _, resource := range got {
		if resource.Name != name {
			return false
		}
		ids = append(ids, resource.ID)
	}
	slices.Sort(ids)
	want = append([]string(nil), want...)
	slices.Sort(want)
	return slices.Equal(ids, want)
}

func systemRoutes(routes []Route) []systemchanges.CloudflareRoute {
	result := make([]systemchanges.CloudflareRoute, len(routes))
	for index, route := range routes {
		result[index] = systemchanges.CloudflareRoute{Hostname: route.Hostname, Origin: route.Service}
	}
	return result
}

func (plan *Plan) StateCloudflareRepair() (source any, bindingJSON []byte, templateSHA256 string, valid bool) {
	if plan == nil || !plan.managedRepair || plan.request.ManagedRepair.TunnelID == "" {
		return nil, nil, "", false
	}
	bindingJSON, err := json.Marshal(struct {
		AccountID, ZoneID, ZoneName, TunnelName, XHTTPHostname, WebSocketHostname, DirectHostname string
		PublicIPv4, PublicIPv6                                                                    string
		Owned                                                                                     OwnedTunnelBinding
	}{plan.request.Authority.AccountID, plan.request.Authority.ZoneID, plan.request.Authority.ZoneName, plan.request.TunnelName, plan.request.XHTTPHostname, plan.request.WebSocketHostname, plan.request.DirectHostname, plan.request.PublicIPv4, plan.request.PublicIPv6, plan.request.ManagedRepair})
	return nil, bindingJSON, plan.request.DesiredStateSHA256, err == nil
}
