package certificatelifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type certificateNetworkAdapter struct{ observed networkpolicy.Observations }

func (adapter certificateNetworkAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return adapter.observed, nil
}

type preparedCertificateState struct {
	changeSet                            string
	revision                             uint64
	starting, candidate, planID, planSHA string
}

func (state *preparedCertificateState) SystemChangesPreparedState() (string, uint64, string, string, string, string, bool) {
	return state.changeSet, state.revision, state.starting, state.candidate, state.planID, state.planSHA, true
}
func (*preparedCertificateState) SystemChangesConsume(any, string, string) (any, error) {
	return nil, errors.New("not reached without an Adapter")
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type staticIssuer struct {
	observation certificatelifecycle.Observation
	err         error
}

func (issuer staticIssuer) Observe(context.Context) (certificatelifecycle.Observation, error) {
	return issuer.observation, issuer.err
}

func TestViewAndPlanProveBothLineagesBeforeOrdering(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	observation := certificatelifecycle.Observation{
		Issuer: certificatelifecycle.IssuerObservation{
			Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "snap",
			SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true,
		},
		IP: certificatelifecycle.CertificateObservation{
			Identity: "192.0.2.10", Profile: "shortlived", NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(159 * time.Hour), ActiveServingID: "ip-serving-7",
		},
		Domain: certificatelifecycle.CertificateObservation{
			Identity: "direct.example.com", Profile: "tlsserver", NotBefore: now.Add(-24 * time.Hour),
			NotAfter: now.Add(44 * 24 * time.Hour), ActiveServingID: "domain-serving-4",
		},
		Scheduler: certificatelifecycle.SchedulerObservation{Enabled: true, Persistent: true, Serial: true, RunsPerDay: 2},
	}
	module := certificatelifecycle.New(staticIssuer{observation: observation}, fixedClock{now: now})
	request := completeViewRequest()

	view := module.View(context.Background(), request)
	if view.Health.Outcome != certificatelifecycle.Healthy || view.Health.Code != "CERTIFICATE-PREREQUISITES-VERIFIED" {
		t.Fatalf("healthy View = %+v", view)
	}
	if view.IP.Lineage != certificatelifecycle.IPLineage || view.IP.RequiredProfile != "shortlived" || !view.IP.Valid || view.IP.Due || view.IP.ActiveServingID != "ip-serving-7" {
		t.Fatalf("IP View = %+v", view.IP)
	}
	if view.Domain.Lineage != certificatelifecycle.DomainLineage || view.Domain.RequiredProfile != "tlsserver" || !view.Domain.Valid || view.Domain.Due || view.Domain.ActiveServingID != "domain-serving-4" {
		t.Fatalf("domain View = %+v", view.Domain)
	}
	if view.Prerequisites.IgnoredChallengeRecords != 3 || !view.Issuer.Qualified || !view.Scheduler.Qualified {
		t.Fatalf("qualified facts = issuer %+v prerequisites %+v scheduler %+v", view.Issuer, view.Prerequisites, view.Scheduler)
	}

	planRequest := certificatelifecycle.PlanRequest{
		View: request, ChangeSet: "certificate-ip-7", StartingRevision: 7, StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64),
		HTTP01:     testHTTP01Contribution(7),
		OwnerEmail: "owner@example.com", SubscriberAgreementReviewed: true,
	}
	first, second := module.Plan(context.Background(), planRequest), module.Plan(context.Background(), planRequest)
	if first.Plan == nil || second.Plan == nil || first.Health.Outcome != certificatelifecycle.Healthy || first.Plan.Identity() != second.Plan.Identity() || first.Plan.SHA256() != second.Plan.SHA256() {
		t.Fatalf("deterministic Plan = first %+v second %+v", first, second)
	}
	orders := first.Plan.Orders()
	if len(orders) != 4 {
		t.Fatalf("orders = %#v", orders)
	}
	if !orders[0].Staging || orders[1].Staging || !orders[2].Staging || orders[3].Staging || orders[0].Lineage != certificatelifecycle.IPLineage || orders[2].Lineage != certificatelifecycle.DomainLineage {
		t.Fatalf("staging-before-production orders = %#v", orders)
	}
	for _, staging := range []certificatelifecycle.OrderContract{orders[0], orders[2]} {
		if staging.ConfigDirectory == "" || staging.ConfigDirectory == orders[1].ConfigDirectory || staging.Account == "" || staging.CertName == "" || staging.OwnerEmail != "owner@example.com" {
			t.Fatalf("staging isolation = %#v", staging)
		}
	}
	if !first.Plan.Consume() || first.Plan.Consume() || !second.Plan.Consume() || second.Plan.Consume() {
		t.Fatal("each reviewed Plan was not one-use")
	}
	changedEmail := planRequest
	changedEmail.OwnerEmail = "other-owner@example.com"
	if changed := module.Plan(t.Context(), changedEmail); changed.Plan == nil || changed.Plan.SHA256() == first.Plan.SHA256() {
		t.Fatal("reviewed Owner email was not bound into the Plan checksum")
	}
	if rendered := fmt.Sprintf("%+v %#v %s", first, first.Plan, first.Plan); strings.Contains(rendered, "--preferred-profile") || strings.Contains(rendered, "PRIVATE-KEY-MARKER") {
		t.Fatalf("unsafe Plan = %s", rendered)
	}
	steps := first.Plan.Steps()
	if len(steps) != 5 {
		t.Fatalf("IP transaction steps = %#v", steps)
	}
	if change, ok := steps[0].FirewallChange(); !ok || change.Action != systemchanges.HTTP01OpenAction || change.TemporaryRuleIdentity != "sbxr:acme-http-01" {
		t.Fatalf("HTTP-01 open step = %#v", steps[0])
	}
	for index, action := range []systemchanges.CertificateAction{systemchanges.CertificateIPStage, systemchanges.CertificateIPOrder, systemchanges.CertificateIPActivate} {
		change, ok := steps[index+1].CertificateChange()
		if !ok || change.Action != action || change.Identity != "192.0.2.10" || change.CertName != "sbxr-ip" || change.RequiredProfile != "shortlived" {
			t.Fatalf("certificate step %d = %#v", index+1, steps[index+1])
		}
	}
	if change, ok := steps[4].FirewallChange(); !ok || change.Action != systemchanges.HTTP01CloseAction {
		t.Fatalf("HTTP-01 close step = %#v", steps[4])
	}
	checks := first.Plan.Checks()
	if len(checks) != 2 || checks[0].Phase != systemchanges.PrePublication || checks[1].Phase != systemchanges.PostPublication || checks[0].Classification != systemchanges.Required || checks[1].Classification != systemchanges.Required {
		t.Fatalf("IP transaction checks = %#v", checks)
	}

	domainRequest := planRequest
	domainRequest.Lineage = certificatelifecycle.DomainLineage
	domainRequest.ChangeSet = "certificate-domain-7"
	domainRequest.DirectTLS = testDirectTLSContribution(7)
	domain := module.Plan(t.Context(), domainRequest)
	if domain.Plan == nil || domain.Health.Outcome != certificatelifecycle.Healthy || !strings.HasPrefix(domain.Plan.Identity(), "certificate-domain-") {
		t.Fatalf("domain Plan = %+v", domain)
	}
	domainSteps := domain.Plan.Steps()
	if len(domainSteps) != 5 {
		t.Fatalf("domain transaction steps = %#v", domainSteps)
	}
	for index, action := range []systemchanges.CertificateAction{systemchanges.CertificateDomainStage, systemchanges.CertificateDomainOrder, systemchanges.CertificateDomainActivate} {
		change, ok := domainSteps[index+1].CertificateChange()
		if !ok || change.Action != action || change.Identity != "direct.example.com" || change.DestinationIP != "192.0.2.10" || change.CertName != "sbxr-domain" || change.RequiredProfile != "tlsserver" {
			t.Fatalf("domain certificate step %d = %#v", index+1, domainSteps[index+1])
		}
	}
	domainChecks := domain.Plan.Checks()
	wantCodes := []string{"CERTIFICATE-DOMAIN-CANDIDATE", "CONNECTION-PROFILES-HYSTERIA2-DIRECT-TLS", "CONNECTION-PROFILES-TUIC-DIRECT-TLS", "CONNECTION-PROFILES-ANYTLS-DIRECT-TLS"}
	if len(domainChecks) != len(wantCodes) {
		t.Fatalf("domain transaction checks = %#v", domainChecks)
	}
	for index, code := range wantCodes {
		if domainChecks[index].Code != code || domainChecks[index].Classification != systemchanges.Required {
			t.Fatalf("domain check %d = %#v", index, domainChecks[index])
		}
	}
}

func TestViewAndPlanFailClosedWithoutLeakingTypedOrToolFacts(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	complete := func() certificatelifecycle.Observation {
		return certificatelifecycle.Observation{
			Issuer:    certificatelifecycle.IssuerObservation{Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "snap", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true},
			Scheduler: certificatelifecycle.SchedulerObservation{Enabled: true, Persistent: true, Serial: true, RunsPerDay: 2},
		}
	}
	tests := []struct {
		name, code string
		change     func(*certificatelifecycle.Observation, *certificatelifecycle.ViewRequest)
	}{
		{name: "Ubuntu Certbot 2.9", code: "CERTIFICATE-ISSUER-CAPABILITY", change: func(observation *certificatelifecycle.Observation, _ *certificatelifecycle.ViewRequest) {
			observation.Issuer.CertbotVersion = "2.9.0"
		}},
		{name: "preferred profile fallback", code: "CERTIFICATE-ISSUER-CAPABILITY", change: func(observation *certificatelifecycle.Observation, _ *certificatelifecycle.ViewRequest) {
			observation.Issuer.RequiredProfile = false
		}},
		{name: "DNS SERVFAIL", code: "CERTIFICATE-DNS-SERVFAIL", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.DNS.Status = certificatelifecycle.DNSSERVFAIL
		}},
		{name: "unqualified DNS address", code: "CERTIFICATE-DNS-ADDRESSES", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.DNS.Addresses = []string{"198.51.100.10"}
		}},
		{name: "other issuer", code: "CERTIFICATE-CAA-ISSUER", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.CAA.Records[0].Value = "example-ca.invalid"
		}},
		{name: "other validation method", code: "CERTIFICATE-CAA-METHOD", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.CAA.Records[0].Value = "letsencrypt.org; validationmethods=dns-01"
		}},
		{name: "account-bound CAA", code: "CERTIFICATE-CAA-PARAMETER", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.CAA.Records[0].Value = "letsencrypt.org; accounturi=https://example.invalid/account/7"
		}},
		{name: "critical unknown CAA", code: "CERTIFICATE-CAA-CRITICAL", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.CAA.Records = []certificatelifecycle.CAARecord{{Flags: 128, Tag: "future", Value: "value"}}
		}},
		{name: "contradictory CAA", code: "CERTIFICATE-CAA-CONTRADICTORY", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.CAA.Status = certificatelifecycle.CAAContradictory
		}},
		{name: "unavailable port 80", code: "CERTIFICATE-HTTP01-PREREQUISITES", change: func(_ *certificatelifecycle.Observation, request *certificatelifecycle.ViewRequest) {
			request.HTTP01.Port80Available = false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation, request := complete(), completeViewRequest()
			test.change(&observation, &request)
			result := certificatelifecycle.New(staticIssuer{observation: observation}, fixedClock{now: now}).View(t.Context(), request)
			if result.Health.Outcome == certificatelifecycle.Healthy || result.Health.Code != test.code || result.Health.Problem == "" || result.Health.Found == "" || result.Health.Required == "" || result.Health.WhyStopped == "" || result.Health.Evidence == "" || len(result.Health.NextActions) < 2 || slices.Contains(result.Health.NextActions, "Continue anyway") {
				t.Fatalf("fail-closed View = %+v", result)
			}
		})
	}

	observation := complete()
	observation.Issuer.Name = "RAW-CERTBOT-SECRET-MARKER"
	observation.IP.ActiveServingID = "PRIVATE-KEY-MARKER with spaces"
	request := completeViewRequest()
	request.DNS.ChallengeRecords = append(request.DNS.ChallengeRecords, certificatelifecycle.DNSRecord{Name: "CLIENT-ACCESS-VALUE-MARKER", Type: "TXT"})
	result := certificatelifecycle.New(staticIssuer{observation: observation}, fixedClock{now: now}).View(t.Context(), request)
	if rendered := fmt.Sprintf("%+v %#v %s", result, result, result); strings.Contains(rendered, "MARKER") {
		t.Fatalf("typed or tool material leaked from View: %s", rendered)
	}
}

func TestPlanRequiresReviewedOwnerIdentityAndAgreement(t *testing.T) {
	module := certificatelifecycle.New(staticIssuer{observation: certificatelifecycle.Observation{
		Issuer: certificatelifecycle.IssuerObservation{Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "snap", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true},
	}}, fixedClock{now: time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)})
	request := completePlanRequest()
	for _, test := range []struct {
		code   string
		change func(*certificatelifecycle.PlanRequest)
	}{
		{code: "CERTIFICATE-PLAN-OWNER-EMAIL", change: func(request *certificatelifecycle.PlanRequest) { request.OwnerEmail = "" }},
		{code: "CERTIFICATE-PLAN-OWNER-EMAIL", change: func(request *certificatelifecycle.PlanRequest) { request.OwnerEmail = "Owner <owner@example.com>" }},
		{code: "CERTIFICATE-PLAN-AGREEMENT", change: func(request *certificatelifecycle.PlanRequest) { request.SubscriberAgreementReviewed = false }},
		{code: "CERTIFICATE-PLAN-NETWORK-POLICY", change: func(request *certificatelifecycle.PlanRequest) { request.HTTP01 = nil }},
		{code: "CERTIFICATE-PLAN-NETWORK-POLICY", change: func(request *certificatelifecycle.PlanRequest) { request.HTTP01 = testHTTP01Contribution(2) }},
	} {
		changed := request
		test.change(&changed)
		result := module.Plan(t.Context(), changed)
		if result.Plan != nil || result.Health.Code != test.code || len(result.Health.NextActions) < 2 {
			t.Fatalf("unreviewed identity Plan = %+v", result)
		}
	}
	for _, authority := range []systemchanges.DirectTLSAuthority{nil, testDirectTLSContribution(2)} {
		domain := request
		domain.Lineage = certificatelifecycle.DomainLineage
		domain.ChangeSet = "certificate-domain-1"
		domain.DirectTLS = authority
		result := module.Plan(t.Context(), domain)
		if result.Plan != nil || result.Health.Code != "CERTIFICATE-PLAN-TRANSACTION" {
			t.Fatalf("untrusted Direct TLS Plan = %+v", result)
		}
	}
}

func TestIPPlanApplyBuildsOneRevisionBoundChangeSet(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	module := certificatelifecycle.New(staticIssuer{observation: certificatelifecycle.Observation{Issuer: certificatelifecycle.IssuerObservation{Name: "Let's Encrypt", CertbotVersion: "5.4.0", Distribution: "snap", SupportedDistribution: true, RequiredProfile: true, IPAddress: true, Staging: true}, Scheduler: certificatelifecycle.SchedulerObservation{Enabled: true, Persistent: true, Serial: true, RunsPerDay: 2}}}, fixedClock{now: now})
	request := completePlanRequest()
	plan := module.Plan(t.Context(), request).Plan
	prepared := &preparedCertificateState{changeSet: request.ChangeSet, revision: 2, starting: request.StartingStateSHA256, candidate: request.DesiredStateSHA256, planID: plan.Identity(), planSHA: plan.SHA256()}
	result := plan.Apply(systemchanges.New(nil), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 1, SHA256: request.StartingStateSHA256}, strings.Repeat("c", 64), systemchanges.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1})
	if result.Finding == nil || result.Finding.Code != "SYSTEM-CHANGES-ADAPTER-UNAVAILABLE" || !result.PlanConsumed {
		t.Fatalf("valid typed Apply = %+v", result)
	}
	if repeated := plan.Apply(systemchanges.New(nil), prepared, systemchanges.StateLineage{Status: systemchanges.Managed, Revision: 1, SHA256: request.StartingStateSHA256}, strings.Repeat("c", 64), systemchanges.DiskRequirement{}); repeated.Finding == nil || repeated.Finding.Code != "SYSTEM-CHANGES-CHANGE-SET-REQUIRED" {
		t.Fatalf("repeated Apply = %+v", repeated)
	}
}

func completePlanRequest() certificatelifecycle.PlanRequest {
	return certificatelifecycle.PlanRequest{
		View: completeViewRequest(), ChangeSet: "certificate-ip-1", StartingRevision: 1,
		StartingStateSHA256: strings.Repeat("a", 64), DesiredStateSHA256: strings.Repeat("b", 64),
		HTTP01:     testHTTP01Contribution(1),
		OwnerEmail: "owner@example.com", SubscriberAgreementReviewed: true,
	}
}

func testHTTP01Contribution(revision uint64) networkpolicy.HTTP01Contribution {
	intent := networkpolicy.Intent{Revision: revision, Baseline: networkpolicy.Clean, PublicIPv4: "192.0.2.10", PrimarySubscriptionAddress: "192.0.2.10", CertificateHostname: "direct.example.com", SSHPort: 22, SubscriptionPort: 10443, TemporaryHTTP: true,
		Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Port: 443}, VLESSXHTTP: networkpolicy.Profile{Address: "127.0.0.1", Port: 11080}, VLESSWebSocket: networkpolicy.Profile{Address: "127.0.0.1", Port: 11081}, Hysteria2: networkpolicy.Profile{Port: 443}, TUIC: networkpolicy.Profile{Port: 8443}, AnyTLS: networkpolicy.Profile{Port: 9443}},
		Disk:     networkpolicy.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1},
	}
	observed := networkpolicy.Observations{
		Host:       networkpolicy.HostFacts{UbuntuVersion: "24.04.3", UbuntuServer: true, Architecture: "amd64", Systemd: true, LogicalCPUs: 1, PhysicalRAM: 1024 << 20},
		PublicIPv4: []string{"192.0.2.10"}, SSH: networkpolicy.SSHFacts{DetectedPort: 22, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session-1"}},
		Firewall: networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true}, Routes: networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound: networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:     networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30}, Time: networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"}, OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Certificate: networkpolicy.CertificateFacts{DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com", IPv4: []string{"192.0.2.10"}}, CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true}}, Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
	}
	result := networkpolicy.New(certificateNetworkAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	contribution, ok := result.HTTP01Contribution()
	if !ok {
		panic(fmt.Sprintf("test Network Policy HTTP-01 contribution unavailable: outcome=%s findings=%+v policy=%s", result.Outcome, result.Findings, result.Policy.Nftables))
	}
	return contribution
}

func testDirectTLSContribution(revision uint64) connectionprofiles.DirectTLSContribution {
	return connectionprofiles.NewDirectTLSContribution(connectionprofiles.DirectTLSRequest{
		Revision: revision, DestinationIP: "192.0.2.10", Hostname: "direct.example.com",
		Hysteria2: connectionprofiles.DirectTLSConsumer{Port: 443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"},
		TUIC:      connectionprofiles.DirectTLSConsumer{Port: 8443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"},
		AnyTLS:    connectionprofiles.DirectTLSConsumer{Port: 9443, CertificatePointer: "/var/lib/sbxr/certificates/domain/current"},
	})
}

func completeViewRequest() certificatelifecycle.ViewRequest {
	return certificatelifecycle.ViewRequest{
		SelectedIP: "192.0.2.10", DirectHostname: "direct.example.com", QualifiedAddresses: []string{"192.0.2.10"},
		HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: true, RouteReachable: true, Port80Available: true, TimeSynchronized: true, FirewallOwned: true},
		DNS: certificatelifecycle.DNSFacts{
			Status: certificatelifecycle.DNSAvailable, Hostname: "direct.example.com", Addresses: []string{"192.0.2.10"}, DNSOnly: true,
			ChallengeRecords: []certificatelifecycle.DNSRecord{{Type: "CNAME"}, {Type: "NS"}, {Type: "TXT"}},
		},
		CAA: certificatelifecycle.CAAFacts{Status: certificatelifecycle.CAAAvailable, Records: []certificatelifecycle.CAARecord{{Tag: "issue", Value: "letsencrypt.org; validationmethods=http-01"}}},
	}
}
