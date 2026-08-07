package certificatelifecycle_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
)

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
		View: request, StartingRevision: 7, StartingStateSHA256: strings.Repeat("a", 64),
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
	request := certificatelifecycle.PlanRequest{View: completeViewRequest(), StartingRevision: 1, StartingStateSHA256: strings.Repeat("a", 64), OwnerEmail: "owner@example.com", SubscriberAgreementReviewed: true}
	for _, test := range []struct {
		code   string
		change func(*certificatelifecycle.PlanRequest)
	}{
		{code: "CERTIFICATE-PLAN-OWNER-EMAIL", change: func(request *certificatelifecycle.PlanRequest) { request.OwnerEmail = "" }},
		{code: "CERTIFICATE-PLAN-OWNER-EMAIL", change: func(request *certificatelifecycle.PlanRequest) { request.OwnerEmail = "Owner <owner@example.com>" }},
		{code: "CERTIFICATE-PLAN-AGREEMENT", change: func(request *certificatelifecycle.PlanRequest) { request.SubscriberAgreementReviewed = false }},
	} {
		changed := request
		test.change(&changed)
		result := module.Plan(t.Context(), changed)
		if result.Plan != nil || result.Health.Code != test.code || len(result.Health.NextActions) < 2 {
			t.Fatalf("unreviewed identity Plan = %+v", result)
		}
	}
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
