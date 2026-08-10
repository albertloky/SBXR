package main

import (
	"context"
	"fmt"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	certificateubuntu "github.com/albertloky/SBXR/internal/certificatelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/networkpolicy"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/state"
)

func managedProviderPresentations(ctx context.Context, snapshot state.Snapshot, secrets state.InfrastructureSecretReader, network networkpolicy.Result) (ownerconsole.CloudflarePresentation, ownerconsole.CertificatesPresentation) {
	desired := snapshot.DesiredState
	viewRequest := cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, TokenRemoved: desired.Cloudflare.ManagementTokenRemoved, NetworkPath: network.CloudflareTunnelPath, CredentialDetail: true}
	api := cloudflaretunnel.NewProductionAPI()
	if !viewRequest.TokenRemoved {
		token, err := cloudflaretunnel.NewManagementToken(secrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
		if err != nil {
			return unavailableCloudflare("stored token is unavailable"), ownerconsole.CertificatesPresentation{}
		}
		viewRequest.Token = token
	}
	cloudflareView := cloudflaretunnel.New(api, cloudflaretunnel.SystemClock{}).View(ctx, viewRequest)
	cloudflarePresentation := ownerCloudflarePresentation(cloudflareView)
	if cloudflareView.Health.Outcome != cloudflaretunnel.Healthy || viewRequest.TokenRemoved {
		return cloudflarePresentation, ownerconsole.CertificatesPresentation{}
	}
	dns, err := api.ObserveCertificateDNS(ctx, cloudflaretunnel.CertificateDNSRequest{
		ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Hostname: desired.Cloudflare.DirectHostname,
		PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6,
		IPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, IPv6RecordID: desired.Cloudflare.DirectIPv6RecordID, Token: viewRequest.Token,
	})
	if err != nil {
		return cloudflarePresentation, ownerconsole.CertificatesPresentation{}
	}
	certificateView := certificatelifecycle.New(certificateubuntu.New(), installClock{}).View(ctx, certificateViewRequest(desired, network, dns))
	return cloudflarePresentation, ownerCertificatesPresentation(certificateView, desired.Certificates.RenewalPolicy)
}

func ownerCloudflarePresentation(view cloudflaretunnel.ViewResult) ownerconsole.CloudflarePresentation {
	if view.Health.Code == "CLOUDFLARE-ZONE-PENDING" {
		return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflarePendingZonePresentation, PendingZone: ownerconsole.CloudflarePendingZone{Zone: view.Zone.Name, AssignedNameServers: view.Zone.AssignedNameServers, ObservedNameServers: view.Zone.ObservedNameServers, RegistrarSteps: []string{view.Zone.RegistrarGuidance}, Evidence: view.Health.Code}}
	}
	if view.Health.Outcome == cloudflaretunnel.Healthy || view.Credential.Status == "removed" {
		first, last := view.Credential.FirstFour, view.Credential.LastFour
		status := ownerconsole.CloudflareTokenActive
		if view.Credential.Status == "removed" {
			first, last, status = "none", "none", ownerconsole.CloudflareTokenUnknown
		}
		expiry := ""
		if view.Credential.ExpiresOn != nil {
			expiry = view.Credential.ExpiresOn.UTC().Format(time.RFC3339)
		}
		return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflareCredentialPresentation, Credential: ownerconsole.CloudflareCredential{Status: status, FirstFour: first, LastFour: last, Account: view.Account.ID, Zone: view.Zone.Name, LastVerification: view.LastCheck.UTC().Format(time.RFC3339), Expiry: expiry, Uses: view.Credential.Uses}}
	}
	return unavailableCloudflare(view.Health.Found)
}

func unavailableCloudflare(found string) ownerconsole.CloudflarePresentation {
	if found == "" {
		found = "the scoped Cloudflare authority could not be proved"
	}
	return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflareMissingPermissionPresentation, MissingPermission: ownerconsole.CloudflareMissingPermission{Capability: "Scoped Cloudflare account and zone authority", Account: "selected account", Zone: "selected zone", Found: found, Required: "Account API Tokens Read, Cloudflare Tunnel Edit, and DNS Write", WhyStopped: "SBXR does not bypass provider ownership", Evidence: "CLOUDFLARE-AUTHORITY-UNPROVED", DashboardSteps: []string{"Check the selected scoped token", "Correct its exact account and zone permissions"}}}
}

func certificateViewRequest(desired state.DesiredState, network networkpolicy.Result, dns cloudflaretunnel.CertificateDNSFacts) certificatelifecycle.ViewRequest {
	addresses := make([]string, len(dns.Addresses))
	for index, address := range dns.Addresses {
		addresses[index] = address.String()
	}
	caa := make([]certificatelifecycle.CAARecord, len(dns.EffectiveCAA.Records))
	for index, record := range dns.EffectiveCAA.Records {
		caa[index] = certificatelifecycle.CAARecord{Flags: record.Flags, Tag: record.Tag, Value: record.Value}
	}
	_, http01 := network.HTTP01Contribution()
	return certificatelifecycle.ViewRequest{
		SelectedIP: desired.NetworkPolicy.PrimarySubscriptionAddress, DirectHostname: desired.Cloudflare.DirectHostname,
		QualifiedAddresses: addresses, HTTP01: certificatelifecycle.HTTP01Prerequisites{AddressQualified: http01, RouteReachable: http01, Port80Available: http01, TimeSynchronized: http01, FirewallOwned: http01},
		DNS: certificatelifecycle.DNSFacts{Status: certificatelifecycle.DNSAvailable, Hostname: dns.Hostname, Addresses: addresses, DNSOnly: true}, CAA: certificatelifecycle.CAAFacts{Status: certificatelifecycle.CAAAvailable, Records: caa},
	}
}

func ownerCertificatesPresentation(view certificatelifecycle.ViewResult, renewalPolicy bool) ownerconsole.CertificatesPresentation {
	return ownerconsole.CertificatesPresentation{IP: ownerCertificateLineage(view.IP), DirectTLS: ownerCertificateLineage(view.Domain), Scheduler: ownerconsole.CertificateScheduler{
		Service: "sbxr-cert-renew.service", Timer: "sbxr-cert-renew.timer", Enabled: view.Scheduler.Enabled, Persistent: view.Scheduler.Persistent, Serial: view.Scheduler.Serial, Randomized: view.Scheduler.Randomized, ExactUnitPair: view.Scheduler.ExactUnitPair, NoCompetingScheduler: view.Scheduler.NoCompetingScheduler, RunsPerDay: view.Scheduler.RunsPerDay,
		Policy: ownerconsole.CertificateRenewalPolicy{Approved: renewalPolicy, IPDueWithin: 72 * time.Hour, IPFailureRetry: 6 * time.Hour, BusyLockRetry: time.Hour, UrgentAt: 24 * time.Hour, UrgentBusyLockRetry: 15 * time.Minute, DomainUsesARI: true, DomainFallbackAfter: 15 * 24 * time.Hour},
	}}
}

func ownerCertificateLineage(lineage certificatelifecycle.LineageStatus) ownerconsole.CertificateLineage {
	status := ownerconsole.CertificateMissing
	if lineage.Valid {
		status = ownerconsole.CertificateHealthy
	}
	if !lineage.NotAfter.IsZero() && !lineage.Valid {
		status = ownerconsole.CertificateNeedsAttention
	}
	notAfter := ""
	if !lineage.NotAfter.IsZero() {
		notAfter = lineage.NotAfter.UTC().Format(time.RFC3339)
	}
	return ownerconsole.CertificateLineage{Status: status, Identity: fmt.Sprint(lineage.Identity), Profile: lineage.RequiredProfile, NotAfter: notAfter, Due: lineage.Due, ActiveServingID: lineage.ActiveServingID}
}
