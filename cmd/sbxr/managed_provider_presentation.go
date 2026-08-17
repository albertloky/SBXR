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
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
)

type managedProviderPresentation struct {
	cloudflare        ownerconsole.CloudflarePresentation
	certificates      ownerconsole.CertificatesPresentation
	cloudflareHealth  cloudflaretunnel.Outcome
	certificateHealth certificatelifecycle.Outcome
}

func managedProviderPresentations(ctx context.Context, snapshot state.Snapshot, secrets state.InfrastructureSecretReader, network networkpolicy.Result) managedProviderPresentation {
	desired := snapshot.DesiredState
	viewRequest := cloudflaretunnel.ViewRequest{AccountID: desired.Cloudflare.AccountID, ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, TokenRemoved: desired.Cloudflare.ManagementTokenRemoved, NetworkPath: network.CloudflareTunnelPath, CredentialDetail: true, DedicatedBroadPolicyConfirmed: desired.Cloudflare.DedicatedBroadPolicyConfirmed}
	api := cloudflaretunnel.NewProductionAPI()
	if !viewRequest.TokenRemoved {
		token, err := cloudflaretunnel.NewManagementToken(secrets.ReadInfrastructureSecret(desired.Cloudflare.ManagementToken))
		if err != nil {
			return managedProviderPresentation{cloudflare: unavailableCloudflare("stored token is unavailable"), cloudflareHealth: cloudflaretunnel.Unknown}
		}
		viewRequest.Token = token
	}
	cloudflareView := cloudflaretunnel.New(api, cloudflaretunnel.SystemClock{}).View(ctx, viewRequest)
	cloudflarePresentation := ownerCloudflarePresentation(cloudflareView)
	result := managedProviderPresentation{cloudflare: cloudflarePresentation, cloudflareHealth: cloudflareView.Health.Outcome, certificateHealth: certificatelifecycle.Unknown}
	if cloudflareView.Health.Outcome != cloudflaretunnel.Healthy || viewRequest.TokenRemoved {
		return result
	}
	dns, err := api.ObserveCertificateDNS(ctx, cloudflaretunnel.CertificateDNSRequest{
		ZoneID: desired.Cloudflare.ZoneID, ZoneName: desired.Cloudflare.ZoneName, Hostname: desired.Cloudflare.DirectHostname,
		PublicIPv4: desired.NetworkPolicy.PublicIPv4, PublicIPv6: desired.NetworkPolicy.PublicIPv6,
		IPv4RecordID: desired.Cloudflare.DirectIPv4RecordID, IPv6RecordID: desired.Cloudflare.DirectIPv6RecordID, Token: viewRequest.Token,
	})
	if err != nil {
		return result
	}
	certificateView := certificatelifecycle.New(certificateubuntu.New(), installClock{}).View(ctx, certificateViewRequest(desired, network, dns))
	result.certificates = ownerCertificatesPresentation(certificateView, desired.Certificates.RenewalPolicy)
	result.certificateHealth = certificateView.Health.Outcome
	return result
}

func ownerCloudflarePresentation(view cloudflaretunnel.ViewResult) ownerconsole.CloudflarePresentation {
	if view.Health.Code == "CLOUDFLARE-ZONE-PENDING" {
		guidance, _ := cloudflaretunnel.ExternalCorrectionGuidance(cloudflaretunnel.NameserverCorrection)
		return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflarePendingZonePresentation, PendingZone: ownerconsole.CloudflarePendingZone{Zone: view.Zone.Name, AssignedNameServers: view.Zone.AssignedNameServers, ObservedNameServers: view.Zone.ObservedNameServers, RegistrarSteps: guidance.Instructions, Evidence: view.Health.Code, HelpURL: guidance.URL}}
	}
	if view.Health.Outcome == cloudflaretunnel.Healthy || view.Credential.Status == "removed" {
		tokenHelp, _ := cloudflaretunnel.CredentialGuidance(cloudflaretunnel.UserTokenInput)
		first, last := view.Credential.FirstFour, view.Credential.LastFour
		status := ownerconsole.CloudflareTokenActive
		if view.Credential.Status == "removed" {
			first, last, status = "none", "none", ownerconsole.CloudflareTokenUnknown
		}
		expiry := ""
		if view.Credential.ExpiresOn != nil {
			expiry = view.Credential.ExpiresOn.UTC().Format(time.RFC3339)
		}
		return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflareCredentialPresentation, Credential: ownerconsole.CloudflareCredential{Status: status, FirstFour: first, LastFour: last, Account: view.Account.ID, Zone: view.Zone.Name, LastVerification: view.LastCheck.UTC().Format(time.RFC3339), Expiry: expiry, Uses: view.Credential.Uses, Guidance: tokenHelp.Instructions, HelpURL: tokenHelp.URL}}
	}
	if view.Health.Code == "CLOUDFLARE-TOKEN-PERMISSION" {
		correction := view.PermissionCorrection
		return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflareMissingPermissionPresentation, MissingPermission: ownerconsole.CloudflareMissingPermission{
			Capability: correction.Capability, Account: correction.AccountID, Zone: fmt.Sprintf("%s (%s)", correction.ZoneID, correction.ZoneName), Found: correction.Found,
			Required: correction.Required, WhyStopped: correction.WhyStopped, Evidence: correction.Evidence, DashboardSteps: correction.DashboardSteps, HelpURL: correction.URL,
		}}
	}
	return unavailableCloudflare(view.Health.Found)
}

func ownerCloudflareExternalGuidance(correction cloudflaretunnel.ExternalCorrection) ownerconsole.CloudflareExternalGuidance {
	help, _ := cloudflaretunnel.ExternalCorrectionGuidance(correction)
	var instructions [3]string
	copy(instructions[:], help.Instructions)
	return ownerconsole.CloudflareExternalGuidance{Instructions: instructions, HelpURL: help.URL}
}

func ownerCompleteRemovalPresentation(presentation ownerconsole.CompleteRemovalPresentation) ownerconsole.CompleteRemovalPresentation {
	if presentation.Kind == ownerconsole.CompleteRemovalReviewAvailable {
		help := softwarelifecycle.CompleteRemovalConfirmationGuidance()
		presentation.ConfirmationHelp = ownerconsole.ConfirmationHelp{Title: help.Title, Lines: append([]string(nil), help.Lines...)}
	}
	if presentation.Kind == ownerconsole.CompleteRemovalForwardOnly && presentation.TokenPhase == ownerconsole.RemovalTokenAwaitingOwnerRevocation {
		presentation.ManagementTokenRevocation = ownerCloudflareExternalGuidance(cloudflaretunnel.ManagementTokenRevocation)
	}
	return presentation
}

func unavailableCloudflare(found string) ownerconsole.CloudflarePresentation {
	if found == "" {
		found = "the Dedicated Broad Cloudflare User API Token authority could not be proved"
	}
	tokenHelp, _ := cloudflaretunnel.CredentialGuidance(cloudflaretunnel.UserTokenInput)
	return ownerconsole.CloudflarePresentation{Kind: ownerconsole.CloudflareMissingPermissionPresentation, MissingPermission: ownerconsole.CloudflareMissingPermission{Capability: "Dedicated Broad Cloudflare User API Token authority", Account: "selected account", Zone: "selected zone", Found: found, Required: "User API Tokens Edit, Cloudflare Tunnel Edit, DNS Edit, and Zone Read", WhyStopped: "SBXR does not bypass provider ownership", Evidence: "CLOUDFLARE-AUTHORITY-UNPROVED", DashboardSteps: tokenHelp.Instructions, HelpURL: tokenHelp.URL}}
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
