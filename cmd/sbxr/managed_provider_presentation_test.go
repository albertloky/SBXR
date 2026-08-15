package main

import (
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/certificatelifecycle"
	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/state"
)

func TestManagedProviderPresentationKeepsTypedCloudflareAndCertificateFacts(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	cloudflare := ownerCloudflarePresentation(cloudflaretunnel.ViewResult{
		Account: cloudflaretunnel.AccountStatus{ID: "11111111111111111111111111111111"}, Zone: cloudflaretunnel.ZoneStatus{Name: "example.com"},
		Credential: cloudflaretunnel.CredentialStatus{Status: "active", FirstFour: "cfat", LastFour: "last", Uses: []string{"manage one Tunnel"}},
		Health:     cloudflaretunnel.Health{Outcome: cloudflaretunnel.Healthy}, LastCheck: now,
	})
	if cloudflare.Kind != ownerconsole.CloudflareCredentialPresentation || cloudflare.Credential.Status != ownerconsole.CloudflareTokenActive || cloudflare.Credential.LastVerification != now.Format(time.RFC3339) || len(cloudflare.Credential.Guidance) != 2 || cloudflare.Credential.HelpURL != "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/" {
		t.Fatalf("Cloudflare presentation = %+v", cloudflare)
	}

	missing := ownerCloudflarePresentation(cloudflaretunnel.ViewResult{
		Health: cloudflaretunnel.Health{Outcome: cloudflaretunnel.Failed, Code: "CLOUDFLARE-TOKEN-PERMISSION", Found: "token is missing DNS Write"},
		PermissionCorrection: cloudflaretunnel.PermissionCorrection{
			Capability: "Required Cloudflare Account API Token authority", AccountID: "11111111111111111111111111111111", ZoneID: "22222222222222222222222222222222", ZoneName: "example.com", Found: "token is missing DNS Write", Required: "Zone > DNS > Edit on selected zone 22222222222222222222222222222222", WhyStopped: "SBXR does not bypass required Cloudflare authority", Evidence: "copyable redacted CLOUDFLARE-TOKEN-PERMISSION result",
			DashboardSteps: []string{"Open Manage Account > Account API Tokens in the selected account.", "Edit the exact token permission.", "Return to SBXR and select Check current token again."}, URL: "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/",
		},
	})
	if missing.Kind != ownerconsole.CloudflareMissingPermissionPresentation || missing.MissingPermission.Account != "11111111111111111111111111111111" || missing.MissingPermission.Zone != "22222222222222222222222222222222 (example.com)" || missing.MissingPermission.Required != "Zone > DNS > Edit on selected zone 22222222222222222222222222222222" {
		t.Fatalf("missing-permission presentation = %+v", missing)
	}

	pending := ownerCloudflarePresentation(cloudflaretunnel.ViewResult{
		Zone:   cloudflaretunnel.ZoneStatus{Name: "example.com", AssignedNameServers: []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}, ObservedNameServers: []string{"old-a.example.net", "old-b.example.net"}},
		Health: cloudflaretunnel.Health{Outcome: cloudflaretunnel.NeedsAttention, Code: "CLOUDFLARE-ZONE-PENDING"},
	})
	if pending.Kind != ownerconsole.CloudflarePendingZonePresentation || pending.PendingZone.HelpURL != "https://developers.cloudflare.com/dns/nameservers/update-nameservers/" || len(pending.PendingZone.RegistrarSteps) != 3 {
		t.Fatalf("pending-zone presentation = %+v", pending)
	}

	certificate := ownerCertificatesPresentation(certificatelifecycle.ViewResult{
		IP:        certificatelifecycle.LineageStatus{Identity: "192.0.2.10", RequiredProfile: "shortlived", Valid: true, Due: true, NotAfter: now.Add(72 * time.Hour), ActiveServingID: "ip-current"},
		Domain:    certificatelifecycle.LineageStatus{Identity: "direct.example.com", RequiredProfile: "tlsserver", Valid: true, NotAfter: now.Add(15 * 24 * time.Hour), ActiveServingID: "domain-current"},
		Scheduler: certificatelifecycle.SchedulerStatus{Enabled: true, Persistent: true, Serial: true, ExactUnitPair: true, Randomized: true, NoCompetingScheduler: true, RunsPerDay: 2},
	}, true)
	if certificate.IP.Status != ownerconsole.CertificateHealthy || !certificate.IP.Due || certificate.DirectTLS.Status != ownerconsole.CertificateHealthy || !certificate.Scheduler.Policy.Approved || certificate.Scheduler.Policy.DomainFallbackAfter != 15*24*time.Hour {
		t.Fatalf("Certificate presentation = %+v", certificate)
	}
	if ownerCertificatesPresentation(certificatelifecycle.ViewResult{}, false).Scheduler.Policy.Approved {
		t.Fatal("disabled renewal policy was presented as approved")
	}
}

func TestManagedCertificateReviewCanPopulateLegacyOwnerEmail(t *testing.T) {
	desired := state.DesiredState{Certificates: state.CertificateSettings{RenewalPolicy: true}}
	manual := managedCertificateCandidate(desired, "owner@example.com", false)
	standing := managedCertificateCandidate(desired, "owner@example.com", true)
	if manual.Certificates.OwnerEmail != "owner@example.com" || standing.Certificates.OwnerEmail != "" {
		t.Fatalf("certificate candidates = manual %q standing %q", manual.Certificates.OwnerEmail, standing.Certificates.OwnerEmail)
	}
}
