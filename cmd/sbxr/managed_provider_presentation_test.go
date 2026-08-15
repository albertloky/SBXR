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
