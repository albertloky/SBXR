package ubuntu

import (
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestControlledInstallationAdapterRefusesEveryCloudflareEffect(t *testing.T) {
	step, err := systemchanges.NewCloudflareStep(systemchanges.CloudflareChange{Action: systemchanges.CloudflareTunnelCreate, AccountID: "account-123", TunnelName: "sbxr-main"})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewControlledInstallationAdapter(systemchanges.Observation{})
	if _, err := adapter.Execute(systemchanges.ExecutionLease{}, "install", 1, step, time.Second, nil); err == nil || !strings.Contains(err.Error(), "Cloudflare") {
		t.Fatalf("controlled Cloudflare effect = %v", err)
	}
}

func TestControlledInstallationAdapterPermitsOnlySBXRIPCertificateEffects(t *testing.T) {
	step, err := systemchanges.NewCertificateStep(systemchanges.CertificateChange{Action: systemchanges.CertificateDomainOrder, Identity: "direct.example.com", DestinationIP: "192.0.2.10", RequiredProfile: "tlsserver", CertName: "sbxr-domain", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewControlledInstallationAdapter(systemchanges.Observation{})
	if _, err := adapter.Execute(systemchanges.ExecutionLease{}, "install", 1, step, time.Second, nil); err == nil || !strings.Contains(err.Error(), "sbxr-ip") {
		t.Fatalf("controlled domain-certificate effect = %v", err)
	}
}
