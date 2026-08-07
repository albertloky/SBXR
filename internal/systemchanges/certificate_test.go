package systemchanges_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestCertificateStepsAcceptOnlyTheFixedSelectedIPContract(t *testing.T) {
	changes := []systemchanges.CertificateChange{
		{Action: systemchanges.CertificateIPStage, Identity: "2001:db8::10", RequiredProfile: "shortlived", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/staging/sbxr-ip", Account: "disposable-staging-sbxr-ip"},
		{Action: systemchanges.CertificateIPOrder, Identity: "2001:db8::10", RequiredProfile: "shortlived", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"},
		{Action: systemchanges.CertificateIPActivate, Identity: "2001:db8::10", RequiredProfile: "shortlived", CertName: "sbxr-ip", SubscriptionUnit: "sbxr-subscription.service"},
	}
	for _, change := range changes {
		step, err := systemchanges.NewCertificateStep(change)
		got, ok := step.CertificateChange()
		if err != nil || !ok || got != change || step.Owner() != systemchanges.CertificateModule {
			t.Fatalf("typed certificate step = %#v, %v", step, err)
		}
		if rendered := fmt.Sprintf("%+v %#v", step, change); strings.Contains(rendered, "PRIVATE-KEY-MARKER") {
			t.Fatalf("private material leaked: %s", rendered)
		}
	}
	invalid := changes[1]
	invalid.RequiredProfile = "preferred shortlived"
	if _, err := systemchanges.NewCertificateStep(invalid); err == nil {
		t.Fatal("fallback profile accepted")
	}
	invalid = changes[2]
	invalid.SubscriptionUnit = "xray.service"
	if _, err := systemchanges.NewCertificateStep(invalid); err == nil {
		t.Fatal("unrelated service accepted")
	}
}
