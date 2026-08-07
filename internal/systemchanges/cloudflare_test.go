package systemchanges

import "testing"

func TestCloudflareStepsAreTypedSecretFreeAndOrderedByEvidence(t *testing.T) {
	tunnel, err := NewCloudflareStep(CloudflareChange{Action: CloudflareTunnelCreate, AccountID: "account-123", TunnelName: "sbxr-main"})
	if err != nil {
		t.Fatal(err)
	}
	routes, err := NewCloudflareStep(CloudflareChange{Action: CloudflareRoutesPut, AccountID: "account-123", TunnelIDFromStep: 1, Routes: []CloudflareRoute{{Hostname: "xhttp.example.com", Origin: "http://127.0.0.1:11080"}, {Hostname: "ws.example.com", Origin: "http://127.0.0.1:11081"}, {Origin: "http_status:404"}}})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := NewCloudflareStep(CloudflareChange{Action: CloudflareDNSCreate, AccountID: "account-123", ZoneID: "zone-123", TunnelIDFromStep: 1, Hostname: "xhttp.example.com", RecordType: "CNAME"})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []Step{tunnel, routes, dns} {
		if step.Owner() != CloudflareModule || step.CancellationContract() != SafeCheckpointCancellation || step.InspectionContract() != InspectBeforeIdempotentReverse {
			t.Fatalf("unsafe Cloudflare step: %#v", step)
		}
		if _, ok := step.CloudflareChange(); !ok {
			t.Fatal("typed Cloudflare contract missing")
		}
	}
}

func TestCloudflareStepRejectsPublicOriginAndMissingEvidenceReference(t *testing.T) {
	bad := []CloudflareChange{
		{Action: CloudflareRoutesPut, AccountID: "account-123", Routes: []CloudflareRoute{{Hostname: "xhttp.example.com", Origin: "http://203.0.113.1:11080"}, {Origin: "http_status:404"}}},
		{Action: CloudflareDNSCreate, AccountID: "account-123", ZoneID: "zone-123", Hostname: "xhttp.example.com", RecordType: "CNAME"},
	}
	for _, change := range bad {
		if _, err := NewCloudflareStep(change); err == nil {
			t.Fatalf("accepted unsafe Cloudflare change: %#v", change)
		}
	}
}
