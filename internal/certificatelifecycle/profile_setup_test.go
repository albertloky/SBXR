package certificatelifecycle

import "testing"

func TestProfileSetupUsesTheCandidateRevisionForNetworkContributions(t *testing.T) {
	request := PlanRequest{Lineage: DomainLineage, StartingRevision: 7, FreshDNS: FreshDNSAuthority{cell: &freshDNSCell{hostname: "direct.example.com"}}}
	if got := networkContributionRevision(request, false); got != 8 {
		t.Fatalf("profile setup contribution revision = %d, want 8", got)
	}
	if got := networkContributionRevision(request, true); got != 7 {
		t.Fatalf("fresh installation contribution revision = %d, want 7", got)
	}
}
