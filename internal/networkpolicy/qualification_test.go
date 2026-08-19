package networkpolicy_test

import (
	"slices"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

func TestControlledInstallationUsesRackNerdShapedCleanVPSFacts(t *testing.T) {
	adapter := networkpolicy.ControlledInstallationAdapter()
	observed, err := adapter.Observe(networkpolicy.ObservationRequest{Scope: networkpolicy.LocalObservations, Stage: networkpolicy.PreApproval})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Firewall.ActiveManager != "ufw.service" || observed.Firewall.UFWConfiguredState != networkpolicy.UFWConfigDisabled || observed.Firewall.UFWReportedState != networkpolicy.UFWStatusInactive || !observed.Firewall.RootVerified {
		t.Fatalf("controlled inactive UFW facts = %+v", observed.Firewall)
	}
	for _, want := range []networkpolicy.Listener{
		{Address: "127.0.0.53", Port: 53, Protocol: networkpolicy.TCP, Process: "systemd-resolve", Service: "systemd-resolved.service", Executable: "/usr/lib/systemd/systemd-resolved"},
		{Address: "127.0.0.54", Port: 53, Protocol: networkpolicy.UDP, Process: "systemd-resolve", Service: "systemd-resolved.service", Executable: "/usr/lib/systemd/systemd-resolved"},
		{Address: "0.0.0.0", Port: 67, Protocol: networkpolicy.UDP, Process: "dhclient"},
		{Address: "::", Port: 547, Protocol: networkpolicy.UDP, Process: "dhcp6"},
		{Address: "127.0.0.1", Port: 123, Protocol: networkpolicy.UDP, Process: "chronyd", Service: "chrony.service"},
	} {
		if !slices.Contains(observed.Listeners, want) {
			t.Fatalf("controlled listeners omitted %+v: %+v", want, observed.Listeners)
		}
	}

	intent := networkpolicy.Intent{Revision: 1, Baseline: networkpolicy.Clean, PublicIPv4: "8.8.8.8", PrimarySubscriptionAddress: "8.8.8.8", SSHPort: 22, SubscriptionPort: 10443, Profiles: networkpolicy.Profiles{VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443}}, Disk: networkpolicy.DiskRequirement{PreparationBytes: 1, TemporaryBytes: 1, SnapshotBytes: 1, JournalBytes: 1, RollbackBytes: 1, OverheadBytes: 1}}
	result := networkpolicy.New(adapter).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PreApproval, ReclamationReview: true})
	if result.Outcome != networkpolicy.Healthy || result.InstallationClass != networkpolicy.CleanVPS || result.Reclamation != nil {
		t.Fatalf("RackNerd-shaped controlled Installation = class %q outcome %q reclamation %+v findings %+v", result.InstallationClass, result.Outcome, result.Reclamation, result.Findings)
	}
}
