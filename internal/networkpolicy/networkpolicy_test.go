package networkpolicy_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/networkpolicy"
)

type staticAdapter struct {
	observed networkpolicy.Observations
}

func TestEvaluatePrivilegeStalenessDiskAndTime(t *testing.T) {
	t.Run("candidate preserves the freshly detected SSH port", func(t *testing.T) {
		observed := completeObservations()
		observed.SSH.DetectedPort = 2200
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-SSH-DETECTION")
		if result.Policy.Exposures[0].Port != 2200 {
			t.Fatalf("SSH exposure = %d, want freshly detected 2200", result.Policy.Exposures[0].Port)
		}
	})

	t.Run("missing current SSH session fails safely", func(t *testing.T) {
		observed := completeObservations()
		observed.SSH.CurrentSessions = nil
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-SSH-DETECTION")
	})

	t.Run("pre-approval discloses root-only check", func(t *testing.T) {
		observed := completeObservations()
		observed.Firewall.RootVerified = false
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PreApproval})
		assertFinding(t, result, networkpolicy.Unknown, networkpolicy.Required, "NETWORK-PRIVILEGED-PENDING")
		if !strings.Contains(result.Findings[0].Required, "nftables") {
			t.Fatalf("pending check = %+v", result.Findings[0])
		}
	})

	t.Run("post-approval requires fresh privileged fact", func(t *testing.T) {
		observed := completeObservations()
		observed.Firewall.RootVerified = false
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-PRIVILEGED-MISSING")
	})

	t.Run("every changed volatile fact is stale but review time is absent", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		request := networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(request)
		if result.Binding.Stale(request, observed) {
			t.Fatal("unchanged facts became stale")
		}
		withUnusedCandidate := completeObservations()
		withUnusedCandidate.PortCandidates = []networkpolicy.PortCandidate{{Port: 20000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true}}
		if result.Binding.Stale(request, withUnusedCandidate) {
			t.Fatal("an unused random candidate became a host fact")
		}
		changes := []func(*networkpolicy.Observations){
			func(o *networkpolicy.Observations) { o.PublicIPv4[0] = "192.0.2.11" },
			func(o *networkpolicy.Observations) {
				o.Listeners = append(o.Listeners, networkpolicy.Listener{Port: 9999, Protocol: networkpolicy.TCP})
			},
			func(o *networkpolicy.Observations) {
				o.SSH.CurrentSessions = append(o.SSH.CurrentSessions, "session-2")
			},
			func(o *networkpolicy.Observations) { o.Firewall.SBXRTableState = "changed" },
			func(o *networkpolicy.Observations) { o.Routes.IPv4 = "changed" },
			func(o *networkpolicy.Observations) { o.OwnerFacts.DNS = "changed" },
			func(o *networkpolicy.Observations) { o.Outbound.DNS = false },
			func(o *networkpolicy.Observations) { o.Checksums["nftables"] = "sha256:changed" },
		}
		for index, change := range changes {
			changed := completeObservations()
			change(&changed)
			if !result.Binding.Stale(request, changed) {
				t.Fatalf("volatile change %d did not invalidate result", index)
			}
		}
	})

	for _, tt := range []struct {
		name       string
		filesystem uint64
		floor      uint64
	}{
		{name: "one GiB floor", filesystem: 8 << 30, floor: 1 << 30},
		{name: "ten percent floor", filesystem: 20 << 30, floor: 2 << 30},
	} {
		t.Run(tt.name, func(t *testing.T) {
			intent, observed := completeIntent(), completeObservations()
			reserved := intent.Disk.Total()
			observed.Disk.FilesystemBytes = tt.filesystem
			observed.Disk.AvailableBytes = reserved + tt.floor - 1
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
			assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-DISK-FLOOR")
			finding := result.Findings[0]
			if finding.Found != fmt.Sprintf("%d bytes available", observed.Disk.AvailableBytes) || finding.Required != fmt.Sprintf("%d bytes available", reserved+tt.floor) {
				t.Fatalf("disk finding = %+v", finding)
			}
		})
	}

	t.Run("Clean VPS can review native time correction", func(t *testing.T) {
		observed := completeObservations()
		observed.Time = networkpolicy.TimeFacts{}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-TIME-CORRECTION")
		if result.Findings[0].Fix.SBXROption != "Review enabling systemd-timesyncd, then check again." {
			t.Fatalf("time correction = %+v", result.Findings[0].Fix)
		}
	})

	t.Run("existing time owner is never replaced", func(t *testing.T) {
		intent, observed := managedBaseline()
		observed.Time = networkpolicy.TimeFacts{Owner: "chrony.service"}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-TIME-OWNER")
		if result.Findings[0].Fix.SBXROption != "" || len(result.Findings[0].Fix.OwnerChecklist) == 0 {
			t.Fatalf("time-owner correction = %+v", result.Findings[0].Fix)
		}
	})
}

func assertFinding(t *testing.T, result networkpolicy.Result, outcome networkpolicy.Outcome, class networkpolicy.Classification, code string) {
	t.Helper()
	if result.Outcome != outcome || len(result.Findings) != 1 || result.Findings[0].Code != code || result.Findings[0].Classification != class {
		t.Fatalf("Evaluate() = outcome %q findings %+v, want %q %s %s", result.Outcome, result.Findings, outcome, class, code)
	}
	finding := result.Findings[0]
	if finding.Problem == "" || finding.Found == "" || finding.Required == "" || finding.WhyStopped == "" || finding.CheckAgain == "" || finding.Back == "" || finding.Evidence == "" {
		t.Fatalf("finding omitted Correction Flow material: %+v", finding)
	}
}

func (a staticAdapter) Observe(networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	return a.observed, nil
}

func TestEvaluateSupportedCleanBaseline(t *testing.T) {
	intent := completeIntent()
	observed := completeObservations()
	observed.Host.Virtualization = "unfamiliar-hypervisor"

	result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{
		Intent: intent,
		Stage:  networkpolicy.PostApproval,
	})

	if result.Outcome != networkpolicy.Healthy || result.Baseline != networkpolicy.Clean || len(result.Findings) != 0 {
		t.Fatalf("Evaluate() = outcome %q, baseline %q, findings %+v", result.Outcome, result.Baseline, result.Findings)
	}
	want := []networkpolicy.Exposure{
		{Purpose: "SSH preservation", Address: "public", Port: 2222, Protocol: networkpolicy.TCP},
		{Purpose: "VLESS REALITY Vision", Address: "public", Port: 443, Protocol: networkpolicy.TCP},
		{Purpose: "Hysteria2", Address: "public", Port: 443, Protocol: networkpolicy.UDP},
		{Purpose: "TUIC", Address: "public", Port: 8443, Protocol: networkpolicy.UDP},
		{Purpose: "AnyTLS", Address: "public", Port: 9443, Protocol: networkpolicy.TCP},
		{Purpose: "Subscription HTTPS", Address: "public", Port: 10443, Protocol: networkpolicy.TCP},
		{Purpose: "VLESS XHTTP origin", Address: "127.0.0.1", Port: 11080, Protocol: networkpolicy.TCP},
		{Purpose: "VLESS WebSocket origin", Address: "127.0.0.1", Port: 11081, Protocol: networkpolicy.TCP},
	}
	if len(result.Policy.Exposures) != len(want) {
		t.Fatalf("exposures = %+v, want %+v", result.Policy.Exposures, want)
	}
	for index := range want {
		if result.Policy.Exposures[index] != want[index] {
			t.Fatalf("exposure %d = %+v, want %+v", index, result.Policy.Exposures[index], want[index])
		}
	}
	if result.Binding.Digest == "" || len(result.PreApplyGates) == 0 || len(result.PostApplyGates) == 0 {
		t.Fatal("healthy result omitted staleness binding or Apply gates")
	}
}

func TestEvaluateRefusesIncompleteIntent(t *testing.T) {
	for _, change := range []func(*networkpolicy.Intent){
		func(intent *networkpolicy.Intent) { intent.Revision = 0 },
		func(intent *networkpolicy.Intent) { intent.Baseline = "discovered" },
		func(intent *networkpolicy.Intent) { intent.SSHPort = 0 },
		func(intent *networkpolicy.Intent) { intent.Profiles.VLESSXHTTP.Address = "" },
	} {
		intent := completeIntent()
		change(&intent)
		result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-INTENT-INVALID")
	}
}

func TestEvaluateHostBaseline(t *testing.T) {
	tests := []struct {
		name    string
		change  func(*networkpolicy.Intent, *networkpolicy.Observations)
		outcome networkpolicy.Outcome
		code    string
		class   networkpolicy.Classification
	}{
		{name: "Ubuntu 22.04", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.UbuntuVersion = "22.04.5" }, outcome: networkpolicy.Failed, code: "NETWORK-HOST-UBUNTU", class: networkpolicy.Required},
		{name: "Ubuntu Desktop", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.UbuntuServer = false }, outcome: networkpolicy.Failed, code: "NETWORK-HOST-UBUNTU-SERVER", class: networkpolicy.Required},
		{name: "unsupported architecture", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.Architecture = "386" }, outcome: networkpolicy.Failed, code: "NETWORK-HOST-ARCH", class: networkpolicy.Required},
		{name: "systemd absent", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.Systemd = false }, outcome: networkpolicy.Failed, code: "NETWORK-HOST-SYSTEMD", class: networkpolicy.Required},
		{name: "no logical CPU", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.LogicalCPUs = 0 }, outcome: networkpolicy.Failed, code: "NETWORK-HOST-CPU", class: networkpolicy.Required},
		{name: "less than 512 MiB physical RAM", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.PhysicalRAM = 511 << 20 }, outcome: networkpolicy.Failed, code: "NETWORK-HOST-RAM", class: networkpolicy.Required},
		{name: "less than recommended RAM", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.Host.PhysicalRAM = 768 << 20 }, outcome: networkpolicy.NeedsAttention, code: "NETWORK-HOST-RAM-RECOMMENDED", class: networkpolicy.Advisory},
		{name: "no public address", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) { o.PublicIPv4 = nil }, outcome: networkpolicy.Failed, code: "NETWORK-PUBLIC-ADDRESS", class: networkpolicy.Required},
		{name: "IPv6 only", change: func(i *networkpolicy.Intent, o *networkpolicy.Observations) {
			i.PublicIPv4, o.PublicIPv4 = "", nil
			i.PublicIPv6, i.PrimarySubscriptionAddress = "2001:db8::10", "2001:db8::10"
			o.PublicIPv6 = []string{"2001:db8::10"}
		}, outcome: networkpolicy.Healthy},
		{name: "dual family", change: func(i *networkpolicy.Intent, o *networkpolicy.Observations) {
			i.PublicIPv6 = "2001:db8::10"
			o.PublicIPv6 = []string{"2001:db8::10"}
		}, outcome: networkpolicy.Healthy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intent, observed := completeIntent(), completeObservations()
			tt.change(&intent, &observed)
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
			if result.Outcome != tt.outcome {
				t.Fatalf("outcome = %q, want %q; findings %+v", result.Outcome, tt.outcome, result.Findings)
			}
			if tt.code == "" {
				if len(result.Findings) != 0 {
					t.Fatalf("findings = %+v, want none", result.Findings)
				}
				return
			}
			if len(result.Findings) != 1 || result.Findings[0].Code != tt.code || result.Findings[0].Classification != tt.class || result.Findings[0].Found == "" || result.Findings[0].Required == "" {
				t.Fatalf("finding = %+v, want %s %s", result.Findings, tt.class, tt.code)
			}
		})
	}
}

func TestEvaluateCleanAndManagedOwnership(t *testing.T) {
	t.Run("Clean refuses unproved proxy ownership", func(t *testing.T) {
		observed := completeObservations()
		observed.Listeners = []networkpolicy.Listener{{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "xray", Service: "xray.service", Ownership: networkpolicy.Unproved}}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CLEAN-ADOPTION-REFUSED")
	})

	t.Run("Clean refuses an unproved service identity without a listener", func(t *testing.T) {
		for _, change := range []func(*networkpolicy.Observations){
			func(observed *networkpolicy.Observations) {
				observed.ServiceIdentities = []string{"cloudflared.service"}
			},
			func(observed *networkpolicy.Observations) { observed.ResourcePaths = []string{"/var/lib/sbxr"} },
		} {
			observed := completeObservations()
			change(&observed)
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
			assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CLEAN-ADOPTION-REFUSED")
		}
	})

	t.Run("Managed matching Desired State is healthy", func(t *testing.T) {
		intent, observed := managedBaseline()
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		if result.Outcome != networkpolicy.Healthy || len(result.Findings) != 0 {
			t.Fatalf("Managed Evaluate() = %q %+v", result.Outcome, result.Findings)
		}
	})

	t.Run("Managed coordinates lineage and ownership with production-shaped facts", func(t *testing.T) {
		intent, observed := managedBaseline()
		observed.Lineage = ""
		observed.Firewall.SBXRTableState = ""
		observed.Checksums["sbxr_nftables"] = "sha256:managed-policy"
		proof := networkpolicy.ManagedProof{Lineage: networkpolicy.ProvenLineage, NftablesSHA256: "sha256:managed-policy"}
		for index := range observed.Listeners {
			observed.Listeners[index].Ownership = networkpolicy.Unproved
			listener := observed.Listeners[index]
			proof.Listeners = append(proof.Listeners, networkpolicy.ListenerProof{Address: listener.Address, Port: listener.Port, Protocol: listener.Protocol, Service: listener.Service})
		}
		request := networkpolicy.Request{
			Intent:     intent,
			Stage:      networkpolicy.PostApproval,
			Managed:    proof,
			OwnerFacts: networkpolicy.OwnerFacts{DNS: "matches Desired State", Tunnel: "matches Desired State"},
		}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(request)
		if result.Outcome != networkpolicy.Healthy || len(result.Findings) != 0 {
			t.Fatalf("coordinated Managed Evaluate() = %q %+v", result.Outcome, result.Findings)
		}
		if result.Binding.Stale(request, observed) {
			t.Fatal("unchanged production-shaped Managed facts became stale")
		}
	})

	t.Run("Managed proven drift repairs forward", func(t *testing.T) {
		intent, observed := managedBaseline()
		observed.Listeners = observed.Listeners[1:]
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-MANAGED-DRIFT")
		if result.Findings[0].Fix.SBXROption == "" {
			t.Fatal("managed drift omitted forward-repair option")
		}
	})

	t.Run("contradictory lineage requires recovery", func(t *testing.T) {
		intent, observed := managedBaseline()
		observed.Lineage = networkpolicy.ContradictoryLineage
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-LINEAGE-RECOVERY")
	})

	t.Run("active competing firewall blocks Clean adoption", func(t *testing.T) {
		observed := completeObservations()
		observed.Firewall.ActiveManager = "ufw.service"
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-FIREWALL-CONFLICT")
		if result.Findings[0].Fix.SBXROption != "" {
			t.Fatal("result offered to disable another firewall manager")
		}
	})

	t.Run("Clean refuses unproved DNS or Tunnel ownership", func(t *testing.T) {
		for _, facts := range []networkpolicy.OwnerFacts{{DNS: networkpolicy.UnprovedResource}, {Tunnel: networkpolicy.UnprovedResource}} {
			observed := completeObservations()
			observed.OwnerFacts = facts
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
			assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CLEAN-ADOPTION-REFUSED")
		}
	})

	t.Run("Clean refuses an existing unproved SBXR nftables table", func(t *testing.T) {
		observed := completeObservations()
		observed.Firewall.SBXRTableState = "present"
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CLEAN-ADOPTION-REFUSED")
	})

	t.Run("disabled profile has no public exposure", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		intent.Profiles.AnyTLS.Enabled = false
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		for _, exposure := range result.Policy.Exposures {
			if exposure.Purpose == "AnyTLS" {
				t.Fatal("disabled AnyTLS remained exposed")
			}
		}
	})

	t.Run("Tunnel origins must stay loopback-only", func(t *testing.T) {
		intent := completeIntent()
		intent.Profiles.VLESSXHTTP.Address = "0.0.0.0"
		result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-ORIGIN-LOOPBACK")
	})
}

func TestEvaluateCorrectiveNetworkPolicy(t *testing.T) {
	t.Run("failed optional family produces a reviewed single-family policy", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		intent.PublicIPv6 = "2001:db8::10"
		intent.PrimarySubscriptionAddress = intent.PublicIPv6
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Advisory, "NETWORK-PUBLIC-FAMILY-EXCLUDED")
		if result.Policy.PublicIPv4 != "192.0.2.10" || result.Policy.PublicIPv6 != "" || result.Policy.PrimaryAddress != "192.0.2.10" {
			t.Fatalf("single-family policy = %+v", result.Policy)
		}
	})

	t.Run("TCP and UDP ownership are independent and configurable conflict gets safe alternative", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		observed.Listeners = []networkpolicy.Listener{{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"}}
		observed.Ephemeral = networkpolicy.PortRange{First: 32768, Last: 60999}
		observed.PortCandidates = []networkpolicy.PortCandidate{
			{Port: 2222, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 80, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 40000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 20000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
		}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-PORT-ALTERNATIVE")
		var vless, hysteria uint16
		for _, exposure := range result.Policy.Exposures {
			switch exposure.Purpose {
			case "VLESS REALITY Vision":
				vless = exposure.Port
			case "Hysteria2":
				hysteria = exposure.Port
			}
		}
		if vless != 20000 || hysteria != 443 {
			t.Fatalf("corrected TCP/UDP policy = %+v", result.Policy.Exposures)
		}
	})

	t.Run("temporary TCP 80 is exact and never moved", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		intent.TemporaryHTTP = true
		observed.Listeners = []networkpolicy.Listener{{Address: "0.0.0.0", Port: 80, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"}}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-FIXED-PORT-CONFLICT")
		if result.Findings[0].Fix.SBXROption != "" {
			t.Fatal("TCP 80 conflict offered an automatic service change")
		}
	})

	t.Run("outbound failure is Required and bounded", func(t *testing.T) {
		observed := completeObservations()
		observed.Outbound.CloudflareHTTPS = false
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-OUTBOUND-CLOUDFLARE-HTTPS")
		if result.Findings[0].Fix.SBXROption != "" || result.Bounds.TemporaryAttempts != 3 || result.Bounds.TemporaryWindowSeconds != 60 {
			t.Fatalf("outbound correction/bounds = %+v %+v", result.Findings[0].Fix, result.Bounds)
		}
	})

	t.Run("evidence never renders supplied checksums", func(t *testing.T) {
		observed := completeObservations()
		observed.Checksums["secret-marker"] = "CLIENT-ACCESS-VALUE-MUST-NOT-RENDER"
		observed.Outbound.DNS = false
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		if strings.Contains(fmt.Sprintf("%+v", result), "CLIENT-ACCESS-VALUE-MUST-NOT-RENDER") {
			t.Fatal("result rendered a supplied checksum value")
		}
	})
}

func managedBaseline() (networkpolicy.Intent, networkpolicy.Observations) {
	intent, observed := completeIntent(), completeObservations()
	intent.Baseline = networkpolicy.Managed
	observed.Lineage = networkpolicy.ProvenLineage
	observed.Firewall.SBXRTableState = "matches Desired State"
	observed.OwnerFacts = networkpolicy.OwnerFacts{DNS: "matches Desired State", Tunnel: "matches Desired State"}
	observed.Listeners = []networkpolicy.Listener{
		{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.UDP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 8443, Protocol: networkpolicy.UDP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 9443, Protocol: networkpolicy.TCP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 10443, Protocol: networkpolicy.TCP, Service: "sbxr-subscription.service", Ownership: networkpolicy.SBXROwned},
		{Address: "127.0.0.1", Port: 11080, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned},
		{Address: "127.0.0.1", Port: 11081, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned},
	}
	return intent, observed
}

func completeIntent() networkpolicy.Intent {
	return networkpolicy.Intent{
		Revision:                   1,
		Baseline:                   networkpolicy.Clean,
		PublicIPv4:                 "192.0.2.10",
		PrimarySubscriptionAddress: "192.0.2.10",
		SSHPort:                    2222,
		Profiles: networkpolicy.Profiles{
			VLESSRealityVision: networkpolicy.Profile{Enabled: true, Port: 443},
			VLESSXHTTP:         networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11080},
			VLESSWebSocket:     networkpolicy.Profile{Enabled: true, Address: "127.0.0.1", Port: 11081},
			Hysteria2:          networkpolicy.Profile{Enabled: true, Port: 443},
			TUIC:               networkpolicy.Profile{Enabled: true, Port: 8443},
			AnyTLS:             networkpolicy.Profile{Enabled: true, Port: 9443},
		},
		SubscriptionPort: 10443,
		Disk: networkpolicy.DiskRequirement{
			PreparationBytes: 100,
			TemporaryBytes:   100,
			SnapshotBytes:    100,
			JournalBytes:     100,
			RollbackBytes:    100,
			OverheadBytes:    100,
		},
	}
}

func completeObservations() networkpolicy.Observations {
	return networkpolicy.Observations{
		Host: networkpolicy.HostFacts{
			UbuntuVersion: "24.04.3",
			UbuntuServer:  true,
			Architecture:  "amd64",
			Systemd:       true,
			LogicalCPUs:   1,
			PhysicalRAM:   1024 << 20,
		},
		PublicIPv4: []string{"192.0.2.10"},
		SSH:        networkpolicy.SSHFacts{DetectedPort: 2222, CurrentSessions: []string{"session-1"}},
		Firewall:   networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true},
		Routes:     networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound:   networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:       networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30},
		Time:       networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"},
		OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Checksums:  map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
	}
}
