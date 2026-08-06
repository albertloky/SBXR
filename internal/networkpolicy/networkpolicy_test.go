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

type stagedAdapter struct {
	observed     networkpolicy.Observations
	requests     []networkpolicy.ObservationRequest
	failExternal bool
}

func (a *stagedAdapter) Observe(request networkpolicy.ObservationRequest) (networkpolicy.Observations, error) {
	a.requests = append(a.requests, request)
	if a.failExternal && request.Scope == networkpolicy.ExternalObservations {
		return networkpolicy.Observations{}, fmt.Errorf("external observation should not run")
	}
	return a.observed, nil
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

func TestEvaluateStopsBeforeExternalChecksOnDeterministicLocalFailure(t *testing.T) {
	observed := completeObservations()
	observed.Host.UbuntuVersion = "22.04.5"
	adapter := &stagedAdapter{observed: observed, failExternal: true}
	result := networkpolicy.New(adapter).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
	assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-HOST-UBUNTU")
	if len(adapter.requests) != 1 || adapter.requests[0].Scope != networkpolicy.LocalObservations {
		t.Fatalf("deterministic local failure observation stages = %+v", adapter.requests)
	}

	healthy := &stagedAdapter{observed: completeObservations()}
	result = networkpolicy.New(healthy).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
	if result.Outcome != networkpolicy.Healthy || len(healthy.requests) != 2 || healthy.requests[1].Scope != networkpolicy.ExternalObservations {
		t.Fatalf("healthy observation stages = %+v result %+v", healthy.requests, result.Findings)
	}
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
	if result.Policy.CertificateAddress != "192.0.2.10" {
		t.Fatalf("certificate address = %q, want primary subscription address", result.Policy.CertificateAddress)
	}
}

func TestEvaluateIsolatedNftablesCandidateAndSSHSafety(t *testing.T) {
	result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
	want := `table inet sbxr {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iifname "lo" accept
		ip protocol icmp accept
		meta l4proto ipv6-icmp accept
		ip daddr 192.0.2.10 tcp dport { 443, 2222, 9443, 10443 } accept
		ip daddr 192.0.2.10 udp dport { 443, 8443 } accept
	}
}`
	if result.Policy.Nftables != want {
		t.Fatalf("nftables candidate:\n%s\nwant:\n%s", result.Policy.Nftables, want)
	}
	if result.Policy.Table != "inet sbxr" || result.Policy.FlushRuleset {
		t.Fatalf("candidate ownership = table %q flush=%t", result.Policy.Table, result.Policy.FlushRuleset)
	}
	if result.SystemChanges != (networkpolicy.SystemChangesRequirements{
		ValidateCompleteCandidate: true,
		AtomicTableApply:          true,
		RootOwnedWatchdog:         true,
		ProveCurrentSSHResponsive: true,
		ProveDetectedSSHAdmitted:  true,
		CancelAfterGate:           "NETWORK-SSH-RESPONSIVE",
		RestoreExactPreviousRules: true,
	}) {
		t.Fatalf("System Changes requirements = %+v", result.SystemChanges)
	}
	if result.SSHSafety.SecondConnectionRequired || result.SSHSafety.EditsSSHConfiguration || !result.SSHSafety.FutureOutsideReconnectUnproved || result.SSHSafety.Warning != "One existing SSH session cannot prove a future outside reconnection." || result.SSHSafety.RecoveryPath != "VPS provider console" {
		t.Fatalf("SSH safety = %+v", result.SSHSafety)
	}
	if result.CompleteRemoval != (networkpolicy.CompleteRemoval{Family: "inet", Table: "sbxr", PreserveUnrelatedPolicy: true}) {
		t.Fatalf("Complete removal = %+v", result.CompleteRemoval)
	}
	if !hasGate(result.PreApplyGates, "NETWORK-WATCHDOG-READY") || !hasGate(result.PostApplyGates, "NETWORK-SSH-RESPONSIVE") {
		t.Fatalf("watchdog gates = pre %+v post %+v", result.PreApplyGates, result.PostApplyGates)
	}
	observed := completeObservations()
	observed.SSH.ServerAddress = "10.0.0.4"
	management := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
	if !strings.Contains(management.Policy.Nftables, "ip daddr 10.0.0.4 tcp dport 2222 accept") {
		t.Fatalf("candidate omitted detected management-address SSH: %q", management.Policy.Nftables)
	}
}

func TestEvaluateNftablesIntervalsAndCompetingPolicy(t *testing.T) {
	t.Run("TCP 80 exists only during certificate work", func(t *testing.T) {
		intent := completeIntent()
		intent.TemporaryHTTP = true
		result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		if !strings.Contains(result.Policy.Nftables, `tcp dport 80 accept comment "sbxr:acme-http-01"`) {
			t.Fatalf("temporary candidate = %q", result.Policy.Nftables)
		}
	})

	for _, manager := range []string{"", "ufw.service", "firewalld.service", "docker.service"} {
		name := manager
		if name == "" {
			name = "installed but inactive managers"
		}
		t.Run(name, func(t *testing.T) {
			observed := completeObservations()
			observed.Firewall.ActiveManager = manager
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
			if manager == "" {
				if result.Outcome != networkpolicy.Healthy {
					t.Fatalf("inactive managers blocked: %+v", result.Findings)
				}
				return
			}
			assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-FIREWALL-CONFLICT")
			if !strings.Contains(result.Findings[0].Found, "manager") || !strings.Contains(result.Findings[0].Found, manager) || !strings.Contains(result.Findings[0].Found, "service") || !strings.Contains(result.Findings[0].Found, "table") || !strings.Contains(result.Findings[0].Found, "chain") || !strings.Contains(result.Findings[0].Found, "rule") {
				t.Fatalf("competing manager finding = %q", result.Findings[0].Found)
			}
		})
	}

	t.Run("unexpected base chain keeps exact safe identity", func(t *testing.T) {
		observed := completeObservations()
		observed.Firewall.UnexpectedRule = `manager "nftables"; service "nftables"; table "filter"; chain "input"; rule "base chain hook input"`
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-FIREWALL-CONFLICT")
		if result.Findings[0].Found != observed.Firewall.UnexpectedRule {
			t.Fatalf("unexpected policy finding = %q", result.Findings[0].Found)
		}
	})
}

func TestEvaluateExactTemporaryHTTP01Policy(t *testing.T) {
	intent := completeIntent()
	intent.TemporaryHTTP = true
	result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	want := &networkpolicy.TemporaryHTTPPolicy{
		Identity:            "sbxr:acme-http-01",
		Purpose:             "ACME HTTP-01 validation for IP and domain certificates",
		Exposure:            networkpolicy.Exposure{Purpose: "ACME HTTP-01", Address: "public", Port: 80, Protocol: networkpolicy.TCP},
		RecordNativeHandles: true,
		RemoveAfter: [5]networkpolicy.CleanupOutcome{
			networkpolicy.CleanupSuccess,
			networkpolicy.CleanupFailure,
			networkpolicy.CleanupInterruption,
			networkpolicy.CleanupCancellation,
			networkpolicy.CleanupRollback,
		},
	}
	if result.Policy.TemporaryHTTP == nil || *result.Policy.TemporaryHTTP != *want {
		t.Fatalf("temporary HTTP-01 policy = %+v, want %+v", result.Policy.TemporaryHTTP, want)
	}
	if strings.Count(result.Policy.Nftables, `comment "sbxr:acme-http-01"`) != 1 || strings.Contains(result.Policy.Nftables, "tcp dport { 80,") {
		t.Fatalf("temporary rule is not exact and separately removable: %s", result.Policy.Nftables)
	}
}

func TestEvaluateTypedDNSAndCAAForHTTP01(t *testing.T) {
	intent := completeIntent()
	intent.CertificateHostname = "direct.example.com"
	request := networkpolicy.Request{
		Intent: intent,
		Stage:  networkpolicy.PostApproval,
		Certificate: networkpolicy.CertificateFacts{
			DNS: networkpolicy.DNSFacts{
				Hostname: "direct.example.com",
				IPv4:     []string{"192.0.2.10"},
				ChallengeRecords: []networkpolicy.DNSRecord{
					{Name: "_acme-challenge.direct.example.com", Type: networkpolicy.CNAME},
					{Name: "_acme-challenge.direct.example.com", Type: networkpolicy.NS},
					{Name: "_acme-challenge.direct.example.com", Type: networkpolicy.TXT},
					{Name: "CLIENT-ACCESS-VALUE-MUST-NOT-RENDER", Type: networkpolicy.TXT},
				},
			},
			CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true},
		},
	}
	result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(request)
	if result.Outcome != networkpolicy.Healthy || len(result.Findings) != 0 {
		t.Fatalf("unrelated challenge records blocked HTTP-01: %+v", result.Findings)
	}
	if result.Certificate != (networkpolicy.CertificatePolicy{HTTP01ForIPAndDomain: true, CreatesCAA: false, IgnoredChallengeRecords: 4}) {
		t.Fatalf("certificate policy = %+v", result.Certificate)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), "CLIENT-ACCESS-VALUE-MUST-NOT-RENDER") {
		t.Fatal("typed certificate input leaked into the result")
	}
	changed := request
	changed.Certificate.CAA.HTTP01Allowed = false
	if !result.Binding.Stale(changed, completeObservations()) {
		t.Fatal("changed effective CAA did not stale the reviewed result")
	}
	blocked := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(changed)
	assertFinding(t, blocked, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CERTIFICATE-CAA")
}

func TestEvaluateKeepsLocalAndOutsideProofDistinct(t *testing.T) {
	cleanRequest := networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval, Outside: networkpolicy.OutsideFacts{Direct: []networkpolicy.OutsideProof{{Purpose: "VLESS REALITY Vision", Address: "192.0.2.10", Port: 443, Protocol: networkpolicy.TCP, Status: networkpolicy.ProofPassed}}}}
	clean := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(cleanRequest)
	assertReachability(t, clean, "VLESS REALITY Vision", networkpolicy.ProofPending, networkpolicy.ProofPending)
	assertReachability(t, clean, "VLESS XHTTP", networkpolicy.ProofPending, networkpolicy.ProofPending)

	intent, observed := managedBaseline()
	request := networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval}
	result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(request)
	assertReachability(t, result, "VLESS REALITY Vision", networkpolicy.ProofPassed, networkpolicy.ProofPending)
	assertReachability(t, result, "Hysteria2", networkpolicy.ProofPassed, networkpolicy.ProofPending)
	assertReachability(t, result, "VLESS XHTTP", networkpolicy.ProofPassed, networkpolicy.ProofPassed)
	assertReachability(t, result, "VLESS WebSocket", networkpolicy.ProofPassed, networkpolicy.ProofPassed)
	if result.SameVPSProvesOutside {
		t.Fatal("same-VPS proof was promoted to outside success")
	}

	for _, change := range []func(*networkpolicy.LocalProof){
		func(proof *networkpolicy.LocalProof) { proof.RouteMatches = false },
		func(proof *networkpolicy.LocalProof) { proof.ConfigurationMatches = false },
	} {
		changedIntent, changedObserved := managedBaseline()
		change(&changedObserved.LocalProofs[0])
		changed := networkpolicy.New(staticAdapter{observed: changedObserved}).Evaluate(networkpolicy.Request{Intent: changedIntent, Stage: networkpolicy.PostApproval})
		assertReachability(t, changed, "VLESS REALITY Vision", networkpolicy.ProofPending, networkpolicy.ProofPending)
	}

	request.Outside.Direct = []networkpolicy.OutsideProof{{Purpose: "VLESS REALITY Vision", Address: "192.0.2.10", Port: 443, Protocol: networkpolicy.TCP, Status: networkpolicy.ProofFailed}}
	result = networkpolicy.New(staticAdapter{observed: observed}).Evaluate(request)
	assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Advisory, "NETWORK-OUTSIDE-REACHABILITY")
	if len(result.ProviderGuidance) != 1 {
		t.Fatalf("provider guidance = %+v", result.ProviderGuidance)
	}
	guidance := result.ProviderGuidance[0]
	if guidance.Address != "192.0.2.10" || guidance.Port != 443 || guidance.Protocol != networkpolicy.TCP || guidance.Action != "Run Live Profile Check again" || len(guidance.RequiredPorts) != 6 || !strings.Contains(guidance.Guidance, "firewall") || !strings.Contains(guidance.Guidance, "security group") || !strings.Contains(guidance.Guidance, "network ACL") || !strings.Contains(guidance.SSHWarning, "2222/TCP") || !strings.Contains(strings.ToLower(guidance.ReconnectionWarning), "one existing ssh session") || guidance.ProviderChanged {
		t.Fatalf("provider guidance = %+v", guidance)
	}
}

func TestEvaluateBoundsOutboundAndRenewalFreshness(t *testing.T) {
	result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
	wantBounds := networkpolicy.CheckBounds{
		DeterministicAttempts:  1,
		TemporaryAttempts:      3,
		TemporaryWindowSeconds: 60,
		LocalHealthSeconds:     60,
		CloudflareOwner:        "Cloudflare Tunnel",
		ACMEOwner:              "Certificate Lifecycle",
	}
	if result.Bounds != wantBounds || result.Renewal != (networkpolicy.RenewalFreshness{ReevaluateAfterGlobalLockWait: true, RebuildOneUsePlan: true}) {
		t.Fatalf("bounds/freshness = %+v %+v", result.Bounds, result.Renewal)
	}
	if !result.Binding.StaleAfterGlobalLockWait() {
		t.Fatal("a delayed automatic renewal could reuse its pre-wait Plan")
	}

	for _, change := range []func(*networkpolicy.OutboundFacts){
		func(facts *networkpolicy.OutboundFacts) { facts.GitHubAttestationHTTPS = false },
		func(facts *networkpolicy.OutboundFacts) { facts.CertificateEndpointsHTTPS = false },
	} {
		observed := completeObservations()
		change(&observed.Outbound)
		failed := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		if failed.Outcome != networkpolicy.Failed || len(failed.Findings) != 1 || !strings.Contains(failed.Findings[0].CheckAgain, "complete preflight") {
			t.Fatalf("bounded outbound failure = %+v", failed.Findings)
		}
	}
}

func TestEvaluateHTTP01OutsideFailureStaysExternal(t *testing.T) {
	intent := completeIntent()
	intent.TemporaryHTTP = true
	request := networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval, Outside: networkpolicy.OutsideFacts{HTTP01: networkpolicy.ProofFailed}}
	result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(request)
	assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-OUTSIDE-HTTP01")
	assertReachability(t, result, "ACME HTTP-01", networkpolicy.ProofPending, networkpolicy.ProofFailed)
	if len(result.ProviderGuidance) != 1 || result.ProviderGuidance[0].Address != "192.0.2.10" || result.ProviderGuidance[0].Port != 80 || len(result.ProviderGuidance[0].RequiredPorts) != 7 || result.ProviderGuidance[0].ProviderChanged {
		t.Fatalf("HTTP-01 external failure guidance = %+v", result.ProviderGuidance)
	}
}

func assertReachability(t *testing.T, result networkpolicy.Result, purpose string, local, outside networkpolicy.ProofStatus) {
	t.Helper()
	for _, proof := range result.Reachability {
		if proof.Purpose == purpose {
			if proof.Local != local || proof.Outside != outside {
				t.Fatalf("%s proof = %+v, want local %s outside %s", purpose, proof, local, outside)
			}
			return
		}
	}
	t.Fatalf("missing %s proof: %+v", purpose, result.Reachability)
}

func hasGate(gates []networkpolicy.Gate, code string) bool {
	for _, gate := range gates {
		if gate.Code == code {
			return true
		}
	}
	return false
}

func TestEvaluatePublicFamilyQualification(t *testing.T) {
	tests := []struct {
		name        string
		change      func(*networkpolicy.Intent, *networkpolicy.Observations)
		outcome     networkpolicy.Outcome
		ipv4        string
		ipv6        string
		primary     string
		certificate string
	}{
		{name: "IPv4 only", change: func(*networkpolicy.Intent, *networkpolicy.Observations) {}, outcome: networkpolicy.Healthy, ipv4: "192.0.2.10", primary: "192.0.2.10", certificate: "192.0.2.10"},
		{name: "IPv6 only", change: func(i *networkpolicy.Intent, o *networkpolicy.Observations) {
			i.PublicIPv4, o.PublicIPv4 = "", nil
			i.PublicIPv6, i.PrimarySubscriptionAddress = "2001:db8::10", "2001:db8::10"
			o.PublicIPv6 = []string{"2001:db8::10"}
		}, outcome: networkpolicy.Healthy, ipv6: "2001:db8::10", primary: "2001:db8::10", certificate: "2001:db8::10"},
		{name: "dual family with Owner-selected IPv6 primary", change: func(i *networkpolicy.Intent, o *networkpolicy.Observations) {
			i.PublicIPv6, i.PrimarySubscriptionAddress = "2001:db8::10", "2001:db8::10"
			o.PublicIPv6 = []string{"2001:db8::10"}
		}, outcome: networkpolicy.Healthy, ipv4: "192.0.2.10", ipv6: "2001:db8::10", primary: "2001:db8::10", certificate: "2001:db8::10"},
		{name: "failed optional primary family", change: func(i *networkpolicy.Intent, _ *networkpolicy.Observations) {
			i.PublicIPv6, i.PrimarySubscriptionAddress = "2001:db8::10", "2001:db8::10"
		}, outcome: networkpolicy.NeedsAttention, ipv4: "192.0.2.10", primary: "192.0.2.10", certificate: "192.0.2.10"},
		{name: "no qualified family", change: func(_ *networkpolicy.Intent, o *networkpolicy.Observations) {
			o.PublicIPv4 = nil
		}, outcome: networkpolicy.Failed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intent, observed := completeIntent(), completeObservations()
			tt.change(&intent, &observed)
			syncCertificateFacts(intent, &observed)
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
			if result.Outcome != tt.outcome || result.Policy.PublicIPv4 != tt.ipv4 || result.Policy.PublicIPv6 != tt.ipv6 || result.Policy.PrimaryAddress != tt.primary || result.Policy.CertificateAddress != tt.certificate {
				t.Fatalf("Evaluate() = outcome %q policy %+v, want %q IPv4 %q IPv6 %q primary %q certificate %q", result.Outcome, result.Policy, tt.outcome, tt.ipv4, tt.ipv6, tt.primary, tt.certificate)
			}
			if tt.name == "no qualified family" && len(result.Policy.Exposures) != 0 {
				t.Fatalf("unqualified public policy retained exposures: %+v", result.Policy.Exposures)
			}
			if tt.ipv4 != "" && !strings.Contains(result.Policy.Nftables, "ip daddr "+tt.ipv4) || tt.ipv6 != "" && !strings.Contains(result.Policy.Nftables, "ip6 daddr "+tt.ipv6) {
				t.Fatalf("candidate omitted qualified family: %q", result.Policy.Nftables)
			}
		})
	}

	t.Run("later family addition or removal invalidates the reviewed Change Set", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		request := networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(request)
		request.Intent.Revision++
		request.Intent.PublicIPv6 = "2001:db8::10"
		if !result.Binding.Stale(request, observed) {
			t.Fatal("family addition did not require a new revision-bound Change Set")
		}

		observed.PublicIPv6 = []string{"2001:db8::10"}
		result = networkpolicy.New(staticAdapter{observed: observed}).Evaluate(request)
		request.Intent.Revision++
		request.Intent.PublicIPv6 = ""
		if !result.Binding.Stale(request, observed) {
			t.Fatal("family removal did not require a new revision-bound Change Set")
		}
	})
}

func TestEvaluateRefusesIncompleteIntent(t *testing.T) {
	for _, change := range []func(*networkpolicy.Intent){
		func(intent *networkpolicy.Intent) { intent.Revision = 0 },
		func(intent *networkpolicy.Intent) { intent.Baseline = "discovered" },
		func(intent *networkpolicy.Intent) { intent.SSHPort = 0 },
		func(intent *networkpolicy.Intent) {
			intent.PublicIPv4 = `192.0.2.10; flush ruleset`
			intent.PrimarySubscriptionAddress = intent.PublicIPv4
		},
		func(intent *networkpolicy.Intent) { intent.CertificateHostname = "" },
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
			syncCertificateFacts(intent, &observed)
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
			OwnerFacts: networkpolicy.OwnerFacts{DNS: "matches Desired State", Tunnel: "matches Desired State", Routes: cloudflareRoutes()},
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

	t.Run("Clean route conflict identifies the route", func(t *testing.T) {
		observed := completeObservations()
		observed.OwnerFacts.Routes = cloudflareRoutes()[:1]
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CLEAN-ADOPTION-REFUSED")
		if !strings.Contains(result.Findings[0].Found, "VLESS XHTTP") || !strings.Contains(result.Findings[0].Found, "127.0.0.1:11080/TCP") {
			t.Fatalf("route conflict omitted safe route identity: %q", result.Findings[0].Found)
		}
	})

	t.Run("Clean refuses an existing unproved SBXR nftables table", func(t *testing.T) {
		observed := completeObservations()
		observed.Firewall.SBXRTableState = "present"
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-CLEAN-ADOPTION-REFUSED")
	})

	t.Run("disabled profile has no public exposure", func(t *testing.T) {
		for _, tt := range []struct {
			name    string
			purpose string
			disable func(*networkpolicy.Intent)
		}{
			{name: "VLESS REALITY Vision", purpose: "VLESS REALITY Vision", disable: func(i *networkpolicy.Intent) { i.Profiles.VLESSRealityVision.Enabled = false }},
			{name: "VLESS XHTTP", purpose: "VLESS XHTTP origin", disable: func(i *networkpolicy.Intent) { i.Profiles.VLESSXHTTP.Enabled = false }},
			{name: "VLESS WebSocket", purpose: "VLESS WebSocket origin", disable: func(i *networkpolicy.Intent) { i.Profiles.VLESSWebSocket.Enabled = false }},
			{name: "Hysteria2", purpose: "Hysteria2", disable: func(i *networkpolicy.Intent) { i.Profiles.Hysteria2.Enabled = false }},
			{name: "TUIC", purpose: "TUIC", disable: func(i *networkpolicy.Intent) { i.Profiles.TUIC.Enabled = false }},
			{name: "AnyTLS", purpose: "AnyTLS", disable: func(i *networkpolicy.Intent) { i.Profiles.AnyTLS.Enabled = false }},
		} {
			t.Run(tt.name, func(t *testing.T) {
				intent := completeIntent()
				tt.disable(&intent)
				result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
				if result.Outcome != networkpolicy.Healthy {
					t.Fatalf("disabled profile was unhealthy: %+v", result.Findings)
				}
				for _, exposure := range result.Policy.Exposures {
					if exposure.Purpose == tt.purpose {
						t.Fatalf("disabled %s remained exposed", tt.name)
					}
				}
			})
		}
	})

	t.Run("Tunnel origins must stay loopback-only", func(t *testing.T) {
		intent := completeIntent()
		intent.Profiles.VLESSXHTTP.Address = "0.0.0.0"
		result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-ORIGIN-LOOPBACK")
	})
}

func TestEvaluateManagedCloudflareRoutes(t *testing.T) {
	intent, observed := managedBaseline()
	observed.OwnerFacts.Routes = []networkpolicy.CloudflareRoute{
		{Profile: "VLESS XHTTP", OriginAddress: "127.0.0.1", OriginPort: 11080, Protocol: networkpolicy.TCP, Connected: true},
		{Profile: "VLESS WebSocket", OriginAddress: "127.0.0.1", OriginPort: 11081, Protocol: networkpolicy.TCP, Connected: true},
	}
	result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	if result.Outcome != networkpolicy.Healthy {
		t.Fatalf("exact routes were unhealthy: %+v", result.Findings)
	}
	observed.OwnerFacts.Routes[0].Connected = false
	result = networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	assertReachability(t, result, "VLESS XHTTP", networkpolicy.ProofPassed, networkpolicy.ProofPending)
	observed.OwnerFacts.Routes[0].Connected = true

	observed.OwnerFacts.Routes[0].OriginAddress = "0.0.0.0"
	result = networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-MANAGED-DRIFT")
}

func TestEvaluateManagedPublicListenersMatchQualifiedFamilies(t *testing.T) {
	for _, address := range []string{"10.0.0.1", "::"} {
		t.Run(address, func(t *testing.T) {
			intent, observed := managedBaseline()
			observed.Listeners[0].Address = address
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
			assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-MANAGED-DRIFT")
		})
	}

	t.Run("dual family requires both listener families", func(t *testing.T) {
		intent, observed := managedBaseline()
		intent.PublicIPv6 = "2001:db8::10"
		observed.PublicIPv6 = []string{"2001:db8::10"}
		syncCertificateFacts(intent, &observed)
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-MANAGED-DRIFT")
	})
}

func TestEvaluateManagedCommittedPortConflictUsesCorrectionFlow(t *testing.T) {
	intent, observed := managedBaseline()
	intent.Profiles.VLESSRealityVision.Port = 20000
	observed.Listeners[0] = networkpolicy.Listener{Address: "0.0.0.0", Port: 20000, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service", Ownership: networkpolicy.Unproved}
	observed.PortCandidates = []networkpolicy.PortCandidate{{Port: 21000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true}}
	result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
	assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-MANAGED-DRIFT")
	if len(result.Policy.Replacements) != 0 || !strings.Contains(result.Findings[0].Found, "process nginx") || !strings.Contains(result.Findings[0].Found, "service nginx.service") || !strings.Contains(result.Findings[0].Found, "0.0.0.0:20000/TCP") {
		t.Fatalf("committed conflict moved or omitted Correction Flow facts: policy %+v finding %+v", result.Policy, result.Findings[0])
	}
}

func TestEvaluateCorrectiveNetworkPolicy(t *testing.T) {
	t.Run("detected SSH port never moves and identifies an unrelated family holder", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		intent.PublicIPv6 = "2001:db8::10"
		observed.PublicIPv6 = []string{"2001:db8::10"}
		syncCertificateFacts(intent, &observed)
		observed.Listeners = []networkpolicy.Listener{
			{Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP, Process: "sshd", Service: "ssh.service"},
			{Address: "::", Port: 2222, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"},
		}
		observed.PortCandidates = []networkpolicy.PortCandidate{{Port: 20000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true}}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-SSH-PORT-CONFLICT")
		if !strings.Contains(result.Findings[0].Found, "process nginx") || !strings.Contains(result.Findings[0].Found, "service nginx.service") || !strings.Contains(result.Findings[0].Found, ":::2222/TCP") || result.Policy.Exposures[0].Port != 2222 {
			t.Fatalf("SSH conflict moved or omitted exact holder facts: policy %+v finding %+v", result.Policy, result.Findings[0])
		}
	})

	t.Run("current custom or unobservable SSH daemon is not an unrelated holder", func(t *testing.T) {
		for _, listener := range []networkpolicy.Listener{
			{Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP, Process: "dropbear", Service: "dropbear.service"},
			{Address: "0.0.0.0", Port: 2222, Protocol: networkpolicy.TCP},
		} {
			observed := completeObservations()
			observed.Listeners = []networkpolicy.Listener{listener}
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
			if result.Outcome != networkpolicy.Healthy {
				t.Fatalf("current SSH daemon was blocked: listener %+v findings %+v", listener, result.Findings)
			}
		}
	})

	t.Run("committed replacement never moves automatically", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		intent.Profiles.AnyTLS.Port = 20000
		observed.Listeners = []networkpolicy.Listener{{Address: "0.0.0.0", Port: 20000, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"}}
		observed.PortCandidates = []networkpolicy.PortCandidate{{Port: 21000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true}}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-PORT-CONFLICT")
		for _, exposure := range result.Policy.Exposures {
			if exposure.Purpose == "AnyTLS" && exposure.Port != 20000 {
				t.Fatalf("committed AnyTLS port moved to %d", exposure.Port)
			}
		}
	})

	t.Run("private listener still conflicts with a public wildcard bind", func(t *testing.T) {
		observed := completeObservations()
		observed.Listeners = []networkpolicy.Listener{{Address: "10.0.0.1", Port: 443, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"}}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-PORT-CONFLICT")
	})

	t.Run("wildcard listener conflicts with a loopback origin bind", func(t *testing.T) {
		observed := completeObservations()
		observed.Listeners = []networkpolicy.Listener{{Address: "0.0.0.0", Port: 11080, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"}}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: completeIntent(), Stage: networkpolicy.PostApproval})
		assertFinding(t, result, networkpolicy.Failed, networkpolicy.Required, "NETWORK-PORT-CONFLICT")
	})

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
		observed.Listeners = []networkpolicy.Listener{
			{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"},
			{Address: "127.0.0.1", Port: 20001, Protocol: networkpolicy.TCP, Process: "other", Service: "other.service"},
		}
		observed.Ephemeral = networkpolicy.PortRange{First: 32768, Last: 60999}
		observed.PortCandidates = []networkpolicy.PortCandidate{
			{Port: 1000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 2222, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 80, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 40000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 8443, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 20001, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 20002, Protocol: networkpolicy.UDP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 20003, Protocol: networkpolicy.TCP, Address: "127.0.0.1", BindProven: true, Cryptographic: true},
			{Port: 20004, Protocol: networkpolicy.TCP, Address: "public", Cryptographic: true},
			{Port: 20005, Protocol: networkpolicy.TCP, Address: "public", BindProven: true},
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
		wantReplacement := networkpolicy.PortReplacement{
			Purpose: "VLESS REALITY Vision", Address: "public", Protocol: networkpolicy.TCP, PreviousPort: 443, Port: 20000,
			RebuiltArtifacts: [7]networkpolicy.RebuiltArtifact{
				networkpolicy.ServerConfiguration, networkpolicy.SubscriptionRepresentation, networkpolicy.ShareURI, networkpolicy.QRValue, networkpolicy.FirewallRule, networkpolicy.CertificateInput, networkpolicy.ReviewPlan,
			},
		}
		if len(result.Policy.Replacements) != 1 || result.Policy.Replacements[0] != wantReplacement {
			t.Fatalf("replacement = %+v, want %+v", result.Policy.Replacements, wantReplacement)
		}
		finding := result.Findings[0]
		for _, required := range []string{"server configuration", "subscription", "share URI", "QR", "firewall", "certificate", "Plan"} {
			if !strings.Contains(finding.Required, required) {
				t.Fatalf("rebuilt review omitted %q: %+v", required, finding)
			}
		}
		if !strings.Contains(finding.Found, "process nginx") || !strings.Contains(finding.Found, "service nginx.service") || !strings.Contains(finding.Found, "0.0.0.0:443/TCP") {
			t.Fatalf("holder facts are incomplete: %q", finding.Found)
		}
		if finding.Fix.SBXROption == "" || finding.Back == "" {
			t.Fatalf("replacement omitted review or Back: %+v", finding)
		}
		if len(result.PreApplyGates) != 5 || result.PreApplyGates[4].Code != "NETWORK-PORT-STILL-BINDABLE" || !strings.Contains(result.PreApplyGates[4].Required, "public:20000/TCP") {
			t.Fatalf("replacement recheck gate = %+v", result.PreApplyGates)
		}
		observed.Listeners = append(observed.Listeners, networkpolicy.Listener{Address: "0.0.0.0", Port: 20000, Protocol: networkpolicy.TCP, Process: "late-holder", Service: "late.service"})
		if !result.Binding.Stale(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval}, observed) {
			t.Fatal("late candidate conflict did not make the reviewed result stale")
		}
	})

	t.Run("all occupied defaults are rebuilt before review", func(t *testing.T) {
		intent, observed := completeIntent(), completeObservations()
		observed.Listeners = []networkpolicy.Listener{
			{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Process: "nginx", Service: "nginx.service"},
			{Address: "0.0.0.0", Port: 8443, Protocol: networkpolicy.UDP, Process: "other", Service: "other.service"},
		}
		observed.PortCandidates = []networkpolicy.PortCandidate{
			{Port: 20000, Protocol: networkpolicy.TCP, Address: "public", BindProven: true, Cryptographic: true},
			{Port: 20001, Protocol: networkpolicy.UDP, Address: "public", BindProven: true, Cryptographic: true},
		}
		result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		if result.Outcome != networkpolicy.NeedsAttention || len(result.Findings) != 2 || len(result.Policy.Replacements) != 2 || result.Policy.Replacements[0].Purpose != "VLESS REALITY Vision" || result.Policy.Replacements[1].Purpose != "TUIC" || len(result.PreApplyGates) != 6 {
			t.Fatalf("partially rebuilt result: %+v", result)
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
		if result.CertificateRetry == nil || result.CertificateRetry.Owner != "Certificate Lifecycle" || !result.CertificateRetry.KeepCurrentCertificate || result.CertificateRetry.Until != "fresh Network Policy evaluation passes" {
			t.Fatalf("TCP 80 conflict omitted typed certificate retention and retry owner: %+v", result.CertificateRetry)
		}
		if !strings.Contains(result.Findings[0].Found, "process nginx") || !strings.Contains(result.Findings[0].Found, "service nginx.service") {
			t.Fatalf("TCP 80 holder facts are incomplete: %q", result.Findings[0].Found)
		}
	})

	t.Run("temporary TCP 80 appears only when requested", func(t *testing.T) {
		intent := completeIntent()
		intent.TemporaryHTTP = true
		result := networkpolicy.New(staticAdapter{observed: completeObservations()}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
		for _, exposure := range result.Policy.Exposures {
			if exposure.Purpose == "ACME HTTP-01" && exposure.Address == "public" && exposure.Port == 80 && exposure.Protocol == networkpolicy.TCP {
				return
			}
		}
		t.Fatal("requested temporary public 80/TCP exposure missing")
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

func TestEvaluateSelectsReplacementForEveryConfigurableDefault(t *testing.T) {
	tests := []struct {
		purpose  string
		address  string
		port     uint16
		protocol networkpolicy.Protocol
	}{
		{"VLESS REALITY Vision", "public", 443, networkpolicy.TCP},
		{"Hysteria2", "public", 443, networkpolicy.UDP},
		{"TUIC", "public", 8443, networkpolicy.UDP},
		{"AnyTLS", "public", 9443, networkpolicy.TCP},
		{"Subscription HTTPS", "public", 10443, networkpolicy.TCP},
		{"VLESS XHTTP origin", "127.0.0.1", 11080, networkpolicy.TCP},
		{"VLESS WebSocket origin", "127.0.0.1", 11081, networkpolicy.TCP},
	}
	for index, tt := range tests {
		t.Run(tt.purpose, func(t *testing.T) {
			intent, observed := completeIntent(), completeObservations()
			foundAddress := tt.address
			if foundAddress == "public" {
				foundAddress = "0.0.0.0"
			}
			observed.Listeners = []networkpolicy.Listener{{Address: foundAddress, Port: tt.port, Protocol: tt.protocol, Process: "holder", Service: "holder.service"}}
			candidatePort := uint16(20000 + index)
			observed.PortCandidates = []networkpolicy.PortCandidate{{Port: candidatePort, Protocol: tt.protocol, Address: tt.address, BindProven: true, Cryptographic: true}}
			result := networkpolicy.New(staticAdapter{observed: observed}).Evaluate(networkpolicy.Request{Intent: intent, Stage: networkpolicy.PostApproval})
			assertFinding(t, result, networkpolicy.NeedsAttention, networkpolicy.Required, "NETWORK-PORT-ALTERNATIVE")
			if len(result.Policy.Replacements) != 1 || result.Policy.Replacements[0].Purpose != tt.purpose || result.Policy.Replacements[0].PreviousPort != tt.port || result.Policy.Replacements[0].Port != candidatePort {
				t.Fatalf("replacement = %+v", result.Policy.Replacements)
			}
		})
	}
}

func managedBaseline() (networkpolicy.Intent, networkpolicy.Observations) {
	intent, observed := completeIntent(), completeObservations()
	intent.Baseline = networkpolicy.Managed
	observed.Lineage = networkpolicy.ProvenLineage
	observed.Firewall.SBXRTableState = "matches Desired State"
	observed.OwnerFacts = networkpolicy.OwnerFacts{DNS: "matches Desired State", Tunnel: "matches Desired State", Routes: cloudflareRoutes()}
	observed.Listeners = []networkpolicy.Listener{
		{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 443, Protocol: networkpolicy.UDP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 8443, Protocol: networkpolicy.UDP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 9443, Protocol: networkpolicy.TCP, Service: "sing-box.service", Ownership: networkpolicy.SBXROwned},
		{Address: "0.0.0.0", Port: 10443, Protocol: networkpolicy.TCP, Service: "sbxr-subscription.service", Ownership: networkpolicy.SBXROwned},
		{Address: "127.0.0.1", Port: 11080, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned},
		{Address: "127.0.0.1", Port: 11081, Protocol: networkpolicy.TCP, Service: "xray.service", Ownership: networkpolicy.SBXROwned},
	}
	observed.LocalProofs = []networkpolicy.LocalProof{
		{Purpose: "VLESS REALITY Vision", Address: "192.0.2.10", Port: 443, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true},
		{Purpose: "Hysteria2", Address: "192.0.2.10", Port: 443, Protocol: networkpolicy.UDP, RouteMatches: true, ConfigurationMatches: true},
		{Purpose: "TUIC", Address: "192.0.2.10", Port: 8443, Protocol: networkpolicy.UDP, RouteMatches: true, ConfigurationMatches: true},
		{Purpose: "AnyTLS", Address: "192.0.2.10", Port: 9443, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true},
		{Purpose: "VLESS XHTTP", Address: "127.0.0.1", Port: 11080, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true},
		{Purpose: "VLESS WebSocket", Address: "127.0.0.1", Port: 11081, Protocol: networkpolicy.TCP, RouteMatches: true, ConfigurationMatches: true},
	}
	return intent, observed
}

func cloudflareRoutes() []networkpolicy.CloudflareRoute {
	return []networkpolicy.CloudflareRoute{
		{Profile: "VLESS XHTTP", OriginAddress: "127.0.0.1", OriginPort: 11080, Protocol: networkpolicy.TCP, Connected: true},
		{Profile: "VLESS WebSocket", OriginAddress: "127.0.0.1", OriginPort: 11081, Protocol: networkpolicy.TCP, Connected: true},
	}
}

func completeIntent() networkpolicy.Intent {
	return networkpolicy.Intent{
		Revision:                   1,
		Baseline:                   networkpolicy.Clean,
		PublicIPv4:                 "192.0.2.10",
		PrimarySubscriptionAddress: "192.0.2.10",
		CertificateHostname:        "direct.example.com",
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
		SSH:        networkpolicy.SSHFacts{DetectedPort: 2222, ServerAddress: "192.0.2.10", CurrentSessions: []string{"session-1"}},
		Firewall:   networkpolicy.FirewallFacts{SBXRTableState: "absent", RootVerified: true},
		Routes:     networkpolicy.RouteFacts{IPv4: "default via 192.0.2.1"},
		Outbound:   networkpolicy.OutboundFacts{DNS: true, GitHubHTTPS: true, GitHubAttestationHTTPS: true, CloudflareHTTPS: true, ACMEHTTPS: true, CertificateEndpointsHTTPS: true, TimeService: true, TunnelTCP7844: true, TunnelUDP7844: true},
		Disk:       networkpolicy.DiskFacts{FilesystemBytes: 20 << 30, AvailableBytes: 3 << 30},
		Time:       networkpolicy.TimeFacts{Synchronized: true, Owner: "systemd-timesyncd"},
		OwnerFacts: networkpolicy.OwnerFacts{DNS: "fresh", Tunnel: "fresh"},
		Certificate: networkpolicy.CertificateFacts{
			DNS: networkpolicy.DNSFacts{Hostname: "direct.example.com", IPv4: []string{"192.0.2.10"}},
			CAA: networkpolicy.CAAFacts{Issuer: "letsencrypt.org", HTTP01Allowed: true},
		},
		Checksums: map[string]string{"sshd_config": "sha256:ssh", "nftables": "sha256:nft"},
	}
}

func syncCertificateFacts(intent networkpolicy.Intent, observed *networkpolicy.Observations) {
	observed.Certificate.DNS.IPv4 = nil
	observed.Certificate.DNS.IPv6 = nil
	for _, address := range observed.PublicIPv4 {
		if address == intent.PublicIPv4 {
			observed.Certificate.DNS.IPv4 = []string{address}
		}
	}
	for _, address := range observed.PublicIPv6 {
		if address == intent.PublicIPv6 {
			observed.Certificate.DNS.IPv6 = []string{address}
		}
	}
}
