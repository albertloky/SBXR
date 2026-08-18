package ownerconsole

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type cloudflareStub struct {
	mu          sync.Mutex
	view        CloudflarePresentation
	responses   map[CloudflareAction]CloudflareResponse
	requests    []CloudflareRequest
	actionDelay time.Duration
}

type certificatesStub struct {
	view     CertificatesPresentation
	reviews  map[CertificateChange]ChangeReview
	requests []CertificateChange
}

func (stub *certificatesStub) ViewCertificates(context.Context) CertificatesPresentation {
	return stub.view
}

func (stub *certificatesStub) ReviewCertificateChange(_ context.Context, change CertificateChange) ChangeReview {
	stub.requests = append(stub.requests, change)
	return stub.reviews[change]
}

func (stub *cloudflareStub) ViewCloudflare(context.Context) CloudflarePresentation { return stub.view }

func (stub *cloudflareStub) ActOnCloudflare(_ context.Context, request CloudflareRequest) CloudflareResponse {
	time.Sleep(stub.actionDelay)
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.requests = append(stub.requests, request)
	return stub.responses[request.Action]
}

func TestRunCloudflareWalkthroughUsesDedicatedBroadUserTokenPathAndMasksByDefault(t *testing.T) {
	walkthrough := completeCloudflareWalkthrough()
	const token = "CLOUDFLARE-INFRASTRUCTURE-SECRET-COMPLETE-TOKEN"
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		t.Run(fmt.Sprintf("%dx%d", size.width, size.height), func(t *testing.T) {
			stub := &cloudflareStub{view: walkthrough, responses: map[CloudflareAction]CloudflareResponse{
				VerifyInitialManagementToken: {Presentation: &CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}},
			}}
			steps := append(cloudflareTraversalSteps(walkthrough, size.width, size.height), token, "\t", "\r", "", "\x03\r")
			got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, size.width, size.height, steps...)
			for _, want := range []string{"https://dash.cloudflare.com/", "My Profile > API Tokens", "Create Token", "selected domain > DNS > Records", "Cloudflare One > Networks > Tunnels & Mesh", "User > API Tokens > Edit", "Cloudflare Tunnel > Edit", "Zone > DNS > Edit", "Zone > Zone >", "All accounts", "All zones", "Do not use a Global API Key", "Do not use an Account API Token", "no expiry", "no client-IP restriction", "I understand; enter the token", "abcd...wxyz", "Ctrl+R Reveal token"} {
				if !strings.Contains(got, want) {
					t.Fatalf("Cloudflare walkthrough omitted %q\n%s", want, got)
				}
			}
			if strings.Contains(got, token) || len(stub.requests) != 1 || stub.requests[0] != (CloudflareRequest{Action: VerifyInitialManagementToken, Token: token, DedicatedBroadPolicyConfirmed: true}) {
				t.Fatalf("Cloudflare token was rendered or did not cross only as masked input: requests=%#v\n%s", stub.requests, got)
			}
		})
	}
}

func completeCloudflareWalkthrough() CloudflarePresentation {
	return ControlledCloudflareWalkthrough()
}

func completeCloudflareCredential() CloudflareCredential {
	return CloudflareCredential{
		Status: CloudflareTokenActive, FirstFour: "abcd", LastFour: "wxyz",
		Account: "selected account", Zone: "example.test",
		LastVerification: "2026-08-09 12:00 UTC",
		Uses:             []string{"one Tunnel", "two hostname routes", "three DNS records", "certificate prerequisites", "managed repair", "Complete removal"},
		Guidance: []string{
			"Open My Profile > API Tokens; Create Token.",
			"Add User API Tokens Edit, Cloudflare Tunnel Edit, DNS Edit, and Zone Read with broad scopes.",
			"Use no expiry and no client-IP restriction.",
		},
		HelpURL: "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
	}
}

func TestRunCloudflareCredentialOffersOnlyTheFiveExactActions(t *testing.T) {
	for _, test := range []struct {
		name, plan  string
		action      int
		request     CloudflareAction
		effects     []string
		wantEffects []string
	}{
		{name: "remove management token", plan: "remove-cloudflare-token", action: 2, request: ReviewManagementTokenRemoval, effects: []string{"Resolve every Tunnel, DNS, certificate, profile, repair, and update dependency", "Mark dependent provider and certificate health Unknown until rechecked"}, wantEffects: []string{"Resolve every Tunnel, DNS, certificate,", "Mark dependent provider and certificate health"}},
		{name: "rotate genuine run token", plan: "rotate-tunnel-run-token", action: 3, request: ReviewTunnelRunTokenRotation, effects: []string{"Verify the candidate through controlled cloudflared restart and both routes", "Keep the old run token as rollback material until durable Complete"}, wantEffects: []string{"Verify the candidate through controlled", "Keep the old run token as rollback material"}},
		{name: "rotate management token", plan: "rotate-management-token", action: 4, request: ReviewManagementTokenRotation, effects: []string{"Create and prove one transaction-bound candidate before the irreversible checkpoint", "Revoke and disprove only the old management token"}, wantEffects: []string{"Create and prove one transaction-bound", "Revoke and disprove only the old"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			review := completePlan(PlanIdentity(test.plan))
			review.Plan.Effects = test.effects
			presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
			stub := &cloudflareStub{view: presentation, responses: map[CloudflareAction]CloudflareResponse{test.request: {Review: &review}}}
			outcomes := &outcomeStub{}
			steps := append(cloudflareTraversalSteps(presentation, 120, 36), strings.Repeat("\x1b[B", test.action)+"\r", "", "\x03\r")
			got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub, CloudflareOutcomes: outcomes}, 120, 36, steps...)
			for _, want := range []string{"Check now", "Replace token", "Remove from SBXR", "Rotate genuine Tunnel run token", "Rotate management token", test.plan} {
				if !strings.Contains(got, want) {
					t.Fatalf("credential journey omitted %q\n%s", want, got)
				}
			}
			if strings.Contains(got, "My Profile > API Tokens") {
				t.Fatalf("credential journey rendered stale user-token guidance\n%s", got)
			}
			if strings.Contains(got, "revoke only that") || strings.Contains(got, "Select Rotate token") {
				t.Fatalf("credential journey rendered a post-approval provider act before Plan review\n%s", got)
			}
			for _, effect := range test.wantEffects {
				if !strings.Contains(got, effect) {
					t.Fatalf("credential Plan omitted exact effect %q\n%s", effect, got)
				}
			}
			if len(stub.requests) != 1 || stub.requests[0] != (CloudflareRequest{Action: test.request}) || len(outcomes.applyPlans) != 0 {
				t.Fatalf("credential action did not stop at its separate review: requests=%#v applies=%#v", stub.requests, outcomes.applyPlans)
			}
		})
	}
}

func TestRunCloudflareReplacementKeepsTheOldTokenUntilCandidateReview(t *testing.T) {
	review := completePlan("replace-cloudflare-token")
	presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	stub := &cloudflareStub{view: presentation, responses: map[CloudflareAction]CloudflareResponse{VerifyReplacementManagementToken: {Review: &review}}}
	outcomes := &outcomeStub{}
	const candidate = "CANDIDATE-INFRASTRUCTURE-SECRET-COMPLETE-TOKEN"
	steps := append(cloudflareTraversalSteps(presentation, 120, 36), "\x1b[B\r", "")
	steps = append(steps, cloudflareReplacingTraversalSteps(presentation, 120, 36)...)
	steps = append(steps, candidate, "\t\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub, CloudflareOutcomes: outcomes}, 120, 36, steps...)
	if strings.Contains(got, candidate) || !strings.Contains(got, "Current token stays active") || !strings.Contains(got, "My Profile > API Tokens") || !strings.Contains(got, "User API Tokens Edit") || !strings.Contains(got, "Cloudflare Tunnel") || !strings.Contains(got, "DNS Edit") || !strings.Contains(got, "Zone Read") || !strings.Contains(got, "replace-cloudflare-token") {
		t.Fatalf("replacement did not remain masked, active, and review-first\n%s", got)
	}
	if len(stub.requests) != 1 || stub.requests[0] != (CloudflareRequest{Action: VerifyReplacementManagementToken, Token: candidate, DedicatedBroadPolicyConfirmed: true}) || len(outcomes.applyPlans) != 0 {
		t.Fatalf("replacement bypassed candidate verification or exact review: requests=%#v applies=%#v", stub.requests, outcomes.applyPlans)
	}
}

func TestRunCloudflareReplacementRevealIsFocusedAndRemasks(t *testing.T) {
	review := completePlan("replace-cloudflare-token")
	presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	stub := &cloudflareStub{view: presentation, responses: map[CloudflareAction]CloudflareResponse{VerifyReplacementManagementToken: {Review: &review}}}
	const candidate = "sbxr_MANAGED-SECRET-MARKER-012345678901234567890"
	steps := append(cloudflareTraversalSteps(presentation, 120, 36), "\x1b[B\r", "")
	steps = append(steps, cloudflareReplacingTraversalSteps(presentation, 120, 36)...)
	steps = append(steps, candidate, "\x12", "", "\t", "", "\x1b[Z", "\t\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub, CloudflareOutcomes: &outcomeStub{}}, 120, 36, steps...)
	if len(stub.requests) != 1 || stub.requests[0] != (CloudflareRequest{Action: VerifyReplacementManagementToken, Token: candidate, DedicatedBroadPolicyConfirmed: true}) {
		t.Fatalf("managed replacement request = %#v", stub.requests)
	}
	for _, want := range []string{"sbxr_MANAGED-SECRET-MARKER-01234567890123456789", "TOKEN REVEALED", "Mask ", "Ctrl+R Reveal token", "replace-cloudflare-token"} {
		if !strings.Contains(got, want) {
			t.Fatalf("managed Reveal omitted %q\n%s", want, got)
		}
	}
	if revealed := cloudflareLines(CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}, true, candidate, 0, true, true); !strings.Contains(strings.Join(revealed, "\n"), candidate) {
		t.Fatal("controlled Reveal frame omitted the complete token")
	}
	if lastSecret, remasked := strings.LastIndex(got, "sbxr_MANAGED-SECRET-MARKER"), strings.LastIndex(got, "Ctrl+R Reveal token"); remasked < lastSecret {
		t.Fatalf("managed focus loss did not remask\n%s", got)
	}
}

func TestRunCloudflareCheckNowRefreshesWithoutAcceptingALateResultOnAnotherVisit(t *testing.T) {
	checked := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	checked.Credential.Account = "fresh checked account"
	presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	stub := &cloudflareStub{view: presentation, responses: map[CloudflareAction]CloudflareResponse{CheckCurrentManagementToken: {Presentation: &checked}}}
	steps := append(cloudflareTraversalSteps(presentation, 120, 36), "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, steps...)
	if len(stub.requests) != 1 || stub.requests[0].Action != CheckCurrentManagementToken || !strings.Contains(got, "fresh checked account") {
		t.Fatalf("Check now did not refresh through the typed Module result: requests=%#v\n%s", stub.requests, got)
	}

	late := checked
	late.Credential.Account = "LATE-CLOUDFLARE-RESULT"
	stub = &cloudflareStub{view: CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}, responses: map[CloudflareAction]CloudflareResponse{CheckCurrentManagementToken: {Presentation: &late}}, actionDelay: 150 * time.Millisecond}
	got = runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, "", "\r", "\x1b[27u", strings.Repeat("\x1b[B", 3)+"\r", "", "", "", "\x03\r")
	if strings.Contains(got, "LATE-CLOUDFLARE-RESULT") {
		t.Fatalf("late Cloudflare result changed a newer visit\n%s", got)
	}

	stub = &cloudflareStub{view: CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}, responses: map[CloudflareAction]CloudflareResponse{CheckCurrentManagementToken: {Presentation: &late}}, actionDelay: 150 * time.Millisecond}
	const candidate = "FOCUS-SAFE-CANDIDATE-TOKEN"
	got = runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, "", "\r", "\x1b[27u", strings.Repeat("\x1b[B", 3)+"\r", "", "\x1b[B\r", candidate, "", "\x1b[27u", "", "\x03\r")
	if strings.Contains(got, "LATE-CLOUDFLARE-RESULT") || strings.Contains(got, candidate) || !strings.Contains(got, "Token active") {
		t.Fatalf("late Check now stole replacement focus or Esc skipped Back\n%s", got)
	}
}

func TestRunCloudflareActionsShowWaitingStateAndQueueExitResult(t *testing.T) {
	checked := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	checked.Credential.Account = "CLOUDFLARE-WAIT-COMPLETE"
	pending := CloudflarePresentation{Kind: CloudflarePendingZonePresentation, PendingZone: CloudflarePendingZone{
		Zone: "example.test", AssignedNameServers: []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"},
		RegistrarSteps: []string{"Keep both assigned nameservers at the registrar"}, Evidence: "CLOUDFLARE-ZONE-WAIT-COMPLETE", HelpURL: "https://developers.cloudflare.com/dns/nameservers/update-nameservers/",
	}}
	for _, test := range []struct {
		name         string
		presentation CloudflarePresentation
		action       CloudflareAction
		start        []string
		response     CloudflarePresentation
		label        string
		delay        time.Duration
	}{
		{name: "Check now", presentation: CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}, action: CheckCurrentManagementToken, start: []string{"\r"}, response: checked, label: "Check now", delay: 1100 * time.Millisecond},
		{name: "Verify token", presentation: completeCloudflareWalkthrough(), action: VerifyInitialManagementToken, start: []string{"WAITING-TOKEN", "\t\r"}, response: checked, label: "I understand; enter the token", delay: 180 * time.Millisecond},
		{name: "Wait another 10 minutes", presentation: pending, action: WaitAnotherTenMinutes, start: []string{"\x1b[B\r"}, response: pending, label: "Wait another 10 minutes", delay: 180 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &cloudflareStub{view: test.presentation, responses: map[CloudflareAction]CloudflareResponse{test.action: {Presentation: &test.response}}, actionDelay: test.delay}
			steps := append(cloudflareTraversalSteps(test.presentation, 120, 36), test.start...)
			steps = append(steps, "", "\r")
			for elapsed := time.Duration(0); elapsed <= test.delay+100*time.Millisecond; elapsed += 60 * time.Millisecond {
				steps = append(steps, "")
			}
			steps = append(steps, "\x03\r")
			got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, steps...)
			if !strings.Contains(got, test.label+" is running") || !strings.Contains(got, "No percentage, completion time, or result is") || len(stub.requests) != 1 {
				t.Fatalf("%s lacked one guarded waiting state: requests=%#v\n%s", test.name, stub.requests, got)
			}
			if test.delay > time.Second && (!strings.Contains(got, "00:00") || !strings.Contains(got, "00:01")) {
				t.Fatalf("%s did not show monotonic elapsed time\n%s", test.name, got)
			}
		})
	}

	presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	stub := &cloudflareStub{view: presentation, responses: map[CloudflareAction]CloudflareResponse{CheckCurrentManagementToken: {Presentation: &checked}}, actionDelay: 100 * time.Millisecond}
	steps := append(cloudflareTraversalSteps(presentation, 120, 36), "\r", "\x03", "", "", "\x1b[27u", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, steps...)
	exit, result := strings.Index(got, "Exit SBXR?"), strings.Index(got, "CLOUDFLARE-WAIT-COMPLETE")
	if exit < 0 || result < exit {
		t.Fatalf("completed Cloudflare result did not wait behind Exit confirmation\n%s", got)
	}

	stub = &cloudflareStub{view: CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}, responses: map[CloudflareAction]CloudflareResponse{CheckCurrentManagementToken: {Presentation: &checked}}, actionDelay: 150 * time.Millisecond}
	got = runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, "", "\r", "\x1b[27u", "", "", "\x03\r")
	if strings.Contains(got, "CLOUDFLARE-WAIT-COMPLETE") || !strings.Contains(got, "OVERVIEW") {
		t.Fatalf("Back did not cancel and ignore the pending Cloudflare presentation\n%s", got)
	}

	const abandonedToken = "ABANDONED-CLOUDFLARE-INFRASTRUCTURE-SECRET-TOKEN"
	walkthrough := completeCloudflareWalkthrough()
	stub = &cloudflareStub{view: walkthrough, responses: map[CloudflareAction]CloudflareResponse{VerifyInitialManagementToken: {Presentation: &checked}}, actionDelay: 150 * time.Millisecond}
	steps = append(cloudflareTraversalSteps(walkthrough, 120, 36), abandonedToken, "\t\r", "\x1b[27u", "", "", strings.Repeat("\x1b[B", 10)+"\r", "", "\x03\r")
	got = runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, steps...)
	if strings.Contains(got, abandonedToken) || !strings.Contains(got, "COMPLETE REMOVAL") {
		t.Fatalf("Back retained an abandoned Cloudflare token in another input screen\n%s", got)
	}

	const refusedToken = "REFUSED-CLOUDFLARE-INFRASTRUCTURE-SECRET-TOKEN"
	stub = &cloudflareStub{view: walkthrough, responses: map[CloudflareAction]CloudflareResponse{VerifyInitialManagementToken: {}}, actionDelay: 50 * time.Millisecond}
	steps = append(cloudflareTraversalSteps(walkthrough, 120, 36), refusedToken, "\t\r", "", "", "\x1b[27u", strings.Repeat("\x1b[B", 10)+"\r", "", "\x03\r")
	got = runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 120, 36, steps...)
	if strings.Contains(got, refusedToken) || !strings.Contains(got, "Cloudflare facts are unavailable") || !strings.Contains(got, "COMPLETE REMOVAL") {
		t.Fatalf("an invalid verification result retained its Cloudflare token\n%s", got)
	}
}

func TestRunCloudflareRemovalRefusesWhileDependentsRemain(t *testing.T) {
	refusal := ChangeReview{Correction: &CorrectionPresentation{
		Problem:    "Management token removal is blocked by dependent managed facts",
		Found:      "one Tunnel, two DNS records, two certificate lineages, and six Connection Profiles still depend on Cloudflare management",
		Required:   "resolve every Tunnel, DNS, certificate, and profile dependency in one reviewed outcome",
		WhyStopped: "removal cannot leave dependent facts falsely Managed or Healthy",
		OwnerSteps: []string{"Keep the management token, or review an outcome that consistently resolves every named dependency"},
		Selections: []CorrectionSelection{{Identity: "dependencies-resolved", Label: "Every named dependency is now resolved"}},
		Evidence:   "CLOUDFLARE-TOKEN-REMOVAL-DEPENDENCIES redacted",
	}}
	stub := &cloudflareStub{view: CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}, responses: map[CloudflareAction]CloudflareResponse{ReviewManagementTokenRemoval: {Review: &refusal}}}
	presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
	steps := append(cloudflareTraversalSteps(presentation, 80, 24), "\x1b[B\x1b[B\r", "", "\r", "", "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub, CloudflareOutcomes: &outcomeStub{}}, 80, 24, steps...)
	for _, want := range []string{"removal is blocked", "one Tunnel, two DNS records", "certificate", "Connection Profiles", "falsely Managed or Healthy", "Check again", "Back"} {
		if !strings.Contains(got, want) {
			t.Fatalf("removal refusal omitted %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "PLAN REVIEW") {
		t.Fatalf("dependent token removal was presented as an applicable Plan\n%s", got)
	}
}

func TestRunCloudflareMissingPermissionAndPendingZoneHaveExactCorrectionActions(t *testing.T) {
	t.Run("missing permission", func(t *testing.T) {
		missing := CloudflarePresentation{Kind: CloudflareMissingPermissionPresentation, MissingPermission: CloudflareMissingPermission{
			Capability: "Dedicated Broad Cloudflare User API Token authority", Account: "selected account", Zone: "selected zone",
			Found: "selected-account Tunnel read is unproved", Required: "Cloudflare Tunnel Edit for all accounts",
			WhyStopped: "SBXR cannot prove its selected account read", Evidence: "CLOUDFLARE-PERMISSION-REDACTED",
			DashboardSteps: []string{"Open My Profile > API Tokens; Create Token.", "Add User API Tokens Edit, Cloudflare Tunnel Edit, DNS Edit, and Zone Read with all-account and all-zone resources."},
			HelpURL:        "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
		}}
		review := completePlan("verify-cloudflare-replacement")
		stub := &cloudflareStub{view: missing, responses: map[CloudflareAction]CloudflareResponse{VerifyReplacementManagementToken: {Review: &review}}}
		const candidate = "REPLACEMENT-INFRASTRUCTURE-SECRET-COMPLETE-TOKEN"
		steps := append(cloudflareTraversalSteps(missing, 80, 24), "\t\x1b[B\r", "\r", candidate, "\t\r", "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub, CloudflareOutcomes: &outcomeStub{}}, 80, 24, steps...)
		for _, want := range []string{"Problem", "Cloudflare Tunnel Edit", "selected account", "selected zone", "My Profile > API Tokens", "User API Tokens Edit", "DNS", "Edit, and Zone Read", "developers.cloudflare.com/fundamentals/api/get-sta", "token again", "placement token", "Verify replacement", "Back"} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing-permission flow omitted %q\n%s", want, got)
			}
		}
		if strings.Contains(got, candidate) || len(stub.requests) != 1 || stub.requests[0].Action != VerifyReplacementManagementToken || stub.requests[0].Token != candidate {
			t.Fatalf("missing-permission replacement was exposed or misrouted: requests=%#v\n%s", stub.requests, got)
		}
	})

	t.Run("pending zone", func(t *testing.T) {
		pending := CloudflarePresentation{Kind: CloudflarePendingZonePresentation, PendingZone: CloudflarePendingZone{
			Zone: "example.test", AssignedNameServers: []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"},
			ObservedNameServers: []string{"old-a.example.net", "old-b.example.net"},
			RegistrarSteps:      []string{"In Cloudflare, select the domain; open domain Overview; copy both assigned Cloudflare nameservers exactly.", "At the registrar or reseller that controls the domain, remove every old authoritative nameserver and add exactly both assigned Cloudflare nameservers.", "Do not use a guessed registrar URL; use that provider's nameserver controls. Wait for public delegation, then select Check again in SBXR."},
			Evidence:            "CLOUDFLARE-ZONE-PENDING", HelpURL: "https://developers.cloudflare.com/dns/nameservers/update-nameservers/",
		}}
		checked := pending
		stub := &cloudflareStub{view: pending, responses: map[CloudflareAction]CloudflareResponse{WaitAnotherTenMinutes: {Presentation: &checked}}}
		steps := append(cloudflareTraversalSteps(pending, 80, 24), "\x1b[B\r", "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub}, 80, 24, steps...)
		for _, want := range []string{"alice.ns.cloudflare.com", "old-a.example.net", "domain", "Overview", "registrar or reseller", "guessed registrar URL", "developers.cloudflare.com/dns/nameservers/update-n", "Check again", "Wait another 10 minutes", "Back and continue later"} {
			if !strings.Contains(got, want) {
				t.Fatalf("pending-zone flow omitted %q\n%s", want, got)
			}
		}
		if len(stub.requests) != 1 || stub.requests[0].Action != WaitAnotherTenMinutes {
			t.Fatalf("pending-zone wait was not a typed Module action: %#v", stub.requests)
		}
	})
}

func TestRunCertificatesShowsBothLineagesAndReviewsIssuanceOrRenewal(t *testing.T) {
	for _, test := range []struct {
		name       string
		present    bool
		selected   int
		change     CertificateChange
		plan       string
		wantAction string
	}{
		{name: "IP issuance", change: IssueIPCertificate, plan: "issue-ip-certificate", wantAction: "Review IP certificate issuance"},
		{name: "Direct TLS issuance", selected: 1, change: IssueDirectTLSCertificate, plan: "issue-domain-certificate", wantAction: "Review Direct TLS certificate issuance"},
		{name: "IP renewal", present: true, change: RenewIPCertificate, plan: "renew-ip-certificate", wantAction: "Review IP certificate renewal"},
		{name: "Direct TLS renewal", present: true, selected: 1, change: RenewDirectTLSCertificate, plan: "renew-domain-certificate", wantAction: "Review Direct TLS certificate renewal"},
	} {
		t.Run(test.name, func(t *testing.T) {
			presentation := completeCertificatesPresentation(test.present)
			review := completePlan(PlanIdentity(test.plan))
			stub := &certificatesStub{view: presentation, reviews: map[CertificateChange]ChangeReview{test.change: review}}
			got := runTranscriptSteps(t, Session{Scenario: CertificatesScreen, Certificates: stub, CertificateOutcomes: &outcomeStub{}}, 120, 36, "", strings.Repeat("\x1b[B", test.selected)+"\r", "", "\x03\r")
			for _, want := range []string{"IP certificate - 203.0.113.10 - shortlived", "IP renewal due", "72 hours or less", "Direct TLS certificate - direct.example.test -", "tlsserver -", "ACME Renewal", "Information, fallback 15 days", "sbxr-cert-renew.service", "sbxr-cert-renew.timer", "serial - persistent - randomized - 2 runs/day", "Standing Certificate Renewal Policy - global", "mutation lock per due Change Set", "IP failure retry 6 hours", "busy lock 1 hour", "15 minutes below 24 hours", "Certificate Lifecycle receives no Cloudflare", "No Cloudflare DNS-01 or CAA creation", test.wantAction, test.plan} {
				if !strings.Contains(got, want) {
					t.Fatalf("certificate journey omitted %q\n%s", want, got)
				}
			}
			if len(stub.requests) != 1 || stub.requests[0] != test.change {
				t.Fatalf("certificate action request = %#v", stub.requests)
			}
			if test.present && !strings.Contains(got, "Last typed outcome ACTIVATED") {
				t.Fatalf("certificate activation outcome was omitted\n%s", got)
			}
		})
	}
}

func TestRunCertificateCorrectionAndTypedRollbackRemainSecretSafe(t *testing.T) {
	presentation := completeCertificatesPresentation(true)
	presentation.LastOutcome = CertificateRolledBack
	correction := ChangeReview{Correction: &CorrectionPresentation{
		Problem: "TCP 80 is occupied", Found: "nginx.service owns 0.0.0.0:80/TCP", Required: "exclusive temporary TCP 80 for ACME HTTP-01", WhyStopped: "SBXR never stops an unrelated listener",
		OwnerSteps: []string{"Stop or reconfigure nginx.service outside SBXR"}, Selections: []CorrectionSelection{{Identity: "tcp-80-available", Label: "TCP 80 is now available"}}, Evidence: "CERTIFICATE-HTTP01-PORT redacted",
	}}
	stub := &certificatesStub{view: presentation, reviews: map[CertificateChange]ChangeReview{RenewIPCertificate: correction}}
	steps := append(certificateTraversalSteps(presentation, 80, 24), "\r", "", "\r", "", "\x03\r")
	got := runTranscriptSteps(t, Session{Scenario: CertificatesScreen, Certificates: stub, CertificateOutcomes: &outcomeStub{}}, 80, 24, steps...)
	for _, want := range []string{"Last typed outcome ROLLED BACK", "TCP 80 is occupied", "nginx.service", "ACME HTTP-01", "Check again", "Back", "Copy redacted evidence"} {
		if !strings.Contains(got, want) {
			t.Fatalf("certificate correction omitted %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("certificate private key marker rendered\n%s", got)
	}
}

func TestRunProviderPlansBackRestoreTheirOriginAndUnsafeFactsNeverRender(t *testing.T) {
	t.Run("Cloudflare Back", func(t *testing.T) {
		review := completePlan("cloudflare-back")
		presentation := CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: completeCloudflareCredential()}
		stub := &cloudflareStub{view: presentation, responses: map[CloudflareAction]CloudflareResponse{ReviewTunnelRunTokenRotation: {Review: &review}}}
		outcomes := &outcomeStub{}
		steps := append(cloudflareTraversalSteps(presentation, 120, 36), strings.Repeat("\x1b[B", 3)+"\r", "", "\x1b[27u", "", "\x03\r")
		got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: stub, CloudflareOutcomes: outcomes}, 120, 36, steps...)
		plan := strings.Index(got, "cloudflare-back")
		if outcomes.backCalls != 1 || plan < 0 || !strings.Contains(got[plan:], "Rotate genuine Tunnel run token") {
			t.Fatalf("Plan Back did not restore Cloudflare safely: back=%d\n%s", outcomes.backCalls, got)
		}
	})

	t.Run("Certificate Back", func(t *testing.T) {
		review := completePlan("certificate-back")
		stub := &certificatesStub{view: completeCertificatesPresentation(true), reviews: map[CertificateChange]ChangeReview{RenewIPCertificate: review}}
		outcomes := &outcomeStub{}
		got := runTranscriptSteps(t, Session{Scenario: CertificatesScreen, Certificates: stub, CertificateOutcomes: outcomes}, 120, 36, "", "\r", "", "\x1b[27u", "", "\x03\r")
		plan := strings.Index(got, "certificate-back")
		if outcomes.backCalls != 1 || plan < 0 || !strings.Contains(got[plan:], "IP certificate") {
			t.Fatalf("Plan Back did not restore Certificates safely: back=%d\n%s", outcomes.backCalls, got)
		}
	})

	t.Run("Infrastructure Secret markers", func(t *testing.T) {
		cloudflare := completeCloudflareCredential()
		cloudflare.Account = "INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN"
		cloudflareOutput := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: &cloudflareStub{view: CloudflarePresentation{Kind: CloudflareCredentialPresentation, Credential: cloudflare}}}, 80, 24, "", "\x03\r")
		certificates := completeCertificatesPresentation(true)
		certificates.DirectTLS.ActiveServingID = "INFRASTRUCTURE-SECRET-MARKER-COMPLETE-PRIVATE-KEY"
		certificateOutput := runTranscriptSteps(t, Session{Scenario: CertificatesScreen, Certificates: &certificatesStub{view: certificates}}, 80, 24, "", "\x03\r")
		for name, test := range map[string]struct{ output, unavailable string }{"Cloudflare": {cloudflareOutput, "Cloudflare facts are unavailable"}, "Certificates": {certificateOutput, "Certificate facts are unavailable"}} {
			if strings.Contains(test.output, "INFRASTRUCTURE-SECRET-MARKER") || !strings.Contains(test.output, test.unavailable) {
				t.Fatalf("%s unsafe facts crossed Run\n%s", name, test.output)
			}
		}
	})

	t.Run("unsafe walkthrough authority", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			mutate func(*CloudflareWalkthroughFacts)
		}{
			{name: "Global API Key", mutate: func(facts *CloudflareWalkthroughFacts) { facts.RejectsGlobalAPIKey = false }},
			{name: "Account API Token", mutate: func(facts *CloudflareWalkthroughFacts) { facts.RejectsAccountAPIToken = false }},
			{name: "broad authority", mutate: func(facts *CloudflareWalkthroughFacts) { facts.RequiresBroadAuthority = false }},
			{name: "changed dashboard path", mutate: func(facts *CloudflareWalkthroughFacts) { facts.TunnelsPage = "Workers & Pages" }},
		} {
			t.Run(test.name, func(t *testing.T) {
				unsafe := completeCloudflareWalkthrough()
				test.mutate(&unsafe.Walkthrough)
				got := runTranscriptSteps(t, Session{Scenario: CloudflareWalkthrough, Cloudflare: &cloudflareStub{view: unsafe}}, 80, 24, "", "\x03\r")
				if !strings.Contains(got, "Cloudflare facts are unavailable") || strings.Contains(got, "Workers & Pages") {
					t.Fatalf("unsafe %s walkthrough crossed Run\n%s", test.name, got)
				}
			})
		}
	})

	t.Run("contradictory certificate dates", func(t *testing.T) {
		for _, presentation := range []CertificatesPresentation{completeCertificatesPresentation(false), completeCertificatesPresentation(true)} {
			if presentation.IP.Status == CertificateMissing {
				presentation.IP.NotAfter = "2026-08-15 12:00 UTC"
			} else {
				presentation.IP.NotAfter = ""
			}
			got := runTranscriptSteps(t, Session{Scenario: CertificatesScreen, Certificates: &certificatesStub{view: presentation}}, 80, 24, "", "\x03\r")
			if !strings.Contains(got, "Certificate facts are unavailable") || strings.Contains(got, "2026-08-15") {
				t.Fatalf("contradictory certificate expiry crossed Run\n%s", got)
			}
		}
	})
}

func completeCertificatesPresentation(present bool) CertificatesPresentation {
	status := CertificateMissing
	serving := ""
	ipExpiry, domainExpiry := "", ""
	if present {
		status = CertificateHealthy
		serving = "serving-pair-7"
		ipExpiry, domainExpiry = "2026-08-15 12:00 UTC", "2026-09-15 12:00 UTC"
	}
	lastOutcome := NoCertificateOutcome
	if present {
		lastOutcome = CertificateActivated
	}
	return CertificatesPresentation{
		IP:        CertificateLineage{Status: status, Identity: "203.0.113.10", Profile: "shortlived", NotAfter: ipExpiry, Due: present, ActiveServingID: serving},
		DirectTLS: CertificateLineage{Status: status, Identity: "direct.example.test", Profile: "tlsserver", NotAfter: domainExpiry, Due: present, ActiveServingID: serving},
		Scheduler: CertificateScheduler{
			Service: "sbxr-cert-renew.service", Timer: "sbxr-cert-renew.timer", Enabled: true, Persistent: true, Serial: true, Randomized: true, ExactUnitPair: true, NoCompetingScheduler: true, RunsPerDay: 2,
			Policy: CertificateRenewalPolicy{Approved: true, IPDueWithin: 72 * time.Hour, IPFailureRetry: 6 * time.Hour, BusyLockRetry: time.Hour, UrgentAt: 24 * time.Hour, UrgentBusyLockRetry: 15 * time.Minute, DomainUsesARI: true, DomainFallbackAfter: 15 * 24 * time.Hour},
		},
		LastOutcome: lastOutcome,
	}
}

func cloudflareTraversalSteps(presentation CloudflarePresentation, width, height int) []string {
	actions := cloudflareActions(presentation.Kind, false)
	lines := cloudflareLines(presentation, true, "", 0, false, false)
	return sectionTraversalSteps(providerPageCount(lines, len(actions), width, height))
}

func cloudflareReplacingTraversalSteps(presentation CloudflarePresentation, width, height int) []string {
	actions := cloudflareActions(presentation.Kind, true)
	lines := cloudflareLines(presentation, true, "", 0, true, false)
	return sectionTraversalSteps(providerPageCount(lines, len(actions), width, height))
}

func certificateTraversalSteps(presentation CertificatesPresentation, width, height int) []string {
	actions := certificateActions(presentation)
	lines := certificateLines(presentation, true, 0)
	return sectionTraversalSteps(providerPageCount(lines, len(actions), width, height))
}

func sectionTraversalSteps(pageCount int) []string {
	steps := make([]string, 0, pageCount)
	for page := 1; page < pageCount; page++ {
		steps = append(steps, "\r", "")
	}
	return steps
}
