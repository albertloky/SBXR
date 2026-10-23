package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

// Independent observations for the two-node profile, not validator-derived checks.
var vmessObservedChecks = map[string][]string{
	"mvp-install":      strings.Fields("packaged-install reviewed-setup outside-proxy-traffic menu-status-and-lifecycle ssh-access-preserved outside-vless-reality-traffic outside-vmess-websocket-traffic dedicated-connector-running"),
	"mvp-subscription": strings.Fields("outside-authenticated-http exact-vless-reality-and-vmess-websocket-nodes wrong-token-refused private-files-and-logs-protected karing-import fresh-karing-node-latency manual-refresh selected-connection-preserved no-certificate-or-renewal-resources http-exposure-disclosed fresh-karing-vless-node-latency fresh-karing-vmess-node-latency"),
	"mvp-credentials":  strings.Fields("old-established-session-terminated old-proxy-credential-refused replacement-proxy-traffic same-link-refreshed-identity old-link-refused replacement-link-usable proxy-identity-unchanged-by-link-rotation fresh-karing-replacement-latency vless-old-established-session-terminated vmess-old-established-session-terminated vless-old-credential-refused vmess-old-credential-refused vless-replacement-proxy-traffic vmess-replacement-proxy-traffic same-link-refreshed-both-identities rotated-link-refreshed-both-identities both-identities-unchanged-by-link-rotation fresh-karing-vless-replacement-latency fresh-karing-vmess-replacement-latency"),
	"mvp-serving":      strings.Fields("serving-restart-preserves-link current-artifact-after-restart outside-authenticated-http no-certificate-or-renewal-resources proxy-traffic-preserved vless-traffic-preserved vmess-traffic-preserved dedicated-connector-preserved"),
	"mvp-removal":      strings.Fields("restart-preserves-access reviewed-complete-removal owned-resources-absent outside-access-refused unrelated-resources-preserved test-client-and-secret-cleanup ssh-access-preserved restart-preserves-vless-access restart-preserves-vmess-access owned-connector-absent outside-vless-access-refused outside-vmess-access-refused tunnel-prerequisites-preserved"),
}

func TestProxyProfileSelectionRejectsUnknownAndIncompatibleDeclarations(t *testing.T) {
	base := v3QualificationAttempt{
		Schema: "sbxr-v3-qualification-attempt-v3", ProxyProfile: "vless-vmess",
		Support: &v3ReleaseSupport{Contract: softwarelifecycle.SubscriptionUpdateContract, Scope: softwarelifecycle.SubscriptionCleanInstallOnly, Sources: []decisionReleaseIdentity{}},
		Sources: []v3QualificationSource{}, EvidencePolicy: softwarelifecycle.MVPHTTPEvidencePolicy,
		RequiredScenarios: strings.Fields(softwarelifecycle.MVPHTTPScenarios),
	}
	if !validProxyProfile(base) || !validAttemptSupport(base) {
		t.Fatal("current two-node HTTP profile refused")
	}
	for name, change := range map[string]func(*v3QualificationAttempt){
		"unknown":             func(a *v3QualificationAttempt) { a.ProxyProfile = "vless" },
		"v2":                  func(a *v3QualificationAttempt) { a.Schema = "sbxr-v3-qualification-attempt-v2" },
		"no support":          func(a *v3QualificationAttempt) { a.Support = nil },
		"repair":              func(a *v3QualificationAttempt) { a.Support.Scope = softwarelifecycle.SubscriptionCleanInstallRepair },
		"recurring":           func(a *v3QualificationAttempt) { a.Support.Scope = softwarelifecycle.RecurringSubscriptionUpgrade },
		"wrong contract":      func(a *v3QualificationAttempt) { a.Support.Contract = "unknown" },
		"nil support sources": func(a *v3QualificationAttempt) { a.Support.Sources = nil },
		"support source":      func(a *v3QualificationAttempt) { a.Support.Sources = []decisionReleaseIdentity{{}} },
		"HTTPS":               func(a *v3QualificationAttempt) { a.EvidencePolicy = softwarelifecycle.MVPLiveEvidencePolicy },
		"recurring policy":    func(a *v3QualificationAttempt) { a.EvidencePolicy = softwarelifecycle.MVPHTTPRecurringEvidencePolicy },
		"nil sources":         func(a *v3QualificationAttempt) { a.Sources = nil },
		"source":              func(a *v3QualificationAttempt) { a.Sources = []v3QualificationSource{{}} },
		"exception":           func(a *v3QualificationAttempt) { a.OwnerException = softwarelifecycle.LateConfirmationID },
		"review": func(a *v3QualificationAttempt) {
			a.LateConfirmationReview = &softwarelifecycle.LateConfirmationReview{}
		},
		"correction":      func(a *v3QualificationAttempt) { a.Live89CorrectionReview = &live89CorrectionReview{} },
		"automated claim": func(a *v3QualificationAttempt) { a.AutomatedOnlyScenarios = []string{} },
	} {
		t.Run(name, func(t *testing.T) {
			a := base
			support := *base.Support
			a.Support = &support
			change(&a)
			if validProxyProfile(a) || validAttemptSupport(a) || len(ordinaryChecks(a, "mvp-install")) != 0 {
				t.Fatal("incompatible two-node declaration accepted")
			}
		})
	}
	base.ProxyProfile = ""
	for _, id := range strings.Fields(softwarelifecycle.MVPHTTPScenarios) {
		if !slices.Equal(ordinaryChecks(base, id), ordinaryFixtureChecksFor(id, true)) {
			t.Fatalf("omitted profile changed existing VLESS checks: %s", id)
		}
	}
}

func TestVMessHTTPQualificationRequiresBothNodesAndEveryObservation(t *testing.T) {
	binary := buildQualificationDeclarationBinary(t)
	boundary, manifest, evidence := mvpQualificationFixtureForSupport(t, binary, false, true, true, "vless-vmess")
	document := recurringResultFixture(t, boundary, manifest, evidence)
	out, err := runQualificationCommand(binary, document)
	if err != nil || jsonObject(t, out)["outcome"] != "accepted" {
		t.Fatalf("two-node HTTP qualification: %v %s", err, out)
	}
	body := jsonObject(t, out)["records"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(body, "Proxy profile: vless-vmess\n") || strings.Count(body, "\nScenario: ") != 5 {
		t.Fatal("record does not disclose the qualified two-node profile")
	}
	for i, raw := range evidence["scenarios"].([]any) {
		s := raw.(map[string]any)
		for j := range s["evidence"].([]any) {
			v := jsonObject(t, []byte(qualificationDocument(t, evidence)))
			item := v["scenarios"].([]any)[i].(map[string]any)
			checks := item["evidence"].([]any)
			item["evidence"] = append(checks[:j], checks[j+1:]...)
			rebindRecurringEvidence(t, v)
			assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, v), "missing "+s["scenario_id"].(string)+" two-node observation")
		}
		v := jsonObject(t, []byte(qualificationDocument(t, evidence)))
		item := v["scenarios"].([]any)[i].(map[string]any)
		var old []any
		for _, check := range ordinaryFixtureChecksFor(s["scenario_id"].(string), true) {
			old = append(old, map[string]any{"record": map[string]any{"check": check, "observed_at": s["completed_at"], "result": "observed"}, "sha256": ""})
		}
		item["evidence"] = old
		rebindRecurringEvidence(t, v)
		assertQualificationRefused(t, binary, recurringResultFixture(t, boundary, manifest, v), "VLESS-only observations substituted for two-node profile")
	}
	var bf qualificationBoundaryFacts
	var vf candidateDraftVerificationFacts
	var cf candidateDraftConstructionFacts
	var pre qualificationFacts
	var m qualificationManifest
	if !decodeCanonical([]byte(boundary), &bf) || !decodeCanonical(bf.DraftVerificationFacts, &vf) || !decodeCanonical(vf.ConstructionFacts, &cf) || !decodeCanonical(cf.PreflightFacts, &pre) || !decodeCanonical(manifest, &m) {
		t.Fatal("fixture decision chain")
	}
	assertCleanInstallOnlyRecordReaders(t, m, body)
	declaration := jsonObject(t, []byte(qualificationDocument(t, m.V3Attempt)))
	delete(declaration, "baseline")
	delete(declaration, "candidate_index")
	for name, change := range map[string]func(map[string]any){
		"valid profile":   func(a map[string]any) {},
		"unknown profile": func(a map[string]any) { a["proxy_profile"] = "one-or-two" },
		"repair scope":    func(a map[string]any) { a["support"].(map[string]any)["scope"] = "subscription-clean-install-repair" },
		"HTTPS policy":    func(a map[string]any) { a["evidence_policy"] = "mvp-live-v1" },
		"exception reuse": func(a map[string]any) { a["owner_exception"] = "exception" },
	} {
		a := jsonObject(t, []byte(qualificationDocument(t, declaration)))
		change(a)
		var output bytes.Buffer
		err := runQualificationDeclaration(strings.NewReader(qualificationDocument(t, map[string]any{"attempt": a, "preflight": pre})), &output)
		if (err == nil) != (name == "valid profile") {
			t.Fatalf("%s declaration: %v %s", name, err, output.String())
		}
	}
	assertCleanInstallOnlyPublication(t, binary, pre, m, document, out)
}
