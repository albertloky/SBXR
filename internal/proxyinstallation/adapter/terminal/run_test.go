package terminal

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

type journeyInstallation struct {
	actions       []proxyinstallation.Action
	confirmations []proxyinstallation.Confirmation
	statusReviews int
}

func (installation *journeyInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	installation.actions = append(installation.actions, action)
	base := proxyinstallation.Review{
		Version: "v3.0.0", Status: proxyinstallation.NotSetUp,
		LegalActions: []proxyinstallation.Action{proxyinstallation.StartSetupAction, proxyinstallation.ViewDetailsAction, proxyinstallation.CompleteRemovalAction},
		Result:       proxyinstallation.Result{Status: proxyinstallation.NotSetUp, Message: "Proxy setup has not started.", Code: proxyinstallation.StatusNotSetUp},
	}
	if action == proxyinstallation.StatusAction {
		installation.statusReviews++
	}
	if action == proxyinstallation.StartSetupAction {
		base.Plan = []string{"Host: Ubuntu 24.04 amd64", "SBXR will not change SSH, firewall, routing, or provider settings."}
		base.Prepared = &proxyinstallation.PreparedAction{}
	}
	return base
}

func (installation *journeyInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, _ proxyinstallation.ProgressReporter) proxyinstallation.Result {
	installation.confirmations = append(installation.confirmations, confirmation)
	return proxyinstallation.Result{Status: proxyinstallation.NotSetUp, Message: "No changes were made.", Code: proxyinstallation.ActionCancelled}
}

func TestRunPresentsAndCancelsTheRealNotSetUpJourney(t *testing.T) {
	installation := &journeyInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("1\n\n0\n"), &output, &output, installation)

	if status != 0 || !reflect.DeepEqual(installation.actions, []proxyinstallation.Action{proxyinstallation.StatusAction, proxyinstallation.StartSetupAction, proxyinstallation.StatusAction}) || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Declined}) || installation.statusReviews != 2 {
		t.Fatalf("status=%d actions=%v confirmations=%v statusReviews=%d", status, installation.actions, installation.confirmations, installation.statusReviews)
	}
	want := "SBXR V3\nVersion: v3.0.0\nProxy status: Not set up\nResult: Proxy setup has not started.\nCode: PROXY-INSTALLATION-STATUS-NOT-SET-UP\n\n1. Start setup\n2. View details\n3. Complete removal\n0. Exit\n"
	if !bytes.Contains(output.Bytes(), []byte(want)) {
		t.Fatalf("initial frame missing:\n%s", output.String())
	}
	for _, required := range []string{
		"Host: Ubuntu 24.04 amd64",
		"Start proxy setup? [y/N]",
		"Result: No changes were made.\nCode: PROXY-INSTALLATION-ACTION-CANCELLED",
	} {
		if !bytes.Contains(output.Bytes(), []byte(required)) {
			t.Errorf("output missing %q:\n%s", required, output.String())
		}
	}
}

func TestRunAcceptsOnlyYOrNConfirmation(t *testing.T) {
	installation := &journeyInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("1\nmaybe\ny\n0\n"), &output, &output, installation)

	if status != 0 || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) || !bytes.Contains(output.Bytes(), []byte("Enter y or n.\nStart proxy setup? [y/N]")) {
		t.Fatalf("status=%d confirmations=%v output:\n%s", status, installation.confirmations, output.String())
	}
}

func TestRunRejectsNonCanonicalMenuNumbers(t *testing.T) {
	installation := &journeyInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("+1\n01\n1\n\n0\n"), &output, &output, installation)

	if status != 0 || len(installation.confirmations) != 1 || bytes.Count(output.Bytes(), []byte("Enter one of the displayed numbers.")) != 2 {
		t.Fatalf("status=%d confirmations=%v output:\n%s", status, installation.confirmations, output.String())
	}
}

type finishingInstallation struct {
	action proxyinstallation.Action
	done   bool
}

func (installation *finishingInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	if installation.done {
		status := proxyinstallation.NotSetUp
		code := proxyinstallation.SetupCleanedUp
		message := "Setup was safely cleaned up. No proxy resources remain."
		if installation.action == proxyinstallation.FinishSetupAction {
			status, code, message = proxyinstallation.Running, proxyinstallation.SetupComplete, "Proxy setup is complete and locally verified."
		}
		return proxyinstallation.Review{Version: "v3.0.0", Status: status, LegalActions: []proxyinstallation.Action{proxyinstallation.ViewDetailsAction}, Result: proxyinstallation.Result{Status: status, Code: code, Message: message}}
	}
	review := proxyinstallation.Review{Version: "v3.0.0", Status: proxyinstallation.SetupIncomplete, LegalActions: []proxyinstallation.Action{installation.action, proxyinstallation.ViewDetailsAction}, Result: proxyinstallation.Result{Status: proxyinstallation.SetupIncomplete, Code: proxyinstallation.SetupNeedsCleanup, Message: "Proxy setup was interrupted and must be finished safely."}}
	if action == installation.action {
		review.Prepared = &proxyinstallation.PreparedAction{}
	}
	return review
}

func (installation *finishingInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	if confirmation != proxyinstallation.Approved {
		return proxyinstallation.Result{Status: proxyinstallation.SetupIncomplete, Code: proxyinstallation.ActionCancelled, Message: "No changes were made."}
	}
	progress(proxyinstallation.Progress{Phase: "Durable finishing checkpoint"})
	installation.done = true
	if installation.action == proxyinstallation.FinishSetupAction {
		return proxyinstallation.Result{Status: proxyinstallation.Running, Code: proxyinstallation.SetupComplete, Message: "Proxy setup is complete and locally verified."}
	}
	return proxyinstallation.Result{Status: proxyinstallation.NotSetUp, Code: proxyinstallation.SetupCleanedUp, Message: "Setup was safely cleaned up. No proxy resources remain."}
}

func TestRunPresentsBothFinishingJourneysAndProgress(t *testing.T) {
	for _, test := range []struct {
		action proxyinstallation.Action
		prompt string
	}{
		{proxyinstallation.FinishCleanupAction, "Finish proxy cleanup? [y/N]"},
		{proxyinstallation.FinishSetupAction, "Finish proxy setup? [y/N]"},
	} {
		t.Run(string(test.action), func(t *testing.T) {
			installation := &finishingInstallation{action: test.action}
			var output bytes.Buffer
			status := Run(t.Context(), nil, bytes.NewBufferString("1\ny\n0\n"), &output, &output, installation)
			if status != 0 || !bytes.Contains(output.Bytes(), []byte(test.prompt)) || !bytes.Contains(output.Bytes(), []byte("Progress: Durable finishing checkpoint")) {
				t.Fatalf("status=%d output:\n%s", status, output.String())
			}
		})
	}
}

type detailsInstallation struct{ actions []proxyinstallation.Action }

func (installation *detailsInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	installation.actions = append(installation.actions, action)
	return proxyinstallation.Review{
		Version: "v3.0.0", Status: proxyinstallation.Running,
		LegalActions: []proxyinstallation.Action{proxyinstallation.ViewDetailsAction},
		Details:      []string{"Fresh inspection: 2"},
		Result:       proxyinstallation.Result{Status: proxyinstallation.Running, Message: "Proxy setup is complete and locally verified.", Code: proxyinstallation.SetupComplete},
	}
}

func (*detailsInstallation) Execute(context.Context, proxyinstallation.PreparedAction, proxyinstallation.Confirmation, proxyinstallation.ProgressReporter) proxyinstallation.Result {
	return proxyinstallation.Result{}
}

func TestRunViewsFreshDetailsAndReinspectsAfterEnter(t *testing.T) {
	installation := &detailsInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("1\n\n0\n"), &output, &output, installation)

	wantActions := []proxyinstallation.Action{proxyinstallation.StatusAction, proxyinstallation.ViewDetailsAction, proxyinstallation.StatusAction}
	if status != 0 || !reflect.DeepEqual(installation.actions, wantActions) || !strings.Contains(output.String(), "Fresh inspection: 2\nPress Enter to return to the menu.") {
		t.Fatalf("status=%d actions=%v output:\n%s", status, installation.actions, output.String())
	}
}

type disclosureInstallation struct {
	actions       []proxyinstallation.Action
	confirmations []proxyinstallation.Confirmation
	privateKey    string
}

func (installation *disclosureInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	installation.actions = append(installation.actions, action)
	review := proxyinstallation.Review{
		Version: "v3.0.0", Status: proxyinstallation.Running,
		LegalActions: []proxyinstallation.Action{proxyinstallation.ViewDetailsAction, proxyinstallation.ShowClientConfigurationAction},
		Result:       proxyinstallation.Result{Status: proxyinstallation.Running, Message: "Proxy setup is complete and locally verified.", Code: proxyinstallation.SetupComplete},
	}
	if action == proxyinstallation.ShowClientConfigurationAction {
		review.Plan = []string{"Warning: this Client Configuration contains a credential."}
		review.Prepared = &proxyinstallation.PreparedAction{}
	}
	return review
}

func (installation *disclosureInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	installation.confirmations = append(installation.confirmations, confirmation)
	if confirmation == proxyinstallation.Declined {
		return proxyinstallation.Result{Status: proxyinstallation.Running, Message: "No changes were made.", Code: proxyinstallation.ActionCancelled}
	}
	progress(proxyinstallation.Progress{ClientConfiguration: []byte(`{"inbounds":[{"type":"mixed","listen":"127.0.0.1"}],"outbounds":[{"type":"vless","server":"8.8.8.8","server_port":443,"uuid":"11111111-2222-4333-8444-555555555555","flow":"xtls-rprx-vision","tls":{"server_name":"microsoft.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"public_key":"public","short_id":"01020304"}}}]}` + "\n")})
	return proxyinstallation.Result{Status: proxyinstallation.Running, Message: "Client Configuration was disclosed.", Code: proxyinstallation.ClientConfigurationDisclosed}
}

func TestRunDisclosesClientConfigurationOnlyInsideConfirmedBoundaries(t *testing.T) {
	installation := &disclosureInstallation{privateKey: "private-infrastructure-secret"}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("2\ny\n\n0\n"), &output, &output, installation)

	wantActions := []proxyinstallation.Action{proxyinstallation.StatusAction, proxyinstallation.ShowClientConfigurationAction, proxyinstallation.StatusAction}
	if status != 0 || !reflect.DeepEqual(installation.actions, wantActions) || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) {
		t.Fatalf("status=%d actions=%v confirmations=%v", status, installation.actions, installation.confirmations)
	}
	begin := strings.Index(output.String(), "----- BEGIN SBXR CLIENT CONFIGURATION -----")
	uuid := strings.Index(output.String(), "11111111-2222-4333-8444-555555555555")
	end := strings.Index(output.String(), "----- END SBXR CLIENT CONFIGURATION -----")
	if !strings.Contains(output.String(), "Warning: this Client Configuration contains a credential.\nShow client configuration? [y/N]") || begin < 0 || uuid < begin || end < uuid || strings.Count(output.String(), "11111111-2222-4333-8444-555555555555") != 1 || strings.Contains(output.String(), installation.privateKey) || !strings.Contains(output.String(), "Press Enter to preserve this configuration in terminal scrollback and return to the menu.") || !strings.Contains(output.String(), "Code: PROXY-INSTALLATION-CLIENT-CONFIGURATION-DISCLOSED") {
		t.Fatalf("output:\n%s", output.String())
	}
}

func TestRunCancelsClientConfigurationDisclosureOnEnterOrN(t *testing.T) {
	for _, confirmation := range []string{"", "n"} {
		installation := &disclosureInstallation{}
		var output bytes.Buffer

		status := Run(t.Context(), nil, bytes.NewBufferString("2\n"+confirmation+"\n0\n"), &output, &output, installation)

		if status != 0 || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Declined}) || strings.Contains(output.String(), "BEGIN SBXR CLIENT CONFIGURATION") || !strings.Contains(output.String(), "Code: PROXY-INSTALLATION-ACTION-CANCELLED") {
			t.Fatalf("confirmation=%q status=%d confirmations=%v output:\n%s", confirmation, status, installation.confirmations, output.String())
		}
	}
}
