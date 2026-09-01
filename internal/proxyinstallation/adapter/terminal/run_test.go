package terminal

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

type subscriptionInstallation struct{ journeyInstallation }

func (installation *subscriptionInstallation) Review(ctx context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	review := installation.journeyInstallation.Review(ctx, action)
	review.Status = proxyinstallation.Running
	review.LegalActions = []proxyinstallation.Action{proxyinstallation.ViewDetailsAction, proxyinstallation.ShowClientConfigurationAction, proxyinstallation.CompleteRemovalAction, proxyinstallation.EnableSubscriptionAction}
	if action == proxyinstallation.EnableSubscriptionAction {
		review.Prepared = &proxyinstallation.PreparedAction{}
		review.Plan = []string{"Plan: recorded IPv4 8.8.8.8; TCP 8443 and TCP 80."}
	}
	return review
}

func (installation *subscriptionInstallation) Execute(ctx context.Context, prepared proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	result := installation.journeyInstallation.Execute(ctx, prepared, confirmation, progress)
	if confirmation == proxyinstallation.Approved {
		progress(proxyinstallation.Progress{Phase: "Verifying subscription result"})
		progress(proxyinstallation.Progress{SubscriptionLink: []byte("https://8.8.8.8:8443/s/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")})
		result.Code, result.Message = proxyinstallation.SubscriptionEnabled, "The subscription is enabled and locally verified."
	}
	return result
}

func TestRunReviewsSubscriptionAndRedrawsAfterExactConfirmation(t *testing.T) {
	for _, test := range []struct {
		input        string
		confirmation proxyinstallation.Confirmation
	}{
		{"y", proxyinstallation.Approved}, {"n", proxyinstallation.Declined}, {"", proxyinstallation.Declined},
		{"Y\nyes\n y\n" + strings.Repeat("x", 300) + "\nn", proxyinstallation.Declined},
	} {
		t.Run(test.input, func(t *testing.T) {
			installation := &subscriptionInstallation{}
			var output bytes.Buffer
			code := Run(t.Context(), nil, strings.NewReader("4\n"+test.input+"\n0\n"), &output, &output, installation)
			if code != 0 || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{test.confirmation}) || installation.statusReviews != 2 {
				t.Fatalf("code=%d confirmations=%v reviews=%d output=%s", code, installation.confirmations, installation.statusReviews, output.String())
			}
			for _, want := range []string{"4. Enable subscription", "Plan: recorded IPv4", "Enable subscription? [y/N]", "Proxy status: Running\nSubscription status: Not enabled"} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("missing %q: %s", want, output.String())
				}
			}
			if test.confirmation == proxyinstallation.Approved {
				for _, want := range []string{"This link is a reusable credential.", "https://8.8.8.8:8443/s/", "Progress: Verifying subscription result"} {
					if !strings.Contains(output.String(), want) {
						t.Fatalf("missing %q: %s", want, output.String())
					}
				}
			} else if !strings.Contains(output.String(), "No changes were made.") {
				t.Fatalf("missing cancellation: %s", output.String())
			}
		})
	}
}

type rotationInstallation struct{ journeyInstallation }

func (installation *rotationInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	review := proxyinstallation.Review{Status: proxyinstallation.Running, SubscriptionStatus: proxyinstallation.SubscriptionAvailable, LegalActions: []proxyinstallation.Action{proxyinstallation.ViewDetailsAction, proxyinstallation.RotateSubscriptionLinkAction}}
	if action == proxyinstallation.RotateSubscriptionLinkAction {
		review.Prepared = &proxyinstallation.PreparedAction{}
		review.Plan = []string{"Action: Rotate subscription link", "There is no overlap."}
	}
	return review
}

func (installation *rotationInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	installation.confirmations = append(installation.confirmations, confirmation)
	if confirmation != proxyinstallation.Approved {
		return proxyinstallation.Result{Code: proxyinstallation.ActionCancelled, Message: "No changes were made."}
	}
	progress(proxyinstallation.Progress{SubscriptionLink: []byte("https://8.8.8.8:8443/s/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")})
	return proxyinstallation.Result{Status: proxyinstallation.Running, SubscriptionStatus: proxyinstallation.SubscriptionAvailable, Code: proxyinstallation.SubscriptionLinkRotated, Message: "The subscription link was rotated. Replace the old link in Karing."}
}

func TestRunDisplaysRotatedLinkAndExactReplacementWarning(t *testing.T) {
	installation := &rotationInstallation{}
	var output bytes.Buffer
	code := Run(t.Context(), nil, strings.NewReader("2\ny\n\n0\n"), &output, &output, installation)
	for _, want := range []string{"Rotate subscription link? [y/N]", "This link is a reusable credential.", "Replace the old link in Karing. The old link no longer works. Your proxy Client Identity has not changed."} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q: %s", want, output.String())
		}
	}
	if code != 0 || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) {
		t.Fatalf("code=%d confirmations=%v output=%s", code, installation.confirmations, output.String())
	}
}

func TestRunReportsCommittedRotationDisplayFailure(t *testing.T) {
	installation := &rotationInstallation{}
	output := &rotationFailWriter{failAt: "Replace the old link in Karing."}
	var errors bytes.Buffer
	code := Run(t.Context(), nil, strings.NewReader("2\ny\n"), output, &errors, installation)
	if code != 1 || !strings.Contains(errors.String(), string(proxyinstallation.SubscriptionLinkDisplayIncomplete)) || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) {
		t.Fatalf("code=%d confirmations=%v output=%s errors=%s", code, installation.confirmations, output.String(), errors.String())
	}
}

type rotationFailWriter struct {
	failAt string
	buffer bytes.Buffer
}

func (writer *rotationFailWriter) Write(body []byte) (int, error) {
	if strings.Contains(string(body), writer.failAt) {
		return 0, io.ErrClosedPipe
	}
	return writer.buffer.Write(body)
}

func (writer *rotationFailWriter) String() string { return writer.buffer.String() }

type subscriptionFailWriter struct {
	failAt string
	bytes.Buffer
}

func (writer *subscriptionFailWriter) Write(body []byte) (int, error) {
	if strings.Contains(string(body), writer.failAt) {
		return 0, io.ErrClosedPipe
	}
	return writer.Buffer.Write(body)
}

type subscriptionFailReader struct{}

func (subscriptionFailReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRunSubscriptionIOFailureDoesNotGrantAuthority(t *testing.T) {
	for _, point := range []string{"Plan:", "Enable subscription?", "Progress:", "https://8.8.8.8:8443/s/", "read"} {
		t.Run(point, func(t *testing.T) {
			installation := &subscriptionInstallation{}
			writer := &subscriptionFailWriter{failAt: point}
			var input io.Reader = strings.NewReader("4\ny\n0\n")
			if point == "read" {
				input = io.MultiReader(strings.NewReader("4\n"), subscriptionFailReader{})
			}
			code := Run(t.Context(), nil, input, writer, writer, installation)
			postcommit := point == "Progress:" || point == "https://8.8.8.8:8443/s/"
			if code != 1 || !postcommit && len(installation.confirmations) != 0 {
				t.Fatalf("code=%d confirmations=%v output=%s", code, installation.confirmations, writer.String())
			}
			if postcommit && !strings.Contains(writer.String(), string(proxyinstallation.SubscriptionLinkDisplayIncomplete)) {
				t.Fatalf("missing display-incomplete result: %s", writer.String())
			}
		})
	}
}

type journeyInstallation struct {
	actions       []proxyinstallation.Action
	confirmations []proxyinstallation.Confirmation
	statusReviews int
}

func (installation *journeyInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	installation.actions = append(installation.actions, action)
	base := proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled,
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
	want := "SBXR V3\nVersion: v3.0.0\nProxy status: Not set up\nSubscription status: Not enabled\nResult: Proxy setup has not started.\nCode: PROXY-INSTALLATION-STATUS-NOT-SET-UP\n\n1. Start setup\n2. View details\n3. Complete removal\n0. Exit\n"
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
		return proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled, Version: "v3.0.0", Status: status, LegalActions: []proxyinstallation.Action{proxyinstallation.ViewDetailsAction}, Result: proxyinstallation.Result{Status: status, Code: code, Message: message}}
	}
	review := proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled, Version: "v3.0.0", Status: proxyinstallation.SetupIncomplete, LegalActions: []proxyinstallation.Action{installation.action, proxyinstallation.ViewDetailsAction}, Result: proxyinstallation.Result{Status: proxyinstallation.SetupIncomplete, Code: proxyinstallation.SetupNeedsCleanup, Message: "Proxy setup was interrupted and must be finished safely."}}
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

type subscriptionFinishingInstallation struct{ done bool }

func (installation *subscriptionFinishingInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	status := proxyinstallation.SubscriptionChangeIncomplete
	result := proxyinstallation.Result{Status: proxyinstallation.Running, SubscriptionStatus: status, Code: proxyinstallation.SubscriptionStatusChangeIncomplete, Message: "A subscription change needs safe cleanup or completion."}
	if installation.done {
		status = proxyinstallation.SubscriptionAvailable
		result = proxyinstallation.Result{Status: proxyinstallation.Running, SubscriptionStatus: status, Code: proxyinstallation.SubscriptionChangeFinished, Message: "The interrupted subscription change was completed."}
	}
	review := proxyinstallation.Review{Version: "v3.0.0", Status: proxyinstallation.Running, SubscriptionStatus: status, LegalActions: []proxyinstallation.Action{proxyinstallation.FinishSubscriptionChangeAction, proxyinstallation.ViewDetailsAction}, Result: result}
	if action == proxyinstallation.FinishSubscriptionChangeAction && !installation.done {
		review.Prepared = &proxyinstallation.PreparedAction{}
		review.Plan = []string{"Direction: activate the exact published certificate generation."}
	}
	return review
}

func (installation *subscriptionFinishingInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	if confirmation != proxyinstallation.Approved {
		return proxyinstallation.Result{Status: proxyinstallation.Running, SubscriptionStatus: proxyinstallation.SubscriptionChangeIncomplete, Code: proxyinstallation.ActionCancelled, Message: "No changes were made."}
	}
	progress(proxyinstallation.Progress{Phase: "Finishing subscription change"})
	installation.done = true
	return proxyinstallation.Result{Status: proxyinstallation.Running, SubscriptionStatus: proxyinstallation.SubscriptionAvailable, Code: proxyinstallation.SubscriptionChangeFinished, Message: "The interrupted subscription change was completed."}
}

func TestRunConfirmsAndFinishesCertificateActivation(t *testing.T) {
	installation := &subscriptionFinishingInstallation{}
	var output bytes.Buffer
	if code := Run(t.Context(), nil, strings.NewReader("1\ny\n0\n"), &output, &output, installation); code != 0 {
		t.Fatalf("Run() = %d output=%s", code, output.String())
	}
	for _, want := range []string{"Finish subscription change? [y/N]", "Progress: Finishing subscription change", "Subscription status: Available", "PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-FINISHED"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q: %s", want, output.String())
		}
	}
}

type detailsInstallation struct{ actions []proxyinstallation.Action }

func (installation *detailsInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	installation.actions = append(installation.actions, action)
	return proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled,
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
	review := proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled,
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

type removalInstallation struct {
	confirmations []proxyinstallation.Confirmation
	statusReviews int
}

func (installation *removalInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	if action == proxyinstallation.StatusAction {
		installation.statusReviews++
	}
	review := proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled,
		Version: "v3.0.0", Status: proxyinstallation.Running,
		LegalActions: []proxyinstallation.Action{proxyinstallation.CompleteRemovalAction},
		Result:       proxyinstallation.Result{Status: proxyinstallation.Running, Message: "Proxy setup is complete and locally verified.", Code: proxyinstallation.SetupComplete},
	}
	if action == proxyinstallation.CompleteRemovalAction {
		review.Plan = []string{"Exact confirmation required: REMOVE SBXR"}
		review.Prepared = &proxyinstallation.PreparedAction{}
	}
	return review
}

func (installation *removalInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	installation.confirmations = append(installation.confirmations, confirmation)
	if confirmation == proxyinstallation.Approved {
		progress(proxyinstallation.Progress{Phase: "Removal committed"})
		return proxyinstallation.Result{Status: proxyinstallation.Running, Message: "The requested action was refused. View details for the failed check and correction.", Code: proxyinstallation.ActionRefused}
	}
	return proxyinstallation.Result{Status: proxyinstallation.Running, Message: "No changes were made.", Code: proxyinstallation.ActionCancelled}
}

func TestRunRequiresExactCompleteRemovalConfirmationAndReinspects(t *testing.T) {
	for _, test := range []struct {
		name         string
		input        string
		confirmation proxyinstallation.Confirmation
		code         proxyinstallation.ResultCode
	}{
		{"exact", "REMOVE SBXR", proxyinstallation.Approved, proxyinstallation.ActionRefused},
		{"wrong case", "remove sbxr", proxyinstallation.Declined, proxyinstallation.ActionCancelled},
		{"ordinary yes", "y", proxyinstallation.Declined, proxyinstallation.ActionCancelled},
		{"empty", "", proxyinstallation.Declined, proxyinstallation.ActionCancelled},
		{"too long", strings.Repeat("x", 257), proxyinstallation.Declined, proxyinstallation.ActionCancelled},
	} {
		t.Run(test.name, func(t *testing.T) {
			installation := &removalInstallation{}
			var output bytes.Buffer

			status := Run(t.Context(), nil, bytes.NewBufferString("1\n"+test.input+"\n0\n"), &output, &output, installation)

			if status != 0 || !reflect.DeepEqual(installation.confirmations, []proxyinstallation.Confirmation{test.confirmation}) || installation.statusReviews != 2 || !strings.Contains(output.String(), "Type REMOVE SBXR to confirm Complete removal") || !strings.Contains(output.String(), "Code: "+string(test.code)) || test.confirmation == proxyinstallation.Approved && !strings.Contains(output.String(), "Progress: Removal committed") {
				t.Fatalf("status=%d confirmations=%v reviews=%d output:\n%s", status, installation.confirmations, installation.statusReviews, output.String())
			}
		})
	}
}

type finishingRemovalInstallation struct{ statusReviews int }

func (installation *finishingRemovalInstallation) Review(_ context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	if action == proxyinstallation.StatusAction {
		installation.statusReviews++
	}
	review := proxyinstallation.Review{SubscriptionStatus: proxyinstallation.SubscriptionNotEnabled,
		Version: "v3.0.0", Status: proxyinstallation.RemovalIncomplete,
		LegalActions: []proxyinstallation.Action{proxyinstallation.FinishRemovalAction},
		Result:       proxyinstallation.Result{Status: proxyinstallation.RemovalIncomplete, Message: "Complete removal was interrupted and must continue forward.", Code: proxyinstallation.RemovalNeedsCompletion},
	}
	if action == proxyinstallation.FinishRemovalAction {
		review.Prepared = &proxyinstallation.PreparedAction{}
	}
	return review
}

func (*finishingRemovalInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, _ proxyinstallation.ProgressReporter) proxyinstallation.Result {
	if confirmation != proxyinstallation.Approved {
		panic("Finish removal was not approved")
	}
	return proxyinstallation.Result{Message: "SBXR is not installed.", Code: proxyinstallation.CompleteRemovalCompleted}
}

func TestRunFinishesCommittedRemovalAndExitsWithoutRedrawing(t *testing.T) {
	installation := &finishingRemovalInstallation{}
	var output bytes.Buffer

	status := Run(t.Context(), nil, bytes.NewBufferString("1\n"), &output, &output, installation)

	if status != 0 || installation.statusReviews != 1 || !strings.Contains(output.String(), "SBXR is not installed.\nCode: SOFTWARE-LIFECYCLE-COMPLETE-REMOVAL-COMPLETED") {
		t.Fatalf("status=%d reviews=%d output:\n%s", status, installation.statusReviews, output.String())
	}
}

type subscriptionStatusInstallation struct{ detailsInstallation }

func (installation *subscriptionStatusInstallation) Review(ctx context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	review := installation.detailsInstallation.Review(ctx, action)
	review.Status = proxyinstallation.Running
	if len(installation.actions) > 1 {
		review.SubscriptionStatus = proxyinstallation.SubscriptionProblemDetected
	}
	return review
}
func TestRunRedrawsSeparateSubscriptionStatusWithoutChangingProxyStatus(t *testing.T) {
	installation := &subscriptionStatusInstallation{}
	var output bytes.Buffer
	if code := Run(t.Context(), nil, strings.NewReader("1\n\n0\n"), &output, &output, installation); code != 0 {
		t.Fatalf("Run = %d", code)
	}
	for _, want := range []string{"Proxy status: Running\nSubscription status: Not enabled", "Proxy status: Running\nSubscription status: Problem detected"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing status frame %q", want)
		}
	}
}
