package terminal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

func TestSetupWizardDefaultsToStandardAndCancelsBeforeApply(t *testing.T) {
	installation := &vmessInstallation{}
	var output bytes.Buffer
	if code := Run(t.Context(), nil, strings.NewReader("1\n\n\n0\n"), &output, &output, installation, nil); code != 0 {
		t.Fatalf("code=%d output=%s", code, output.String())
	}
	for _, want := range []string{"Setup 1 — Choose connection", "1. Standard (default; no domain needed)", "2. Standard + Cloudflare (your own hostname and tunnel)", "Setup 2 — Review", "Apply setup? [y/N]", "No changes were made."} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q: %s", want, output.String())
		}
	}
	if len(installation.confirmations) != 0 || installation.hostname != "" || strings.Contains(output.String(), "4. Start setup with VMess") {
		t.Fatalf("cancellation executed setup or menu bypassed wizard: %+v", installation)
	}
}

func TestWizardValidatesHostnameInlineWithoutEchoingBadInput(t *testing.T) {
	v := &vmessInstallation{}
	invalid := []string{"", "HTTPS://proxy.example.com", "proxy.example.com:443", "proxy.example.com/path", "203.0.113.1", "token secret", strings.Repeat("a", 257)}
	var output bytes.Buffer
	input := "1\n2\n\n" + strings.Join(invalid, "\n") + "\nproxy.example.com\nc\n0\n"
	if code := Run(t.Context(), nil, strings.NewReader(input), &output, &output, v, nil); code != 0 || v.hostname != "proxy.example.com" || len(v.confirmations) != 0 {
		t.Fatalf("code=%d installation=%+v output=%s", code, v, output.String())
	}
	if !strings.Contains(output.String(), "Use a lowercase DNS hostname") || !strings.Contains(output.String(), "Input is too long") || strings.Contains(output.String(), "token secret") {
		t.Fatal("missing inline validation or bad input echoed")
	}
}

func TestWizardBackPreservesDraftAndReviewsAgain(t *testing.T) {
	v := &vmessInstallation{}
	var output bytes.Buffer
	// Review -> hostname -> preparation -> choice -> Cloudflare -> keep hostname.
	input := "1\n2\n\nproxy.example.com\nb\nb\nb\n\n\n\ny\n0\n"
	if code := Run(t.Context(), nil, strings.NewReader(input), &output, &output, v, nil); code != 0 || v.hostname != "proxy.example.com" || !reflect.DeepEqual(v.confirmations, []proxyinstallation.Confirmation{proxyinstallation.Approved}) {
		t.Fatalf("code=%d installation=%+v output=%s", code, v, output.String())
	}
	if strings.Count(output.String(), "VMess origin for proxy.example.com") != 2 || !strings.Contains(output.String(), "Connection [2]") || !strings.Contains(output.String(), "Hostname draft: proxy.example.com") {
		t.Fatal("Back lost a draft or did not review again")
	}
}

func TestWizardRepeatedFlowsDiscardCancelledDrafts(t *testing.T) {
	v := &vmessInstallation{}
	var output bytes.Buffer
	input := "1\n2\n\nproxy.example.com\nc\n1\n\ny\n0\n"
	if code := Run(t.Context(), nil, strings.NewReader(input), &output, &output, v, nil); code != 0 || len(v.confirmations) != 1 {
		t.Fatalf("code=%d installation=%+v output=%s", code, v, output.String())
	}
	if strings.Count(output.String(), "Connection [1]") != 2 || strings.Count(output.String(), "Setup 2 — Prepare Cloudflare") != 1 || v.actions[len(v.actions)-2] != proxyinstallation.StartSetupAction {
		t.Fatal("repeated flow reused a cancelled profile or hostname")
	}
}

func TestWizardHelpAndInvalidChoicesKeepSafeDefaults(t *testing.T) {
	v := &journeyInstallation{}
	var output bytes.Buffer
	if code := Run(t.Context(), nil, strings.NewReader("1\nh\n2\nx\n\nY\nyes\n y\n"+strings.Repeat("y", 257)+"\nn\n0\n"), &output, &output, v, nil); code != 0 || len(v.confirmations) != 0 {
		t.Fatalf("code=%d confirmations=%v output=%s", code, v.confirmations, output.String())
	}
	for _, want := range []string{"Standard uses VLESS REALITY Vision", "no domain", "Choose a displayed connection number", "Only y applies", "Enter y to apply", "Input is too long"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(output.String(), "2. Standard + Cloudflare") || strings.Contains(output.String(), "Match the selected tunnel ID") {
		t.Fatal("unsupported mode was offered or Standard review mentioned tunnel")
	}
}

type setupFailingWriter struct{ bytes.Buffer }

func (w *setupFailingWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Apply setup?")) {
		return 0, errors.New("fixture display failed")
	}
	return w.Buffer.Write(p)
}

type setupFailingReader struct{}

func (setupFailingReader) Read([]byte) (int, error) { return 0, errors.New("fixture input failed") }

func TestWizardNeverAppliesAfterMissingInputOrFailedPrompt(t *testing.T) {
	for _, input := range []io.Reader{
		strings.NewReader("1\n\n"), strings.NewReader("1\n\ny"),
		io.MultiReader(strings.NewReader("1\n\n"), setupFailingReader{}),
	} {
		v := &journeyInstallation{}
		var output bytes.Buffer
		Run(t.Context(), nil, input, &output, &output, v, nil)
		if len(v.confirmations) != 0 {
			t.Fatal("missing or failed input approved Apply")
		}
	}
	v := &journeyInstallation{}
	var output setupFailingWriter
	if code := Run(t.Context(), nil, strings.NewReader("1\n\ny\n"), &output, &output, v, nil); code != 1 || len(v.confirmations) != 0 {
		t.Fatal("failed prompt approved Apply or reported success")
	}
}

type setupOutcomeInstallation struct {
	vmessInstallation
	result   proxyinstallation.Result
	refusals int
}

func (v *setupOutcomeInstallation) ReviewVMessSetup(ctx context.Context, hostname string) proxyinstallation.Review {
	review := v.vmessInstallation.ReviewVMessSetup(ctx, hostname)
	if v.refusals > 0 {
		v.refusals--
		review.Prepared = nil
		review.Result = proxyinstallation.Result{Code: proxyinstallation.ActionRefused, FailedCheck: "Protected token file", Correction: "Restore the dedicated token file as root-owned 0600; never overwrite a different tunnel's token."}
	}
	return review
}

func (v *setupOutcomeInstallation) Execute(_ context.Context, _ proxyinstallation.PreparedAction, confirmation proxyinstallation.Confirmation, progress proxyinstallation.ProgressReporter) proxyinstallation.Result {
	v.confirmations = append(v.confirmations, confirmation)
	progress(proxyinstallation.Progress{Phase: "Checking installation"})
	return v.result
}

type setupRefusedInstallation struct{ setupOutcomeInstallation }

func (v *setupRefusedInstallation) Review(ctx context.Context, action proxyinstallation.Action) proxyinstallation.Review {
	review := v.setupOutcomeInstallation.Review(ctx, action)
	if action == proxyinstallation.StartSetupAction {
		review.Prepared = nil
		review.Result = proxyinstallation.Result{Code: proxyinstallation.ActionRefused, FailedCheck: "Fixture setup prerequisites", Correction: "Correct the fixture prerequisite before trying again."}
	}
	return review
}

func (*setupRefusedInstallation) Execute(context.Context, proxyinstallation.PreparedAction, proxyinstallation.Confirmation, proxyinstallation.ProgressReporter) proxyinstallation.Result {
	panic("refused setup must never execute")
}

func TestWizardRefusalOffersRetryBackAndCancel(t *testing.T) {
	for _, answer := range []string{"r\ny", "b\n\ny", "c"} {
		v := &setupOutcomeInstallation{refusals: 1}
		var output bytes.Buffer
		input := "1\n2\n\nproxy.example.com\n" + answer + "\n0\n"
		if code := Run(t.Context(), nil, strings.NewReader(input), &output, &output, v, nil); code != 0 {
			t.Fatal(output.String())
		}
		if !strings.Contains(output.String(), "Failed safety check: Protected token file") || !strings.Contains(output.String(), "r Retry checks, b Back, c Cancel") || strings.Count(output.String(), "Apply setup? [y/N]") != len(v.confirmations) {
			t.Fatal("refusal allowed Apply or hid correction/retry")
		}
		if answer == "c" && len(v.confirmations) != 0 || answer != "c" && len(v.confirmations) != 1 {
			t.Fatal("refusal recovery executed an unexpected number of times")
		}
	}
}

func TestWizardCompletionSeparatesInstallationAndConnectionProof(t *testing.T) {
	for _, test := range []struct {
		result proxyinstallation.Result
		want   string
	}{
		{proxyinstallation.Result{Status: proxyinstallation.Running, Code: proxyinstallation.SetupComplete}, "fresh outside-client connection test has not passed"},
		{proxyinstallation.Result{Status: proxyinstallation.Running, Code: proxyinstallation.VMessConnectionReady}, "Fresh Cloudflare connection test: passed from this server"},
		{proxyinstallation.Result{Status: proxyinstallation.Running, Code: proxyinstallation.VMessConnectionPending, FailedCheck: "TLS", Correction: "Wait for DNS."}, "Fresh Cloudflare connection test: pending"},
		{proxyinstallation.Result{Status: proxyinstallation.ProblemDetected, Code: proxyinstallation.VMessConnectionPending}, "local runtime could not be verified"},
		{proxyinstallation.Result{Status: proxyinstallation.SetupIncomplete, Code: proxyinstallation.SetupNeedsCompletion}, "choose Finish setup"},
		{proxyinstallation.Result{Status: proxyinstallation.SetupIncomplete, Code: proxyinstallation.SetupNeedsCleanup}, "choose Finish cleanup"},
		{proxyinstallation.Result{Code: proxyinstallation.ActionRefused, FailedCheck: "Changed facts", Correction: "Review again."}, "Correction: Review again."},
	} {
		t.Run(string(test.result.Code)+string(test.result.Status), func(t *testing.T) {
			v := &setupOutcomeInstallation{result: test.result}
			var output bytes.Buffer
			if code := Run(t.Context(), nil, strings.NewReader("1\n\ny\n0\n"), &output, &output, v, nil); code != 0 || !strings.Contains(output.String(), test.want) {
				t.Fatalf("code=%d output=%s", code, output.String())
			}
			if test.result.Status == proxyinstallation.Running && !strings.Contains(output.String(), "Enable subscription for an import link") {
				t.Fatal("missing import guidance")
			}
			if test.result.Status != proxyinstallation.Running && strings.Contains(output.String(), "Installed: local proxy setup complete") {
				t.Fatal("incomplete setup claimed installed")
			}
		})
	}
}

// The actual terminal adapter runs in a child, so the production Python driver
// must navigate the new prompts over real pipes rather than a copied transcript.
func TestSetupWizardOperatorDriver(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(t.TempDir(), "menu")
	body := fmt.Sprintf("#!%s\nimport os\nos.execv(%q, [%q, '-test.run=^TestSetupWizardChild$'])\n", python, executable, executable)
	if err := os.WriteFile(launcher, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		fixture string
		code    proxyinstallation.ResultCode
		want    string
	}{
		{"1", proxyinstallation.SetupComplete, "Installed: Standard proxy is locally verified"},
		{"refused", proxyinstallation.ActionRefused, "Code: PROXY-INSTALLATION-ACTION-CANCELLED"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			args := []string{"../../../../.github/scripts/v3-menu-session.py", "action", "Start setup", string(test.code), "--executable", launcher, "--timeout", "10"}
			if test.fixture == "1" {
				args = append(args, "--confirmation", "yes")
			}
			command := exec.CommandContext(ctx, python, args...)
			command.Env = append(os.Environ(), "SBXR_SETUP_FIXTURE="+test.fixture)
			output, err := command.CombinedOutput()
			if err != nil || !bytes.Contains(output, []byte(test.want)) {
				t.Fatalf("real driver/terminal boundary: %v\n%s", err, output)
			}
		})
	}
}

func TestSetupWizardChild(t *testing.T) {
	fixture := os.Getenv("SBXR_SETUP_FIXTURE")
	if fixture != "1" && fixture != "refused" {
		return
	}
	installation := &setupOutcomeInstallation{result: proxyinstallation.Result{Status: proxyinstallation.Running, Code: proxyinstallation.SetupComplete}}
	var ownerInterface proxyinstallation.Interface = installation
	if fixture == "refused" {
		ownerInterface = &setupRefusedInstallation{}
	}
	os.Exit(Run(t.Context(), nil, os.Stdin, os.Stdout, os.Stderr, ownerInterface, nil))
}
