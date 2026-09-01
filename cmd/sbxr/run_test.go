package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type constructionLifecycle struct{}

func (constructionLifecycle) Status(context.Context) softwarelifecycle.Result {
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: "v3.0.0", Commit: strings.Repeat("a", 40), IndexSHA256: strings.Repeat("b", 64)}
	return softwarelifecycle.Result{State: softwarelifecycle.Ready, Installed: &identity, Code: softwarelifecycle.StatusReady}
}

func (constructionLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (constructionLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func (constructionLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	return softwarelifecycle.Result{}
}

func TestProductionConstructionOpensTheV3Menu(t *testing.T) {
	var output bytes.Buffer

	status := run(t.Context(), nil, strings.NewReader("0\n"), &output, &output, constructionLifecycle{})

	if status != 0 || !strings.Contains(output.String(), "SBXR V3\nVersion: v3.0.0\nProxy status:") || !strings.Contains(output.String(), "\nSubscription status:") || strings.Contains(output.String(), "Enable subscription") {
		t.Fatalf("status=%d output:\n%s", status, output.String())
	}
}

func TestPrivateServingArgumentDoesNotAuthorizeExecution(t *testing.T) {
	t.Setenv("SBXR_SERVING_ROLE", "authorized")
	t.Setenv("LISTEN_PID", "1")
	var output bytes.Buffer
	if run(t.Context(), []string{"--subscription-serving"}, strings.NewReader(""), &output, &output, constructionLifecycle{}) != 1 || output.Len() != 0 {
		t.Fatal("private serving dispatch did not refuse silently")
	}
}

func TestPrivateProxyStartArgumentDoesNotCreateAuthority(t *testing.T) {
	var output bytes.Buffer
	if run(t.Context(), []string{hostadapter.ProxyStartRole}, strings.NewReader(""), &output, &output, constructionLifecycle{}) != 1 || output.Len() != 0 {
		t.Fatal("private proxy start dispatch did not refuse silently")
	}
}

func TestPrivateRenewalArgumentsAndEnvironmentDoNotAuthorizeExecution(t *testing.T) {
	t.Setenv("SBXR_RENEWAL_ATTEMPT_ID", strings.Repeat("a", 32))
	t.Setenv("RENEWED_LINEAGE", "/etc/letsencrypt/live/sbxr-subscription")
	t.Setenv("RENEWED_DOMAINS", "8.8.8.8")
	for _, test := range []struct {
		role string
		code int
	}{
		{hostadapter.RenewalRecorderRole, hostadapter.RenewalRecorderRefused},
		{hostadapter.RenewalDeployRole, 1},
		{hostadapter.RenewalPostRole, 1},
	} {
		t.Run(test.role, func(t *testing.T) {
			var output bytes.Buffer
			if code := run(t.Context(), []string{test.role}, strings.NewReader(""), &output, &output, constructionLifecycle{}); code != test.code || output.Len() != 0 {
				t.Fatalf("run() = %d output=%q", code, output.String())
			}
		})
	}
}

type menuLifecycle struct {
	constructionLifecycle
	updates, checks, recoveries int
}

func (m *menuLifecycle) Check(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	m.checks++
	r := m.Status(context.Background())
	target := *r.Installed
	target.Tag = "v3.0.22"
	r.Latest, r.Code = &target, softwarelifecycle.CheckUpdateAvailable
	return r
}
func (m *menuLifecycle) Update(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	m.updates++
	return m.Status(context.Background())
}
func (m *menuLifecycle) Recover(context.Context, softwarelifecycle.ProgressReporter) softwarelifecycle.Result {
	m.recoveries++
	return m.Status(context.Background())
}
func TestProductionMenuLifecycleConfirmation(t *testing.T) {
	for _, answer := range []string{"", "n", "y"} {
		t.Run(answer, func(t *testing.T) {
			lifecycle := &menuLifecycle{}
			var frame bytes.Buffer
			run(t.Context(), nil, strings.NewReader("0\n"), &frame, &frame, lifecycle)
			choice := ""
			for _, line := range strings.Split(frame.String(), "\n") {
				if strings.HasSuffix(line, ". Update") {
					choice = strings.TrimSuffix(line, ". Update")
				}
			}
			if choice == "" || !strings.Contains(frame.String(), ". Check\n") || !strings.Contains(frame.String(), ". Recover\n") {
				t.Fatalf("missing lifecycle choices: %s", frame.String())
			}
			var output bytes.Buffer
			code := run(t.Context(), nil, strings.NewReader(choice+"\n"+answer+"\n0\n"), &output, &output, lifecycle)
			want := 0
			if answer == "y" {
				want = 1
			}
			if code != 0 || lifecycle.updates != want || lifecycle.checks != 1 || !strings.Contains(output.String(), "v3.0.22") || !strings.Contains(output.String(), "Update SBXR? [y/N]") {
				t.Fatalf("code=%d lifecycle=%+v output=%s", code, lifecycle, output.String())
			}
		})
	}
}

type failingMenuOutput struct{ needle string }

func (w failingMenuOutput) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.needle) {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func TestProductionMenuOutputFailurePreventsApproval(t *testing.T) {
	lifecycle := &menuLifecycle{}
	var frame bytes.Buffer
	run(t.Context(), nil, strings.NewReader("0\n"), &frame, &frame, lifecycle)
	choice := ""
	for _, line := range strings.Split(frame.String(), "\n") {
		if strings.HasSuffix(line, ". Update") {
			choice = strings.TrimSuffix(line, ". Update")
		}
	}
	if choice == "" {
		t.Fatal("missing update choice")
	}
	for _, needle := range []string{"Target:", "Update SBXR? [y/N]"} {
		var errors bytes.Buffer
		code := run(t.Context(), nil, strings.NewReader(choice+"\ny\n0\n"), failingMenuOutput{needle}, &errors, lifecycle)
		if code != 1 || lifecycle.updates != 0 {
			t.Fatalf("output failure authorized update: code=%d updates=%d", code, lifecycle.updates)
		}
	}
}
