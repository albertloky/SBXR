package main

import (
	"bytes"
	"context"
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
