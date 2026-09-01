package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installRenewalCertificate(t *testing.T, a Adapter, publicIPv4 string) *x509.CertPool {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SBXR test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(publicIPv4)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for path, fixture := range map[string]struct {
		body []byte
		mode os.FileMode
	}{
		servingArchive + "/cert1.pem":      {leaf, 0644},
		servingArchive + "/chain1.pem":     {chain, 0644},
		servingArchive + "/fullchain1.pem": {append(append([]byte{}, leaf...), chain...), 0644},
		servingArchive + "/privkey1.pem":   {key, 0600},
	} {
		if err := os.WriteFile(a.path(path), fixture.body, fixture.mode); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(ca)
	return roots
}

func renewalFiles(t *testing.T) (Adapter, RenewalAuthority) {
	t.Helper()
	a := Adapter{root: t.TempDir()}
	a.renewalCertificateValid = func(RenewalAuthority, int) bool { return true }
	managedRoute := true
	a.subscriptionCommand = func(_ context.Context, name string, arguments ...string) (string, int, bool) {
		command := name + " " + strings.Join(arguments, " ")
		switch command {
		case "systemctl show --property=ExecStart --value snap.certbot.renew.service":
			if !managedRoute {
				return "/usr/bin/snap run --timer=00:00~24:00/2 certbot.renew\n", 0, true
			}
			return "/usr/local/bin/sbxr --certbot-recorder\n", 0, true
		case "systemctl daemon-reload":
			_, err := os.Stat(a.path(RenewalDropInPath))
			managedRoute = err == nil
			return "", 0, true
		case "systemctl show --property=FragmentPath --value snap.certbot.renew.service":
			return "/etc/systemd/system/snap.certbot.renew.service\n", 0, true
		case "systemctl show --property=LoadState --value snap.certbot.renew.timer":
			return "loaded\n", 0, true
		case "systemctl show --property=FragmentPath --value snap.certbot.renew.timer":
			return "/etc/systemd/system/snap.certbot.renew.timer\n", 0, true
		case "systemctl show --property=DropInPaths --value snap.certbot.renew.timer":
			return "\n", 0, true
		case "systemctl show --property=Unit --value snap.certbot.renew.timer":
			return "snap.certbot.renew.service\n", 0, true
		case "systemctl show --property=TimersCalendar --value snap.certbot.renew.timer":
			return "{ OnCalendar=*-*-* 06:00:00 ; next_elapse=1 } { OnCalendar=*-*-* 18:00:00 ; next_elapse=2 }\n", 0, true
		case "systemctl show --property=UnitFileState --value snap.certbot.renew.timer":
			return "enabled\n", 0, true
		case "systemctl show --property=ActiveState --value snap.certbot.renew.timer":
			return "active\n", 0, true
		case "snap list certbot --unicode=always --color=never":
			return "Name Version Rev Tracking Publisher Notes\ncertbot 5.4.0 5000 latest/stable certbot-eff✓ classic\n", 0, true
		}
		return "", 0, true
	}
	for _, dir := range []string{"/var/lib/sbxr", filepath.Dir(RenewalDropInPath), filepath.Dir(RenewalDeployHookPath), filepath.Dir(RenewalPostHookPath), "/etc/letsencrypt/live/sbxr-subscription", "/etc/letsencrypt/archive/sbxr-subscription"} {
		if err := os.MkdirAll(a.path(dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(a.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.path("/etc/letsencrypt/archive/sbxr-subscription/cert1.pem"), []byte("test certificate 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../archive/sbxr-subscription/cert1.pem", a.path("/etc/letsencrypt/live/sbxr-subscription/cert.pem")); err != nil {
		t.Fatal(err)
	}
	authority := RenewalAuthority{RecorderID: strings.Repeat("a", 32), Lineage: "sbxr-subscription", PublicIPv4: "8.8.8.8", Invocation: OfficialRenewalInvocation}
	established := time.Now().UTC().Format(time.RFC3339Nano)
	for path, fixture := range map[string]struct {
		body string
		mode os.FileMode
	}{
		RenewalDropInPath:     {RenewalDropIn, 0644},
		RenewalDeployHookPath: {RenewalDeployHook, 0700},
		RenewalPostHookPath:   {RenewalPostHook, 0700},
		RenewalEvidencePath:   {`{"schema":1,"recorder_id":"` + authority.RecorderID + `","established_at":"` + established + `","attempts":[]}` + "\n", 0600},
		RenewalAdmissionPath:  {"sbxr renewal admission v1\n", 0600},
		RenewalWriterPath:     {"sbxr renewal writer v1\n", 0600},
	} {
		if err := os.WriteFile(a.path(path), []byte(fixture.body), fixture.mode); err != nil {
			t.Fatal(err)
		}
	}
	return a, authority
}

func runRenewalRecorder(ctx context.Context, a Adapter, authority RenewalAuthority) int {
	runner, ok := a.PrepareRenewalRecorder(authority)
	if !ok {
		return RenewalRecorderRefused
	}
	return runner.Run(ctx)
}

func TestRenewalCertificateValidationUsesProtectedArchiveMaterial(t *testing.T) {
	for _, test := range []struct {
		name   string
		ip     string
		mutate func(t *testing.T, a Adapter)
		valid  bool
	}{
		{name: "valid", ip: "8.8.8.8", valid: true},
		{name: "wrong-san", ip: "1.1.1.1"},
		{name: "wrong-mode", ip: "8.8.8.8", mutate: func(t *testing.T, a Adapter) {
			if err := os.Chmod(a.path(servingArchive+"/privkey1.pem"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard-link", ip: "8.8.8.8", mutate: func(t *testing.T, a Adapter) {
			if err := os.Link(a.path(servingArchive+"/cert1.pem"), a.path(servingArchive+"/cert-alias.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mismatched-key", ip: "8.8.8.8", mutate: func(t *testing.T, a Adapter) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil || os.WriteFile(a.path(servingArchive+"/privkey1.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600) != nil {
				t.Fatal("mismatched key fixture failed")
			}
		}},
		{name: "broken-chain", ip: "8.8.8.8", mutate: func(t *testing.T, a Adapter) {
			if err := os.WriteFile(a.path(servingArchive+"/chain1.pem"), []byte("not a certificate\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, authority := renewalFiles(t)
			a.renewalCertificateValid = nil
			a.renewalTrustRoots = installRenewalCertificate(t, a, test.ip)
			if test.mutate != nil {
				test.mutate(t, a)
			}
			if got := a.validRenewalCertificate(authority, 1); got != test.valid {
				t.Fatalf("validRenewalCertificate() = %v", got)
			}
		})
	}
}

func advanceRenewalLineage(t *testing.T, a Adapter) {
	t.Helper()
	if err := os.WriteFile(a.path("/etc/letsencrypt/archive/sbxr-subscription/cert2.pem"), []byte("test certificate 2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	path := a.path("/etc/letsencrypt/live/sbxr-subscription/cert.pem")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../archive/sbxr-subscription/cert2.pem", path); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalRecorderPublishesStartBeforeChildAndExactCompletion(t *testing.T) {
	a, authority := renewalFiles(t)
	called := false
	a.renewalCommand = func(_ context.Context, name string, arguments ...string) int {
		called = true
		if name != "/usr/bin/snap" || strings.Join(arguments, " ") != "run --timer=00:00~24:00/2 certbot.renew" {
			t.Fatalf("invocation = %q %q", name, arguments)
		}
		inspection := a.InspectRenewal(authority)
		if inspection.State != RenewalAttemptLive || len(inspection.Evidence.Attempts) != 1 || inspection.Evidence.Attempts[0].Completion != nil {
			t.Fatalf("child observed evidence = %#v", inspection)
		}
		return 17
	}
	if code := runRenewalRecorder(t.Context(), a, authority); code != 17 || !called {
		t.Fatalf("RunRenewalRecorder() = %d called=%v", code, called)
	}
	inspection := a.InspectRenewal(authority)
	if inspection.State != RenewalAttemptFailed || len(inspection.Evidence.Attempts) != 1 || inspection.Evidence.Attempts[0].Completion == nil || inspection.Evidence.Attempts[0].Completion.ExitCode != 17 {
		t.Fatalf("completed evidence = %#v", inspection)
	}
}

func TestRenewalRecorderNeverLaunchesAfterUncertainStartPublication(t *testing.T) {
	a, authority := renewalFiles(t)
	a.syncDirectoryFault = func(string) error { return errors.New("test sync failure") }
	a.renewalCommand = func(context.Context, string, ...string) int {
		t.Fatal("child launched before durable start receipt")
		return 0
	}
	if code := runRenewalRecorder(t.Context(), a, authority); code != RenewalRecorderRefused {
		t.Fatalf("RunRenewalRecorder() = %d", code)
	}
}

func TestRenewalRecorderNeverLaunchesWithInvalidExistingCertificate(t *testing.T) {
	a, authority := renewalFiles(t)
	a.renewalCertificateValid = func(RenewalAuthority, int) bool { return false }
	a.renewalCommand = func(context.Context, string, ...string) int {
		t.Fatal("child launched with invalid existing certificate")
		return 0
	}
	if code := runRenewalRecorder(t.Context(), a, authority); code != RenewalRecorderRefused {
		t.Fatalf("RunRenewalRecorder() = %d", code)
	}
}

func TestRenewalEvidenceKeepsEarlierFailureAndBindsHookWriter(t *testing.T) {
	a, authority := renewalFiles(t)
	a.renewalCommand = func(context.Context, string, ...string) int { return 9 }
	if runRenewalRecorder(t.Context(), a, authority) != 9 {
		t.Fatal("failed attempt was not recorded")
	}
	a.renewalCommand = func(context.Context, string, ...string) int { return 0 }
	if runRenewalRecorder(t.Context(), a, authority) != 0 {
		t.Fatal("successful attempt was not recorded")
	}
	inspection := a.InspectRenewal(authority)
	if inspection.State != RenewalAttemptFailed || len(inspection.Evidence.Attempts) != 2 {
		t.Fatalf("later success erased failure: %#v", inspection)
	}
	if a.RecordRenewalHook(authority, RenewalDeployRole, map[string]string{"SBXR_RENEWAL_ATTEMPT_ID": inspection.Evidence.Attempts[1].AttemptID, "RENEWED_LINEAGE": "/etc/letsencrypt/live/sbxr-subscription", "RENEWED_DOMAINS": "8.8.8.8"}) {
		t.Fatal("completed attempt accepted a stale hook writer")
	}
}

func TestRenewalHookWriterPublishesOnlyForItsLiveOwnedAttempt(t *testing.T) {
	a, authority := renewalFiles(t)
	a.renewalCommand = func(context.Context, string, ...string) int {
		inspection := a.InspectRenewal(authority)
		attempt := inspection.Evidence.Attempts[len(inspection.Evidence.Attempts)-1]
		advanceRenewalLineage(t, a)
		if !a.RecordRenewalHook(authority, RenewalDeployRole, map[string]string{
			"SBXR_RENEWAL_ATTEMPT_ID": attempt.AttemptID,
			"RENEWED_LINEAGE":         "/etc/letsencrypt/live/sbxr-subscription",
			"RENEWED_DOMAINS":         "8.8.8.8",
		}) {
			t.Fatal("owned live deploy outcome refused")
		}
		if !a.RecordRenewalHook(authority, RenewalDeployRole, map[string]string{
			"SBXR_RENEWAL_ATTEMPT_ID": attempt.AttemptID,
			"RENEWED_LINEAGE":         "/etc/letsencrypt/live/unrelated",
			"RENEWED_DOMAINS":         "example.com",
		}) {
			t.Fatal("unrelated lineage hook was not preserved")
		}
		if !a.RecordRenewalHook(authority, RenewalPostRole, map[string]string{
			"SBXR_RENEWAL_ATTEMPT_ID": attempt.AttemptID,
			"RENEWED_DOMAINS":         "8.8.8.8",
		}) {
			t.Fatal("owned live post outcome refused")
		}
		return 0
	}
	if runRenewalRecorder(t.Context(), a, authority) != 0 {
		t.Fatal("recorded renewal failed")
	}
	inspection := a.InspectRenewal(authority)
	if inspection.State != RenewalAttemptHealthy || inspection.Evidence.Attempts[0].DeployHook == nil || inspection.Evidence.Attempts[0].PostHook == nil || inspection.Evidence.Attempts[0].DeployHook.Outcome != "succeeded" || inspection.Evidence.Attempts[0].PostHook.Outcome != "succeeded" {
		t.Fatalf("hook evidence = %#v", inspection)
	}
}

func TestRenewalInspectionRequiresPairedOwnedHooks(t *testing.T) {
	a, authority := renewalFiles(t)
	a.renewalCommand = func(context.Context, string, ...string) int {
		attempt := a.InspectRenewal(authority).Evidence.Attempts[0]
		if !a.RecordRenewalHook(authority, RenewalDeployRole, map[string]string{
			"SBXR_RENEWAL_ATTEMPT_ID": attempt.AttemptID,
			"RENEWED_LINEAGE":         "/etc/letsencrypt/live/sbxr-subscription",
			"RENEWED_DOMAINS":         "8.8.8.8",
		}) {
			t.Fatal("deploy outcome refused")
		}
		return 0
	}
	if runRenewalRecorder(t.Context(), a, authority) != 0 {
		t.Fatal("recorded renewal failed")
	}
	if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptFailed {
		t.Fatalf("missing post outcome = %#v", inspection)
	}
}

func TestRenewalDeployOutcomeRequiresValidatedCertificateGeneration(t *testing.T) {
	a, authority := renewalFiles(t)
	a.renewalCommand = func(context.Context, string, ...string) int {
		attempt := a.InspectRenewal(authority).Evidence.Attempts[0]
		advanceRenewalLineage(t, a)
		a.renewalCertificateValid = func(RenewalAuthority, int) bool { return false }
		if a.RecordRenewalHook(authority, RenewalDeployRole, map[string]string{
			"SBXR_RENEWAL_ATTEMPT_ID": attempt.AttemptID,
			"RENEWED_LINEAGE":         "/etc/letsencrypt/live/sbxr-subscription",
			"RENEWED_DOMAINS":         "8.8.8.8",
		}) {
			t.Fatal("unvalidated certificate recorded as successful")
		}
		return 0
	}
	if runRenewalRecorder(t.Context(), a, authority) != 0 {
		t.Fatal("recorded renewal failed")
	}
	inspection := a.InspectRenewal(authority)
	if inspection.State != RenewalAttemptUnsafe || inspection.Evidence.Attempts[0].DeployHook == nil || inspection.Evidence.Attempts[0].DeployHook.Outcome != "failed" {
		t.Fatalf("unvalidated certificate evidence = %#v", inspection)
	}
}

func TestExactSystemdExecStartRejectsExtraOrDuplicateFields(t *testing.T) {
	valid := "{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --certbot-recorder ; ignore_errors=no }"
	if path, arguments, exact := exactSystemdExecStart(valid); !exact || path != "/usr/local/bin/sbxr" || arguments != "/usr/local/bin/sbxr --certbot-recorder" {
		t.Fatalf("valid structured ExecStart rejected: %q %q %v", path, arguments, exact)
	}
	for _, value := range []string{
		"/usr/local/bin/sbxr --certbot-recorder extra",
		"{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --certbot-recorder extra ; ignore_errors=no ; }",
		"{ path=/usr/local/bin/sbxr ; argv[]=/usr/local/bin/sbxr --certbot-recorder ; ignore_errors= ; ignore_errors=no ; }",
	} {
		path, arguments, exact := exactSystemdExecStart(value)
		if exact && path == "/usr/local/bin/sbxr" && arguments == "/usr/local/bin/sbxr --certbot-recorder" {
			t.Fatalf("unsafe ExecStart accepted: %q", value)
		}
	}
}

func TestRenewalRouteRefusesActiveSnapChangeAndReentrantConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(t *testing.T, a *Adapter)
	}{
		{"active-snap-change", func(_ *testing.T, a *Adapter) {
			base := a.subscriptionCommand
			a.subscriptionCommand = func(ctx context.Context, name string, arguments ...string) (string, int, bool) {
				if name+" "+strings.Join(arguments, " ") == "snap changes" {
					return "ID Status Spawn Ready Summary\n42 Doing now - Refresh certbot\n", 0, true
				}
				return base(ctx, name, arguments...)
			}
		}},
		{"altered-timer-schedule", func(_ *testing.T, a *Adapter) {
			base := a.subscriptionCommand
			a.subscriptionCommand = func(ctx context.Context, name string, arguments ...string) (string, int, bool) {
				if name+" "+strings.Join(arguments, " ") == "systemctl show --property=TimersCalendar --value snap.certbot.renew.timer" {
					return "{ OnCalendar=Mon *-*-* 06:00:00 ; next_elapse=1 }\n", 0, true
				}
				return base(ctx, name, arguments...)
			}
		}},
		{"reentrant-config", func(t *testing.T, a *Adapter) {
			path := a.path("/etc/letsencrypt/cli.ini")
			if err := os.WriteFile(path, []byte("deploy_hook = /usr/local/bin/sbxr --certbot-hook=deploy\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory-hooks-disabled", func(t *testing.T, a *Adapter) {
			path := a.path("/etc/letsencrypt/cli.ini")
			if err := os.WriteFile(path, []byte("no-directory-hooks = true\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, authority := renewalFiles(t)
			test.set(t, &a)
			if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptUnsafe || inspection.Observed {
				t.Fatalf("unsafe route = %#v", inspection)
			}
		})
	}
}

func TestRenewalInspectionRejectsStaleAndUnverifiableAttempts(t *testing.T) {
	for _, test := range []struct {
		name     string
		attempt  RenewalAttempt
		identity func(int) (string, uint64, bool)
	}{
		{
			name: "stale-completion",
			attempt: RenewalAttempt{AttemptID: strings.Repeat("1", 32), Invocation: OfficialRenewalInvocation, StartedAt: time.Now().Add(-maxRenewalEvidenceAge - time.Hour).Format(time.RFC3339Nano), BootID: "old", RecorderPID: 1, ProcessTick: 1,
				Completion: &RenewalCompletion{ExitCode: 0, CompletedAt: time.Now().Add(-maxRenewalEvidenceAge - time.Hour + time.Second).Format(time.RFC3339Nano), OwnedOutcome: "no-op"}},
		},
		{
			name:     "unverifiable-process",
			attempt:  RenewalAttempt{AttemptID: strings.Repeat("2", 32), Invocation: OfficialRenewalInvocation, StartedAt: time.Now().Format(time.RFC3339Nano), BootID: "unknown", RecorderPID: 999, ProcessTick: 1},
			identity: func(int) (string, uint64, bool) { return "", 0, false },
		},
		{
			name: "future-hook",
			attempt: RenewalAttempt{AttemptID: strings.Repeat("3", 32), Invocation: OfficialRenewalInvocation, StartedAt: time.Now().Format(time.RFC3339Nano), BootID: "unknown", RecorderPID: 999, ProcessTick: 1,
				DeployHook: &RenewalHookOutcome{Role: RenewalDeployRole, Outcome: "succeeded", RecordedAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano), LineageTarget: "../../archive/sbxr-subscription/cert1.pem"}},
		},
		{
			name: "reversed-hooks",
			attempt: RenewalAttempt{AttemptID: strings.Repeat("4", 32), Invocation: OfficialRenewalInvocation, StartedAt: time.Now().Add(-2 * time.Minute).Format(time.RFC3339Nano), BootID: "old", RecorderPID: 1, ProcessTick: 1,
				DeployHook: &RenewalHookOutcome{Role: RenewalDeployRole, Outcome: "succeeded", RecordedAt: time.Now().Add(-30 * time.Second).Format(time.RFC3339Nano), LineageTarget: "../../archive/sbxr-subscription/cert2.pem"},
				PostHook:   &RenewalHookOutcome{Role: RenewalPostRole, Outcome: "succeeded", RecordedAt: time.Now().Add(-time.Minute).Format(time.RFC3339Nano)},
				Completion: &RenewalCompletion{ExitCode: 0, CompletedAt: time.Now().Format(time.RFC3339Nano), OwnedOutcome: "renewed", LineageAfter: "../../archive/sbxr-subscription/cert2.pem"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, authority := renewalFiles(t)
			a.renewalProcessIdentity = test.identity
			test.attempt.LineageBefore = "../../archive/sbxr-subscription/cert1.pem"
			if test.attempt.Completion != nil && test.attempt.Completion.LineageAfter == "" {
				test.attempt.Completion.LineageAfter = test.attempt.LineageBefore
			}
			evidence := RenewalEvidence{Schema: 1, RecorderID: authority.RecorderID, EstablishedAt: test.attempt.StartedAt, Attempts: []RenewalAttempt{test.attempt}}
			body, err := json.Marshal(evidence)
			if err != nil || os.WriteFile(a.path(RenewalEvidencePath), append(body, '\n'), 0600) != nil {
				t.Fatal("evidence fixture failed")
			}
			if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptUnsafe || inspection.Observed {
				t.Fatalf("unsafe attempt = %#v", inspection)
			}
		})
	}
}

func TestRenewalInspectionRejectsStaleEmptyStore(t *testing.T) {
	a, authority := renewalFiles(t)
	evidence := RenewalEvidence{Schema: 1, RecorderID: authority.RecorderID, EstablishedAt: time.Now().Add(-maxRenewalEvidenceAge - time.Hour).Format(time.RFC3339Nano)}
	body, err := json.Marshal(evidence)
	if err != nil || os.WriteFile(a.path(RenewalEvidencePath), append(body, '\n'), 0600) != nil {
		t.Fatal("evidence fixture failed")
	}
	if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptUnsafe || inspection.Observed {
		t.Fatalf("stale empty evidence = %#v", inspection)
	}
}

func TestRenewalInspectionRefusesRouteDriftAndUnsafeEvidence(t *testing.T) {
	t.Run("route", func(t *testing.T) {
		a, authority := renewalFiles(t)
		a.subscriptionCommand = func(context.Context, string, ...string) (string, int, bool) { return "changed", 0, true }
		if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptUnsafe || inspection.Observed {
			t.Fatalf("route drift = %#v", inspection)
		}
	})
	t.Run("evidence", func(t *testing.T) {
		a, authority := renewalFiles(t)
		if err := os.WriteFile(a.path(RenewalEvidencePath), []byte(`{"schema":1}`), 0600); err != nil {
			t.Fatal(err)
		}
		if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptUnsafe || inspection.Observed {
			t.Fatalf("unsafe evidence = %#v", inspection)
		}
	})
	t.Run("writer-link", func(t *testing.T) {
		a, authority := renewalFiles(t)
		if err := os.Link(a.path(RenewalWriterPath), a.path("/var/lib/sbxr/writer-alias")); err != nil {
			t.Fatal(err)
		}
		if inspection := a.InspectRenewal(authority); inspection.State != RenewalAttemptUnsafe || inspection.Observed {
			t.Fatalf("unsafe writer = %#v", inspection)
		}
	})
}

func TestRenewalEvidenceBoundDropsOnlyResolvedSuccess(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-%v", failed), func(t *testing.T) {
			a, authority := renewalFiles(t)
			started := time.Now().Add(-time.Duration(maxRenewalAttempts+1) * time.Second)
			evidence := RenewalEvidence{Schema: 1, RecorderID: authority.RecorderID, EstablishedAt: started.Format(time.RFC3339Nano)}
			for i := 1; i <= maxRenewalAttempts; i++ {
				exit := 0
				if failed {
					exit = 1
				}
				completed := started.Add(time.Second)
				evidence.Attempts = append(evidence.Attempts, RenewalAttempt{AttemptID: fmt.Sprintf("%032x", i), Invocation: authority.Invocation, StartedAt: started.Format(time.RFC3339Nano), BootID: "old", RecorderPID: i, ProcessTick: uint64(i), LineageBefore: "../../archive/sbxr-subscription/cert1.pem", Completion: &RenewalCompletion{ExitCode: exit, CompletedAt: completed.Format(time.RFC3339Nano), OwnedOutcome: "no-op", LineageAfter: "../../archive/sbxr-subscription/cert1.pem"}})
				started = completed
			}
			body, err := json.Marshal(evidence)
			if err != nil || os.WriteFile(a.path(RenewalEvidencePath), append(body, '\n'), 0600) != nil {
				t.Fatal("evidence fixture failed")
			}
			called := false
			a.renewalCommand = func(context.Context, string, ...string) int { called = true; return 0 }
			code := runRenewalRecorder(t.Context(), a, authority)
			if failed && (code != RenewalRecorderRefused || called) {
				t.Fatal("unresolved evidence was discarded")
			}
			if !failed {
				inspection := a.InspectRenewal(authority)
				if code != 0 || !called || len(inspection.Evidence.Attempts) != maxRenewalAttempts || inspection.Evidence.Attempts[0].AttemptID == fmt.Sprintf("%032x", 1) {
					t.Fatalf("resolved retention = code %d called=%v evidence=%#v", code, called, inspection.Evidence)
				}
			}
		})
	}
}

func TestRenewalExclusionRefusesLiveChildAndRemovalPreservesOverrides(t *testing.T) {
	a, authority := renewalFiles(t)
	started := make(chan struct{})
	release := make(chan struct{})
	a.renewalCommand = func(context.Context, string, ...string) int {
		close(started)
		<-release
		return 0
	}
	done := make(chan int, 1)
	go func() { done <- runRenewalRecorder(t.Context(), a, authority) }()
	<-started
	if exclusion, ok := a.AcquireRenewalExclusion(authority); ok {
		exclusion.Release()
		t.Fatal("live managed child admitted for removal")
	}
	close(release)
	if code := <-done; code != 0 {
		t.Fatalf("recorder exit = %d", code)
	}
	unrelated := a.path(filepath.Join(filepath.Dir(RenewalDropInPath), "90-owner.conf"))
	if err := os.WriteFile(unrelated, []byte("[Service]\nNice=5\n"), 0644); err != nil {
		t.Fatal(err)
	}
	exclusion, ok := a.AcquireRenewalExclusion(authority)
	if !ok {
		t.Fatal("idle renewal integration refused")
	}
	defer exclusion.Release()
	if !a.RemoveRenewalIntegration(t.Context(), authority, exclusion) || !a.RenewalIntegrationAbsent(authority) {
		t.Fatal("renewal integration removal failed")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("unrelated service override removed")
	}
}

func TestRenewalRemovalResumesAfterEveryPublicationSyncFailure(t *testing.T) {
	for boundary := 1; boundary <= 6; boundary++ {
		t.Run("sync", func(t *testing.T) {
			a, authority := renewalFiles(t)
			calls := 0
			a.syncDirectoryFault = func(string) error {
				calls++
				if calls == boundary {
					return os.ErrInvalid
				}
				return nil
			}
			exclusion, ok := a.AcquireRenewalExclusion(authority)
			if !ok {
				t.Fatal("initial exclusion failed")
			}
			if a.RemoveRenewalIntegration(t.Context(), authority, exclusion) {
				t.Fatal("sync failure accepted")
			}
			exclusion.Release()
			a.syncDirectoryFault = nil
			exclusion, ok = a.AcquireRenewalExclusion(authority)
			if !ok {
				t.Fatal("recovery exclusion failed")
			}
			defer exclusion.Release()
			if !a.RemoveRenewalIntegration(t.Context(), authority, exclusion) || !a.RenewalIntegrationAbsent(authority) {
				t.Fatal("removal recovery failed")
			}
		})
	}
}

func TestRenewalRemovalResumesWithEitherLockAlreadyDeleted(t *testing.T) {
	for _, missing := range []string{RenewalAdmissionPath, RenewalWriterPath} {
		t.Run(filepath.Base(missing), func(t *testing.T) {
			a, authority := renewalFiles(t)
			for _, path := range []string{RenewalDeployHookPath, RenewalPostHookPath, RenewalDropInPath, missing} {
				if err := os.Remove(a.path(path)); err != nil {
					t.Fatal(err)
				}
			}
			exclusion, ok := a.AcquireRenewalExclusion(authority)
			if !ok {
				t.Fatal("partial lock state refused")
			}
			defer exclusion.Release()
			if !a.RemoveRenewalIntegration(t.Context(), authority, exclusion) || !a.RenewalIntegrationAbsent(authority) {
				t.Fatal("partial lock removal did not resume")
			}
		})
	}
}
