package host

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This fixture is an external issuer process, not a successful-command stub.
// It publishes real, locally trusted certificate files and exercises the normal
// runner's process, environment, descriptor, lock and receipt boundaries. ACME
// issuance itself remains a live acceptance check.
func TestRenewalIssuerProcessFixture(t *testing.T) {
	if os.Getenv("SBXR_TEST_ISSUER_PROCESS") != "1" {
		return
	}
	root, mode := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	a := Adapter{root: root}
	input, err := io.ReadAll(os.Stdin)
	if err != nil || len(input) != 0 {
		os.Exit(71)
	}
	for _, key := range []string{"RENEWED_LINEAGE", "RENEWED_DOMAINS", "FAILED_DOMAINS"} {
		if _, found := os.LookupEnv(key); found {
			os.Exit(72)
		}
	}
	if len(os.Getenv("SBXR_RENEWAL_ATTEMPT_ID")) != 32 || os.Getenv("SBXR_RENEWAL_ATTEMPT_ID") == strings.Repeat("f", 32) {
		os.Exit(73)
	}
	null, err := os.Stat(os.DevNull)
	if err != nil {
		os.Exit(74)
	}
	stdout, err := os.Stdout.Stat()
	if err != nil || !os.SameFile(null, stdout) {
		os.Exit(75)
	}
	stderr, err := os.Stderr.Stat()
	if err != nil || stderr.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(75)
	}
	if lock, ok := a.openRenewalLock(RenewalAdmissionPath, false); ok {
		lock.Close()
		os.Exit(76)
	}
	ready := filepath.Join(root, "issuer-ready")
	staged := ready + ".next"
	if err := os.WriteFile(staged, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		_ = os.Remove(staged)
		os.Exit(77)
	}
	if err := os.Rename(staged, ready); err != nil {
		_ = os.Remove(staged)
		os.Exit(77)
	}
	if mode == "cancel" {
		time.Sleep(time.Minute)
		os.Exit(78)
	}
	if mode == "retain-success" || mode == "retain-fail" {
		holder := exec.Command("/bin/sh", "-c", "sleep 60")
		holder.Stdin, holder.Stdout, holder.Stderr = nil, nil, os.Stderr
		holder.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if holder.Start() != nil {
			os.Exit(82)
		}
		if os.WriteFile(filepath.Join(root, "stderr-holder"), []byte(strconv.Itoa(holder.Process.Pid)), 0600) != nil {
			_ = syscall.Kill(-holder.Process.Pid, syscall.SIGKILL)
			_ = holder.Wait()
			os.Exit(82)
		}
	}
	if mode == "retain-fail" {
		_, _ = io.WriteString(os.Stderr, "urn:ietf:params:acme:error:rateLimited retry after 2026-09-14 16:16:25 UTC\n")
		os.Exit(37)
	}
	if mode == "rate-limit" {
		_, _ = io.WriteString(os.Stderr, "2026-09-13 13:22:26 unrelated timestamp\n")
		_, _ = io.WriteString(os.Stderr, "acme.messages.Error: urn:ietf:params:acme:error:rateLimited :: There were too many requests of a given type :: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-09-14 16:16:25 UTC: see [documentation URL]\n")
		_, _ = io.WriteString(os.Stderr, "private-secret-marker-must-not-be-saved\n")
		os.Exit(37)
	}
	if mode == "unknown" {
		_, _ = io.WriteString(os.Stderr, "private-secret-marker-must-not-be-saved\n")
		os.Exit(37)
	}
	if mode == "missing-retry" {
		_, _ = io.WriteString(os.Stderr, "acme.messages.Error: urn:ietf:params:acme:error:rateLimited :: request refused\n")
		os.Exit(37)
	}
	if mode == "invalid-retry" {
		_, _ = io.WriteString(os.Stderr, "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after tomorrow UTC\n")
		os.Exit(37)
	}
	if mode == "overflow" {
		_, _ = io.WriteString(os.Stderr, "urn:ietf:params:acme:error:rateLimited retry after 2026-09-14 16:16:25 UTC\n")
		_, _ = os.Stderr.Write(make([]byte, maxRenewalDiagnosticBytes+1))
		os.Exit(37)
	}
	if mode == "fail" {
		os.Exit(37)
	}
	for _, part := range []string{"cert", "chain", "fullchain", "privkey"} {
		body, err := os.ReadFile(filepath.Join(root, "replacement", part+".pem"))
		if err != nil {
			os.Exit(79)
		}
		perm := os.FileMode(0644)
		if part == "privkey" {
			perm = 0600
		}
		if os.WriteFile(a.path(servingArchive+"/"+part+"2.pem"), body, perm) != nil {
			os.Exit(80)
		}
		link := a.path(servingLive + "/" + part + ".pem")
		if os.Remove(link) != nil || os.Symlink("../../archive/sbxr-subscription/"+part+"2.pem", link) != nil {
			os.Exit(81)
		}
	}
	os.Exit(0)
}

func TestOwnerRenewalRealProcessPublicationFailureAndCancellation(t *testing.T) {
	for _, mode := range []string{"publish", "retain-success", "fail", "rate-limit", "unknown", "missing-retry", "invalid-retry", "overflow", "retain-fail", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			a, authority := renewalFiles(t)
			if mode == "retain-success" || mode == "retain-fail" {
				t.Cleanup(func() {
					holderBody, err := os.ReadFile(filepath.Join(a.root, "stderr-holder"))
					if err != nil {
						return
					}
					holderPID, err := strconv.Atoi(string(holderBody))
					if err == nil {
						_ = syscall.Kill(-holderPID, syscall.SIGKILL)
					}
				})
			}
			a.renewalCertificateValid = nil
			a.renewalTrustRoots = installRenewalCertificate(t, a, authority.PublicIPv4)
			original := map[string][]byte{}
			for _, part := range []string{"cert", "chain", "fullchain", "privkey"} {
				body, err := os.ReadFile(a.path(servingArchive + "/" + part + "1.pem"))
				if err != nil {
					t.Fatal(err)
				}
				original[part] = body
				if part != "cert" {
					if err := os.Symlink("../../archive/sbxr-subscription/"+part+"1.pem", a.path(servingLive+"/"+part+".pem")); err != nil {
						t.Fatal(err)
					}
				}
			}
			installRenewalCertificate(t, a, authority.PublicIPv4)
			if err := os.Mkdir(filepath.Join(a.root, "replacement"), 0700); err != nil {
				t.Fatal(err)
			}
			for part, old := range original {
				path := a.path(servingArchive + "/" + part + "1.pem")
				next, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if part == "chain" && !a.renewalTrustRoots.AppendCertsFromPEM(next) {
					t.Fatal("replacement trust fixture")
				}
				if os.WriteFile(filepath.Join(a.root, "replacement", part+".pem"), next, 0600) != nil || os.WriteFile(path, old, 0600) != nil {
					t.Fatal("certificate fixture")
				}
			}
			// Restore public file modes changed by the fixture writes only where needed.
			for _, part := range []string{"cert", "chain", "fullchain"} {
				if err := os.Chmod(a.path(servingArchive+"/"+part+"1.pem"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if !a.validRenewalCertificate(authority, 1) {
				t.Fatal("initial certificate is invalid")
			}
			t.Setenv("SBXR_TEST_ISSUER_PROCESS", "1")
			for _, key := range []string{"RENEWED_LINEAGE", "RENEWED_DOMAINS", "FAILED_DOMAINS"} {
				t.Setenv(key, "must-not-reach-issuer")
			}
			t.Setenv("SBXR_RENEWAL_ATTEMPT_ID", strings.Repeat("f", 32))
			command := []string{os.Args[0], "-test.run=^TestRenewalIssuerProcessFixture$", "--", a.root, mode}
			runner, ok := a.prepareRenewalAttempt(authority, OwnerRenewalInvocation, true, true, command)
			if !ok {
				t.Fatal("prepare Owner renewal")
			}
			defer runner.Abort()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan int, 1)
			go func() { done <- runner.Run(ctx) }()
			ready := filepath.Join(a.root, "issuer-ready")
			if mode == "cancel" {
				until := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(ready); err == nil {
						break
					}
					if time.Now().After(until) {
						cancel()
						<-done
						t.Fatal("issuer did not reach execution boundary")
					}
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}
			code := <-done
			if mode == "retain-success" || mode == "retain-fail" {
				holderBody, err := os.ReadFile(filepath.Join(a.root, "stderr-holder"))
				if err != nil {
					t.Fatalf("stderr holder: %v", err)
				}
				holderPID, err := strconv.Atoi(string(holderBody))
				if err != nil {
					t.Fatal(err)
				}
				_ = syscall.Kill(-holderPID, syscall.SIGKILL)
			}
			pidBytes, err := os.ReadFile(ready)
			if err != nil {
				t.Fatalf("issuer boundary: exit %d: %v", code, err)
			}
			pid, err := strconv.Atoi(string(pidBytes))
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("issuer process still exists: %v", err)
			}
			evidence, _, err := a.readRenewalEvidence(authority)
			if err != nil || len(evidence.Attempts) != 1 || evidence.Attempts[0].Completion == nil {
				t.Fatalf("receipt: %#v %v", evidence, err)
			}
			completion := evidence.Attempts[0].Completion
			if completion.ExitCode != code {
				t.Fatalf("exit not preserved: %d %#v", code, completion)
			}
			body, err := os.ReadFile(a.path(RenewalEvidencePath))
			if err != nil {
				t.Fatal(err)
			}
			recognizedFailure := mode == "rate-limit" || mode == "missing-retry" || mode == "invalid-retry"
			if recognizedFailure && !strings.Contains(string(body), `"kind":"rate-limited"`) {
				t.Fatalf("rate-limit diagnosis absent from receipt: %s", body)
			}
			if mode == "rate-limit" && (completion.Failure == nil || completion.Failure.RetryAfter != "2026-09-14T16:16:25Z" || runner.Failure() == nil || *runner.Failure() != *completion.Failure) {
				t.Fatalf("issuer retry time did not reach both the receipt and repair result: %#v", completion.Failure)
			}
			if !recognizedFailure && strings.Contains(string(body), `"failure"`) {
				t.Fatalf("unexpected diagnosis saved for %s: %s", mode, body)
			}
			if (mode == "missing-retry" || mode == "invalid-retry") && strings.Contains(string(body), `"retry_after"`) {
				t.Fatalf("unreliable retry time saved for %s: %s", mode, body)
			}
			if strings.Contains(string(body), "private-secret-marker") {
				t.Fatal("raw issuer stderr escaped into renewal evidence")
			}
			if mode == "publish" || mode == "retain-success" {
				if code != 0 || completion.OwnedOutcome != "renewed" || !a.validRenewalCertificate(authority, 2) {
					t.Fatalf("replacement not proved: %d %#v", code, completion)
				}
			} else {
				if code == 0 || mode == "fail" && code != 37 || !a.validRenewalCertificate(authority, 1) {
					t.Fatalf("failure handling: %d %#v", code, completion)
				}
				target, ok := a.renewalLineageTarget(authority)
				if !ok || !strings.HasSuffix(target, "cert1.pem") {
					t.Fatal("failed process changed the certificate")
				}
			}
			if lock, ok := a.openRenewalLock(RenewalAdmissionPath, true); !ok {
				t.Fatal("renewal admission leaked")
			} else {
				lock.Close()
			}
			for _, path := range []string{servingArchive, servingLive} {
				info, err := os.Stat(a.path(path))
				if err != nil || info.Mode().Perm() != 0700 {
					t.Fatalf("lineage protection: %s %v", path, err)
				}
			}
		})
	}
}
