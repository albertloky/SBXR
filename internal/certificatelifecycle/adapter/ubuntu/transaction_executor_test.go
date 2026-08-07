package ubuntu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestIPOrderIsBoundedAndCleansIsolatedStaging(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	root, roots := writeCandidate(t, now, "192.0.2.10", false)
	staging := filepath.Join(root, "var/lib/sbxr/certbot/staging/sbxr-ip")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	var command string
	executor := TransactionExecutor{now: func() time.Time { return now }, roots: roots, uid: os.Geteuid(), gid: os.Getegid(), run: func(ctx context.Context, name string, arguments ...string) error {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Minute {
			return errors.New("unbounded")
		}
		command = name + " " + strings.Join(arguments, " ")
		return nil
	}}
	step, _ := systemchanges.NewCertificateStep(systemchanges.CertificateChange{Action: systemchanges.CertificateIPOrder, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", OwnerEmail: "owner@example.com", ConfigDirectory: "/var/lib/sbxr/certbot/production", Account: "production"})
	if _, err := executor.Execute(root, step, time.Minute, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "--required-profile shortlived --ip-address 192.0.2.10 --cert-name sbxr-ip") {
		t.Fatalf("production command = %s", command)
	}
	if _, err := os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("isolated staging remains: %v", err)
	}
	if _, err := executor.Reverse(root, step, strings.NewReader(`{}`), time.Minute); err != nil {
		t.Fatal(err)
	}
	if strings.Count(command, "certbot certonly") != 1 {
		t.Fatalf("rollback reordered certificate: %s", command)
	}

	executor.run = func(context.Context, string, ...string) error { return errors.New("RAW-CHALLENGE-SECRET-MARKER") }
	if _, err := executor.Execute(root, step, time.Minute, systemchanges.NewCancellation()); err == nil || strings.Contains(err.Error(), "MARKER") {
		t.Fatalf("unsafe order failure = %v", err)
	}
	cancelled := systemchanges.NewCancellation()
	cancelled.Request()
	if _, err := executor.Execute(root, step, time.Minute, cancelled); err == nil {
		t.Fatal("cancelled order started")
	}
	executor.run = func(ctx context.Context, _ string, _ ...string) error { <-ctx.Done(); return ctx.Err() }
	if _, err := executor.Execute(root, step, time.Millisecond, systemchanges.NewCancellation()); err == nil {
		t.Fatal("timed-out order accepted")
	}
}

func TestIPActivationFailureRestoresPriorPointerAndReprovesService(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	root, roots := writeCandidate(t, now, "192.0.2.10", false)
	base := filepath.Join(root, "var/lib/sbxr/certificates/ip")
	prior := filepath.Join(base, "sets/ip-prior")
	if err := os.MkdirAll(prior, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sets/ip-prior", filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
	var commands, proofs int
	executor := TransactionExecutor{now: func() time.Time { return now }, roots: roots, uid: os.Geteuid(), gid: os.Getegid(), run: func(_ context.Context, name string, arguments ...string) error {
		commands++
		if name != "systemctl" || strings.Join(arguments, " ") != "reload-or-restart sbxr-subscription.service" {
			return errors.New("wrong service")
		}
		return nil
	}, prove: func(context.Context, string) error { proofs++; return errors.New("new pair refused") }}
	step, _ := systemchanges.NewCertificateStep(systemchanges.CertificateChange{Action: systemchanges.CertificateIPActivate, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", SubscriptionUnit: "sbxr-subscription.service"})
	var snapshot bytes.Buffer
	if err := executor.CaptureRollback(root, step, func(source io.Reader) error { _, err := io.Copy(&snapshot, source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(root, step, time.Minute, systemchanges.NewCancellation()); err == nil {
		t.Fatal("activation failure accepted")
	}
	executor.prove = func(context.Context, string) error { proofs++; return nil }
	if _, err := executor.Reverse(root, step, bytes.NewReader(snapshot.Bytes()), time.Minute); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil || target != "sets/ip-prior" || commands != 2 || proofs != 2 {
		t.Fatalf("rollback target=%q commands=%d proofs=%d err=%v", target, commands, proofs, err)
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		matches, _ := filepath.Glob(filepath.Join(base, "sets/ip-*", name))
		for _, match := range matches {
			if strings.Contains(match, "ip-prior") {
				continue
			}
			info, statErr := os.Lstat(match)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
				t.Fatalf("serving file %s = %v %v", match, info, statErr)
			}
		}
	}
}

func TestIPActivationRestartInspectionAndCompleteCleanup(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	root, roots := writeCandidate(t, now, "192.0.2.10", false)
	base := filepath.Join(root, "var/lib/sbxr/certificates/ip")
	prior := filepath.Join(base, "sets/ip-prior")
	if err := os.MkdirAll(prior, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		file := filepath.Join(prior, name)
		if err := os.WriteFile(file, []byte("prior"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(file, os.Geteuid(), os.Getegid()); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(prior, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sets/ip-prior", filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
	executor := TransactionExecutor{now: func() time.Time { return now }, roots: roots, uid: os.Geteuid(), gid: os.Getegid(), run: func(context.Context, string, ...string) error { return nil }, prove: func(context.Context, string) error { return nil }}
	step, _ := systemchanges.NewCertificateStep(systemchanges.CertificateChange{Action: systemchanges.CertificateIPActivate, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", SubscriptionUnit: "sbxr-subscription.service"})
	var snapshot bytes.Buffer
	if err := executor.CaptureRollback(root, step, func(source io.Reader) error { _, err := io.Copy(&snapshot, source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(root, step, time.Minute, systemchanges.NewCancellation()); err != nil {
		t.Fatal(err)
	}
	if effect, err := executor.Inspect(root, step, bytes.NewReader(snapshot.Bytes()), time.Minute); err != nil || effect != systemchanges.StepEffectPresent {
		t.Fatalf("restart inspection = %s, %v", effect, err)
	}
	if err := executor.Cleanup(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(prior); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prior private-key set remains: %v", err)
	}
	current, err := os.Readlink(filepath.Join(base, "current"))
	if err != nil || current == "sets/ip-prior" {
		t.Fatalf("current pointer = %q, %v", current, err)
	}
}

func TestIPRollbackAcceptsNoPriorPointer(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	root, roots := writeCandidate(t, now, "192.0.2.10", false)
	executor := TransactionExecutor{now: func() time.Time { return now }, roots: roots, uid: os.Geteuid(), gid: os.Getegid(), run: func(context.Context, string, ...string) error { return nil }, prove: func(context.Context, string) error { return nil }}
	step, _ := systemchanges.NewCertificateStep(systemchanges.CertificateChange{Action: systemchanges.CertificateIPActivate, Identity: "192.0.2.10", RequiredProfile: "shortlived", CertName: "sbxr-ip", SubscriptionUnit: "sbxr-subscription.service"})
	if _, err := executor.Reverse(root, step, strings.NewReader(`{}`), time.Minute); err != nil {
		t.Fatalf("no-prior rollback = %v", err)
	}
}
