package filesystem_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/state"
	subscriptionpublication "github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestAtomicArtifactSetActivationRollbackAndServingAgreement(t *testing.T) {
	root := t.TempDir()
	prepared8 := preparedSet(t, root, 8, strings.Repeat("8", 64), "BODY-N8")
	proofs := 0
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(_ context.Context, address string) error {
		proofs++
		if address != "198.51.100.10" {
			return errors.New("wrong address")
		}
		return nil
	})
	var absent bytes.Buffer
	if err := executor.CaptureRollback(root, func(source io.Reader) error { _, err := io.Copy(&absent, source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Activate(root, prepared8, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared8), time.Second); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "var/lib/sbxr/subscriptions/current")
	first := "sets/revision-00000000000000000008-888888888888"
	if info, err := os.Lstat(current); err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Fatalf("current = %v, %v", info, err)
	}
	for _, name := range subscriptionpublication.Names() {
		info, err := os.Lstat(filepath.Join(current, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode = %v, %v", name, info, err)
		}
	}
	if configuration, err := os.ReadFile(filepath.Join(current, "serving.json")); err != nil || !bytes.Contains(configuration, []byte(`"listen_port":10443`)) {
		t.Fatalf("active serving configuration = %q, %v", configuration, err)
	}
	for _, code := range []string{"SUBSCRIPTION-PUBLICATION-CANDIDATE", "SUBSCRIPTION-PUBLICATION-ACTIVATION", "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"} {
		if health, err := executor.Check(root, code, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared8), time.Second); health != systemchanges.Healthy || err != nil {
			t.Fatalf("Check(%s) = %s, %v", code, health, err)
		}
	}
	published, err := executor.ObserveCurrent(root, time.Second)
	if err != nil || published.Revision != 8 || published.StateSHA256 != strings.Repeat("8", 64) || published.Compatibility != subscriptionpublication.CurrentCompatibilityDefinition || published.Serving != systemchanges.Healthy {
		t.Fatalf("current publication = %#v, %v", published, err)
	}
	if proofs != 2 {
		t.Fatalf("serving proofs = %d", proofs)
	}

	var prior bytes.Buffer
	if err := executor.CaptureRollback(root, func(source io.Reader) error { _, err := io.Copy(&prior, source); return err }); err != nil {
		t.Fatal(err)
	}
	prepared9 := preparedSet(t, root, 9, strings.Repeat("9", 64), "BODY-N9")
	if _, err := executor.Activate(root, prepared9, binding(9, strings.Repeat("9", 64)), preparedSHA(t, prepared9), time.Second); err != nil {
		t.Fatal(err)
	}
	second := "sets/revision-00000000000000000009-999999999999"
	setsInfo, _ := os.Stat(filepath.Join(root, "var/lib/sbxr/subscriptions/sets"))
	priorInfo, _ := os.Stat(filepath.Join(root, "var/lib/sbxr/subscriptions", first))
	activeInfo, _ := os.Stat(current)
	if setsInfo.Mode().Perm() != 0o700 || priorInfo.Mode().Perm() != 0o700 || activeInfo.Mode().Perm() != 0o750 {
		t.Fatalf("serving traversal modes = sets %o, prior %o, active %o", setsInfo.Mode().Perm(), priorInfo.Mode().Perm(), activeInfo.Mode().Perm())
	}
	if _, err := executor.Reverse(root, bytes.NewReader(prior.Bytes()), time.Second); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(filepath.Join(current, "raw")); !bytes.Contains(raw, []byte("BODY-N8")) {
		t.Fatalf("rollback did not restore N8: %q", raw)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/sbxr/subscriptions", second)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back candidate remains: %v", err)
	}

	if _, err := executor.Reverse(root, bytes.NewReader(absent.Bytes()), time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(current); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh-install rollback left current: %v", err)
	}
}

func TestProductionExecutorRequiresServingProof(t *testing.T) {
	if _, err := filesystem.New(nil); err == nil {
		t.Fatal("production executor accepted no Subscription Serving health proof")
	}
}

func TestActivationFailsClosedAtCandidateAndServingBoundaries(t *testing.T) {
	root := t.TempDir()
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return errors.New("controlled health failure") })
	prepared := preparedSet(t, root, 8, strings.Repeat("8", 64), "SECRET-MARKER")
	if err := os.WriteFile(filepath.Join(prepared, "subscriptions.bundle"), []byte("SECRET-MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Activate(root, prepared, binding(8, strings.Repeat("8", 64)), strings.Repeat("0", 64), time.Second); err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("incomplete activation error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "var/lib/sbxr/subscriptions/current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed activation changed current: %v", err)
	}

	prepared = preparedSet(t, root, 8, strings.Repeat("8", 64), "SECRET-MARKER")
	if _, err := executor.Activate(root, prepared, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared), time.Second); err != nil {
		t.Fatal(err)
	}
	if health, err := executor.Check(root, "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT", binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared), time.Second); health != systemchanges.Failed || err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("serving refusal = %s, %v", health, err)
	}
}

func TestActivationRejectsAnUnsafePreparedServingConfiguration(t *testing.T) {
	root := t.TempDir()
	prepared := preparedSet(t, root, 8, strings.Repeat("8", 64), "BODY-N8")
	configuration := filepath.Join(prepared, "subscription.json")
	outside := filepath.Join(root, "SECRET-CONFIGURATION-MARKER")
	if os.WriteFile(outside, []byte(`{"token":"SECRET-CONFIGURATION-MARKER"}`), 0o600) != nil || os.Remove(configuration) != nil || os.Symlink(outside, configuration) != nil {
		t.Fatal("prepare hostile serving configuration")
	}
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return nil })
	if _, err := executor.Activate(root, prepared, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared), time.Second); err == nil || strings.Contains(err.Error(), "SECRET-CONFIGURATION-MARKER") {
		t.Fatalf("unsafe serving configuration activation = %v", err)
	}
}

func TestRestartInspectionFindsAndRemovesAnInactiveCandidate(t *testing.T) {
	root := t.TempDir()
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return nil })
	var snapshot bytes.Buffer
	if err := executor.CaptureRollback(root, func(source io.Reader) error { _, err := io.Copy(&snapshot, source); return err }); err != nil {
		t.Fatal(err)
	}
	prepared := preparedSet(t, root, 8, strings.Repeat("8", 64), "BODY-N8")
	if _, err := executor.Activate(root, prepared, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared), time.Second); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "var/lib/sbxr/subscriptions/current")
	target := filepath.Join(root, "var/lib/sbxr/subscriptions/sets/revision-00000000000000000008-888888888888")
	if err := os.Chmod(current, 0o700); err != nil || os.Rename(current, target) != nil {
		t.Fatal(err)
	}
	if effect, err := executor.Inspect(root, bytes.NewReader(snapshot.Bytes()), time.Second); effect != systemchanges.StepEffectPresent || err != nil {
		t.Fatalf("Inspect interrupted switch = %s, %v", effect, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := executor.Reverse(root, bytes.NewReader(snapshot.Bytes()), time.Second); err != nil {
			t.Fatalf("Reverse retry %d: %v", attempt+1, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "var/lib/sbxr/subscriptions/sets"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("inactive candidates after recovery = %v, %v", entries, err)
	}
}

func TestRestartReconcilesAnInterruptedDirectoryExchange(t *testing.T) {
	root := t.TempDir()
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return nil })
	prepared8 := preparedSet(t, root, 8, strings.Repeat("8", 64), "BODY-N8")
	if _, err := executor.Activate(root, prepared8, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared8), time.Second); err != nil {
		t.Fatal(err)
	}
	var prior bytes.Buffer
	if err := executor.CaptureRollback(root, func(source io.Reader) error { _, err := io.Copy(&prior, source); return err }); err != nil {
		t.Fatal(err)
	}
	prepared9 := preparedSet(t, root, 9, strings.Repeat("9", 64), "BODY-N9")
	if _, err := executor.Activate(root, prepared9, binding(9, strings.Repeat("9", 64)), preparedSHA(t, prepared9), time.Second); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "var/lib/sbxr/subscriptions")
	current := filepath.Join(base, "current")
	priorPath := filepath.Join(base, "sets/revision-00000000000000000008-888888888888")
	temporary := filepath.Join(base, ".interrupted-exchange")
	if err := os.Rename(current, temporary); err != nil || os.Rename(priorPath, current) != nil || os.Rename(temporary, priorPath) != nil {
		t.Fatal("simulate interruption after exchange")
	}
	if err := os.Chmod(current, 0o750); err != nil || os.Chmod(priorPath, 0o700) != nil {
		t.Fatal("simulate interrupted exchange permissions")
	}
	if effect, err := executor.Inspect(root, bytes.NewReader(prior.Bytes()), time.Second); effect != systemchanges.StepEffectPresent || err != nil {
		t.Fatalf("Inspect interrupted exchange = %s, %v", effect, err)
	}
	if _, err := executor.Reverse(root, bytes.NewReader(prior.Bytes()), time.Second); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(filepath.Join(base, "sets")); err != nil || len(entries) != 0 {
		t.Fatalf("interrupted exchange cleanup = %v, %v", entries, err)
	}
}

func TestRestartRestoresPriorBeforeInactiveModeSettles(t *testing.T) {
	root := t.TempDir()
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return nil })
	prepared8 := preparedSet(t, root, 8, strings.Repeat("8", 64), "BODY-N8")
	if _, err := executor.Activate(root, prepared8, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared8), time.Second); err != nil {
		t.Fatal(err)
	}
	var prior bytes.Buffer
	if err := executor.CaptureRollback(root, func(source io.Reader) error { _, err := io.Copy(&prior, source); return err }); err != nil {
		t.Fatal(err)
	}
	prepared9 := preparedSet(t, root, 9, strings.Repeat("9", 64), "BODY-N9")
	if _, err := executor.Activate(root, prepared9, binding(9, strings.Repeat("9", 64)), preparedSHA(t, prepared9), time.Second); err != nil {
		t.Fatal(err)
	}
	priorPath := filepath.Join(root, "var/lib/sbxr/subscriptions/sets/revision-00000000000000000008-888888888888")
	if err := os.Chmod(priorPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Reverse(root, bytes.NewReader(prior.Bytes()), time.Second); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "var/lib/sbxr/subscriptions/current/raw"))
	if !bytes.Contains(raw, []byte("BODY-N8")) {
		t.Fatalf("transient prior mode did not restore N8: %q", raw)
	}
}

func TestStorageFailureLeavesPriorGenerationActive(t *testing.T) {
	root := t.TempDir()
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return nil })
	firstPrepared := preparedSet(t, root, 8, strings.Repeat("8", 64), "BODY-N8")
	if _, err := executor.Activate(root, firstPrepared, binding(8, strings.Repeat("8", 64)), preparedSHA(t, firstPrepared), time.Second); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "var/lib/sbxr/subscriptions/current")
	blocked := filepath.Join(root, "var/lib/sbxr/subscriptions/sets/revision-00000000000000000009-999999999999.preparing")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	secondPrepared := preparedSet(t, root, 9, strings.Repeat("9", 64), "BODY-N9")
	if _, err := executor.Activate(root, secondPrepared, binding(9, strings.Repeat("9", 64)), preparedSHA(t, secondPrepared), time.Second); err == nil {
		t.Fatal("blocked storage preparation succeeded")
	}
	info, _ := os.Stat(current)
	raw, _ := os.ReadFile(filepath.Join(current, "raw"))
	if info.Mode().Perm() != 0o750 || !bytes.Contains(raw, []byte("BODY-N8")) {
		t.Fatalf("failed storage changed current mode=%o raw=%q", info.Mode().Perm(), raw)
	}
}

func TestActivationRejectsHostileParentSymlinkAndWrongStateBinding(t *testing.T) {
	executor := filesystem.NewAt(os.Geteuid(), os.Getegid(), func(context.Context, string) error { return nil })
	prepared := preparedSet(t, t.TempDir(), 8, strings.Repeat("8", 64), "SECRET-MARKER")
	for _, final := range []bool{false, true} {
		root := t.TempDir()
		outside := t.TempDir()
		link := filepath.Join(root, "var/lib/sbxr")
		if final {
			if err := os.MkdirAll(link, 0o755); err != nil {
				t.Fatal(err)
			}
			link = filepath.Join(link, "subscriptions")
		} else if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal("prepare hostile symlink")
		}
		if _, err := executor.Activate(root, prepared, binding(8, strings.Repeat("8", 64)), preparedSHA(t, prepared), time.Second); err == nil {
			t.Fatal("hostile symlink was accepted")
		}
		entries, _ := os.ReadDir(outside)
		if len(entries) != 0 {
			t.Fatalf("hostile symlink changed outside directory: %v", entries)
		}
	}

	root := t.TempDir()
	if _, err := executor.Activate(root, prepared, binding(9, strings.Repeat("9", 64)), preparedSHA(t, prepared), time.Second); err == nil {
		t.Fatal("artifact set for a different State transaction was accepted")
	}
	if _, err := executor.Activate(root, prepared, binding(8, strings.Repeat("8", 64)), strings.Repeat("0", 64), time.Second); err == nil {
		t.Fatal("artifact set with a different Plan SHA-256 was accepted")
	}
}

func preparedSet(t *testing.T, root string, revision uint64, digest, marker string) string {
	t.Helper()
	directory := filepath.Join(root, "prepared", marker, string(rune('0'+revision)))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(strings.Join([]string{marker + "-1", marker + "-2", marker + "-3", marker + "-4", marker + "-5", marker + "-6"}, "\n"))
	base64Body := []byte(base64.StdEncoding.EncodeToString(raw))
	bodies := map[string][]byte{"raw": raw, "base64": base64Body, "v2rayn": base64Body, "shadowrocket": base64Body, "mihomo": []byte("proxies: []\n"), "sing-box": []byte(`{"outbounds":[]}`), "karing": []byte(`{"outbounds":[]}`)}
	names := subscriptionpublication.Names()
	set, err := subscriptionpublication.NewPreparedArtifactSet(bodies, subscriptionpublication.Metadata{Schema: "sbxr-subscription-artifact-set-v1", ChangeSet: "change-0008", SelectedAddress: "198.51.100.10", DesiredStateSHA256: digest, ManagedInputsSHA256: strings.Repeat("a", 64), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("b", 64), Subscription: strings.Repeat("c", 64)}, Compatibility: string(subscriptionpublication.CurrentCompatibilityDefinition), DesiredStateRevision: revision, ReleaseIdentity: state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("d", 40), ReleaseIndexSHA256: strings.Repeat("e", 64)}, Representations: names[:7], ProfileCount: 6, ValidationComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := set.Bundle()
	configuration := []byte(`{"token":"` + strings.Repeat("6", 64) + `","listen_port":10443,"certificate_pointer":"/var/lib/sbxr/certificates/ip/current","primary_address":"198.51.100.10"}`)
	if err != nil || os.WriteFile(filepath.Join(directory, "subscriptions.bundle"), bundle, 0o600) != nil || os.WriteFile(filepath.Join(directory, "subscription.json"), configuration, 0o600) != nil {
		t.Fatal("write prepared artifact bundle")
	}
	return directory
}

func binding(revision uint64, digest string) systemchanges.StateTransactionBinding {
	return systemchanges.StateTransactionBinding{ChangeSet: "change-0008", CandidateRevision: revision, CandidateSHA256: digest, CandidateRelease: systemchanges.ReleaseBinding{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("d", 40), ReleaseIndexSHA256: strings.Repeat("e", 64)}}
}

func preparedSHA(t *testing.T, directory string) string {
	t.Helper()
	bundle, err := os.ReadFile(filepath.Join(directory, "subscriptions.bundle"))
	if err != nil {
		t.Fatal(err)
	}
	return subscriptionpublication.BundleSHA256(bundle)
}
