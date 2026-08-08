package subscriptionserving

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/state"
	subscriptionpublication "github.com/albertloky/SBXR/internal/subscriptionpublication"
	publicationfilesystem "github.com/albertloky/SBXR/internal/subscriptionpublication/adapter/filesystem"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestServeSwitchesAuthorizationAndCompleteBodiesTogether(t *testing.T) {
	server, roots, oldToken, oldBody := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
	endpoint := "https://" + listener.Addr().String() + "/s/"

	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)

	newToken := strings.Repeat("9", 64)
	newRaw := []byte("vless://candidate")
	newBase64 := []byte(base64.StdEncoding.EncodeToString(newRaw))
	for _, name := range []string{"base64", "v2rayn", "shadowrocket"} {
		mustFile(t, server.root, artifactPath+"/"+name, newBase64, 0o640)
	}
	mustFile(t, server.root, artifactPath+"/raw", newRaw, 0o640)
	rewriteArtifactDigests(t, server)
	configuration, _ := json.Marshal(map[string]any{"token": newToken, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": "127.0.0.1"})
	mustFile(t, server.root, configurationPath, configuration, 0o640)

	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusOK, string(newBase64))
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusNotFound, "not found\n")
}

func TestConcurrentRequestsObserveOnlyOneCompleteServingSnapshot(t *testing.T) {
	server, roots, oldToken, oldBody := testServer(t, "127.0.0.1")
	newToken := strings.Repeat("9", 64)
	newRaw := []byte("vless://candidate")
	newBody := base64.StdEncoding.EncodeToString(newRaw)
	candidate := filepath.Join(server.root, "var/lib/sbxr/subscriptions/candidate")
	copyServingSnapshot(t, filepath.Join(server.root, artifactPath), candidate)
	writeCandidateSnapshot(t, candidate, newToken, newRaw)

	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1"), DisableKeepAlives: true}}
	endpoint := "https://" + listener.Addr().String() + "/s/"
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)

	results := make(chan struct {
		token, body string
		status      int
	}, 40)
	var workers sync.WaitGroup
	for index := range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			token := oldToken
			if index%2 == 1 {
				token = newToken
			}
			response, err := client.Get(endpoint + token)
			if err != nil {
				results <- struct {
					token, body string
					status      int
				}{token: token, status: -1, body: err.Error()}
				return
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			results <- struct {
				token, body string
				status      int
			}{token: token, status: response.StatusCode, body: string(body)}
		}()
		if index == 7 {
			activateServingSnapshot(t, server, candidate)
		}
	}
	workers.Wait()
	close(results)
	for result := range results {
		valid := result.status == http.StatusNotFound && result.body == "not found\n" || result.token == oldToken && result.status == http.StatusOK && result.body == oldBody || result.token == newToken && result.status == http.StatusOK && result.body == newBody
		if !valid {
			t.Fatalf("mixed serving snapshot: token suffix %q status %d body %q", result.token[len(result.token)-4:], result.status, result.body)
		}
	}
	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusOK, newBody)
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusNotFound, "not found\n")
}

func TestServePreservesDeliberateProfileDisablementAcrossActivation(t *testing.T) {
	server, roots, oldToken, _ := testServer(t, "127.0.0.1")
	oldArtifacts := installPublicationFixture(t, server, "2001:db8::10", false)
	candidateServer, _, _, _ := testServer(t, "127.0.0.1")
	newArtifacts := installPublicationFixture(t, candidateServer, "2001:db8::10", true)
	newToken := strings.Repeat("9", 64)
	configuration, _ := json.Marshal(map[string]any{"token": newToken, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": "127.0.0.1"})
	mustFile(t, candidateServer.root, configurationPath, configuration, 0o640)
	candidate := filepath.Join(server.root, "var/lib/sbxr/subscriptions/candidate-disabled")
	copyServingSnapshot(t, filepath.Join(candidateServer.root, artifactPath), candidate)

	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1"), DisableKeepAlives: true}}
	endpoint := "https://" + listener.Addr().String() + "/s/"
	assertSubscriptionResponse(t, client, endpoint+oldToken+"/sing-box", http.StatusOK, string(oldArtifacts.SingBox.Body))
	assertSubscriptionResponse(t, client, endpoint+oldToken+"/raw", http.StatusOK, string(oldArtifacts.Raw))
	activateServingSnapshot(t, server, candidate)
	assertSubscriptionResponse(t, client, endpoint+newToken+"/sing-box", http.StatusOK, string(newArtifacts.SingBox.Body))
	assertSubscriptionResponse(t, client, endpoint+newToken+"/raw", http.StatusOK, string(newArtifacts.Raw))
	assertSubscriptionResponse(t, client, endpoint+oldToken+"/sing-box", http.StatusNotFound, "not found\n")

	reenabledToken := strings.Repeat("8", 64)
	reenabled := filepath.Join(server.root, "var/lib/sbxr/subscriptions/prior")
	configuration, _ = json.Marshal(map[string]any{"token": reenabledToken, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": "127.0.0.1"})
	mustFile(t, reenabled, configurationName, configuration, 0o640)
	disabled := filepath.Join(server.root, "var/lib/sbxr/subscriptions/disabled")
	if os.Rename(filepath.Join(server.root, artifactPath), disabled) != nil || os.Rename(reenabled, filepath.Join(server.root, artifactPath)) != nil {
		t.Fatal("reactivate complete enabled serving snapshot")
	}
	assertSubscriptionResponse(t, client, endpoint+reenabledToken+"/sing-box", http.StatusOK, string(oldArtifacts.SingBox.Body))
	assertSubscriptionResponse(t, client, endpoint+reenabledToken+"/raw", http.StatusOK, string(oldArtifacts.Raw))
	assertSubscriptionResponse(t, client, endpoint+newToken+"/sing-box", http.StatusNotFound, "not found\n")
}

func TestServeKeepsThePreviousProvenHTTPSStateWhenCertificateActivationFails(t *testing.T) {
	server, roots, token, body := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1"), DisableKeepAlives: true}}
	endpoint := "https://" + listener.Addr().String() + "/s/" + token
	assertSubscriptionResponse(t, client, endpoint, http.StatusOK, body)

	invalid := "var/lib/sbxr/certificates/ip/sets/ip-invalid"
	mustDirectory(t, server.root, invalid, 0o750)
	pointer := filepath.Join(server.root, certificatePath)
	next := pointer + ".next"
	if os.Symlink("sets/ip-invalid", next) != nil || os.Rename(next, pointer) != nil {
		t.Fatal("activate invalid certificate pointer")
	}
	if health := server.Health(); health.Status != Failed || health.Code != "SUBSCRIPTION-SERVING-CERTIFICATE" {
		t.Fatalf("Health() = %+v", health)
	}
	assertSubscriptionResponse(t, client, endpoint, http.StatusOK, body)

	if os.Symlink("sets/ip-fixture", next) != nil || os.Rename(next, pointer) != nil {
		t.Fatal("restore prior certificate pointer")
	}
	if health := server.Health(); health.Status != Healthy || health.Code != "SUBSCRIPTION-SERVING-HTTPS" {
		t.Fatalf("Health() = %+v", health)
	}
	assertSubscriptionResponse(t, client, endpoint, http.StatusOK, body)
}

func TestServeRestartAndRollbackUseOnlyAProvenCompleteSnapshot(t *testing.T) {
	server, roots, oldToken, oldBody := testServer(t, "127.0.0.1")
	newToken := strings.Repeat("9", 64)
	newRaw := []byte("vless://candidate")
	newBody := base64.StdEncoding.EncodeToString(newRaw)
	candidate := filepath.Join(server.root, "var/lib/sbxr/subscriptions/candidate-restart")
	copyServingSnapshot(t, filepath.Join(server.root, artifactPath), candidate)
	writeCandidateSnapshot(t, candidate, newToken, newRaw)

	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1"), DisableKeepAlives: true}}
	endpoint := "https://" + listener.Addr().String() + "/s/"
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)
	activateServingSnapshot(t, server, candidate)
	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusOK, newBody)
	cancel()

	listener, cancel = startServer(t, server, "tcp4", "127.0.0.1:0")
	endpoint = "https://" + listener.Addr().String() + "/s/"
	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusOK, newBody)
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusNotFound, "not found\n")
	current := filepath.Join(server.root, artifactPath)
	rejected := filepath.Join(server.root, "var/lib/sbxr/subscriptions/rejected")
	prior := filepath.Join(server.root, "var/lib/sbxr/subscriptions/prior")
	if os.Rename(current, rejected) != nil || os.Rename(prior, current) != nil {
		t.Fatal("restore previous proven serving snapshot")
	}
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)
	cancel()

	listener, cancel = startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	endpoint = "https://" + listener.Addr().String() + "/s/"
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)
	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusNotFound, "not found\n")
}

func TestPublicationGateAndRollbackPassThroughServe(t *testing.T) {
	server, roots, oldToken, oldBody := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1"), DisableKeepAlives: true}}
	endpoint := "https://" + listener.Addr().String() + "/s/"
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)

	newToken := strings.Repeat("9", 64)
	newRaw := []byte("vless://transaction-candidate")
	newBody := base64.StdEncoding.EncodeToString(newRaw)
	prepared, binding, bundleSHA := preparedServingSet(t, server.root, newToken, newRaw)
	mustDirectory(t, server.root, "var/lib/sbxr/subscriptions/sets", 0o700)
	proofs := 0
	executor := publicationfilesystem.NewAt(server.uid, server.gid, func(_ context.Context, address string) error {
		proofs++
		if address != "198.51.100.10" {
			return errors.New("selected address mismatch")
		}
		if health := server.Health(); health.Status != Healthy {
			return errors.New(health.Code)
		}
		response, err := client.Get(endpoint + newToken)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK || string(body) != newBody {
			return errors.New("active response does not match Publication")
		}
		return nil
	})
	var rollback bytes.Buffer
	if err := executor.CaptureRollback(server.root, func(source io.Reader) error { _, err := io.Copy(&rollback, source); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Activate(server.root, prepared, binding, bundleSHA, time.Second); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"SUBSCRIPTION-PUBLICATION-CANDIDATE", "SUBSCRIPTION-PUBLICATION-ACTIVATION", "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT"} {
		if health, err := executor.Check(server.root, code, binding, bundleSHA, time.Second); health != systemchanges.Healthy || err != nil {
			t.Fatalf("Check(%s) = %s, %v", code, health, err)
		}
	}
	if proofs != 1 {
		t.Fatalf("Serve health proofs = %d", proofs)
	}
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusNotFound, "not found\n")

	invalid := "var/lib/sbxr/certificates/ip/sets/ip-invalid-gate"
	mustDirectory(t, server.root, invalid, 0o750)
	pointer := filepath.Join(server.root, certificatePath)
	next := pointer + ".next"
	if os.Symlink("sets/ip-invalid-gate", next) != nil || os.Rename(next, pointer) != nil {
		t.Fatal("activate invalid certificate candidate")
	}
	if health, err := executor.Check(server.root, "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT", binding, bundleSHA, time.Second); health != systemchanges.Failed || err == nil {
		t.Fatalf("failed post-publication gate = %s, %v", health, err)
	}
	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusOK, newBody)

	if os.Symlink("sets/ip-fixture", next) != nil || os.Rename(next, pointer) != nil {
		t.Fatal("restore proven certificate pointer")
	}
	if _, err := executor.Reverse(server.root, bytes.NewReader(rollback.Bytes()), time.Second); err != nil {
		t.Fatal(err)
	}
	if restored, err := server.load(); err != nil || restored.route != "/s/"+oldToken {
		t.Fatalf("restored Serve state = %q, %v", restored.route, err)
	}
	assertSubscriptionResponse(t, client, endpoint+oldToken, http.StatusOK, oldBody)
	assertSubscriptionResponse(t, client, endpoint+newToken, http.StatusNotFound, "not found\n")
}

func preparedServingSet(t *testing.T, root, token string, raw []byte) (string, systemchanges.StateTransactionBinding, string) {
	t.Helper()
	prepared := filepath.Join(root, "prepared", "subscription")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	bodies := map[string][]byte{"raw": raw, "base64": encoded, "v2rayn": encoded, "shadowrocket": encoded, "mihomo": []byte("proxies: []\n"), "sing-box": []byte(`{"outbounds":[]}`), "karing": []byte(`{"outbounds":[]}`)}
	digest := strings.Repeat("9", 64)
	release := state.ReleaseIdentity{Repository: "github.com/albertloky/SBXR", Tag: "v1.0.0", Commit: strings.Repeat("a", 40), ReleaseIndexSHA256: strings.Repeat("b", 64)}
	set, err := subscriptionpublication.NewPreparedArtifactSet(bodies, subscriptionpublication.Metadata{
		Schema: "sbxr-subscription-artifact-set-v1", ChangeSet: "change-0003", SelectedAddress: "198.51.100.10", DesiredStateSHA256: digest,
		ManagedInputsSHA256: strings.Repeat("e", 64), RelevantChecksums: subscriptionpublication.RelevantChecksums{ConnectionProfiles: strings.Repeat("f", 64), Subscription: strings.Repeat("1", 64)},
		Compatibility: string(subscriptionpublication.CurrentCompatibilityDefinition), DesiredStateRevision: 3, ReleaseIdentity: release,
		Representations: subscriptionpublication.Names()[:7], ProfileCount: 1, Omissions: []subscriptionpublication.Omission{{ID: "vless-xhttp"}, {ID: "vless-websocket"}, {ID: "hysteria2"}, {ID: "tuic"}, {ID: "anytls"}}, ValidationComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := set.Bundle()
	configuration, _ := json.Marshal(map[string]any{"token": token, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": "127.0.0.1"})
	if err != nil || os.WriteFile(filepath.Join(prepared, "subscriptions.bundle"), bundle, 0o600) != nil || os.WriteFile(filepath.Join(prepared, "subscription.json"), configuration, 0o600) != nil {
		t.Fatal("write prepared serving transaction")
	}
	binding := systemchanges.StateTransactionBinding{ChangeSet: "change-0003", CandidateRevision: 3, CandidateSHA256: digest, CandidateRelease: systemchanges.ReleaseBinding{Repository: release.Repository, Tag: release.Tag, Commit: release.Commit, ReleaseIndexSHA256: release.ReleaseIndexSHA256}}
	return prepared, binding, subscriptionpublication.BundleSHA256(bundle)
}

func activateServingSnapshot(t *testing.T, server Server, candidate string) {
	t.Helper()
	current := filepath.Join(server.root, artifactPath)
	prior := filepath.Join(server.root, "var/lib/sbxr/subscriptions/prior")
	if os.Rename(current, prior) != nil || os.Rename(candidate, current) != nil {
		t.Fatal("activate complete serving snapshot")
	}
}

func copyServingSnapshot(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.Mkdir(destination, 0o750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil || os.WriteFile(filepath.Join(destination, entry.Name()), body, 0o640) != nil {
			t.Fatalf("copy serving snapshot %s: %v", entry.Name(), err)
		}
	}
}

func writeCandidateSnapshot(t *testing.T, directory, token string, raw []byte) {
	t.Helper()
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	for _, name := range []string{"base64", "v2rayn", "shadowrocket"} {
		mustFile(t, directory, name, encoded, 0o640)
	}
	mustFile(t, directory, "raw", raw, 0o640)
	metadataPath := filepath.Join(directory, "metadata")
	var metadata map[string]any
	body, _ := os.ReadFile(metadataPath)
	if json.Unmarshal(body, &metadata) != nil {
		t.Fatal("decode candidate metadata")
	}
	digests := map[string]string{}
	for _, name := range []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box"} {
		body, _ := os.ReadFile(filepath.Join(directory, name))
		digest := sha256.Sum256(body)
		digests[name] = hex.EncodeToString(digest[:])
	}
	metadata["artifact_sha256"] = digests
	body, _ = json.Marshal(metadata)
	mustFile(t, directory, "metadata", body, 0o640)
	configuration, _ := json.Marshal(map[string]any{"token": token, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": "127.0.0.1"})
	mustFile(t, directory, configurationName, configuration, 0o640)
}

func assertSubscriptionResponse(t *testing.T, client *http.Client, endpoint string, status int, body string) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != status || string(got) != body {
		t.Fatalf("GET subscription = %d, %q", response.StatusCode, got)
	}
}
