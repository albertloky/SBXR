package subscriptionserving_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

func TestHTTPSubscriptionServesAuthenticatedRealityArtifactWithoutCertificate(t *testing.T) {
	facts := profile(t)
	m := subscriptionserving.New(nil, nil)
	generation := subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}
	state, code := m.PrepareHTTP(facts, generation)
	if code != subscriptionserving.Ready || !m.Inspect(state).Expires.IsZero() {
		t.Fatal("HTTP preparation required certificate material")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan subscriptionserving.Code, 1)
	go func() { done <- m.Serve(ctx, state, listener) }()
	t.Cleanup(func() {
		cancel()
		if code := <-done; code != subscriptionserving.Stopped {
			t.Errorf("shutdown: %s", code)
		}
	})
	expected, _ := subscriptionserving.Artifact(facts)
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/s/" + credential, 200},
		{"GET", "/s/" + strings.Repeat("B", 43), 404},
		{"GET", "/s/" + credential + "?x=1", 404},
		{"POST", "/s/" + credential, 404},
		{"GET", "/s/" + credential + "/", 404},
		{"GET", "/", 404},
	} {
		conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", test.method, test.path)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		conn.Close()
		if err != nil || response.StatusCode != test.status || response.Header.Get("Cache-Control") != "no-store" || response.TLS != nil {
			t.Fatalf("HTTP result: %d %v", response.StatusCode, err)
		}
		if test.status == 200 && string(body) != string(expected) {
			t.Fatal("HTTP artifact differs from REALITY configuration")
		}
		if test.status != 200 && strings.Contains(string(body), facts.UUID) {
			t.Fatal("refusal disclosed proxy credentials")
		}
	}
}

func TestHTTPPreparationRejectsMissingAuthenticationAndInvalidProfile(t *testing.T) {
	m := subscriptionserving.New(nil, nil)
	facts := profile(t)
	if _, code := m.PrepareHTTP(facts, subscriptionserving.Generation{}); code != subscriptionserving.Refused {
		t.Fatal("empty credential authority accepted")
	}
	facts.PublicIPv4 = "::1"
	if _, code := m.PrepareHTTP(facts, subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}); code != subscriptionserving.Refused {
		t.Fatal("unsupported profile accepted")
	}
}
