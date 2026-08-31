package subscriptionserving_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

const credential = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func material(t *testing.T, until time.Time) (subscriptionserving.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test only"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("test root failed")
	}
	ca, _ = x509.ParseCertificate(root)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: until, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal("test leaf failed")
	}
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return subscriptionserving.Certificate{Chain: cert, Key: keyPEM, ChainSHA256: sha256.Sum256(cert), KeySHA256: sha256.Sum256(keyPEM), Lineage: "sbxr-subscription", Generation: 1}, pool
}

func profile(t *testing.T) singbox.ConnectionFacts {
	t.Helper()
	identity := singbox.Identity{UUID: "12345678-1234-4234-8234-123456789abc", PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PublicKey: "L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q", ShortID: "01020304"}
	// The Adapter derives the public key from the server configuration.
	key, err := singbox.New().PrepareIdentity()
	if err != nil {
		t.Fatal("test identity failed")
	}
	identity.PrivateKey, identity.PublicKey = key.PrivateKey, key.PublicKey
	body, err := singbox.New().EncodeServerConfiguration(identity, "google.com:443", "google.com")
	if err != nil {
		t.Fatal("test configuration failed")
	}
	facts, err := singbox.New().CurrentConnectionFacts(body, "127.0.0.1")
	if err != nil {
		t.Fatal("test facts failed")
	}
	return facts
}

func TestServeExactAuthenticatedArtifact(t *testing.T) {
	cert, roots := material(t, time.Now().Add(time.Hour/2))
	module := subscriptionserving.New(roots, nil)
	facts := profile(t)
	state, code := module.Prepare(facts, subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}, cert)
	if code != subscriptionserving.Ready {
		t.Fatalf("prepare: %s", code)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan subscriptionserving.Code, 1)
	go func() { done <- module.Serve(ctx, state, listener) }()
	t.Cleanup(func() {
		cancel()
		if <-done != subscriptionserving.Stopped {
			t.Error("shutdown failed")
		}
	})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 3 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get("https://" + listener.Addr().String() + "/s/" + credential)
	if err != nil {
		t.Fatal("HTTPS request failed")
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	want := "vless://12345678-1234-4234-8234-123456789abc@127.0.0.1:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=google.com&fp=chrome&pbk=" + facts.PublicKey + "&sid=01020304&type=tcp#SBXR%20Proxy%20%28127.0.0.1%29\n"
	if response.StatusCode != 200 || string(body) != want {
		t.Fatal("exact artifact contract failed")
	}
	if response.Header.Get("Content-Type") != "text/plain; charset=utf-8" || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("response headers failed")
	}
}

func start(t *testing.T, until time.Time, distinctSources ...bool) (*subscriptionserving.Module, *subscriptionserving.State, *tls.Config, net.Listener, context.CancelFunc, <-chan subscriptionserving.Code) {
	t.Helper()
	cert, roots := material(t, until)
	module := subscriptionserving.New(roots, nil)
	state, code := module.Prepare(profile(t), subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}, cert)
	if code != subscriptionserving.Ready {
		t.Fatal("prepare failed")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan subscriptionserving.Code, 1)
	if len(distinctSources) > 0 && distinctSources[0] {
		listener = &sourceListener{Listener: listener}
	}
	go func() { done <- module.Serve(ctx, state, listener) }()
	t.Cleanup(cancel)
	return module, state, &tls.Config{RootCAs: roots}, listener, cancel, done
}

func request(t *testing.T, address string, config *tls.Config, raw string) (int, http.Header, string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp4", address, config)
	if err != nil {
		t.Fatal("TLS connection failed")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal("request write failed")
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal("response read failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("response body failed")
	}
	return response.StatusCode, response.Header, string(body)
}

func TestConcealedRefusalForEveryUnauthorizedRequest(t *testing.T) {
	for _, raw := range []string{
		"GET / HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/short HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/" + strings.Repeat("B", 43) + " HTTP/1.1\r\nHost: example\r\n\r\n",
		"POST /s/" + credential + " HTTP/1.1\r\nHost: example\r\n\r\n",
		"HEAD /s/" + credential + " HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/" + credential + "? HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/" + credential + "?x=1 HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/" + credential + " HTTP/1.1\r\nHost: example\r\nContent-Length: 1\r\n\r\nx",
		"GET /s/" + credential + " HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"GET https://example/s/" + credential + " HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/%41" + credential[1:] + " HTTP/1.1\r\nHost: example\r\n\r\n",
		"GET /s/" + credential + " HTTP/1.1\r\nHost: example\r\nX-Large: " + strings.Repeat("x", 8192) + "\r\n\r\n",
	} {
		t.Run("concealed", func(t *testing.T) {
			_, _, config, listener, cancel, done := start(t, time.Now().Add(time.Minute))
			status, headers, body := request(t, listener.Addr().String(), config, raw)
			if status != 404 || body != "Not Found\n" || headers.Get("Cache-Control") != "no-store" || headers.Get("Location") != "" || headers.Get("Set-Cookie") != "" || headers.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("concealed refusal failed")
			}
			cancel()
			if <-done != subscriptionserving.Stopped {
				t.Fatal("shutdown failed")
			}
		})
	}
}

func TestRemoteAddressBurstAndRefillIgnoreForwardedHeaders(t *testing.T) {
	_, _, config, listener, cancel, done := start(t, time.Now().Add(time.Minute))
	for i := 0; i < 8; i++ {
		status, headers, body := request(t, listener.Addr().String(), config, "GET / HTTP/1.1\r\nHost: example\r\nX-Forwarded-For: 203.0.113."+string(rune('1'+i))+"\r\n\r\n")
		want := 404
		if i >= 6 {
			want = 429
		}
		if status != want || i >= 6 && (headers.Get("Retry-After") != "10" || body != "Too Many Requests\n") {
			t.Fatal("source allowance failed")
		}
	}
	time.Sleep(10 * time.Second)
	status, _, _ := request(t, listener.Addr().String(), config, "GET / HTTP/1.1\r\nHost: example\r\n\r\n")
	if status != 404 {
		t.Fatal("refill failed")
	}
	cancel()
	if <-done != subscriptionserving.Stopped {
		t.Fatal("shutdown failed")
	}
}

func TestSlowTLSHeadersAndShutdownStayBounded(t *testing.T) {
	_, _, config, listener, cancel, done := start(t, time.Now().Add(time.Minute), true)
	var clients []net.Conn
	for i := 0; i < 8; i++ {
		conn, err := tls.Dial("tcp4", listener.Addr().String(), config)
		if err != nil {
			t.Fatal("slow client failed")
		}
		clients = append(clients, conn)
		io.WriteString(conn, "GET /s/")
	}
	status, headers, body := request(t, listener.Addr().String(), config, "GET / HTTP/1.1\r\nHost: example\r\n\r\n")
	if status != 503 || headers.Get("Retry-After") != "10" || body != "Service Unavailable\n" {
		t.Fatal("executing ceiling failed")
	}
	cancel()
	select {
	case code := <-done:
		if code != subscriptionserving.Stopped {
			t.Fatal("shutdown outcome failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not end accepted work")
	}
	for _, conn := range clients {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 1)
		if _, err := conn.Read(buffer); err == nil {
			t.Error("accepted client still open")
		}
		conn.Close()
	}
}

func TestCertificateRejectionPreservesLoadedStateAndExpiryClosesListener(t *testing.T) {
	m, state, config, listener, _, done := start(t, time.Now().Add(3*time.Second))
	bad, _ := material(t, time.Now().Add(time.Minute))
	bad.KeySHA256 = [32]byte{}
	if next, code := m.Prepare(profile(t), subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}, bad); next != nil || code != subscriptionserving.Refused {
		t.Fatal("invalid replacement accepted")
	}
	if m.Inspect(state).Code != subscriptionserving.Ready {
		t.Fatal("valid loaded state lost")
	}
	status, _, _ := request(t, listener.Addr().String(), config, "GET /s/"+credential+" HTTP/1.1\r\nHost: example\r\n\r\n")
	if status != 200 {
		t.Fatal("loaded state not serving")
	}
	select {
	case code := <-done:
		if code != subscriptionserving.Expired {
			t.Fatal("expiry outcome failed")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("expiry did not stop listener")
	}
	if m.Inspect(state).Code != subscriptionserving.Expired {
		t.Fatal("expired state reported ready")
	}
	if m.Inspect(state).Runtime != subscriptionserving.RuntimeStopped {
		t.Fatal("ended runtime not proved stopped")
	}
	if conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("expired listener accepted")
	}
}

type sourceListener struct {
	net.Listener
	next atomic.Uint32
}
type sourceConn struct {
	net.Conn
	source net.Addr
}

func (c sourceConn) RemoteAddr() net.Addr { return c.source }
func (l *sourceListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	i := l.next.Add(1)
	return sourceConn{Conn: conn, source: &net.TCPAddr{IP: net.IPv4(192, 0, byte(i>>8), byte(i)), Port: 1234}}, nil
}

func TestSourceTableIsBoundedAndIdleSourcesExpire(t *testing.T) {
	cert, roots := material(t, time.Now().Add(30*time.Minute))
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	m := subscriptionserving.New(roots, func() time.Time { return time.Unix(0, clock.Load()) })
	state, code := m.Prepare(profile(t), subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}, cert)
	if code != subscriptionserving.Ready {
		t.Fatal("prepare failed")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan subscriptionserving.Code, 1)
	go func() { done <- m.Serve(ctx, state, &sourceListener{Listener: listener}) }()
	config := &tls.Config{RootCAs: roots}
	for i := 0; i < 1025; i++ {
		status, _, _ := request(t, listener.Addr().String(), config, "GET / HTTP/1.1\r\nHost: example\r\n\r\n")
		want := 404
		if i == 1024 {
			want = 429
		}
		if status != want {
			t.Fatalf("source table bound failed at entry %d", i)
		}
	}
	clock.Add(int64(10 * time.Minute))
	status, _, _ := request(t, listener.Addr().String(), config, "GET / HTTP/1.1\r\nHost: example\r\n\r\n")
	if status != 404 {
		t.Fatal("idle sources did not expire")
	}
	cancel()
	if <-done != subscriptionserving.Stopped {
		t.Fatal("shutdown failed")
	}
}

func TestPrepareRejectsCertificateAndProfileConflicts(t *testing.T) {
	cert, roots := material(t, time.Now().Add(time.Minute))
	facts := profile(t)
	generation := subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}
	for _, mutate := range []func(*singbox.ConnectionFacts, *subscriptionserving.Generation, *subscriptionserving.Certificate){
		func(f *singbox.ConnectionFacts, _ *subscriptionserving.Generation, _ *subscriptionserving.Certificate) {
			f.PublicIPv4 = "8.8.8.8"
		},
		func(f *singbox.ConnectionFacts, _ *subscriptionserving.Generation, _ *subscriptionserving.Certificate) {
			f.UUID = "not a UUID"
		},
		func(f *singbox.ConnectionFacts, _ *subscriptionserving.Generation, _ *subscriptionserving.Certificate) {
			f.ServerName = "name\nsecond node"
		},
		func(f *singbox.ConnectionFacts, _ *subscriptionserving.Generation, _ *subscriptionserving.Certificate) {
			f.ServerName = strings.Repeat("a", 4096)
		},
		func(f *singbox.ConnectionFacts, _ *subscriptionserving.Generation, _ *subscriptionserving.Certificate) {
			f.ShortID = "01020304&other=node"
		},
		func(_ *singbox.ConnectionFacts, g *subscriptionserving.Generation, _ *subscriptionserving.Certificate) {
			g.CredentialSHA256 = [32]byte{}
		},
		func(_ *singbox.ConnectionFacts, _ *subscriptionserving.Generation, c *subscriptionserving.Certificate) {
			c.Lineage = "unrelated"
		},
		func(_ *singbox.ConnectionFacts, _ *subscriptionserving.Generation, c *subscriptionserving.Certificate) {
			c.Generation = 0
		},
		func(_ *singbox.ConnectionFacts, _ *subscriptionserving.Generation, c *subscriptionserving.Certificate) {
			c.ChainSHA256 = [32]byte{}
		},
		func(_ *singbox.ConnectionFacts, _ *subscriptionserving.Generation, c *subscriptionserving.Certificate) {
			replacement, _ := material(t, time.Now().Add(time.Minute))
			c.Key = replacement.Key
			c.KeySHA256 = replacement.KeySHA256
		},
	} {
		t.Run("refused", func(t *testing.T) {
			f, g, c := facts, generation, cert
			mutate(&f, &g, &c)
			if state, code := subscriptionserving.New(roots, nil).Prepare(f, g, c); state != nil || code != subscriptionserving.Refused {
				t.Fatal("unsafe serving state accepted")
			}
		})
	}
	if _, code := subscriptionserving.New(x509.NewCertPool(), nil).Prepare(facts, generation, cert); code != subscriptionserving.Refused {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestServingValuesAreRedactedFromOrdinaryDiagnostics(t *testing.T) {
	cert, roots := material(t, time.Now().Add(time.Minute))
	facts := profile(t)
	generation := subscriptionserving.Generation{LinkID: strings.Repeat("a", 32), CredentialSHA256: sha256.Sum256([]byte(credential))}
	state, code := subscriptionserving.New(roots, nil).Prepare(facts, generation, cert)
	if code != subscriptionserving.Ready {
		t.Fatal("prepare failed")
	}
	for _, value := range []any{facts, generation, cert, state} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal("diagnostic encoding failed")
		}
		output := fmt.Sprintf("%+v %#v %s", value, value, encoded)
		for _, secret := range []string{facts.UUID, facts.PublicKey, credential, string(cert.Key), fmt.Sprintf("%x", generation.CredentialSHA256)} {
			if strings.Contains(output, secret) {
				t.Fatal("ordinary diagnostics expose secret-bearing state")
			}
		}
	}
}
