package subscriptionserving

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeReturnsTheExactBase64ArtifactOverTrustedTLS(t *testing.T) {
	server, roots, token, body := testServer(t, "127.0.0.1")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(ctx, listener) }()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
	response, err := client.Get("https://" + listener.Addr().String() + "/s/" + token)
	if err != nil {
		select {
		case serveErr := <-serveError:
			t.Fatalf("Serve: %v; GET: %v", serveErr, err)
		default:
			t.Fatal(err)
		}
	}
	defer response.Body.Close()
	got, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(got) != body {
		t.Fatalf("GET base route = %d %q", response.StatusCode, got)
	}
	for name, want := range map[string]string{
		"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "private, no-store",
		"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
	} {
		if response.Header.Get(name) != want {
			t.Fatalf("%s = %q, want %q", name, response.Header.Get(name), want)
		}
	}
}

func TestServeRefusesEveryOtherBasicRouteAndTokenShape(t *testing.T) {
	server, roots, token, _ := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
	base := "https://" + listener.Addr().String()
	requests := []struct{ method, path string }{
		{http.MethodGet, "/" + token},
		{http.MethodGet, "/s/" + token[:63]},
		{http.MethodGet, "/s/" + token + "0"},
		{http.MethodGet, "/s/" + strings.Repeat("0", 64)},
		{http.MethodGet, "/s/" + token + "/base64"},
		{http.MethodGet, "/s/" + token + "?format=base64"},
		{http.MethodPost, "/s/" + token},
	}
	for _, check := range requests {
		request, _ := http.NewRequest(check.method, base+check.path, nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound || string(body) != "not found\n" {
			t.Fatalf("%s %s = %d %q", check.method, check.path, response.StatusCode, body)
		}
	}
	requestURL, _ := url.Parse(base + "/s/" + token)
	requestURL.RawPath = "/s/%30" + token[1:]
	request, _ := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	request.URL.RawPath = requestURL.RawPath
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("encoded token route = %d", response.StatusCode)
	}
}

func TestServeFailsClosedOnUnsafeInputs(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, server *Server)
	}{
		{"short token", func(t *testing.T, server *Server) {
			path := filepath.Join(server.root, configurationPath)
			body, _ := os.ReadFile(path)
			mustFile(t, server.root, configurationPath, []byte(strings.Replace(string(body), "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "01", 1)), 0o640)
		}},
		{"writable artifact", func(t *testing.T, server *Server) {
			if err := os.Chmod(filepath.Join(server.root, artifactPath, "base64"), 0o660); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable parent", func(t *testing.T, server *Server) {
			if err := os.Chmod(filepath.Join(server.root, "var/lib/sbxr/subscriptions"), 0o770); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong owner", func(_ *testing.T, server *Server) { server.uid++ }},
		{"artifact symlink", func(t *testing.T, server *Server) {
			path := filepath.Join(server.root, artifactPath, "base64")
			if err := os.Remove(path); err != nil || os.Symlink("raw", path) != nil {
				t.Fatal("replace artifact with symlink")
			}
		}},
		{"mismatched certificate", func(t *testing.T, server *Server) {
			path := filepath.Join(server.root, configurationPath)
			body, _ := os.ReadFile(path)
			mustFile(t, server.root, configurationPath, []byte(strings.Replace(string(body), "127.0.0.1", "127.0.0.2", 1)), 0o640)
		}},
		{"unavailable certificate", func(t *testing.T, server *Server) {
			target, _ := os.Readlink(filepath.Join(server.root, certificatePath))
			if err := os.Remove(filepath.Join(server.root, "var/lib/sbxr/certificates/ip", target, "privkey.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{"expired certificate", func(_ *testing.T, server *Server) {
			server.now = func() time.Time { return time.Now().Add(200 * time.Hour) }
		}},
		{"untrusted certificate", func(_ *testing.T, server *Server) { server.roots = x509.NewCertPool() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, _, _, _ := testServer(t, "127.0.0.1")
			test.change(t, &server)
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var failure *Failure
			if err := server.Serve(t.Context(), listener); err == nil || !errors.As(err, &failure) || Result(err).Status != Failed {
				t.Fatalf("Serve() = %v", err)
			}
		})
	}
}

func TestServeHasNoPlainHTTPOrUntrustedTLSFallback(t *testing.T) {
	server, _, token, _ := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	connection, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(connection, "GET /s/"+token+" HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\n\r\n")
	response, _ := io.ReadAll(connection)
	if strings.Contains(string(response), "HTTP/") || strings.Contains(string(response), "not found") {
		t.Fatalf("plain HTTP received an HTTP response: %q", response)
	}

	untrusted := server
	untrusted.roots = x509.NewCertPool()
	refused, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := untrusted.Serve(t.Context(), refused); Result(err).Status != Failed {
		t.Fatalf("untrusted certificate fallback = %v", err)
	}
}

func TestServeSupportsTheSelectedIPv6Family(t *testing.T) {
	server, roots, token, body := testServer(t, "::1")
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "::1")}}
	response, err := client.Get("https://" + listener.Addr().String() + "/s/" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(got) != body {
		t.Fatalf("IPv6 GET = %d %q", response.StatusCode, got)
	}
}

func TestServiceUnitHasOnlyReadOnlySubscriptionAuthority(t *testing.T) {
	unit := ServiceUnit()
	for _, required := range []string{
		"User=sbxr-subscription", "Group=sbxr-subscription", "ExecStart=/usr/local/bin/sbxr __subscription-serve",
		"StandardOutput=null", "StandardError=null",
		"ProtectSystem=strict", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true",
		"TemporaryFileSystem=/:ro", "BindReadOnlyPaths=/usr/local/bin/sbxr", "BindReadOnlyPaths=/etc/sbxr/subscription.json",
		"BindReadOnlyPaths=/var/lib/sbxr/subscriptions/current", "BindReadOnlyPaths=/var/lib/sbxr/certificates/ip/current",
		"BindReadOnlyPaths=/etc/ssl/certs/ca-certificates.crt", "RestrictAddressFamilies=AF_INET AF_INET6",
		"PrivateDevices=true", "UMask=0027", "LimitCORE=0",
		"ProtectProc=invisible", "ProcSubset=pid",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("service unit omitted %q", required)
		}
	}
	for _, forbidden := range []string{"Environment=", "AmbientCapabilities=", "ReadWritePaths=", "CAP_", "StateDirectory=", "\nReadOnlyPaths="} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("service unit grants %q", forbidden)
		}
	}
}

func TestServeRefusesTheWrongServiceIdentity(t *testing.T) {
	server, _, _, _ := testServer(t, "127.0.0.1")
	server.serviceUID++
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := server.Serve(t.Context(), listener)
	var failure *Failure
	if !errors.As(serveErr, &failure) || failure.Code != "SUBSCRIPTION-SERVING-IDENTITY" {
		t.Fatalf("wrong service identity = %v", serveErr)
	}
}

func startServer(t *testing.T, server Server, network, address string) (net.Listener, context.CancelFunc) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _ = server.Serve(ctx, listener) }()
	return listener, cancel
}

func testServer(t *testing.T, address string) (Server, *x509.CertPool, string, string) {
	t.Helper()
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	tokenBytes := make([]byte, 32)
	for index := range tokenBytes {
		tokenBytes[index] = byte(index + 1)
	}
	token := hex.EncodeToString(tokenBytes)
	body := "dmxlc3M6Ly9leGFtcGxlCg=="
	mustDirectory(t, root, "etc", 0o755)
	mustDirectory(t, root, "etc/sbxr", 0o750)
	configuration, _ := json.Marshal(map[string]any{"token": token, "listen_port": 10443, "certificate_pointer": "/var/lib/sbxr/certificates/ip/current", "primary_address": address})
	mustFile(t, root, "etc/sbxr/subscription.json", configuration, 0o640)
	mustDirectory(t, root, "var/lib/sbxr", 0o755)
	mustDirectory(t, root, "var/lib/sbxr/subscriptions", 0o750)
	mustDirectory(t, root, "var/lib/sbxr/subscriptions/current", 0o750)
	for _, name := range []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box", "metadata"} {
		contents := []byte("fixture")
		if name == "base64" {
			contents = []byte(body)
		}
		mustFile(t, root, "var/lib/sbxr/subscriptions/current/"+name, contents, 0o640)
	}
	roots := testCertificate(t, root, address)
	return NewAt(root, uid, gid, roots, time.Now()), roots, token, body
}

func testCertificate(t *testing.T, root, address string) *x509.CertPool {
	t.Helper()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(160*time.Hour - time.Minute), IPAddresses: []net.IP{net.ParseIP(address)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	mustDirectory(t, root, "var/lib/sbxr/certificates", 0o755)
	mustDirectory(t, root, "var/lib/sbxr/certificates/ip", 0o750)
	mustDirectory(t, root, "var/lib/sbxr/certificates/ip/sets", 0o750)
	mustDirectory(t, root, "var/lib/sbxr/certificates/ip/sets/ip-fixture", 0o750)
	mustFile(t, root, "var/lib/sbxr/certificates/ip/sets/ip-fixture/fullchain.pem", chain, 0o640)
	mustFile(t, root, "var/lib/sbxr/certificates/ip/sets/ip-fixture/privkey.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o640)
	if err := os.Symlink("sets/ip-fixture", filepath.Join(root, certificatePath)); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	rootCertificate, _ := x509.ParseCertificate(rootDER)
	roots.AddCert(rootCertificate)
	return roots
}

func mustDirectory(t *testing.T, root, name string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, name), mode); err != nil || os.Chmod(filepath.Join(root, name), mode) != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}

func mustFile(t *testing.T, root, name string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), body, mode); err != nil || os.Chmod(filepath.Join(root, name), mode) != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func testTLSConfig(roots *x509.CertPool, address string) *tls.Config {
	return &tls.Config{RootCAs: roots, ServerName: address, MinVersion: tls.VersionTLS13}
}
