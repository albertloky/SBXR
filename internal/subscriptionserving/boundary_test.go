package subscriptionserving

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServeEnforcesFixedResourceBounds(t *testing.T) {
	t.Run("request rate", func(t *testing.T) {
		server, roots, token, _ := testServer(t, "127.0.0.1")
		listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
		defer cancel()
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
		endpoint := "https://" + listener.Addr().String() + "/s/" + token
		for requestNumber := 1; requestNumber <= 59; requestNumber++ {
			response, err := client.Get(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("request %d = %d", requestNumber, response.StatusCode)
			}
		}
		response, err := client.Get(endpoint + "/missing")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound || string(body) != "not found\n" {
			t.Fatalf("hostile request 60 = %d, body length %d", response.StatusCode, len(body))
		}
		response, err = client.Get(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusTooManyRequests || string(body) != "busy\n" {
			t.Fatalf("bounded request = %d, body length %d", response.StatusCode, len(body))
		}
	})

	t.Run("concurrent connections", func(t *testing.T) {
		server, roots, _, _ := testServer(t, "127.0.0.1")
		listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
		defer cancel()
		connections := make([]*tls.Conn, 0, 8)
		for range 8 {
			connection, err := tls.Dial("tcp", listener.Addr().String(), testTLSConfig(roots, "127.0.0.1"))
			if err != nil {
				t.Fatal(err)
			}
			connections = append(connections, connection)
		}
		defer func() {
			for _, connection := range connections {
				_ = connection.Close()
			}
		}()
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: testTLSConfig(roots, "127.0.0.1")}
		connection, err := dialer.Dial("tcp", listener.Addr().String())
		if err == nil {
			_ = connection.Close()
			t.Fatal("ninth concurrent connection was accepted")
		}
	})

	t.Run("header and body", func(t *testing.T) {
		server, roots, token, _ := testServer(t, "127.0.0.1")
		listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
		defer cancel()
		target := "/s/" + token
		base := len("GET " + target + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\nConnection: close\r\nX-Padding: \r\n\r\n")
		response, _ := rawTLSRequest(t, listener.Addr().String(), roots, http.MethodGet, target, []string{"X-Padding: " + strings.Repeat("x", maxHeaderBytes-base)})
		if response.StatusCode != http.StatusOK {
			t.Fatalf("exact maximum header = %d", response.StatusCode)
		}
		response, body := rawTLSRequest(t, listener.Addr().String(), roots, http.MethodGet, target, []string{"X-Padding: " + strings.Repeat("x", maxHeaderBytes-base+1)})
		if response.StatusCode != http.StatusNotFound || string(body) != "not found\n" || bytes.Contains(body, []byte(token)) {
			t.Fatalf("oversized header = %d, body length %d", response.StatusCode, len(body))
		}
		connection, err := tls.Dial("tcp", listener.Addr().String(), testTLSConfig(roots, "127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(connection)
		keepAliveBase := len("GET " + target + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\nConnection: keep-alive\r\nX-Padding: \r\n\r\n")
		_, _ = io.WriteString(connection, "GET "+target+" HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\nConnection: keep-alive\r\nX-Padding: "+strings.Repeat("x", maxHeaderBytes-keepAliveBase)+"\r\n\r\n")
		response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("second-connection exact header = %v, %v", response, err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		closeBase := len("GET " + target + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\nConnection: close\r\nX-Padding: \r\n\r\n")
		_, _ = io.WriteString(connection, "GET "+target+" HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\nConnection: close\r\nX-Padding: "+strings.Repeat("x", maxHeaderBytes-closeBase+1)+"\r\n\r\n")
		response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		connection.Close()
		if err != nil || response.StatusCode != http.StatusNotFound {
			t.Fatalf("same-connection oversized header = %v, %v", response, err)
		}
		response.Body.Close()
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
		for _, size := range []int{maxRequestBodyBytes, maxRequestBodyBytes + 1} {
			request, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+target, strings.NewReader(strings.Repeat("b", size)))
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusNotFound || string(body) != "not found\n" {
				t.Fatalf("%d-byte body = %d, body length %d", size, response.StatusCode, len(body))
			}
		}
		request, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+target, strings.NewReader(strings.Repeat("c", maxRequestBodyBytes)))
		request.ContentLength = -1
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound || string(body) != "not found\n" {
			t.Fatalf("chunked body = %d, body length %d", response.StatusCode, len(body))
		}
		connection, err = tls.Dial("tcp", listener.Addr().String(), testTLSConfig(roots, "127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		reader = bufio.NewReader(connection)
		_, _ = io.WriteString(connection, "GET "+target+" HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\nContent-Length: "+fmt.Sprint(maxRequestBodyBytes)+"\r\nConnection: keep-alive\r\n\r\n"+strings.Repeat("b", maxRequestBodyBytes))
		response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil || response.StatusCode != http.StatusNotFound || !response.Close {
			t.Fatalf("body connection refusal = %v, %v", response, err)
		}
		response.Body.Close()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(connection, "GET "+target+" HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\nX-Padding: "+strings.Repeat("x", maxHeaderBytes)+"\r\n\r\n")
		if _, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet}); err == nil {
			t.Fatal("body-bearing connection accepted a later oversized header")
		}
		connection.Close()
	})

	t.Run("response size", func(t *testing.T) {
		server, roots, token, _ := testServer(t, "127.0.0.1")
		prefix, suffix := []byte(`{"padding":"`), []byte(`"}`)
		body := append(append(prefix, bytes.Repeat([]byte{'x'}, (1<<20)-len(prefix)-len(suffix))...), suffix...)
		mustFile(t, server.root, artifactPath+"/karing", body, 0o644)
		mustFile(t, server.root, artifactPath+"/sing-box", body, 0o644)
		rewriteArtifactDigests(t, server)
		listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
		defer cancel()
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
		response, err := client.Get("https://" + listener.Addr().String() + "/s/" + token + "/sing-box")
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || len(got) != 1<<20 {
			t.Fatalf("maximum response = %d, %d bytes", response.StatusCode, len(got))
		}
	})
}

func rewriteArtifactDigests(t *testing.T, server Server) {
	t.Helper()
	digests := map[string]string{}
	for _, name := range []string{"base64", "raw", "v2rayn", "shadowrocket", "karing", "mihomo", "sing-box"} {
		body, err := os.ReadFile(filepath.Join(server.root, artifactPath, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		digests[name] = hex.EncodeToString(digest[:])
	}
	path := filepath.Join(server.root, artifactPath, "metadata")
	var metadata map[string]any
	body, _ := os.ReadFile(path)
	if json.Unmarshal(body, &metadata) != nil {
		t.Fatal("decode fixture metadata")
	}
	metadata["artifact_sha256"] = digests
	body, _ = json.Marshal(metadata)
	mustFile(t, server.root, artifactPath+"/metadata", body, 0o644)
}

func TestServeEnforcesFixedConnectionTimeouts(t *testing.T) {
	server, roots, token, _ := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()

	t.Run("TLS handshake", func(t *testing.T) {
		connection, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		started := time.Now()
		_ = connection.SetReadDeadline(started.Add(tlsHandshakeTimeout + 2*time.Second))
		_, err = connection.Read(make([]byte, 1))
		elapsed := time.Since(started)
		if err == nil || elapsed < tlsHandshakeTimeout-time.Second || elapsed > tlsHandshakeTimeout+2*time.Second {
			t.Fatalf("TLS handshake closed after %s with %v", elapsed.Round(100*time.Millisecond), err)
		}
	})

	t.Run("header read", func(t *testing.T) {
		connection, err := tls.Dial("tcp", listener.Addr().String(), testTLSConfig(roots, "127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		started := time.Now()
		_ = connection.SetDeadline(started.Add(headerReadTimeout + 2*time.Second))
		_, _ = io.WriteString(connection, "GET /s/")
		_, _ = io.ReadAll(connection)
		elapsed := time.Since(started)
		if elapsed < headerReadTimeout-time.Second || elapsed > headerReadTimeout+2*time.Second {
			t.Fatalf("partial header closed after %s", elapsed.Round(100*time.Millisecond))
		}
	})

	t.Run("request body read", func(t *testing.T) {
		connection, err := tls.Dial("tcp", listener.Addr().String(), testTLSConfig(roots, "127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		request := "GET /s/" + token + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\nContent-Length: 1\r\n\r\n"
		started := time.Now()
		_ = connection.SetDeadline(started.Add(requestReadTimeout + 2*time.Second))
		_, _ = io.WriteString(connection, request)
		_, _ = io.ReadAll(connection)
		elapsed := time.Since(started)
		if elapsed < requestReadTimeout-time.Second || elapsed > requestReadTimeout+2*time.Second {
			t.Fatalf("partial request body closed after %s", elapsed.Round(100*time.Millisecond))
		}
	})

	t.Run("response write", func(t *testing.T) {
		serverSide, clientSide := net.Pipe()
		listener := newSingleConnListener(serverSide)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() { _ = server.Serve(ctx, listener) }()
		connection := tls.Client(clientSide, testTLSConfig(roots, "127.0.0.1"))
		defer clientSide.Close()
		if err := connection.Handshake(); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_ = connection.SetReadDeadline(started.Add(responseWriteTimeout + 2*time.Second))
		_, _ = io.WriteString(connection, "GET /s/"+token+" HTTP/1.1\r\nHost: test\r\n\r\n")
		<-time.After(responseWriteTimeout + 100*time.Millisecond)
		_, err := connection.Read(make([]byte, 1))
		elapsed := time.Since(started)
		if err == nil || elapsed < responseWriteTimeout-time.Second || elapsed > responseWriteTimeout+2*time.Second {
			t.Fatalf("blocked response write closed after %s with %v", elapsed.Round(100*time.Millisecond), err)
		}
	})

	t.Run("total operation", func(t *testing.T) {
		started := time.Now()
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/s/fixture", nil)
		operationBound(http.HandlerFunc(func(_ http.ResponseWriter, bounded *http.Request) {
			<-bounded.Context().Done()
		})).ServeHTTP(response, request)
		elapsed := time.Since(started)
		if response.Code != http.StatusServiceUnavailable || response.Body.String() != "busy\n" || elapsed < totalOperationTimeout-time.Second || elapsed > totalOperationTimeout+2*time.Second {
			t.Fatalf("total operation = %d after %s, body %q", response.Code, elapsed.Round(100*time.Millisecond), response.Body.String())
		}
	})

	t.Run("idle connection", func(t *testing.T) {
		connection, err := tls.Dial("tcp", listener.Addr().String(), testTLSConfig(roots, "127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		request := "GET /s/" + token + " HTTP/1.1\r\nHost: " + listener.Addr().String() + "\r\n\r\n"
		if _, err := io.WriteString(connection, request); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(connection)
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		started := time.Now()
		_ = connection.SetReadDeadline(started.Add(idleConnectionTimeout + 2*time.Second))
		_, err = reader.ReadByte()
		elapsed := time.Since(started)
		if err == nil || elapsed < idleConnectionTimeout-time.Second || elapsed > idleConnectionTimeout+2*time.Second {
			t.Fatalf("idle connection closed after %s with %v", elapsed.Round(100*time.Millisecond), err)
		}
	})
}

func TestServeRejectsEveryUnsafeArtifactSet(t *testing.T) {
	checks := []struct {
		name   string
		change func(t *testing.T, server Server)
	}{
		{"unexpected entry", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/extra", []byte("marker"), 0o644)
		}},
		{"partial set", func(t *testing.T, server Server) {
			if err := os.Remove(filepath.Join(server.root, artifactPath, "raw")); err != nil {
				t.Fatal(err)
			}
		}},
		{"non-regular entry", func(t *testing.T, server Server) {
			path := filepath.Join(server.root, artifactPath, "raw")
			if err := os.Remove(path); err != nil || os.Mkdir(path, 0o644) != nil {
				t.Fatal("replace artifact with directory")
			}
		}},
		{"symbolic link", func(t *testing.T, server Server) {
			path := filepath.Join(server.root, artifactPath, "raw")
			if err := os.Remove(path); err != nil || os.Symlink("../../../../arbitrary-file-marker", path) != nil {
				t.Fatal("replace artifact with symbolic link")
			}
		}},
		{"configuration symbolic link", func(t *testing.T, server Server) {
			mustFile(t, server.root, "arbitrary-file-marker", []byte("ARBITRARY-FILE-MARKER"), 0o644)
			path := filepath.Join(server.root, configurationPath)
			if err := os.Remove(path); err != nil || os.Symlink("../../arbitrary-file-marker", path) != nil {
				t.Fatal("replace configuration with symbolic link")
			}
		}},
		{"certificate symbolic link", func(t *testing.T, server Server) {
			target, _ := os.Readlink(filepath.Join(server.root, certificatePath))
			path := filepath.Join(server.root, "var/lib/sbxr/certificates/ip", target, "privkey.pem")
			if err := os.Remove(path); err != nil || os.Symlink("fullchain.pem", path) != nil {
				t.Fatal("replace certificate key with symbolic link")
			}
		}},
		{"unsafe mode", func(t *testing.T, server Server) {
			if err := os.Chmod(filepath.Join(server.root, artifactPath, "raw"), 0o660); err != nil {
				t.Fatal(err)
			}
		}},
		{"changed raw", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/raw", []byte("CHANGED-RAW-MARKER"), 0o644)
		}},
		{"changed v2rayN", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/v2rayn", []byte("CHANGED-V2RAYN-MARKER"), 0o644)
		}},
		{"changed Shadowrocket", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/shadowrocket", []byte("CHANGED-SHADOWROCKET-MARKER"), 0o644)
		}},
		{"changed Karing", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/karing", []byte("{}"), 0o644)
		}},
		{"coordinated Karing and sing-box change", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/karing", []byte("{}"), 0o644)
			mustFile(t, server.root, artifactPath+"/sing-box", []byte("{}"), 0o644)
		}},
		{"invalid sing-box", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/sing-box", []byte("INVALID-JSON-MARKER"), 0o644)
		}},
		{"empty Mihomo", func(t *testing.T, server Server) { mustFile(t, server.root, artifactPath+"/mihomo", []byte{}, 0o644) }},
		{"changed Mihomo", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/mihomo", []byte("proxies: []\n"), 0o644)
		}},
		{"changed metadata", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/metadata", []byte("{}\n"), 0o644)
		}},
		{"unknown metadata fact", func(t *testing.T, server Server) {
			mutateArtifactMetadata(t, server, func(metadata map[string]any) { metadata["unexpected"] = true })
		}},
		{"changed selected address", func(t *testing.T, server Server) {
			mutateArtifactMetadata(t, server, func(metadata map[string]any) { metadata["selected_address"] = "invalid" })
		}},
		{"changed compatibility", func(t *testing.T, server Server) {
			mutateArtifactMetadata(t, server, func(metadata map[string]any) { metadata["compatibility_definition"] = "changed" })
		}},
		{"oversized response", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/mihomo", bytes.Repeat([]byte{'x'}, (1<<20)+1), 0o644)
		}},
		{"oversized metadata", func(t *testing.T, server Server) {
			mustFile(t, server.root, artifactPath+"/metadata", bytes.Repeat([]byte{'x'}, (64<<10)+1), 0o644)
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			server, _, _, _ := testServer(t, "127.0.0.1")
			installPublicationFixture(t, server, "2001:db8::10", false)
			check.change(t, server)
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err = server.Serve(ctx, listener)
			var failure *Failure
			wantCode := "SUBSCRIPTION-SERVING-ARTIFACT"
			if check.name == "certificate symbolic link" {
				wantCode = "SUBSCRIPTION-SERVING-CERTIFICATE"
			}
			if !errors.As(err, &failure) || failure.Code != wantCode || strings.Contains(err.Error(), "MARKER") {
				t.Fatalf("Serve() = %v", err)
			}
		})
	}
}

func TestServingRefusesMetadataThatMarksAnEmittedProfileOmitted(t *testing.T) {
	server, _, _, _ := testServer(t, "127.0.0.1")
	installPublicationFixture(t, server, "2001:db8::10", true)
	mutateArtifactMetadata(t, server, func(metadata map[string]any) {
		omission := metadata["omissions"].([]any)[0].(map[string]any)
		omission["id"], omission["name"] = "vless-reality-vision", "VLESS REALITY Vision"
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = server.Serve(ctx, listener)
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code != "SUBSCRIPTION-SERVING-ARTIFACT" {
		t.Fatalf("Serve() = %v", err)
	}
}

func TestServingRefusesMalformedRawConnectionProfile(t *testing.T) {
	server, _, _, _ := testServer(t, "127.0.0.1")
	raw := []byte("vless://reality\x00")
	universal := []byte(base64.StdEncoding.EncodeToString(raw))
	for _, file := range []struct {
		name string
		body []byte
	}{{"raw", raw}, {"base64", universal}, {"v2rayn", universal}, {"shadowrocket", universal}} {
		mustFile(t, server.root, artifactPath+"/"+file.name, file.body, 0o644)
		name, body := file.name, file.body
		mutateArtifactMetadata(t, server, func(metadata map[string]any) {
			digest := sha256.Sum256(body)
			metadata["artifact_sha256"].(map[string]any)[name] = hex.EncodeToString(digest[:])
		})
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = server.Serve(ctx, listener)
	var failure *Failure
	if !errors.As(err, &failure) || failure.Code != "SUBSCRIPTION-SERVING-ARTIFACT" {
		t.Fatalf("Serve() = %v", err)
	}
}

func mutateArtifactMetadata(t *testing.T, server Server, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(server.root, artifactPath, "metadata")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if json.Unmarshal(body, &metadata) != nil {
		t.Fatal("decode fixture metadata")
	}
	mutate(metadata)
	body, _ = json.Marshal(metadata)
	mustFile(t, server.root, artifactPath+"/metadata", body, 0o644)
}

func TestServeReturnsOneIndistinguishableRefusalForEveryHostileRequestShape(t *testing.T) {
	server, roots, token, _ := testServer(t, "127.0.0.1")
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	defer cancel()
	checks := []struct{ method, target string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/s/"},
		{http.MethodGet, "/" + token},
		{http.MethodGet, "/s/" + token[:63]},
		{http.MethodGet, "/s/" + token + "0"},
		{http.MethodGet, "/s/" + token + "/"},
		{http.MethodGet, "/s/" + token + "/missing"},
		{http.MethodGet, "/s/" + token + "/raw/extra"},
		{http.MethodGet, "/s//" + token},
		{http.MethodGet, "/s/" + token + "/../raw"},
		{http.MethodGet, "/s/" + token + "%2fraw"},
		{http.MethodGet, "/s/" + token + "%zz"},
		{http.MethodGet, "https://example.invalid/s/" + token},
		{http.MethodGet, "/s/" + token + "?format=raw"},
		{http.MethodHead, "/s/" + token},
		{http.MethodPost, "/s/" + token},
		{http.MethodPut, "/s/" + token},
		{http.MethodOptions, "/s/" + token},
		{http.MethodOptions, "*"},
	}
	for index, check := range checks {
		response, body := rawTLSRequest(t, listener.Addr().String(), roots, check.method, check.target, nil)
		bodyIsPlain := string(body) == "not found\n" || check.method == http.MethodHead && len(body) == 0
		if response.StatusCode != http.StatusNotFound || !bodyIsPlain {
			t.Fatalf("hostile request %d = status %d, body length %d", index, response.StatusCode, len(body))
		}
		for name, want := range map[string]string{
			"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "private, no-store",
			"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		} {
			if response.Header.Get(name) != want {
				t.Fatalf("hostile response %s = %q", name, response.Header.Get(name))
			}
		}
	}
}

func TestServeNeverExposesSecretOrOperationalMarkers(t *testing.T) {
	server, roots, token, _ := testServer(t, "127.0.0.1")
	installPublicationFixture(t, server, "2001:db8::10", false)
	listener, cancel := startServer(t, server, "tcp4", "127.0.0.1:0")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: testTLSConfig(roots, "127.0.0.1")}}
	request, _ := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/s/"+token+"/missing?authorization=COMPLETE-SUBSCRIPTION-URL-MARKER", nil)
	request.Header.Set("User-Agent", "USER-AGENT-MARKER")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	cancel()
	visible := append([]byte(nil), body...)
	for name, values := range response.Header {
		visible = append(visible, name...)
		visible = append(visible, strings.Join(values, ",")...)
	}
	for _, marker := range []string{token, "COMPLETE-SUBSCRIPTION-URL-MARKER", "USER-AGENT-MARKER", "11111111-1111-4111-8111-111111111111", "VLESS XHTTP 香港", "2001:db8::10"} {
		if bytes.Contains(visible, []byte(marker)) {
			t.Fatal("hostile response exposed a protected marker")
		}
	}
	t.Log("RELEASE-STAGED-ONBOARDING-MARKER-COMPLETE-URL")
	unit := ServiceUnit()
	for _, required := range []string{"StandardOutput=null", "StandardError=null", "LimitCORE=0"} {
		if !strings.Contains(unit, required) {
			t.Fatalf("service unit is missing %q", required)
		}
	}

	server, _, _, _ = testServer(t, "127.0.0.1")
	underlying, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = server.Serve(t.Context(), &failingListener{Listener: underlying})
	result := Result(err)
	if err == nil || strings.Contains(err.Error(), "EXTERNAL-ERROR-MARKER") || strings.Contains(result.Code, "EXTERNAL-ERROR-MARKER") || result.Code != "SUBSCRIPTION-SERVING-RUNTIME" {
		t.Fatalf("unexpected listener failure = %v", err)
	}
}

type failingListener struct{ net.Listener }

func (failingListener) Accept() (net.Conn, error) {
	return nil, errors.New("EXTERNAL-ERROR-MARKER")
}

type singleConnListener struct {
	connection net.Conn
	closed     chan struct{}
	once       sync.Once
}

func newSingleConnListener(connection net.Conn) *singleConnListener {
	return &singleConnListener{connection: connection, closed: make(chan struct{})}
}

func (listener *singleConnListener) Accept() (net.Conn, error) {
	if listener.connection != nil {
		connection := listener.connection
		listener.connection = nil
		return connection, nil
	}
	<-listener.closed
	return nil, net.ErrClosed
}

func (listener *singleConnListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

func (*singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IP{127, 0, 0, 1}, Port: 10443}
}

func rawTLSRequest(t *testing.T, address string, roots *x509.CertPool, method, target string, headers []string) (*http.Response, []byte) {
	t.Helper()
	connection, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := method + " " + target + " HTTP/1.1\r\nHost: " + address + "\r\nConnection: close\r\n"
	if len(headers) > 0 {
		request += strings.Join(headers, "\r\n") + "\r\n"
	}
	if _, err := io.WriteString(connection, request+"\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}
