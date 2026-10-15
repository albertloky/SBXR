package proxyinstallation

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

func TestHTTPServingDistinguishesWatchFailureFromOwnerCancellation(t *testing.T) {
	for _, cause := range []string{"watch-loss", "owner-cancellation"} {
		t.Run(cause, func(t *testing.T) {
			_, h := enabledIdentityInstallation(t)
			before := bytes.Clone(h.ownership)
			record, ok := decodeOwnership(h.ownership)
			if !ok {
				t.Fatal("invalid fixture authority")
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			host := &dispatchTestHost{servingTestHost: &servingTestHost{controlledHost: h, safe: true},
				listener: listener, ip: record.PublicIPv4, bound: make(chan struct{}), publicIPv4: make(chan bool, 1)}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan subscriptionserving.Code, 1)
			go func() { done <- serveSubscription(ctx, readyLifecycle{}, host, subscriptionserving.New(nil, nil)) }()
			finished := false
			t.Cleanup(func() {
				cancel()
				listener.Close()
				if !finished {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("fixture serving goroutine did not stop")
					}
				}
			})
			select {
			case <-host.bound:
			case <-time.After(2 * time.Second):
				t.Fatal("dispatch did not bind")
			}
			client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
			defer client.CloseIdleConnections()
			response, err := client.Get("http://" + listener.Addr().String() + "/s/" + string(h.subscriptionCredential))
			if err != nil {
				t.Fatal("local fixture HTTP request failed")
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			artifact, _, valid := clientArtifact(h.configuration, record.PublicIPv4)
			if err != nil || !valid || response.StatusCode != 200 || !bytes.Equal(body, artifact) {
				t.Fatal("authenticated fixture artifact was not served")
			}
			if cause == "watch-loss" {
				host.publicIPv4 <- false
			} else {
				cancel()
			}
			select {
			case code := <-done:
				finished = true
				expected := subscriptionserving.Stopped
				if cause == "watch-loss" {
					expected = subscriptionserving.Failed
				}
				if code != expected {
					t.Fatalf("terminal code=%s want=%s", code, expected)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("dispatch did not stop")
			}
			conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
			if err == nil {
				conn.Close()
				t.Fatal("listener survived cancellation")
			}
			if !bytes.Equal(before, h.ownership) {
				t.Fatal("read-only serving changed authority")
			}
		})
	}
}
