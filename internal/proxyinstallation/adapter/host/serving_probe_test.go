package host

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

func TestLoadedHTTPServingRequiresExactCurrentArtifact(t *testing.T) {
	a := Adapter{root: t.TempDir()}
	adapter := singboxadapter.New()
	id, err := adapter.PrepareIdentity()
	if err != nil {
		t.Fatal(err)
	}
	reality, err := adapter.EncodeServerConfiguration(id, "google.com:443", "google.com")
	if err != nil {
		t.Fatal(err)
	}
	vmess, err := adapter.WithVMessWebSocket(reality, "tunnel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	artifact := func(config []byte) []byte {
		t.Helper()
		facts, err := adapter.CurrentConnectionFacts(config, "127.0.0.1")
		body, code := subscriptionserving.Artifact(facts)
		if err != nil || code != subscriptionserving.Ready {
			t.Fatal("invalid profile fixture")
		}
		return body
	}
	plain, twoNodes := artifact(reality), artifact(vmess)
	rotated, err := adapter.ReplaceClientIdentity(vmess)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("A", 43)
	serving := ServingAuthority{HTTP: true, LinkID: strings.Repeat("a", 32), CredentialSHA256: digest([]byte(token))}
	for path, body := range map[string]string{ServingTokenPath: token + "\n", servingCgroup + "/cgroup.procs": "123\n"} {
		if err := os.MkdirAll(filepath.Dir(a.path(path)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(a.path(path), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(a.path("/var/lib/sbxr"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.path("/etc/sing-box"), 0755); err != nil {
		t.Fatal(err)
	}
	a.subscriptionCommand = func(_ context.Context, name string, args ...string) (string, int, bool) {
		switch name + " " + strings.Join(args, " ") {
		case "systemctl show --property=ActiveState --value sbxr-subscription.service":
			return "active\n", 0, true
		case "systemctl show --property=MainPID --value sbxr-subscription.service":
			return "123\n", 0, true
		case "ss -H -ltnp sport = :8443":
			return `LISTEN 0 128 127.0.0.1:8443 0.0.0.0:* users:(("sbxr",pid=123,fd=3))`, 0, true
		default:
			t.Errorf("unexpected probe command %s", name)
			return "", 1, true
		}
	}
	for _, tc := range []struct {
		name         string
		config, body []byte
		accepted     bool
	}{
		{"REALITY", reality, plain, true},
		{"VMess", vmess, twoNodes, true},
		{"old identity", rotated, twoNodes, false},
		{"missing VMess", vmess, plain, false},
		{"extra node", reality, twoNodes, false},
		{"extra newline", vmess, append(append([]byte{}, twoNodes...), '\n'), false},
		{"missing newline", vmess, twoNodes[:len(twoNodes)-1], false},
		{"oversized", vmess, []byte(strings.Repeat("x", 4096) + "\n"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(a.path("/etc/sing-box/config.json"), tc.config, 0640); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:8443")
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/s/"+token {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Write(tc.body)
			})}
			done := make(chan struct{})
			t.Cleanup(func() { server.Close(); <-done })
			go func() { defer close(done); server.Serve(listener) }()
			loaded, observed := a.loadedServingAuthority(t.Context(), RenewalAuthority{PublicIPv4: "127.0.0.1"}, serving, serving)
			if observed != tc.accepted || tc.accepted && loaded != serving {
				t.Fatalf("probe accepted = %v; want %v", observed, tc.accepted)
			}
		})
	}
}
