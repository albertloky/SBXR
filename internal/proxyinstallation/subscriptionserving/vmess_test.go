package subscriptionserving_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/proxyinstallation/subscriptionserving"
)

func TestOptionalVMessArtifactKeepsRealityAndUsesTLSWebSocket(t *testing.T) {
	facts := profile(t)
	plain, code := subscriptionserving.Artifact(facts)
	if code != subscriptionserving.Ready {
		t.Fatal(code)
	}
	facts.VMessHostname = "tunnel.example.com"
	body, code := subscriptionserving.Artifact(facts)
	if code != subscriptionserving.Ready || !strings.HasPrefix(string(body), string(plain)) {
		t.Fatal("REALITY node changed")
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "vmess://") {
		t.Fatal("expected two subscription nodes")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines[1], "vmess://"))
	var node map[string]string
	if err != nil || json.Unmarshal(decoded, &node) != nil {
		t.Fatal("invalid VMess URI")
	}
	for key, value := range map[string]string{"v": "2", "add": facts.VMessHostname, "port": "443", "id": facts.UUID, "aid": "0", "scy": "auto", "net": "ws", "host": facts.VMessHostname, "path": "/sbxr-vmess", "tls": "tls", "sni": facts.VMessHostname} {
		if node[key] != value {
			t.Errorf("incorrect VMess %s", key)
		}
	}
	facts.VMessHostname = "https://unsafe.example.com"
	if _, code := subscriptionserving.Artifact(facts); code != subscriptionserving.Refused {
		t.Fatal("accepted unsafe hostname")
	}
}
