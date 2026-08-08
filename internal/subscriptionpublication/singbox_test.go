package subscriptionpublication_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

type singBoxValidatorFunc func(context.Context, io.Reader) error

func (validate singBoxValidatorFunc) ValidateSingBox(ctx context.Context, document io.Reader) error {
	return validate(ctx, document)
}

func TestRenderProducesValidatedFiveConnectionProfileSingBoxAndKaringDocument(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	want := []byte(`{
  "dns": {
    "servers": [
      {
        "tag": "local-dns",
        "type": "local"
      }
    ]
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "tag": "mixed-in",
      "type": "mixed"
    }
  ],
  "outbounds": [
    {
      "flow": "xtls-rprx-vision",
      "server": "198.51.100.10",
      "server_port": 443,
      "tag": "VLESS REALITY Vision",
      "tls": {
        "enabled": true,
        "reality": {
          "enabled": true,
          "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
          "short_id": "0123456789abcdef"
        },
        "server_name": "direct.example.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "type": "vless",
      "uuid": "11111111-1111-4111-8111-111111111111"
    },
    {
      "server": "ws.example.com",
      "server_port": 443,
      "tag": "VLESS WebSocket",
      "tls": {
        "enabled": true,
        "server_name": "ws.example.com"
      },
      "transport": {
        "headers": {
          "Host": "origin.example.com"
        },
        "path": "/ws path?獨立",
        "type": "ws"
      },
      "type": "vless",
      "uuid": "33333333-3333-4333-8333-333333333333"
    },
    {
      "password": "hy:p@ss /雪",
      "server": "198.51.100.10",
      "server_port": 4443,
      "tag": "Hysteria2",
      "tls": {
        "enabled": true,
        "server_name": "direct.example.com"
      },
      "type": "hysteria2"
    },
    {
      "congestion_control": "cubic",
      "password": "tuic:p@ss /密碼",
      "server": "198.51.100.10",
      "server_port": 8443,
      "tag": "TUIC",
      "tls": {
        "enabled": true,
        "server_name": "direct.example.com"
      },
      "type": "tuic",
      "uuid": "55555555-5555-4555-8555-555555555555",
      "zero_rtt_handshake": false
    },
    {
      "password": "any:p@ss /秘密",
      "server": "198.51.100.10",
      "server_port": 9443,
      "tag": "AnyTLS",
      "tls": {
        "enabled": true,
        "server_name": "direct.example.com"
      },
      "type": "anytls"
    },
    {
      "default": "VLESS REALITY Vision",
      "outbounds": [
        "VLESS REALITY Vision",
        "VLESS WebSocket",
        "Hysteria2",
        "TUIC",
        "AnyTLS"
      ],
      "tag": "SBXR",
      "type": "selector"
    }
  ],
  "route": {
    "default_domain_resolver": "local-dns",
    "final": "SBXR"
  }
}
`)
	validated := 0
	module := subscriptionpublication.New(
		mihomoValidatorFunc(func(context.Context, io.Reader) error { return nil }),
		singBoxValidatorFunc(func(_ context.Context, document io.Reader) error {
			validated++
			got, err := io.ReadAll(document)
			if err != nil || !bytes.Equal(got, want) {
				return errors.New("unexpected sing-box document")
			}
			return nil
		}),
	)

	first, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if validated != 2 || !bytes.Equal(first.SingBox.Body, want) || !bytes.Equal(first.Karing.Body, want) || !bytes.Equal(first.SingBox.Body, second.SingBox.Body) {
		t.Fatalf("Render() sing-box validation calls=%d bytes stable=%t", validated, bytes.Equal(first.SingBox.Body, second.SingBox.Body))
	}
	if first.SingBox.ProfileCount != 5 || first.Karing.ProfileCount != 5 || len(first.SingBox.Omissions) != 1 || first.SingBox.Omissions[0].Status != subscriptionpublication.NotOffered || first.SingBox.Omissions[0].Reason != "VLESS XHTTP is unsupported by the sing-box transport contract" || len(first.Karing.Omissions) != 1 || first.Karing.Omissions[0].Status != subscriptionpublication.NotOffered || first.Karing.Omissions[0].Reason != "VLESS XHTTP is unavailable in the Karing core" {
		t.Fatalf("Render() sing-box metadata = %#v; Karing metadata = %#v", first.SingBox, first.Karing)
	}
	for _, rendered := range []string{fmt.Sprint(first.SingBox), fmt.Sprintf("%#v", first.Karing)} {
		if strings.Contains(rendered, "hy:p@ss /雪") || strings.Contains(rendered, "11111111-1111-4111-8111-111111111111") {
			t.Fatalf("default representation formatting exposed a Client Access Value: %s", rendered)
		}
	}
	if encoded, marshalErr := json.Marshal(first.SingBox); marshalErr == nil || strings.Contains(string(encoded), "hy:p@ss /雪") {
		t.Fatalf("json.Marshal(Representation) = %s, %v", encoded, marshalErr)
	}
}

func TestRenderSingBoxOmitsDisabledConnectionProfileAndPreservesIPv6(t *testing.T) {
	source, reader := sixProfileSource(t, "2001:db8::10")
	profiles := slices.Delete(source.Profiles(), 2, 3)
	source, err := connectionprofiles.NewPublicationSource(profiles, []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSWebSocketProfileID}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.SingBox.ProfileCount != 4 || !bytes.Equal(result.SingBox.Body, result.Karing.Body) || bytes.Contains(result.SingBox.Body, []byte("VLESS XHTTP")) || bytes.Contains(result.SingBox.Body, []byte("VLESS WebSocket")) || bytes.Contains(result.SingBox.Body, []byte("22222222-2222-4222-8222-222222222222")) || bytes.Contains(result.SingBox.Body, []byte("33333333-3333-4333-8333-333333333333")) || !bytes.Contains(result.SingBox.Body, []byte(`"server": "2001:db8::10"`)) {
		t.Fatalf("disabled/IPv6 sing-box result = count %d, body %s", result.SingBox.ProfileCount, result.SingBox.Body)
	}
	if len(result.SingBox.Omissions) != 2 || result.SingBox.Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID || result.SingBox.Omissions[0].Status != subscriptionpublication.NotOffered || result.SingBox.Omissions[1].ID != connectionprofiles.VLESSWebSocketProfileID || result.SingBox.Omissions[1].Status != subscriptionpublication.Disabled {
		t.Fatalf("disabled sing-box omissions = %#v", result.SingBox.Omissions)
	}
}

func TestRenderRefusesSingBoxValidatorFailureWithoutLeakingSecrets(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	module := subscriptionpublication.New(
		mihomoValidatorFunc(func(context.Context, io.Reader) error { return nil }),
		singBoxValidatorFunc(func(context.Context, io.Reader) error { return errors.New("tuic:p@ss /密碼") }),
	)
	result, err := module.Render(t.Context(), source, reader)
	if err == nil || strings.Contains(err.Error(), "tuic:p@ss /密碼") || result.SingBox.Body != nil || result.Karing.Body != nil {
		t.Fatalf("Render() sing-box validator failure = result %v, error %v", result, err)
	}
}

func TestPinnedSingBoxAcceptsCompleteDocument(t *testing.T) {
	binary, version := os.Getenv("SBXR_SING_BOX_BIN"), os.Getenv("SBXR_SING_BOX_VERSION")
	if binary == "" || version == "" {
		t.Skip("set SBXR_SING_BOX_BIN and SBXR_SING_BOX_VERSION to the pinned sing-box validator")
	}
	versionOutput, err := exec.Command(binary, "version").CombinedOutput()
	if err != nil || !slices.Contains(strings.Fields(string(versionOutput)), version) {
		t.Fatalf("pinned sing-box version %q is unavailable", version)
	}
	validator := singBoxValidatorFunc(func(ctx context.Context, document io.Reader) error {
		command := exec.CommandContext(ctx, binary, "check", "-c", "/dev/stdin")
		command.Stdin = document
		if command.Run() != nil {
			return errors.New("pinned sing-box rejected the complete document")
		}
		return nil
	})
	source, reader := sixProfileSource(t, "198.51.100.10")
	if result, err := subscriptionpublication.New(mihomoValidatorFunc(func(context.Context, io.Reader) error { return nil }), validator).Render(t.Context(), source, reader); err != nil || result.SingBox.ProfileCount != 5 {
		t.Fatalf("pinned sing-box validation = count %d, error %v", result.SingBox.ProfileCount, err)
	}
	disabled, err := connectionprofiles.NewPublicationSource(nil, allPublicationOmissions())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := subscriptionpublication.New(mihomoValidatorFunc(func(context.Context, io.Reader) error { return nil }), validator).Render(t.Context(), disabled, reader); err != nil || result.SingBox.ProfileCount != 0 {
		t.Fatalf("pinned sing-box all-disabled validation = count %d, error %v", result.SingBox.ProfileCount, err)
	}
	if err := validator.ValidateSingBox(t.Context(), strings.NewReader("{")); err == nil {
		t.Fatal("pinned sing-box accepted malformed output")
	}
}
