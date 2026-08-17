package subscriptionpublication_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

type mihomoValidatorFunc func(context.Context, io.Reader) error

func (validate mihomoValidatorFunc) ValidateMihomo(ctx context.Context, document io.Reader) error {
	return validate(ctx, document)
}

func TestRenderRefusesUnsupportedMihomoField(t *testing.T) {
	tests := []struct {
		name   string
		change func([]connectionprofiles.PublicationProfile)
	}{
		{"duplicate name", func(profiles []connectionprofiles.PublicationProfile) { profiles[1].Name = profiles[0].Name }},
		{"wrong transport", func(profiles []connectionprofiles.PublicationProfile) { profiles[2].Transport = "gRPC" }},
		{"unsupported congestion", func(profiles []connectionprofiles.PublicationProfile) {
			profiles[4].CongestionControl = state.CongestionControl("cubic\n    unsupported: true")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, reader := sixProfileSource(t, "198.51.100.10")
			profiles := source.Profiles()
			test.change(profiles)
			source, err := connectionprofiles.NewPublicationSource(profiles, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newAcceptingTestModule().Render(t.Context(), source, reader); err == nil {
				t.Fatal("Render() accepted an unsupported Mihomo field")
			}
		})
	}
}

func TestRenderMihomoOmitsDisabledProfileAndPreservesIPv6(t *testing.T) {
	source, reader := sixProfileSource(t, "2001:db8::10")
	profiles := slices.Delete(source.Profiles(), 1, 2)
	source, err := connectionprofiles.NewPublicationSource(profiles, []connectionprofiles.PublicationOmission{{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Lifecycle: state.ProfileDisabled}})
	if err != nil {
		t.Fatal(err)
	}
	var validated []byte
	module := subscriptionpublication.New(mihomoValidatorFunc(func(_ context.Context, document io.Reader) error {
		validated, _ = io.ReadAll(document)
		return nil
	}), singBoxValidatorFunc(func(context.Context, io.Reader) error { return nil }))

	result, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProfileCount != 5 || len(result.Omissions) != 1 || result.Omissions[0].ID != connectionprofiles.VLESSXHTTPProfileID || !bytes.Equal(result.Mihomo, validated) || bytes.Contains(result.Mihomo, []byte("VLESS XHTTP")) || bytes.Contains(result.Mihomo, []byte("22222222-2222-4222-8222-222222222222")) || !bytes.Contains(result.Mihomo, []byte(`server: "2001:db8::10"`)) {
		t.Fatalf("disabled-profile Mihomo result = count %d, omissions %v", result.ProfileCount, result.Omissions)
	}
	for _, name := range []string{"VLESS REALITY Vision", "VLESS WebSocket", "Hysteria2", "TUIC", "AnyTLS"} {
		if bytes.Count(result.Mihomo, []byte(`- "`+name+`"`)) != 1 {
			t.Fatalf("Mihomo group reference for %q is missing or duplicated", name)
		}
	}
}

func TestRenderMihomoAllowsEveryConnectionProfileToBeDisabled(t *testing.T) {
	_, reader := sixProfileSource(t, "198.51.100.10")
	source, err := connectionprofiles.NewPublicationSource(nil, allPublicationOmissions())
	if err != nil {
		t.Fatal(err)
	}
	result, err := newAcceptingTestModule().Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProfileCount != 0 || len(result.Omissions) != 6 || string(result.Mihomo) != "proxies: []\n" {
		t.Fatalf("all-disabled Mihomo result = count %d, omissions %d, document %q", result.ProfileCount, len(result.Omissions), result.Mihomo)
	}
}

func TestRenderRefusesMihomoValidatorFailureWithoutLeakingSecrets(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	module := subscriptionpublication.New(mihomoValidatorFunc(func(context.Context, io.Reader) error {
		return errors.New("hy:p@ss /雪")
	}), singBoxValidatorFunc(func(context.Context, io.Reader) error { return nil }))

	result, err := module.Render(t.Context(), source, reader)
	if err == nil || strings.Contains(err.Error(), "hy:p@ss /雪") || result.Mihomo != nil {
		t.Fatalf("Render() validator failure = result %v, error %v", result, err)
	}
}

func TestPinnedMihomoAcceptsCompleteDocument(t *testing.T) {
	binary, version := os.Getenv("SBXR_MIHOMO_BIN"), os.Getenv("SBXR_MIHOMO_VERSION")
	if binary == "" || version == "" {
		t.Skip("set SBXR_MIHOMO_BIN and SBXR_MIHOMO_VERSION to the pinned Mihomo validator")
	}
	versionOutput, err := exec.Command(binary, "-v").CombinedOutput()
	if err != nil || !slices.Contains(strings.Fields(string(versionOutput)), version) {
		t.Fatalf("pinned Mihomo version %q is unavailable", version)
	}
	validator := mihomoValidatorFunc(func(ctx context.Context, document io.Reader) error {
		command := exec.CommandContext(ctx, binary, "-t", "-d", t.TempDir(), "-f", "/dev/stdin")
		command.Stdin = document
		if command.Run() != nil {
			return errors.New("pinned Mihomo rejected the complete document")
		}
		return nil
	})
	source, reader := sixProfileSource(t, "198.51.100.10")
	if result, err := subscriptionpublication.New(validator, singBoxValidatorFunc(func(context.Context, io.Reader) error { return nil })).Render(t.Context(), source, reader); err != nil || result.ProfileCount != 6 {
		t.Fatalf("pinned Mihomo validation = count %d, error %v", result.ProfileCount, err)
	}
	disabled, err := connectionprofiles.NewPublicationSource(nil, allPublicationOmissions())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := subscriptionpublication.New(validator, singBoxValidatorFunc(func(context.Context, io.Reader) error { return nil })).Render(t.Context(), disabled, reader); err != nil || result.ProfileCount != 0 {
		t.Fatalf("pinned Mihomo all-disabled validation = count %d, error %v", result.ProfileCount, err)
	}
	if err := validator.ValidateMihomo(t.Context(), strings.NewReader("proxies:\n  - malformed")); err == nil {
		t.Fatal("pinned Mihomo accepted malformed output")
	}
}

func allPublicationOmissions() []connectionprofiles.PublicationOmission {
	return []connectionprofiles.PublicationOmission{
		{ID: connectionprofiles.VLESSRealityVisionProfileID, Name: "VLESS REALITY Vision", Lifecycle: state.ProfileDisabled},
		{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Lifecycle: state.ProfileDisabled},
		{ID: connectionprofiles.VLESSWebSocketProfileID, Name: "VLESS WebSocket", Lifecycle: state.ProfileDisabled},
		{ID: connectionprofiles.Hysteria2ProfileID, Name: "Hysteria2", Lifecycle: state.ProfileDisabled},
		{ID: connectionprofiles.TUICProfileID, Name: "TUIC", Lifecycle: state.ProfileDisabled},
		{ID: connectionprofiles.AnyTLSProfileID, Name: "AnyTLS", Lifecycle: state.ProfileDisabled},
	}
}

func newAcceptingTestModule() subscriptionpublication.Interface {
	return subscriptionpublication.New(mihomoValidatorFunc(func(context.Context, io.Reader) error { return nil }), singBoxValidatorFunc(func(context.Context, io.Reader) error { return nil }))
}

func TestRenderProducesValidatedSixProfileMihomoDocument(t *testing.T) {
	source, reader := sixProfileSource(t, "198.51.100.10")
	want := []byte(`proxies:
  - name: "VLESS REALITY Vision"
    type: vless
    server: "198.51.100.10"
    port: 443
    uuid: "11111111-1111-4111-8111-111111111111"
    flow: xtls-rprx-vision
    tls: true
    servername: "direct.example.com"
    network: tcp
    client-fingerprint: chrome
    reality-opts:
      public-key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
      short-id: "0123456789abcdef"
  - name: "VLESS XHTTP 香港"
    type: vless
    server: "xhttp.example.com"
    port: 443
    uuid: "22222222-2222-4222-8222-222222222222"
    tls: true
    servername: "xhttp.example.com"
    network: xhttp
    xhttp-opts:
      path: "/xhttp path?雪"
      host: "xhttp.example.com"
      mode: auto
  - name: "VLESS WebSocket"
    type: vless
    server: "ws.example.com"
    port: 443
    uuid: "33333333-3333-4333-8333-333333333333"
    tls: true
    servername: "ws.example.com"
    network: ws
    ws-opts:
      path: "/ws path?獨立"
      headers:
        Host: "origin.example.com"
  - name: "Hysteria2"
    type: hysteria2
    server: "198.51.100.10"
    port: 4443
    password: "hy:p@ss /雪"
    sni: "direct.example.com"
    skip-cert-verify: false
  - name: "TUIC"
    type: tuic
    server: "198.51.100.10"
    port: 8443
    uuid: "55555555-5555-4555-8555-555555555555"
    password: "tuic:p@ss /密碼"
    sni: "direct.example.com"
    congestion-controller: cubic
    reduce-rtt: false
    skip-cert-verify: false
  - name: "AnyTLS"
    type: anytls
    server: "198.51.100.10"
    port: 9443
    password: "any:p@ss /秘密"
    sni: "direct.example.com"
    skip-cert-verify: false
proxy-groups:
  - name: "SBXR"
    type: select
    proxies:
      - "VLESS REALITY Vision"
      - "VLESS XHTTP 香港"
      - "VLESS WebSocket"
      - "Hysteria2"
      - "TUIC"
      - "AnyTLS"
rules:
  - "MATCH,SBXR"
`)
	validated := 0
	module := subscriptionpublication.New(mihomoValidatorFunc(func(_ context.Context, document io.Reader) error {
		validated++
		got, err := io.ReadAll(document)
		if err != nil || !bytes.Equal(got, want) {
			return errors.New("unexpected Mihomo document")
		}
		return nil
	}), singBoxValidatorFunc(func(context.Context, io.Reader) error { return nil }))

	first, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := module.Render(t.Context(), source, reader)
	if err != nil {
		t.Fatal(err)
	}
	if validated != 2 || !bytes.Equal(first.Mihomo, want) || !bytes.Equal(first.Mihomo, second.Mihomo) || first.ProfileCount != 6 {
		t.Fatalf("Render() validation calls=%d count=%d Mihomo bytes stable=%t", validated, first.ProfileCount, bytes.Equal(first.Mihomo, second.Mihomo))
	}
}
