package subscriptionpublication

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

var errInvalidSource = errors.New("Subscription Publication refused an invalid rendering source")

// MihomoValidator is the pinned full-document client-validation Seam.
type MihomoValidator interface {
	ValidateMihomo(context.Context, io.Reader) error
}

type Interface struct{ mihomo MihomoValidator }

// New returns a rendering Interface bound to one Mihomo validation Seam.
func New(mihomo MihomoValidator) Interface { return Interface{mihomo: mihomo} }

// Artifacts contains the explicit secret-bearing URI and Mihomo outputs. Its
// default formatting and JSON rendering stay redacted.
type Artifacts struct {
	Raw, Base64, V2RayN, Mihomo []byte
	ProfileCount                int
	Omissions                   []connectionprofiles.PublicationOmission
}

func (artifacts Artifacts) String() string {
	return "Subscription Publication artifacts: " + strconv.Itoa(artifacts.ProfileCount) + " profiles, bodies redacted"
}

func (artifacts Artifacts) GoString() string { return artifacts.String() }

func (Artifacts) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication artifacts cannot be rendered")
}

// Render produces raw, standard-base64, v2rayN, and validated Mihomo bytes from
// one complete typed Connection Profiles source.
func (module Interface) Render(ctx context.Context, source connectionprofiles.PublicationSource, secrets state.ClientAccessReader) (Artifacts, error) {
	if ctx == nil || secrets == nil || module.mihomo == nil {
		return Artifacts{}, errInvalidSource
	}
	profiles := source.Profiles()
	lines := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		line, ok := renderProfile(profile, secrets)
		if !ok {
			return Artifacts{}, errInvalidSource
		}
		lines = append(lines, line)
	}
	if len(profiles)+len(source.Omissions()) != 6 {
		return Artifacts{}, errInvalidSource
	}
	raw := []byte(strings.Join(lines, "\n"))
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	mihomo, ok := renderMihomo(profiles, secrets)
	if !ok || module.mihomo.ValidateMihomo(ctx, bytes.NewReader(mihomo)) != nil {
		return Artifacts{}, errInvalidSource
	}
	return Artifacts{Raw: raw, Base64: encoded, V2RayN: append([]byte(nil), encoded...), Mihomo: mihomo, ProfileCount: len(profiles), Omissions: source.Omissions()}, nil
}

func renderMihomo(profiles []connectionprofiles.PublicationProfile, secrets state.ClientAccessReader) ([]byte, bool) {
	read := func(value state.ClientAccessValue) string { return secrets.ReadClientAccessValue(value) }
	if len(profiles) == 0 {
		return []byte("proxies: []\n"), true
	}
	var document strings.Builder
	document.WriteString("proxies:\n")
	names := make([]string, 0, len(profiles))
	unique := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if profile.Name == "" || unique[profile.Name] {
			return nil, false
		}
		unique[profile.Name] = true
		names = append(names, profile.Name)
		switch profile.ID {
		case connectionprofiles.VLESSRealityVisionProfileID:
			uuid, shortID := read(profile.UUID), read(profile.ShortID)
			if uuid == "" || shortID == "" {
				return nil, false
			}
			writeMihomoBase(&document, profile, "vless")
			writeMihomoString(&document, "    ", "uuid", uuid)
			document.WriteString("    flow: xtls-rprx-vision\n    tls: true\n")
			writeMihomoString(&document, "    ", "servername", profile.ServerName)
			document.WriteString("    network: tcp\n    client-fingerprint: chrome\n    reality-opts:\n")
			writeMihomoString(&document, "      ", "public-key", profile.PublicKey)
			writeMihomoString(&document, "      ", "short-id", shortID)
		case connectionprofiles.VLESSXHTTPProfileID:
			uuid, path := read(profile.UUID), read(profile.Path)
			if uuid == "" || path == "" {
				return nil, false
			}
			writeMihomoBase(&document, profile, "vless")
			writeMihomoString(&document, "    ", "uuid", uuid)
			document.WriteString("    tls: true\n")
			writeMihomoString(&document, "    ", "servername", profile.Hostname)
			document.WriteString("    network: xhttp\n    xhttp-opts:\n")
			writeMihomoString(&document, "      ", "path", path)
			writeMihomoString(&document, "      ", "host", profile.Hostname)
			document.WriteString("      mode: auto\n")
		case connectionprofiles.VLESSWebSocketProfileID:
			uuid, path := read(profile.UUID), read(profile.Path)
			if uuid == "" || path == "" {
				return nil, false
			}
			writeMihomoBase(&document, profile, "vless")
			writeMihomoString(&document, "    ", "uuid", uuid)
			document.WriteString("    tls: true\n")
			writeMihomoString(&document, "    ", "servername", profile.TLSName)
			document.WriteString("    network: ws\n    ws-opts:\n")
			writeMihomoString(&document, "      ", "path", path)
			document.WriteString("      headers:\n")
			writeMihomoString(&document, "        ", "Host", profile.HTTPHost)
		case connectionprofiles.Hysteria2ProfileID:
			password := read(profile.Password)
			if !writeMihomoDirectTLS(&document, profile, "hysteria2", password) {
				return nil, false
			}
		case connectionprofiles.TUICProfileID:
			uuid, password := read(profile.UUID), read(profile.Password)
			if uuid == "" || password == "" || !validCongestionControl(profile.CongestionControl) {
				return nil, false
			}
			writeMihomoBase(&document, profile, "tuic")
			writeMihomoString(&document, "    ", "uuid", uuid)
			writeMihomoString(&document, "    ", "password", password)
			writeMihomoString(&document, "    ", "sni", profile.ServerName)
			document.WriteString("    congestion-controller: " + string(profile.CongestionControl) + "\n    reduce-rtt: false\n    skip-cert-verify: false\n")
		case connectionprofiles.AnyTLSProfileID:
			password := read(profile.Password)
			if !writeMihomoDirectTLS(&document, profile, "anytls", password) {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	document.WriteString("proxy-groups:\n  - name: \"SBXR\"\n    type: select\n    proxies:\n")
	for _, name := range names {
		document.WriteString("      - " + yamlString(name) + "\n")
	}
	document.WriteString("rules:\n  - \"MATCH,SBXR\"\n")
	return []byte(document.String()), true
}

func writeMihomoDirectTLS(document *strings.Builder, profile connectionprofiles.PublicationProfile, profileType, password string) bool {
	if password == "" {
		return false
	}
	writeMihomoBase(document, profile, profileType)
	writeMihomoString(document, "    ", "password", password)
	writeMihomoString(document, "    ", "sni", profile.ServerName)
	document.WriteString("    skip-cert-verify: false\n")
	return true
}

func writeMihomoBase(document *strings.Builder, profile connectionprofiles.PublicationProfile, profileType string) {
	document.WriteString("  - name: " + yamlString(profile.Name) + "\n    type: " + profileType + "\n")
	writeMihomoString(document, "    ", "server", profile.Address)
	document.WriteString("    port: " + strconv.Itoa(int(profile.Port)) + "\n")
}

func writeMihomoString(document *strings.Builder, indent, key, value string) {
	document.WriteString(indent + key + ": " + yamlString(value) + "\n")
}

func yamlString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func validCongestionControl(value state.CongestionControl) bool {
	return value == state.CongestionBBR || value == state.CongestionCubic
}

func renderProfile(profile connectionprofiles.PublicationProfile, secrets state.ClientAccessReader) (string, bool) {
	read := func(value state.ClientAccessValue) string { return secrets.ReadClientAccessValue(value) }
	query := url.Values{}
	var user *url.Userinfo
	var scheme string
	switch profile.ID {
	case connectionprofiles.VLESSRealityVisionProfileID:
		scheme = "vless"
		uuid, shortID := read(profile.UUID), read(profile.ShortID)
		if profile.Transport != "RAW" || profile.Security != "REALITY" || profile.Flow != "xtls-rprx-vision" || profile.Fingerprint != "chrome" || profile.ServerName == "" || profile.PublicKey == "" || uuid == "" || shortID == "" {
			return "", false
		}
		user = url.User(uuid)
		query = url.Values{"encryption": {"none"}, "flow": {profile.Flow}, "security": {"reality"}, "sni": {profile.ServerName}, "fp": {profile.Fingerprint}, "pbk": {profile.PublicKey}, "sid": {shortID}, "type": {"tcp"}}
	case connectionprofiles.VLESSXHTTPProfileID:
		scheme = "vless"
		uuid, path := read(profile.UUID), read(profile.Path)
		if profile.Transport != "XHTTP" || profile.Security != "TLS" || profile.XHTTPServerMode != state.XHTTPPacketUp || profile.Hostname == "" || uuid == "" || path == "" {
			return "", false
		}
		user = url.User(uuid)
		query = url.Values{"encryption": {"none"}, "security": {"tls"}, "sni": {profile.Hostname}, "type": {"xhttp"}, "host": {profile.Hostname}, "path": {path}, "mode": {"auto"}}
	case connectionprofiles.VLESSWebSocketProfileID:
		scheme = "vless"
		uuid, path := read(profile.UUID), read(profile.Path)
		if profile.Transport != "WebSocket" || profile.Security != "TLS" || profile.Hostname == "" || profile.TLSName == "" || profile.HTTPHost == "" || uuid == "" || path == "" {
			return "", false
		}
		user = url.User(uuid)
		query = url.Values{"encryption": {"none"}, "security": {"tls"}, "sni": {profile.TLSName}, "type": {"ws"}, "host": {profile.HTTPHost}, "path": {path}}
	case connectionprofiles.Hysteria2ProfileID:
		scheme = "hysteria2"
		password := read(profile.Password)
		if profile.Transport != "QUIC" || profile.Security != "TLS" || profile.ServerName == "" || password == "" {
			return "", false
		}
		user = url.User(password)
		query = url.Values{"sni": {profile.ServerName}, "insecure": {"0"}}
	case connectionprofiles.TUICProfileID:
		scheme = "tuic"
		uuid, password := read(profile.UUID), read(profile.Password)
		if profile.Transport != "QUIC" || profile.Security != "TLS" || profile.ServerName == "" || !validCongestionControl(profile.CongestionControl) || uuid == "" || password == "" {
			return "", false
		}
		user = url.UserPassword(uuid, password)
		query = url.Values{"sni": {profile.ServerName}, "congestion_control": {string(profile.CongestionControl)}, "insecure": {"0"}}
	case connectionprofiles.AnyTLSProfileID:
		scheme = "anytls"
		password := read(profile.Password)
		if profile.Transport != "TCP" || profile.Security != "TLS" || profile.ServerName == "" || password == "" {
			return "", false
		}
		user = url.User(password)
		query = url.Values{"security": {"tls"}, "sni": {profile.ServerName}, "type": {"tcp"}, "insecure": {"0"}}
	default:
		return "", false
	}
	if profile.Name == "" || profile.Address == "" || profile.Port == 0 {
		return "", false
	}
	address := profile.Address
	if parsed, err := netip.ParseAddr(strings.Trim(address, "[]")); err == nil {
		address = parsed.String()
	}
	return (&url.URL{Scheme: scheme, User: user, Host: net.JoinHostPort(address, strconv.Itoa(int(profile.Port))), RawQuery: strings.ReplaceAll(query.Encode(), "+", "%20"), Fragment: profile.Name}).String(), true
}
