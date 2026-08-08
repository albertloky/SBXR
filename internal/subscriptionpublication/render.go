package subscriptionpublication

import (
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
	"github.com/albertloky/SBXR/internal/state"
)

var errInvalidSource = errors.New("Subscription Publication refused an invalid rendering source")

type Interface struct{}

// New returns the Subscription Publication rendering Interface.
func New() Interface { return Interface{} }

// Artifacts contains the explicit secret-bearing renderer outputs. Its default
// formatting and JSON rendering stay redacted.
type Artifacts struct {
	Raw, Base64, V2RayN []byte
	ProfileCount        int
	Omissions           []connectionprofiles.PublicationOmission
}

func (artifacts Artifacts) String() string {
	return "Subscription Publication artifacts: " + strconv.Itoa(artifacts.ProfileCount) + " profiles, bodies redacted"
}

func (artifacts Artifacts) GoString() string { return artifacts.String() }

func (Artifacts) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication artifacts cannot be rendered")
}

// Render produces raw, standard-base64, and v2rayN bytes from one complete
// typed Connection Profiles source.
func (Interface) Render(source connectionprofiles.PublicationSource, secrets state.ClientAccessReader) (Artifacts, error) {
	if secrets == nil {
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
	return Artifacts{Raw: raw, Base64: encoded, V2RayN: append([]byte(nil), encoded...), ProfileCount: len(profiles), Omissions: source.Omissions()}, nil
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
		if profile.Transport != "QUIC" || profile.Security != "TLS" || profile.ServerName == "" || profile.CongestionControl == "" || uuid == "" || password == "" {
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
