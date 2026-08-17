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

const (
	singBoxXHTTPReason = "VLESS XHTTP is unsupported by the sing-box transport contract"
	karingXHTTPReason  = "VLESS XHTTP is unavailable in the Karing core"
)

// MihomoValidator is the pinned full-document client-validation Seam.
type MihomoValidator interface {
	ValidateMihomo(context.Context, io.Reader) error
}

// SingBoxValidator is the pinned full-document client-validation Seam.
type SingBoxValidator interface {
	ValidateSingBox(context.Context, io.Reader) error
}

type Interface struct {
	mihomo  MihomoValidator
	singBox SingBoxValidator
}

// New returns a rendering Interface bound to the required client-validation Seams.
func New(mihomo MihomoValidator, singBox SingBoxValidator) Interface {
	return Interface{mihomo: mihomo, singBox: singBox}
}

// NewIntegrated uses the Module's strict deterministic Mihomo document check
// and the staged qualified sing-box parser supplied by the composition root.
func NewIntegrated(singBox SingBoxValidator) Interface {
	return New(integratedMihomoValidator{}, singBox)
}

type integratedMihomoValidator struct{}

func (integratedMihomoValidator) ValidateMihomo(_ context.Context, source io.Reader) error {
	document, err := io.ReadAll(io.LimitReader(source, 1<<20+1))
	text := string(document)
	if err != nil || len(document) == 0 || len(document) > 1<<20 || strings.ContainsAny(text, "\x00\r\t") || !strings.HasPrefix(text, "proxies:\n") || !strings.Contains(text, "\nproxy-groups:\n") || strings.Count(text, "  - name:") == 0 {
		return errors.New("complete Mihomo document validation failed")
	}
	return nil
}

type Availability string

const (
	NotOffered Availability = "Not offered"
	Disabled   Availability = "Disabled"
	NotSetUp   Availability = "Not set up"
)

type RepresentationOmission struct {
	ID     connectionprofiles.ProfileID
	Name   string
	Status Availability
	Reason string
}

// Representation contains one explicit secret-bearing body and its honest metadata.
type Representation struct {
	Body         []byte
	ProfileCount int
	Omissions    []RepresentationOmission
}

func (representation Representation) String() string {
	return "Subscription Publication representation: " + strconv.Itoa(representation.ProfileCount) + " Connection Profiles, body redacted"
}

func (representation Representation) GoString() string { return representation.String() }

func (Representation) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication representation cannot be rendered")
}

// Artifacts contains the explicit secret-bearing raw, base64, v2rayN,
// Shadowrocket, Mihomo, sing-box, and Karing outputs. Its default formatting
// and JSON rendering stay redacted.
type Artifacts struct {
	Raw, Base64, V2RayN, Shadowrocket, Mihomo []byte
	SingBox, Karing                           Representation
	ProfileCount                              int
	Omissions                                 []connectionprofiles.PublicationOmission
}

func (artifacts Artifacts) String() string {
	return "Subscription Publication artifacts: " + strconv.Itoa(artifacts.ProfileCount) + " Connection Profiles, bodies redacted"
}

func (artifacts Artifacts) GoString() string { return artifacts.String() }

func (Artifacts) MarshalJSON() ([]byte, error) {
	return nil, errors.New("Subscription Publication artifacts cannot be rendered")
}

// Render produces all seven client representations from one complete typed
// Connection Profile source. Both structured documents must pass their pinned
// validators before any artifact is returned.
func (module Interface) Render(ctx context.Context, source connectionprofiles.PublicationSource, secrets state.ClientAccessReader) (Artifacts, error) {
	if ctx == nil || secrets == nil || module.mihomo == nil || module.singBox == nil {
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
	singBox, count, ok := renderSingBox(profiles, secrets)
	if !ok || module.singBox.ValidateSingBox(ctx, bytes.NewReader(singBox)) != nil {
		return Artifacts{}, errInvalidSource
	}
	return Artifacts{
		Raw: raw, Base64: encoded, V2RayN: append([]byte(nil), encoded...), Shadowrocket: append([]byte(nil), encoded...), Mihomo: mihomo,
		SingBox:      representation(singBox, count, source.Omissions(), singBoxXHTTPReason),
		Karing:       representation(singBox, count, source.Omissions(), karingXHTTPReason),
		ProfileCount: len(profiles), Omissions: source.Omissions(),
	}, nil
}

func representation(body []byte, count int, omissions []connectionprofiles.PublicationOmission, xhttpReason string) Representation {
	return Representation{Body: append([]byte(nil), body...), ProfileCount: count, Omissions: representationOmissions(omissions, xhttpReason)}
}

func representationOmissions(source []connectionprofiles.PublicationOmission, xhttpReason string) []RepresentationOmission {
	xhttp := RepresentationOmission{ID: connectionprofiles.VLESSXHTTPProfileID, Name: "VLESS XHTTP", Status: NotOffered, Reason: xhttpReason}
	for _, omission := range source {
		if omission.ID == connectionprofiles.VLESSXHTTPProfileID {
			xhttp = representationOmission(omission)
			break
		}
	}
	omissions := []RepresentationOmission{xhttp}
	for _, omission := range source {
		if omission.ID != connectionprofiles.VLESSXHTTPProfileID {
			omissions = append(omissions, representationOmission(omission))
		}
	}
	return omissions
}

func representationOmission(omission connectionprofiles.PublicationOmission) RepresentationOmission {
	if omission.Lifecycle == state.ProfileNotSetUp {
		return RepresentationOmission{ID: omission.ID, Name: omission.Name, Status: NotSetUp, Reason: "The Connection Profile is not set up"}
	}
	return RepresentationOmission{ID: omission.ID, Name: omission.Name, Status: Disabled, Reason: "The Connection Profile is deliberately disabled"}
}

func renderSingBox(profiles []connectionprofiles.PublicationProfile, secrets state.ClientAccessReader) ([]byte, int, bool) {
	read := func(value state.ClientAccessValue) string { return secrets.ReadClientAccessValue(value) }
	outbounds := make([]any, 0, len(profiles)+1)
	tags := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		outbound := map[string]any{"tag": profile.Name, "server": profile.Address, "server_port": profile.Port}
		switch profile.ID {
		case connectionprofiles.VLESSRealityVisionProfileID:
			uuid, shortID := read(profile.UUID), read(profile.ShortID)
			if uuid == "" || shortID == "" {
				return nil, 0, false
			}
			tls := singBoxTLS(profile.ServerName)
			tls["reality"] = map[string]any{"enabled": true, "public_key": profile.PublicKey, "short_id": shortID}
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			outbound["type"], outbound["uuid"], outbound["flow"], outbound["tls"] = "vless", uuid, "xtls-rprx-vision", tls
		case connectionprofiles.VLESSXHTTPProfileID:
			continue
		case connectionprofiles.VLESSWebSocketProfileID:
			uuid, path := read(profile.UUID), read(profile.Path)
			if uuid == "" || path == "" {
				return nil, 0, false
			}
			outbound["type"], outbound["uuid"], outbound["tls"] = "vless", uuid, singBoxTLS(profile.TLSName)
			outbound["transport"] = map[string]any{"type": "ws", "path": path, "headers": map[string]any{"Host": profile.HTTPHost}}
		case connectionprofiles.Hysteria2ProfileID:
			password := read(profile.Password)
			if password == "" {
				return nil, 0, false
			}
			outbound["type"], outbound["password"], outbound["tls"] = "hysteria2", password, singBoxTLS(profile.ServerName)
			if profile.Obfuscation {
				obfuscationSecret := read(profile.ObfuscationSecret)
				if obfuscationSecret == "" {
					return nil, 0, false
				}
				outbound["obfs"] = map[string]any{"type": "salamander", "password": obfuscationSecret}
			}
		case connectionprofiles.TUICProfileID:
			uuid, password := read(profile.UUID), read(profile.Password)
			if uuid == "" || password == "" || !validCongestionControl(profile.CongestionControl) {
				return nil, 0, false
			}
			outbound["type"], outbound["uuid"], outbound["password"] = "tuic", uuid, password
			outbound["congestion_control"], outbound["zero_rtt_handshake"], outbound["tls"] = profile.CongestionControl, false, singBoxTLS(profile.ServerName)
		case connectionprofiles.AnyTLSProfileID:
			password := read(profile.Password)
			if password == "" {
				return nil, 0, false
			}
			outbound["type"], outbound["password"], outbound["tls"] = "anytls", password, singBoxTLS(profile.ServerName)
		default:
			return nil, 0, false
		}
		outbounds = append(outbounds, outbound)
		tags = append(tags, profile.Name)
	}
	inbounds := []any{}
	route := map[string]any{"default_domain_resolver": "local-dns"}
	if len(tags) != 0 {
		outbounds = append(outbounds, map[string]any{"type": "selector", "tag": "SBXR", "outbounds": tags, "default": tags[0]})
		inbounds = append(inbounds, map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080})
		route["final"] = "SBXR"
	}
	document, err := json.MarshalIndent(map[string]any{
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local-dns"}}},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
	}, "", "  ")
	if err != nil {
		return nil, 0, false
	}
	return append(document, '\n'), len(tags), true
}

func singBoxTLS(serverName string) map[string]any {
	return map[string]any{"enabled": true, "server_name": serverName}
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
			if profile.Obfuscation {
				obfuscationSecret := read(profile.ObfuscationSecret)
				if obfuscationSecret == "" {
					return nil, false
				}
				document.WriteString("    obfs: salamander\n")
				writeMihomoString(&document, "    ", "obfs-password", obfuscationSecret)
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
		if profile.Obfuscation {
			obfuscationSecret := read(profile.ObfuscationSecret)
			if obfuscationSecret == "" {
				return "", false
			}
			query.Set("obfs", "salamander")
			query.Set("obfs-password", obfuscationSecret)
		}
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
