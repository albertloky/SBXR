// Package singbox owns official sing-box key and configuration mechanics.
package singbox

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
)

type Identity struct {
	UUID, PrivateKey, PublicKey, ShortID string
}

type Adapter struct{}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func New() Adapter { return Adapter{} }

func (Adapter) PrepareIdentity() (Identity, error) {
	uuid, err := prepareUUID()
	if err != nil {
		return Identity{}, err
	}
	shortID := make([]byte, 4)
	if _, err := rand.Read(shortID); err != nil {
		return Identity{}, err
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		UUID:       uuid,
		PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),
		ShortID:    hex.EncodeToString(shortID),
	}, nil
}

func prepareUUID() (string, error) {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return "", err
	}
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// ReplaceClientIdentity preserves every supported server field except the one
// VLESS UUID. It never generates new REALITY key or short-ID material.
func (adapter Adapter) ReplaceClientIdentity(source []byte) ([]byte, error) {
	if _, err := adapter.CurrentConnectionFacts(source, "192.0.2.1"); err != nil {
		return nil, fmt.Errorf("client identity replacement refused")
	}
	var configuration map[string]any
	if json.Unmarshal(source, &configuration) != nil {
		return nil, fmt.Errorf("client identity replacement refused")
	}
	inbounds, ok := configuration["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return nil, fmt.Errorf("client identity replacement refused")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("client identity replacement refused")
	}
	users, ok := inbound["users"].([]any)
	if !ok || len(users) != 1 {
		return nil, fmt.Errorf("client identity replacement refused")
	}
	user, ok := users[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("client identity replacement refused")
	}
	uuid, err := prepareUUID()
	if err != nil {
		return nil, err
	}
	user["uuid"] = uuid
	body, err := json.Marshal(configuration)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (Adapter) ValidIdentity(identity Identity) bool {
	privateBytes, privateErr := base64.RawURLEncoding.DecodeString(identity.PrivateKey)
	publicBytes, publicErr := base64.RawURLEncoding.DecodeString(identity.PublicKey)
	shortID, shortErr := hex.DecodeString(identity.ShortID)
	if privateErr != nil || publicErr != nil || shortErr != nil || len(privateBytes) != 32 || len(publicBytes) != 32 || len(shortID) != 4 || !uuidPattern.MatchString(identity.UUID) {
		return false
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	return err == nil && subtle.ConstantTimeCompare(private.PublicKey().Bytes(), publicBytes) == 1
}

func (adapter Adapter) EncodeServerConfiguration(identity Identity, destinationAddress, serverName string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(destinationAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || serverName == "" || !adapter.ValidIdentity(identity) {
		return nil, fmt.Errorf("server configuration refused")
	}
	configuration := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "vless-in", "listen": "::", "listen_port": 443,
			"users": []any{map[string]any{"uuid": identity.UUID, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{
				"enabled": true, "server_name": serverName,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": host, "server_port": port},
					"private_key": identity.PrivateKey,
					"short_id":    []string{identity.ShortID},
				},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	body, err := json.Marshal(configuration)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// ConnectionFacts contains only Client Access Values, never a REALITY private key.
type ConnectionFacts struct {
	PublicIPv4, UUID, ServerName, PublicKey, ShortID string
}

func (ConnectionFacts) String() string   { return "Client Access Values (redacted)" }
func (ConnectionFacts) GoString() string { return "Client Access Values (redacted)" }
func (ConnectionFacts) MarshalJSON() ([]byte, error) {
	return []byte(`"Client Access Values (redacted)"`), nil
}

func (adapter Adapter) CurrentConnectionFacts(serverConfiguration []byte, publicIPv4 string) (ConnectionFacts, error) {
	var server struct {
		Inbounds []struct {
			Type, Listen string
			ListenPort   int `json:"listen_port"`
			Users        []struct{ UUID, Flow string }
			TLS          struct {
				Enabled    bool
				ServerName string `json:"server_name"`
				Reality    struct {
					Enabled    bool
					PrivateKey string   `json:"private_key"`
					ShortID    []string `json:"short_id"`
				}
			}
		}
	}
	if err := json.Unmarshal(serverConfiguration, &server); err != nil || len(server.Inbounds) != 1 || len(server.Inbounds[0].Users) != 1 || len(server.Inbounds[0].TLS.Reality.ShortID) != 1 {
		return ConnectionFacts{}, fmt.Errorf("client configuration refused")
	}
	inbound, user := server.Inbounds[0], server.Inbounds[0].Users[0]
	privateBytes, err := base64.RawURLEncoding.DecodeString(inbound.TLS.Reality.PrivateKey)
	if err != nil {
		return ConnectionFacts{}, fmt.Errorf("client configuration refused")
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return ConnectionFacts{}, fmt.Errorf("client configuration refused")
	}
	address := net.ParseIP(publicIPv4)
	identity := Identity{UUID: user.UUID, PrivateKey: inbound.TLS.Reality.PrivateKey, PublicKey: base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), ShortID: inbound.TLS.Reality.ShortID[0]}
	if address == nil || address.To4() == nil || inbound.Type != "vless" || inbound.ListenPort != 443 || user.Flow != "xtls-rprx-vision" || !inbound.TLS.Enabled || inbound.TLS.ServerName == "" || !inbound.TLS.Reality.Enabled || !adapter.ValidIdentity(identity) {
		return ConnectionFacts{}, fmt.Errorf("client configuration refused")
	}
	return ConnectionFacts{PublicIPv4: publicIPv4, UUID: user.UUID, ServerName: inbound.TLS.ServerName, PublicKey: identity.PublicKey, ShortID: identity.ShortID}, nil
}

func (adapter Adapter) EncodeClientConfiguration(serverConfiguration []byte, publicIPv4 string) ([]byte, error) {
	facts, err := adapter.CurrentConnectionFacts(serverConfiguration, publicIPv4)
	if err != nil {
		return nil, err
	}
	configuration := struct {
		Log       any   `json:"log"`
		Inbounds  []any `json:"inbounds"`
		Outbounds []any `json:"outbounds"`
	}{
		Log:      map[string]any{"level": "warn", "timestamp": true},
		Inbounds: []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}},
		Outbounds: []any{map[string]any{
			"type": "vless", "tag": "vless-out", "server": publicIPv4, "server_port": 443, "uuid": facts.UUID, "flow": "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled": true, "server_name": facts.ServerName,
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": facts.PublicKey, "short_id": facts.ShortID},
			},
		}},
	}
	body, err := json.Marshal(configuration)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}
