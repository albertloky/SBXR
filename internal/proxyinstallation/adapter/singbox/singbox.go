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
	uuid := make([]byte, 16)
	shortID := make([]byte, 4)
	if _, err := rand.Read(uuid); err != nil {
		return Identity{}, err
	}
	if _, err := rand.Read(shortID); err != nil {
		return Identity{}, err
	}
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		UUID:       fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]),
		PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()),
		ShortID:    hex.EncodeToString(shortID),
	}, nil
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
