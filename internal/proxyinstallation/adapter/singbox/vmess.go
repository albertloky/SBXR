package singbox

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
)

const VMessWebSocketPort = 10000
const VMessWebSocketPath = "/sbxr-vmess"

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// ValidVMessHostname accepts a canonical DNS hostname, never a URL or an IP.
func ValidVMessHostname(hostname string) bool {
	if len(hostname) > 253 || !strings.Contains(hostname, ".") || net.ParseIP(hostname) != nil {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) > 63 || !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func vmessInbound(uuid, hostname string) map[string]any {
	return map[string]any{
		"type": "vmess", "tag": "vmess-ws@" + hostname,
		"listen": "127.0.0.1", "listen_port": VMessWebSocketPort,
		"users":     []any{map[string]any{"uuid": uuid}},
		"transport": map[string]any{"type": "ws", "path": VMessWebSocketPath},
	}
}

// WithVMessWebSocket adds an origin for an independently managed cloudflared
// connector. The nonsecret tag retains the public hostname for client encoding.
func (a Adapter) WithVMessWebSocket(source []byte, hostname string) ([]byte, error) {
	facts, err := a.CurrentConnectionFacts(source, "192.0.2.1")
	if err != nil || facts.VMessHostname != "" || !ValidVMessHostname(hostname) {
		return nil, fmt.Errorf("VMess WebSocket configuration refused")
	}
	var config map[string]any
	if json.Unmarshal(source, &config) != nil {
		return nil, fmt.Errorf("VMess WebSocket configuration refused")
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return nil, fmt.Errorf("VMess WebSocket configuration refused")
	}
	config["inbounds"] = append(inbounds, vmessInbound(facts.UUID, hostname))
	body, err := json.Marshal(config)
	return append(body, '\n'), err
}

func vmessHostname(source []byte, uuid string) (string, error) {
	var config struct{ Inbounds []map[string]any }
	if json.Unmarshal(source, &config) != nil || len(config.Inbounds) < 1 || len(config.Inbounds) > 2 {
		return "", fmt.Errorf("client configuration refused")
	}
	if len(config.Inbounds) == 1 {
		return "", nil
	}
	inbound := config.Inbounds[1]
	tag, _ := inbound["tag"].(string)
	hostname := strings.TrimPrefix(tag, "vmess-ws@")
	// Compare the complete origin contract, including its single shared identity.
	expected, _ := json.Marshal(vmessInbound(uuid, hostname))
	var canonical map[string]any
	json.Unmarshal(expected, &canonical)
	if !ValidVMessHostname(hostname) || !reflect.DeepEqual(inbound, canonical) {
		return "", fmt.Errorf("client configuration refused")
	}
	return hostname, nil
}

func vmessOutbound(f ConnectionFacts) map[string]any {
	return map[string]any{
		"type": "vmess", "tag": "vmess-ws-out", "server": f.VMessHostname, "server_port": 443,
		"uuid": f.UUID, "security": "auto",
		"tls":       map[string]any{"enabled": true, "server_name": f.VMessHostname},
		"transport": map[string]any{"type": "ws", "path": VMessWebSocketPath, "headers": map[string]any{"Host": f.VMessHostname}},
	}
}
