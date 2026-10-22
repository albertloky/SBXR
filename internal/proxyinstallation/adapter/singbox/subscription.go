package singbox

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var clientServerName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// EncodeSubscriptionArtifact owns the client URI formats and their validation.
// It prepares secret-bearing bytes independently of the serving transport.
func (Adapter) EncodeSubscriptionArtifact(f ConnectionFacts) ([]byte, error) {
	ip, err := netip.ParseAddr(f.PublicIPv4)
	public, publicErr := base64.RawURLEncoding.Strict().DecodeString(f.PublicKey)
	short, shortErr := hex.DecodeString(f.ShortID)
	if err != nil || !ip.Is4() || ip.String() != f.PublicIPv4 || !uuidPattern.MatchString(f.UUID) || !clientServerName.MatchString(f.ServerName) || publicErr != nil || len(public) != 32 || shortErr != nil || len(short) != 4 || hex.EncodeToString(short) != f.ShortID {
		return nil, fmt.Errorf("subscription artifact refused")
	}
	escape := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	artifact := "vless://" + f.UUID + "@" + f.PublicIPv4 + ":443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=" + escape(f.ServerName) + "&fp=chrome&pbk=" + escape(f.PublicKey) + "&sid=" + escape(f.ShortID) + "&type=tcp#" + escape("SBXR Proxy ("+f.PublicIPv4+")") + "\n"
	if f.VMessHostname != "" {
		if !ValidVMessHostname(f.VMessHostname) {
			return nil, fmt.Errorf("subscription artifact refused")
		}
		node, err := json.Marshal(map[string]string{
			"v": "2", "ps": "SBXR VMess (" + f.VMessHostname + ")", "add": f.VMessHostname, "port": "443",
			"id": f.UUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
			"host": f.VMessHostname, "path": VMessWebSocketPath, "tls": "tls", "sni": f.VMessHostname,
		})
		if err != nil {
			return nil, fmt.Errorf("subscription artifact refused")
		}
		artifact += "vmess://" + base64.StdEncoding.EncodeToString(node) + "\n"
	}
	if len(artifact) == 0 || len(artifact) > 4096 {
		return nil, fmt.Errorf("subscription artifact refused")
	}
	return []byte(artifact), nil
}
