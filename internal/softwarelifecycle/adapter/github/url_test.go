package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

func TestCheckLatestRefusesMalformedAssetURLsWithoutPanicking(t *testing.T) {
	for _, address := range []string{"https://api.github.com/%", "https://api.github.com:bad/repos/albertloky/SBXR/releases/assets/1"} {
		t.Run(address, func(t *testing.T) {
			assets := []map[string]any{}
			for index, name := range []string{"install.sh", "release-index.json", "sbxr-linux-amd64.tar.gz", "sbxr-linux-arm64.tar.gz"} {
				assetURL := fmt.Sprintf("https://api.github.com/repos/albertloky/SBXR/releases/assets/%d", index+1)
				if index == 0 {
					assetURL = address
				}
				assets = append(assets, map[string]any{"name": name, "url": assetURL, "digest": "sha256:" + strings.Repeat("a", 64), "state": "uploaded", "size": 1})
			}
			body, err := json.Marshal(map[string]any{"assets": assets, "tag_name": "v3.1.90", "target_commitish": strings.Repeat("b", 40), "immutable": true})
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: request}, nil
			})}
			source := NewWithEndpoint(client, "https://api.github.com", func([]byte, string, string) ([]byte, error) {
				t.Fatal("malformed metadata reached attestation")
				return nil, nil
			})
			if _, result := source.CheckLatest(t.Context()); result != softwarelifecycle.LatestReleaseRefused || requests != 1 {
				t.Fatalf("result=%v requests=%d", result, requests)
			}
		})
	}
}
