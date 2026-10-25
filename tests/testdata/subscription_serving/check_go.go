//go:build ignore

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type vector struct {
	Name     string `json:"name"`
	Request  string `json:"request"`
	Status   int    `json:"status"`
	GoStatus int    `json:"go_status"`
}

func main() {
	bytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic("fixture read failed")
	}
	var cases []vector
	if json.Unmarshal(bytes, &cases) != nil {
		panic("fixture decode failed")
	}
	token := strings.Repeat("A", 43)
	expected := sha256.Sum256([]byte(token))
	mismatches := 0
	for _, test := range cases {
		raw := strings.ReplaceAll(test.Request, "@TOKEN@", token)
		req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(strings.NewReader(raw), 8192)))
		valid := err == nil
		presented := ""
		if valid {
			path := req.RequestURI
			valid = req.Method == "GET" && req.Proto == "HTTP/1.1" && req.Host != "" && req.ContentLength == 0 && len(req.TransferEncoding) == 0 && req.URL.RawQuery == "" && !req.URL.ForceQuery && len(path) == 46 && strings.HasPrefix(path, "/s/")
			if valid {
				presented = path[3:]
			}
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(presented)
		digest := sha256.Sum256([]byte(presented))
		status := 404
		if valid && err == nil && len(decoded) == 32 && subtle.ConstantTimeCompare(digest[:], expected[:]) == 1 {
			status = 200
		}
		expectedStatus := test.Status
		if test.GoStatus != 0 {
			expectedStatus = test.GoStatus
			fmt.Printf("documented strict Rust refusal: %s (Go %d, Rust %d)\n", test.Name, expectedStatus, test.Status)
		}
		if status != expectedStatus {
			fmt.Printf("%s: fixture %d, Go %d\n", test.Name, expectedStatus, status)
			mismatches++
		}
	}
	fmt.Printf("%d cases, %d mismatches\n", len(cases), mismatches)
	if mismatches != 0 {
		os.Exit(1)
	}
}
